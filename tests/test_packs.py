"""Offline pack contracts: subprocess tools are disposable Python fixtures."""
import argparse, datetime as dt, importlib.machinery, importlib.util, json, os, pathlib, subprocess, sys, tempfile, unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
from helix_contracts import VERSION
import helix_packs as P


class Packs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup); self.repo = pathlib.Path(self.temp.name)
        self.git('init', '-b', 'main'); self.git('config', 'user.name', 'Test'); self.git('config', 'user.email', 'test@example.test')
        self.write('README', 'fixture'); self.git('add', '.'); self.git('commit', '-m', 'base')
        self.tools = self.repo / 'fake-tools'; self.tools.mkdir()
        self.env = patch.dict(os.environ, {'PATH': str(self.tools) + os.pathsep + os.environ['PATH']}); self.env.start(); self.addCleanup(self.env.stop)
        self.ctx = type('Context', (), dict(repo=self.repo, cfg={}, state=lambda s, cp: {}, ev=lambda s, cp: self.repo / 'helix-evidence' / cp))()
        self.args = argparse.Namespace(out=str(self.repo / 'output'), trusted_base=False, base=None, no_start=True, base_url=None, accept_secret=[], reason=None)

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True, text=True).stdout.strip()

    def write(self, path, text):
        p = self.repo / path; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text); return p

    def config(self, pack, config, **packs):
        self.write('helix.json', json.dumps({'helix_version': VERSION, 'packs': {pack: config, **packs}}))

    def fake(self, tool, payload, code=0):
        script = '''#!%s
import json, pathlib, sys
if '--version' in sys.argv:
 print('%s fixture 1'); sys.exit(0)
data = %r
args = sys.argv
if '-r' in args and args[0].endswith('gitleaks'):
 pathlib.Path(args[args.index('-r')+1]).write_text(json.dumps(data))
elif '--output-path' in args:
 pathlib.Path(args[args.index('--output-path')+1]).write_text(json.dumps(data))
elif '--summary-export' in args:
 pathlib.Path(args[args.index('--summary-export')+1]).write_text(json.dumps(data))
else: print(json.dumps(data))
sys.exit(%d)
''' % (sys.executable, tool, payload, code)
        p = self.write('fake-tools/' + tool, script); p.chmod(0o755)

    def scan(self, pack): return P.scan(self.ctx, pack, self.args)

    def test_fingerprint_ignores_whitespace(self):
        self.assertEqual(P.fingerprint('t','r','f',' a \n b '), P.fingerprint('t','r','f','a b'))

    def test_dedupe_fingerprint(self):
        f = P.finding('security','a','r','high','t',snippet='s')
        self.assertEqual(len(P.dedupe([f, dict(f, line=9)])), 1)

    def test_sca_alias_dedupe(self):
        a = P.sca('trivy','lock','node-pkg','pkg','1','CVE-1','critical','2',[])
        b = P.sca('osv-scanner','lock','npm','pkg','1','GHSA-1','high','2',['CVE-1'])
        self.assertEqual(len(P.dedupe([a,b])), 1)
        self.assertEqual(a['severity'], 'critical')

    def test_secret_redaction_severity_and_command(self):
        self.config('security', {'tools':['gitleaks']})
        self.fake('gitleaks', [dict(RuleID='private-key',File='key.pem',StartLine=5,Secret='NEVER-OUTPUT-THIS',Match='NEVER-OUTPUT-THIS')], 1)
        r, f, run, out = self.scan('security')
        self.assertEqual(f[0]['severity'], 'critical'); self.assertEqual(f[0]['category'], 'secret')
        self.assertIn('--redact', run['tools'][0]['command'])
        for p in out.iterdir(): self.assertNotIn('NEVER-OUTPUT-THIS', p.read_text())
        self.assertEqual(r['exit_code'], 2)

    def test_semgrep_mapping_and_baseline_gate(self):
        self.config('security', {'tools':['semgrep']})
        self.fake('semgrep', {'errors':[], 'paths':{'scanned':['app.py']}, 'results':[dict(check_id='r',path='app.py',start={'line':3},extra=dict(severity='ERROR',message='Popraw API.',lines='bad()'))]})
        r, f, run, _ = self.scan('security'); self.assertEqual(r['exit_code'], 2)
        self.assertEqual(f[0]['severity'], 'high')
        P.baseline_write(self.repo,'security',f,{},self.args)
        r, f, _, _ = self.scan('security'); self.assertEqual(r['exit_code'],0); self.assertEqual(f[0]['status'],'baselined')

    def test_semgrep_complete_empty_scan_passes(self):
        self.config('security', {'tools': ['semgrep']})
        self.fake('semgrep', {'results': [], 'errors': [], 'paths': {'scanned': []}})
        result, _, run, _ = self.scan('security')
        self.assertTrue(result['pass'])
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(run['tools'][0]['status'], 'ok')

    def test_semgrep_partial_parse_warning_keeps_results_and_marks_coverage_incomplete(self):
        self.config('security', {'tools': ['semgrep']})
        warning = {'type': ['PartialParsing', []], 'level': 'warn', 'message': 'Syntax error', 'path': 'b.tsx'}
        self.fake('semgrep', {'errors': [warning], 'paths': {'scanned': ['app.py', 'b.tsx']},
                              'results': [dict(check_id='r', path='app.py', start={'line': 3}, extra=dict(severity='ERROR', message='Popraw API.', lines='bad()'))]})
        result, findings, run, _ = self.scan('security')
        self.assertEqual(len(findings), 1)   # wynik z app.py zostaje
        self.assertEqual((run['tools'][0]['status'], result['status']), ('partial', 'INCOMPLETE'))
        self.assertIn('b.tsx', run['tools'][0]['error'])
        # G3 r2: częściowy skan nie trafia do pamięci podręcznej; kolejny przebieg znów uruchamia semgrep i zostaje INCOMPLETE.
        self.args.out = str(self.repo / 'output-2')
        result, findings, run, _ = self.scan('security')
        self.assertEqual((run['tools'][0]['status'], result['status'], len(findings)), ('partial', 'INCOMPLETE', 1))

    def test_semgrep_incomplete_json_fails_with_zero_exit(self):
        self.config('security', {'tools': ['semgrep']})
        valid = {'results': [], 'errors': [], 'paths': {'scanned': ['app.py']}}
        invalid = [{}, {k: v for k, v in valid.items() if k != 'results'}]
        invalid += [dict(valid, results=value) for value in (None, {}, '')]
        invalid += [dict(valid, errors=value) for value in (None, {}, '', [{'message': 'parse error'}])]
        invalid += [dict(valid, paths=value) for value in (None, {}, {'scanned': None}, {'scanned': 'app.py'}, {'scanned': [1]})]
        invalid += [{k: v for k, v in valid.items() if k != 'errors'}]
        for payload in invalid:
            with self.subTest(payload=payload):
                self.fake('semgrep', payload)
                result, _, run, _ = self.scan('security')
                self.assertFalse(result['pass'])
                self.assertIn(result['status'], ('ERROR', 'INCOMPLETE'))
                self.assertEqual(result['exit_code'], 3)
                self.assertEqual(run['tools'][0]['status'], 'error')
                self.assertEqual(run['tools'][0]['exit_code'], 0)

    def test_trivy_mapping(self):
        self.config('security', {'tools':['trivy']})
        self.fake('trivy', {'Results':[{'Target':'lock','Type':'npm','Vulnerabilities':[dict(PkgName='p',InstalledVersion='1',VulnerabilityID='CVE-1',Severity='CRITICAL',FixedVersion='2')],
            'Misconfigurations':[dict(ID='bad',Severity='MEDIUM',Title='Zła konfiguracja')]}]})
        _, f, _, _ = self.scan('security'); self.assertEqual([x['severity'] for x in f], ['critical','medium']); self.assertIn('2', f[0]['fix_hint'])

    def test_advisory_zero(self):
        self.config('security', {'tools':['gitleaks'], 'mode':'advisory'})
        self.fake('gitleaks',[dict(RuleID='token',File='f')],1)
        r, _, _, _ = self.scan('security'); self.assertEqual(r['exit_code'],0); self.assertTrue(r['would_fail'])

    def test_tool_crash_error(self):
        self.config('security', {'tools':['semgrep']}); self.fake('semgrep',{},7)
        r, _, run, _ = self.scan('security'); self.assertEqual(r['exit_code'],3); self.assertEqual(run['status'],'error')

    def test_required_missing_error(self):
        self.config('security', {'tools':['gitleaks']})
        with patch.object(P.shutil, 'which', return_value=None): r, _, _, _ = self.scan('security')
        self.assertEqual(r['status'],'INCOMPLETE'); self.assertFalse(r['pass'])

    def test_optional_missing_skipped(self):
        self.config('security', {'tools':['osv-scanner']})
        with patch.object(P.shutil, 'which', return_value=None): r, _, run, _ = self.scan('security')
        self.assertEqual(r['exit_code'],3); self.assertEqual(run['tools'][0]['status'],'skipped')

    def test_secret_not_baselined_without_acceptance(self):
        f = P.finding('security','gitleaks','key','high','Sekret',category='secret')
        with self.assertRaises(ValueError): P.baseline_write(self.repo,'security',[f],{},self.args)
        self.assertFalse((self.repo / '.helix/baselines/security.json').exists())
        self.args.accept_secret = [f['fingerprint'] + '=revoked at provider']
        P.baseline_write(self.repo,'security',[f],{},self.args)
        self.assertIn(f['fingerprint'], P.read_json(self.repo / '.helix/baselines/security.json'))

    def test_trusted_base_rejects_branch_baseline(self):
        self.config('security', {'tools':['semgrep']}, trusted_base=True, base_ref='main')
        self.git('add','helix.json'); self.git('commit','-m','policy'); self.git('checkout','-b','feature')
        self.fake('semgrep', {'results':[], 'errors':[], 'paths':{'scanned':[]}}); self.write('.helix/baselines/security.json',json.dumps({'fake':{}}))
        r, _, _, out = self.scan('security'); self.assertEqual(r['exit_code'],2); self.assertTrue(r['trust_changed'])
        self.assertIn('wymaga akceptacji właściciela',(out / 'report.md').read_text())

    def test_trusted_config_cannot_disable_tools(self):
        self.config('security', {'tools':['semgrep']}, trusted_base=True, base_ref='main')
        self.git('add','helix.json'); self.git('commit','-m','policy'); self.git('checkout','-b','feature')
        self.config('security', {'tools':[], 'mode':'advisory'}, trusted_base=True, base_ref='main')
        self.fake('semgrep', {'results':[], 'errors':[], 'paths':{'scanned':[]}})
        r, _, run, _ = self.scan('security'); self.assertEqual(r['exit_code'],2); self.assertEqual(run['tools'][0]['tool'],'semgrep')

    def lighthouse(self, lcp=3000):
        return {'audits':{'largest-contentful-paint':{'numericValue':lcp}, 'cumulative-layout-shift':{'numericValue':.01},
                          'total-blocking-time':{'numericValue':30},'total-byte-weight':{'numericValue':10000}},'categories':{'performance':{'score':.95}}}

    def test_perf_three_runs_budget_and_median(self):
        self.config('perf',dict(base_url='http://localhost:1234',pages=[dict(name='home',path='/')]))
        self.fake('lighthouse', self.lighthouse())
        # Different values per invocation, no server/browser needed.
        p = self.tools / 'lighthouse'; s = p.read_text(); s = s.replace('data = ', "counter=pathlib.Path('counter'); n=int(counter.read_text()) if counter.exists() else 0; counter.write_text(str(n+1))\ndata = ")
        s = s.replace('args = sys.argv', "data['audits']['largest-contentful-paint']['numericValue']=[1000,3000,5000][n%3]\nargs = sys.argv")
        p.write_text(s)
        r, f, run, _ = self.scan('perf'); self.assertEqual(r['exit_code'],0)
        self.assertEqual(run['metrics']['home|lcp'],dict(median=3000,values=[1000,3000,5000])); self.assertEqual(f[0]['severity'],'medium')

    def test_macos_chrome_for_testing_path(self):
        browser = self.repo / 'browsers/chromium-123/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'
        browser.parent.mkdir(parents=True); browser.touch()
        self.config('perf', dict(base_url='http://localhost:1234', pages=[dict(name='home', path='/')]))
        seen = []
        def run(tool, command, *args, **kwargs):
            seen.append(kwargs['env']['CHROME_PATH'])
            return self.lighthouse(1000)
        with patch.dict(os.environ, {'PLAYWRIGHT_BROWSERS_PATH': str(self.repo / 'browsers'), 'CHROME_PATH': ''}), patch.object(P.sys, 'platform', 'darwin'), patch.object(P.Runner, 'run', side_effect=run):
            result, _, _, _ = self.scan('perf')
        self.assertEqual(result['exit_code'], 0)
        self.assertTrue(seen)
        self.assertEqual(set(seen), {str(browser)})

    def test_perf_relative_regression(self):
        self.config('perf',dict(base_url='http://localhost:1234',pages=[dict(name='home',path='/')]))
        self.fake('lighthouse', self.lighthouse(1000)); _, f, run, _ = self.scan('perf')
        P.baseline_write(self.repo,'perf',f,run['metrics'],self.args)
        self.fake('lighthouse', self.lighthouse(1200)); _, f, _, _ = self.scan('perf')
        self.assertTrue(any(x['id']=='lcp' for x in f))

    def test_perf_nonlocal_refused(self):
        self.config('perf',dict(base_url='https://example.com',pages=[dict(name='home',path='/')]))
        r, _, run, _ = self.scan('perf'); self.assertEqual(r['exit_code'],3); self.assertTrue(run['tools'][0]['error'])

    def test_bundle_budget(self):
        self.config('perf',dict(build_dir='dist',budgets={'bundle_kb_gzip':.01})); self.write('dist/app.js', 'large javascript')
        _, f, run, _ = self.scan('perf'); self.assertIn('bundle|bundle',run['metrics']); self.assertEqual(f[0]['tool'],'bundle')

    def test_k6_threshold_failure(self):
        self.config('perf',dict(base_url='http://localhost:1234',k6=[dict(name='api',script='smoke.js')]))
        self.fake('k6',{'metrics':{'http_req_duration':{'thresholds':{'p(95)<500':False}}}},99)
        _, f, _, _ = self.scan('perf'); self.assertEqual(f[0]['severity'],'high')

    def integrity_base(self, text):
        self.write('tests/test_app.py',text); self.git('add','tests'); self.git('commit','-m','tests'); return self.git('rev-parse','HEAD')

    def test_integrity_deleted_function(self):
        self.integrity_base('def test_one():\n    assert True\ndef test_two():\n    assert True\n')
        self.write('tests/test_app.py','def test_one():\n    assert True\n')
        r,f,_,_ = self.scan('integrity'); self.assertEqual(r['exit_code'],2); self.assertIn('deleted-test-function',[x['id'] for x in f])

    def test_integrity_deleted_file(self):
        self.integrity_base('def test_one():\n    assert True\n'); (self.repo / 'tests/test_app.py').unlink()
        _,f,_,_ = self.scan('integrity'); self.assertIn('deleted-test-file',[x['id'] for x in f])

    def test_integrity_skip_only_assert_drop_runner(self):
        self.integrity_base('def test_one():\n    assert True\n')
        self.write('tests/test_app.py','@pytest.mark.skip\ndef test_one():\n    pass\n')
        self.write('tests/ui.test.js', "test.only('hi', () => {});")
        self.write('pytest.ini','[pytest]\naddopts=-x\n')
        _,f,_,_ = self.scan('integrity'); ids={x['id'] for x in f}
        self.assertTrue({'added-skip','added-only','zero-assertions','assertion-drop','runner-config'} <= ids)

    def test_integrity_added_test_is_fine(self):
        self.integrity_base('def test_one():\n    assert True\n')
        self.write('tests/test_app.py','def test_one():\n    assert True\ndef test_two():\n    assert True\n')
        _,f,_,_ = self.scan('integrity'); self.assertEqual(f,[])

    def test_waiver_base_only(self):
        self.integrity_base('def test_one():\n    assert True\n')
        self.write('tests/test_app.py','')
        _,f,_,_ = self.scan('integrity'); waiver={x['fingerprint']:'owner: replacement coverage' for x in f}
        self.write('.helix/integrity-waivers.json',json.dumps(waiver))
        _,f,_,_ = self.scan('integrity'); self.assertTrue(all(x['status']=='new' for x in f))
        self.git('add','.helix/integrity-waivers.json'); self.git('commit','-m','owner waiver')
        _,f,_,_ = self.scan('integrity'); self.assertTrue(all(x['status']=='waived' for x in f))

    def test_cli_exit_codes(self):
        self.config('security',{'tools':['gitleaks']}); self.fake('gitleaks',[dict(RuleID='key',File='f')],1)
        p = subprocess.run([sys.executable,str(ROOT / 'bin/helix'),'--repo',str(self.repo),'gate','security'],capture_output=True,text=True)
        self.assertEqual(p.returncode,2,p.stderr); self.assertEqual(json.loads(p.stdout)['status'],'FAIL')

    def test_snapshot_and_package_script(self):
        self.write('package.json','{"scripts":{"test":"pytest"},"version":"1"}'); self.git('add','package.json'); self.git('commit','-m','package')
        self.write('package.json','{"scripts":{"test":"pytest"},"version":"2"}')
        _,f,_,_ = self.scan('integrity'); self.assertEqual(f,[])
        self.write('package.json','{"scripts":{"test":"true"}}'); self.write('ui.snap','changed')
        _,f,_,_ = self.scan('integrity'); self.assertEqual({x['id'] for x in f},{'snapshot-change','runner-config'})

    def test_timeout_is_error(self):
        self.config('security', {'tools':['semgrep']}); self.fake('semgrep',{})
        with patch.object(P.subprocess, 'run', side_effect=subprocess.TimeoutExpired('semgrep', 1)):
            runner=P.Runner(self.repo); self.assertIsNone(runner.run('semgrep',['semgrep','scan']))
        self.assertEqual(runner.records[0]['status'],'error')

    def test_invalid_json_is_error(self):
        self.config('security', {'tools':['semgrep']}); self.fake('semgrep', [])
        r,_,_,_ = self.scan('security'); self.assertEqual(r['exit_code'],3)

    def test_perf_regression_reopens_baselined_breach(self):
        self.config('perf',dict(base_url='http://localhost:1234',pages=[dict(name='home',path='/')],mode='blocking',fail_on=['medium','high']))
        self.fake('lighthouse', self.lighthouse(3000)); _,f,run,_=self.scan('perf')
        P.baseline_write(self.repo,'perf',f,run['metrics'],self.args)
        self.fake('lighthouse', self.lighthouse(3500)); r,f,_,_=self.scan('perf')
        self.assertEqual(r['exit_code'],2); self.assertEqual(f[0]['status'],'new')

    def test_perf_noise_floor(self):
        metrics={'home|cls':dict(median=.018,values=[.018])}; old={'home|cls':dict(median=.01)}
        self.assertEqual(P.metric_findings(metrics,{},old),[])

    def test_k6_nonlocal_even_allowlisted(self):
        self.write('helix.json',json.dumps({'helix_version': VERSION, 'ux':{'allow_hosts':['staging.testhost']},'packs':{'perf':{'base_url':'https://staging.testhost','k6':[{'name':'api','script':'smoke.js'}]}}}))
        r,_,_,_=self.scan('perf'); self.assertEqual(r['exit_code'],3)

    def test_secret_fingerprint_survives_line_shift(self):
        self.config('security',{'tools':['gitleaks']}); self.write('key.txt','token=synthetic-value\n')
        self.fake('gitleaks',[dict(RuleID='token',File='key.txt',StartLine=1)],1)
        _,a,_,_=self.scan('security'); self.write('key.txt','\n\ntoken=synthetic-value\n')
        self.fake('gitleaks',[dict(RuleID='token',File='key.txt',StartLine=3)],1)
        _,b,_,_=self.scan('security'); self.assertEqual(a[0]['fingerprint'],b[0]['fingerprint'])

    def test_sca_transitive_aliases(self):
        fs=[P.sca('t','f','npm','p','1',v,'high','2',aliases) for v,aliases in [('CVE-1',[]),('CVE-2',[]),('GHSA-1',['CVE-1','CVE-2'])]]
        self.assertEqual(len(P.dedupe(fs)),1)

    def test_integrity_same_method_names_in_classes(self):
        self.integrity_base('class A:\n    def test_one(self):\n        assert True\nclass B:\n    def test_one(self):\n        assert True\n')
        self.write('tests/test_app.py','class A:\n    def test_one(self):\n        assert True\n')
        _,f,_,_=self.scan('integrity'); self.assertTrue(any(x['id']=='deleted-test-function' and 'B.test_one' in x['title'] for x in f))

    def test_checkpoint_report_copied(self):
        self.config('security',{'tools':['semgrep']}); self.fake('semgrep',{'results':[], 'errors':[], 'paths':{'scanned':[]}})
        r,_,_,_=P.scan(self.ctx,'security',self.args,'cp1')
        self.assertEqual(r['exit_code'],0); self.assertTrue((self.repo/'helix-evidence/cp1/security.md').exists())
        self.assertIn('findings',P.read_json(self.repo/'helix-evidence/cp1/security.json'))

    def test_report_reuses_evidence(self):
        self.config('security',{'tools':['semgrep']}); self.fake('semgrep',{'results':[], 'errors':[], 'paths':{'scanned':[]}})
        self.scan('security'); (self.tools/'semgrep').unlink()
        self.args.cmd='security'; self.args.action='report'; P.cmd_pack(self.ctx,self.args)
        self.assertTrue((self.repo/'output/report.md').exists())

    def test_readonly_diff_includes_new_file(self):
        loader=importlib.machinery.SourceFileLoader('helix_pack_cli', str(ROOT/'bin/helix'))
        spec=importlib.util.spec_from_loader(loader.name,loader); h=importlib.util.module_from_spec(spec)
        sys.modules[loader.name]=h; loader.exec_module(h)
        self.write('new.py','print("new")\n'); self.write('README','changed')
        before=self.git('status','--porcelain')
        diff=h.diff_since(self.ctx,'HEAD')
        self.assertIn('new.py',diff); self.assertIn('changed',diff)
        self.assertEqual(before,self.git('status','--porcelain'))

    def test_integrity_fixture_strings_are_not_skip_markers(self):
        self.write('tests/test_data.py', 'def test_data():\n    sample = "@pytest.mark.skip test.only( expect("\n    assert sample\n')
        self.write('tests/data.test.js', "test('data', () => {const sample = 'test.skip('; expect(sample).toBeTruthy();}); // test.only(\n")
        _, f, _, _ = self.scan('integrity'); self.assertEqual(f, [])


if __name__ == '__main__': unittest.main()
