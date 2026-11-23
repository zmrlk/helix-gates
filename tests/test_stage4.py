"""Stage 4 regression cases: offline synthetic repositories and fake tool processes."""
import copy
import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_owner_report as owner
import helix_quality_domains as domains
import helix_runtime_mutation as mutation
import helix_license_adapters as licenses
from helix_contracts import VERSION

FIX = ROOT / 'tests/fixtures/stage4'


class Stage4Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def finding(self, **kw):
        return dict(dict(id='R1', file='src/api.py', line=3, severity='high', confidence='possible',
            lens='security', why='Brak odmowy dostępu obcego użytkownika.', fix='Sprawdź scope rekordu.', evidence=['src/api.py:3']), **kw)

    def test_weighted_does_not_hide_high_or_missing_execution(self):
        rows = [dict(id='a', status='PASS', score=100, execution_verified=True), dict(id='b', status='not-run', score=100)]
        result = owner.weighted(rows, {'a': 9, 'b': 1}, [self.finding()])
        self.assertEqual(result['score'], 90)
        self.assertEqual(result['readiness'], 'BLOCKED')
        self.assertEqual(len(result['blockers']), 2)
        self.assertEqual(result['counts']['not-run'], 1)
        self.assertEqual(owner.weighted([])['readiness'], 'BLOCKED')

    def test_na_requires_reason_and_is_not_not_run(self):
        with self.assertRaises(ValueError): owner.weighted([dict(id='seo',status='N/A')])
        result = owner.weighted([dict(id='seo',status='N/A',reason='Prywatne API')])
        self.assertEqual(result['counts'], {'not-run':0,'N/A':1,'executed':0})
        self.assertEqual(result['readiness'], 'N/A')
        for weight in (0,-1,True,float('nan'),float('inf')):
            with self.assertRaises(ValueError): owner.weighted([dict(id='a')], {'a':weight})

    def test_failed_execution_never_earns_score(self):
        result = owner.weighted([dict(id='a',status='FAIL',score=100,execution_verified=True)])
        self.assertEqual(result['score'],0)
        self.assertEqual(result['readiness'],'BLOCKED')
        for score in (-1,101,float('nan'),True):
            with self.assertRaises(ValueError): owner.weighted([dict(id='a',status='PASS',score=score,execution_verified=True)])

    def test_bounded_owner_report_and_complete_gap_plan(self):
        findings = [self.finding(id='R'+str(i),line=i+1) for i in range(300)]
        data = dict(findings=findings*2, owner_report=dict(decisions=['wybór'],obsolete=['old']*300),
                    coverage=dict(files_read=98,files_total=100,status='INCOMPLETE'),
                    gap_assignments={'R0':dict(owner='maintainer',due_date='2026-12-01',effort='2h',dependencies=['ADR-1'],closure='Negatywny test scope')})
        before = copy.deepcopy(data)
        result = owner.build(data, {'status':'FAIL'}, {'status':'FAIL'}, 'full.json')
        text = owner.markdown(result)
        self.assertEqual(data,before)
        self.assertEqual(len(result['gaps']),300)
        self.assertEqual(text.count('ASSUMPTION high/possible'),5)
        self.assertIn('98/100',text)
        self.assertIn('(full.json)',text)
        self.assertEqual(result['gaps'][0]['owner'],'maintainer')
        self.assertEqual(result['gaps'][1]['owner'],'do przypisania')
        self.assertEqual(result['gaps'][1]['due_date'],'do przypisania')
        self.assertEqual(result['gaps'][0]['closure'],'Negatywny test scope')

    def test_source_only_and_wrong_sha_no_execution_credit(self):
        (self.root/'log').write_text('test passed')
        run=dict(status='passed',exit=0,who='runner',where='tmp',sha='other',command='unittest',log='log')
        data=dict(sha='current',assessment=dict(controls=[dict(id='security',status='PASS',score=100,run=run)]))
        self.assertEqual(owner.build(data,{}, {},'x',self.root)['assessment']['score'],0)
        run['sha']='current'
        with patch('helix_release.git',return_value='current'):
            self.assertEqual(owner.build(data,{}, {},'x',self.root)['assessment']['score'],100)
        (self.root/'log').unlink()
        self.assertEqual(owner.build(data,{}, {},'x',self.root)['assessment']['score'],0)

    def test_domains_are_separate_not_run_and_na(self):
        profile=json.loads((FIX/'profile.json').read_text())
        result=domains.analyze(json.loads((FIX/'sources.json').read_text()),profile)
        checks={c['id']:c for c in result['checks']}
        self.assertEqual(checks['seo-meta']['status'],'N/A')
        self.assertEqual(checks['eu-consent']['status'],'N/A')
        self.assertEqual(checks['pl-ksef']['status'],'not-run')
        self.assertIn('src/invoice.go:2',checks['pl-ksef']['evidence'])
        self.assertEqual(result['test_pyramid']['files'],dict(unit=1,integration=1,e2e=1,unclassified=0))
        self.assertTrue(all(c['score']==0 for c in result['checks']))
        self.assertTrue(all(f[k] for f in result['findings'] for k in ('file','line','severity','confidence','why','fix')))
        self.assertTrue(result['findings'])

    def test_tracker_signal_and_guarded_negative(self):
        unsafe = '<script src="https://www.googletagmanager.com/gtag/js"></script>'
        safe = '<script type="text/plain" data-consent="analytics" src="https://www.googletagmanager.com/gtag/js"></script>'
        self.assertEqual([r['line'] for r in domains.analyze({'index.html':unsafe})['findings']], [1])
        self.assertEqual(domains.analyze({'index.html':safe})['findings'], [])
        self.assertEqual(domains.analyze({'index.html':unsafe},{'tracking':dict(applicable=False,reason='Fixture bez trackerów w dostarczanym profilu')})['findings'], [])

    def test_part_area_profile_weights(self):
        rows=[dict(id='a',part='api',area='security',status='PASS',score=100,execution_verified=True),
              dict(id='b',part='web',area='UX',status='not-run')]
        self.assertEqual(owner.weighted(rows,dict(parts=dict(api=2),areas=dict(security=2)))['score'],80)
        with self.assertRaises(ValueError): owner.weighted(rows,dict(parts=dict(api=0)))

    def test_unknown_profile_never_becomes_na(self):
        result=domains.analyze({})
        self.assertTrue(all(c['status']=='not-run' for c in result['checks']))
        self.assertTrue(all(not c['evidence'] for c in result['checks']))
        self.assertEqual({c['area'] for c in result['checks']},{'tests','compliance','observability','finops','data','seo'})
        with self.assertRaises(ValueError): domains.analyze({}, {'public_web':dict(applicable=False)})

    def test_domains_signal_is_not_proof_of_compliance(self):
        result=domains.analyze({'app.vue':'<meta name="description"> sitemap robots application/ld+json consent AI KSeF WCAG GDPR'})
        self.assertTrue(any(c['evidence'] for c in result['checks']))
        self.assertTrue(all(c['status']=='not-run' and c['score']==0 for c in result['checks']))
        self.assertEqual(domains.analyze({'tests/unit/x.py':'assert result == 1'})['findings'],[])

    def test_existing_quality_audit_includes_domains(self):
        import helix_quality
        result=helix_quality.analyze(self.root,sources={'test_unit.py':'time.sleep(1)'},coverage={})
        self.assertIn('domains',result)
        self.assertIn('QA-FLAKY-SIGNAL',{f['id'] for f in result['findings']})
        self.assertEqual(result['execution_credit'],0)

    def mutation_stats(self, **kw):
        data=dict(total=0,killed=0,survived=0,no_tests=0,skipped=0,suspicious=0,timeout=0,check_was_interrupted_by_user=0,segfault=0)
        data.update(kw)
        return json.dumps(data)

    def test_mutation_parsers_reject_empty_and_skipped(self):
        self.assertEqual(mutation.measured('stryker','{"files":{}}')['status'],'incomplete')
        raw=json.dumps({'files':{'src.ts':{'mutants':[dict(status='Killed'),dict(status='Survived')]}}})
        self.assertEqual(mutation.measured('stryker',raw)['mutation_score'],50)
        raw=json.dumps({'files':{'src.ts':{'mutants':[dict(status='Killed'),dict(status='Timeout')]}}})
        self.assertEqual(mutation.measured('stryker',raw)['status'],'incomplete')
        self.assertEqual(mutation.measured('mutmut',self.mutation_stats(total=1,skipped=1))['status'],'incomplete')
        self.assertEqual(mutation.measured('mutmut',self.mutation_stats(total=2,killed=1,survived=1))['mutation_score'],50)

    def test_mutation_budget_offline_and_copy(self):
        (self.root/'app.py').write_text('assert 1')
        calls=[]
        def fake(argv,cwd,env,seconds):
            calls.append(argv)
            self.assertNotEqual(cwd,self.root)
            self.assertEqual(cwd,cwd.resolve())
            self.assertEqual((cwd/'app.py').read_text(),'assert 1')
            self.assertEqual(env['UV_OFFLINE'],'1')
            self.assertLessEqual(seconds,30)
            if argv[-1]=='export-cicd-stats':
                (cwd/'mutants').mkdir()
                (cwd/'mutants/mutmut-cicd-stats.json').write_text(self.mutation_stats(total=1,killed=1))
            return ''
        with patch.object(mutation,'locate',side_effect=lambda name:'/tool/'+name), patch.object(mutation,'command',side_effect=fake):
            result=mutation.run(self.root,'mutmut',30)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['killed'],1)
        self.assertTrue(all(a[:3]==['/tool/unshare','--net','--'] for a in calls))
        self.assertEqual((self.root/'app.py').read_text(),'assert 1')

    def test_mutation_rejects_report_symlink_outside_disposable_copy(self):
        external=self.root/'outside.json'
        external.write_text(self.mutation_stats(total=1,killed=1))
        def fake(argv,cwd,env,seconds):
            if argv[-1]=='export-cicd-stats':
                (cwd/'mutants').mkdir()
                (cwd/'mutants/mutmut-cicd-stats.json').symlink_to(external)
            return ''
        with patch.object(mutation,'locate',return_value='/fake'),patch.object(mutation,'command',side_effect=fake):
            result=mutation.run(self.root,'mutmut',30)
        self.assertEqual(result['status'],'error')
        self.assertEqual(result['score'],0)
        self.assertTrue(external.is_file())

    def test_mutation_no_namespace_or_tool_is_not_run(self):
        with patch.object(mutation,'locate',return_value=None):
            self.assertEqual(mutation.run(self.root,'mutmut')['status'],'not-run')
        with patch.object(mutation,'locate',return_value='/fake'),patch.object(mutation,'command',side_effect=ValueError('sandbox unavailable')) as cmd:
            self.assertEqual(mutation.run(self.root,'stryker')['status'],'not-run')
            self.assertEqual(cmd.call_count,1)
        for budget in (0,-1,301,True,float('nan')):
            with self.assertRaises(ValueError): mutation.run(self.root,'mutmut',budget)

    def test_mutation_timeout_is_zero(self):
        with patch.object(mutation,'locate',return_value='/fake'),patch.object(mutation,'command',side_effect=['',subprocess.TimeoutExpired('tool',1)]):
            result=mutation.run(self.root,'mutmut',1)
        self.assertEqual(result['status'],'timeout')
        self.assertEqual(result['score'],0)

    def test_license_adapter_inventory_not_certification(self):
        (self.root/'LICENSE').write_text('Synthetic permissive license')
        def fake(argv, **kw):
            path=Path(argv[argv.index('--json')+1])
            path.write_text(json.dumps(dict(files=[dict(path='LICENSE',detected_license_expression_spdx='MIT') ])))
            return subprocess.CompletedProcess([],0,'','')
        with patch.object(licenses,'locate',return_value='/tool/scancode'),patch.object(licenses.subprocess,'run',side_effect=fake) as run:
            result=licenses.scan(self.root,'scancode')
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['score'],0)
        self.assertEqual(result['licenses'],[dict(file='LICENSE',license='MIT')])
        self.assertNotEqual(run.call_args.kwargs['cwd'],self.root)
        self.assertEqual((self.root/'LICENSE').read_text(),'Synthetic permissive license')
        self.assertNotIn('Synthetic',json.dumps(result))

    def test_license_missing_bad_json_fail_closed(self):
        with patch.object(licenses,'locate',return_value=None):
            self.assertEqual(licenses.scan(self.root,'scancode')['status'],'unavailable')
        with patch.object(licenses,'locate',return_value='/tool/licensee'):
            self.assertEqual(licenses.scan(self.root,'licensee')['status'],'not-run')
        def fake(argv,**kw):
            Path(argv[argv.index('--json')+1]).write_text('invalid')
            return subprocess.CompletedProcess([],0,'','')
        with patch.object(licenses,'locate',return_value='/tool/scancode'),patch.object(licenses.subprocess,'run',side_effect=fake):
            self.assertEqual(licenses.scan(self.root,'scancode')['status'],'error')

    def cli_main(self,args):
        # CLI routing without executing any providers or committing fixture repos.
        module=runpy.run_path(str(ROOT/'bin/helix'),run_name='stage4_cli')
        with patch.object(sys,'argv',['helix','--repo',str(self.root),*args]),contextlib.redirect_stdout(io.StringIO()):
            return module['main']()

    def test_handoff_legacy_and_explicit_run_cli(self):
        import helix_runs
        (self.root/'.git').mkdir()
        (self.root/'helix.json').write_text(json.dumps(dict(helix_version=VERSION)))
        for args in (['handoff','--run-id','run-1'],['handoff','run','--run-id','run-1']):
            with patch.object(helix_runs,'handoff') as handoff:
                self.cli_main(args)
                self.assertEqual(handoff.call_args.args[1].run_id,'run-1')
        # Actual renderer still handles the old run format, not just parser routing.
        from types import SimpleNamespace
        state=self.root/'.helix/runs/run-1/state.json'; state.parent.mkdir(parents=True)
        state.write_text(json.dumps(dict(run_id='run-1',pack='security',units={},out=str(self.root/'out'))))
        path=helix_runs.handoff(SimpleNamespace(repo=self.root),SimpleNamespace(run_id='run-1',out=None))
        self.assertIn('security',path.read_text())

    def test_handoff_continuity_cli_routes_only_named_actions(self):
        import helix_continuity
        for action in ('write','read','check'):
            with patch.object(helix_continuity,'dispatch',return_value=0) as dispatch:
                with self.assertRaises(SystemExit) as caught: self.cli_main(['handoff',action])
                self.assertEqual(caught.exception.code,0)
                self.assertEqual(dispatch.call_args.args[0].action,action)

    def test_new_audit_writes_owner_current_without_touching_source(self):
        import helix_new
        project=self.root/'project'; project.mkdir()
        (project/'app.py').write_text('def run():\n    return 1\n')
        out=self.root/'out'
        helix_new.audit(project,out)
        report=json.loads((out/'owner-current.json').read_text())
        self.assertEqual((project/'app.py').read_text(),'def run():\n    return 1\n')
        self.assertEqual(report['assessment']['score'],0)
        self.assertTrue(report['gaps'])
        self.assertIn('owner-current.json',(out/'owner-current.md').read_text())
        self.assertTrue({'security','qa','senior_developer','architect','product_manager','ux_designer','ui_designer','ops_data','tech_writer'} <= set(report['lenses']))


if __name__=='__main__': unittest.main()
