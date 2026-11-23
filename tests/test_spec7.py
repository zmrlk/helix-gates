"""SPEC7 regressions use fixtures/mocked providers; no network or provider CLI."""
import argparse, importlib.machinery, importlib.util, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
from helix_contracts import VERSION
loader = importlib.machinery.SourceFileLoader('spec7_helix', str(ROOT / 'bin/helix'))
spec = importlib.util.spec_from_loader(loader.name, loader)
H = importlib.util.module_from_spec(spec); sys.modules[loader.name] = H; loader.exec_module(H)
import helix_packs as P
import helix_security_deep as D
import helix_consistency as C

class Regression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.repo = self.root / 'target'; self.repo.mkdir()
        self.git('init', '-q'); self.git('config', 'user.name', 'Test'); self.git('config', 'user.email', 'test@example.test')
        (self.repo / 'helix.json').write_text(json.dumps({'helix_version': VERSION}))
        (self.repo / 'font.woff2').write_bytes(b'\x80\xff\x00font')
        (self.repo / 'test_api.py').write_text('def test_ok():\n    assert True\n')
        self.git('add', '.'); self.git('commit', '-qm', 'fixture')
    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True, text=True).stdout
    def test_external_state_scan_never_writes_target(self):
        before = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob('*') if p.is_file()}
        p = subprocess.run([sys.executable, str(ROOT / 'bin/helix'), '--repo', str(self.repo), '--state-dir', str(self.root / 'state'), 'integrity', 'scan'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        after = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertTrue(list((self.root / 'state/evidence').glob('*/coverage-ledger.json')))
    def test_binary_base_does_not_hide_deleted_assertion(self):
        (self.repo / 'test_api.py').write_text('def test_ok():\n    pass\n')
        findings, metrics = P.integrity(self.repo, {}, 'HEAD', P.Runner(self.repo))
        self.assertIn('zero-assertions', [f['id'] for f in findings])
        self.assertEqual(metrics['coverage'][0]['unit'], 'font.woff2')
    def test_sca_preserves_versions_importers_tools_and_duplicate_identity(self):
        fs = [P.sca(tool, source, 'npm', 'postcss', version, 'CVE-X', 'high', '9', []) for tool, source, version in [('trivy','a/lock','8.4'),('trivy','b/lock','8.5'),('osv-scanner','c/lock','8.4')]]
        result = P.dedupe(fs)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['versions'], ['8.4','8.5'])
        self.assertEqual(len(result[0]['occurrences']), 3)
    def test_secret_is_hypothesis(self):
        f = P.finding('security', 'gitleaks', 'key', 'high', 'possible key', category='secret')
        self.assertEqual((f['verdict'], f['tag']), ('needs_validation', 'ASSUMPTION'))
    def test_runner_categorizes_and_redacts_version_failure(self):
        runner = P.Runner(self.repo, version_timeout=71)
        failed = SimpleNamespace(returncode=1, stdout='', stderr='Permission denied token=SUPERSECRET')
        with patch.object(P.shutil, 'which', return_value='/fake'), patch.object(P.subprocess, 'run', return_value=failed) as run:
            self.assertIsNone(runner.run('semgrep', ['semgrep','scan']))
        self.assertEqual(run.call_args.kwargs['timeout'], 71)
        self.assertEqual(runner.records[0]['error_category'], 'version')
        self.assertEqual(runner.records[0]['stderr'], 'permission')
        self.assertNotIn('SUPERSECRET', json.dumps(runner.records))
    @unittest.skipUnless(shutil.which("node"), "Node validator unavailable")
    def test_provider_attempts_saved_and_hunter_failure_returns_error(self):
        from datetime import datetime, timezone
        from test_security_deep import NormalResources
        checked_at = datetime.now(timezone.utc).isoformat()
        proofs = [dict(provider=provider, model=H.DEFAULT_CFG['models'][provider][0],
                       family=D.RP.model_family(provider, H.DEFAULT_CFG['models'][provider][0]),
                       status='available', method='short_call', checked_at=checked_at)
                  for provider in ('codex', 'gemini')]
        cfg = json.loads(json.dumps(H.DEFAULT_CFG))
        cfg['data_egress'] = dict(status='approved', allowed_providers=['codex', 'gemini'], exclude_paths=[])
        ctx = SimpleNamespace(repo=self.repo, cfg=cfg, availability={'models': proofs}, resource_governor=NormalResources())
        args = SimpleNamespace(hunter='codex', verifier='gemini', max_candidates=8, scope=None, profile='standard', out=str(self.root / 'audit'))
        with patch.object(D, 'H', H), patch.object(D, 'run_root', return_value=self.root / 'runs'), patch.object(D, 'validate', return_value=''), patch.object(H, 'call_codex', side_effect=H.ProviderError('network token=SUPERSECRET')) as hunter:
            out, meta = D.run(ctx, args)
            hunter.assert_called_once()
            self.assertEqual(meta['provider_attempts'][0]['status'], 'error')
            self.assertEqual(meta['run_status'], 'error')
            data = (out / 'provider-errors.json').read_text()
            self.assertIn('network', data); self.assertNotIn('SUPERSECRET', data)
            with patch.object(D, 'run', return_value=(out, meta)), self.assertRaises(SystemExit) as e: D.cmd_deep(ctx, args)
            self.assertEqual(e.exception.code, 3)
    def test_attack_surface_batches_cover_late_api_and_record_binary(self):
        (self.repo / 'aaa.txt').write_text('documentation\n' * 1800)
        (self.repo / 'zzz_api.py').write_text('def upload():\n    pass\n' * 700)
        self.git('add', '.')
        batches, ledger = D.context_plan(self.repo, ['.'], 'quick')
        self.assertIn('zzz_api.py', batches[0][1])
        self.assertGreaterEqual(len(batches), 2)
        self.assertTrue(any(u['unit'] == 'font.woff2' and u['status'] == 'uncovered' for u in ledger))
    def test_consistency_static_flag_skips_browser_for_scan_and_all(self):
        ctx = SimpleNamespace(repo=self.repo, cfg={})
        for action in ('scan','all'):
            args = SimpleNamespace(action=action, static_only=True, out=str(self.root / action))
            with patch.object(C, 'run_pipeline', return_value=(None,None,[],None)) as pipeline, patch.object(C, 'build_report', return_value={'top':[], 'findings':[], 'status':'COMPLETE'}):
                C.cmd_consistency(ctx, args)
            self.assertFalse(pipeline.call_args.kwargs['runtime']); self.assertTrue(pipeline.call_args.kwargs['static'])
    def test_aggregate_severity_matches_json_and_report(self):
        f = C.finding('raw-element','medium','raw input','st:raw:input:a',layer='static',count=5)
        C.ADOPTION['input'] = 0
        result = C.aggregate_static([f])
        self.assertEqual(result[0]['severity'], 'medium')  # aggregation preserves severity; counts are not stronger evidence
        ctx = SimpleNamespace(repo=self.repo, cfg={})
        out = self.root / 'aggregate-report'; out.mkdir()
        with patch.object(C, 'render_html', return_value=''), patch.object(C, 'contact_sheet'):
            rep = C.build_report(ctx, C.cfg(ctx), out, None, None, [f], None)
        emitted = json.loads((out / 'findings.json').read_text())
        self.assertEqual(emitted, rep['findings'])
        self.assertEqual(rep['top'][0]['severity'], emitted[0]['severity'])
    def test_missing_scanner_is_explicit_incomplete(self):
        runner = P.Runner(self.repo)
        with patch.object(P.shutil, 'which', return_value=None): runner.run('trivy', ['trivy','fs'])
        result = P.evaluate('security', [], {'mode':'blocking','fail_on':['high']}, runner.records, False)
        self.assertEqual(result['status'], 'INCOMPLETE'); self.assertFalse(result['pass'])
    def test_missing_yaml_produces_skip_artifacts(self):
        import helix_dependencies as deps
        file = self.root / 'flows.yaml'; file.write_text('flows: []')
        with patch.dict(sys.modules, {'yaml': None}), patch.object(deps, 'node_module', return_value=None):
            with self.assertRaises(deps.MissingDependency) as e: deps.load_yaml(file)
        deps.skipped(self.root / 'out', e.exception)
        self.assertEqual(json.loads((self.root / 'out/coverage-ledger.json').read_text())[0]['status'], 'skipped')
    def test_no_machine_specific_paths(self):
        for name in ('helix','ux.cjs','consistency.cjs','setup-browsers.sh'):
            self.assertNotIn('/home/example/', (ROOT / 'bin' / name).read_text())

if __name__ == '__main__': unittest.main()
