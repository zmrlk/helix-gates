"""Execution provenance is retained by scans, gates and durable run state."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_environment as environment
import helix_packs as packs
from helix_contracts import VERSION
H = runpy.run_path(str(ROOT / 'bin/helix'))


class PackProvenance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.repo = self.home / 'repo'; self.repo.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Fixture'); self.git('config', 'user.email', 'fixture@example.test')
        self.config = {'helix_version': VERSION, 'packs': {'security': {'tools': ['gitleaks']}}}
        (self.repo / 'helix.json').write_text(json.dumps(self.config))
        (self.repo / 'app.py').write_text('print("fixture")\n')
        self.git('add', '.'); self.git('commit', '-qm', 'fixture')
        self.head = self.git('rev-parse', 'HEAD')
        self.evidence = self.home / 'evidence'; self.evidence.mkdir()
        self.ctx = SimpleNamespace(repo=self.repo, state_dir=self.home / 'state', evidence_root=self.evidence,
            external_state=True, cfg=self.config, state=lambda cp: {}, cp=lambda cp: {},
            ev=lambda cp: self.evidence, test_cmd=lambda: None)
        self.args = argparse.Namespace(out=str(self.home / 'scan'), trusted_base=False, base=None,
            no_start=True, accept_secret=[], reason=None, offline=True, no_cache=True, checkpoint=None, which='security')
        fake_dir = self.home / 'tools'; fake_dir.mkdir()
        fake = fake_dir / 'gitleaks'
        fake.write_text('#!' + sys.executable + '''
import json, pathlib, sys
if '--version' in sys.argv:
    print('gitleaks version 8.22.0'); raise SystemExit(0)
pathlib.Path(sys.argv[sys.argv.index('-r') + 1]).write_text('[]')
''')
        fake.chmod(0o755)
        self.env = patch.dict(os.environ, {'PATH': str(fake_dir) + os.pathsep + os.environ['PATH']})
        self.env.start(); self.addCleanup(self.env.stop)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True).strip()

    def test_scan_gate_and_state_share_actual_tool_version_and_target(self):
        result, _, record, out = packs.scan(self.ctx, 'security', self.args)
        provenance = record['provenance']
        self.assertEqual(provenance['target_head'], self.head)
        self.assertEqual(provenance['helix_version'], VERSION)
        self.assertEqual(provenance['models'], [])
        self.assertIn('8.22.0', json.dumps(provenance['tools']['gitleaks']))
        self.assertEqual(result['provenance'], provenance)
        self.assertEqual(json.loads((out / 'run.json').read_text())['provenance'], provenance)
        self.assertEqual(json.loads((out / 'gate.json').read_text())['provenance'], provenance)
        self.assertEqual(self.ctx._pack_session.data['provenance'], provenance)
        self.assertIn(self.head, (out / 'report.md').read_text())
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_gate_error_keeps_identity_without_inventing_provider_execution(self):
        self.ctx.cfg['providers'] = {'implementer': 'codex'}
        with patch.object(environment, 'local_tool', side_effect=AssertionError('hidden probe')):
            result = H['gate_behavior'](self.ctx, 'cp1')
            self.ctx.cfg['visual'] = {'enabled': False}
            skipped = H['gate_visual'](self.ctx, 'cp1')
        for value in (result, skipped):
            self.assertEqual(value['provenance']['target_head'], self.head)
            self.assertEqual(value['provenance']['models'], [])
        self.assertFalse(result['pass'])
        self.assertTrue(skipped['skipped'])
        self.assertEqual(json.loads((self.evidence / 'behavior.json').read_text())['provenance'], result['provenance'])

    def test_review_precheck_failure_writes_provenance(self):
        workflow = H['helix_workflow']
        with patch.object(workflow, 'check_connections', return_value=True), patch.object(workflow, 'precheck', return_value={'pass': False}):
            result = H['gate_review'](self.ctx, 'cp1')
        self.assertFalse(result['pass'])
        self.assertEqual(result['provenance']['target_head'], self.head)
        self.assertEqual(json.loads((self.evidence / 'review.json').read_text())['provenance'], result['provenance'])

    def test_gate_pack_keeps_provenance(self):
        self.args.which = 'security'
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
            packs.gate_pack(self.ctx, self.args)
        self.assertEqual(stopped.exception.code, 0)
        gate = json.loads((Path(self.args.out) / 'gate.json').read_text())
        self.assertEqual(gate['provenance']['target_head'], self.head)
        self.assertIn('8.22.0', json.dumps(gate['provenance']['tools']['gitleaks']))

    def test_failed_pack_still_records_target_and_unknown_tool_version(self):
        self.config['packs']['security']['tools'] = ['missing-fixture-tool']
        (self.repo / 'helix.json').write_text(json.dumps(self.config))
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
            packs.gate_pack(self.ctx, self.args)
        self.assertEqual(stopped.exception.code, 3)
        gate = json.loads((Path(self.args.out) / 'gate.json').read_text())
        self.assertEqual(gate['status'], 'ERROR')
        self.assertEqual(gate['provenance']['target_head'], self.head)
        self.assertTrue(gate['provenance']['target_dirty'])
        self.assertIsNone(gate['provenance']['tools']['gitleaks']['version'])

    def test_truth_gate_keeps_checker_model_receipt(self):
        (self.evidence / 'truth.json').write_text(json.dumps({'kind': 'report', 'systems': [], 'claims': []}))
        (self.evidence / 'truth-check.json').write_text(json.dumps({'false_claims': [], 'break_risks': [],
            '_used': {'provider': 'gemini', 'model': 'synthetic-gemini'}}))
        result = H['gate_truth'](self.ctx, 'cp1')
        self.assertEqual(result['provenance']['target_head'], self.head)
        self.assertIn('synthetic-gemini', json.dumps(result['provenance']['models']))
        self.assertEqual(json.loads((self.evidence / 'truth-gate.json').read_text())['provenance'], result['provenance'])


class ScreenshotProvenance(unittest.TestCase):
    @unittest.skipUnless(__import__('shutil').which('node'), 'Node is required for the fake Playwright fixture')
    def test_runner_reports_loaded_library_and_actual_browser_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / 'playwright'; module.mkdir()
            (module / 'package.json').write_text('{"name":"playwright","version":"1.48.2","main":"index.cjs"}')
            (module / 'index.cjs').write_text('''module.exports = {chromium:{launch:async()=>({
              version:()=>"130.0.6723.58", close:async()=>{}, newPage:async()=>({
                goto:async()=>{}, screenshot:async({path})=>require('fs').writeFileSync(path,'synthetic')
              })
            })}};''')
            result = subprocess.run(['node', str(ROOT / 'bin/shot.cjs'), 'http://unused.invalid', str(root / 'shot'), '10', '10', '[]'],
                env=dict(os.environ, HELIX_PLAYWRIGHT=str(module)), capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = next(line for line in result.stdout.splitlines() if line.startswith('HELIX_TOOL_VERSIONS='))
            tools = environment.normalize_tools(json.loads(receipt.split('=', 1)[1]))
            self.assertEqual(tools['playwright']['version'], '1.48.2')
            self.assertEqual(tools['chromium']['version'], '130.0.6723.58')
            self.assertTrue(tools['node']['used'])
            self.assertEqual((root / 'shot').read_text(), 'synthetic')


if __name__ == '__main__': unittest.main()
