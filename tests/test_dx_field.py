"""External configuration, offline execution and bounded Git reads, no network."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_config as config
import helix_packs as packs
import helix_audit_context as audit
from helix_contracts import VERSION


class FieldDX(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / 'project'; self.repo.mkdir()
        self.git('init', '-q')
        self.write('test_api.py', 'def test_item():\n    assert True\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        self.cfg = self.root / 'external.json'
        self.cfg.write_text(json.dumps({'helix_version': VERSION, 'packs': {'security': {'tools': ['semgrep', 'trivy']}}}))
        self.addCleanup(config._overrides.pop, self.repo, None)

    def write(self, name, text):
        path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, text=True, capture_output=True).stdout

    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'bin/helix'), '--repo', str(self.repo),
                               '--state-dir', str(self.root / 'state'), '--config', str(self.cfg),
                               '--offline', *args], capture_output=True, text=True)

    def test_external_config_and_integrity_leave_target_unchanged(self):
        before = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob('*') if p.is_file()}
        result = self.cli('integrity', 'scan', '--out', str(self.root / 'integrity'))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        after = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse((self.repo / 'helix.json').exists())

    def test_external_config_reaches_static_audit_and_pack_policy(self):
        self.cfg.write_text(json.dumps({'helix_version': VERSION, 'profile': 'XL', 'packs': {'integrity': {'fail_on': ['medium']}}}))
        config.configure(self.repo, self.cfg)
        self.assertEqual(audit.config(self.repo)['profile'], 'XL')
        args = type('Args', (), {'trusted_base': False})()
        self.assertEqual(packs.policy(self.repo, 'integrity', args)[1]['fail_on'], ['medium'])

    def test_invalid_external_config_and_pin_fail(self):
        for value in ('[]', '{', '{"helix_version":"obsolete"}'):
            self.cfg.write_text(value)
            result = self.cli('integrity', 'scan')
            self.assertNotEqual(result.returncode, 0)
        alias = self.root / 'alias.json'; alias.symlink_to(self.cfg)
        with self.assertRaises(ValueError): config.configure(self.repo, alias)

    def test_offline_security_records_unexecuted_tools_as_error(self):
        result = self.cli('security', 'scan', '--out', str(self.root / 'scan'))
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = json.loads((self.root / 'scan/run.json').read_text())
        self.assertEqual({r['error_category'] for r in run['tools']}, {'offline'})
        self.assertTrue(all(r['command'] == [] for r in run['tools']))

    def test_offline_refuses_models_updates_and_target_execution(self):
        for argv in [('plan', 'change'), ('security', 'deep'), ('update',), ('truth', 'suite', 'cp1', 'before'), ('runtime', 'run', '--project', str(self.repo), '--out', str(self.root / 'runtime'))]:
            with self.subTest(argv=argv):
                result = self.cli(*argv)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('offline', result.stderr)


    def test_offline_consistency_gate_uses_external_state(self):
        self.write('frontend/src/Page.svelte', '<p>Hello</p>')
        self.cfg.write_text(json.dumps({'helix_version': VERSION, 'consistency': {'base_url': 'http://127.0.0.1:1', 'pages': [{'path': '/'}]}}))
        before = self.git('status', '--porcelain')
        result = self.cli('gate', 'consistency')
        self.assertNotIn('Playwright', result.stdout + result.stderr)
        self.assertEqual(before, self.git('status', '--porcelain'))
        self.assertFalse((self.repo / 'helix-evidence').exists())
        self.assertTrue(list((self.root / 'state/evidence').glob('consistency-gate-*/static.json')))

    def test_doctor_version_health_and_no_fetch(self):
        from unittest.mock import MagicMock
        import helix_update
        with patch.object(packs, 'tool_health', return_value={'status': 'broken', 'reason': 'ca-certs'}), patch.object(packs.shutil, 'which', return_value=None), patch.object(packs.subprocess, 'run', return_value=MagicMock(returncode=1)), patch.object(helix_update, 'inspect', return_value={'status': 'nie sprawdzono'}) as inspect, contextlib.redirect_stdout(io.StringIO()) as out:
            packs.doctor(offline=True)
        inspect.assert_called_once_with(fetch=False)
        result = json.loads(out.getvalue())
        self.assertEqual(result['helix']['version'], VERSION)
        self.assertEqual(result['semgrep'], 'broken')

    def test_ca_certs_diagnostic_retains_cause_but_no_payload(self):
        failure = subprocess.CompletedProcess([], 2, '', 'Fatal: ca-certs: empty trust anchors token=PRIVATE_VALUE')
        with patch.object(packs.shutil, 'which', return_value='/fake/semgrep'), patch.object(packs.subprocess, 'run', return_value=failure):
            result = packs.tool_health('semgrep')
        self.assertEqual(result['status'], 'broken')
        self.assertIn('empty trust anchors', result['reason'])
        self.assertNotIn('PRIVATE_VALUE', json.dumps(result))

    def test_tool_version_keeps_major_after_v_prefix(self):
        response = subprocess.CompletedProcess([], 0, 'k6 v1.3.0 (go1.25.3)', '')
        with patch.object(packs.shutil, 'which', return_value='/fake/k6'), patch.object(packs.subprocess, 'run', return_value=response):
            self.assertEqual(packs.tool_health('k6')['version'], '1.3.0')

    def test_integrity_batches_changed_blobs_and_handles_newline_names(self):
        for i in range(30): self.write(f'src/file{i}.py', 'value = 1\n')
        self.write('tests/test_odd\nname.py', 'def test_ok():\n    assert True\n')
        self.git('add', '.'); self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'more')
        self.write('tests/test_odd\nname.py', 'def test_ok():\n    pass\n')
        self.write('test_api.py', 'def test_item():\n    pass\n')
        original = subprocess.run
        with patch.object(packs.subprocess, 'run', wraps=original) as calls:
            findings, metrics = packs.integrity(self.repo, {}, 'HEAD', packs.Runner(self.repo))
        commands = [c.args[0] for c in calls.call_args_list]
        self.assertFalse(any(c[1] == 'show' for c in commands))
        self.assertEqual(sum(c[1] == 'cat-file' for c in commands), 1)
        self.assertEqual(metrics['base_blobs_read'], 2)
        self.assertEqual(sum(f['id'] == 'zero-assertions' for f in findings), 2)

    def test_unchanged_integrity_does_not_read_any_base_blob(self):
        with patch.object(packs, 'base_blobs', wraps=packs.base_blobs) as batch:
            findings, metrics = packs.integrity(self.repo, {}, 'HEAD', packs.Runner(self.repo))
        self.assertEqual(findings, [])
        self.assertEqual(metrics['base_blobs_read'], 0)
        self.assertEqual(batch.call_args.args[2], set())

    def test_mac_system_alias_keeps_private_project_directories_protected(self):
        self.assertIn('private', audit.user_parts('/work/private/source.py'))
        with patch.object(audit.sys, 'platform', 'darwin'):
            self.assertNotIn('private', audit.user_parts('/private/var/folders/sample/source.py'))
        outside = self.root / 'secret.txt'; outside.write_text('not source')
        linked = self.repo / 'linked.py'; linked.symlink_to(outside)
        with self.assertRaises(OSError): audit.safe_read(linked)
