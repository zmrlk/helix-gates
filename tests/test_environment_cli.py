"""Environment CLI stays read-only and never needs models, network or a project pin."""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_config as config
import helix_environment as environment
import helix_packs as packs
import helix_update


def load_cli():
    loader = importlib.machinery.SourceFileLoader('helix_environment_cli_test', str(ROOT / 'bin/helix'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    import helix_ux, helix_consistency, helix_security_deep
    bindings = [(item, getattr(item, 'H', None)) for item in (helix_ux, helix_consistency, helix_security_deep)]
    try:
        with patch.dict(sys.modules, {loader.name: module}):
            loader.exec_module(module)
    finally:
        for item, previous in bindings:
            item.H = previous
    return module


class EnvironmentCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / 'project'
        self.repo.mkdir()
        subprocess.run(['git', 'init', '-q'], cwd=self.repo, check=True, capture_output=True)
        self.write('package.json', json.dumps({'engines': {'node': '>=22'}, 'scripts': {'preinstall': 'touch NEVER_EXECUTE'}}))
        self.write('.nvmrc', '18.20.0\n')
        self.write('src/app.ts', 'export const value = process.env.API_KEY + process.env.MISSING_NAME;\n')
        self.write('.env.example', 'API_KEY=EXAMPLE_SECRET_VALUE\n')
        self.write('.env', 'API_KEY=REAL_DOTENV_SECRET_VALUE\n')
        self.addCleanup(config._overrides.pop, self.repo, None)
        self.cli = load_cli()

    def write(self, name, value):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def snapshot(self):
        return {p.relative_to(self.repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.repo.rglob('*') if p.is_file()}

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        code = 0
        argv = ['helix', '--repo', str(self.repo), '--offline', *map(str, args)]
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                result = self.cli.main()
                if isinstance(result, int): code = result
            except SystemExit as error:
                code = error.code or 0
        return code, stdout.getvalue(), stderr.getvalue()

    def test_unpinned_offline_json_and_external_artifacts_preserve_target(self):
        before = self.snapshot()
        out = self.root / 'report'
        original_open = Path.open
        def without_dotenv(path, *args, **kwargs):
            self.assertNotEqual(path.resolve(), self.repo / '.env', 'real dotenv must not be opened')
            return original_open(path, *args, **kwargs)
        with patch.object(environment, 'local_tool', side_effect=AssertionError('no-probe must not execute tools')), \
             patch.object(Path, 'open', without_dotenv):
            code, stdout, stderr = self.invoke('env', '--no-probe', '--json', '--out', out)
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report['status'], 'WARN')
        self.assertIn('MISSING_NAME', report['env_names']['missing_from_examples'])
        node = next(item for item in report['components'] if item['name'] == 'node')
        self.assertEqual(node['local']['status'], 'not_probed')
        self.assertEqual(node['production']['status'], 'unknown')
        self.assertTrue(any(item['kind'] == 'declaration_conflict' for item in node['conflicts']))
        self.assertEqual(json.loads((out / 'environment.json').read_text()), report)
        self.assertEqual((out / 'environment.md').read_text(), report['markdown'])
        self.assertNotIn('EXAMPLE_SECRET_VALUE', stdout + stderr + report['markdown'])
        self.assertNotIn('REAL_DOTENV_SECRET_VALUE', stdout + stderr + report['markdown'])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.repo / 'helix.json').exists())
        self.assertFalse((self.repo / 'NEVER_EXECUTE').exists())

    def test_incomplete_empty_target_exits_three_and_keeps_json_report(self):
        for path in self.repo.rglob('*'):
            if path.is_file() and '.git' not in path.relative_to(self.repo).parts:
                path.unlink()
        code, stdout, stderr = self.invoke('env', '--json', '--no-probe')
        self.assertEqual(code, 3, stderr)
        self.assertEqual(json.loads(stdout)['status'], 'INCOMPLETE')
        self.assertFalse((self.repo / '.helix').exists())

    def test_external_config_does_not_require_pin_or_reveal_values(self):
        cfg = self.root / 'outside-helix.json'
        cfg.write_text(json.dumps({'custom': {'API_KEY': 'CONFIG_SECRET_VALUE'}}))
        before = self.snapshot()
        code, stdout, stderr = self.invoke('--config', cfg, 'env', '--json', '--no-probe')
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout)['status'], 'WARN')
        self.assertNotIn('CONFIG_SECRET_VALUE', stdout + stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / '.helix-state').exists())

    def test_output_inside_target_or_alias_is_rejected_before_writing(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.repo, target_is_directory=True)
        before = self.snapshot()
        for out in (self.repo / 'report', alias / 'report'):
            with self.subTest(out=out):
                code, stdout, stderr = self.invoke('env', '--json', '--no-probe', '--out', out)
                self.assertEqual(code, 3)
                self.assertIn('poza repo', stderr)
                self.assertFalse((self.repo / 'report').exists())
        self.assertEqual(self.snapshot(), before)

    def test_external_output_leaf_symlink_never_overwrites_target(self):
        for artifact in ('environment.json', 'environment.md'):
            with self.subTest(artifact=artifact):
                self.write('.nvmrc', '18.20.0\n')
                out = self.root / artifact.replace('.', '-')
                out.mkdir()
                link = out / artifact
                link.symlink_to(self.repo / '.nvmrc')
                before = self.snapshot()
                code, stdout, stderr = self.invoke('env', '--json', '--no-probe', '--out', out)
                self.assertEqual(self.snapshot(), before, 'output symlink must not overwrite a target file')
                self.assertEqual(code, 3, stderr)
                self.assertTrue(link.is_symlink())

    def test_doctor_uses_requested_target_with_fake_local_probes_and_no_fetch(self):
        before = self.snapshot()
        production = self.root / 'production-evidence.json'
        production.write_text(json.dumps({'components': {'node': {'version': '22.3.0',
            'checked_at': '2020-01-01T00:00:00+00:00', 'evidence': 'EVIDENCE_SECRET_VALUE'}}}))
        def local(component):
            self.assertEqual(component, 'node')
            return {'status': 'available', 'version': '20.12.0', 'scope': 'local', 'tag': 'VERIFIED'}
        def process(argv, **kwargs):
            self.assertTrue(argv[0] in ('node', 'git'), argv)
            return subprocess.CompletedProcess(argv, 1, '', '')
        with patch.object(environment, 'local_tool', side_effect=local) as probe, \
             patch.object(packs, 'tool_health', return_value={'status': 'missing', 'reason': 'synthetic'}), \
             patch.object(packs.shutil, 'which', return_value=None), \
             patch.object(packs.subprocess, 'run', side_effect=process), \
             patch.object(helix_update, 'inspect', return_value={'status': 'nie sprawdzono'}) as inspect:
            code, stdout, stderr = self.invoke('doctor', '--prod-evidence', production)
        self.assertEqual(code, 0, stderr)
        inspect.assert_called_once_with(fetch=False)
        probe.assert_called_once_with('node')
        report = json.loads(stdout)['environment']
        node = next(item for item in report['components'] if item['name'] == 'node')
        self.assertEqual(node['local']['version'], '20.12.0')
        self.assertEqual(node['production']['version'], '22.3.0')
        self.assertEqual(node['production']['status'], 'provided')
        self.assertTrue(any(item['path'] == '.nvmrc' for item in node['declarations']))
        self.assertNotIn('SECRET_VALUE', stdout + stderr)
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
