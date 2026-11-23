"""Supply-chain attacks from the review; all downloads/executables are fakes."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import test_tools_manager as fixtures
from test_tools_manager import M


class ReviewToolPins(unittest.TestCase):
    setUp = fixtures.ToolsManagerTests.setUp
    install = fixtures.ToolsManagerTests.install

    def pin_path(self, name):
        return self.executor.pins / 'darwin-arm64' / ('cp312' if M.CATALOG[name]['channel'] == 'wheel' else '') / (name + '.json')

    def test_postinstall_is_never_run_and_native_bytes_must_match_pin(self):
        self.executor.fault = 'evil_postinstall'
        self.assertEqual(self.install(['ast-grep'])['status'], 'COMPLETE')
        receipt = M.resolve_installed('ast-grep', tools_root=self.root)
        self.assertIn('/cli-darwin-arm64/ast-grep', receipt['argv_prefix'][0])
        self.assertFalse(any(any(str(arg).endswith('/postinstall.js') for arg in row['argv']) for row in self.executor.calls))
        pin = json.loads(self.pin_path('ast-grep').read_text()); pin['native']['sha256'] = '0' * 64
        self.pin_path('ast-grep').write_text(json.dumps(pin))
        self.assertIsNone(M.resolve_installed('ast-grep', tools_root=self.root))
        self.assertEqual(self.install(['ast-grep'])['tools'][0]['reason_code'], 'PACKAGE_HASH_MISMATCH')

    def test_missing_repo_pin_refuses_before_any_package_resolution(self):
        for name in ('knip', 'mutmut'):
            with self.subTest(name=name):
                self.pin_path(name).unlink(); self.executor.calls.clear()
                self.assertEqual(self.install([name])['tools'][0]['reason_code'], 'APPROVED_PIN_MISSING')
                self.assertFalse(any('ci' in row['argv'] or 'download' in row['argv'] for row in self.executor.calls))

    def test_unpinned_transitive_wheel_is_not_self_signed(self):
        original = self.executor.run
        def replace_download(argv, **kwargs):
            result = original(argv, **kwargs)
            if 'download' in argv:
                wheels = Path(argv[argv.index('--dest') + 1])
                (wheels / 'extra-1.0.0-py3-none-any.whl').write_bytes(self.executor.wheel('extra', '1.0.0'))
            return result
        self.executor.run = replace_download
        result = self.install(['mutmut'])
        self.assertEqual(result['tools'][0]['reason_code'], 'PACKAGE_HASH_MISSING')
        self.assertFalse(any('install' in row['argv'] for row in self.executor.calls))

    def test_changed_transitive_wheel_is_rejected_before_install(self):
        original = self.executor.run
        def replace_download(argv, **kwargs):
            result = original(argv, **kwargs)
            if 'download' in argv:
                path = Path(argv[argv.index('--dest') + 1]) / 'fixture_dependency-1.0.0-py3-none-any.whl'
                path.write_bytes(path.read_bytes() + b'payload')
            return result
        self.executor.run = replace_download
        self.assertEqual(self.install(['mutmut'])['tools'][0]['reason_code'], 'PACKAGE_HASH_MISMATCH')

    def test_download_and_install_use_same_preapproved_hash_lock(self):
        self.assertEqual(self.install(['mutmut'])['status'], 'COMPLETE')
        calls = [r['argv'] for r in self.executor.calls if 'download' in r['argv'] or 'install' in r['argv']]
        self.assertEqual(len(calls), 2)
        for argv in calls:
            self.assertIn('--require-hashes', argv); self.assertIn('--only-binary=:all:', argv)
        self.assertEqual(calls[0][-1], calls[1][-1])

    def test_registry_tarball_cannot_change_pinned_lock(self):
        self.executor.fault = 'bad_tarball'
        self.assertEqual(self.install(['knip'])['tools'][0]['reason_code'], 'PACKAGE_HASH_MISMATCH')
        self.assertFalse(any('ci' in row['argv'] or '--package-lock-only' in row['argv'] for row in self.executor.calls))

    def test_npm_lock_is_bound_to_reviewed_bytes(self):
        path = self.executor.pins / 'darwin-arm64/knip.package-lock.json'
        path.write_bytes(path.read_bytes() + b' ')
        self.assertEqual(self.install(['knip'])['tools'][0]['reason_code'], 'PIN_MISMATCH')
        self.assertFalse(any('ci' in row['argv'] for row in self.executor.calls))

    def test_changed_launchers_during_smoke_never_get_sealed(self):
        original = self.executor.run
        for name in ('knip', 'jscpd'):
            def mutate(argv, **kwargs):
                result = original(argv, **kwargs)
                if kwargs['cwd'].name == 'fixture':
                    path = Path(argv[1] if name == 'knip' else argv[0])
                    path.write_text('changed after expected stdout')
                return result
            self.executor.run = mutate
            with self.subTest(name=name):
                self.assertEqual(self.install([name])['tools'][0]['reason_code'], 'INSTALLED_TREE_CHANGED')
                self.assertIsNone(M.resolve_installed(name, tools_root=self.root))

    def test_missing_native_hash_fails_closed(self):
        pin = json.loads(self.pin_path('ast-grep').read_text()); pin.pop('native')
        self.pin_path('ast-grep').write_text(json.dumps(pin))
        self.assertEqual(self.install(['ast-grep'])['tools'][0]['reason_code'], 'PACKAGE_HASH_MISSING')


class ReviewCiLock(unittest.TestCase):
    def test_repository_pin_graphs_and_locks_are_consistent(self):
        import helix_tools_manager as manager
        for name, spec in manager.CATALOG.items():
            key = 'darwin-arm64' + ('/cp312' if spec['channel'] == 'wheel' else '')
            pin, _ = manager._approved_pin(name, key)
            if spec['channel'] == 'wheel':
                rows = manager._wheel_pins(pin)
                self.assertTrue(any(row['name'] == manager._normalized(spec['package']) and row['version'] == spec['version'] for row in rows.values()))
            else:
                path = manager.PIN_ROOT / key / (name + '.package-lock.json')
                self.assertEqual(manager._file_digest(path), pin['lock_sha256'])
                self.assertTrue(manager._npm_lock(path, spec))
        ci = manager.PIN_ROOT / 'darwin-arm64/cp312'
        rows = json.loads((ci / 'ci.wheels.json').read_text())
        self.assertEqual(manager._requirements({r['filename']: r for r in rows}), (ci / 'ci.requirements.lock').read_bytes())
        self.assertTrue({'pyyaml', 'pillow', 'semgrep', 'zizmor'} <= {r['name'] for r in rows})
        for key in ('linux-x86_64/cp312', 'linux-arm64/cp312', 'darwin-x86_64/cp312', 'darwin-arm64/cp313'):
            with self.subTest(key=key), self.assertRaisesRegex(manager.InstallError, 'APPROVED_PIN_MISSING'):
                manager._approved_pin('mutmut', key)

    def test_ci_uses_hashes_and_wheels_for_entire_dependency_graph(self):
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('ci_pin_installer', root / 'scripts/install_ci_dependencies.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with patch.object(module.sys, 'version_info', (3, 12)), patch.object(module.platform, 'system', return_value='Linux'), \
             patch.object(module.platform, 'machine', return_value='x86_64'), patch.object(Path, 'is_file', return_value=True), \
             patch.object(Path, 'read_text', return_value='pinned==1 --hash=sha256:' + '0' * 64):
            argv = module.command(root)
        self.assertIn('--require-hashes', argv); self.assertIn('--only-binary=:all:', argv)
        self.assertTrue(argv[-1].endswith('linux-x86_64/cp312/ci.requirements.lock'))
        workflow = (root / '.github/workflows/ci.yml').read_text()
        self.assertIn('run: python3 scripts/install_ci_dependencies.py', workflow)
        self.assertNotIn('pip install -r requirements.txt', workflow)
        with patch.object(module.sys, 'version_info', (3, 12)), patch.object(Path, 'is_file', return_value=False):
            with self.assertRaisesRegex(ValueError, 'approved CI wheel lock missing'): module.command(root)


if __name__ == '__main__': unittest.main()
