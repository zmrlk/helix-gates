"""Portable regressions for installer boundaries, with no real tools or network."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_tools_manager import FakeExecutor, M


class ToolsInstallBoundaryTests(unittest.TestCase):
    def test_system_temp_alias_accepts_absolute_and_relative_expected_targets(self):
        original = Path.is_symlink
        for target in ('/private/tmp', 'private/tmp'):
            with self.subTest(target=target), patch.object(Path, 'is_symlink', lambda p: True if str(p) == '/tmp' else original(p)), \
                 patch.object(M.os, 'readlink', return_value=target):
                self.assertEqual(M._canonical('/tmp/helix/package-lock.json'), Path('/private/tmp/helix/package-lock.json'))
        with patch.object(Path, 'is_symlink', lambda p: True if str(p) == '/tmp' else original(p)), \
             patch.object(M.os, 'readlink', return_value='private/foreign'):
            with self.assertRaisesRegex(M.InstallError, 'UNSAFE_PATH'): M._canonical('/tmp/helix/lock')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / 'isolated-tools'
        self.executor = FakeExecutor(self.base)
        self.executor.prepare_pins()
        pins = patch.object(M, 'PIN_ROOT', self.executor.pins)
        pins.start()
        self.addCleanup(pins.stop)
        platform = patch.multiple(M.platform, system=lambda: 'Darwin', machine=lambda: 'arm64')
        platform.start()
        self.addCleanup(platform.stop)
        process = patch.object(subprocess, 'Popen', side_effect=AssertionError('real subprocess forbidden'))
        process.start()
        self.addCleanup(process.stop)

    def install_with_dependency_link(self, target):
        execute = self.executor.run

        def run(argv, **kwargs):
            result = execute(argv, **kwargs)
            if 'ci' in argv:
                directory = Path(kwargs['cwd'])
                dependency = directory / 'node_modules/knip/dependency.js'
                dependency.unlink()
                dependency.symlink_to(target(directory))
            return result

        self.executor.run = run
        return M.install(['knip'], yes=True, tools_root=self.root, executor=self.executor)

    def test_dependency_cannot_reference_unhashed_private_home(self):
        def target(directory):
            source = directory / 'home/untracked-loader.js'
            source.write_text('BOUNDARY_UNHASHED_CANARY')
            return '../../home/untracked-loader.js'

        result = self.install_with_dependency_link(target)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['tools'][0]['reason_code'], 'INSTALLED_SYMLINK_ESCAPE')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))
        self.assertFalse((self.root / 'active.json').exists())
        self.assertFalse(any('--reporter' in call['argv'] for call in self.executor.calls))

    def test_internal_link_requires_unchanged_target_bytes(self):
        def target(directory):
            (directory / 'node_modules/knip/owned.js').write_text('owned dependency')
            return 'owned.js'

        self.assertEqual(self.install_with_dependency_link(target)['status'], 'COMPLETE')
        resolved = M.resolve_installed('knip', tools_root=self.root)
        self.assertIsNotNone(resolved)
        self.assertFalse(resolved['usable'])  # A fake installation is never actual tool evidence.
        receipt = Path(resolved['receipt'])
        (receipt.parent / 'node_modules/knip/owned.js').write_text('changed dependency')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))

    def test_npm_dependency_cannot_use_interpreter_link_exception(self):
        result = self.install_with_dependency_link(lambda _: self.executor.runtime / 'python3')
        self.assertEqual(result['tools'][0]['reason_code'], 'INSTALLED_SYMLINK_ESCAPE')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))
        self.assertFalse(any('--reporter' in call['argv'] for call in self.executor.calls))

    def test_read_and_write_remain_anchored_after_parent_swap(self):
        original = os.open
        for operation in ('read', 'write'):
            with self.subTest(operation=operation):
                parent = self.base / ('owned-' + operation)
                retained = self.base / ('retained-' + operation)
                outside = self.base / ('outside-' + operation)
                parent.mkdir()
                outside.mkdir()
                (outside / 'value').write_bytes(b'FOREIGN_CANARY')
                if operation == 'read':
                    (parent / 'value').write_bytes(b'OWNED')
                swaps = []

                def swap(name, flags, *args, **kwargs):
                    if name == 'value' and kwargs.get('dir_fd') is not None and not swaps:
                        parent.rename(retained)
                        parent.symlink_to(outside, target_is_directory=True)
                        swaps.append(True)
                    return original(name, flags, *args, **kwargs)

                with patch.object(M.os, 'open', side_effect=swap):
                    if operation == 'read':
                        self.assertEqual(M._read(parent / 'value'), b'OWNED')
                    else:
                        M._write(parent / 'value', b'OWNED')
                self.assertEqual(swaps, [True])
                self.assertEqual((retained / 'value').read_bytes(), b'OWNED')
                self.assertEqual((outside / 'value').read_bytes(), b'FOREIGN_CANARY')

    def test_atomic_activation_does_not_follow_swapped_parent(self):
        parent, retained, outside = (self.base / name for name in ('active', 'retained', 'outside'))
        parent.mkdir()
        outside.mkdir()
        (parent / 'selection.json').write_text('{"old":true}')
        (outside / 'selection.json').write_text('{"foreign":true}')
        original = os.replace

        def swap(source, destination, **kwargs):
            parent.rename(retained)
            parent.symlink_to(outside, target_is_directory=True)
            self.assertIsNotNone(kwargs.get('src_dir_fd'))
            self.assertEqual(kwargs.get('src_dir_fd'), kwargs.get('dst_dir_fd'))
            return original(source, destination, **kwargs)

        with patch.object(M.os, 'replace', side_effect=swap):
            M._atomic(parent / 'selection.json', {'selected': True})
        self.assertEqual(json.loads((retained / 'selection.json').read_text()), {'selected': True})
        self.assertEqual(json.loads((outside / 'selection.json').read_text()), {'foreign': True})

    def test_directory_creation_does_not_follow_swapped_parent(self):
        parent, retained, outside = (self.base / name for name in ('install', 'retained', 'outside'))
        parent.mkdir()
        outside.mkdir()
        original = os.mkdir
        swaps = []

        def swap(name, *args, **kwargs):
            if name == 'new-installation' and not swaps:
                parent.rename(retained)
                parent.symlink_to(outside, target_is_directory=True)
                swaps.append(True)
                self.assertIsNotNone(kwargs.get('dir_fd'))
            return original(name, *args, **kwargs)

        with patch.object(M.os, 'mkdir', side_effect=swap):
            M._mkdir(parent / 'new-installation')
        self.assertEqual(swaps, [True])
        self.assertTrue((retained / 'new-installation').is_dir())
        self.assertFalse((outside / 'new-installation').exists())

    def test_normal_launcher_exit_still_cleans_owned_process_group(self):
        process = Mock(pid=431, returncode=0)
        process.wait.return_value = 0
        with patch.object(M.subprocess, 'Popen', return_value=process) as spawn, patch.object(M.os, 'killpg') as kill:
            result = M.Executor().run(['/synthetic/tool'], cwd=self.base, env={}, timeout=1)
        self.assertEqual(result.returncode, 0)
        kill.assert_called_once_with(431, M.signal.SIGKILL)
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])

    def test_interrupt_keeps_original_error_and_cleans_owned_group(self):
        interrupt = KeyboardInterrupt('synthetic interrupt')
        process = Mock(pid=432, returncode=0)
        process.wait.side_effect = [interrupt, 0]
        with patch.object(M.subprocess, 'Popen', return_value=process) as spawn, patch.object(M.os, 'killpg') as kill:
            with self.assertRaises(KeyboardInterrupt) as raised:
                M.Executor().run(['/synthetic/tool'], cwd=self.base, env={}, timeout=1)
        self.assertIs(raised.exception, interrupt)
        kill.assert_called_once_with(432, M.signal.SIGKILL)
        self.assertTrue(spawn.call_args.kwargs['close_fds'])
        self.assertEqual(spawn.call_args.kwargs['pass_fds'], ())
        self.assertEqual(spawn.call_args.kwargs['stdin'], subprocess.DEVNULL)


if __name__ == '__main__':
    unittest.main()
