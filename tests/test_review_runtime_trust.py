"""Runtime admission covers trusted managers and refuses repository/PATH traps."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_tools_manager import M


class ReviewRuntimeTrust(unittest.TestCase):
    def test_homebrew_admin_group_write_is_recorded_not_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); cellar = root / 'Cellar'; cellar.mkdir(mode=0o775); cellar.chmod(0o775)
            binary = cellar / 'node'; binary.write_bytes(b'fixture'); binary.chmod(0o755)
            gid = cellar.stat().st_gid
            with patch.object(M, 'RUNTIME_ROOTS', (str(root),)), patch.object(M.platform, 'system', return_value='Darwin'), \
                 patch.object(M.os, 'getgroups', return_value=[gid]), patch('grp.getgrgid', return_value=SimpleNamespace(gr_name='admin')), \
                 patch.object(M.shutil, 'which', return_value=str(binary)):
                self.assertEqual(M.Executor().locate('node'), str(binary))
                _, observation = M._runtime_trust(binary)
                self.assertTrue(any(row['path'] == str(cellar) and row['group'] == 'admin' for row in observation))

    def test_fnm_resolved_home_location_is_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); binary = root / '.local/share/fnm/node-versions/v22/installation/bin/node'
            binary.parent.mkdir(parents=True); binary.write_bytes(b'fixture'); binary.chmod(0o755)
            with patch.object(M.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(root))), patch.object(M.shutil, 'which', return_value=str(binary)):
                self.assertEqual(M.Executor().locate('node'), str(binary))

    def test_home_environment_override_does_not_move_trusted_managers(self):
        with tempfile.TemporaryDirectory() as account, tempfile.TemporaryDirectory() as attacker:
            fake = Path(attacker).resolve(); binary = fake / '.local/share/fnm/node-versions/v22/installation/bin/node'
            binary.parent.mkdir(parents=True); binary.write_bytes(b'fixture'); binary.chmod(0o755)
            with patch.dict(os.environ, {'HOME': str(fake)}), \
                 patch.object(M.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(Path(account).resolve()))), \
                 patch.object(M.shutil, 'which', return_value=str(binary)):
                with self.assertRaisesRegex(M.InstallError, 'UNTRUSTED_RUNTIME'): M.Executor().locate('node')

    def test_staff_group_write_is_refused_on_macos(self):
        # Every local macOS account is in staff, so staff-writable means writable by other users.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); shared = root / 'Cellar'; shared.mkdir(); shared.chmod(0o775)
            binary = shared / 'node'; binary.write_bytes(b'fixture'); binary.chmod(0o755)
            gid = shared.stat().st_gid
            with patch.object(M, 'RUNTIME_ROOTS', (str(root),)), patch.object(M.platform, 'system', return_value='Darwin'), \
                 patch.object(M.os, 'getgroups', return_value=[gid]), patch('grp.getgrgid', return_value=SimpleNamespace(gr_name='staff')), \
                 patch.object(M.shutil, 'which', return_value=str(binary)):
                with self.assertRaisesRegex(M.InstallError, 'UNTRUSTED_RUNTIME'): M.Executor().locate('node')

    def test_repository_and_world_writable_runtime_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); repo = root / 'repo'; repo.mkdir(); (repo / '.git').mkdir()
            binary = repo / 'node'; binary.write_bytes(b'fixture'); binary.chmod(0o755)
            with patch.object(M, 'RUNTIME_ROOTS', (str(root),)), patch.object(M.Path, 'cwd', return_value=repo), \
                 patch.object(M.shutil, 'which', return_value=str(binary)):
                with self.assertRaisesRegex(M.InstallError, 'UNTRUSTED_RUNTIME'): M.Executor().locate('node')
            binary = root / 'npm'; binary.write_bytes(b'fixture'); binary.chmod(0o777)
            with patch.object(M, 'RUNTIME_ROOTS', (str(root),)), patch.object(M.shutil, 'which', return_value=str(binary)):
                with self.assertRaisesRegex(M.InstallError, 'UNTRUSTED_RUNTIME'): M.Executor().locate('npm')

    def test_untrusted_path_entry_is_not_an_executable_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {'PATH': temporary}), patch.object(M.shutil, 'which', return_value=None) as which:
                self.assertIsNone(M.Executor().locate('node'))
                self.assertNotIn(temporary, which.call_args.kwargs['path'].split(os.pathsep))


if __name__ == '__main__': unittest.main()
