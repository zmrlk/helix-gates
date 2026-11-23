"""Offline update contracts; every remote is a disposable local bare repo."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_update as U


class UpdateTests(unittest.TestCase):
    def git(self, repo, *args):
        return subprocess.run(['git', '-C', str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.origin, self.seed, self.local = [root / p for p in ('origin.git', 'seed', 'local')]
        self.git(root, 'init', '--bare', str(self.origin))
        self.git(root, 'init', str(self.seed))
        self.git(self.seed, 'checkout', '-b', 'main')
        self.configure(self.seed)
        self.commit(self.seed, 'base')
        self.git(self.seed, 'remote', 'add', 'origin', str(self.origin))
        self.git(self.seed, 'push', '-u', 'origin', 'main')
        self.git(root, 'clone', '-b', 'main', str(self.origin), str(self.local))
        self.configure(self.local)

    def configure(self, repo):
        self.git(repo, 'config', 'user.name', 'Test')
        self.git(repo, 'config', 'user.email', 'test@example.test')

    def commit(self, repo, name):
        (repo / name).write_text(name)
        self.git(repo, 'add', name)
        self.git(repo, 'commit', '-m', name)

    def advance(self):
        self.commit(self.seed, 'remote-change')
        self.git(self.seed, 'push', 'origin', 'main')

    def run_update(self, **kwargs):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            result = U.update(repo=self.local, **kwargs)
        return result, stream.getvalue()

    def test_current(self):
        info = U.inspect(self.local)
        self.assertEqual(info['status'], 'aktualny')
        self.assertEqual(info['branch'], 'main')
        self.assertFalse(info['dirty'])
        self.assertEqual(info['commit'], self.git(self.local, 'rev-parse', '--short', 'HEAD'))
        self.assertEqual(self.run_update()[0], 0)

    def test_remote_ahead_and_update(self):
        self.advance()
        self.assertIn('jest 1 nowych commitów', U.inspect(self.local)['status'])
        doctor = Mock()
        code, text = self.run_update(doctor=doctor)
        self.assertEqual(code, 0)
        self.assertIn('remote-change', text)
        doctor.assert_called_once_with()
        self.assertEqual(self.git(self.local, 'rev-parse', 'HEAD'), self.git(self.seed, 'rev-parse', 'HEAD'))

    def test_check_does_not_fetch_or_modify(self):
        self.advance()
        before = self.git(self.local, 'rev-parse', 'HEAD', 'origin/main')
        with patch.object(U, 'git', wraps=U.git) as runner:
            self.assertEqual(self.run_update(check=True)[0], 0)
        self.assertFalse(any(call.args[1] in ('fetch', 'pull') for call in runner.call_args_list))
        self.assertEqual(before, self.git(self.local, 'rev-parse', 'HEAD', 'origin/main'))

    def test_dirty_tracked_and_untracked(self):
        for name in ('base', 'untracked'):
            with self.subTest(name=name):
                path = self.local / name
                path.write_text('changed')
                before = self.git(self.local, 'rev-parse', 'HEAD')
                self.assertEqual(self.run_update()[0], 1)
                self.assertEqual(before, self.git(self.local, 'rev-parse', 'HEAD'))
                if name == 'base':
                    path.write_text('base')
                else:
                    path.unlink()

    def test_diverged(self):
        self.advance()
        self.commit(self.local, 'local-change')
        before = self.git(self.local, 'rev-parse', 'HEAD')
        self.assertIn('rozjechała', U.inspect(self.local)['status'])
        self.assertEqual(self.run_update()[0], 1)
        self.assertEqual(before, self.git(self.local, 'rev-parse', 'HEAD'))

    def test_missing_and_unreachable_remote(self):
        self.git(self.local, 'remote', 'set-url', 'origin', str(self.local / 'absent.git'))
        self.assertEqual(U.inspect(self.local)['status'], 'nie sprawdzono')
        self.assertEqual(self.run_update()[0], 1)
        self.git(self.local, 'remote', 'remove', 'origin')
        self.assertEqual(U.inspect(self.local)['status'], 'nie sprawdzono')
        self.assertEqual(self.run_update()[0], 1)

    def test_timeout_is_nonfatal_in_doctor(self):
        real = U.git
        def timeout(repo, *args):
            if args[0] == 'fetch':
                raise subprocess.TimeoutExpired('git', 10)
            return real(repo, *args)
        with patch.object(U, 'git', side_effect=timeout):
            self.assertEqual(U.inspect(self.local)['status'], 'nie sprawdzono')


if __name__ == '__main__':
    unittest.main()
