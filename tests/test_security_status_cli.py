"""The public reminder stays read-only and does not construct a model context."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_provider_plan import load_helix
import helix_security_status as status


class StatusCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / 'source'; self.repo.mkdir()
        self.state = self.root / 'state'
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '--allow-empty', '-qm', 'fixture'], check=True)
        self.cli = load_helix()

    def call(self, args):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['helix', '--repo', str(self.repo), '--state-dir', str(self.state), '--offline', *args]), \
             patch.object(self.cli, 'Ctx', side_effect=AssertionError('reminder must not create Ctx')), \
             patch.object(self.cli, 'ask', side_effect=AssertionError('no model call')), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as result:
                self.cli.main()
        return result.exception.code, output.getvalue()

    def test_status_json_without_plan_or_pin_never_creates_state(self):
        # A historical pin cannot block reading an existing status.
        (self.repo / 'helix.json').write_text('{"helix_version":"0.0.0"}')
        before = sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob('*'))
        code, output = self.call(['status', '--json'])
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data['status'], 'NO_BASELINE')
        self.assertIsNone(data['commits_since_complete'])
        self.assertEqual(data['next_command'][-1], 'full')
        self.assertFalse(self.state.exists())
        self.assertEqual(before, sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob('*')))

    def test_reminder_is_one_line(self):
        code, output = self.call(['status', '--reminder-only'])
        self.assertEqual(code, 0)
        self.assertEqual(len(output.splitlines()), 1)
        self.assertIn('full', output)
        self.assertFalse(self.state.exists())

    def test_hook_install_is_only_the_explicit_branch(self):
        with patch.object(status, 'install_hook', return_value={'status': 'installed'}) as install:
            code, output = self.call(['hooks', 'install', '--post-commit'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['status'], 'installed')
        install.assert_called_once_with(str(self.repo), str(self.state), helix_path=Path(self.cli.__file__).resolve(), config_path=None)

    def test_missing_explicit_hook_flag_does_not_install(self):
        with patch.object(status, 'install_hook') as install, contextlib.redirect_stderr(io.StringIO()):
            code, _ = self.call(['hooks', 'install'])
        self.assertEqual(code, 2); install.assert_not_called()

    def test_external_config_is_preserved_in_suggested_command(self):
        config = self.root / 'helix.proposed.json'
        config.write_text('{"helix_version":"0.0.0","providers":{"planner":"grok-cli"}}')
        code, output = self.call(['status', '--json', '--config', str(config)])
        self.assertEqual(code, 0)
        command = json.loads(output)['next_command']
        self.assertIn('--config', command)
        self.assertEqual(command[command.index('--config') + 1], str(config))
        self.assertFalse(self.state.exists())

    def test_hook_git_timeout_is_observable_without_a_traceback(self):
        with patch.object(status, 'install_hook', side_effect=subprocess.TimeoutExpired('git', 10)), \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            code, _ = self.call(['hooks', 'install', '--post-commit'])
        self.assertEqual(code, 3)
        self.assertIn('ERROR', errors.getvalue())
        self.assertNotIn('Traceback', errors.getvalue())

    def test_invalid_git_target_returns_observable_error(self):
        code, _ = self.call(['status', '--json'])
        self.assertEqual(code, 0)
        with patch.object(status, 'report', return_value={'status':'ERROR'}):
            code, output = self.call(['status', '--json'])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output)['status'], 'ERROR')
