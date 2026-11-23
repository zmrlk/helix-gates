"""Read-only security status and explicit hooks on small local Git fixtures."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_security_status as status


class SecurityStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        self.state = self.base / 'state'
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.head = self.commit('initial')

    def git(self, *args, repo=None):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=repo or self.repo, text=True).strip()

    def commit(self, value):
        (self.repo / 'app.txt').write_text(value)
        self.git('add', 'app.txt')
        self.git('commit', '-qm', value)
        return self.git('rev-parse', 'HEAD')

    def receipt(self, head=None):
        head = head or self.head
        run = self.base / 'completed-run'
        run.mkdir(exist_ok=True)
        meta = dict(target=str(self.repo), run_status='complete', source_ref={'head': head, 'dirty': False},
                    profile='standard', scope_paths=['.'], mode='full')
        path = run / 'run-metadata.json'
        path.write_text(json.dumps(meta))
        cursor = status.cursor_path(self.repo, self.state)
        cursor.parent.mkdir(parents=True, exist_ok=True)
        cursor.write_text(json.dumps(dict(schema_version=1, target=str(self.repo), run_status='complete', head=head,
                                         run=str(run), completed_at=datetime.now(timezone.utc).isoformat())))
        return cursor, path

    def test_missing_baseline_needs_full_without_creating_state_or_refreshing_index(self):
        index = self.repo / '.git/index'
        before = (index.read_bytes(), index.stat().st_mtime_ns)
        result = status.report(self.repo, self.state)
        self.assertEqual(result['status'], 'NO_BASELINE')
        self.assertIsNone(result['commits_since_complete'])
        self.assertEqual(result['next_command'][-1], 'full')
        self.assertEqual(result['execution'], {'models': 0, 'source_scans': 0, 'writes': 0})
        self.assertFalse(self.state.exists())
        self.assertFalse((self.repo / '.helix').exists())
        self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), before)
        line = status.text_report(result, reminder_only=True)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertIn('nieznane', line); self.assertIn('daily/release', line)
        self.assertEqual(status.text_report(result), line)

    def test_current_and_two_new_commits_have_exact_counter_and_commands(self):
        self.receipt()
        current = status.report(self.repo, self.state)
        self.assertEqual(current['status'], 'CURRENT')
        self.assertEqual(current['commits_since_complete'], 0)
        self.assertFalse(current['review_due'])
        reminder = status.text_report(current, reminder_only=True)
        self.assertEqual(len(reminder.splitlines()), 1)
        self.assertIn('commitów od COMPLETE 0', reminder)
        self.assertIn('--mode daily', reminder); self.assertIn('--mode release', reminder)
        self.commit('second'); self.commit('third')
        result = status.report(self.repo, self.state)
        self.assertEqual(result['status'], 'DUE')
        self.assertEqual(result['relation'], 'ancestor')
        self.assertEqual(result['commits_since_complete'], 2)
        self.assertEqual(result['next_command'][-1], 'daily')
        self.assertIn(str(self.state), result['commands']['release'])

    def test_same_head_with_dirty_files_never_means_current(self):
        self.receipt()
        (self.repo / 'app.txt').write_text('unreviewed change')
        result = status.report(self.repo, self.state)
        self.assertEqual(result['commits_since_complete'], 0)
        self.assertEqual(result['status'], 'DUE')
        self.assertTrue(result['dirty']); self.assertTrue(result['review_due'])

    def test_diverged_or_missing_revision_is_unknown_not_zero(self):
        baseline = self.commit('reviewed branch')
        self.receipt(baseline)
        self.git('checkout', '-q', '-b', 'other', self.head)
        self.commit('other branch')
        result = status.report(self.repo, self.state)
        self.assertEqual(result['status'], 'UNKNOWN_BASELINE')
        self.assertEqual(result['relation'], 'diverged')
        self.assertIsNone(result['commits_since_complete'])
        self.assertEqual(result['next_command'][-1], 'full')
        self.receipt('a' * 40)
        self.assertEqual(status.report(self.repo, self.state)['relation'], 'unknown')

    def test_receipt_scope_identity_dirty_and_partial_are_rejected(self):
        for field, value in [('target', str(self.base)), ('run_status', 'partial'), ('profile', 'quick'), ('scope_paths', ['src'])]:
            with self.subTest(field=field):
                _, path = self.receipt()
                data = json.loads(path.read_text()); data[field] = value
                path.write_text(json.dumps(data))
                result = status.report(self.repo, self.state)
                self.assertEqual(result['status'], 'UNKNOWN_BASELINE')
                self.assertIsNone(result['commits_since_complete'])
        _, path = self.receipt()
        data = json.loads(path.read_text()); data['source_ref']['dirty'] = True
        path.write_text(json.dumps(data))
        self.assertEqual(status.report(self.repo, self.state)['status'], 'UNKNOWN_BASELINE')

    def test_symlink_cursor_receipt_and_corrupt_json_do_not_establish_baseline(self):
        cursor, path = self.receipt()
        original = cursor.read_text()
        linked = self.base / 'other.json'; linked.write_text(original)
        cursor.unlink(); cursor.symlink_to(linked)
        self.assertEqual(status.report(self.repo, self.state)['status'], 'UNKNOWN_BASELINE')
        cursor.unlink(); cursor.write_text(original)
        meta = self.base / 'metadata.json'; path.rename(meta); path.symlink_to(meta)
        self.assertEqual(status.report(self.repo, self.state)['status'], 'UNKNOWN_BASELINE')
        path.unlink(); path.write_text('{invalid')
        self.assertEqual(status.report(self.repo, self.state)['status'], 'UNKNOWN_BASELINE')

    def test_newer_partial_run_does_not_replace_complete_and_no_directory_scan(self):
        cursor, receipt = self.receipt()
        latest = self.state / 'security-audit/newer-run'
        latest.mkdir()
        (latest / 'run-metadata.json').write_text(json.dumps(dict(run_status='budget_exhausted')))
        with patch.object(Path, 'glob', side_effect=AssertionError('no inventory')), \
             patch.object(Path, 'rglob', side_effect=AssertionError('no source scan')):
            result = status.report(self.repo, self.state)
        self.assertEqual(result['status'], 'CURRENT')
        self.assertEqual(result['cursor_path'], str(cursor))
        self.assertEqual(result['receipt_path'], str(receipt))

    def test_checkpoint_compatibility_is_optional_bounded_and_never_writes(self):
        self.state.mkdir()
        (self.state / 'plan.json').write_text(json.dumps({'checkpoints': [{'id': 'cp1', 'title': 'Fixture'}]}))
        (self.state / 'cp1.state.json').write_text(json.dumps({'status': 'awaiting_approval', 'gates': {'review': True}}))
        result = status.report(self.repo, self.state)
        self.assertEqual(result['checkpoints']['items'][0]['status'], 'awaiting_approval')
        self.assertIn('cp1: awaiting_approval', status.text_report(result))
        (self.state / 'plan.json').write_text(json.dumps({'checkpoints': [{'id': '../private', 'title': 'Do not read'}]}))
        self.assertEqual(status.report(self.repo, self.state)['checkpoints']['status'], 'invalid_or_unreadable')

    def test_git_status_disables_repository_fsmonitor_execution(self):
        marker = self.base / 'fsmonitor-called'
        command = self.base / 'fsmonitor'
        command.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
        command.chmod(0o755)
        self.git('config', 'core.fsmonitor', str(command))
        status.report(self.repo, self.state)
        self.assertFalse(marker.exists())

    def test_same_length_dirty_file_does_not_execute_git_clean_filter(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=synthetic\n')
        self.git('add', '.gitattributes')
        self.git('commit', '-qm', 'attributes')
        self.head = self.git('rev-parse', 'HEAD')
        self.receipt()
        marker = self.base / 'filter-executed'
        code = self.base / 'filter.py'
        code.write_text('import sys\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\nsys.stdout.write(sys.stdin.read())\n')
        self.git('config', 'filter.synthetic.clean', shlex.join([sys.executable, str(code)]))
        (self.repo / 'app.txt').write_text('changed')  # Same length as committed "initial".
        result = status.report(self.repo, self.state)
        self.assertFalse(marker.exists())
        self.assertIsNone(result['dirty'])
        self.assertEqual(result['dirty_reason'], 'git_filters_not_executed')
        self.assertEqual(result['status'], 'UNKNOWN_BASELINE')
        self.assertNotIn(str(code), json.dumps(result))
        self.assertIn('filtry Git niewykonane', status.text_report(result, reminder_only=True))

    def test_global_process_smudge_and_required_filters_are_not_executed(self):
        self.receipt()
        marker = self.base / 'global-filter-executed'
        code = self.base / 'filter.py'
        code.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n')
        global_config = self.base / 'global.gitconfig'
        # Git runs a driver only for paths whose `filter` attribute names it; an unused
        # global driver is inert (test_git_readonly covers that case).
        (self.repo / '.git/info').mkdir(exist_ok=True)
        (self.repo / '.git/info/attributes').write_text('app.txt filter=synthetic\n')
        for field in ('clean', 'smudge', 'process', 'required'):
            with self.subTest(field=field):
                value = 'true' if field == 'required' else shlex.join([sys.executable, str(code)])
                global_config.write_text('[filter "synthetic"]\n    ' + field + ' = ' + value + '\n')
                with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}):
                    result = status.report(self.repo, self.state)
                self.assertFalse(marker.exists())
                self.assertIsNone(result['dirty'])
                self.assertEqual(result['status'], 'UNKNOWN_BASELINE')
                self.assertEqual(result['dirty_reason'], 'git_filters_not_executed')
                self.assertNotIn(str(code), json.dumps(result))

    def test_submodule_local_clean_filter_is_not_executed_or_ignored_as_clean(self):
        origin = self.base / 'module-source'
        origin.mkdir()
        self.git('init', '-q', repo=origin)
        self.git('config', 'user.name', 'Fixture', repo=origin)
        self.git('config', 'user.email', 'fixture@example.invalid', repo=origin)
        (origin / 'data.txt').write_text('initial')
        (origin / '.gitattributes').write_text('data.txt filter=nested\n')
        self.git('add', '.', repo=origin)
        self.git('commit', '-qm', 'module fixture', repo=origin)
        self.git('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', str(origin), 'module')
        self.git('commit', '-qam', 'module')
        self.head = self.git('rev-parse', 'HEAD')
        self.receipt()
        marker = self.base / 'nested-filter-executed'
        code = self.base / 'filter.py'
        code.write_text('import sys\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\nsys.stdout.write(sys.stdin.read())\n')
        module = self.repo / 'module'
        self.git('config', 'filter.nested.clean', shlex.join([sys.executable, str(code)]), repo=module)
        (module / 'data.txt').write_text('changed')
        result = status.report(self.repo, self.state)
        self.assertFalse(marker.exists())
        self.assertIsNone(result['dirty'])
        self.assertEqual(result['dirty_reason'], 'git_submodules_not_inspected')
        self.assertEqual(result['status'], 'UNKNOWN_BASELINE')
        self.assertEqual(result['commits_since_complete'], 0)
        self.assertEqual(result['next_command'][-1], 'daily')

    def fake_cli(self, exit_code=0):
        path = self.base / 'fake helix.py'
        path.write_text('import json, os, sys\nfrom pathlib import Path\nPath(os.environ["FIXTURE_HOOK_LOG"]).write_text(json.dumps(sys.argv[1:]))\nraise SystemExit(' + str(exit_code) + ')\n')
        return path

    def run_hook(self, hook, repo=None):
        log = self.base / 'hook-args.json'
        result = subprocess.run([str(hook)], cwd=repo or self.repo,
                                env=dict(os.environ, FIXTURE_HOOK_LOG=str(log)), capture_output=True, text=True)
        return result, json.loads(log.read_text())

    def test_explicit_hook_never_overwrites_and_only_calls_offline_status(self):
        before = (self.repo / '.git/hooks/post-commit').exists()
        status.report(self.repo, self.state)
        self.assertEqual((self.repo / '.git/hooks/post-commit').exists(), before)
        installed = status.install_hook(self.repo, self.state, helix_path=self.fake_cli())
        hook = Path(installed['hook']); content = hook.read_bytes()
        result, args = self.run_hook(hook)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(args, ['--repo', str(self.repo), '--offline', '--state-dir', str(self.state), 'status', '--reminder-only'])
        with self.assertRaisesRegex(ValueError, 'istniejący hook'):
            status.install_hook(self.repo, self.state)
        self.assertEqual(hook.read_bytes(), content)
        self.assertFalse(self.state.exists())

    def test_hook_supports_core_hooks_path_and_linked_worktree_without_wrong_state(self):
        hooks = self.base / 'shared hooks'
        self.git('config', 'core.hooksPath', str(hooks))
        sibling = self.base / 'sibling'
        self.git('worktree', 'add', '-q', '-b', 'sibling', str(sibling))
        self.assertTrue((sibling / '.git').is_file())
        installed = status.install_hook(self.repo, self.state, helix_path=self.fake_cli())
        hook = Path(installed['hook'])
        self.assertEqual(hook, hooks / 'post-commit')
        result, args = self.run_hook(hook, sibling)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(args, ['--repo', str(sibling), '--offline', 'status', '--reminder-only'])
        self.assertTrue(installed['shared_hooks'])
        self.assertFalse(self.state.exists())

    def test_external_config_path_is_retained_without_reading_values(self):
        config = self.base / 'external config.json'
        config.write_text('NOT_JSON PRIVATE_VALUE_NOT_TO_READ')
        real_read = status.safe_read
        def safe_read(path, **kwargs):
            self.assertNotEqual(Path(path), config)
            return real_read(path, **kwargs)
        with patch.object(status, 'safe_read', side_effect=safe_read):
            data = status.report(self.repo, self.state, config_path=config)
            hook = Path(status.install_hook(self.repo, self.state, config_path=config, helix_path=self.fake_cli())['hook'])
        self.assertEqual(data['next_command'][:5], ['helix', '--repo', str(self.repo), '--config', str(config)])
        self.assertNotIn('PRIVATE_VALUE', json.dumps(data))
        result, args = self.run_hook(hook)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(args, ['--repo', str(self.repo), '--offline', '--config', str(config),
                                '--state-dir', str(self.state), 'status', '--reminder-only'])
        sibling = self.base / 'sibling'
        self.git('worktree', 'add', '-q', '-b', 'sibling', str(sibling))
        result, args = self.run_hook(hook, sibling)
        self.assertNotIn('--config', args)
        self.assertNotIn('--state-dir', args)
        self.assertEqual(args, ['--repo', str(sibling), '--offline', 'status', '--reminder-only'])

    def test_hook_failure_does_not_fail_completed_commit(self):
        hook = Path(status.install_hook(self.repo, helix_path=self.fake_cli(3))['hook'])
        result, args = self.run_hook(hook)
        self.assertEqual(result.returncode, 0)
        self.assertIn('zaległość przeglądu jest nieznana', result.stdout)
        self.assertEqual(args[-2:], ['status', '--reminder-only'])

    def test_hook_symlink_is_rejected_without_touching_destination(self):
        destination = self.base / 'owner-hook'; destination.write_text('owner content')
        hook = self.repo / '.git/hooks/post-commit'
        hook.symlink_to(destination)
        with self.assertRaisesRegex(ValueError, 'dowiązanie'):
            status.install_hook(self.repo)
        self.assertEqual(destination.read_text(), 'owner content')


@unittest.skipUnless(shutil.which('node'), 'Local Node validator unavailable')
class RealCompleteContract(unittest.TestCase):
    def test_actual_deep_builder_receipt_is_accepted_without_reusing_providers(self):
        from test_security_deep_budget import DeepBudget, D
        fixture = DeepBudget(methodName='test_plan_cost_is_saved_before_any_provider_call')
        fixture.setUp()
        try:
            _, meta = D.run(fixture.ctx, fixture.args())
            self.assertEqual(meta['run_status'], 'complete')
            self.assertTrue(meta['complete_cursor']['updated'])
            self.assertEqual(meta['profile'], 'standard')
            self.assertEqual(meta['scope_paths'], ['.'])
            count = len(fixture.hunter_calls) + len(fixture.verifier_calls)
            result = status.report(fixture.repo, fixture.ctx.state_dir)
            self.assertEqual(result['status'], 'CURRENT', result)
            self.assertEqual(result['reviewed_head'], meta['source_ref']['head'])
            self.assertEqual(count, len(fixture.hunter_calls) + len(fixture.verifier_calls))
        finally:
            fixture.doCleanups()


if __name__ == '__main__': unittest.main()
