"""Planning and cursor bookkeeping must never execute configured Git filters."""
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

import test_security_deep_budget as fixture
from test_security_deep import D


class DeepReadOnlyGit(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True, text=True).stdout

    def filter_fixture(self):
        (self.repo / '.git/info/attributes').write_text('src/app.py filter=fixture\n')
        marker = self.root / 'executed-filter'
        script = self.root / 'filter.py'
        script.write_text('from pathlib import Path\nimport sys\nPath(' + repr(str(marker)) + ').write_text("executed")\nsys.stdout.write(sys.stdin.read())\n')
        self.git('config', 'filter.fixture.clean', shlex.join([sys.executable, str(script)]))
        original = (self.repo / 'src/app.py').read_text()
        (self.repo / 'src/app.py').write_text(original.replace('pass', 'None'))
        return marker

    def test_full_plan_keeps_known_head_without_running_clean_filter(self):
        marker = self.filter_fixture()
        _, meta = D.run(self.ctx, self.args(plan_only=True))
        self.assertEqual(meta['run_status'], 'planned')
        self.assertIsNone(meta['source_ref']['dirty'])
        self.assertEqual(meta['source_ref']['status'], 'partial')
        self.assertEqual(meta['source_ref']['dirty_reason'], 'git_filters_not_executed')
        self.assertEqual(meta['source_ref']['head'], self.git('rev-parse', 'HEAD').strip())
        self.assertFalse(marker.exists())
        self.assertFalse(self.hunter_calls); self.assertFalse(self.verifier_calls)

    def test_incremental_plan_refuses_unknown_worktree_before_diff_or_models(self):
        marker = self.filter_fixture()
        with self.assertRaisesRegex(ValueError, 'bezpiecznie.*różnicy'):
            D.run(self.ctx, self.args(plan_only=True, since='HEAD'))
        self.assertFalse(marker.exists())
        self.assertFalse(self.hunter_calls); self.assertFalse(self.verifier_calls)

    def test_complete_review_cannot_advance_cursor_when_clean_state_is_unknown(self):
        marker = self.filter_fixture()
        # The review itself may finish, but a clean revision has not been proved.
        _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'complete')
        self.assertFalse(meta['complete_cursor']['updated'])
        self.assertIn('unknown', meta['complete_cursor']['reason'])
        self.assertFalse(Path(meta['complete_cursor']['path']).exists())
        self.assertFalse(marker.exists())

    def test_full_plan_disables_fsmonitor_during_all_git_inventory_calls(self):
        marker = self.root / 'executed-fsmonitor'
        script = self.root / 'fsmonitor.py'
        script.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n')
        self.git('config', 'core.fsmonitor', shlex.join([sys.executable, str(script)]))
        _, meta = D.run(self.ctx, self.args(plan_only=True))
        self.assertEqual(meta['run_status'], 'planned')
        self.assertFalse(marker.exists())
        self.assertFalse(self.hunter_calls)

    def test_pack_diff_refuses_filters_even_for_name_only(self):
        marker = self.filter_fixture()
        with self.assertRaisesRegex(ValueError, 'bezpiecznie.*diff'):
            D.P.git(self.repo, 'diff', '--name-only', 'HEAD', required=True)
        self.assertFalse(marker.exists())
