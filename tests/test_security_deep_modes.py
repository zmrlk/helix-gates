"""Full/daily/release modes preserve an evidence-backed clean Git cursor."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import test_security_deep_budget as fixture
from test_security_deep import D, H


class DeepModes(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def commit_change(self, value):
        (self.repo / 'src/app.py').write_text(f'def update(): return {value}\n')
        for args in (['add', '.'], ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'change']):
            subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True)
        return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=self.repo, capture_output=True, text=True, check=True).stdout.strip()

    def test_full_defaults_and_daily_release_use_last_complete(self):
        _, first = D.run(self.ctx, self.args())
        self.assertEqual(first['mode'], 'full'); self.assertEqual(first['profile'], 'standard')
        self.assertEqual(first['budget'], {'seconds': None, 'calls': None}); self.assertEqual(first['plan']['jobs'], 3)
        self.assertTrue(first['complete_cursor']['updated'])
        head = self.commit_change(2)
        _, daily = D.run(self.ctx, self.args(mode='daily', out=str(self.root / 'daily')))
        self.assertEqual(daily['incremental']['ref'], first['source_ref']['head'])
        self.assertIsNone(daily['budget']['seconds']); self.assertTrue(daily['complete_cursor']['updated'])
        self.commit_change(3)
        _, release = D.run(self.ctx, self.args(mode='release', out=str(self.root / 'release')))
        self.assertEqual(release['incremental']['ref'], head)
        self.assertEqual(release['budget']['seconds'], 1800)
        self.assertTrue(release['complete_cursor']['updated'])

    def test_missing_complete_is_an_actionable_error_without_silent_full(self):
        for mode in ('daily', 'release'):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, '--mode full'):
                D.run(self.ctx, self.args(mode=mode))
        self.assertFalse(self.out.exists()); self.assertFalse(self.hunter_calls)

    def test_explicit_overrides_do_not_create_a_full_coverage_cursor(self):
        _, meta = D.run(self.ctx, self.args(mode='release', since='HEAD', budget='calls=2', jobs=1))
        self.assertEqual(meta['budget'], {'seconds': None, 'calls': 2})
        self.assertEqual(meta['plan']['jobs'], 1)
        self.assertEqual(meta['run_status'], 'complete')
        self.assertFalse(meta['complete_cursor']['updated'])
        self.assertIn('no matching clean COMPLETE baseline', meta['complete_cursor']['reason'])

    def test_dirty_source_and_changed_source_never_advance_cursor(self):
        (self.repo / 'src/app.py').write_text('def update(): return 2\n')
        _, dirty = D.run(self.ctx, self.args())
        self.assertEqual(dirty['run_status'], 'complete')
        self.assertFalse(dirty['complete_cursor']['updated']); self.assertIn('Dirty', dirty['complete_cursor']['reason'])
        self.commit_change(3)
        original = self.hunter
        def change_source(*args):
            result = original(*args)
            (self.repo / 'src/app.py').write_text('def update(): return 4\n')
            return result
        with patch.object(H, 'call_codex', side_effect=change_source):
            _, changed = D.run(self.ctx, self.args(out=str(self.root / 'changed')))
        self.assertFalse(changed['complete_cursor']['updated'])

    def test_partial_and_budget_exhausted_leave_prior_cursor_unchanged(self):
        _, first = D.run(self.ctx, self.args())
        cursor = Path(first['complete_cursor']['path']); before = cursor.read_bytes()
        self.commit_change(2)
        _, stopped = D.run(self.ctx, self.args(mode='daily', budget='calls=1', out=str(self.root / 'stopped')))
        self.assertEqual(stopped['run_status'], 'budget_exhausted'); self.assertEqual(cursor.read_bytes(), before)
        _, partial = D.run(self.ctx, self.args(profile='quick', out=str(self.root / 'partial')))
        self.assertEqual(partial['run_status'], 'partial'); self.assertEqual(cursor.read_bytes(), before)

    def test_expensive_full_requires_yes_and_plan_only_never_calls_models(self):
        original = D._plan
        def expensive(*args, **kwargs):
            value = original(*args, **kwargs); value['estimated_seconds'] = 3601; return value
        with patch.object(D, '_plan', side_effect=expensive):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'awaiting_confirmation'); self.assertFalse(self.hunter_calls)
        _, meta = D.run(self.ctx, self.args(resume=str(self.out), yes=True))
        self.assertEqual(meta['run_status'], 'complete'); self.assertEqual(len(self.hunter_calls), 1)
        with patch.object(D, '_plan', side_effect=expensive):
            _, planned = D.run(self.ctx, self.args(plan_only=True, out=str(self.root / 'planned')))
        self.assertEqual(planned['run_status'], 'planned'); self.assertEqual(len(self.hunter_calls), 1)


if __name__ == '__main__': unittest.main()
