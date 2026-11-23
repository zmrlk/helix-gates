"""Diff selection and source/model-aware caches use synthetic git repositories."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import test_security_deep_budget as fixture
from test_security_deep import D


class DeepIncremental(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def commit(self):
        for args in (['add', '.'], ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'change']):
            subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True)

    def test_unchanged_batch_reuses_hunter_but_not_independent_verifier(self):
        D.run(self.ctx, self.args(profile='standard'))
        _, meta = D.run(self.ctx, self.args(profile='standard', out=str(self.root / 'second')))
        self.assertEqual(len(self.hunter_calls), 1)
        self.assertEqual(len(self.verifier_calls), 2)
        self.assertEqual(meta['usage']['calls'], 1)
        self.assertEqual(meta['progress']['cache_hits'], 1)
        self.assertEqual(meta['run_status'], 'complete')

    def test_model_or_source_change_invalidates_cache(self):
        D.run(self.ctx, self.args(profile='standard'))
        self.cfg['models']['codex'] = ['new-model']
        self.ctx.availability = fixture.availability(self.cfg)
        D.run(self.ctx, self.args(profile='standard', out=str(self.root / 'second')))
        self.assertEqual(len(self.hunter_calls), 2)
        (self.repo / 'src/app.py').write_text('def update():\n    return 1\n')
        D.run(self.ctx, self.args(profile='standard', out=str(self.root / 'third')))
        self.assertEqual(len(self.hunter_calls), 3)

    def test_shared_guard_change_invalidates_unchanged_batch(self):
        guard = self.repo / 'src/guard.py'; guard.write_text('def guard(): return True\n'); self.commit()
        batches = [('FILE src/app.py\n1: def update(): pass', ['src/app.py'])]
        units = [dict(unit='src/app.py', status='planned', reason=None)]
        with patch.object(D, 'context_plan', side_effect=lambda *a: (copy.deepcopy(batches), copy.deepcopy(units))):
            D.run(self.ctx, self.args(profile='standard'))
            guard.write_text('def guard(): return False\n')
            D.run(self.ctx, self.args(profile='standard', out=str(self.root / 'second')))
        self.assertEqual(len(self.hunter_calls), 2)

    def test_since_selects_only_changed_batches_and_marks_other_units(self):
        (self.repo / 'src/other.py').write_text('value=1\n'); self.commit()
        (self.repo / 'src/app.py').write_text('def update(): return 2\n')
        batches = [('FILE src/app.py\n1: def update(): return 2', ['src/app.py']), ('FILE src/other.py\n1: value=1', ['src/other.py'])]
        units = [dict(unit=name, status='planned', reason=None) for name in ('src/app.py', 'src/other.py')]
        with patch.object(D, 'context_plan', return_value=(batches, units)):
            _, meta = D.run(self.ctx, self.args(profile='standard', since='HEAD'))
        self.assertEqual(meta['plan']['batches'], 1)
        self.assertEqual(meta['incremental']['changed_files'], ['src/app.py'])
        self.assertEqual(meta['progress']['units']['not_selected'], 1)
        self.assertEqual(len(self.hunter_calls), 1)
        self.assertNotIn('src/other.py', self.hunter_calls[0][0])

    def test_unchanged_diff_executes_no_models_and_invalid_ref_fails_closed(self):
        _, meta = D.run(self.ctx, self.args(profile='standard', since='HEAD'))
        self.assertEqual(meta['plan']['batches'], 0)
        self.assertEqual(meta['run_status'], 'complete')
        self.assertFalse(self.hunter_calls + self.verifier_calls)
        with self.assertRaises(ValueError):
            D.run(self.ctx, self.args(since='nonexistent', out=str(self.root / 'second')))
        self.assertFalse((self.root / 'second').exists())

    def test_deleted_source_stays_an_explicit_gap(self):
        (self.repo / 'src/app.py').unlink()
        _, meta = D.run(self.ctx, self.args(profile='standard', since='HEAD'))
        self.assertEqual(meta['run_status'], 'partial')
        self.assertEqual(meta['uncovered_units'], ['src/app.py'])
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_corrupt_cached_coverage_is_rechecked(self):
        D.run(self.ctx, self.args(profile='standard'))
        cache = next((self.ctx.state_dir / 'security-audit' / 'batch-cache').rglob('*.json'))
        data = json.loads(cache.read_text()); data['result']['coverage'] = [{}]; cache.write_text(json.dumps(data))
        _, meta = D.run(self.ctx, self.args(profile='standard', out=str(self.root / 'second')))
        self.assertEqual(len(self.hunter_calls), 2); self.assertEqual(meta['progress']['cache_hits'], 0)


if __name__ == '__main__': unittest.main()
