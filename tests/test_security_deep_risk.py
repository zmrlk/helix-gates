"""Risk ordering and cost estimates are source-only and distinguish assumptions."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_security_deep_budget as fixture
from test_security_deep import D
import helix_static_security


class DeepRisk(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def test_money_and_static_idor_high_precede_docs(self):
        names = ['docs/aaa.md', 'src/invoice.py', 'src/zz_ordinary.py', 'src/auth/session.py', 'src/upload.py']
        for name in names:
            path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('value = 1\n')
        rows = [{'file': 'src/zz_ordinary.py', 'id': 'SEC-IDOR', 'severity': 'medium', 'line': 1}]
        with patch.object(helix_static_security, 'analyze', return_value={'findings': rows}):
            batches, units = D.context_plan(self.repo, ['.'], 'standard')
        ordered = [u['unit'] for u in units]
        self.assertLess(ordered.index('src/invoice.py'), ordered.index('docs/aaa.md'))
        self.assertLess(ordered.index('src/zz_ordinary.py'), ordered.index('docs/aaa.md'))
        idor = next(u for u in units if u['unit'] == 'src/zz_ordinary.py')
        self.assertEqual(idor['risk']['priority'], 0)
        self.assertEqual(idor['risk']['tag'], 'ASSUMPTION')
        self.assertIn('SEC-IDOR', ' '.join(idor['risk']['reasons']))

    def test_missing_static_review_is_an_explicit_limit(self):
        with patch.object(helix_static_security, 'analyze', side_effect=OSError('unavailable')):
            rows = D.risk_priorities(self.repo, ['src/payment.py'])
        self.assertEqual(rows['src/payment.py']['priority'], 0)
        self.assertEqual(rows['src/payment.py']['static_review_error'], 'OSError')

    def test_time_estimate_uses_recorded_rate_and_job_count(self):
        prior = self.root / 'previous'; prior.mkdir()
        meta = {'profile': 'standard', 'provider_attempts': [
            {'provider': 'codex', 'role': 'hunter', 'batch_index': 0, 'status': 'complete', 'started_elapsed_seconds': 0, 'finished_elapsed_seconds': 30},
            {'provider': 'codex', 'role': 'hunter', 'batch_index': 1, 'status': 'complete', 'started_elapsed_seconds': 0, 'finished_elapsed_seconds': 50}]}
        (prior / 'run-metadata.json').write_text(json.dumps(meta))
        settings = {'hunter': 'codex', 'verifier': 'grok-cli', 'max_candidates': 2, 'jobs': 3, 'profile': 'standard'}
        settings['role_assignments'] = D.role_assignments(D.role_plan(self.ctx, self.args()))
        plan = D._plan([('source', ['src/app.py'])] * 6, 'prompt', settings, self.ctx, [prior])
        self.assertEqual(plan['observed_batch_seconds'], 40)
        self.assertEqual(plan['observed_samples'], 2)
        self.assertEqual(plan['estimated_seconds'], 160)
        settings['jobs'] = 1
        serial = D._plan([('source', ['src/app.py'])] * 6, 'prompt', settings, self.ctx, [prior])
        self.assertEqual(serial['estimated_seconds'], 320)
        unknown = D._plan([('source', ['src/app.py'])], 'prompt', settings, self.ctx)
        self.assertIsNone(unknown['estimated_seconds'])


if __name__ == '__main__': unittest.main()
