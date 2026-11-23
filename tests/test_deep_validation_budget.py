"""Local validator timeouts share the deep budget; no models or network."""
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_deep_budget as fixture
from test_security_deep import D


class ValidationBudget(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def hanging(self, clock, observed):
        original = subprocess.run
        def run(command, **kwargs):
            if command[0] != 'node': return original(command, **kwargs)
            observed.append(kwargs['timeout']); clock[0] += kwargs['timeout']
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])
        return run

    def test_hanging_validation_uses_remaining_budget_and_does_not_reprompt(self):
        clock = [0.0]; observed = []
        with patch.object(D, 'time', SimpleNamespace(monotonic=lambda: clock[0])), \
             patch.object(D.subprocess, 'run', side_effect=self.hanging(clock, observed)):
            _, meta = D.run(self.ctx, self.args(budget='time=0.75s'))
        self.assertEqual(observed, [0.75])
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(meta['usage']['elapsed_seconds'], 0.75)
        self.assertEqual(meta['usage']['calls'], 1)
        self.assertEqual(len(self.hunter_calls), 1)
        self.assertFalse(self.verifier_calls)
        self.assertEqual(meta['progress']['batches_not_checked'], 1)
        _, resumed = D.run(self.ctx, self.args(resume=str(self.out), budget='time=5s'))
        self.assertEqual(resumed['run_status'], 'complete')
        self.assertEqual(len(self.hunter_calls), 1)

    def test_cached_batch_validation_receives_the_same_remaining_cap(self):
        D.run(self.ctx, self.args())
        clock = [0.0]; observed = []
        with patch.object(D, 'time', SimpleNamespace(monotonic=lambda: clock[0])), \
             patch.object(D.subprocess, 'run', side_effect=self.hanging(clock, observed)):
            _, meta = D.run(self.ctx, self.args(out=str(self.root / 'cached'), budget='time=0.25s'))
        self.assertEqual(observed, [0.25])
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(meta['usage']['calls'], 0)
        self.assertEqual(meta['progress']['cache_hits'], 0)
        self.assertEqual(len(self.hunter_calls), 1)

    def test_real_sleeping_fake_validator_is_terminated_by_a_small_cap(self):
        original = subprocess.run; observed = []
        def run(command, **kwargs):
            observed.append(kwargs['timeout'])
            return original([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
        started = time.monotonic()
        with patch.object(D.subprocess, 'run', side_effect=run):
            error = D.validate('validate-coverage-ledger.cjs', self.root / 'fixture.json', timeout=0.15)
        self.assertEqual(observed, [0.15])
        self.assertIn('timed out', error)
        self.assertLess(time.monotonic() - started, 3)

    def test_unbounded_review_keeps_the_existing_validator_ceiling(self):
        with patch.object(D.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as process:
            self.assertEqual(D.validate('fixture.cjs', self.root / 'fixture.json', timeout=500), '')
        self.assertEqual(process.call_args.kwargs['timeout'], 30)


if __name__ == '__main__': unittest.main()
