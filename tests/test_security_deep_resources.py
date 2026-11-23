"""Resource admission and durable scheduler regressions, with synthetic clocks."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_deep_budget as fixture
from test_security_deep import D, H, NormalResources
import test_security_deep_jobs as jobs_fixture
from helix_resources import Governor


class DeepResources(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load
    batches, plan = jobs_fixture.DeepJobs.batches, jobs_fixture.DeepJobs.plan

    def governor(self, levels, jobs=3, maximum=10):
        now = [0.0]; levels = iter(levels); last = ['normal']
        def sample():
            last[0] = next(levels, last[0])
            return {'memory_pressure': last[0]}
        governor = Governor(snapshot_fn=sample, policy={'max_pause_s': maximum, 'poll_s': 5, 'sample_s': 0.001}, requested_jobs=jobs)
        governor._clock = lambda: now[0]
        governor._sleep = lambda seconds: now.__setitem__(0, now[0] + seconds)
        self.ctx.resource_governor = governor
        return governor, now

    def test_calls_one_reserves_batch_zero_even_when_its_worker_is_delayed(self):
        delayed = threading.Event(); executed = []
        original = D.ask
        def ask(ctx, *args, **kwargs):
            if getattr(ctx, '_deep_batch_index', None) == 0:
                delayed.wait(0.1)
            return original(ctx, *args, **kwargs)
        def hunt(ctx, *args):
            executed.append(ctx._deep_batch_index)
            return self.hunter(ctx, *args)
        with self.plan(), patch.object(D, 'ask', side_effect=ask), patch.object(H, 'call_codex', side_effect=hunt):
            _, meta = D.run(self.ctx, self.args(jobs=3, budget='calls=1'))
        self.assertEqual(executed, [0])
        self.assertEqual(meta['provider_attempts'][0]['batch_index'], 0)
        self.assertEqual(meta['usage']['calls'], 1)

    def test_time_budget_is_checked_before_a_cross_run_cache_hit(self):
        D.run(self.ctx, self.args())
        clock = [0.0]
        original = D.context_plan
        def plan(*args):
            result = original(*args); clock[0] = 11.0; return result
        with patch.object(D, 'time', SimpleNamespace(monotonic=lambda: clock[0])), \
             patch.object(D, 'context_plan', side_effect=plan), patch.object(D, 'load_batch_cache') as cache:
            _, meta = D.run(self.ctx, self.args(out=str(self.root / 'cached'), budget='time=10s'))
        cache.assert_not_called()
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(meta['progress']['cache_hits'], 0)
        self.assertEqual(meta['progress']['batches_not_checked'], 1)

    def test_high_pressure_reduces_parallelism_without_changing_requested_jobs(self):
        self.governor(['high'])
        active = 0; maximum = 0; lock = threading.Lock()
        def hunt(*args):
            nonlocal active, maximum
            with lock: active += 1; maximum = max(maximum, active)
            try: return json.dumps(dict(architecture_md='fixture', coverage_ledger=self.covered(), candidates=[]))
            finally:
                with lock: active -= 1
        with self.plan(), patch.object(H, 'call_codex', side_effect=hunt):
            _, meta = D.run(self.ctx, self.args(jobs=3))
        self.assertEqual(maximum, 1)
        self.assertEqual(meta['plan']['jobs'], 3)
        self.assertEqual(meta['resources']['current']['effective_jobs'], 1)
        self.assertEqual(meta['run_status'], 'complete')

    def test_critical_pause_recovers_without_calls_during_pause(self):
        governor, clock = self.governor(['critical', 'critical', 'normal'])
        original_sleep = governor._sleep
        def sleep(seconds):
            self.assertFalse(self.hunter_calls)
            original_sleep(seconds)
        governor._sleep = sleep
        with patch.object(D, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'complete')
        self.assertGreaterEqual(meta['usage']['elapsed_seconds'], 5)
        self.assertEqual(len(self.hunter_calls), 1)

    def test_critical_timeout_keeps_checkpoint_and_resumes_after_policy_change(self):
        self.governor(['critical'])
        _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'resource_paused')
        self.assertEqual(meta['progress']['batches_not_checked'], 1)
        self.assertFalse(self.hunter_calls)
        self.ctx.resource_governor = NormalResources()
        self.cfg['resources'] = {'max_pause_s': 600}
        _, resumed = D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertEqual(resumed['run_status'], 'complete')
        self.assertEqual(len(self.hunter_calls), 1)

    def test_critical_wait_consumes_global_time_budget(self):
        _, clock = self.governor(['critical'], maximum=30)
        with patch.object(D, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            _, meta = D.run(self.ctx, self.args(budget='time=1s'))
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(meta['usage']['elapsed_seconds'], 1)
        self.assertFalse(self.hunter_calls)

    def test_active_batch_finishes_and_is_saved_before_resource_pause(self):
        state = ['normal']; entered = threading.Event()
        governor = Governor(snapshot_fn=lambda: {'memory_pressure': state[0]},
                            policy={'sample_s': 0.001, 'max_pause_s': 1}, requested_jobs=1)
        clock = [0.0]; governor._clock = lambda: clock[0]
        governor._sleep = lambda n: clock.__setitem__(0, clock[0] + n)
        self.ctx.resource_governor = governor
        def hunt(*args):
            state[0] = 'critical'; clock[0] += 1; entered.set()
            return json.dumps(dict(architecture_md='retained', coverage_ledger=self.covered(), candidates=[]))
        with self.plan(2), patch.object(H, 'call_codex', side_effect=hunt):
            _, meta = D.run(self.ctx, self.args(jobs=1))
        self.assertTrue(entered.is_set())
        self.assertEqual(meta['run_status'], 'resource_paused')
        self.assertEqual(meta['progress']['batches_complete'], 1)
        self.assertEqual(meta['progress']['batches_not_checked'], 1)
        self.assertEqual((self.out / 'architecture.md').read_text(), 'retained')

    def test_concurrent_run_index_updates_and_output_allocation_are_lossless(self):
        root = self.root / 'parallel-index'
        barrier = threading.Barrier(12)
        def write(index):
            barrier.wait(timeout=3)
            out = D.output_dir(self.repo, root=root)
            D.update_run_index(root, out, [])
            return str(out)
        with ThreadPoolExecutor(max_workers=12) as pool:
            outputs = list(pool.map(write, range(12)))
        self.assertEqual(len(set(outputs)), 12)
        self.assertEqual(set(json.loads((root / 'run-index.json').read_text())), set(outputs))


if __name__ == '__main__': unittest.main()
