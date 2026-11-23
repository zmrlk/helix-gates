"""Concurrent synthetic hunters keep ordered evidence and share one budget."""
import copy
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
import test_security_deep_budget as fixture
from test_security_deep import record
from test_security_deep import D, H


class DeepJobs(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def batches(self, count=3):
        return [(f'FILE src/app.py\n# BATCH {i}\nvalue = {i}', ['src/app.py']) for i in range(count)]

    def plan(self, count=3):
        return patch.object(D, 'context_plan', side_effect=lambda *a: (self.batches(count), [dict(unit='src/app.py', status='planned', reason=None)]))

    def test_default_three_jobs_run_concurrently_and_commit_in_batch_order(self):
        barrier = threading.Barrier(3)
        second_done = threading.Event()
        contexts = []; directories = []; committed = []
        def hunt(ctx, model, prompt, images, schema, write, out, timeout):
            index = int(prompt.split('# BATCH ')[1].split('\n')[0])
            contexts.append(id(ctx)); directories.append(out)
            barrier.wait(timeout=3)
            if index == 0:
                self.assertTrue(second_done.wait(3))
            elif index == 1:
                second_done.set()
            return json.dumps(dict(architecture_md=f'batch {index}', coverage_ledger=self.covered(), candidates=[]))
        original = D.atomic_json
        def save(path, data):
            if Path(path).name == 'checkpoint.json':
                completed = [b['index'] for b in data['batches'] if b['status'] == 'complete']
                if completed: committed.append(completed)
            return original(path, data)
        with self.plan(), patch.object(H, 'call_codex', side_effect=hunt), patch.object(D, 'atomic_json', side_effect=save):
            _, meta = D.run(self.ctx, self.args(profile='standard', budget='time=30s'))
        self.assertEqual(meta['plan']['jobs'], 3)
        self.assertEqual(len(set(contexts)), 3); self.assertEqual(len(set(directories)), 3)
        self.assertEqual(meta['usage']['calls'], 3)
        self.assertTrue(all(items == list(range(len(items))) for items in committed))
        self.assertEqual((self.out / 'architecture.md').read_text(), 'batch 0\n\nbatch 1\n\nbatch 2')
        self.assertFalse(hasattr(self.ctx, '_deep_deadline'))

    def test_resume_accepts_a_different_job_count_and_verifier_slot_goes_to_first_finished(self):
        # Projekt B: 240 podejrzeń po ok. 5 min; liczba zadań nie zmienia treści przeglądu, a wolne miejsce nie czeka na najstarsze.
        slow_started, release = threading.Event(), threading.Event(); order = []
        def hunt(ctx, model, prompt, *args, **kwargs):
            return json.dumps(dict(architecture_md='fixture', coverage_ledger=self.covered(),
                                   candidates=[record(fp='c-' + str(i)) for i in range(3)]))
        def verify(ctx, model, prompt, *args, **kwargs):
            fp = prompt.split('"fingerprint": "')[1].split('"')[0]
            if fp == 'c-0':
                slow_started.set(); self.assertTrue(release.wait(3))
            else:
                self.assertTrue(slow_started.wait(3))
            order.append(fp)
            if len(order) == 2: release.set()
            return json.dumps(record(fp=fp))
        with self.plan(1), patch.object(H, 'call_codex', side_effect=hunt), patch.object(H, 'call_grok_cli', side_effect=verify):
            _, meta = D.run(self.ctx, self.args(jobs=2, budget='calls=1'))
            self.assertEqual(meta['run_status'], 'budget_exhausted')
            _, meta = D.run(self.ctx, self.args(jobs=3, resume=str(self.out), out=None, budget='calls=10'))
        self.assertEqual(self.load('checkpoint.json')['settings']['jobs'], 3)
        self.assertEqual(order[-1], 'c-0')   # dwa szybkie skończyły, zanim wolne miejsce czekało na pierwsze
        self.assertEqual(meta['progress']['candidates_complete'], 3)

    def test_concurrent_hunters_cannot_overspend_call_budget(self):
        barrier = threading.Barrier(2); executed = []
        def hunt(ctx, model, prompt, images, schema, write, out, timeout):
            executed.append(ctx._deep_batch_index); barrier.wait(timeout=3)
            return json.dumps(dict(architecture_md='fixture', coverage_ledger=self.covered(), candidates=[]))
        with self.plan(6), patch.object(H, 'call_codex', side_effect=hunt):
            _, meta = D.run(self.ctx, self.args(jobs=3, budget='calls=2'))
        self.assertEqual(len(executed), 2); self.assertEqual(meta['usage']['calls'], 2)
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(meta['progress']['batches_complete'], 2)
        self.assertEqual(meta['progress']['batches_not_checked'], 4)
        self.assertEqual(meta['progress']['batches_blocked'], 0)

    def test_explicit_one_job_never_overlaps_and_invalid_jobs_fail_before_model(self):
        active = 0
        def hunt(*args):
            nonlocal active
            active += 1; self.assertEqual(active, 1)
            result = self.hunter(*args); active -= 1; return result
        with self.plan(), patch.object(H, 'call_codex', side_effect=hunt):
            _, meta = D.run(self.ctx, self.args(jobs=1))
        self.assertEqual(meta['plan']['jobs'], 1)
        for jobs in (0, -1, 65, True, 1.5):
            with self.subTest(jobs=jobs), self.assertRaisesRegex(ValueError, 'jobs'):
                D.run(self.ctx, self.args(jobs=jobs))


if __name__ == '__main__': unittest.main()
