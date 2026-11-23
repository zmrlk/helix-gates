"""Synthetic provider probes: no process, provider, network or project execution."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_provider_plan as routing


class ParallelRefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'project'
        self.repo.mkdir()
        (self.repo / 'AGENTS.md').write_text('PRIVATE_PROJECT_INSTRUCTIONS')
        (self.repo / '.env').write_text('SECRET=PRIVATE_PROJECT_VALUE')
        self.cache = self.repo / 'state/provider-availability.json'
        self.ctx = SimpleNamespace(repo=self.repo, state_dir=self.cache.parent, offline=False,
                                   cfg={'models': {'codex': ['m0', 'm1', 'm2', 'm3']}, 'providers': {}})

    def test_default_parallel_limit_neutral_cwd_and_single_ordered_writer(self):
        active = 0
        maximum = 0
        lock = threading.Lock()
        barrier = threading.Barrier(3)
        first_checkpoint = threading.Event()
        saved = []
        directories = []
        original = copy.deepcopy(self.ctx.cfg)
        writer = routing.atomic_json
        main_thread = threading.get_ident()

        def persist(path, data):
            self.assertEqual(threading.get_ident(), main_thread)
            writer(path, data)
            saved.append(copy.deepcopy(json.loads(path.read_text())))
            if data['models'] and data['models'][0]['model'] == 'm1':
                first_checkpoint.set()

        def caller(ctx, model, prompt, images, schema, write, out, timeout):
            nonlocal active, maximum
            self.assertFalse(ctx.repo.is_relative_to(self.repo))
            self.assertFalse(self.repo.is_relative_to(ctx.repo))
            self.assertEqual(ctx.repo, out)
            self.assertEqual(ctx.state_dir, out)
            self.assertGreater(ctx._deep_deadline, time.monotonic())
            self.assertLessEqual(ctx._deep_deadline - time.monotonic(), timeout)
            self.assertFalse((out / 'AGENTS.md').exists())
            self.assertFalse((out / '.env').exists())
            self.assertNotIn('PRIVATE_PROJECT', prompt)
            self.assertIsNone(images); self.assertIsNone(schema); self.assertFalse(write)
            ctx.cfg['models']['codex'].append('worker-local-change')
            with lock:
                directories.append(out)
                active += 1
                maximum = max(maximum, active)
            if model in ('m0', 'm1', 'm2'):
                barrier.wait(timeout=5)
            if model in ('m0', 'm2'):
                self.assertTrue(first_checkpoint.wait(timeout=5))
            (out / 'raw.txt').write_text('PRIVATE_PROVIDER_RESPONSE')
            with lock: active -= 1
            return '{"ok": true}'

        with patch.object(routing, 'atomic_json', side_effect=persist):
            data = routing.refresh(self.ctx, {'codex': caller}, self.cache)
        self.assertEqual(maximum, 3)
        self.assertEqual(data['jobs'], 3)
        self.assertEqual(data['availability_probe_calls'], 4)
        self.assertEqual(data['source_review_calls'], 0)
        self.assertEqual([row['model'] for row in data['models']], ['m0', 'm1', 'm2', 'm3'])
        self.assertEqual([row['completed'] for row in saved], [0, 1, 2, 3, 4, 4])
        self.assertEqual(saved[1]['models'][0]['model'], 'm1')
        for snapshot in saved:
            names = [row['model'] for row in snapshot['models']]
            self.assertEqual(names, sorted(names))
        self.assertTrue(all(row['status'] == 'available' and row['call_invoked'] for row in data['models']))
        self.assertEqual(self.ctx.cfg, original)
        self.assertEqual(len(set(directories)), 4)
        self.assertFalse(any(p.exists() for p in directories))
        self.assertNotIn('PRIVATE_', self.cache.read_text())

    def test_explicit_jobs_two_and_serial_one(self):
        for jobs in (1, 2, 4):
            with self.subTest(jobs=jobs):
                barrier = threading.Barrier(jobs)
                active = maximum = 0
                lock = threading.Lock()
                def caller(ctx, model, *args):
                    nonlocal active, maximum
                    with lock:
                        active += 1
                        maximum = max(maximum, active)
                    barrier.wait(timeout=5)
                    with lock: active -= 1
                    return '{"ok": true}'
                data = routing.refresh(self.ctx, {'codex': caller}, self.cache, jobs=jobs)
                self.assertEqual(maximum, jobs)
                self.assertEqual(data['jobs'], jobs)
                self.assertEqual(data['requested_jobs'], jobs)
                self.assertTrue(all(row['status'] == 'available' for row in data['models']))

    def test_failed_json_and_exception_count_but_manual_and_unknown_do_not(self):
        self.ctx.cfg['models'] = {'codex': ['invalid', 'exception'], 'grok': [None], 'unknown': [None]}
        def caller(ctx, model, *args):
            if model == 'exception': raise RuntimeError('permission denied token=PRIVATE_TOKEN')
            return '{"ok": false, "private": "PRIVATE_RESPONSE"}'
        data = routing.refresh(self.ctx, {'codex': caller}, self.cache)
        self.assertEqual(data['availability_probe_calls'], 2)
        self.assertEqual([row['call_invoked'] for row in data['models']], [True, True, False, False])
        self.assertTrue(all(row['status'] == 'unavailable' for row in data['models']))
        self.assertNotIn('PRIVATE_', self.cache.read_text())
        self.assertIn('permission', data['models'][1]['reason'])

    def test_invalid_jobs_offline_or_tmp_inside_target_refuse_before_writes(self):
        caller = unittest.mock.Mock(side_effect=AssertionError('must not call'))
        for jobs in (0, -1, True, 1.5):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                routing.refresh(self.ctx, {'codex': caller}, self.cache, jobs=jobs)
        self.ctx.offline = True
        with self.assertRaises(ValueError): routing.refresh(self.ctx, {'codex': caller}, self.cache)
        self.ctx.offline = False
        with patch.object(routing.tempfile, 'gettempdir', return_value=str(self.repo)), \
             patch.object(routing.tempfile, 'TemporaryDirectory', side_effect=AssertionError('must not create')), \
             self.assertRaisesRegex(ValueError, 'neutralnego cwd'):
            routing.refresh(self.ctx, {'codex': caller}, self.cache)
        self.assertFalse(self.cache.parent.exists())
        caller.assert_not_called()

    def test_interrupt_drains_started_attempt_without_admitting_next(self):
        calls = []
        def caller(ctx, model, *args):
            calls.append(model)
            return '{"ok": true}'
        with patch.object(routing, 'wait', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            routing.refresh(self.ctx, {'codex': caller}, self.cache, jobs=1)
        data = json.loads(self.cache.read_text())
        self.assertEqual(calls, ['m0'])
        self.assertEqual(data['status'], 'interrupted')
        self.assertEqual(data['completed'], 1)
        self.assertEqual(data['availability_probe_calls'], 1)
        self.assertEqual(data['models'][0]['status'], 'available')

    def test_cache_symlink_or_linked_parent_rejected_without_call(self):
        destination = self.base / 'destination'
        destination.mkdir()
        self.cache.parent.symlink_to(destination, target_is_directory=True)
        caller = unittest.mock.Mock(side_effect=AssertionError('must not call'))
        with self.assertRaisesRegex(ValueError, 'dowiązania'):
            routing.refresh(self.ctx, {'codex': caller}, self.cache)
        caller.assert_not_called()
        self.assertEqual(list(destination.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
