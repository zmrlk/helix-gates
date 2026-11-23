"""Admission tests execute synthetic work, never recursively run the test suite."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
spec = importlib.util.spec_from_file_location('resource_test_runner', ROOT / 'scripts/run_tests_parallel.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def decision(jobs, state='normal'):
    return dict(effective_jobs=jobs, requested_jobs=3, state=state, reason=state)


class TestRunnerResources(unittest.TestCase):
    def test_worker_exit_zero_requires_full_unittest_completion(self):
        cases = [('', False), ('Ran 0 tests in 0.001s\n\nOK\n', False),
                 ('Ran 1 test in 0.001s\n\nFAILED (errors=1)\n', False),
                 ('Ran 1 test in 0.001s\n\nOK\n', True),
                 ('Ran 1 test in 0.001s\n\nOK (skipped=1)\n', True)]
        for stderr, good in cases:
            with self.subTest(stderr=stderr), patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr=stderr)):
                result = runner.run(['synthetic_case.test_one'])
            self.assertEqual(result[1] == 0, good)
        with patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr='Ran 1 test in 0.001s\n\nOK\n')):
            self.assertNotEqual(runner.run(['case.test_one', 'case.test_two'])[1], 0)
        nested = 'Ran 1 test in 0.001s\n\nOK\nRan 2 tests in 0.002s\n\nOK\n'
        with patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr=nested)):
            self.assertEqual(runner.run(['case.test_one', 'case.test_two'])[1], 0)

    def test_real_worker_exiting_zero_before_tests_is_an_error(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, 'premature_case.py').write_text('import os\nos._exit(0)\n')
            env = dict(runner.ENV, PYTHONPATH=temp)
            with patch.object(runner, 'ENV', env):
                result = runner.run(['premature_case'])
            self.assertEqual(result[1], 1)
            self.assertEqual(result[2], 0)
            self.assertIn('exit 0 alone is insufficient', result[4])

    def test_incomplete_suite_returns_nonzero_and_writes_unchecked_batches(self):
        with tempfile.TemporaryDirectory() as temp:
            suite = unittest.TestSuite([self.__class__('test_high_limits_admission_but_runs_every_batch_once')])
            pending = [['test_package.test_case']]
            execution = dict(results=[], not_run=pending, paused=decision(0, 'critical'), resource_decisions=[decision(0, 'critical')])
            with patch.object(sys, 'argv', ['run_tests_parallel.py', '-j', '2', '--resource-report', temp]), patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), patch.object(unittest.defaultTestLoader, 'discover', return_value=suite), patch.object(runner, 'execute_batches', return_value=execution), contextlib.redirect_stdout(io.StringIO()):
                code = runner.main()
            self.assertEqual(code, 2)
            report = json.loads((Path(temp) / 'test-summary.json').read_text())
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertEqual(report['not_run'], pending)
            self.assertEqual(report['tests'], 0)
            self.assertEqual(report['requested_jobs'], 2)

    def test_empty_discovery_is_incomplete_even_without_worker_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sys, 'argv', ['run_tests_parallel.py', '--resource-report', temp]), patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), patch.object(unittest.defaultTestLoader, 'discover', return_value=unittest.TestSuite()), contextlib.redirect_stdout(io.StringIO()):
                code = runner.main()
            self.assertEqual(code, 2)
            report = json.loads((Path(temp) / 'test-summary.json').read_text())
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertTrue(report['discovery_empty'])
            self.assertEqual(report['tests'], 0)

    def test_every_test_skipped_does_not_claim_a_complete_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            suite = unittest.TestSuite([self.__class__('test_high_limits_admission_but_runs_every_batch_once')])
            execution = dict(results=[('skipped-test', 0, 1, 0, 'Ran 1 test in 0.01s\nOK (skipped=1)\n')], not_run=[], paused=None, resource_decisions=[])
            with patch.object(sys, 'argv', ['run_tests_parallel.py', '--resource-report', temp]), patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), patch.object(unittest.defaultTestLoader, 'discover', return_value=suite), patch.object(runner, 'execute_batches', return_value=execution), contextlib.redirect_stdout(io.StringIO()):
                code = runner.main()
            self.assertEqual(code, 2)
            report = json.loads((Path(temp) / 'test-summary.json').read_text())
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertEqual(report['skipped'], 1)

    def test_high_limits_admission_but_runs_every_batch_once(self):
        class Governor:
            def decision(self): return decision(1, 'high')
            def wait(self): raise AssertionError('high must still admit one batch')
        lock = threading.Lock()
        counts = dict(active=0, peak=0)
        seen = []
        def work(batch):
            with lock:
                counts['active'] += 1
                counts['peak'] = max(counts['peak'], counts['active'])
                seen.append(batch[0])
            time.sleep(.005)
            with lock: counts['active'] -= 1
            return batch[0], 0, 1, .005, ''
        result = runner.execute_batches([[str(i)] for i in range(6)], 3, Governor(), work)
        self.assertEqual(counts['peak'], 1)
        self.assertEqual(seen, [str(i) for i in range(6)])
        self.assertEqual(len(result['results']), 6)
        self.assertEqual(result['not_run'], [])

    def test_critical_drains_active_and_then_resumes_without_duplicates(self):
        first_started = threading.Event()
        first_finished = threading.Event()
        waits = []
        class Governor:
            def __init__(self): self.calls = 0; self.resumed = False
            def decision(self):
                self.calls += 1
                if self.resumed: return decision(1)
                return decision(1) if self.calls == 1 else decision(0, 'critical')
            def wait(self):
                if not first_finished.is_set(): raise AssertionError('active work must drain before waiting')
                waits.append(True); self.resumed = True
                return decision(1)
        seen = []
        def work(batch):
            seen.append(batch[0])
            if batch[0] == 'first':
                first_started.set(); time.sleep(.015); first_finished.set()
            return batch[0], 0, 1, 0, ''
        result = runner.execute_batches([['first'], ['second'], ['third']], 3, Governor(), work)
        self.assertTrue(first_started.is_set()); self.assertEqual(waits, [True])
        self.assertEqual(seen, ['first', 'second', 'third'])
        self.assertEqual(result['not_run'], []); self.assertIsNone(result['paused'])

    def test_pause_timeout_keeps_not_run_explicit_and_preserves_results(self):
        from helix_resources import ResourcePaused
        class Governor:
            def __init__(self): self.calls = 0
            def decision(self):
                self.calls += 1
                return decision(1) if self.calls == 1 else decision(0, 'critical')
            def wait(self): raise ResourcePaused('Host remains critical', decision(0, 'critical'))
        executed = []
        def work(batch):
            executed.append(batch[0]); return batch[0], 0, 1, 0, ''
        result = runner.execute_batches([['done'], ['not_checked']], 3, Governor(), work)
        self.assertEqual(executed, ['done'])
        self.assertEqual(result['not_run'], [['not_checked']])
        self.assertEqual(result['paused']['state'], 'critical')
        self.assertEqual(result['results'][0][0], 'done')

    def test_requested_jobs_remains_upper_bound_with_changing_pressure(self):
        class Governor:
            def decision(self): return decision(2)
        lock = threading.Lock(); counts = dict(active=0, peak=0)
        def work(batch):
            with lock:
                counts['active'] += 1; counts['peak'] = max(counts['peak'], counts['active'])
            time.sleep(.005)
            with lock: counts['active'] -= 1
            return batch[0], 0, 1, .005, ''
        result = runner.execute_batches([[str(i)] for i in range(8)], 2, Governor(), work)
        self.assertLessEqual(counts['peak'], 2)
        self.assertEqual(len(result['results']), 8)
