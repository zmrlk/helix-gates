"""Admission tests execute synthetic work, never recursively run the test suite."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
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

    def test_failure_names_the_failing_tests_not_the_batch_label(self):
        stderr = ("FAIL: test_b (case.Case.test_b) (report='x.json')\nERROR: test_c (case.Case.test_c)\n"
                  "Ran 4 tests in 0.01s\n\nFAILED (failures=1, errors=1)\n")
        with tempfile.TemporaryDirectory() as temp:
            suite = unittest.TestSuite([self.__class__('test_high_limits_admission_but_runs_every_batch_once')])
            execution = dict(results=[('case.Case.test_a (+3)', 1, 4, 0, stderr), ('case.Crash.test_d (+3)', 1, 0, 0, 'Segmentation fault\n')],
                             not_run=[], paused=None, resource_decisions=[])
            out = io.StringIO()
            with patch.object(sys, 'argv', ['run_tests_parallel.py', '--resource-report', temp]), patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), patch.object(unittest.defaultTestLoader, 'discover', return_value=suite), patch.object(runner, 'execute_batches', return_value=execution), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = runner.main()
            self.assertEqual(code, 1)
            report = json.loads((Path(temp) / 'test-summary.json').read_text())
        # A worker that died without unittest headers names no test: it stays a batch in `failed`.
        self.assertEqual(report['failed_tests'], ['case.Case.test_b', 'case.Case.test_c'])
        self.assertEqual(report['failed'], ['case.Case.test_a (+3)', 'case.Crash.test_d (+3)'])
        self.assertIn('FAIL case.Case.test_b, case.Case.test_c, batch case.Crash.test_d (+3) without a unittest failure header', out.getvalue())
        self.assertNotIn('test_a', out.getvalue())

    def guarded_run(self, source, *argv, real_discovery=False):
        """Real workers on a temporary test module; only the release check and discovery are replaced."""
        temp = tempfile.mkdtemp(); self.addCleanup(__import__('shutil').rmtree, temp)
        Path(temp, 'guard_case.py').write_text(source)
        report = Path(temp) / 'report'
        sys.path.insert(0, temp); self.addCleanup(sys.path.remove, temp)
        sys.modules.pop('guard_case', None); __import__('importlib').invalidate_caches()   # each scenario is a fresh module
        self.addCleanup(sys.modules.pop, 'guard_case', None)
        env = dict(runner.ENV, PYTHONPATH=temp); real_run = subprocess.run
        keys = ('PATH', 'HELIX_TEST_MODEL_CLI_LOG', 'HELIX_TEST_GUARD_BATCH'); before = {key: os.environ.get(key) for key in keys}
        # Real discovery imports the module inside the runner, like unittest discover -s tests does.
        load = ((lambda *a, **k: unittest.TestLoader().discover(temp, pattern='guard_*.py', top_level_dir=temp)) if real_discovery
                else (lambda *a, **k: unittest.defaultTestLoader.loadTestsFromName('guard_case')))
        with patch.object(runner, 'ENV', env), patch.object(sys, 'argv', ['run_tests_parallel.py', '-j', '1', '--resource-report', str(report), *argv]), \
             patch.object(runner.subprocess, 'run', side_effect=lambda *a, **k: SimpleNamespace(returncode=0) if 'check_release_version' in str(a[0]) else real_run(*a, **k)), \
             patch.object(unittest.defaultTestLoader, 'discover', side_effect=load), contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = runner.main()
        # The guard is undone afterwards (also when this suite itself runs under the guarded runner).
        self.assertEqual({key: os.environ.get(key) for key in keys}, before)
        summary = report / 'test-summary.json'
        return code, json.loads(summary.read_text()) if summary.exists() else None, out.getvalue() + err.getvalue()

    CALL = 'import subprocess, unittest\nCLI = lambda: subprocess.run(["agy", "-p", "synthetic"], capture_output=True)\n'

    def test_a_passing_test_that_starts_a_model_cli_fails_the_run(self):
        # On CI the model CLIs are absent, so such a test passes there; the runner's guard catches it,
        # names the test that ran it (not the first of its batch) and wins over an all-skipped verdict.
        code, summary, output = self.guarded_run(self.CALL + (
            'class Case(unittest.TestCase):\n'
            '    def test_a_quiet(self): pass\n'
            '    def test_b_calls_cli(self): CLI()\n'))
        self.assertEqual(code, 1)
        self.assertEqual(summary['status'], 'FAIL')
        self.assertEqual(summary['failed_tests'], [])
        self.assertEqual(summary['model_cli_calls'], ['agy [guard_case.Case.test_b_calls_cli]'])
        self.assertIn('real model CLI started by tests: agy', output)
        code, summary, _ = self.guarded_run(self.CALL + (
            'class Case(unittest.TestCase):\n'
            '    def test_calls_then_skips(self): CLI(); self.skipTest("synthetic")\n'))
        self.assertEqual((code, summary['status']), (1, 'FAIL'))
        # A caller that keeps only PATH (several Helix modules sanitize the environment) is still recorded.
        code, summary, _ = self.guarded_run(
            'import os, subprocess, unittest\n'
            'class Case(unittest.TestCase):\n'
            '    def test_sanitized_callers(self):\n'
            '        for name in ("agy", "codex", "grok", "claude", "gemini"):\n'
            '            subprocess.run([name, "--version"], env={"PATH": os.environ["PATH"]}, capture_output=True)\n')
        self.assertEqual((code, summary['status']), (1, 'FAIL'))
        self.assertEqual(sorted(call.split()[0] for call in summary['model_cli_calls']), ['agy', 'claude', 'codex', 'gemini', 'grok'])

    def test_a_call_during_discovery_fails_the_run_even_as_an_import_error(self):
        quiet = 'class Case(unittest.TestCase):\n    def test_quiet(self): pass\n'
        for call in ('CLI()\n', 'subprocess.run(["agy"], check=True)\n'):
            with self.subTest(call=call):
                code, summary, _ = self.guarded_run(self.CALL + call + quiet, real_discovery=True)
                # The module-level call runs in discovery and again when a worker imports the module.
                self.assertEqual((code, summary['status']), (1, 'FAIL'))
                self.assertIn('agy [discovery]', summary['model_cli_calls'])

    def test_a_call_with_an_unrun_batch_is_still_a_failure(self):
        seen = []
        def execute(batches, jobs, governor):
            seen.extend(batches); first, second = batches
            with open(os.environ['HELIX_TEST_MODEL_CLI_LOG'], 'a') as log: log.write('agy [' + first[0] + ']\n')
            return dict(results=[(first[0], 0, 1, 0, 'Ran 1 test in 0.01s\n\nOK\n')], not_run=[second],
                        paused=decision(0, 'critical'), resource_decisions=[decision(0, 'critical')])
        suite = unittest.TestSuite([self.__class__('test_high_limits_admission_but_runs_every_batch_once'), self.__class__('test_requested_jobs_remains_upper_bound_with_changing_pressure')])
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sys, 'argv', ['run_tests_parallel.py', '--resource-report', temp]), patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                 patch.object(unittest.defaultTestLoader, 'discover', return_value=suite), patch.object(runner, 'execute_batches', side_effect=execute), \
                 patch.dict(os.environ, {'HELIX_TEST_BATCH': '1'}), contextlib.redirect_stdout(io.StringIO()):
                code = runner.main()
            report = json.loads((Path(temp) / 'test-summary.json').read_text())
        self.assertEqual(len(seen), 2)
        self.assertEqual((code, report['status'], report['model_cli_calls'], report['not_run']), (1, 'FAIL', ['agy [' + seen[0][0] + ']'], [seen[1]]))

    def test_serial_mode_is_the_test_command_and_its_real_worker_is_guarded(self):
        self.assertEqual(json.loads((ROOT / 'helix.json').read_text())['test_cmd'], 'python3 scripts/run_tests_parallel.py --serial')
        with tempfile.TemporaryDirectory() as temp:
            tree = Path(temp) / 'tree'; (tree / 'tests/fixtures').mkdir(parents=True)
            (tree / 'tests/fixtures/model-cli-guard.sh').write_bytes((ROOT / 'tests/fixtures/model-cli-guard.sh').read_bytes())
            (tree / 'tests/fixtures/model-cli-guard.sh').chmod(0o755)
            real_run = subprocess.run; outputs = []; release_checks = []; env = dict(runner.ENV); env_before = dict(env)
            keys = ('PATH', 'HELIX_TEST_MODEL_CLI_LOG', 'HELIX_TEST_GUARD_BATCH'); process_before = {key: os.environ.get(key) for key in keys}
            def worker(*args, **kwargs):
                if 'check_release_version' in str(args[0]): release_checks.append(args); return SimpleNamespace(returncode=0)
                done = real_run(*args, **kwargs); outputs.append(done.stderr); return done
            # A CLI call fails, a quiet test passes, an all-skipped suite is no evidence; each run writes its own summary.
            for index, (body, expected, status) in enumerate((('CLI()', 1, 'FAIL'), ('pass', 0, 'PASS'), ('self.skipTest("synthetic")', 2, 'INCOMPLETE'))):
                report = Path(temp) / ('report-' + str(index))
                (tree / 'tests/test_guard_serial.py').write_text(self.CALL + 'class Case(unittest.TestCase):\n    def test_serial(self): ' + body + '\n')
                with patch.object(runner, 'ROOT', str(tree)), patch.object(runner, 'ENV', env), patch.object(runner.subprocess, 'run', side_effect=worker), \
                     patch.object(sys, 'argv', ['run_tests_parallel.py', '--serial', '--resource-report', str(report)]), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(runner.main(), expected, err.getvalue())
                self.assertRegex(outputs[-1], r'(?m)^Ran 1 test in')
                self.assertEqual(env, env_before)
                self.assertEqual({key: os.environ.get(key) for key in keys}, process_before)
                self.assertEqual(json.loads((report / 'test-summary.json').read_text())['status'], status)
                self.assertEqual(len(list(report.glob('model-cli-guard-*'))), 1)
                if expected == 1: self.assertIn('real model CLI started by tests: agy [test_guard_serial.Case.test_serial]', err.getvalue())
            # A report directory is single-use: a later run cannot leave an earlier summary in place.
            with patch.object(sys, 'argv', ['run_tests_parallel.py', '--serial', '--resource-report', str(Path(temp) / 'report-1')]), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as refused:
                runner.main()
            self.assertEqual(refused.exception.code, 2)
            # The behaviour gate does not depend on release history; CI checks that in its own step.
            self.assertEqual(release_checks, [])

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
