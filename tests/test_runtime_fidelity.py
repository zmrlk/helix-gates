"""Durable runtime backend fidelity with fake processes only."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_runtime import FakeExecutor, TOOLS, FIX
import helix_runtime as rt


class DatabaseFidelityTests(unittest.TestCase):
    def test_fallback_is_announced_and_saved_before_native_start(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runner = rt.Runner(FIX/'project-runner', base/'out', executor=FakeExecutor(),
                               tools={'tools':dict(TOOLS)}, port_factory=lambda:31234)
            runner.work = FIX/'project-runner'
            runner.tmp = base/'scratch'; runner.tmp.mkdir()
            (runner.out/'logs').mkdir(parents=True)
            observed = []
            original = runner.executor.run
            def execute(argv, *args):
                if argv[0].endswith(('podman', 'docker')) and 'run' in argv:
                    return 1, 'container daemon unavailable'
                if argv[0].endswith('initdb'):
                    saved = json.loads((runner.out/'database-fidelity.json').read_text())
                    observed.append(saved)
                    self.assertEqual([r['status'] for r in saved['attempts']], ['failed', 'failed', 'starting'])
                    self.assertIn('fallback to native', saved['warnings'][-1])
                return original(argv, *args)
            runner.executor.run = execute
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                runner.database()
            self.assertTrue(observed)
            self.assertIn('fallback to native', stderr.getvalue())
            saved = json.loads((runner.out/'database-fidelity.json').read_text())
            self.assertEqual(saved['selection_status'], 'selected')
            self.assertEqual(saved['backend'], 'native')
            self.assertEqual(saved['server_version'], '16.4')
            self.assertTrue(saved['compatible'])

    def test_wrong_native_major_is_persisted_without_initializing(self):
        class WrongVersion(FakeExecutor):
            def run(self, argv, *args):
                if argv[-1] == '--version':
                    self.calls.append((argv, *args))
                    return 0, 'postgres (PostgreSQL) 14.12'
                return super().run(argv, *args)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runner = rt.Runner(FIX/'project-runner', base/'out', engine='native', executor=WrongVersion(),
                               tools={'tools':dict(TOOLS)}, port_factory=lambda:31234)
            runner.work = FIX/'project-runner'
            runner.tmp = base/'scratch'; runner.tmp.mkdir()
            (runner.out/'logs').mkdir(parents=True)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(rt.Blocked):
                runner.database()
            self.assertFalse(any(c[0][0].endswith('initdb') for c in runner.executor.calls))
            saved = json.loads((runner.out/'database-fidelity.json').read_text())
            self.assertEqual(saved['selection_status'], 'blocked')
            self.assertIsNone(saved['server_version'])
            self.assertIn('major mismatch', saved['attempts'][0]['reason'])

    def test_opt_in_mismatch_still_has_degraded_evidence(self):
        class WrongServer(FakeExecutor):
            def run(self, argv, *args):
                if argv[-1] == 'SHOW server_version': return 0, '14.12\n'
                return super().run(argv, *args)
        with tempfile.TemporaryDirectory() as directory:
            runner = rt.Runner(FIX/'project-runner', Path(directory)/'out', engine='native',
                               executor=WrongServer(), tools={'tools':dict(TOOLS)},
                               port_factory=lambda:31234, allow_version_mismatch=True)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                report = runner.run()
            self.assertEqual(report['parts'][0]['checks']['schema-apply']['status'], 'DEGRADED')
            self.assertIn('14.12 does not match target 16', stderr.getvalue())
            saved = json.loads((runner.out/'database-fidelity.json').read_text())
            self.assertFalse(saved['compatible'])
            self.assertEqual(saved['server_version'], report['database_fidelity']['server_version'])
            rt.validate_report(report)

    def test_selection_survives_interruption_before_server_ready(self):
        class Interrupted(FakeExecutor):
            def run(self, argv, *args):
                if 'run' in argv: raise KeyboardInterrupt()
                return super().run(argv, *args)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runner = rt.Runner(FIX/'project-runner', base/'out', executor=Interrupted(),
                               tools={'tools':dict(TOOLS)}, port_factory=lambda:31234)
            runner.work = FIX/'project-runner'; runner.tmp = base
            (runner.out/'logs').mkdir(parents=True)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(KeyboardInterrupt):
                runner.database()
            saved = json.loads((runner.out/'database-fidelity.json').read_text())
            self.assertEqual(saved['selection_status'], 'selecting')
            self.assertEqual(saved['attempts'][0]['status'], 'starting')
            self.assertIsNone(saved['server_version'])
