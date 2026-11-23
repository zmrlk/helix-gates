"""Actual PostgreSQL major admission with fake commands, never live services."""
import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_runtime import FakeExecutor, FIX, TOOLS
import helix_runtime as runtime


class ActualVersionExecutor(FakeExecutor):
    def __init__(self, versions):
        super().__init__()
        self.versions = iter(versions)
        self.observed = []

    def run(self, argv, cwd, env, timeout):
        result = super().run(argv, cwd, env, timeout)
        if argv[-1] == 'SHOW server_version':
            version = next(self.versions)
            self.observed.append((argv[1], version))
            return 0, version + '\n'
        return result


class RuntimeActualVersion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.count = 0

    def runner(self, engine, versions, *, override=False, manual=False, tools=None):
        self.count += 1
        out = self.base / ('out-' + str(self.count))
        ports = iter((31234, 31235, 31236))
        runner = runtime.Runner(FIX / 'sveltekit-pg', out, engine=engine,
            executor=ActualVersionExecutor(versions), tools={'tools': dict(TOOLS if tools is None else tools)},
            port_factory=lambda: next(ports), allow_version_mismatch=override)
        if manual:
            runner.work = FIX / 'sveltekit-pg'
            runner.tmp = self.base / ('scratch-' + str(self.count)); runner.tmp.mkdir(mode=0o700)
            (runner.tmp / 'home').mkdir(mode=0o700)
            (out / 'logs').mkdir(parents=True)
            runner.env = {'PATH': '/fake', 'HOME': str(runner.tmp / 'home'), 'CI': '1'}
        return runner

    @contextlib.contextmanager
    def offline(self):
        with contextlib.redirect_stderr(io.StringIO()), \
             patch.object(socket, 'socket', side_effect=AssertionError('unexpected network')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected process')), \
             patch('helix_environment._git_ref', return_value={
                 'head': None, 'dirty': None, 'status': 'unknown', 'reason': 'synthetic fixture'}):
            yield

    def saved(self, runner):
        return json.loads((runner.out / 'database-fidelity.json').read_text())

    def assert_owned_cleanup(self, runner, engine):
        commands = [c[0] for c in runner.executor.calls]
        if engine == 'native':
            starts = [c for c in commands if c[0].endswith('pg_ctl') and c[-1] == 'start']
            stops = [c for c in commands if c[0].endswith('pg_ctl') and c[-1] == 'stop']
            self.assertEqual(len(starts), 1); self.assertEqual(len(stops), 1)
            self.assertEqual(starts[0][starts[0].index('-D') + 1], stops[0][stops[0].index('-D') + 1])
        elif engine == 'docker':
            starts = [c for c in commands if c[0].endswith('docker') and c[1] == 'run']
            removes = [c for c in commands if c[0].endswith('docker') and c[1:3] == ['rm', '-f']]
            self.assertEqual(len(starts), 1); self.assertEqual(len(removes), 1)
            self.assertEqual(starts[0][starts[0].index('--name') + 1], removes[0][-1])
        else:
            creates = [c[-1] for c in commands if c[-1].startswith('CREATE DATABASE helix_rt_')]
            drops = [c[-1] for c in commands if c[-1].startswith('DROP DATABASE ')]
            self.assertEqual(len(creates), 1); self.assertEqual(len(drops), 1)
            owned = creates[0].removeprefix('CREATE DATABASE ')
            self.assertEqual(drops, ['DROP DATABASE ' + owned + ' WITH (FORCE)'])

    def test_native_container_service_refuse_actual_mismatch_before_application_work(self):
        for engine in ('native', 'docker', 'service'):
            with self.subTest(engine=engine):
                runner = self.runner(engine, ['14.12'])
                with self.offline():
                    report = runner.run()
                fidelity = self.saved(runner)
                self.assertIsNone(runner.db)
                self.assertIsNone(report['engine'])
                self.assertEqual(report['status'], 'BLOCKED')
                self.assertEqual(fidelity['target']['major'], 16)
                self.assertEqual(fidelity['server_version'], '14.12')
                self.assertFalse(fidelity['compatible'])
                self.assertEqual(fidelity['selection_status'], 'blocked')
                self.assertEqual(fidelity['attempts'][0]['status'], 'failed')
                self.assertEqual(fidelity['attempts'][0]['server_version'], '14.12')
                self.assertIn('actual PostgreSQL server major mismatch', fidelity['attempts'][0]['reason'])
                self.assertEqual(report['database_fidelity'], fidelity)
                self.assertEqual(runner.executor.started, [])
                commands = [call[0] for call in runner.executor.calls]
                self.assertFalse(any('-f' in command for command in commands if command[0].endswith('psql')))
                self.assertFalse(any(command[0].endswith(('npm', 'pnpm', 'yarn')) for command in commands))
                self.assert_owned_cleanup(runner, engine)
                runtime.validate_report(report)

    def test_auto_fallback_cleans_rejected_backend_and_measures_next_server_independently(self):
        tools = dict(TOOLS); tools.pop('podman')
        runner = self.runner('auto', ['14.12', '16.4'], manual=True, tools=tools)
        with self.offline():
            runner.database()
        fidelity = self.saved(runner)
        self.assertEqual([(a['backend'], a['status']) for a in fidelity['attempts']],
            [('podman', 'unavailable'), ('docker', 'failed'), ('native', 'ready')])
        self.assertEqual([(a['server_version'], a['compatible']) for a in fidelity['attempts'][1:]],
                         [('14.12', False), ('16.4', True)])
        self.assertEqual((fidelity['backend'], fidelity['server_version'], fidelity['compatible']), ('native', '16.4', True))
        self.assertEqual(fidelity['selection_status'], 'selected')
        self.assertEqual(runner.used_engine, 'native')
        self.assertIn(':31235/', runner.db)
        self.assertEqual([version for _, version in runner.executor.observed], ['14.12', '16.4'])
        self.assertNotEqual(runner.executor.observed[0][0], runner.executor.observed[1][0])
        commands = [c[0] for c in runner.executor.calls]
        remove = next(i for i, c in enumerate(commands) if c[0].endswith('docker') and c[1:3] == ['rm', '-f'])
        initialize = next(i for i, c in enumerate(commands) if c[0].endswith('initdb'))
        self.assertLess(remove, initialize)
        self.assert_owned_cleanup(runner, 'docker')
        self.assertEqual(len(runner.cleanup_actions), 1)
        with self.offline():
            for action in reversed(runner.cleanup_actions): action()
        self.assert_owned_cleanup(runner, 'native')

    def test_override_keeps_known_mismatch_degraded_and_never_admits_unknown_version(self):
        runner = self.runner('native', ['14.12'], override=True)
        with self.offline():
            report = runner.run()
        self.assertIsNotNone(runner.db)
        self.assertTrue(runner.executor.started)
        fidelity = self.saved(runner)
        self.assertFalse(fidelity['compatible'])
        self.assertEqual(fidelity['server_version'], '14.12')
        self.assertEqual(fidelity['selection_status'], 'selected')
        for name in ('schema-apply', 'backup', 'load'):
            self.assertEqual(report['parts'][0]['checks'][name]['status'], 'DEGRADED', name)
        runtime.validate_report(report)
        for actual in ('', 'unknown', '16.not-a-version'):
            for override in (False, True):
                with self.subTest(actual=actual, override=override):
                    runner = self.runner('service', [actual], override=override, manual=True)
                    with self.offline(), self.assertRaises(runtime.Blocked):
                        runner.database()
                    saved = self.saved(runner)
                    self.assertIsNone(runner.db)
                    self.assertEqual(saved['server_version'], actual)
                    self.assertFalse(saved['compatible'])
                    self.assertEqual(saved['selection_status'], 'blocked')
                    self.assertEqual(saved['attempts'][0]['status'], 'failed')
                    self.assertIn('version is unknown', saved['attempts'][0]['reason'])
                    self.assert_owned_cleanup(runner, 'service')
                    self.assertEqual(runner.cleanup_actions, [])


if __name__ == '__main__':
    unittest.main()
