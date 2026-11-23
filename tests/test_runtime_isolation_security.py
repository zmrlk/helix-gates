"""Independent admission boundaries; no real service, network or sandbox probe."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_runtime import FakeExecutor, FIX, TOOLS, SyntheticNetworkGuard
import helix_runtime as runtime
import helix_runtime_isolation as isolation
import helix_runtime_isolation_probe as isolation_probe


CANARY = 'PRIVATE_ISOLATION_CANARY'


class DeniedBackend:
    """A refusal oracle, never a claim that an OS backend is working."""
    def __init__(self): self.policies = []
    def capability(self):
        return dict(backend='unavailable', status='blocked', reason_code='PROBE_DENIED')
    def admit(self, policy, remaining):
        self.policies.append(copy.deepcopy(policy))
        return dict(enforcement='blocked', proof_kind='none', backend='unavailable',
                    reason_code='PROBE_DENIED', policy_hash=None, scope=policy['scope'])
    def wrap(self, argv, grant):
        raise AssertionError('refused grant must never reach wrapping or execution')


class RuntimeIsolationSecurity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.number = 0

    @contextlib.contextmanager
    def offline(self):
        with contextlib.redirect_stderr(io.StringIO()), \
             patch.object(socket, 'socket', side_effect=AssertionError('unexpected network')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected process')), \
             patch('helix_environment._git_ref', return_value={
                 'head': None, 'dirty': None, 'status': 'unknown', 'reason': 'synthetic fixture'}):
            yield

    def runner(self, backend, *, engine='native', executor=None, manual=False):
        self.number += 1
        project = self.base / ('project-' + str(self.number))
        shutil.copytree(FIX / 'sveltekit-pg', project)
        runner = runtime.Runner(project, self.base / ('out-' + str(self.number)), engine=engine,
            executor=executor or FakeExecutor(), tools={'tools': dict(TOOLS)},
            port_factory=lambda: 31234, network_guard=backend)
        if manual:
            runner.work = project
            runner.tmp = self.base / ('scratch-' + str(self.number)); runner.tmp.mkdir(mode=0o700)
            (runner.tmp / 'home').mkdir(mode=0o700)
            (runner.out / 'logs').mkdir(parents=True)
            runner.env = dict(PATH='/fake', HOME=str(runner.tmp / 'home'), CI='1', PORT='31235')
            runner.database_network = dict(port=31234, data=runner.tmp / 'pgdata',
                socket=runner.tmp / '.s.PGSQL.31234', log=runner.out / 'logs/postgres.log')
        return runner

    def test_admission_refusal_precedes_every_project_phase_and_spawn(self):
        for phase in ('install', 'migration', 'build', 'application', 'measurement', 'database_server'):
            with self.subTest(phase=phase):
                backend = DeniedBackend(); runner = self.runner(backend, manual=True)
                # This test isolates the process boundary. The independent SQL
                # admission test below starts with the server unconfirmed.
                runner.database_network_ready = True
                with self.offline(), self.assertRaises(runtime.Blocked):
                    runner.project_command(['synthetic-target', '--phase', phase], phase=phase)
                self.assertEqual(runner.executor.calls, [])
                self.assertTrue(backend.policies)
                with self.offline(), self.assertRaises(runtime.Blocked):
                    runner.project_spawn(['synthetic-target'], runner.work, runner.env,
                                         runner.tmp / 'application.log', phase=phase)
                self.assertEqual(runner.executor.started, [])
                self.assertEqual(runner.executor.calls, [])

    def test_node_python_install_and_retry_never_escape_refused_boundary(self):
        for manager, lock in (('npm', 'package-lock.json'), ('pnpm', 'pnpm-lock.yaml'), ('pip', None)):
            with self.subTest(manager=manager):
                backend = DeniedBackend(); runner = self.runner(backend, manual=True)
                with self.offline(), self.assertRaises(runtime.Blocked):
                    runner.install(dict(workspace='.', package_manager=manager, lockfile=lock))
                self.assertTrue(backend.policies)
                self.assertEqual(runner.executor.calls, [])

    def test_server_scope_is_required_before_sql_restore_or_trial_migrations(self):
        for operation in ('sql', 'restore', 'trial'):
            with self.subTest(operation=operation):
                backend = DeniedBackend(); runner = self.runner(backend, manual=True)
                runner.db = 'postgresql://helix@127.0.0.1:31234/helix'
                self.assertFalse(runner.database_network_ready)
                migration = dict(kind='sql', path='manual.sql')
                (runner.work / 'manual.sql').write_text('CREATE TABLE own_items(id integer);')
                with self.offline():
                    if operation == 'sql':
                        with self.assertRaises(runtime.Blocked):
                            runner.project_command(['/fake/psql', runner.db, '-f', runner.work / 'manual.sql'], phase='migration')
                    elif operation == 'restore':
                        with self.assertRaises(runtime.Blocked): runner.backup()
                    else:
                        part = dict(path='.', env=[], migrations=[migration], schema_selection={}, schema_strategies=[
                            dict(root='.', strategy='only', trial_required=True,
                                 candidates=[dict(strategy='only', migrations=[migration])])])
                        try: runner.select_schema(part)
                        except runtime.Blocked: pass
                commands = [row[0] for row in runner.executor.calls]
                self.assertFalse(any('-f' in argv or any('pg_restore' in str(x) or 'pg_dump' in str(x) for x in argv)
                                     for argv in commands), commands)
                self.assertFalse(runner.database_network_ready)
                self.assertEqual(runner.applied, set())

    def test_synthetic_receipt_cannot_be_projected_as_real_enforcement(self):
        row = dict(enforcement='simulated', proof_kind='synthetic_test', backend='test-fixture',
            reason_code='SYNTHETIC_TEST', policy_hash='1' * 64, scope='project',
            phase='application', command_invoked=True)
        report = dict(network_isolation=runtime.network_isolation_record([row]))
        projected = runtime.project_network_isolation(report)
        self.assertEqual(projected['status'], 'SIMULATED')
        self.assertEqual(projected['coverage_status'], 'INCOMPLETE')
        self.assertEqual(projected['counts']['enforced'], 0)
        self.assertEqual(projected['counts']['simulated'], 1)
        for changes in ({'enforcement': 'enforced'}, {'proof_kind': 'execution'},
                        {'command_invoked': 1}, {'private_env': CANARY}):
            forged = dict(row, **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runtime.project_network_isolation(dict(network_isolation=runtime.network_isolation_record([forged])))
        legacy = runtime.project_network_isolation({})
        self.assertEqual(legacy['status'], 'NOT_RECORDED')
        self.assertTrue(all(value is None for value in legacy['counts'].values()))

    def test_database_engine_selection_never_falls_back_to_unprotected_execution(self):
        for engine in ('native', 'docker', 'service', 'auto'):
            with self.subTest(engine=engine):
                runner = self.runner(DeniedBackend(), engine=engine, manual=True)
                with self.offline(), self.assertRaises(runtime.Blocked): runner.database()
                self.assertIsNone(runner.db)
                self.assertFalse(runner.database_network_ready)
                self.assertEqual(runner.executor.calls, [])
                self.assertEqual(runner.executor.started, [])
                fidelity = json.loads((runner.out / 'database-fidelity.json').read_text())
                self.assertEqual(fidelity['selection_status'], 'blocked')
                self.assertIsNone(fidelity['server_version'])
                receipt = json.loads((runner.out / 'network-isolation.json').read_text())
                self.assertEqual(receipt['status'], 'BLOCKED')
                self.assertTrue(all(not row['command_invoked'] for row in receipt['records']))
                self.assertEqual(runtime.project_network_isolation(dict(network_isolation=receipt))['coverage_status'], 'INCOMPLETE')

    def policy_fixture(self):
        self.number += 1
        root = self.base / ('policy-' + str(self.number)); root.mkdir(mode=0o700)
        for name in ('work', 'read', 'original'):(root / name).mkdir(mode=0o700)
        backend = isolation.SeatbeltBackend(root / 'control')
        policy = dict(scope='project', connect_tcp=[31234], listen_tcp=[31235], unix_sockets=[],
                      writable_roots=[str(root / 'work')], writable_files=[],
                      readonly_roots=[str(root / 'read')], protected_roots=[str(root / 'original')])
        return backend, policy

    @contextlib.contextmanager
    def mocked_probe(self, backend):
        # This only tests admission parsing and profile construction. No OS
        # protection is established by replacing the neutral probe transport.
        def proof(policy, profile_path, remaining):
            required = isolation.required_probe_checks(policy)
            return dict(status='passed', checks={key:True for key in required},
                child_checks={key:True for key in required}, cleanup=True,
                policy_hash=hashlib.sha256(profile_path.read_bytes()).hexdigest(), probe_policy_hash='2' * 64)
        with patch.object(backend, 'capability', return_value=dict(backend='macos-seatbelt',
                status='present_not_probed', reason_code='SANDBOX_EXEC_PRESENT')), \
             patch.object(backend, '_probe', side_effect=proof) as probe, self.offline():
            yield probe

    def test_real_profile_uses_remote_exact_ports_and_no_source_or_unix_wildcards(self):
        backend, policy = self.policy_fixture()
        before = copy.deepcopy(policy)
        with self.mocked_probe(backend): grant = backend.admit(policy, 3)
        self.assertEqual(grant['enforcement'], 'enforced')
        profile = Path(grant['profile_path']).read_text()
        self.assertIn('(deny default)', profile)
        self.assertIn('(remote tcp "localhost:31234")', profile)
        self.assertIn('(local tcp "localhost:31235")', profile)
        self.assertNotIn('(local ip', profile)
        self.assertNotIn('localhost:*', profile)
        self.assertNotIn('unix-socket', profile)
        self.assertNotIn('system.sb', profile)
        self.assertNotIn('docker.sock', profile)
        self.assertEqual(policy, before)
        policy['connect_tcp'].append(65534)
        self.assertNotIn('65534', Path(grant['profile_path']).read_text())

    def test_grants_are_instance_bound_single_use_and_profiles_are_immutable(self):
        for mutation in ('none', 'public', 'profile'):
            with self.subTest(mutation=mutation):
                backend, policy = self.policy_fixture()
                with self.mocked_probe(backend): grant = backend.admit(policy, 3)
                other = isolation.SeatbeltBackend(backend.control_dir)
                with self.assertRaises(ValueError): other.wrap(['synthetic-child'], grant)
                if mutation == 'public': grant['scope'] = 'database_server'
                elif mutation == 'profile':
                    path = Path(grant['profile_path']); path.chmod(0o600)
                    path.write_text('(version 1)\n(allow default)\n')
                if mutation == 'none':
                    wrapped = backend.wrap(['synthetic-child', '--arg', CANARY], grant)
                    self.assertEqual(wrapped, [isolation.SANDBOX_EXEC, '-f', grant['profile_path'],
                                               'synthetic-child', '--arg', CANARY])
                else:
                    with self.assertRaises(ValueError): backend.wrap(['synthetic-child'], grant)
                with self.assertRaises(ValueError): backend.wrap(['synthetic-child'], grant)

    def test_invalid_scope_and_incomplete_probe_never_create_a_usable_grant(self):
        for replacement in ({'connect_tcp':[True]}, {'connect_tcp':[0]}, {'connect_tcp':[65536]},
                            {'connect_tcp':['127.0.0.1:31234']}, {'private_env':CANARY},
                            {'writable_roots':['/']}, {'unix_sockets':['/var/run/docker.sock']}):
            with self.subTest(replacement=replacement):
                backend, policy = self.policy_fixture()
                with self.mocked_probe(backend) as probe:
                    grant = backend.admit(dict(policy, **replacement), 3)
                self.assertEqual(grant['enforcement'], 'blocked')
                probe.assert_not_called()
                self.assertNotIn(CANARY, json.dumps(grant))
                with self.assertRaises(ValueError): backend.wrap(['synthetic-child'], grant)
        backend, policy = self.policy_fixture()
        with self.mocked_probe(backend), patch.object(backend, '_probe', return_value=dict(status='passed', checks={})):
            grant = backend.admit(policy, 3)
        self.assertEqual((grant['enforcement'], grant['reason_code']), ('blocked', 'PROBE_INCOMPLETE'))
        backend, policy = self.policy_fixture()
        policy['unix_sockets'] = [str(Path(policy['writable_roots'][0]) / 'owned.sock')]
        def missing_unix_proof(policy, path, _):
            return dict(status='passed', checks={key:True for key in isolation.PROBE_CHECKS},
                child_checks={key:True for key in isolation.PROBE_CHECKS}, cleanup=True,
                policy_hash=hashlib.sha256(path.read_bytes()).hexdigest(), probe_policy_hash='2' * 64)
        with self.mocked_probe(backend), patch.object(backend, '_probe', side_effect=missing_unix_proof):
            grant = backend.admit(policy, 3)
        self.assertEqual((grant['enforcement'], grant['reason_code']), ('blocked', 'PROBE_INCOMPLETE'))

    def test_project_environment_cannot_expand_policy_or_export_host_relays(self):
        guard = SyntheticNetworkGuard(); runner = self.runner(guard, manual=True)
        runner.network_connect_ports = {31234}; runner.network_listen_ports = {31235}
        forbidden = ('DOCKER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_HOST', 'SSH_AUTH_SOCK',
                     'HTTP_PROXY', 'ALL_PROXY', 'NODE_OPTIONS', 'PYTHONPATH', 'BASH_ENV',
                     'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'OPENSSL_CONF', 'SSLKEYLOGFILE')
        runner.env.update({name: CANARY for name in forbidden}); runner.env['PORT'] = '65534'
        original = copy.deepcopy(runner.env)
        with self.offline():
            runner.project_command(['bash', '-c', 'synthetic-child'], phase='build')
            runner.command(['/fake/pg_ctl', '-D', 'owned', 'stop'], cleanup=True)
        self.assertEqual(runner.env, original)
        self.assertEqual(guard.policies[-1]['connect_tcp'], [31234])
        self.assertEqual(guard.policies[-1]['listen_tcp'], [31235])
        self.assertEqual(guard.policies[-1]['unix_sockets'], [])
        self.assertEqual(guard.wrapped, [['bash', '-c', 'synthetic-child']])
        for _, _, env, _ in runner.executor.calls:
            self.assertTrue(set(forbidden).isdisjoint(env))
        self.assertNotIn(CANARY, (runner.out / 'network-isolation.json').read_text())

    def test_actual_runner_routes_all_phases_and_keeps_synthetic_results_incomplete(self):
        guard = SyntheticNetworkGuard(); runner = self.runner(guard)
        with self.offline(), patch.object(runner.executor, 'spawn', wraps=runner.executor.spawn) as spawn:
            report = runner.run()
        projection = runtime.project_network_isolation(report)
        self.assertEqual(projection['status'], 'SIMULATED')
        self.assertEqual(projection['coverage_status'], 'INCOMPLETE')
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(projection['counts']['enforced'], 0)
        self.assertEqual({row['phase'] for row in projection['records'] if row['command_invoked']},
                         {'database_server', 'migration', 'install', 'build', 'application', 'measurement'})
        wrapped = guard.wrapped
        self.assertTrue(any(argv[0].endswith('pg_ctl') and argv[-1] == 'start' for argv in wrapped))
        self.assertTrue(any(argv[0].endswith('pg_restore') for argv in wrapped))
        for argv, _, _, _ in runner.executor.calls:
            is_target = (argv[0].endswith(('npm', 'lighthouse', 'k6')) and argv[-1] != '--version') or \
                        any(str(arg).endswith('runtime-browser.cjs') for arg in argv) or \
                        ('-f' in argv and 'migration' in argv[-1])
            if is_target:self.assertIn(argv, wrapped)
        for call in spawn.call_args_list:self.assertIn([str(arg) for arg in call.args[0]], wrapped)
        self.assertEqual(runner.executor.started, runner.executor.stopped)
        runtime.validate_report(report)

    def test_runner_native_and_measurement_scopes_survive_real_policy_validation(self):
        runner = self.runner(DeniedBackend(), manual=True)
        work = runner.tmp / 'work'; shutil.copytree(runner.work, work); runner.work = work
        runner.database_network['socket'] = runner.tmp / 'pg-socket' / '.s.PGSQL.31234'
        runner.database_network['data'].mkdir(mode=0o700)
        runner.database_network['socket'].parent.mkdir(mode=0o700)
        backend = isolation.SeatbeltBackend(runner.tmp / 'network-control')
        for phase in ('database_server', 'measurement'):
            with self.subTest(phase=phase):
                policy = runner.isolation_policy(phase)
                with self.mocked_probe(backend): grant = backend.admit(policy, 3)
                self.assertEqual(grant['enforcement'], 'enforced', grant)
                profile = Path(grant['profile_path']).read_text()
                self.assertNotIn('(deny file-read* (subpath ' + json.dumps(str(runtime.HOME)) + '))', profile)
                self.assertNotIn('(deny file-read* file-write* (subpath ' + json.dumps(str(runtime.HOME)) + '))', profile)
                self.assertIn('(deny file-write* (subpath ' + json.dumps(str(runtime.HOME)) + '))', profile)
                if phase == 'database_server':
                    self.assertEqual(policy['connect_tcp'], [])
                    self.assertEqual(policy['listen_tcp'], [31234])
                    self.assertIn(str(runner.database_network['socket'].parent), policy['writable_roots'])
                else:self.assertEqual(policy['unix_sockets'], [])

    def test_real_executor_seals_descriptors_and_stdin_for_run_and_spawn(self):
        process = Mock(returncode=0, pid=12345)
        process.communicate.return_value = ('synthetic output', None)
        log = self.base / 'owned.log'
        with patch.object(subprocess, 'Popen', return_value=process) as popen:
            self.assertEqual(runtime.Executor().run(['synthetic-child'], self.base, {}, 2), (0, 'synthetic output'))
            self.assertIs(runtime.Executor().spawn(['synthetic-child'], self.base, {}, log), process)
        self.assertEqual(popen.call_count, 2)
        for call in popen.call_args_list:
            self.assertIs(call.kwargs['close_fds'], True)
            self.assertEqual(call.kwargs['pass_fds'], ())
            self.assertEqual(call.kwargs['stdin'], subprocess.DEVNULL)
            self.assertIs(call.kwargs['start_new_session'], True)
        self.assertEqual(popen.call_args_list[0].kwargs['stdout'], subprocess.PIPE)
        self.assertTrue(popen.call_args_list[1].kwargs['stdout'].closed)

    def test_real_executor_interrupt_stops_owned_process_group(self):
        for failure in (KeyboardInterrupt(), subprocess.TimeoutExpired(['synthetic-child'], 1)):
            with self.subTest(failure=type(failure).__name__):
                process = Mock(returncode=None, pid=12345)
                process.communicate.side_effect = failure
                executor = runtime.Executor()
                with patch.object(subprocess, 'Popen', return_value=process), patch.object(executor, 'stop') as stop:
                    with self.assertRaises(type(failure)):
                        executor.run(['synthetic-child'], self.base, {}, 1)
                    stop.assert_called_once_with(process)

    def test_neutral_probe_cleans_group_even_when_launcher_already_exited(self):
        process = Mock(returncode=0, pid=12345)
        process.communicate.return_value = (b'neutral output', None)
        process.poll.return_value = 0
        with patch.object(subprocess, 'Popen', return_value=process) as popen, \
             patch.object(isolation_probe.time, 'monotonic', return_value=1), \
             patch.object(os, 'killpg') as kill:
            result = isolation_probe._command(['neutral-child'], {'HOME': str(self.base)}, 2)
        self.assertEqual(result, (0, b'neutral output'))
        kill.assert_called_once_with(12345, runtime.signal.SIGKILL)
        self.assertEqual(popen.call_args.kwargs['pass_fds'], ())
        self.assertIs(popen.call_args.kwargs['close_fds'], True)
        self.assertEqual(popen.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_interrupt_after_project_spawn_still_closes_owned_process(self):
        runner = self.runner(SyntheticNetworkGuard(), manual=True)
        original = runner.save_network_isolation
        def interrupted():
            if runner.executor.started: raise KeyboardInterrupt()
            return original()
        with self.offline(), patch.object(runner, 'save_network_isolation', side_effect=interrupted), \
             self.assertRaises(KeyboardInterrupt):
            runner.project_spawn(['synthetic-target'], runner.work, runner.env,
                                 runner.tmp / 'application.log', phase='application')
        self.assertEqual(len(runner.executor.started), 1)
        self.assertEqual(runner.executor.started, runner.executor.stopped)


if __name__ == '__main__':
    unittest.main()
