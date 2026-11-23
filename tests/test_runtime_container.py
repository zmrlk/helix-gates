"""Shared Docker transport and env boundary, with synthetic executors only."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_runtime import FakeExecutor, FIX, TOOLS
from test_runtime_keycloak import FakeExecutor as IdentityExecutor
import helix_runtime as runtime
import helix_runtime_container as container
import helix_runtime_identity as identity
import helix_runtime_integrations as integrations
import helix_runtime_keycloak as keycloak

ENDPOINT = dict(host='unix:///synthetic/docker.sock', kind='unix', source='test_fixture')


class ContainerTransport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / 'project'; shutil.copytree(FIX / 'sveltekit-pg', self.project)

    def runner(self, executor=None, **kwargs):
        return runtime.Runner(self.project, self.root / 'out', engine='docker', executor=executor or FakeExecutor(),
                              tools={'tools': dict(TOOLS)}, port_factory=lambda: 31234, **kwargs)

    def manual(self, executor=None):
        runner = self.runner(executor)
        runner.tmp = self.root / 'private'; runner.tmp.mkdir(mode=0o700)
        runner.work = self.project; (runner.out / 'logs').mkdir(parents=True)
        runner.env = dict(PATH='/fake', HOME=str(runner.tmp / 'home'), CI='1', PORT='43127', APP_SECRET='PRIVATE_APP_VALUE',
                          DOCKER_HOST='tcp://remote.invalid:2375', DOCKER_CONTEXT='untrusted', DOCKER_CONFIG='/untrusted/config')
        return runner

    def test_pure_environment_never_inherits_remote_context_or_application_values(self):
        original = dict(PATH='/fake', HOME='/private/home', CI='1', DOCKER_HOST='tcp://remote.invalid:2375',
                        DOCKER_CONTEXT='foreign', DOCKER_CONFIG='/private/credentials', HTTPS_PROXY='https://proxy.invalid',
                        SESSION_SECRET='PRIVATE', NODE_OPTIONS='--require malicious')
        before = copy.deepcopy(original)
        with patch.object(Path, 'stat', side_effect=AssertionError('pure helper must not probe')):
            result = container.engine_environment(original, engine='docker', endpoint=ENDPOINT)
        self.assertEqual(result, dict(PATH='/fake', HOME='/private/home', CI='1', DOCKER_HOST=ENDPOINT['host']))
        self.assertEqual(original, before)
        self.assertEqual(container.public_endpoint(ENDPOINT), {'kind': 'unix', 'source': 'test_fixture'})
        self.assertNotIn('/synthetic', json.dumps(container.public_endpoint(ENDPOINT)))

    def test_invalid_or_missing_endpoint_cannot_reach_remote_context(self):
        for endpoint in [None, {}, dict(ENDPOINT, host='tcp://remote.invalid:2375'),
                         dict(ENDPOINT, host='unix://remote.invalid/socket'), dict(ENDPOINT, host='unix:///a/../socket'),
                         dict(ENDPOINT, host='unix:///socket?private=PRIVATE'), dict(ENDPOINT, password='PRIVATE')]:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError) as caught:
                container.engine_environment({'HOME': '/private/home'}, engine='docker', endpoint=endpoint)
            self.assertNotIn('PRIVATE', str(caught.exception)); self.assertNotIn('remote.invalid', str(caught.exception))
        for environment in [{}, {'HOME': 'relative'}, {'HOME': None}]:
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                container.engine_environment(environment, engine='docker', endpoint=ENDPOINT)

    def test_docker_database_backup_and_cleanup_share_transport_and_keep_fidelity(self):
        executor = FakeExecutor(); selector = []
        executor.docker_endpoint = lambda home: selector.append(home) or dict(ENDPOINT)
        runner = self.runner(executor)
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process')), \
             patch('helix_environment._git_ref', return_value=dict(head=None,dirty=None,status='unknown',reason='synthetic fixture')), \
             patch.object(container, 'local_docker_endpoint', side_effect=AssertionError('host discovery')):
            report = runner.run()
        docker = [call for call in executor.calls if call[0][0] == '/fake/docker' and call[0][1:] != ['--version']]
        self.assertTrue(docker)
        for argv, cwd, env, timeout in docker:
            self.assertEqual(set(env), {'PATH', 'HOME', 'CI', 'DOCKER_HOST'})
            self.assertEqual(env['DOCKER_HOST'], ENDPOINT['host'])
            self.assertTrue(Path(env['HOME']).is_relative_to(runner.tmp))
        for action in ['run', 'exec', 'cp', 'rm']: self.assertTrue(any(call[0][1] == action for call in docker), action)
        self.assertEqual(selector, [runner.host_home])
        fidelity = report['database_fidelity']
        self.assertEqual((fidelity['backend'], fidelity['server_version'], fidelity['compatible']), ('docker', '16.4', True))
        self.assertEqual(fidelity['target']['major'], 16)
        self.assertEqual(report['parts'][0]['checks']['backup']['status'], 'PASS')
        self.assertEqual(report['container_endpoints'], {'docker': {'kind': 'unix', 'source': 'test_fixture'}})
        runtime.validate_report(report)

    def test_missing_local_socket_blocks_docker_before_cli_without_native_fallback(self):
        executor = FakeExecutor(); executor.docker_endpoint = lambda home: None
        runner = self.runner(executor); report = runner.run()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertIsNone(report['database_fidelity']['backend'])
        self.assertFalse(any(call[0][0].endswith(('docker', 'initdb')) for call in executor.calls))
        self.assertIn('Unix socket missing', report['database_fidelity']['attempts'][0]['reason'])
        self.assertEqual(report['container_endpoints']['docker']['kind'], 'unavailable')
        self.assertEqual(report['provenance']['tools'].get('docker', {}).get('used', False), False)

    def test_failure_and_cleanup_preserve_app_env_and_do_not_reselect_endpoint(self):
        executor = FakeExecutor(fail=lambda argv: argv[0] == '/fake/docker'); selected = []
        executor.docker_endpoint = lambda home: selected.append(home) or dict(ENDPOINT)
        runner = self.manual(executor); previous = runner.env; before = dict(previous)
        for cleanup in [False, True]:
            with self.assertRaises(runtime.Blocked): runner.command(['/fake/docker', 'rm', '-f', 'owned'], cleanup=cleanup)
            self.assertIs(runner.env, previous); self.assertEqual(runner.env, before)
        self.assertEqual(len(selected), 1)
        self.assertTrue(all(call[2]['DOCKER_HOST'] == ENDPOINT['host'] for call in executor.calls))
        returned = runner.docker_endpoint(); returned['host'] = 'tcp://foreign.invalid:1234'
        self.assertEqual(runner.docker_endpoint(), ENDPOINT)

    def test_client_version_requires_neither_socket_nor_daemon_readiness(self):
        executor = FakeExecutor(); executor.docker_endpoint = lambda home: self.fail('client version must not select socket')
        runner = self.manual(executor)
        self.assertIn('1.2.3', runner.command(['/fake/docker', '--version']))
        self.assertNotIn('DOCKER_HOST', executor.calls[-1][2]); self.assertEqual(runner.container_endpoints, {})
        self.assertFalse(runner.execution_tools['docker']['used'])
        self.assertIsNone(runner.fidelity['server_version'])
        runner.execution_tools['docker'].update(used=True, version=None)
        runner.collect_tool_versions()
        env = executor.calls[-1][2]
        self.assertEqual(set(env), {'PATH', 'HOME'})
        self.assertNotEqual(env['HOME'], str(runner.host_home)); self.assertFalse(Path(env['HOME']).exists())
        self.assertEqual(runner.execution_tools['docker']['version'], '1.2.3')
        self.assertIsNone(runner.fidelity['server_version'])
        self.assertFalse(hasattr(runtime.Executor(), 'docker_endpoint'))

    def test_original_home_is_captured_before_application_environment(self):
        selected = []; executor = FakeExecutor()
        executor.docker_endpoint = lambda home: selected.append(home) or dict(ENDPOINT)
        with patch.object(Path, 'home', return_value=Path('/original/operator')):
            runner = self.manual(executor)
        runner.env['HOME'] = str(self.root / 'isolated-app-home')
        with patch.object(Path, 'home', return_value=Path('/later/context')), \
             patch.dict(os.environ, {'HOME': '/untrusted', 'DOCKER_HOST': 'tcp://remote.invalid:2375'}):
            runner.command(['/fake/docker', 'info'])
        self.assertEqual(selected, [Path('/original/operator')])
        self.assertEqual(executor.calls[-1][2]['HOME'], str(self.root / 'isolated-app-home'))

    def test_inner_container_version_is_not_the_docker_client_version(self):
        executor = FakeExecutor(); original = executor.run
        def execute(argv, *args):
            if argv[:2] == ['/fake/docker', 'exec']:
                executor.calls.append((argv, *args))
                return 0, 'Keycloak 26.8.1\n'
            return original(argv, *args)
        executor.run = execute
        runner = self.manual(executor)
        runner.command(['/fake/docker', 'exec', 'owned-container', '/opt/keycloak/bin/kc.sh', '--version'])
        record = runner.execution_tools['docker']
        self.assertTrue(record['used']); self.assertEqual(record['calls'], 1)
        self.assertIsNone(record['version'])
        runner.collect_tool_versions()
        self.assertEqual(record['version'], '1.2.3')
        self.assertEqual(executor.calls[-1][0], ['/fake/docker', '--version'])
        self.assertNotIn('DOCKER_HOST', executor.calls[-1][2])
        self.assertIsNone(runner.fidelity['server_version'])

    def test_postgres_and_keycloak_keep_one_pinned_endpoint_until_cleanup(self):
        class Combined(FakeExecutor):
            def __init__(self): super().__init__(); self.identity = IdentityExecutor(); self.selected = []
            def docker_endpoint(self, home): self.selected.append(home); return dict(ENDPOINT)
            def run(self, argv, cwd, env, timeout):
                is_identity = (argv[0] == '/fake/docker' and (argv[1:3] in (['image','inspect'], ['container','inspect']) or
                    any(str(arg).startswith('--hostname=') for arg in argv) or 'c' * 64 in argv))
                return self.identity.run(argv,cwd,env,timeout) if is_identity else super().run(argv,cwd,env,timeout)
            def keycloak_json(self, *args): return self.identity.keycloak_json(*args)
            def sleep(self, value): self.identity.sleep(value)
        executor = Combined(); runner = self.manual(executor); executor.identity.runner = runner
        ports = iter([43126, 43128, 43129]); runner.port_factory = lambda: next(ports)
        sources = {'auth.ts': "import Keycloak from 'keycloak-js';"}; parts = [dict(path='.', name='.')]
        cfg = {'runtime': {'keycloak': {'parts': {'.': dict(client_id='fixture-client', client_type='public',
            callback_paths=['/return'], pkce='S256', role_claim='realm_access.roles', roles=['reader'],
            env_roles=dict(APP_ISSUER='issuer', APP_CLIENT_ID='client_id'))}}}}
        selected = identity.identity_plan(sources, parts, cfg)['parts'][0]
        runner.integration_plan = integrations.inventory(sources, parts, cfg)
        runner.integration_receipts = []; runner.run_id = 'runtime-container-test'
        cert = runner.tmp / 'cert.pem'; key = runner.tmp / 'key.pem'
        cert.write_text('synthetic cert'); key.write_text('synthetic key')
        tls = dict(cert_path=cert, key_path=key, spki_sha256=base64.b64encode(b'0'*32).decode())
        with patch.object(runner, 'identity_tls', return_value=tls), \
             patch.object(keycloak, 'local_docker_endpoint', side_effect=AssertionError('second endpoint selection')):
            runner.database()
            handle = runner.start_planned_keycloak(parts[0], selected)
            self.assertTrue(executor.identity.created)
            status, metrics = runner.backup(); self.assertEqual(status, 'PASS')
            for cleanup in reversed(runner.database_cleanup + runner.cleanup_actions): cleanup()
        self.assertEqual(executor.selected, [runner.host_home])
        self.assertTrue(executor.identity.removed)
        for call in executor.identity.calls:
            if call['argv'][0] == '/fake/docker': self.assertEqual(call['env']['DOCKER_HOST'], ENDPOINT['host'])
        self.assertEqual(handle.receipt()['endpoint'], container.public_endpoint(ENDPOINT))
        self.assertEqual(runner.integration_receipts[0]['tested_routes'], [])


if __name__ == '__main__': unittest.main()
