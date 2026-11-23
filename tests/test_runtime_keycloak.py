"""Offline executable lifecycle steering through a FakeExecutor, no Docker/IdP."""
import base64
import copy
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime as runtime
import helix_runtime_identity as identity
import helix_runtime_keycloak as keycloak
from helix_resources import ResourcePaused


class FakeExecutor:
    def __init__(self):
        self.calls = []; self.probes = []; self.clock = 0.; self.owner = None; self.fail = None
        self.owner_mismatch = False; self.version = '26.8.1'; self.health = True; self.wrong_endpoint = False
        self.keys = [{'kty': 'RSA', 'n': 'A' * 342, 'e': 'AQAB'}]; self.interrupt_start = False
        self.runner = None; self.created = False; self.removed = False; self.realm = None
        self.image = dict(id='sha256:' + 'a' * 64, digests=['quay.io/keycloak/keycloak@sha256:' + 'b' * 64], os='linux', architecture='arm64')

    def run(self, argv, cwd, env, timeout):
        self.calls.append(dict(argv=argv, cwd=str(cwd), env=dict(env), timeout=timeout))
        phase = 'image' if argv[1:3] == ['image', 'inspect'] else 'owner' if argv[1:3] == ['container', 'inspect'] else argv[1]
        if self.fail == phase: return 1, 'synthetic failure for ' + phase
        if phase == 'image': return 0, json.dumps(self.image)
        if phase == 'run':
            self.assert_registered = len(self.runner.cleanup_actions) == 1
            self.owner = argv[argv.index('--label') + 1].split('=', 1)[1]
            self.origin = next(a.split('=', 1)[1] for a in argv if a.startswith('--hostname='))
            mount = next(a for a in argv if a.startswith('type=bind,') and '/data/import/' in a)
            source = mount.split(',src=', 1)[1].split(',dst=', 1)[0]
            self.realm = json.loads(Path(source).read_text()); self.created = True
            if self.interrupt_start: raise KeyboardInterrupt()
            return 0, 'c' * 64
        if phase == 'exec': return 0, 'Keycloak ' + self.version + '\n'
        if phase == 'owner': return 0, json.dumps('foreign-owner' if self.owner_mismatch else self.owner)
        if phase == 'rm': self.removed = True; return 0, 'removed\n'
        if Path(argv[0]).name == 'node': return 0, ''
        raise AssertionError('Unexpected command: ' + repr(argv))

    def keycloak_json(self, url, cert, timeout):
        self.probes.append(dict(url=url, cert=str(cert), timeout=timeout))
        path = urlsplit(url).path
        if path == '/health/ready': return dict(status=200 if self.health else 503, data={'status': 'UP' if self.health else 'DOWN', 'checks': []})
        issuer = self.origin + '/realms/' + self.realm['realm']
        if path.endswith('/.well-known/openid-configuration'):
            data = dict(issuer=issuer, authorization_endpoint=issuer + '/protocol/openid-connect/auth',
                        token_endpoint=issuer + '/protocol/openid-connect/token', jwks_uri=issuer + '/protocol/openid-connect/certs')
            if self.wrong_endpoint: data['jwks_uri'] = 'https://remote.invalid/keys'
            return dict(status=200, data=data)
        if path.endswith('/protocol/openid-connect/certs'): return dict(status=200, data={'keys': self.keys})
        raise AssertionError('Unexpected probe URL')

    def sleep(self, value): self.clock += value


class FakeResources:
    def __init__(self): self.calls = 0; self.pause_at = None
    def wait(self, stop=None):
        self.calls += 1
        if stop: stop()
        if self.calls == self.pause_at: raise ResourcePaused('synthetic resource pause', {'state': 'critical', 'effective_jobs': 0})
        return dict(state='normal', effective_jobs=1)


class RuntimeKeycloakTests(unittest.TestCase):
    def setUp(self):
        endpoint = patch.object(keycloak, 'local_docker_endpoint', return_value={
            'host': 'unix:///synthetic/docker.sock', 'kind': 'unix', 'source': 'test_fixture'})
        self.endpoint = endpoint.start(); self.addCleanup(endpoint.stop)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); project = self.base / 'project'; project.mkdir()
        self.fake = FakeExecutor(); self.resources = FakeResources()
        ports = iter([43128, 43129])
        self.runner = runtime.Runner(project, self.base / 'out', executor=self.fake,
                                    tools={'tools': dict(docker='/fake/docker', node='/fake/node')},
                                    resource_governor=self.resources, port_factory=lambda: next(ports))
        self.fake.runner = self.runner
        self.runner.budget = runtime.Budget(120, clock=lambda: self.fake.clock)
        self.runner.tmp = self.base / 'private'; self.runner.tmp.mkdir(mode=0o700)
        self.runner.work = self.runner.tmp / 'project'; self.runner.work.mkdir()
        (self.runner.out / 'logs').mkdir(parents=True)
        self.runner.env = dict(PATH='/fake', HOME=str(self.runner.tmp / 'home'), PORT='43127')
        tls_dir = self.runner.tmp / 'shared-tls'; tls_dir.mkdir(mode=0o700)
        cert = tls_dir / 'cert.pem'; key = tls_dir / 'key.pem'
        cert.write_bytes(b'synthetic-cert'); key.write_bytes(b'synthetic-key')
        self.tls = dict(cert_path=cert, key_path=key, spki_sha256=base64.b64encode(b'0' * 32).decode())
        values = dict(client_id='fixture-client', client_type='confidential', callback_paths=['/auth/callback'],
                      pkce='S256', role_claim='realm_access.roles', roles=['reader', 'manager'])
        config = {'runtime': {'keycloak': {'parts': {'.': values}}}}
        self.plan = identity.identity_plan({}, [dict(path='.')], config)['parts'][0]
        self.material = keycloak.private_material(self.plan, 'http://127.0.0.1:43127')
        self.binding = dict(integration_id='keycloak:0123456789ab', plan_id='d' * 64, run_id='runtime-test-0001')

    def start(self, **kwargs):
        return keycloak.start_keycloak(self.runner, self.plan, self.material, self.tls, binding=self.binding, **kwargs)

    def report(self):
        paths = list(self.runner.out.glob('helix-keycloak-*-status.json'))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text())

    def commands(self): return [call['argv'] for call in self.fake.calls]

    def test_real_command_builder_is_pinned_owned_loopback_and_no_pull(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch.object(subprocess, 'Popen', side_effect=AssertionError('process')):
            handle = self.start()
        self.assertTrue(self.fake.assert_registered)
        run = next(a for a in self.commands() if a[1] == 'run')
        self.assertIn('--pull=never', run); self.assertIn('sha256:' + 'a' * 64, run)
        self.assertNotIn(keycloak.IMAGE, run)  # image ID pins the inspected tag against a race
        self.assertIn('127.0.0.1:43128:8443', run); self.assertIn('127.0.0.1:43129:9000', run)
        self.assertIn('--http-enabled=false', run); self.assertIn('--http-management-scheme=inherited', run)
        mounts = [a for a in run if a.startswith('type=bind,')]
        self.assertEqual(len(mounts), 3); self.assertTrue(all(a.endswith(',readonly') for a in mounts))
        self.assertFalse(any('pull' in a for argv in self.commands() for a in argv if a != '--pull=never'))
        self.assertTrue(all('/project' not in a for a in mounts))
        self.assertEqual(handle.directory.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o444 for p in handle.directory.iterdir()))
        handle.close(); count = len(self.fake.calls); handle.close()
        self.assertEqual(len(self.fake.calls), count); self.assertTrue(self.fake.removed)
        self.assertFalse(handle.directory.exists()); self.assertEqual(handle.receipt()['cleanup']['status'], 'removed')

    def test_ready_is_not_login_or_route_coverage_and_has_actual_versions(self):
        handle = self.start(); report = handle.receipt()
        self.assertEqual(report['readiness'], 'ready'); self.assertEqual(report['status'], 'ready')
        self.assertEqual(report['actual_version'], '26.8.1'); self.assertEqual(report['image']['architecture'], 'arm64')
        self.assertEqual(report['tested_routes'], []); self.assertEqual(report['coverage'], 'not_checked')
        self.assertIn('no_login_performed', report['limitations'])
        self.assertEqual([p['name'] for p in report['phases']], ['image_inspect', 'container_start', 'server_version', 'health', 'discovery', 'jwks', 'node_tls'])
        self.assertEqual([urlsplit(p['url']).path for p in self.fake.probes], ['/health/ready',
            '/realms/' + self.material['realm'] + '/.well-known/openid-configuration',
            '/realms/' + self.material['realm'] + '/protocol/openid-connect/certs'])
        self.assertEqual(report['phases'][3]['checks_count'], 0)
        self.assertFalse(report['phases'][5]['signature_verification_performed'])
        for key, value in self.binding.items(): self.assertEqual(report[key], value)
        handle.close()

    def test_secrets_never_enter_commands_environment_logs_or_public_receipt(self):
        before = copy.deepcopy((self.plan, self.material, self.runner.env))
        handle = self.start()
        public = json.dumps(handle.receipt()) + json.dumps(self.fake.calls)
        public += ''.join(p.read_text() for p in (self.runner.out / 'logs').glob('*'))
        for value in [self.material['client_secret'], *self.material['user_passwords'].values(), 'synthetic-key']:
            self.assertNotIn(value, public)
        self.assertNotIn('Config.Env', keycloak.IMAGE_FORMAT); self.assertFalse(any(a[1] == 'logs' for a in self.commands()))
        self.assertEqual((self.plan, self.material, self.runner.env), before)
        node = next(c for c in self.fake.calls if Path(c['argv'][0]).name == 'node')
        self.assertEqual(node['env']['NODE_EXTRA_CA_CERTS'], str(handle.cert))
        self.assertNotIn('NODE_TLS_REJECT_UNAUTHORIZED', node['env'])
        self.assertIn("redirect:'error'", node['argv'][2]); handle.close()

    def test_missing_engine_or_image_never_launches_or_falls_back(self):
        self.runner.tools.pop('docker')
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertEqual(self.fake.calls, []); self.assertEqual(self.report()['status'], 'blocked')

    def test_missing_image_is_blocked_before_private_import_and_creation(self):
        self.fake.fail = 'image'
        with self.assertRaises(keycloak.KeycloakBlocked) as caught: self.start()
        self.assertEqual(caught.exception.receipt['failed_phase'], 'image_inspect')
        self.assertTrue(caught.exception.artifact.is_relative_to(self.runner.out))
        self.assertEqual(json.loads(caught.exception.artifact.read_text()), caught.exception.receipt)
        self.assertFalse(self.fake.created); self.assertEqual(len(self.fake.calls), 1)
        self.assertEqual(list(self.runner.tmp.glob('helix-keycloak-*')), [])

    def test_explicit_engine_is_never_silently_replaced(self):
        with self.assertRaises(keycloak.KeycloakBlocked): self.start(engine='podman')
        self.assertEqual(self.fake.calls, [])

    def test_podman_uses_same_no_pull_ownership_contract(self):
        self.runner.tools['podman'] = '/fake/podman'
        handle = self.start(engine='podman')
        self.assertTrue(all(c['argv'][0] in ('/fake/podman', '/fake/node') for c in self.fake.calls))
        handle.close(); self.assertTrue(self.fake.removed)

    def test_actual_version_mismatch_stops_before_health_and_cleans_container(self):
        self.fake.version = '25.0.6'
        with self.assertRaises(keycloak.KeycloakBlocked) as caught: self.start()
        self.assertEqual(self.fake.probes, []); self.assertTrue(self.fake.removed)
        self.assertEqual(caught.exception.receipt['actual_version'], '25.0.6')
        self.assertEqual(caught.exception.receipt['cleanup']['status'], 'removed')
        self.assertEqual(self.report()['status'], 'blocked')

    def test_health_timeout_uses_global_budget_and_cleanup_bypasses_it(self):
        self.fake.health = False; self.runner.budget = runtime.Budget(.5, clock=lambda: self.fake.clock)
        with self.assertRaises(keycloak.KeycloakBlocked) as caught: self.start()
        self.assertAlmostEqual(self.fake.clock, .5); self.assertTrue(self.fake.removed)
        self.assertEqual(caught.exception.receipt['readiness'], 'not_checked')
        self.assertTrue(all(c['timeout'] <= .5 for c in self.fake.calls if c['argv'][1] not in ('container', 'rm')))
        self.assertTrue(all(c['timeout'] == 15 for c in self.fake.calls if c['argv'][1] in ('container', 'rm')))
        self.assertTrue(all(urlsplit(p['url']).path == '/health/ready' for p in self.fake.probes))

    def test_external_discovery_endpoint_is_rejected_before_any_followup(self):
        self.fake.wrong_endpoint = True
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertEqual(len(self.fake.probes), 2); self.assertTrue(self.fake.removed)
        self.assertTrue(all(urlsplit(p['url']).hostname == '127.0.0.1' for p in self.fake.probes))
        self.assertNotIn('remote.invalid', json.dumps(self.report()))

    def test_empty_or_private_jwks_cannot_count_as_ready(self):
        self.fake.keys = [{'kty': 'RSA', 'n': 'A' * 342, 'e': 'AQAB', 'd': 'PRIVATE_KEY_MUST_NOT_LEAK'}]
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertTrue(self.fake.removed); self.assertNotIn('PRIVATE_KEY_MUST_NOT_LEAK', json.dumps(self.report()))
        self.assertFalse(any(Path(a[0]).name == 'node' for a in self.commands()))

    def test_resource_pause_after_start_preserves_partial_receipt_and_cleans(self):
        self.resources.pause_at = 4  # image, start, version, first health admission
        with self.assertRaises(ResourcePaused) as caught: self.start()
        self.assertTrue(self.fake.created); self.assertTrue(self.fake.removed)
        self.assertEqual(self.resources.calls, 4)
        self.assertEqual(self.report()['status'], 'resource_paused'); self.assertEqual(self.report()['tested_routes'], [])
        self.assertEqual(caught.exception.receipt, self.report())
        self.assertEqual(caught.exception.receipt['cleanup']['status'], 'removed')
        self.assertEqual(caught.exception.receipt['actual_version'], '26.8.1')

    def test_interruption_after_engine_create_without_returned_id_cleans_only_owned_name(self):
        self.fake.interrupt_start = True
        with self.assertRaises(KeyboardInterrupt): self.start()
        self.assertTrue(self.fake.created); self.assertTrue(self.fake.removed)
        remove = next(a for a in self.commands() if a[1] == 'rm')
        self.assertTrue(remove[-1].startswith('helix-keycloak-'))
        self.assertEqual(self.report()['status'], 'interrupted')

    def test_foreign_container_label_is_never_removed(self):
        handle = self.start(); self.fake.owner_mismatch = True; handle.close()
        self.assertFalse(self.fake.removed); self.assertEqual(handle.receipt()['cleanup']['status'], 'refused')
        self.assertFalse(any(a[1] == 'rm' for a in self.commands()))

    def test_owned_cleanup_failure_is_visible_and_can_retry(self):
        handle = self.start(); self.fake.fail = 'rm'; handle.close()
        self.assertEqual(handle.receipt()['cleanup']['status'], 'unknown'); self.assertTrue(handle.directory.exists())
        self.fake.fail = None; handle.close()
        self.assertEqual(handle.receipt()['cleanup']['status'], 'removed'); self.assertFalse(handle.directory.exists())

    def test_engine_and_final_cleanup_never_inherit_application_credentials(self):
        self.runner.env.update(CI='1', APP_CLIENT_SECRET='BEFORE_START_SECRET', DATABASE_URL='PRIVATE_DATABASE',
                               DOCKER_HOST='tcp://remote.invalid:2375')
        before = self.runner.env
        handle = self.start()
        self.assertIs(self.runner.env, before)
        self.runner.env['APP_CLIENT_SECRET'] = 'AFTER_READINESS_SECRET'
        handle.close()
        engine_calls = [call for call in self.fake.calls if call['argv'][0] == '/fake/docker']
        self.assertTrue(any(call['argv'][1] == 'rm' for call in engine_calls))
        self.assertTrue(all(set(call['env']) == {'PATH', 'HOME', 'CI', 'DOCKER_HOST'} for call in engine_calls))
        self.assertTrue(all(call['env']['DOCKER_HOST'] == 'unix:///synthetic/docker.sock' for call in engine_calls))
        self.assertNotIn('SECRET', json.dumps(engine_calls)); self.assertNotIn('remote.invalid', json.dumps(engine_calls))
        self.assertIs(self.runner.env, before)
        self.assertEqual(self.runner.env['APP_CLIENT_SECRET'], 'AFTER_READINESS_SECRET')
        node = next(call for call in self.fake.calls if call['argv'][0] == '/fake/node')
        self.assertEqual(node['env']['NODE_EXTRA_CA_CERTS'], str(handle.cert))

    def test_missing_local_socket_blocks_before_any_engine_call(self):
        self.endpoint.return_value = None
        self.runner.env['DOCKER_HOST'] = 'tcp://remote.invalid:2375'
        with self.assertRaisesRegex(keycloak.KeycloakBlocked, 'Unix socket missing') as caught: self.start()
        self.assertEqual(self.fake.calls, []); self.assertEqual(self.fake.probes, [])
        self.assertEqual(caught.exception.receipt['endpoint'], {'kind': 'unavailable', 'source': 'known_local_paths'})
        self.assertNotIn('remote.invalid', json.dumps(caught.exception.receipt))

    def test_socket_home_comes_from_helix_process_and_receipt_omits_endpoint(self):
        with patch.object(keycloak.Path, 'home', return_value=Path('/synthetic/operator-home')):
            handle = self.start()
        # Runner pins the original process home before any later env change.
        self.endpoint.assert_called_once_with(self.runner.host_home)
        self.assertNotEqual(self.runner.host_home, Path('/synthetic/operator-home'))
        self.assertEqual(handle.receipt()['endpoint'], {'kind': 'unix', 'source': 'test_fixture'})
        self.assertNotIn('/synthetic/', json.dumps(handle.receipt()))
        self.assertNotEqual(self.runner.env['HOME'], '/synthetic/operator-home')
        handle.close()

    def test_engine_failure_restores_app_environment(self):
        self.runner.env['APP_CLIENT_SECRET'] = 'SECRET_MUST_STAY_PRIVATE'
        before = self.runner.env; self.fake.fail = 'image'
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertIs(self.runner.env, before)
        self.assertNotIn('APP_CLIENT_SECRET', self.fake.calls[0]['env'])

    def test_tls_symlink_or_project_file_is_rejected_before_engine(self):
        original = self.tls['key_path']; link = original.with_name('linked.pem'); link.symlink_to(original)
        self.tls['key_path'] = link
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertEqual(self.fake.calls, [])

    def test_conflicting_ports_block_without_starting_container(self):
        self.runner.port_factory = lambda: 43127
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertFalse(self.fake.created); self.assertEqual(list(self.runner.tmp.glob('helix-keycloak-*')), [])

    def test_node_probe_failure_blocks_and_restores_previous_environment(self):
        previous = dict(self.runner.env); original = self.fake.run
        def fail_node(argv, *args):
            if Path(argv[0]).name == 'node': raise subprocess.TimeoutExpired(argv, .1, output='PRIVATE_OUTPUT')
            return original(argv, *args)
        self.fake.run = fail_node
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertEqual(self.runner.env, previous); self.assertTrue(self.fake.removed)
        self.assertNotIn('PRIVATE_OUTPUT', json.dumps(self.report()))

    def test_fresh_private_material_is_unique_and_never_mutates_plan(self):
        before = copy.deepcopy(self.plan); other = keycloak.private_material(self.plan, 'http://127.0.0.1:43127')
        self.assertNotEqual(other['realm'], self.material['realm']); self.assertNotEqual(other['client_secret'], self.material['client_secret'])
        self.assertTrue(set(other['user_passwords'].values()).isdisjoint(self.material['user_passwords'].values()))
        self.assertEqual(self.plan, before)

    def test_binding_requires_exact_keycloak_inventory_and_run_grammar_before_io(self):
        for field, invalid in [('integration_id', 'redis:0123456789ab'), ('integration_id', 'keycloak-synthetic'),
                               ('plan_id', 'not-a-hash'), ('run_id', ':'), ('run_id', 'x' * 101)]:
            binding = dict(self.binding); binding[field] = invalid
            with self.subTest(field=field, invalid=invalid), patch.object(keycloak.IdentityHandle, 'save', side_effect=AssertionError('I/O')):
                with self.assertRaisesRegex(keycloak.KeycloakBlocked, 'binding'):
                    keycloak.start_keycloak(self.runner, self.plan, self.material, self.tls, binding=binding)
            self.assertEqual(self.fake.calls, []); self.assertEqual(self.runner.cleanup_actions, [])

    def test_final_node_response_cannot_mark_ready_after_global_budget_elapsed(self):
        original = self.fake.run
        def late_response(argv, *args):
            result = original(argv, *args)
            if Path(argv[0]).name == 'node': self.fake.clock = 121
            return result
        self.fake.run = late_response
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertEqual(self.report()['status'], 'blocked'); self.assertTrue(self.fake.removed)
        self.assertEqual(self.report()['failed_phase'], 'node_tls')

    def test_late_health_response_cannot_admit_discovery_after_budget(self):
        original = self.fake.keycloak_json
        def late_response(*args):
            result = original(*args); self.fake.clock = 121
            return result
        self.fake.keycloak_json = late_response
        with self.assertRaises(keycloak.KeycloakBlocked): self.start()
        self.assertEqual(len(self.fake.probes), 1); self.assertTrue(self.fake.removed)
        self.assertEqual(self.report()['failed_phase'], 'health')

    def test_actual_probe_rejects_remote_urls_before_tls_or_request(self):
        for url in ['https://remote.invalid:443/health/ready', 'http://127.0.0.1:4443/health/ready',
                    'https://user:secret@127.0.0.1:4443/health/ready', 'https://127.0.0.1:4443/health/ready?secret=value']:
            with self.subTest(url=url), patch.object(keycloak.ssl, 'create_default_context', side_effect=AssertionError('TLS')):
                with self.assertRaises(keycloak.KeycloakBlocked): keycloak.local_json(url, self.tls['cert_path'], 1)

    def test_actual_probe_has_ca_verification_no_proxy_and_no_redirects(self):
        response = Mock(code=200)
        response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"status":"UP"}'
        opener = Mock(); opener.open.return_value = response
        context = object()
        with patch.object(keycloak.ssl, 'create_default_context', return_value=context) as tls_context, \
             patch.object(keycloak.urllib.request, 'build_opener', return_value=opener) as build:
            result = keycloak.local_json('https://127.0.0.1:4443/health/ready', self.tls['cert_path'], .25)
        self.assertEqual(result, {'status': 200, 'data': {'status': 'UP'}})
        tls_context.assert_called_once_with(cafile=str(self.tls['cert_path']))
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsNone(handlers[1].redirect_request(None, None, 302, '', {}, 'https://remote.invalid'))
        self.assertIs(handlers[2]._context, context)
        opener.open.assert_called_once_with('https://127.0.0.1:4443/health/ready', timeout=.25)
        response.read.assert_called_once_with(keycloak.LIMIT + 1)

    def test_actual_probe_caps_response_before_json_parsing(self):
        response = Mock(code=200)
        response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'x' * (keycloak.LIMIT + 1)
        opener = Mock(); opener.open.return_value = response
        with patch.object(keycloak.ssl, 'create_default_context', return_value=object()), \
             patch.object(keycloak.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(keycloak.KeycloakBlocked, 'size limit'):
                keycloak.local_json('https://127.0.0.1:4443/health/ready', self.tls['cert_path'], 1)


class DockerEndpointTests(unittest.TestCase):
    def test_known_system_socket_wins_without_reading_docker_environment(self):
        calls = []
        def fake_stat(path):
            calls.append(str(path)); return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600)
        with patch.object(Path, 'stat', fake_stat), patch.dict(os.environ, {
                'DOCKER_HOST': 'tcp://remote.invalid:2375', 'DOCKER_CONTEXT': 'private-context'}):
            result = keycloak.local_docker_endpoint('/synthetic/home')
        self.assertEqual(calls, ['/var/run/docker.sock'])
        self.assertEqual(result, {'host': 'unix:///var/run/docker.sock', 'kind': 'unix', 'source': 'system_socket'})

    def test_docker_desktop_socket_works_with_private_runtime_home(self):
        calls = []
        def fake_stat(path):
            calls.append(str(path))
            if str(path) == '/var/run/docker.sock': raise FileNotFoundError()
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600)
        with patch.object(Path, 'stat', fake_stat), patch.object(Path, 'home', return_value=Path('/synthetic/helix-home')):
            result = keycloak.local_docker_endpoint()
        self.assertEqual(calls, ['/var/run/docker.sock', '/synthetic/helix-home/.docker/run/docker.sock'])
        self.assertEqual(result, {'host': 'unix:///synthetic/helix-home/.docker/run/docker.sock',
                                  'kind': 'unix', 'source': 'docker_desktop_socket'})

    def test_regular_fifo_and_inaccessible_candidates_are_not_endpoints(self):
        for mode in (stat.S_IFREG, stat.S_IFIFO, stat.S_IFDIR):
            with self.subTest(mode=mode), patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=mode)):
                self.assertIsNone(keycloak.local_docker_endpoint('/synthetic/home'))
        with patch.object(Path, 'stat', side_effect=PermissionError('private path')):
            self.assertIsNone(keycloak.local_docker_endpoint('/synthetic/home'))


if __name__ == '__main__': unittest.main()
