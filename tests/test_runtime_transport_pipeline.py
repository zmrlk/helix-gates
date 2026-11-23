"""HTTPS pipeline steering with synthetic TLS/processes, never a real handshake."""
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import test_runtime_keycloak_pipeline as identity_fixture
import helix_config
import helix_environment
import helix_runtime as runtime
import helix_runtime_keycloak as keycloak
import helix_visual
from helix_resources import ResourcePaused


class FakeProcess:
    def __init__(self, code=None):
        self.code = code
    def poll(self):
        return self.code


class TransportExecutor(identity_fixture.PipelineExecutor):
    def __init__(self):
        super().__init__()
        self.proxy_starts = []
        self.health_calls = []
        self.tls_material = []
        self.proxy_error = None
        self.proxy_exit = None
        self.redirect = None

    def run(self, argv, cwd, env, timeout):
        if Path(str(argv[0])).name == 'openssl':
            self.calls.append((list(argv), Path(cwd), dict(env), timeout))
            if argv[1] == 'req':
                cert = Path(argv[argv.index('-out') + 1])
                key = Path(argv[argv.index('-keyout') + 1])
                index = len(self.tls_material) + 1
                cert.write_text('SYNTHETIC CERT ' + str(index) + '\n')
                key.write_text('PRIVATE SYNTHETIC KEY ' + str(index) + '\n')
                self.tls_material.append(dict(cert=cert.read_text(), key=key.read_text(),
                    cert_path=str(cert), key_path=str(key), argv=list(argv), env=dict(env)))
            elif argv[1] == 'pkey':
                Path(argv[argv.index('-out') + 1]).write_bytes(('synthetic DER ' + str(len(self.tls_material))).encode())
            elif argv[1] == 'version':
                return 0, 'OpenSSL 3.0.0\n'
            else:
                raise AssertionError('Unexpected OpenSSL command')
            return 0, 'synthetic key generation\n'
        return super().run(argv, cwd, env, timeout)

    def spawn(self, argv, cwd, env, log):
        if any(str(arg).endswith('runtime-https.cjs') for arg in argv):
            config_path = Path(argv[-1])
            config = json.loads(config_path.read_text())
            self.proxy_starts.append(dict(argv=list(argv), cwd=str(cwd), env=dict(env),
                config=config, config_path=str(config_path), mode=config_path.stat().st_mode & 0o777,
                parent_mode=config_path.parent.stat().st_mode & 0o777))
            if self.proxy_error:
                raise self.proxy_error
            proc = FakeProcess(self.proxy_exit)
            self.started.append(proc)
            log.write_text(json.dumps(dict(type='runtime-https', event='listening' if self.proxy_exit is None else 'failed',
                origin=config['public_origin'], backend=config['backend_origin'])) + '\n')
            return proc
        return super().spawn(argv, cwd, env, log)

    def health(self, url, timeout, ca_file=None):
        ca = Path(ca_file) if ca_file else None
        self.health_calls.append(dict(url=url, timeout=timeout, ca_file=str(ca) if ca else None,
                                      ca=ca.read_text() if ca else None))
        if self.proxy_exit is not None:
            raise runtime.Blocked('synthetic HTTPS front exited')
        return self.redirect or url


class RuntimeTransportPipeline(unittest.TestCase):
    # Reuse fixture builders, not the TestCase or its test methods.
    app = identity_fixture.RuntimeKeycloakPipeline.app
    snapshot = identity_fixture.RuntimeKeycloakPipeline.snapshot

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / 'project'
        self.project.mkdir()
        self.out = self.base / 'out'
        self.config_path = self.base / 'config.json'
        self.addCleanup(helix_config._overrides.pop, self.project, None)
        self.executor = TransportExecutor()
        self.parts = {}
        self.env_roles = dict(EXAMPLE_KC_ISSUER='issuer', EXAMPLE_KC_URL='idp_origin',
            EXAMPLE_KC_REALM='realm', EXAMPLE_KC_CLIENT_ID='client_id',
            EXAMPLE_KC_CLIENT_SECRET='client_secret', EXAMPLE_APP_URL='app_origin',
            EXAMPLE_AUTH_CALLBACK='callback_uri', PUBLIC_APP_URL='app_origin')

    def configure(self, enabled=True, host='localhost'):
        cfg = {'runtime': {'keycloak': {'parts': self.parts}}}
        if enabled is not None:
            cfg['runtime']['https'] = dict(enabled=enabled, public_host=host)
        self.config_path.write_text(json.dumps(cfg))
        helix_config.configure(self.project, self.config_path)
        return cfg

    def application(self, part='frontend', *, identity=False):
        root = self.app(part, configured=identity, identity_source=identity,
                        names=[*self.env_roles, 'ORIGIN'] if identity else ['ORIGIN', 'PUBLIC_APP_URL'])
        with (root / 'server.js').open('a') as source:
            source.write("cookies.set('synthetic-session', token, {secure:true});\n")
        return root

    def run_pipeline(self):
        ports = iter(range(44200, 44300))
        resources = identity_fixture.PipelineResources(self.executor)
        self.runner = runtime.Runner(self.project, self.out, executor=self.executor,
            tools={'tools': {name: '/fake/' + name for name in ('docker', 'node', 'npm', 'openssl', 'k6')}},
            port_factory=lambda: next(ports), resource_governor=resources)
        self.executor.identity.runner = self.runner
        measured = self.runner.measure
        self.measure_calls = []
        def measure(check, part, url, budgets):
            self.measure_calls.append((check, part['path'], url))
            if check == 'load':
                return measured(check, part, url, budgets)
            return 'PASS', dict(synthetic_measurement=1)
        def database():
            self.runner.db = 'postgresql://helix@127.0.0.1:44199/helix'
            self.runner.used_engine = 'native'
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(subprocess, 'run', side_effect=AssertionError('real process')))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('real process')))
            stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('real network')))
            stack.enter_context(patch.object(helix_environment, '_git_ref', return_value={
                'head': None, 'dirty': None, 'status': 'unknown', 'reason': 'synthetic fixture'}))
            stack.enter_context(patch.object(keycloak, 'local_docker_endpoint', return_value={
                'host': 'unix:///synthetic/docker.sock', 'kind': 'unix', 'source': 'test_fixture'}))
            stack.enter_context(patch.object(self.runner, 'database', side_effect=database))
            stack.enter_context(patch.object(self.runner, 'select_schema'))
            stack.enter_context(patch.object(self.runner, 'migrate'))
            stack.enter_context(patch.object(self.runner, 'measure', side_effect=measure))
            stack.enter_context(patch.object(self.runner, 'oidc', side_effect=lambda part: None))
            stack.enter_context(patch.object(helix_visual, 'runtime_weight', return_value={'status': 'needs-runtime'}))
            stack.enter_context(patch.object(helix_visual, 'runtime_audits', return_value={'status': 'needs-runtime'}))
            return self.runner.run()

    def test_plan_calls_pure_transport_once_from_existing_snapshot(self):
        import helix_runtime_transport as transport
        self.application()
        self.configure(enabled=False)
        before = self.snapshot()
        with patch.object(transport, 'transport_plan', wraps=transport.transport_plan) as builder, \
             patch.object(runtime, 'Executor', side_effect=AssertionError('execution')), \
             patch.object(runtime, 'free_port', side_effect=AssertionError('port allocation')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')):
            planned = runtime.plan(self.project)
        builder.assert_called_once()
        self.assertIn('frontend/server.js', builder.call_args.args[0])
        self.assertEqual(builder.call_args.args[1], planned['parts'])
        self.assertEqual(builder.call_args.args[2], planned['integrations'])
        part = planned['transport_plan']['parts'][0]
        self.assertEqual((part['selected'], part['selection']), ('http', 'explicit'))
        self.assertTrue(part['https_needed'])
        self.assertEqual(part['execution'], 'not_run')
        self.assertEqual(before, self.snapshot())

    def test_public_origin_is_fixed_before_build_and_backend_port_stays_separate(self):
        self.application()
        self.configure()
        before = self.snapshot()
        report = self.run_pipeline()
        front, = self.executor.proxy_starts
        app, = [row for row in self.executor.app_starts if row['env'].get('HELIX_RUNTIME_TIMEZONE_PASS') != 'utc-smoke']
        cfg, env = front['config'], app['env']
        self.assertEqual(cfg['public_origin'], 'https://localhost:44201')
        self.assertEqual(cfg['backend_origin'], 'http://127.0.0.1:44200')
        self.assertEqual(env['PORT'], '44200')
        self.assertEqual(env['ORIGIN'], cfg['public_origin'])
        self.assertEqual(env['PUBLIC_APP_URL'].rstrip('/'), cfg['public_origin'])
        build = next(call for call in self.executor.calls if call[0][-2:] == ['run', 'build'])
        self.assertEqual(build[2]['ORIGIN'], env['ORIGIN'])
        self.assertEqual(build[2]['PORT'], env['PORT'])
        self.assertTrue(self.executor.health_calls)
        self.assertTrue(all(call['url'].startswith(cfg['public_origin'] + '/') for call in self.executor.health_calls))
        transport = report['parts'][0]['transport']
        self.assertEqual(transport['public_origin'], cfg['public_origin'])
        self.assertEqual(transport['backend_origin'], cfg['backend_origin'])
        self.assertEqual(transport['status'], 'ready')
        self.assertEqual(before, self.snapshot())
        runtime.validate_report(report)

    def test_keycloak_callback_uses_public_https_and_exact_two_owned_keys(self):
        self.application(identity=True)
        self.configure()
        report = self.run_pipeline()
        env = self.executor.app_starts[0]['env']
        origin = self.executor.proxy_starts[0]['config']['public_origin']
        realm, = self.executor.identity_realms
        self.assertEqual(realm['clients'][0]['redirectUris'], [origin + '/auth/callback'])
        self.assertEqual(env['EXAMPLE_APP_URL'], origin)
        self.assertEqual(env['EXAMPLE_AUTH_CALLBACK'], origin + '/auth/callback')
        self.assertEqual(len(self.executor.tls_material), 2)
        trust = self.executor.health_calls[0]['ca']
        for material in self.executor.tls_material:
            self.assertIn(material['cert'], trust)
            self.assertNotIn(material['key'], trust)
        self.assertEqual(len(set(env['HELIX_RUNTIME_TLS_SPKI_LIST'].split(','))), 2)
        self.assertEqual(report['integration_receipts'][0]['tested_routes'], [])
        self.assertEqual(report['coverage_status'], 'INCOMPLETE')
        self.assertTrue(self.executor.identity.removed)

    def test_proxy_private_config_and_environment_never_receive_app_credentials(self):
        self.application(identity=True)
        self.configure()
        report = self.run_pipeline()
        front, = self.executor.proxy_starts
        self.assertEqual(set(front['env']), {'PATH', 'HOME', 'CI'})
        self.assertEqual(front['mode'], 0o600)
        self.assertEqual(front['parent_mode'], 0o700)
        self.assertFalse(Path(front['config_path']).is_relative_to(self.project))
        self.assertEqual(Path(front['config_path']), Path(front['config_path']).resolve())
        public = json.dumps(report) + ''.join(p.read_text() for p in self.out.rglob('*') if p.is_file())
        for material in self.executor.tls_material:
            self.assertNotIn(material['key'], public)
        for row in [*self.executor.app_starts, front]:
            self.assertNotIn('NODE_TLS_REJECT_UNAUTHORIZED', row['env'])
            self.assertNotIn('ignoreHTTPSErrors', json.dumps(row, default=str))
        self.assertNotIn('DOCKER_HOST', front['env'])
        self.assertFalse(self.runner.tmp.exists())

    def test_explicit_false_keeps_http_and_transport_gap_without_tls_or_proxy(self):
        self.application()
        self.configure(enabled=False)
        report = self.run_pipeline()
        self.assertEqual(self.executor.proxy_starts, [])
        self.assertEqual(self.executor.tls_material, [])
        self.assertTrue(all(call['url'].startswith('http://127.0.0.1:') for call in self.executor.health_calls))
        part = report['transport_plan']['parts'][0]
        self.assertEqual((part['selected'], part['selection']), ('http', 'explicit'))
        self.assertIn('https_not_enabled', [gap['kind'] for gap in part['gaps']])
        self.assertNotEqual(report['status'], 'PASS')

    def test_tls_ready_does_not_credit_login_cookie_webauthn_or_untrusted_load(self):
        self.application(identity=True)
        self.configure()
        report = self.run_pipeline()
        part = report['parts'][0]
        self.assertEqual(part['transport']['status'], 'ready')
        self.assertNotEqual(part['checks'].get('auth-flow', {}).get('status'), 'PASS')
        self.assertEqual(part['checks']['load']['status'], 'BLOCKED')
        self.assertFalse(any(Path(call[0][0]).name == 'k6' and '--version' not in call[0] for call in self.executor.calls))
        self.assertEqual(report['integration_receipts'][0]['tested_routes'], [])
        self.assertNotEqual(report['status'], 'PASS')

    def assert_redirect_blocked(self, target):
        self.application()
        self.configure()
        self.executor.redirect = target
        report = self.run_pipeline()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertNotEqual(report['parts'][0]['transport']['status'], 'ready')
        self.assertFalse(any(check in ('e2e', 'a11y') for check, _, _ in self.measure_calls))
        self.assertFalse(self.runner.tmp.exists())

    def test_health_cannot_downgrade_public_https(self):
        self.assert_redirect_blocked('http://localhost:44201/private')

    def test_health_cannot_switch_to_backend_or_remote_origin(self):
        self.assert_redirect_blocked('https://remote.invalid/private')

    def test_advertised_backend_port_drift_is_blocked_without_redirect_repair(self):
        self.application()
        self.configure()
        self.executor.port_change = 44999
        report = self.run_pipeline()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertNotEqual(report['parts'][0]['transport']['status'], 'ready')
        self.assertFalse(any(check in ('e2e', 'a11y') for check, _, _ in self.measure_calls))
        self.assertEqual(self.executor.proxy_starts[0]['config']['backend_origin'], 'http://127.0.0.1:44200')

    def test_proxy_spawn_failure_cleans_every_owned_started_process(self):
        self.application(identity=True)
        self.configure()
        self.executor.proxy_error = OSError('synthetic front spawn failure')
        report = self.run_pipeline()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertNotEqual(report['parts'][0]['transport']['status'], 'ready')
        self.assertEqual(set(self.executor.started), set(self.executor.stopped))
        self.assertTrue(self.executor.identity.removed)
        self.assertFalse(self.runner.tmp.exists())

    def test_resource_pause_retains_incomplete_transport_and_cleans_owned_identity(self):
        self.application(identity=True)
        self.configure()
        self.executor.proxy_error = ResourcePaused('synthetic admission pause', {'state': 'critical', 'effective_jobs': 0})
        report = self.run_pipeline()
        self.assertEqual(report['run_status'], 'resource_paused')
        self.assertTrue(report['partial'])
        self.assertNotEqual(report['parts'][0].get('transport', {}).get('status'), 'ready')
        self.assertEqual(set(self.executor.started), set(self.executor.stopped))
        self.assertTrue(self.executor.identity.removed)
        self.assertFalse(self.runner.tmp.exists())

    def test_monorepo_next_part_does_not_trust_previous_identity_certificate(self):
        self.application('apps/a', identity=True)
        self.application('apps/b', identity=False)
        self.configure()
        report = self.run_pipeline()
        self.assertEqual(len(self.executor.proxy_starts), 2)
        primary = [row for row in self.executor.app_starts if row['env'].get('HELIX_RUNTIME_TIMEZONE_PASS') != 'utc-smoke']
        self.assertEqual(len(primary), 2)
        first, second = [row['env'] for row in primary]
        self.assertNotEqual(first['ORIGIN'], second['ORIGIN'])
        self.assertEqual(len(set(first['HELIX_RUNTIME_TLS_SPKI_LIST'].split(','))), 2)
        self.assertEqual(len(set(second['HELIX_RUNTIME_TLS_SPKI_LIST'].split(','))), 1)
        self.assertNotIn('EXAMPLE_KC_ISSUER', second)
        self.assertNotIn('HELIX_RUNTIME_IDENTITY_MODE', second)
        self.assertEqual(len(report['parts']), 2)
        self.assertEqual(set(self.executor.started), set(self.executor.stopped))


if __name__ == '__main__':
    unittest.main()
