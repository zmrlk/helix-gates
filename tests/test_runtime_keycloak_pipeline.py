"""Offline Runner integration: real lifecycle builder, synthetic executor only."""
import base64
import contextlib
import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_runtime import FakeExecutor as ApplicationExecutor
from test_runtime_keycloak import FakeExecutor as IdentityExecutor
import helix_config
import helix_environment
import helix_runtime as runtime
import helix_runtime_keycloak as keycloak
import helix_visual
from helix_resources import ResourcePaused


class PipelineExecutor(ApplicationExecutor):
    """Retain the actual app and IdP command/environment boundaries."""
    def __init__(self):
        super().__init__()
        self.identity = IdentityExecutor()
        self.app_starts = []
        self.identity_realms = []
        self.port_change = None
        self.health_result = None
        self.startup_env_error = False
        self.echo_secrets = False
        self.raw_canary = None
        self.raw_parent_symlink = False

    def run(self, argv, cwd, env, timeout):
        if Path(str(argv[0])).name in ('docker', 'podman') and argv[1:] != ['--version']:
            result = self.identity.run(argv, cwd, env, timeout)
            if argv[1] == 'run':
                self.identity_realms.append(copy.deepcopy(self.identity.realm))
            return result
        result = super().run(argv, cwd, env, timeout)
        if self.echo_secrets and argv[-2:] == ['run', 'build']:
            return 0, 'Build diagnostic: ' + env['EXAMPLE_KC_CLIENT_SECRET'] + '\n'
        return result

    def spawn(self, argv, cwd, env, log):
        self.app_starts.append(dict(argv=list(argv), cwd=str(cwd), env=dict(env)))
        process = super().spawn(argv, cwd, env, log)
        if self.port_change:
            log.write_text('Listening at http://127.0.0.1:' + str(self.port_change) + '\n')
        if self.startup_env_error:
            log.write_text('Error: EXAMPLE_KC_CLIENT_ID invalid environment value\n')
        if self.echo_secrets:
            log.write_text('Error: startup authentication failure ' + env['EXAMPLE_KC_CLIENT_SECRET'] + '\n')
        if self.raw_canary:
            if self.raw_parent_symlink:
                log.parent.rename(log.parent.with_name(log.parent.name + '-original'))
                log.parent.symlink_to(self.raw_canary.parent, target_is_directory=True)
            else:
                log.unlink()
                log.symlink_to(self.raw_canary)
        return process

    def health(self, url, timeout):
        if self.startup_env_error or self.echo_secrets:
            raise runtime.Blocked('synthetic startup health failure')
        return self.health_result or super().health(url, timeout)

    def keycloak_json(self, url, cert, timeout):
        return self.identity.keycloak_json(url, cert, timeout)

    def sleep(self, value):
        self.identity.sleep(value)


class PipelineResources:
    def __init__(self, executor, pause_after_start=False):
        self.executor = executor
        self.pause_after_start = pause_after_start
        self.requested_jobs = 1
        self.policy = {}
        self.history = []

    def monitor(self):
        return contextlib.nullcontext()

    def wait(self, stop=None):
        if stop:
            stop()
        if self.pause_after_start and self.executor.identity.created:
            raise ResourcePaused('synthetic resource pause', dict(state='critical', effective_jobs=0))
        return dict(state='normal', effective_jobs=1)


class RuntimeKeycloakPipeline(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / 'project'
        self.project.mkdir()
        self.out = self.base / 'out'
        self.config_path = self.base / 'config.json'
        self.addCleanup(helix_config._overrides.pop, self.project, None)
        self.executor = PipelineExecutor()
        self.parts = {}
        self.env_roles = dict(EXAMPLE_KC_ISSUER='issuer', EXAMPLE_KC_URL='idp_origin',
                              EXAMPLE_KC_REALM='realm', EXAMPLE_KC_CLIENT_ID='client_id',
                              EXAMPLE_KC_CLIENT_SECRET='client_secret', EXAMPLE_APP_URL='app_origin',
                              EXAMPLE_AUTH_CALLBACK='callback_uri')

    def app(self, part='frontend', *, client='fixture-client', confidential=False,
            names=None, configured=True, identity_source=True):
        root = self.project / part
        root.mkdir(parents=True, exist_ok=True)
        deps = {'express': '1'}
        if identity_source:
            deps['keycloak-js'] = '1'
        (root / 'package.json').write_text(json.dumps(dict(dependencies=deps,
            scripts=dict(build='node build.js', start='node server.js'))))
        source = "import Keycloak from 'keycloak-js';\n" if identity_source else ''
        source += '\n'.join('const value' + str(index) + '=process.env.' + name + ';'
                            for index, name in enumerate(names if names is not None else self.env_roles if identity_source else []))
        source += "\napp.get('/private', () => 'synthetic');\n"
        (root / 'server.js').write_text(source)
        (root / 'build.js').write_text('// Synthetic fixture, never executed.\n')
        if configured:
            self.parts[part] = dict(client_id=client, client_type='confidential' if confidential else 'public',
                callback_paths=['/auth/callback'], pkce='S256', role_claim='realm_access.roles',
                roles=['reader'], env_roles=dict(self.env_roles))
        return root

    def configure(self, *, strategy=None):
        cfg = {'runtime': {'keycloak': {'parts': self.parts}}}
        if strategy:
            cfg['runtime']['integrations'] = {'keycloak': {'strategy': strategy}}
        self.config_path.write_text(json.dumps(cfg))
        helix_config.configure(self.project, self.config_path)
        return cfg

    def snapshot(self):
        return {p.relative_to(self.project).as_posix(): p.read_bytes()
                for p in self.project.rglob('*') if p.is_file()}

    def run_pipeline(self, *, pause_after_start=False, allow_plain_oidc=False,
                     interrupt_first_log=False, **kwargs):
        ports = iter(range(43127, 43227))
        resources = PipelineResources(self.executor, pause_after_start)
        self.runner = runtime.Runner(self.project, self.out, executor=self.executor,
            tools={'tools': {'docker': '/fake/docker', 'node': '/fake/node', 'npm': '/fake/npm'}},
            port_factory=lambda: next(ports), resource_governor=resources, **kwargs)
        self.executor.identity.runner = self.runner
        tls_count = 0

        def tls(label='oidc'):
            nonlocal tls_count
            tls_count += 1
            folder = self.runner.tmp / ('synthetic-tls-' + str(tls_count))
            folder.mkdir(mode=0o700)
            cert, key = folder / 'cert.pem', folder / 'key.pem'
            cert.write_bytes(b'synthetic-public-cert')
            key.write_bytes(b'synthetic-private-key')
            return dict(cert_path=cert, key_path=key,
                        spki_sha256=base64.b64encode(b'0' * 32).decode())

        def database():
            self.runner.db = 'postgresql://helix@127.0.0.1:43126/helix'
            self.runner.used_engine = 'native'

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(subprocess, 'run', side_effect=AssertionError('real process')))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('real process')))
            stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('real network')))
            stack.enter_context(patch.object(keycloak, 'local_docker_endpoint', return_value={
                'host': 'unix:///synthetic/docker.sock', 'kind': 'unix', 'source': 'test_fixture'}))
            stack.enter_context(patch.object(helix_environment, '_git_ref', return_value={
                'head': None, 'dirty': None, 'status': 'unknown', 'reason': 'synthetic non-Git fixture'}))
            stack.enter_context(patch.object(self.runner, 'identity_tls', side_effect=tls))
            stack.enter_context(patch.object(self.runner, 'database', side_effect=database))
            stack.enter_context(patch.object(self.runner, 'select_schema'))
            stack.enter_context(patch.object(self.runner, 'migrate'))
            stack.enter_context(patch.object(self.runner, 'measure', return_value=('PASS', {'synthetic_measurement': 1})))
            stack.enter_context(patch.object(helix_visual, 'runtime_weight', return_value={'status': 'needs-runtime'}))
            stack.enter_context(patch.object(helix_visual, 'runtime_audits', return_value={'status': 'needs-runtime'}))
            if interrupt_first_log:
                original_startup_text = self.runner.startup_text
                first = True
                def interrupted_startup_text(public):
                    nonlocal first
                    if first:
                        first = False
                        raise KeyboardInterrupt()
                    return original_startup_text(public)
                stack.enter_context(patch.object(self.runner, 'startup_text', side_effect=interrupted_startup_text))
            def old_oidc(part):
                if allow_plain_oidc and part['path'] not in self.parts:
                    return
                raise AssertionError('Keycloak must not use old OIDC stub')
            self.old_oidc = stack.enter_context(patch.object(self.runner, 'oidc', side_effect=old_oidc))
            lifecycle = stack.enter_context(patch.object(keycloak, 'start_keycloak', wraps=keycloak.start_keycloak))
            result = self.runner.run()
        self.lifecycle_calls = lifecycle.call_args_list
        return result

    def entry(self, report):
        return next(row for row in report['integrations']['integrations']
                    if row['provider'] == 'keycloak' and row['area'] == 'active')

    def rich_receipts(self):
        return [json.loads(path.read_text()) for path in self.out.glob('helix-keycloak-*-status.json')]

    def test_ready_blueprint_invokes_real_lifecycle_and_preserves_current_binding(self):
        self.app()
        self.configure()
        before = self.snapshot()
        report = self.run_pipeline()
        self.assertEqual(len(self.lifecycle_calls), 1)
        self.assertTrue(self.executor.identity.created)
        self.assertTrue(self.executor.identity.removed)
        self.assertTrue(self.executor.app_starts)
        receipt, = report['integration_receipts']
        binding = self.lifecycle_calls[0].kwargs['binding']
        self.assertEqual(binding, dict(integration_id=self.entry(report)['id'],
            plan_id=report['integrations']['plan_id'], run_id=report['run_id']))
        for name, value in binding.items():
            self.assertEqual(receipt[name], value)
        self.assertEqual(receipt['actual_version'], '26.8.1')
        self.assertEqual(receipt['tested_routes'], [])
        self.assertEqual(self.entry(report)['execution']['readiness'], 'ready')
        self.assertEqual(self.entry(report)['coverage']['status'], 'not_checked')
        self.assertEqual(report['measurement_status'], 'PASS')
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(report['coverage_status'], 'INCOMPLETE')
        self.assertEqual(before, self.snapshot())
        runtime.validate_report(report)

    def test_public_secret_empty_and_identity_urls_match_build_and_app_port(self):
        self.app()
        self.configure()
        report = self.run_pipeline()
        start, = [row for row in self.executor.app_starts if row['env'].get('HELIX_RUNTIME_TIMEZONE_PASS') != 'utc-smoke']
        env = start['env']
        realm, = self.executor.identity_realms
        issuer = self.executor.identity.origin + '/realms/' + realm['realm']
        self.assertEqual(env['EXAMPLE_KC_ISSUER'], issuer)
        self.assertEqual(env['EXAMPLE_KC_URL'], self.executor.identity.origin)
        self.assertNotIn('/realms/', env['EXAMPLE_KC_URL'])
        self.assertEqual(env['EXAMPLE_KC_REALM'], realm['realm'])
        self.assertTrue(realm['realm'].startswith('helix-'))
        self.assertEqual(env['EXAMPLE_KC_CLIENT_ID'], 'fixture-client')
        self.assertEqual(env.get('EXAMPLE_KC_CLIENT_SECRET', ''), '')
        self.assertEqual(env['EXAMPLE_APP_URL'], 'http://127.0.0.1:' + env['PORT'])
        self.assertEqual(env['EXAMPLE_AUTH_CALLBACK'], env['EXAMPLE_APP_URL'] + '/auth/callback')
        self.assertEqual(realm['clients'][0]['redirectUris'], [env['EXAMPLE_AUTH_CALLBACK']])
        self.assertEqual(env['HELIX_RUNTIME_IDENTITY_MODE'], 'keycloak-readiness')
        self.assertNotIn('runtime-fetch.cjs', env.get('NODE_OPTIONS', ''))
        self.assertNotIn('NODE_TLS_REJECT_UNAUTHORIZED', env)
        build = next(c for c in self.executor.calls if c[0][-2:] == ['run', 'build'])
        for name in self.env_roles:
            self.assertEqual(build[2].get(name), env.get(name))
        self.assertEqual(report['status'], 'INCOMPLETE')

    def test_confidential_secret_is_fresh_private_and_not_in_reports_or_logs(self):
        self.app(confidential=True)
        self.configure()
        report = self.run_pipeline()
        secret = self.executor.app_starts[0]['env']['EXAMPLE_KC_CLIENT_SECRET']
        self.assertGreaterEqual(len(secret), 24)
        self.assertEqual(secret, self.executor.identity_realms[0]['clients'][0]['secret'])
        public = json.dumps(report) + json.dumps(self.rich_receipts())
        public += ''.join(path.read_text() for path in (self.out / 'logs').glob('*'))
        self.assertNotIn(secret, public)
        self.assertNotIn('synthetic-private-key', public)
        for call in self.executor.identity.calls:
            self.assertNotIn(secret, json.dumps(call))

    def test_blocked_blueprint_never_uses_old_oidc_or_starts_identity(self):
        self.app(configured=False)
        self.configure()
        report = self.run_pipeline(oidc_stub=True)
        self.assertEqual(self.lifecycle_calls, [])
        self.assertFalse(self.executor.identity.created)
        self.assertEqual(self.executor.app_starts, [])
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertNotEqual(self.entry(report)['coverage']['status'], 'tested')
        self.old_oidc.assert_not_called()

    def test_explicit_empty_env_map_blocks_without_dummy_auth_or_fallback(self):
        self.app()
        self.parts['frontend']['env_roles'] = {}
        self.configure()
        report = self.run_pipeline(oidc_stub=True)
        self.assertEqual(self.lifecycle_calls, [])
        self.assertEqual(self.executor.app_starts, [])
        self.assertEqual(report['status'], 'BLOCKED')
        self.old_oidc.assert_not_called()

    def test_unsupported_strategy_never_silently_starts_container_or_stub(self):
        self.app()
        self.configure(strategy='disabled')
        report = self.run_pipeline(oidc_stub=True)
        self.assertEqual(self.lifecycle_calls, [])
        self.assertEqual(self.executor.app_starts, [])
        self.assertEqual(report['status'], 'BLOCKED')
        self.old_oidc.assert_not_called()

    def test_protected_environment_mapping_is_rejected_before_any_process(self):
        self.app(names=['PATH', *self.env_roles])
        self.parts['frontend']['env_roles']['PATH'] = 'issuer'
        self.configure()
        with self.assertRaises(ValueError):
            self.run_pipeline()
        self.assertEqual(self.executor.calls, [])
        self.assertEqual(self.executor.identity.calls, [])
        self.assertEqual(self.executor.app_starts, [])

    def test_receipt_projection_is_schema_bounded_and_cleanup_is_current(self):
        self.app()
        self.configure()
        report = self.run_pipeline()
        receipt, = report['integration_receipts']
        self.assertEqual(set(receipt), {'integration_id', 'plan_id', 'run_id', 'strategy',
            'status', 'readiness', 'actual_version', 'logs', 'tested_routes'})
        raw, = self.rich_receipts()
        self.assertEqual(raw['cleanup']['status'], 'removed')
        self.assertIn('image', raw)
        self.assertIn('identity_plan_id', raw)
        self.assertEqual(raw['tested_routes'], [])
        self.assertTrue(receipt['logs'])
        for name in receipt['logs']:
            self.assertFalse(Path(name).is_absolute())
            self.assertNotIn('..', Path(name).parts)
            self.assertTrue((self.out / name).is_file())
        self.assertTrue(any(name.endswith('-status.json') for name in receipt['logs']))
        self.assertFalse(self.runner.tmp.exists())
        runtime.validate_report(report)

    def test_resource_pause_keeps_binding_and_final_cleanup_without_route_credit(self):
        self.app()
        self.configure()
        report = self.run_pipeline(pause_after_start=True)
        self.assertEqual(report['run_status'], 'resource_paused')
        self.assertTrue(report['partial'])
        receipt, = report['integration_receipts']
        raw, = self.rich_receipts()
        self.assertEqual(raw['status'], 'resource_paused')
        self.assertEqual(raw['cleanup']['status'], 'removed')
        self.assertEqual(receipt['status'], 'incomplete')
        self.assertEqual(receipt['readiness'], 'unknown')
        self.assertEqual(receipt['run_id'], report['run_id'])
        self.assertEqual(receipt['tested_routes'], [])
        self.assertTrue(any(name.endswith('-status.json') for name in receipt['logs']))
        self.assertEqual(self.executor.app_starts, [])
        self.assertTrue(self.executor.identity.removed)
        self.assertEqual(report['coverage_status'], 'INCOMPLETE')
        runtime.validate_report(report)

    def test_wrong_server_version_is_blocked_cleaned_and_never_stubbed(self):
        self.app()
        self.configure()
        self.executor.identity.version = '25.0.6'
        report = self.run_pipeline()
        receipt, = report['integration_receipts']
        self.assertEqual(receipt['status'], 'blocked')
        self.assertEqual(receipt['actual_version'], '25.0.6')
        self.assertTrue(any(name.endswith('-status.json') for name in receipt['logs']))
        self.assertEqual(self.rich_receipts()[0]['cleanup']['status'], 'removed')
        self.assertEqual(self.executor.app_starts, [])
        self.assertTrue(self.executor.identity.removed)
        self.assertEqual(report['status'], 'BLOCKED')
        self.old_oidc.assert_not_called()

    def test_advertised_app_port_change_cannot_repair_registered_callback_silently(self):
        self.app()
        self.configure()
        self.executor.port_change = 43999
        report = self.run_pipeline()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'], 'BLOCKED')
        realm, = self.executor.identity_realms
        self.assertEqual(realm['clients'][0]['redirectUris'], ['http://127.0.0.1:43127/auth/callback'])
        self.assertNotIn('43999', json.dumps(realm))
        self.assertEqual(report['integration_receipts'][0]['tested_routes'], [])
        self.assertTrue(self.executor.identity.removed)

    def test_foreign_lifecycle_binding_cannot_replace_current_receipt(self):
        self.app()
        self.configure()
        report = self.run_pipeline()
        expected = copy.deepcopy(report['integration_receipts'])
        raw, = self.rich_receipts()
        raw['run_id'] = 'runtime-previous-fixture'
        with self.assertRaises(runtime.Blocked):
            self.runner.record_keycloak({'path': 'frontend', 'name': 'frontend'}, raw)
        self.assertEqual(self.runner.integration_receipts, expected)

    def test_health_returned_origin_change_blocks_registered_callback(self):
        self.app()
        self.configure()
        self.executor.health_result = 'http://127.0.0.1:43999/private'
        report = self.run_pipeline()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'], 'BLOCKED')
        self.assertEqual(len(self.executor.app_starts), 1)
        self.assertEqual(self.executor.identity_realms[0]['clients'][0]['redirectUris'],
                         ['http://127.0.0.1:43127/auth/callback'])
        self.assertTrue(self.executor.identity.removed)

    def test_identity_environment_failure_does_not_replace_client_or_retry(self):
        self.app(client='explicit-client')
        self.configure()
        self.executor.startup_env_error = True
        report = self.run_pipeline()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(len(self.executor.app_starts), 1)
        self.assertEqual(self.executor.app_starts[0]['env']['EXAMPLE_KC_CLIENT_ID'], 'explicit-client')
        self.assertEqual(self.runner.env['EXAMPLE_KC_CLIENT_ID'], 'explicit-client')
        self.assertIn('EXAMPLE_KC_CLIENT_ID invalid', report['parts'][0]['startup']['reason'])
        self.assertEqual(self.executor.identity_realms[0]['clients'][0]['clientId'], 'explicit-client')
        self.assertTrue(self.executor.identity.removed)

    def test_generated_secret_echo_is_redacted_from_build_startup_and_report(self):
        self.app(confidential=True)
        self.configure()
        self.executor.echo_secrets = True
        report = self.run_pipeline()
        secret = self.executor.app_starts[0]['env']['EXAMPLE_KC_CLIENT_SECRET']
        self.assertGreaterEqual(len(secret), 24)
        self.assertEqual(report['status'], 'BLOCKED')
        public = json.dumps(report)
        for path in self.out.rglob('*'):
            if path.is_file():
                text = path.read_text()
                self.assertNotIn(secret, text, path.relative_to(self.out).as_posix())
                public += text
        self.assertNotIn(secret, public)
        self.assertIn('Build diagnostic: [REDACTED]', public)
        self.assertIn('Error: startup authentication failure [REDACTED]', public)
        self.assertEqual(len(self.executor.app_starts), 1)
        self.assertFalse(self.runner.tmp.exists())
        self.assertTrue(self.executor.identity.removed)

    def assert_untrusted_startup_log_is_unread(self, *, parent_symlink):
        self.app()
        self.configure()
        foreign = self.base / 'foreign-private'
        foreign.mkdir()
        canary = foreign / 'start-1.log'
        marker = 'EXTERNAL_CANARY_MUST_NOT_BE_READ_OR_PUBLISHED'
        canary.write_text(marker)
        self.executor.raw_canary = canary
        self.executor.raw_parent_symlink = parent_symlink
        report = self.run_pipeline()
        self.assertTrue(report['partial'])
        self.assertTrue(report['startup_log_gaps'])
        self.assertTrue(all(row['status'] == 'not_read' for row in report['startup_log_gaps']))
        self.assertNotEqual(report['status'], 'PASS')
        public = json.dumps(report)
        public += ''.join(path.read_text() for path in self.out.rglob('*') if path.is_file())
        self.assertNotIn(marker, public)
        self.assertIn('INCOMPLETE: startup log unavailable', public)
        self.assertEqual(canary.read_text(), marker)
        self.assertFalse(self.runner.tmp.exists())
        self.assertTrue(self.executor.identity.removed)

    def test_raw_startup_symlink_is_not_read_and_cleanup_completes(self):
        self.assert_untrusted_startup_log_is_unread(parent_symlink=False)

    def test_raw_startup_parent_symlink_is_not_read_and_cleanup_completes(self):
        self.assert_untrusted_startup_log_is_unread(parent_symlink=True)

    def test_interrupt_after_app_spawn_still_cleans_app_and_owned_identity(self):
        self.app()
        self.configure()
        with self.assertRaises(KeyboardInterrupt):
            self.run_pipeline(interrupt_first_log=True)
        self.assertEqual(len(self.executor.started), 1)
        self.assertEqual(self.executor.started, self.executor.stopped)
        self.assertTrue(self.executor.identity.removed)
        self.assertFalse(self.runner.tmp.exists())

    def test_browser_journal_redacts_known_generated_secret_before_publication(self):
        secret = 'SYNTHETIC_GENERATED_SECRET_REDACTION_CANARY'
        executor = ApplicationExecutor()
        original = executor.run
        def command(argv, cwd, env, timeout):
            answer = original(argv, cwd, env, timeout)
            if any(str(arg).endswith('runtime-browser.cjs') for arg in argv):
                journal = Path(str(argv[3]) + '.jsonl')
                row = json.loads(journal.read_text().splitlines()[0])
                row['errors'] = ['Synthetic browser failure ' + secret]
                journal.write_text(json.dumps(row) + '\n')
            return answer
        executor.run = command
        runner = runtime.Runner(self.project, self.out, executor=executor,
            tools={'tools': {'node': '/fake/node', 'npm': '/fake/npm'}})
        (self.out / 'logs').mkdir(parents=True)
        runner.tmp = self.base / 'private-browser'
        runner.tmp.mkdir()
        runner.work = self.project
        runner.env = {}
        runner.private_values = {secret}
        with patch.object(subprocess, 'run', side_effect=AssertionError('real process')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('real process')), \
             patch.object(socket, 'socket', side_effect=AssertionError('real network')):
            runner.measure('e2e', {'path': '.', 'routes': ['/']}, 'http://127.0.0.1:43127',
                           runtime.profile_budgets({}))
        copied, = (self.out / 'logs').glob('browser-*.jsonl')
        self.assertNotIn(secret, copied.read_text())
        self.assertIn('Synthetic browser failure [REDACTED]', copied.read_text())

    def test_monorepo_second_part_does_not_inherit_identity_environment(self):
        self.app('apps/a')
        self.app('apps/b', configured=False, identity_source=False)
        self.configure()
        # A part with no identity source may use the existing no-op OIDC path.
        report = self.run_pipeline(allow_plain_oidc=True)
        self.assertEqual(len(self.lifecycle_calls), 1)
        primary = [row for row in self.executor.app_starts if row['env'].get('HELIX_RUNTIME_TIMEZONE_PASS') != 'utc-smoke']
        self.assertEqual(len(primary), 2)
        first, second = [row['env'] for row in primary]
        self.assertIn('EXAMPLE_KC_ISSUER', first)
        for name in [*self.env_roles, 'HELIX_RUNTIME_IDENTITY_MODE', 'HELIX_RUNTIME_OIDC_ISSUER',
                     'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE']:
            self.assertNotIn(name, second)
        self.assertEqual(self.entry(report)['parts'], ['apps/a'])


if __name__ == '__main__':
    unittest.main()
