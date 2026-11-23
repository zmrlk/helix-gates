"""Identity blueprints are offline declarations, bound to the selected project."""
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_provider_plan import load_helix
import helix_config
import helix_runtime as runtime
import helix_runtime_identity as identity
import helix_runtime_integrations as integrations


class IdentityPipeline(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / 'project'
        self.project.mkdir()
        self.config_path = self.base / 'external.json'
        self.addCleanup(helix_config._overrides.pop, self.project, None)

    def app(self, part='frontend', client='fixture-web', role='reader', source=None):
        root = self.project / part
        root.mkdir(parents=True, exist_ok=True)
        (root / 'package.json').write_text(json.dumps({
            'dependencies': {'express': '1', 'keycloak-js': '1'},
            'scripts': {'start': 'node server.js'}}))
        if source is None:
            source = ("import Keycloak from 'keycloak-js';\n"
                      f"const auth = new Keycloak({{clientId: '{client}', publicClient: true}});\n"
                      "auth.init({redirectUri: '/auth/callback', pkceMethod: 'S256'});\n"
                      f"auth.hasRealmRole('{role}');\n"
                      "app.get('/private', () => 'synthetic');\n")
        (root / 'server.js').write_text(source)
        return root

    def config(self, part='frontend', client='configured-client', role='configured-reader'):
        return {'runtime': {'keycloak': {'parts': {part: {
            'client_id': client, 'client_type': 'public',
            'callback_paths': ['/auth/callback'], 'pkce': 'S256',
            'role_claim': 'realm_access.roles', 'roles': [role]}}}}}

    def snapshot(self):
        return {p.relative_to(self.project).as_posix(): p.read_bytes()
                for p in self.project.rglob('*') if p.is_file() and not p.is_symlink()}

    def test_plan_reuses_source_inventory_once_without_identity_io_or_execution(self):
        self.app()
        before = self.snapshot()
        original = identity.identity_plan

        def pure(sources, parts, config):
            with patch.object(runtime, 'read', side_effect=AssertionError('identity reread')), \
                 patch('builtins.open', side_effect=AssertionError('identity I/O')):
                return original(sources, parts, config)

        with patch.object(identity, 'identity_plan', side_effect=pure) as build, \
             patch.object(integrations, 'inventory', wraps=integrations.inventory) as inventory, \
             patch.object(runtime, 'Executor', side_effect=AssertionError('executor')), \
             patch.object(runtime, 'Runner', side_effect=AssertionError('runtime runner')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')):
            result = runtime.plan(self.project)
        build.assert_called_once()
        inventory.assert_called_once()
        self.assertEqual(build.call_args.args[0], inventory.call_args.args[0])
        self.assertEqual(build.call_args.args[1], result['parts'])
        self.assertEqual(build.call_args.args[2], {})
        self.assertIn('frontend/server.js', build.call_args.args[0])
        self.assertEqual(result['identity_plan']['status'], 'READY')
        self.assertEqual(result['identity_plan']['execution'],
                         dict(files_opened=0, commands=0, models=0, network=0))
        self.assertEqual(before, self.snapshot())

    def test_ready_blueprint_does_not_promote_integration_or_route_coverage(self):
        self.app()
        result = runtime.plan(self.project)
        blueprint = result['identity_plan']['parts'][0]
        service = next(row for row in result['integrations']['integrations'] if row['provider'] == 'keycloak')
        self.assertEqual(blueprint['status'], 'READY')
        self.assertIsNone(blueprint['fallback'])
        self.assertEqual(blueprint['execution'],
                         dict(service_started=False, login_performed=False, tested_routes=[]))
        # Adapter availability does not mean this offline plan executed it.
        self.assertTrue(service['strategy']['implemented'])
        self.assertEqual(service['execution']['status'], 'not_run')
        self.assertEqual(service['coverage']['status'], 'not_checked')
        self.assertEqual(service['coverage']['tested_routes'], [])

    def test_external_config_reaches_identity_and_does_not_write_target_config(self):
        self.app(source="import Keycloak from 'keycloak-js';\n")
        cfg = self.config()
        self.config_path.write_text(json.dumps(cfg))
        original_config = self.config_path.read_bytes()
        helix_config.configure(self.project, self.config_path)
        before = self.snapshot()
        result = runtime.plan(self.project)
        self.assertEqual(result['identity_plan']['status'], 'READY')
        self.assertEqual(result['identity_plan']['parts'][0]['client']['client_id'], 'configured-client')
        self.assertEqual(result['identity_plan']['parts'][0]['client']['roles'], ['configured-reader'])
        self.assertEqual(before, self.snapshot())
        self.assertEqual(original_config, self.config_path.read_bytes())
        self.assertFalse((self.project / 'helix.json').exists())
        self.assertFalse((self.project / '.helix').exists())

    def test_cli_offline_uses_project_without_repo_and_returns_real_public_plan(self):
        self.app(source="import Keycloak from 'keycloak-js';\n")
        self.config_path.write_text(json.dumps(self.config()))
        cli = load_helix()
        before = self.snapshot()
        argv = ['helix', '--offline', '--config', str(self.config_path),
                'runtime', 'plan', '--project', str(self.project), '--json']
        with patch.object(sys, 'argv', argv), \
             patch.object(cli, 'Ctx', side_effect=AssertionError('model context')), \
             patch.object(runtime, 'Runner', side_effect=AssertionError('runtime runner')), \
             patch.object(runtime, 'Executor', side_effect=AssertionError('executor')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exited:
                cli.main()
        self.assertEqual(exited.exception.code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['project'], str(self.project))
        self.assertEqual(result['identity_plan']['parts'][0]['client']['client_id'], 'configured-client')
        self.assertFalse(result['identity_plan']['parts'][0]['execution']['service_started'])
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.base / '.helix-state').exists())
        self.assertFalse((self.project / 'helix.json').exists())

    def test_monorepo_identity_clients_roles_and_evidence_stay_part_scoped(self):
        self.app('apps/one', 'client-one', 'reader')
        self.app('apps/two', 'client-two', 'operator')
        result = runtime.plan(self.project)
        plans = {row['part']: row for row in result['identity_plan']['parts']}
        self.assertEqual(set(plans), {'apps/one', 'apps/two'})
        for part, client, role in [('apps/one', 'client-one', 'reader'),
                                   ('apps/two', 'client-two', 'operator')]:
            self.assertEqual(plans[part]['client']['client_id'], client)
            self.assertEqual(plans[part]['client']['roles'], [role])
            self.assertTrue(plans[part]['evidence'])
            self.assertTrue(all(row['source'].startswith(part + '/') for row in plans[part]['evidence']))

    def test_missing_contract_is_blocked_and_private_files_are_never_read(self):
        app = self.app(source="import Keycloak from 'keycloak-js';\nconst client=process.env.EXAMPLE_KC_CLIENT_ID;\n")
        marker = 'PRIVATE_IDENTITY_VALUE'
        (app / '.env').write_text('EXAMPLE_KC_CLIENT_SECRET=' + marker)
        private = app / 'secrets'; private.mkdir()
        (private / 'realm.json').write_text(json.dumps({'users': [marker]}))
        outside = self.base / 'outside.js'; outside.write_text(marker)
        (app / 'outside.js').symlink_to(outside)
        original_read = runtime.read

        def guarded(path):
            self.assertFalse(path.name.startswith('.env'))
            self.assertNotIn('secrets', path.parts)
            self.assertNotEqual(path.resolve(), outside)
            return original_read(path)

        with patch.object(runtime, 'read', side_effect=guarded):
            result = runtime.plan(self.project)
        self.assertEqual(result['identity_plan']['status'], 'BLOCKED')
        self.assertIsNone(result['identity_plan']['parts'][0]['client']['client_id'])
        self.assertNotIn(marker, json.dumps(result))
        self.assertTrue(result['identity_plan']['parts'][0]['gaps'])

    def test_caller_config_and_sources_are_not_mutated(self):
        self.app(source="import Keycloak from 'keycloak-js';\n")
        cfg = self.config()
        expected = copy.deepcopy(cfg)
        before = self.snapshot()
        result = runtime.plan(self.project, cfg)
        self.assertEqual(result['identity_plan']['status'], 'READY')
        self.assertEqual(cfg, expected)
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main()
