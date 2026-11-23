"""Synthetic Keycloak plan/import fixtures; no service, real user or network."""
import copy
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_identity as identity


class RuntimeIdentityTests(unittest.TestCase):
    def settings(self):
        return dict(client_id='test-app', client_type='public', callback_paths=['/auth/callback'],
                    pkce='S256', role_claim='realm_access.roles', roles=['reader', 'editor'])

    def config(self, values=None, part='app'):
        return {'runtime': {'keycloak': {'parts': {part: values or self.settings()}}}}

    def plan(self, values=None, sources=None):
        result = identity.identity_plan(sources or {}, [{'path': 'app'}], self.config(values))
        self.assertEqual(result['status'], 'READY', result)
        self.assertEqual(len(result['parts']), 1)
        return result['parts'][0]

    def material(self, plan, **changes):
        value = dict(realm='helix-offline-run001', app_origin='http://127.0.0.1:43127',
                     user_passwords={row['id']: 'synthetic-password-' + row['id'] for row in plan['identities']})
        if plan['client']['client_type'] == 'confidential': value['client_secret'] = 'synthetic-private-client-secret-001'
        value.update(changes)
        return value

    def source(self, client='test-app', role='reader'):
        return ("import Keycloak from 'keycloak-js';\n"
                f"const auth = new Keycloak({{clientId: '{client}', publicClient: true}});\n"
                "auth.init({redirectUri: 'https://production.invalid/auth/callback', pkceMethod: 'S256'});\n"
                f"auth.hasRealmRole('{role}');\n")

    def test_static_contract_keeps_locations_but_never_claims_execution(self):
        report = identity.identity_plan({'app/src/auth.ts': self.source()}, [{'path': 'app'}])
        self.assertEqual(report['status'], 'READY', report)
        part = report['parts'][0]
        self.assertEqual(part['client']['callback_paths'], ['/auth/callback'])
        self.assertEqual(part['client']['roles'], ['reader'])
        self.assertEqual(part['evidence'][0]['source'], 'app/src/auth.ts')
        self.assertTrue(all(row['line'] > 0 for row in part['evidence']))
        self.assertEqual(part['strategy'], 'container'); self.assertIsNone(part['fallback'])
        self.assertEqual(part['image_basis'], 'ASSUMPTION_supported_default')
        self.assertEqual(report['execution'], dict(files_opened=0, commands=0, models=0, network=0))
        self.assertEqual(part['execution'], dict(service_started=False, login_performed=False, tested_routes=[]))
        self.assertNotIn('production.invalid', json.dumps(report))

    def test_explicit_external_config_and_inputs_are_immutable_and_deterministic(self):
        sources = {'app/src/main.ts': 'const client = process.env.KEYCLOAK_CLIENT_ID;'}
        config = self.config(); parts = [{'path': 'app'}]
        before = copy.deepcopy((sources, parts, config))
        result = identity.identity_plan(sources, parts, config)
        self.assertEqual(result, identity.identity_plan(sources, parts, config))
        self.assertEqual((sources, parts, config), before)
        self.assertEqual(result['status'], 'READY')

    def test_comments_string_examples_and_inactive_sources_do_not_detect_service(self):
        fake = "// import Keycloak from 'keycloak-js';\nconst example = `import x from 'keycloak-js'; Keycloak.hasRealmRole('admin')`;"
        sources = {'app/src/main.ts': fake}
        for path in ['app/docs/auth.md', 'app/legacy/auth.ts', 'app/tests/auth.test.ts', 'app/examples/auth.ts']:
            sources[path] = self.source()
        result = identity.identity_plan(sources, [{'path': 'app'}])
        self.assertEqual(result['status'], 'NOT_DETECTED', result)
        self.assertEqual(len(result['excluded']), 4)

    def test_secrets_exports_users_and_unrelated_config_are_not_copied(self):
        marker = 'REAL_PRIVATE_ACCOUNT_AND_SECRET'
        sources = {'app/.env': f'KEYCLOAK_CLIENT_ID={marker}',
                   'app/.env.example': f'KEYCLOAK_SECRET={marker}',
                   'app/realm-export.json': json.dumps({'realm': 'real', 'users': [{'username': marker}]}),
                   'app/credentials.json': marker,
                   'app/src/auth.ts': self.source() + f"const clientSecret = '{marker}';"}
        result = identity.identity_plan(sources, [{'path': 'app'}])
        self.assertEqual(result['status'], 'READY'); self.assertNotIn(marker, json.dumps(result))
        for field in ['users', 'smtpServer', 'client_secret', 'userFederationProviders', 'assertions']:
            values = self.settings(); values[field] = marker
            with self.subTest(field=field), self.assertRaises(ValueError) as caught:
                identity.identity_plan({}, [{'path': 'app'}], self.config(values))
            self.assertNotIn(marker, str(caught.exception))

    def test_monorepo_clients_and_roles_do_not_leak_between_parts(self):
        result = identity.identity_plan({'apps/a/src/auth.ts': self.source('one', 'reader'),
                                         'apps/b/src/auth.ts': self.source('two', 'accountant')},
                                        [{'path': 'apps/a'}, {'path': 'apps/b'}])
        self.assertEqual(result['status'], 'READY')
        self.assertEqual([(p['client']['client_id'], p['client']['roles']) for p in result['parts']],
                         [('one', ['reader']), ('two', ['accountant'])])

    def test_root_compose_version_cannot_be_silently_replaced_by_supported_default(self):
        for roots in [[{'path': 'app'}], [{'path': '.'}, {'path': 'app'}]]:
            with self.subTest(roots=roots):
                result = identity.identity_plan({'compose.yaml': 'services:\n  auth:\n    image: quay.io/keycloak/keycloak:25.0.6\n',
                                                 'app/auth.ts': self.source()}, roots)
                app = next(part for part in result['parts'] if part['part'] == 'app')
                self.assertEqual(app['status'], 'BLOCKED'); self.assertIsNone(app['fallback'])
                self.assertEqual(app['image'], 'quay.io/keycloak/keycloak:25.0.6')
                self.assertTrue(any(g['field'] == 'image' for g in app['gaps']))

    def test_sdk_version_does_not_become_server_version_and_explicit_pin_is_retained(self):
        sources = {'app/package.json': json.dumps({'dependencies': {'keycloak-js': '99.2.1'}})}
        plan = self.plan(sources=sources)
        self.assertEqual(plan['server_version'], '26.8.1')
        self.assertEqual(plan['image_basis'], 'ASSUMPTION_supported_default')
        sources['compose.yml'] = 'image: ' + identity.IMAGE
        plan = self.plan(sources=sources)
        self.assertEqual(plan['image_basis'], 'declared')
        for image in ['quay.io/keycloak/keycloak:latest', 'quay.io/keycloak/keycloak:25.0.6']:
            values = self.settings(); values['image'] = image
            result = identity.identity_plan({}, [{'path': 'app'}], self.config(values))
            self.assertEqual(result['status'], 'BLOCKED'); self.assertEqual(result['parts'][0]['image'], image)

    def test_missing_ambiguous_or_conflicting_values_fail_closed(self):
        cases = [({}, {'app/auth.ts': "import Keycloak from 'keycloak-js';"}),
                 (self.config(), {'app/auth.ts': self.source('other-client')}),
                 ({}, {'app/auth.ts': self.source() + "\nconst another = {clientId: 'other-client'};"})]
        for config, sources in cases:
            with self.subTest(sources=sources):
                result = identity.identity_plan(sources, [{'path': 'app'}], config)
                self.assertEqual(result['status'], 'BLOCKED')
                with self.assertRaises(ValueError): identity.synthetic_realm(result['parts'][0], {})

    def test_dynamic_roles_and_claims_need_explicit_contract(self):
        for extra in ['auth.hasRealmRole(roleName);', 'consume(token.resource_access[clientName].roles);']:
            with self.subTest(extra=extra):
                sources = {'app/auth.ts': self.source() + extra}
                result = identity.identity_plan(sources, [{'path': 'app'}])
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertTrue(any(g['reason'].startswith('dynamic_') for g in result['parts'][0]['gaps']))
                self.assertEqual(identity.identity_plan(sources, [{'path': 'app'}], self.config())['status'], 'READY')

    def test_dynamic_callback_needs_explicit_contract_and_is_resolved_by_it(self):
        extra = "\nconst redirectUri = `${base.replace(/\\/$/, '')}/api/oauth/${provider}/callback`;\n"
        sources = {'app/auth.ts': self.source() + extra}
        result = identity.identity_plan(sources, [{'path': 'app'}])
        self.assertIn(dict(field='callback_paths', reason='dynamic_or_unsupported_source_value'), result['parts'][0]['gaps'])
        self.assertEqual(identity.identity_plan(sources, [{'path': 'app'}], self.config())['status'], 'READY')

    def test_administrative_and_service_token_clients_never_become_login_client(self):
        for grant, client in [('password', 'admin-cli'), ('client_credentials', 'worker-console')]:
            sources = {'app/admin.ts': f"const body = new URLSearchParams({{client_id: '{client}', grant_type: '{grant}'}});",
                       'app/login.ts': "import Keycloak from 'keycloak-js'; const login = settings.clientId;"}
            with self.subTest(grant=grant):
                result = identity.identity_plan(sources, [{'path': 'app'}])['parts'][0]
                self.assertIsNone(result['client']['client_id'])
                self.assertEqual([row['client_id'] for row in result['service_clients']], [client])
                configured = identity.identity_plan(sources, [{'path': 'app'}], self.config())['parts'][0]
                self.assertEqual(configured['status'], 'READY', configured)
                self.assertEqual(configured['client']['client_id'], 'test-app')
        sources = {'app/mixed.ts': self.source() + "\nconst service = {client_id: 'daemon-client', grant_type: 'client_credentials'};"}
        result = identity.identity_plan(sources, [{'path': 'app'}])['parts'][0]
        self.assertEqual(result['status'], 'READY'); self.assertEqual(result['client']['client_id'], 'test-app')

    def test_prefixed_env_helpers_are_names_only_and_do_not_need_other_keycloak_source(self):
        source = ("import { env as privateEnv } from '$env/dynamic/private';\n"
                  "function required(name: string): string { return (privateEnv[name] ?? '').trim(); }\n"
                  "export const identityConfig = {\n"
                  " get clientId() { return required('ACME_KC_CLIENT_ID'); },\n"
                  " get realm() { return required('ACME_KC_REALM'); },\n"
                  " get secret() { return privateEnv.ACME_KC_CLIENT_SECRET; } };\n")
        result = identity.identity_plan({'app/settings.ts': source}, [{'path': 'app'}])
        self.assertEqual(result['status'], 'BLOCKED')
        plan = result['parts'][0]
        self.assertIsNone(plan['client']['client_id']); self.assertIsNone(plan['client']['client_type'])
        self.assertIn({'field': 'client_id', 'reason': 'environment_value_unresolved'}, plan['gaps'])
        self.assertEqual({row['name'] for row in plan['env_bindings']}, {'ACME_KC_CLIENT_ID', 'ACME_KC_REALM', 'ACME_KC_CLIENT_SECRET'})
        client = next(row for row in plan['env_bindings'] if row['role'] == 'client_id')
        self.assertEqual((client['source'], client['line']), ('app/settings.ts', 4))
        configured = identity.identity_plan({'app/settings.ts': source}, [{'path': 'app'}], self.config())
        self.assertEqual(configured['status'], 'READY', configured)

    def test_env_labels_examples_and_unproven_helper_calls_do_not_detect_keycloak(self):
        sources = {'app/a.ts': "const label = 'ACME_KC_CLIENT_ID'; // process.env.ACME_KC_REALM\n"
                   "function translate(name: string) { return labels[name]; }\n"
                   "const text = translate('ACME_KC_CLIENT_ID');\n"
                   "const example = \"process.env.ACME_KC_REALM\";"}
        self.assertEqual(identity.identity_plan(sources, [{'path': 'app'}])['status'], 'NOT_DETECTED')

    def test_env_dependent_client_does_not_reuse_an_unrelated_literal(self):
        sources = {'app/auth.ts': self.source() + '\nconst alternate = process.env.ACME_KEYCLOAK_CLIENT_ID;'}
        result = identity.identity_plan(sources, [{'path': 'app'}])['parts'][0]
        self.assertEqual(result['status'], 'BLOCKED'); self.assertIsNone(result['client']['client_id'])

    def test_callback_template_preserves_only_static_path_after_one_origin(self):
        for value in ['${origin}/session/return', '${request.origin}/session/return']:
            source = self.source().replace("redirectUri: 'https://production.invalid/auth/callback'", 'redirect_uri: `' + value + '`')
            result = identity.identity_plan({'app/auth.ts': source}, [{'path': 'app'}])['parts'][0]
            self.assertEqual(result['status'], 'READY', result)
            self.assertEqual(result['client']['callback_paths'], ['/session/return'])
        for value in ['${host}/session/return', '${origin}/${path}', '${origin}/ok?token=PRIVATE',
                      '${origin}/../return', '${origin}//evil.invalid/path', '${origin}/return#PRIVATE']:
            source = self.source().replace("redirectUri: 'https://production.invalid/auth/callback'", 'redirect_uri: `' + value + '`')
            result = identity.identity_plan({'app/auth.ts': source}, [{'path': 'app'}])['parts'][0]
            self.assertEqual(result['status'], 'BLOCKED', value)
            self.assertEqual(result['client']['callback_paths'], [])
            self.assertNotIn('PRIVATE', json.dumps(result))

    def test_imported_literal_role_matrix_has_locations_and_requires_explicit_contract(self):
        sources = {'app/src/lib/access/roles.ts': "export const LEVELS = ['reader', 'editor'] as const;\n"
                   "export const LABELS = {reader: 'Display label'};\n"
                   "export const COLORS = ['blue', 'red'] as const;",
                   'app/src/lib/server/auth.ts': "import { LEVELS as PRIORITY, COLORS } from '../access/roles';\n"
                   "const claimed = token.realm_access.roles;\n"
                   "export function select(roles: string[]) { return PRIORITY.find((level) => roles.includes(level)); }\n"
                   "function color(colors: string[]) { return COLORS.find((item) => colors.includes(item)); }\n",
                   'app/login.ts': self.source().replace("auth.hasRealmRole('reader');", '')}
        result = identity.identity_plan(sources, [{'path': 'app'}])['parts'][0]
        self.assertEqual(result['client']['roles'], ['editor', 'reader'])
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn({'field': 'roles', 'reason': 'static_membership_list_requires_explicit_role_contract'}, result['gaps'])
        self.assertIn({'field': 'roles', 'source': 'app/src/lib/access/roles.ts', 'line': 1}, result['evidence'])
        self.assertIn({'field': 'role_list_membership', 'source': 'app/src/lib/server/auth.ts', 'line': 3}, result['evidence'])
        self.assertNotIn('Display label', json.dumps(result)); self.assertNotIn('blue', result['client']['roles'])
        self.assertEqual(identity.identity_plan(sources, [{'path': 'app'}], self.config())['status'], 'READY')
        sources['app/src/lib/server/auth.ts'] = sources['app/src/lib/server/auth.ts'].replace('const claimed = token.realm_access.roles;', '')
        result = identity.identity_plan(sources, [{'path': 'app'}])['parts'][0]
        self.assertEqual(result['client']['roles'], [])

    def test_app_url_callback_suffix_is_candidate_until_explicit_contract(self):
        source = self.source().replace("redirectUri: 'https://production.invalid/auth/callback'",
                                       'redirect_uri: `${settings.appUrl}/session/return`')
        sources = {'app/auth.ts': source}
        result = identity.identity_plan(sources, [{'path': 'app'}])['parts'][0]
        self.assertEqual(result['client']['callback_paths'], ['/session/return'])
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn({'field': 'callback_paths', 'reason': 'callback_origin_requires_explicit_contract'}, result['gaps'])
        values = self.settings(); values['callback_paths'] = ['/session/return']
        self.assertEqual(identity.identity_plan(sources, [{'path': 'app'}], self.config(values))['status'], 'READY')
        for suffix in ['/${path}', '/ok?secret=PRIVATE', '/../../return', '//remote.invalid/return']:
            dynamic = source.replace('/session/return`', suffix + '`')
            plan = identity.identity_plan({'app/auth.ts': dynamic}, [{'path': 'app'}])['parts'][0]
            self.assertEqual(plan['status'], 'BLOCKED')
            self.assertEqual(plan['client']['callback_paths'], [])
            self.assertNotIn('PRIVATE', json.dumps(plan))

    def test_mixed_dynamic_claims_do_not_present_realm_as_resolved(self):
        sources = {'app/auth.ts': self.source() + '\nconst other = token.resource_access[settings.clientId].roles;'}
        result = identity.identity_plan(sources, [{'path': 'app'}])['parts'][0]
        self.assertIsNone(result['client']['role_claim'])
        self.assertIn({'field': 'role_claim', 'reason': 'mixed_claim_sources_require_explicit_contract'}, result['gaps'])
        self.assertEqual(identity.identity_plan(sources, [{'path': 'app'}], self.config())['status'], 'READY')

    def test_env_role_contract_keeps_names_only_and_rejects_process_controls(self):
        values = self.settings(); values['env_roles'] = {'APP_IDENTITY_URL': 'idp_origin', 'APP_IDENTITY_CLIENT': 'client_id', 'APP_REALM': 'realm'}
        result = self.plan(values)
        self.assertEqual(result['env_roles'], values['env_roles']); self.assertEqual(result['env_roles_basis'], 'explicit')
        for name in ['PATH', 'PORT', 'HOME', 'NODE_OPTIONS', 'NODE_CUSTOM', 'NPM_CONFIG_USERCONFIG', 'GIT_CONFIG_COUNT',
                     'BASH_ENV', 'ENV', 'ZDOTDIR', 'SSLKEYLOGFILE', 'OPENSSL_CONF', 'LD_PRELOAD', 'HTTP_PROXY',
                     'NODE_TLS_REJECT_UNAUTHORIZED', 'PYTHONSTARTUP', 'DATABASE_URL', 'APP_POSTGRES_PASSWORD']:
            values['env_roles'] = {name: 'issuer'}
            with self.subTest(name=name), self.assertRaises(ValueError): self.plan(values)
        for invalid in [[], {'APP_CLIENT': {'PRIVATE': 'secret'}}, {'APP_CLIENT': 'https://private.invalid'}, {5: 'issuer'}]:
            values['env_roles'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError) as caught: self.plan(values)
            self.assertNotIn('PRIVATE', str(caught.exception)); self.assertNotIn('private.invalid', str(caught.exception))

    def test_inferred_env_roles_distinguish_identity_and_app_origin_without_executing(self):
        source = "const cfg=[process.env.ACME_KC_URL,process.env.ACME_KC_ISSUER,process.env.ACME_APP_URL];"
        result = identity.identity_plan({'app/settings.ts': source}, [{'path': 'app'}])['parts'][0]
        self.assertEqual(result['env_roles'], dict(ACME_KC_URL='idp_origin', ACME_KC_ISSUER='issuer', ACME_APP_URL='app_origin'))
        self.assertEqual(result['env_roles_basis'], 'source_declaration'); self.assertEqual(result['status'], 'BLOCKED')
        values = self.settings(); values['env_roles'] = {}
        result = identity.identity_plan({'app/settings.ts': source}, [{'path': 'app'}], self.config(values))['parts'][0]
        self.assertEqual(result['env_roles'], {}); self.assertEqual(result['env_roles_basis'], 'explicit')
        self.assertEqual(identity.identity_plan({'app/settings.ts': 'const url=process.env.ACME_APP_URL;'}, [{'path': 'app'}])['status'], 'NOT_DETECTED')

    def test_access_token_audience_mapper_is_scoped_to_only_selected_synthetic_client(self):
        for kind in ['public', 'confidential']:
            for claim in ['realm_access.roles', 'resource_access.test-app.roles']:
                with self.subTest(kind=kind, claim=claim):
                    values = self.settings(); values.update(client_type=kind, role_claim=claim)
                    plan = self.plan(values); realm = identity.synthetic_realm(plan, self.material(plan))
                    mappers = [m for m in realm['clients'][0]['protocolMappers'] if m['protocolMapper'] == 'oidc-audience-mapper']
                    self.assertEqual(len(mappers), 1)
                    self.assertEqual(mappers[0]['config'], {'included.client.audience': plan['client']['client_id'],
                                     'access.token.claim': 'true', 'id.token.claim': 'false',
                                     'introspection.token.claim': 'false', 'lightweight.claim': 'false'})
                    self.assertEqual([c['clientId'] for c in realm['clients']], ['test-app'])
                    self.assertFalse(plan['execution']['login_performed'])

    def test_custom_other_client_and_dotted_client_claims_are_explicit_gaps(self):
        for client, claim in [('test-app', 'permissions'), ('test-app', 'resource_access.other.roles'),
                              ('app.with.dot', 'resource_access.app.with.dot.roles')]:
            values = self.settings(); values.update(client_id=client, role_claim=claim)
            result = identity.identity_plan({}, [{'path': 'app'}], self.config(values))
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertTrue(any(g['field'] == 'role_claim' for g in result['parts'][0]['gaps']))

    def test_client_role_static_calls_and_bracket_claim_are_not_realm_roles(self):
        for role_source in ["auth.hasResourceRole('reader', 'test-app');",
                            "auth.hasResourceRole('reader'); consume(token.resource_access['test-app'].roles);"]:
            with self.subTest(role_source=role_source):
                source = self.source().replace("auth.hasRealmRole('reader');", role_source)
                result = identity.identity_plan({'app/auth.ts': source}, [{'path': 'app'}])
                self.assertEqual(result['status'], 'READY', result)
                plan = result['parts'][0]
                self.assertEqual(plan['client']['role_claim'], 'resource_access.test-app.roles')
                realm = identity.synthetic_realm(plan, self.material(plan))
                self.assertIn('clientRoles', realm['users'][0]); self.assertNotIn('realmRoles', realm['users'][0])

    def test_python_import_and_bracket_realm_claim_require_real_code(self):
        result = identity.identity_plan({'app/auth.py': 'from keycloak import KeycloakOpenID\n'}, [{'path': 'app'}])
        self.assertEqual(result['status'], 'BLOCKED')
        source = self.source().replace("auth.hasRealmRole('reader');", "requireRole('reader'); consume(token.realm_access['roles']);")
        result = identity.identity_plan({'app/auth.ts': source}, [{'path': 'app'}])
        self.assertEqual(result['status'], 'READY', result)
        self.assertEqual(result['parts'][0]['client']['role_claim'], 'realm_access.roles')

    def test_malformed_values_and_callbacks_block_without_copying_unsafe_values(self):
        for field, value in [('client_id', '${PRIVATE}'), ('roles', ['${PRIVATE}']), ('roles', {}),
                             ('pkce', None), ('pkce', {}), ('client_type', 'unknown'),
                             ('callback_paths', [None]), ('callback_paths', ['/valid', None]),
                             ('callback_paths', ['/auth/*']), ('callback_paths', ['https://real.invalid/callback']),
                             ('callback_paths', ['/auth/../callback']), ('callback_paths', ['/auth/%2e/callback']),
                             ('callback_paths', ['/auth/call back']), ('callback_paths', ['/auth/callback?secret=PRIVATE'])]:
            values = self.settings(); values[field] = value
            with self.subTest(field=field, value=value):
                result = identity.identity_plan({}, [{'path': 'app'}], self.config(values))
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertNotIn('PRIVATE', json.dumps(result))

    def test_realm_contains_only_synthetic_users_and_exact_actual_port_callbacks(self):
        plan = self.plan(); material = self.material(plan)
        before = copy.deepcopy((plan, material))
        realm = identity.synthetic_realm(plan, material)
        self.assertEqual((plan, material), before)
        self.assertEqual(realm, identity.synthetic_realm(plan, material))
        self.assertEqual(realm['clients'][0]['redirectUris'], ['http://127.0.0.1:43127/auth/callback'])
        self.assertEqual(realm['clients'][0]['webOrigins'], ['http://127.0.0.1:43127'])
        self.assertEqual(len(realm['users']), len(plan['client']['roles']) + 2)
        self.assertTrue(all(u['username'].startswith('helix-') and u['email'].endswith('@example.invalid') for u in realm['users']))
        self.assertEqual([u['realmRoles'] for u in realm['users'] if u['username'] == 'helix-no-app-role'], [[]])
        unverified = next(u for u in realm['users'] if u['username'] == 'helix-unverified-email')
        self.assertFalse(unverified['emailVerified']); self.assertFalse(realm['verifyEmail'])
        self.assertEqual(realm['sslRequired'], 'all')
        self.assertGreaterEqual(realm['ssoSessionIdleTimeout'], 6*3600); self.assertGreaterEqual(realm['ssoSessionMaxLifespan'], 6*3600)
        for key in ['registrationAllowed', 'resetPasswordAllowed', 'editUsernameAllowed']: self.assertFalse(realm[key])
        for key in ['smtpServer', 'identityProviders', 'identityProviderMappers', 'userFederationProviders', 'components', 'eventsListeners']:
            self.assertFalse(realm[key])
        public = json.dumps(plan)
        self.assertTrue(all(secret not in public for secret in material['user_passwords'].values()))

    def test_flow_pkce_and_user_claims_are_explicit(self):
        plan = self.plan(); realm = identity.synthetic_realm(plan, self.material(plan)); client = realm['clients'][0]
        self.assertTrue(client['publicClient']); self.assertTrue(client['standardFlowEnabled'])
        for key in ['implicitFlowEnabled', 'directAccessGrantsEnabled', 'serviceAccountsEnabled']: self.assertFalse(client[key])
        self.assertEqual(client['attributes'], {'pkce.code.challenge.method': 'S256'})
        self.assertNotIn('secret', client)
        mapper = client['protocolMappers'][0]
        self.assertEqual(mapper['protocolMapper'], 'oidc-usermodel-realm-role-mapper')
        self.assertEqual(mapper['config']['claim.name'], 'realm_access.roles')
        claims = {m['config'].get('claim.name', m['name']): m for s in realm['clientScopes'] for m in s['protocolMappers']}
        self.assertEqual(set(claims), {'sub', 'auth_time', 'preferred_username', 'email', 'email_verified'})
        # Zakres basic jak w domyślnym realmie Keycloak 25+: bez sub i auth_time aplikacja odrzuca token dostępu.
        self.assertEqual(client['defaultClientScopes'], ['basic', 'profile', 'email'])
        self.assertEqual(claims['sub']['protocolMapper'], 'oidc-sub-mapper')
        basic = next(s for s in realm['clientScopes'] if s['name'] == 'basic')
        self.assertEqual(basic['attributes'], {'include.in.token.scope': 'false', 'display.on.consent.screen': 'false'})
        self.assertEqual(claims['sub']['config']['access.token.claim'], 'true')
        self.assertEqual(claims['auth_time']['config']['user.session.note'], 'AUTH_TIME')
        self.assertEqual(claims['email_verified']['config']['user.attribute'], 'emailVerified')
        self.assertEqual(claims['email_verified']['config']['jsonType.label'], 'boolean')

    def test_confidential_client_role_mapper_and_disabled_pkce_are_preserved(self):
        values = self.settings(); values.update(client_type='confidential', pkce=False, role_claim='resource_access.test-app.roles')
        plan = self.plan(values); material = self.material(plan); realm = identity.synthetic_realm(plan, material)
        client = realm['clients'][0]; mapper = client['protocolMappers'][0]
        self.assertFalse(client['publicClient']); self.assertEqual(client['secret'], material['client_secret'])
        self.assertEqual(client['clientAuthenticatorType'], 'client-secret'); self.assertEqual(client['attributes'], {})
        self.assertEqual(mapper['protocolMapper'], 'oidc-usermodel-client-role-mapper')
        self.assertEqual(mapper['config']['usermodel.clientRoleMapping.clientId'], 'test-app')
        self.assertEqual(realm['roles'], {'client': {'test-app': [{'name': 'editor'}, {'name': 'reader'}]}})
        self.assertTrue(all('realmRoles' not in u and set(u['clientRoles']) == {'test-app'} for u in realm['users']))

    def test_unsafe_origins_are_rejected_without_echoing_values(self):
        plan = self.plan()
        for origin in ['https://real.invalid:443', 'http://127.0.0.1', 'http://127.0.0.1:43127/',
                       'http://127.0.0.1:43127/path', 'http://user:PRIVATE@127.0.0.1:43127',
                       'http://127.0.0.1:43127?secret=PRIVATE', 'http://127.0.0.1:0', None, {}, 'file:///PRIVATE']:
            with self.subTest(origin=origin), self.assertRaises(ValueError) as caught:
                identity.synthetic_realm(plan, self.material(plan, app_origin=origin))
            self.assertNotIn('PRIVATE', str(caught.exception))
        for origin in ['https://localhost:4443', 'https://[::1]:4443']:
            self.assertEqual(identity.synthetic_realm(plan, self.material(plan, app_origin=origin))['clients'][0]['webOrigins'], [origin])

    def test_private_material_requires_unique_credentials_and_rejects_real_imports(self):
        plan = self.plan(); material = self.material(plan)
        bad = [dict(material, realm='production'), dict(material, users=[{'username': 'real'}]),
               dict(material, user_passwords={}), dict(material, client_secret='unused-public-secret'),
               dict(material, user_passwords={key: 'same-password-0123456' for key in material['user_passwords']}),
               dict(material, user_passwords={key: '${PRIVATE}-012345678901' + key for key in material['user_passwords']})]
        for value in bad:
            with self.subTest(value=list(value)), self.assertRaises(ValueError): identity.synthetic_realm(plan, value)
        values = self.settings(); values['client_type'] = 'confidential'; plan = self.plan(values)
        material = self.material(plan); material.pop('client_secret')
        with self.assertRaises(ValueError): identity.synthetic_realm(plan, material)

    def test_mutated_plan_cannot_be_used_as_a_template(self):
        plan = self.plan(); plan['client']['callback_paths'] = ['https://real.invalid/callback']
        with self.assertRaisesRegex(ValueError, 'zmieniony'): identity.synthetic_realm(plan, self.material(plan))

    def test_pure_apis_perform_no_io_network_subprocess_or_entropy(self):
        config = self.config()
        with patch('builtins.open', side_effect=AssertionError('I/O')), patch.object(Path, 'read_text', side_effect=AssertionError('I/O')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('subprocess')), patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             patch('os.urandom', side_effect=AssertionError('entropy')):
            result = identity.identity_plan({}, [{'path': 'app'}], config)
            plan = result['parts'][0]
            realm = identity.synthetic_realm(plan, self.material(plan))
        self.assertEqual(result['status'], 'READY'); self.assertTrue(realm['users'])


if __name__ == '__main__': unittest.main()
