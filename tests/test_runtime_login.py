"""Pure private browser input fixtures, no real identity, network or service."""
import builtins
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(os.environ.get('HELIX_SOURCE_ROOT', ROOT)) / 'bin'))
sys.path.insert(0, str(ROOT / 'bin'))
import helix_runtime_identity as identity
import helix_runtime_login as login


class RuntimeLoginInput(unittest.TestCase):
    def setUp(self):
        self.values = dict(client_id='fixture-app', client_type='confidential', callback_paths=['/auth/callback'],
                           pkce='S256', role_claim='realm_access.roles', roles=['reader', 'editor'], login_path='/login')
        self.plan = self.make_plan()
        self.material = dict(realm='helix-test-attempt01', app_origin='https://localhost:44100',
                             client_secret='synthetic-client-secret-must-not-reach-browser',
                             user_passwords={row['id']: 'synthetic-password-' + row['id'] for row in self.plan['identities']})
        self.binding = dict(run_id='runtime-test-0001', integration_id='keycloak:0123456789ab',
                            integration_plan_id='a' * 64, identity_plan_id=self.plan['plan_id'],
                            attempt_id='login-' + 'b' * 32, part='frontend')
        self.issuer = 'https://127.0.0.1:44200/realms/' + self.material['realm']

    def make_plan(self, **changes):
        values = dict(self.values, **changes)
        return identity.identity_plan({}, [{'path': 'frontend'}], {'runtime': {'keycloak': {'parts': {'frontend': values}}}})['parts'][0]

    def build(self, **kwargs):
        arguments = dict(binding=self.binding, issuer=self.issuer, deadline_unix_ms=1900000000000)
        arguments.update(kwargs)
        return login.build_login_input(self.plan, self.material, **arguments)

    def test_positive_role_users_only_and_no_client_secret_or_negative_password(self):
        result = self.build(); encoded = json.dumps(result)
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(result['binding'], self.binding)
        self.assertEqual(result['authorization_endpoint'], self.issuer + '/protocol/openid-connect/auth')
        self.assertEqual(sorted(row['app_roles'][0] for row in result['identities']), ['editor', 'reader'])
        self.assertTrue(all(row['email_verified'] is True for row in result['identities']))
        self.assertTrue(all(row['username'] == 'helix-' + row['id'] for row in result['identities']))
        self.assertNotIn('client_secret', result)
        self.assertNotIn(self.material['client_secret'], encoded)
        for negative in ('no-app-role', 'unverified-email'):
            self.assertNotIn(negative, encoded)
            self.assertNotIn(self.material['user_passwords'][negative], encoded)
        self.assertNotIn('tested_routes', result)
        self.assertNotIn('session', result)

    def test_input_is_immutable_and_reproducible(self):
        before = copy.deepcopy((self.plan, self.material, self.binding))
        one = self.build(); self.assertEqual(one, self.build())
        self.assertEqual((self.plan, self.material, self.binding), before)
        one['identities'][0]['app_roles'].append('changed')
        one['binding']['run_id'] = 'changed'
        self.assertEqual((self.plan, self.material, self.binding), before)

    def test_builder_never_reads_files_or_executes_process_network_entropy(self):
        with patch.object(builtins, 'open', side_effect=AssertionError('file read')), \
             patch.object(Path, 'read_text', side_effect=AssertionError('file read')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process')), \
             patch.object(os, 'urandom', side_effect=AssertionError('entropy')):
            result = self.build()
        self.assertEqual(result['operation_timeout_ms'], 15000)

    def test_binding_requires_exact_inventory_plan_part_run_and_attempt(self):
        for key, value in (('run_id', ':'), ('integration_id', 'redis:0123456789ab'),
                           ('integration_plan_id', 'not-a-hash'), ('identity_plan_id', 'c' * 64),
                           ('attempt_id', 'login-old'), ('part', 'other'), ('secret', 'SHOULD_NOT_PRINT')):
            binding = dict(self.binding); binding[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'binding') as error:
                self.build(binding=binding)
            self.assertNotIn('SHOULD_NOT_PRINT', str(error.exception))

    def test_changed_or_blocked_identity_plan_fails_closed(self):
        for field, value in (('status', 'BLOCKED'), ('plan_id', 'c' * 64)):
            original = self.plan; self.plan = dict(self.plan, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError): self.build()
            self.plan = original

    def test_https_exact_app_origin_required_with_localhost_or_ipv4(self):
        for origin in ('http://localhost:44100', 'https://outside.invalid:44100', 'https://localhost',
                       'https://localhost:44100/path', 'https://localhost:44100?secret=value',
                       'https://user:secret@localhost:44100', 'https://[::1]:44100'):
            self.material['app_origin'] = origin
            with self.subTest(origin=origin), self.assertRaises(ValueError): self.build()
        self.material['app_origin'] = 'https://127.0.0.1:44100'
        self.assertEqual(self.build()['app_origin'], self.material['app_origin'])

    def test_issuer_cannot_change_realm_endpoint_host_or_collide_with_app_port(self):
        for issuer in (self.issuer.replace('127.0.0.1', 'outside.invalid'), self.issuer.replace('https:', 'http:'),
                       self.issuer.replace('44200', '44100'), self.issuer.replace('attempt01', 'other01'),
                       self.issuer + '/protocol/openid-connect/auth', self.issuer + '?SECRET=hidden'):
            with self.subTest(issuer=issuer), self.assertRaises(ValueError) as error: self.build(issuer=issuer)
            self.assertNotIn('hidden', str(error.exception))

    def test_login_path_must_be_explicit_and_callback_must_be_exact(self):
        for changes in ({'login_path': None}, {'login_path': '//outside.invalid'}, {'login_path':'/auth/callback'},
                        {'callback_paths': ['/callback?code=SECRET']}, {'callback_paths': ['/auth/%2e%2e/callback']}):
            self.plan = self.make_plan(**changes); self.binding['identity_plan_id'] = self.plan['plan_id']
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.build()

    def test_deadlines_are_positive_safe_integers_without_clock_reads(self):
        for value in (None, True, 0, -1, 1.5, float('inf'), float('nan'), login.MAX_SAFE_INTEGER + 1):
            for field in ('deadline_unix_ms', 'operation_timeout_ms'):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.build(**{field: value})
        self.assertEqual(self.build(operation_timeout_ms=2000)['operation_timeout_ms'], 2000)
        with self.assertRaises(ValueError): self.build(operation_timeout_ms=60001)

    def test_public_client_needs_no_secret_and_keeps_declared_pkce(self):
        self.plan = self.make_plan(client_type='public', pkce='disabled')
        self.binding['identity_plan_id'] = self.plan['plan_id']; self.material.pop('client_secret')
        self.assertEqual(self.build()['pkce'], 'disabled')

    def test_missing_synthetic_password_is_error_without_value_exposure(self):
        self.material['user_passwords'].pop(next(iter(self.material['user_passwords'])))
        with self.assertRaises(ValueError) as error: self.build()
        self.assertNotIn('synthetic-password-', str(error.exception))


if __name__ == '__main__': unittest.main()
