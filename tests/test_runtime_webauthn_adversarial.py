"""Independent pure WebAuthn planning boundaries; no browser or service."""
import builtins
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_runtime_identity as identity
import helix_runtime_identity_policy as policy
import helix_runtime_integrations as integrations
import helix_runtime_transport as transport
import helix_runtime_webauthn as webauthn

CANARY = 'PRIVATE_WEBAUTHN_ASSERTION_5d6f8034'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def rehash(value):
    value['plan_id'] = digest({key: item for key, item in value.items() if key != 'plan_id'})
    return value


def fixture():
    sources = {'frontend/package.json': json.dumps({'dependencies': {'@simplewebauthn/browser': '^13.3.0'}}),
               'frontend/src/session.ts': 'export function session() { return null; }'}
    parts = [{'path': 'frontend'}]
    config = {'runtime': {'https': {'enabled': True, 'public_host': 'localhost'}, 'keycloak': {'parts': {'frontend': {
        'client_id': 'synthetic-app', 'client_type': 'public', 'login_path': '/login', 'callback_paths': ['/auth/callback'],
        'pkce': 'S256', 'role_claim': 'realm_access.roles', 'roles': ['reader', 'editor']}}}, 'identity_policy': {
        'schema_version': 1, 'parts': {'frontend': {'basis': 'explicit_config', 'session': {
            'path': '/api/session', 'method': 'GET', 'http_status': 200, 'anonymous': {'kind': 'status', 'codes': [401]},
            'assertions': [{'pointer': '/user/name', 'equals_identity': 'username'},
                           {'pointer': '/user/roles', 'equals_identity': 'app_roles', 'comparison': 'set_exact'}]},
            'cells': [{'id': 'read-items', 'identity': {'role': 'reader'}, 'request': {'method': 'GET', 'path': '/api/items'},
                       'anonymous': {'kind': 'status', 'codes': [401]}, 'expected': {'access': 'allow', 'http_status': 200,
                         'json': [{'pointer': '/kind', 'equals_literal': 'items'}]}}]}}}}}
    declared_identity = identity.identity_plan(sources, parts, config)
    inventory = integrations.inventory(sources, parts, config)
    declared_transport = transport.transport_plan(sources, parts, inventory, config)
    declared_policy = policy.policy_plan(sources, parts, declared_identity, inventory, config)
    def flow(kind):
        return {'path': '/account/passkeys' if kind == 'registration' else '/passkey-login',
                'action': {'test_id': 'passkey-' + kind}, 'options': {'method': 'GET', 'path': '/api/passkeys/' + kind + '/options'},
                'verify': {'method': 'POST', 'path': '/api/passkeys/' + kind + '/verify', 'http_status': 200,
                           'json': [{'pointer': '/result', 'equals_literal': CANARY}]}}
    raw = {'enabled': True, 'rp_owner': 'application', 'rp_id': 'localhost', 'role': 'reader',
           'policy_cell_ids': [declared_policy['parts'][0]['cells'][0]['id']],
           'registration': flow('registration'), 'authentication': flow('authentication'),
           'logout': {'path': '/account', 'action': {'test_id': 'logout'}, 'request': {'method': 'POST', 'path': '/api/logout'}}}
    config['runtime']['webauthn'] = {'schema_version': 1, 'parts': {'frontend': raw}}
    return sources, parts, inventory, declared_identity, declared_transport, declared_policy, config


class RuntimeWebAuthnAdversarial(unittest.TestCase):
    def setUp(self):
        self.args = fixture()

    @property
    def raw(self):
        return self.args[6]['runtime']['webauthn']['parts']['frontend']

    def compile(self):
        return webauthn.webauthn_plan(*self.args)

    def refresh_source_plans(self):
        sources, parts, _, _, _, _, config = self.args
        inventory = integrations.inventory(sources, parts, config)
        identities = identity.identity_plan(sources, parts, config)
        transports = transport.transport_plan(sources, parts, inventory, config)
        policies = policy.policy_plan(sources, parts, identities, inventory, config)
        self.args = sources, parts, inventory, identities, transports, policies, config

    def report(self, plan=None):
        return dict(parts=self.args[1], integrations=self.args[2], identity_plan=self.args[3], transport_plan=self.args[4],
            identity_policy_plan=self.args[5], identity_policy_receipts=[], webauthn_plan=self.compile() if plan is None else plan,
            webauthn_receipts=[])

    def project(self, plan=None):
        return webauthn.project_webauthn_plan(self.report(plan))

    def rejection(self, callback):
        with self.assertRaises(ValueError) as caught:
            callback()
        self.assertNotIn(CANARY, str(caught.exception))

    def test_complete_declaration_is_only_planned_and_public_literals_are_hashed(self):
        plan = self.compile(); projected = self.project(plan)
        self.assertEqual(plan['status'], 'PLANNED')
        self.assertEqual(projected['plan_status'], 'PLANNED')
        self.assertEqual(projected['execution_status'], 'NOT_RUN')
        self.assertNotIn(CANARY, json.dumps((plan, projected)))
        self.assertIn(digest(CANARY), json.dumps(plan))
        self.assertFalse(plan['execution']['application'])
        self.assertEqual(plan['execution']['commands'], 0)

    def test_dependency_without_flow_has_explicit_gap_and_no_inferred_action(self):
        self.args[6]['runtime'].pop('webauthn')
        plan = self.compile(); projected = self.project(plan)
        self.assertEqual(plan['status'], 'BLOCKED')
        self.assertIn('DEPENDENCY_WITHOUT_FLOW_CONTRACT', json.dumps(plan))
        self.assertEqual(projected['execution_status'], 'NOT_RUN')
        self.assertNotIn('passkey-registration', json.dumps(plan))

    def test_legacy_counts_remain_unknown(self):
        result = webauthn.project_webauthn_plan({'parts': []})
        self.assertEqual(result['execution_status'], 'NOT_RECORDED')
        self.assertEqual(result['coverage_status'], 'NOT_RECORDED')
        self.assertTrue(result['counts'])
        self.assertTrue(all(value is None for value in result['counts'].values()))

    def test_explicit_disabled_is_preserved_without_execution_credit(self):
        self.args[6]['runtime']['webauthn']['parts']['frontend'] = {'enabled': False}
        plan = self.compile(); result = self.project(plan)
        self.assertEqual(plan['parts'][0]['status'], 'DISABLED')
        self.assertEqual(result['execution_status'], 'NOT_RUN')
        self.assertNotEqual(result['coverage_status'], 'RECORDED')

    def test_changed_literal_changes_binding_without_exposure(self):
        first = self.compile()
        self.raw['registration']['verify']['json'][0]['equals_literal'] = CANARY + '_changed'
        second = self.compile()
        self.assertNotEqual(first['plan_id'], second['plan_id'])
        self.assertNotIn(CANARY, json.dumps(second))

    def test_runtime_receipts_and_forged_execution_are_unsupported(self):
        report = self.report(); report['webauthn_receipts'] = [{'status': 'PASS', 'privateKey': CANARY}]
        self.rejection(lambda: webauthn.project_webauthn_plan(report))
        for field, value in (('application', True), ('commands', True), ('network', 1)):
            plan = self.compile(); plan['execution'][field] = value; rehash(plan)
            with self.subTest(field=field): self.rejection(lambda: self.project(plan))

    def test_rehashed_removal_of_active_part_cannot_be_not_detected(self):
        plan = self.compile(); plan['parts'] = []; plan['status'] = 'NOT_DETECTED'; rehash(plan)
        self.rejection(lambda: self.project(plan))

    def test_pure_planner_uses_snapshot_without_file_process_network_or_entropy(self):
        before = copy.deepcopy(self.args)
        with patch.object(builtins, 'open', side_effect=AssertionError('file access')), \
             patch.object(Path, 'read_text', side_effect=AssertionError('file access')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process')), \
             patch.object(os, 'urandom', side_effect=AssertionError('entropy')):
            plan = self.compile(); self.project(plan)
        self.assertEqual(self.args, before)

    def test_no_dependency_no_config_is_distinct_from_legacy(self):
        self.args[0].pop('frontend/package.json')
        self.args[6]['runtime'].pop('webauthn')
        self.refresh_source_plans()
        plan = self.compile(); result = self.project(plan)
        self.assertEqual(plan['status'], 'NOT_DETECTED'); self.assertEqual(plan['parts'], [])
        self.assertEqual(result['coverage_status'], 'NOT_DETECTED')
        self.assertEqual(result['counts']['ceremonies_executed'], 0)

    def test_unknown_role_stays_blocked_without_echoing_private_label(self):
        self.raw['role'] = CANARY
        plan = self.compile(); result = self.project(plan)
        self.assertEqual(plan['status'], 'BLOCKED')
        self.assertIn('ROLE_NOT_DECLARED', json.dumps(plan))
        self.assertIsNone(plan['parts'][0]['role']); self.assertIsNone(plan['parts'][0]['identity_id'])
        self.assertNotIn(CANARY, json.dumps((plan, result)))

    def test_missing_enabled_contract_field_is_visible_instead_of_inferred(self):
        for field in ('registration', 'authentication', 'logout', 'role', 'policy_cell_ids'):
            original = self.raw.pop(field)
            with self.subTest(field=field):
                plan = self.compile(); self.assertEqual(plan['status'], 'BLOCKED')
                self.assertIn('CONTRACT_FIELD_MISSING', json.dumps(plan))
                self.project(plan)
            self.raw[field] = original

    def test_private_syntax_cannot_add_dynamic_paths_arbitrary_code_or_headers(self):
        original = copy.deepcopy(self.raw)
        changes = [lambda r: r['registration'].update(path='/keys//register'),
            lambda r: r['registration'].update(path='/keys/../register'),
            lambda r: r['authentication'].update(path='https://outside.invalid/'+CANARY),
            lambda r: r['registration']['options'].update(path='/options?token='+CANARY),
            lambda r: r['registration']['verify'].update(method='DELETE'),
            lambda r: r['registration']['action'].update(eval=CANARY),
            lambda r: r['registration']['action'].update(test_id='button[onclick]'),
            lambda r: r['logout']['request'].update(headers={'Authorization': CANARY}),
            lambda r: r['registration']['verify'].update(http_status=True),
            lambda r: r['registration']['verify']['json'][0].update(pointer='/__proto__/value'),
            lambda r: r['registration']['verify']['json'][0].update(equals_literal={'secret': CANARY})]
        for change in changes:
            self.args[6]['runtime']['webauthn']['parts']['frontend'] = copy.deepcopy(original)
            change(self.raw)
            with self.subTest(change=change): self.rejection(self.compile)

    def test_selected_cells_are_unique_and_belong_to_the_same_positive_role(self):
        known = self.raw['policy_cell_ids'][0]
        self.raw['policy_cell_ids'] = [known, known]
        self.rejection(self.compile)
        for cells in ([known.replace('cell-', 'cell-f', 1)[:21]], ['cell-'+'f'*16]):
            self.raw['policy_cell_ids'] = cells
            plan = self.compile()
            self.assertEqual(plan['status'], 'BLOCKED'); self.assertIn('POLICY_CELL_NOT_BOUND', json.dumps(plan))
        self.raw['policy_cell_ids'] = [known]; self.raw['role'] = 'editor'
        plan = self.compile()
        self.assertEqual(plan['status'], 'BLOCKED'); self.assertIn('POLICY_CELL_NOT_BOUND', json.dumps(plan))

    def test_transport_origin_choice_is_same_part_and_not_runtime_readiness(self):
        for settings in ({'enabled': False}, {'enabled': True, 'public_host': '127.0.0.1'}):
            args = list(self.args); config = copy.deepcopy(args[6]); config['runtime']['https'] = settings
            args[4] = transport.transport_plan(args[0], args[1], args[2], config); self.args = tuple(args)
            plan = self.compile()
            self.assertEqual(plan['status'], 'BLOCKED'); self.assertIn('TRANSPORT_NOT_READY', json.dumps(plan))
            self.project(plan)

    def test_cross_part_config_cannot_borrow_neighbor_identity_policy_or_transport(self):
        self.args[6]['runtime']['webauthn']['parts']['other'] = self.args[6]['runtime']['webauthn']['parts'].pop('frontend')
        plan = self.compile(); self.assertEqual(plan['status'], 'BLOCKED')
        other = next(part for part in plan['parts'] if part['part'] == 'other')
        self.assertNotEqual(other['status'], 'PLANNED'); self.assertIsNone(other['identity_id'])
        self.assertIn('PART_NOT_DECLARED', json.dumps(other)); self.project(plan)

    def test_rehashed_bound_ids_roles_cells_and_transport_cannot_be_substituted(self):
        mutations = [lambda p: p['parts'][0].update(identity_plan_id='f'*64),
            lambda p: p['parts'][0].update(identity_id='role-'+digest('editor')[:12], role='editor', identity_selector={'role_sha256':digest('editor')}),
            lambda p: p['parts'][0].update(policy_cell_ids=['cell-'+'e'*16]),
            lambda p: p['parts'][0].update(policy_hash='c'*64),
            lambda p: p['parts'][0].update(transport_part_digest='d'*64),
            lambda p: p['parts'][0]['declarations'][0].update(integration_id='webauthn:'+'f'*12)]
        for mutate in mutations:
            plan = self.compile(); mutate(plan); rehash(plan)
            with self.subTest(mutate=mutate): self.rejection(lambda: self.project(plan))

    def test_rehashed_public_literal_and_unknown_fields_are_rejected(self):
        for mutate in (lambda p: p['parts'][0]['registration']['verify']['json'][0].update(equals_literal=CANARY),
                       lambda p: p['parts'][0].update(privateKey=CANARY),
                       lambda p: p.update(counts={'ceremonies_executed': 1})):
            plan = self.compile(); mutate(plan); rehash(plan)
            with self.subTest(mutate=mutate): self.rejection(lambda: self.project(plan))

    def test_dynamic_inventory_execution_does_not_change_static_binding(self):
        plan = self.compile(); report = self.report(plan)
        report['integrations'] = integrations.execution_inventory(self.args[2], [], run_id='synthetic-webauthn-review')
        result = webauthn.project_webauthn_plan(report)
        self.assertEqual(result['plan_status'], 'PLANNED'); self.assertEqual(result['execution_status'], 'NOT_RUN')

    def test_docs_and_private_env_snapshot_values_are_not_active_evidence(self):
        before = self.compile()
        self.args[0]['frontend/.env'] = 'PRIVATE_PASSWORD='+CANARY
        self.args[0]['docs/WebAuthn.md'] = 'navigator.credentials.create({publicKey: value}); '+CANARY
        self.args[0]['legacy/auth.ts'] = 'export const value='+json.dumps(CANARY)+';'
        after = self.compile()
        self.assertEqual(before['source_digest'], after['source_digest'])
        self.assertNotIn(CANARY, json.dumps(after))

    def test_empty_discovery_cannot_prove_no_requirement(self):
        args = list(self.args); args[0] = {}; args[6]['runtime'].pop('webauthn')
        self.args = tuple(args); self.refresh_source_plans()
        plan = self.compile(); result = self.project(plan)
        self.assertNotEqual(plan['status'], 'NOT_DETECTED')
        self.assertEqual(result['coverage_status'], 'INCOMPLETE')
        self.assertTrue(plan['gaps'])

    def test_unscoped_active_dependency_remains_visible(self):
        args = list(self.args)
        args[0] = {'shared/security.ts': "import {startRegistration} from '@simplewebauthn/browser';"}
        args[6]['runtime'].pop('webauthn'); self.args = tuple(args); self.refresh_source_plans()
        plan = self.compile()
        self.assertEqual(plan['status'], 'BLOCKED'); self.assertTrue(plan['unscoped_declarations'])
        self.assertIn('INTEGRATION_SCOPE_UNRESOLVED', json.dumps(plan)); self.project(plan)
        plan['unscoped_declarations'] = []; plan['gaps'] = []; plan['status'] = 'NOT_DETECTED'; rehash(plan)
        self.rejection(lambda: self.project(plan))

    def test_bool_schema_version_and_malformed_config_lists_fail_cleanly(self):
        for changes in ({'schema_version': True}, {'parts': []}, {'unexpected': CANARY}):
            original = copy.deepcopy(self.args[6]['runtime']['webauthn'])
            self.args[6]['runtime']['webauthn'].update(changes)
            with self.subTest(changes=changes): self.rejection(self.compile)
            self.args[6]['runtime']['webauthn'] = original

    def test_stale_source_policy_binding_is_rejected_by_planner_and_projection(self):
        plan = self.compile()
        self.args[0]['frontend/src/session.ts'] += '\nexport const changed = true;'
        self.rejection(self.compile)
        self.refresh_source_plans()
        self.rejection(lambda: self.project(plan))


if __name__ == '__main__': unittest.main()
