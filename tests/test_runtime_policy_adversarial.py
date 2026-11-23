"""Independent policy compiler/projection regressions; synthetic data, no runtime."""
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

ROOT = Path(os.environ.get('HELIX_SOURCE_ROOT', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT / 'bin'))
if os.environ.get('HELIX_POLICY_MODULE_DIR'):
    sys.path.insert(0, os.environ['HELIX_POLICY_MODULE_DIR'])
import helix_runtime_identity as identity
import helix_runtime_identity_policy as policy
import helix_runtime_policy_receipts as receipts


CANARY = 'PRIVATE_ASSERTION_LITERAL_f92b7161'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':')).encode()).hexdigest()


def rehash(plan):
    plan['plan_id'] = digest({key: value for key, value in plan.items() if key != 'plan_id'})
    return plan


def fixture():
    parts = [{'path': 'frontend', 'name': 'Synthetic application'}]
    sources = {'frontend/src/server.ts': 'export function session() { return null; }'}
    values = dict(client_id='fixture-app', client_type='public', callback_paths=['/auth/callback'],
                  pkce='S256', role_claim='realm_access.roles', roles=['reader', 'editor'], login_path='/login')
    identities = identity.identity_plan(sources, parts, {'runtime': {'keycloak': {'parts': {'frontend': values}}}})
    inventory = {'plan_id': 'a' * 64, 'integrations': [{'id': 'keycloak:0123456789ab',
                   'provider': 'keycloak', 'parts': ['frontend'], 'area': 'active'}]}
    session = {'path': '/api/session', 'method': 'GET', 'http_status': 200,
               'anonymous': {'kind': 'status', 'codes': [401]},
               'assertions': [{'pointer': '/user/username', 'equals_identity': 'username'},
                              {'pointer': '/user/roles', 'equals_identity': 'app_roles', 'comparison': 'set_exact'}]}
    cell = {'id': 'reader-items', 'identity': {'role': 'reader'},
            'request': {'method': 'GET', 'path': '/api/items'},
            'anonymous': {'kind': 'status', 'codes': [401]},
            'expected': {'access': 'allow', 'http_status': 200,
                         'json': [{'pointer': '/kind', 'equals_literal': CANARY}]}}
    config = {'runtime': {'identity_policy': {'schema_version': 1, 'parts': {
        'frontend': {'basis': 'explicit_config', 'session': session, 'cells': [cell]}}}}}
    return sources, parts, identities, inventory, config


class RuntimePolicyAdversarial(unittest.TestCase):
    def setUp(self):
        self.args = fixture()

    @property
    def config(self):
        return self.args[4]

    @property
    def declaration(self):
        return self.config['runtime']['identity_policy']['parts']['frontend']

    def compile(self):
        return policy.policy_plan(*self.args)

    def project(self, plan=None, **extra):
        report = {'identity_plan': self.args[2],
                  'identity_policy_plan': self.compile() if plan is None else plan,
                  'identity_policy_receipts': []}
        report.update(extra)
        return receipts.project_policy_plan(report)

    def rejection(self, callback):
        with self.assertRaises(ValueError) as caught:
            callback()
        self.assertNotIn(CANARY, str(caught.exception))

    def test_declared_plan_is_not_execution_or_session_credit(self):
        plan = self.compile(); result = self.project(plan)
        self.assertEqual(plan['status'], 'PLANNED')
        self.assertEqual(plan['execution'], {'files_opened': 0, 'commands': 0, 'models': 0,
                                            'network': 0, 'application': False})
        self.assertEqual(result['plan_status'], 'PLANNED')
        self.assertEqual(result['execution_status'], 'NOT_RUN')
        self.assertEqual(result['coverage_status'], 'NOT_RUN')
        self.assertNotIn(CANARY, json.dumps((plan, result)))

    def test_same_get_path_for_two_roles_keeps_two_distinct_cells(self):
        second = copy.deepcopy(self.declaration['cells'][0])
        second.update(id='editor-items', identity={'role': 'editor'},
                      expected={'access': 'deny', 'denial': {'kind': 'status', 'codes': [403]}})
        self.declaration['cells'].append(second)
        plan = self.compile(); cells = plan['parts'][0]['cells']
        self.assertEqual(len(cells), 2)
        self.assertEqual(cells[0]['request'], cells[1]['request'])
        self.assertNotEqual(cells[0]['identity_id'], cells[1]['identity_id'])
        self.assertNotEqual(cells[0]['id'], cells[1]['id'])
        self.assertEqual({row['expected']['access'] for row in cells}, {'allow', 'deny'})
        result = self.project(plan)
        self.assertEqual(len(result['parts'][0]['cells']), 2)
        self.assertEqual(result['coverage_status'], 'NOT_RUN')

    def test_literal_and_anonymous_declaration_changes_change_plan_identity(self):
        first = self.compile()
        self.declaration['cells'][0]['expected']['json'][0]['equals_literal'] = CANARY + '-changed'
        second = self.compile()
        self.assertNotEqual(first['plan_id'], second['plan_id'])
        self.assertNotEqual(first['parts'][0]['policy_hash'], second['parts'][0]['policy_hash'])
        self.assertNotEqual(first['parts'][0]['cells'][0]['id'], second['parts'][0]['cells'][0]['id'])
        self.assertNotIn(CANARY, json.dumps(second))
        self.declaration['cells'][0]['anonymous']['codes'] = [401, 403]
        third = self.compile()
        self.assertNotEqual(second['plan_id'], third['plan_id'])

    def test_source_and_identity_declarations_bind_the_plan(self):
        first = self.compile()
        self.args[0]['frontend/src/server.ts'] += '\nexport const revision = 2;'
        second = self.compile()
        self.assertNotEqual(first['source_digest'], second['source_digest'])
        self.assertNotEqual(first['plan_id'], second['plan_id'])
        client = copy.deepcopy(self.args[2]['parts'][0]['client']); client['login_path'] = '/account/login'
        changed = identity.identity_plan(self.args[0], self.args[1],
            {'runtime': {'keycloak': {'parts': {'frontend': client}}}})
        args = list(self.args); args[2] = changed
        third = policy.policy_plan(*args)
        self.assertNotEqual(second['identity_plan_digest'], third['identity_plan_digest'])
        self.assertNotEqual(second['plan_id'], third['plan_id'])

    def test_env_values_are_not_copied_or_bound_as_code(self):
        first = self.compile()
        self.args[0]['frontend/.env'] = 'PRIVATE_VALUE=' + CANARY
        self.args[0]['frontend/.env.production'] = 'PRIVATE_VALUE=' + CANARY
        second = self.compile()
        self.assertEqual(first['source_digest'], second['source_digest'])
        self.assertNotIn(CANARY, json.dumps(second))

    def test_compiler_and_projection_are_pure_and_do_not_mutate_inputs(self):
        before = copy.deepcopy(self.args)
        with patch.object(builtins, 'open', side_effect=AssertionError('unexpected file IO')), \
             patch.object(Path, 'read_text', side_effect=AssertionError('unexpected file IO')), \
             patch.object(socket, 'socket', side_effect=AssertionError('unexpected network')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('unexpected process')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected process')), \
             patch.object(os, 'urandom', side_effect=AssertionError('unexpected entropy')):
            plan = self.compile(); snapshot = copy.deepcopy(plan); projected = self.project(plan)
        self.assertEqual(before, self.args)
        self.assertEqual(snapshot, plan)
        projected['parts'].clear()
        self.assertEqual(snapshot, plan)

    def test_missing_policy_preserves_not_configured_and_all_uncovered_identities(self):
        self.config['runtime'].pop('identity_policy')
        plan = self.compile()
        self.assertEqual(plan['status'], 'NOT_CONFIGURED')
        self.assertEqual(plan['parts'][0]['cells'], [])
        self.assertEqual(len(plan['parts'][0]['unconfigured_identities']),
                         len(self.args[2]['parts'][0]['identities']))
        self.assertIn('POLICY_NOT_CONFIGURED', [gap['code'] for gap in plan['parts'][0]['gaps']])
        self.assertEqual(self.project(plan)['coverage_status'], 'NOT_RUN')

    def test_no_identity_declaration_and_no_policy_is_not_detected(self):
        args = list(self.args)
        args[2] = identity.identity_plan(args[0], args[1], {})
        args[3] = {'integrations': []}
        args[4] = {}
        self.args = tuple(args)
        plan = self.compile()
        self.assertEqual(plan['status'], 'NOT_DETECTED')
        self.assertEqual(plan['parts'], [])
        result = self.project(plan)
        self.assertEqual(result['plan_status'], 'NOT_DETECTED')
        self.assertEqual(result['counts']['required_cells'], 0)
        self.assertEqual(result['counts']['executed'], 0)

    def test_monorepo_identical_get_cells_remain_scoped_and_missing_sibling_is_visible(self):
        args = list(self.args); args[1] = args[1] + [{'path': 'portal', 'name': 'Sibling application'}]
        client = copy.deepcopy(args[2]['parts'][0]['client'])
        args[2] = identity.identity_plan(args[0], args[1], {'runtime': {'keycloak': {'parts': {
            'frontend': client, 'portal': copy.deepcopy(client)}}}})
        self.args = tuple(args)
        first = self.compile(); by_part = {row['part']: row for row in first['parts']}
        self.assertEqual(by_part['portal']['status'], 'NOT_CONFIGURED')
        self.assertEqual(by_part['portal']['cells'], [])
        self.config['runtime']['identity_policy']['parts']['portal'] = copy.deepcopy(self.declaration)
        second = self.compile(); by_part = {row['part']: row for row in second['parts']}
        left = by_part['frontend']['cells'][0]; right = by_part['portal']['cells'][0]
        self.assertEqual(left['request'], right['request'])
        self.assertNotEqual(left['id'], right['id'])
        projected = self.project(second)
        self.assertEqual({row['part'] for row in projected['parts']}, {'frontend', 'portal'})
        self.assertEqual(projected['coverage_status'], 'NOT_RUN')

    def test_unknown_role_is_retained_blocked_and_not_published_as_raw_text(self):
        self.declaration['cells'][0]['identity']['role'] = CANARY
        plan = self.compile(); cell = plan['parts'][0]['cells'][0]
        self.assertEqual(plan['status'], 'BLOCKED')
        self.assertEqual(cell['status'], 'BLOCKED')
        self.assertIsNone(cell['identity_id'])
        self.assertIn('ROLE_NOT_DECLARED', [gap['code'] for gap in cell['gaps']])
        self.assertNotIn(CANARY, json.dumps((plan, self.project(plan))))

    def test_missing_identity_or_roles_assertion_blocks_without_guessing(self):
        for remove in ('username', 'app_roles'):
            self.args = fixture()
            self.declaration['session']['assertions'] = [row for row in self.declaration['session']['assertions']
                if row['equals_identity'] != remove]
            with self.subTest(remove=remove):
                plan = self.compile()
                self.assertEqual(plan['status'], 'BLOCKED')
                self.assertEqual(self.project(plan)['coverage_status'], 'NOT_RUN')

    def test_duplicate_user_ids_and_duplicate_semantic_cells_are_rejected(self):
        for semantic in (True, False):
            self.args = fixture(); second = copy.deepcopy(self.declaration['cells'][0])
            if semantic: second['id'] = 'different-user-label'
            else: second['identity']['role'] = 'editor'
            self.declaration['cells'].append(second)
            with self.subTest(semantic=semantic): self.rejection(self.compile)

    def test_noncanonical_or_nonlocal_paths_cannot_be_compiled(self):
        paths = ('https://outside.invalid/items', '//outside.invalid/items', '/items?token=' + CANARY,
                 '/items#private', '/items/../admin', '/./items', '/items//admin', '/items\\admin',
                 '/items/%2e%2e/admin', '/items/%2Fadmin', '/items/*', '/items\nadmin', '', None, 17)
        for location in ('session', 'request'):
            for value in paths:
                self.args = fixture()
                node = self.declaration['session'] if location == 'session' else self.declaration['cells'][0]['request']
                node['path'] = value
                with self.subTest(location=location, value=value): self.rejection(self.compile)

    def test_only_exact_get_status_and_denial_contracts_are_accepted(self):
        changes = [('method', 'POST'), ('method', 'get'), ('method', None), ('http_status', True),
                   ('http_status', 200.0), ('http_status', '200'), ('http_status', 204)]
        for key, value in changes:
            self.args = fixture(); self.declaration['session'][key] = value
            with self.subTest(key=key, value=value): self.rejection(self.compile)
        for codes in ([], [True], [401.0], ['401'], [200], [302], [404], [500], [401, 401], '401'):
            self.args = fixture(); self.declaration['cells'][0]['anonymous']['codes'] = codes
            with self.subTest(codes=codes): self.rejection(self.compile)

    def test_wrong_shapes_unknown_fields_and_negative_selector_are_not_silently_ignored(self):
        mutations = [lambda block: block.update(schema_version=True), lambda block: block.update(schema_version='1'),
                     lambda block: block.update(parts=[]), lambda block: block.update(secret=CANARY),
                     lambda block: block['parts']['frontend'].update(cells={}),
                     lambda block: block['parts']['frontend'].update(session=[]),
                     lambda block: block['parts']['frontend']['cells'][0]['identity'].update(role=['reader']),
                     lambda block: block['parts']['frontend']['cells'][0].update(identity={'variant': 'no-app-role'}),
                     lambda block: block['parts']['frontend']['cells'][0]['request'].update(headers={'Authorization': CANARY}),
                     lambda block: block['parts']['frontend']['cells'][0]['expected'].update(ui={'text': CANARY})]
        for index, mutate in enumerate(mutations):
            self.args = fixture(); mutate(self.config['runtime']['identity_policy'])
            with self.subTest(index=index): self.rejection(self.compile)

    def test_identity_declaration_schema_version_cannot_be_boolean(self):
        self.args[2]['schema_version'] = True
        self.rejection(self.compile)

    def test_json_pointer_is_not_jsonpath_wildcard_or_prototype_access(self):
        for pointer in ('$.user.name', '/user/*', '/__proto__/x', '/constructor/prototype', '/x~2y', None):
            self.args = fixture(); self.declaration['session']['assertions'][0]['pointer'] = pointer
            with self.subTest(pointer=pointer): self.rejection(self.compile)

    def test_assertion_literals_never_enter_plan_projection_or_error_message(self):
        plan = self.compile(); encoded = json.dumps((plan, self.project(plan)))
        self.assertNotIn(CANARY, encoded)
        expected = plan['parts'][0]['cells'][0]['expected']['json'][0]
        self.assertEqual(expected['value_hash'], digest(CANARY))
        self.assertNotIn('equals_literal', expected)
        self.declaration['cells'][0]['expected']['json'][0]['secret'] = CANARY
        self.rejection(self.compile)

    def test_legacy_and_explicit_empty_receipts_do_not_claim_execution(self):
        self.assertEqual(receipts.project_policy_plan({})['plan_status'], 'NOT_RECORDED')
        for value in ([{'status': 'PASS', 'secret': CANARY}], {}, None, 'PASS'):
            with self.subTest(value=type(value).__name__):
                self.rejection(lambda: self.project(identity_policy_receipts=value))

    def test_stale_hash_or_rehashed_execution_claims_are_rejected(self):
        plan = self.compile(); plan['plan_id'] = 'f' * 64
        self.rejection(lambda: self.project(plan))
        for field, value in (('commands', 1), ('application', True), ('models', True), ('network', 0.0)):
            plan = self.compile(); plan['execution'][field] = value; rehash(plan)
            with self.subTest(field=field): self.rejection(lambda: self.project(plan))

    def test_rehashed_public_plan_cannot_smuggle_literals_or_unsafe_session_path(self):
        mutations = [lambda p: p.update(secret=CANARY),
                     lambda p: p['parts'][0]['session'].update(path='/api/session?token=' + CANARY),
                     lambda p: p['parts'][0]['cells'][0]['expected']['json'][0].update(equals_literal=CANARY),
                     lambda p: p['parts'][0]['cells'].append(copy.deepcopy(p['parts'][0]['cells'][0])),
                     lambda p: p['parts'][0].update(status='PASS')]
        for index, mutate in enumerate(mutations):
            plan = self.compile(); mutate(plan); rehash(plan)
            with self.subTest(index=index): self.rejection(lambda: self.project(plan))

    def test_rehashed_plan_cannot_change_identity_binding_or_erase_undeclared_coverage(self):
        for mutation in ('part_hash', 'missing_identities'):
            plan = self.compile()
            if mutation == 'part_hash': plan['parts'][0]['identity_plan_id'] = 'f' * 64
            else: plan['parts'][0]['unconfigured_identities'] = []
            rehash(plan)
            with self.subTest(mutation=mutation): self.rejection(lambda: self.project(plan))
        plan = self.compile()
        self.rejection(lambda: receipts.project_policy_plan(
            {'identity_policy_plan': plan, 'identity_policy_receipts': []}))

    def test_rehashed_plan_cannot_hide_detected_part_as_not_detected(self):
        plan = self.compile(); plan['parts'] = []; plan['status'] = 'NOT_DETECTED'; rehash(plan)
        self.rejection(lambda: self.project(plan, parts=self.args[1]))


if __name__ == '__main__': unittest.main()
