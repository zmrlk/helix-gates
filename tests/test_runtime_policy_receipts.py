"""No-execution policy projections with small synthetic declarations only."""
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
sys.path.insert(0, str(ROOT / 'bin'))
if os.environ.get('HELIX_POLICY_COMPILER_DIR'):
    sys.path.insert(0, os.environ['HELIX_POLICY_COMPILER_DIR'])
import helix_runtime_identity as identity
import helix_runtime_identity_policy as compiler
import helix_runtime_policy_receipts as receipts


def fixture(parts=('frontend',), configured=True, role='reader'):
    client = dict(client_id='synthetic-app', client_type='public', callback_paths=['/auth/callback'],
                  login_path='/login', pkce='S256', role_claim='realm_access.roles', roles=['reader', 'editor'])
    session = dict(path='/api/session', method='GET', http_status=200, anonymous=dict(kind='status', codes=[401]),
                   assertions=[dict(pointer='/user/name', equals_identity='username'),
                               dict(pointer='/user/roles', equals_identity='app_roles', comparison='set_exact')])
    policy = dict(basis='explicit_config', session=session, cells=[dict(id='read-items', identity=dict(role=role),
        request=dict(method='GET', path='/api/items'), anonymous=dict(kind='status', codes=[401]),
        expected=dict(access='allow', http_status=200, json=[dict(pointer='/kind', equals_literal='ASSERTION_VALUE_CANARY')]))])
    config = dict(runtime=dict(keycloak=dict(parts={part: copy.deepcopy(client) for part in parts})))
    if configured:
        config['runtime']['identity_policy'] = dict(schema_version=1, parts={part: copy.deepcopy(policy) for part in parts})
    entries = [dict(path=part) for part in parts]
    sources = {part + '/app.js': '// Synthetic source, never executed.\n' for part in parts}
    identities = identity.identity_plan(sources, entries, config)
    plan = compiler.policy_plan(sources, entries, identities, {}, config)
    return dict(parts=entries, identity_plan=identities, identity_policy_plan=plan, identity_policy_receipts=[])


def rehash(plan):
    plan['plan_id'] = receipts._digest({key: value for key, value in plan.items() if key != 'plan_id'})


class RuntimePolicyReceipts(unittest.TestCase):
    def test_ready_plan_has_only_known_not_run_counts_without_execution(self):
        report = fixture(); before = copy.deepcopy(report)
        result = receipts.project_policy_plan(report)
        self.assertEqual(result['plan_status'], 'PLANNED')
        self.assertEqual(result['execution_status'], 'NOT_RUN')
        self.assertEqual(result['coverage_status'], 'NOT_RUN')
        self.assertEqual(result['counts'], dict(parts=1, required_cells=1, ready_cells=1, blocked_cells=0, not_run=1, executed=0))
        self.assertEqual(result['parts'][0]['cells'][0]['role'], 'reader')
        self.assertEqual(result['parts'][0]['session']['assertion_count'], 2)
        self.assertEqual(report, before)
        result['parts'][0]['gaps'].append({'code': 'changed'})
        self.assertEqual(report, before)

    def test_legacy_unknown_is_not_zero_or_not_run(self):
        result = receipts.project_policy_plan({})
        self.assertEqual(result['plan_status'], 'NOT_RECORDED')
        self.assertEqual(result['execution_status'], 'NOT_RECORDED')
        self.assertEqual(result['coverage_status'], 'NOT_RECORDED')
        self.assertTrue(all(value is None for value in result['counts'].values()))

    def test_missing_policy_and_no_identity_are_distinct(self):
        missing = receipts.project_policy_plan(fixture(configured=False))
        self.assertEqual(missing['plan_status'], 'NOT_CONFIGURED')
        self.assertIn('POLICY_NOT_CONFIGURED', [gap['code'] for gap in missing['parts'][0]['gaps']])
        self.assertEqual(len(missing['parts'][0]['unconfigured_identities']), 4)
        identities = {'schema_version': 1, 'parts': []}
        plan = compiler.policy_plan({}, [{'path': 'app'}], identities, {})
        absent = receipts.project_policy_plan(dict(identity_plan=identities, identity_policy_plan=plan, identity_policy_receipts=[]))
        self.assertEqual(absent['plan_status'], 'NOT_DETECTED')
        self.assertEqual(absent['counts']['required_cells'], 0)

    def test_unknown_role_retains_cell_without_echoing_unknown_name(self):
        report = fixture(role='UNKNOWN_ROLE_CANARY')
        result = receipts.project_policy_plan(report)
        self.assertEqual(result['plan_status'], 'BLOCKED')
        self.assertEqual(result['counts']['blocked_cells'], 1)
        cell = result['parts'][0]['cells'][0]
        self.assertIsNone(cell['identity_id']); self.assertIsNone(cell['role'])
        self.assertEqual(cell['execution_status'], 'NOT_RUN')
        self.assertNotIn('UNKNOWN_ROLE_CANARY', json.dumps(report))
        self.assertNotIn('UNKNOWN_ROLE_CANARY', json.dumps(result))

    def test_public_raw_plan_and_projection_never_include_literal_assertion(self):
        report = fixture(); result = receipts.project_policy_plan(report)
        self.assertNotIn('ASSERTION_VALUE_CANARY', json.dumps(report))
        self.assertNotIn('ASSERTION_VALUE_CANARY', json.dumps(result))
        self.assertNotIn('value_hash', json.dumps(result))
        report['private_config'] = {'secret': 'PRIVATE_CONFIG_CANARY'}
        self.assertNotIn('PRIVATE_CONFIG_CANARY', json.dumps(receipts.project_policy_plan(report)))

    def test_any_execution_receipt_is_unsupported_without_credit(self):
        for value in ([{'status': 'PASS', 'secret': 'RECEIPT_CANARY'}], [{}], {}, None):
            report = fixture(); report['identity_policy_receipts'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'unsupported') as error:
                receipts.project_policy_plan(report)
            self.assertNotIn('RECEIPT_CANARY', str(error.exception))

    def test_half_metadata_and_wrong_identity_snapshot_are_rejected(self):
        report = fixture()
        for key in ('identity_policy_plan', 'identity_policy_receipts'):
            value = copy.deepcopy(report); value.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError): receipts.project_policy_plan(value)
        report['identity_plan']['status'] = 'changed'
        with self.assertRaises(ValueError): receipts.project_policy_plan(report)

    def test_rehashed_extra_fields_and_execution_claim_cannot_enter_projection(self):
        mutations = [lambda p: p.update(secret='PRIVATE_CANARY'),
                     lambda p: p['execution'].update(application=True),
                     lambda p: p['execution'].update(commands=True),
                     lambda p: p['parts'][0]['cells'][0]['expected']['json'][0].update(equals_literal='PRIVATE_CANARY'),
                     lambda p: p['parts'][0].update(status='PASS')]
        for mutate in mutations:
            report = fixture(); plan = report['identity_policy_plan']; mutate(plan); rehash(plan)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError) as error: receipts.project_policy_plan(report)
            self.assertNotIn('PRIVATE_CANARY', str(error.exception))

    def test_cell_ids_roles_paths_and_pointers_have_semantic_binding(self):
        mutations = [lambda c: c.update(id='cell-' + 'f' * 16), lambda c: c.update(role='editor'),
                     lambda c: c.update(identity_id='role-' + 'f' * 12),
                     lambda c: c['request'].update(path='https://outside.invalid/private'),
                     lambda c: c.update(config_pointer='/runtime/identity_policy/parts/PRIVATE_CANARY'),
                     lambda c: c['expected']['json'][0].update(pointer='/__proto__/secret')]
        for mutate in mutations:
            report = fixture(); plan = report['identity_policy_plan']; mutate(plan['parts'][0]['cells'][0]); rehash(plan)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): receipts.project_policy_plan(report)

    def test_duplicate_cell_or_part_cannot_increase_coverage(self):
        for cells in (True, False):
            report = fixture(); plan = report['identity_policy_plan']
            rows = plan['parts'][0]['cells'] if cells else plan['parts']; rows.append(copy.deepcopy(rows[0])); rehash(plan)
            with self.subTest(cells=cells), self.assertRaises(ValueError): receipts.project_policy_plan(report)

    def test_rehashed_plan_must_bind_each_role_part_and_remaining_identity(self):
        def foreign_role(plan):
            cell = plan['parts'][0]['cells'][0]
            cell.update(role='owner', identity_id='role-' + receipts._digest('owner')[:12],
                        identity_selector={'role_sha256': receipts._digest('owner')})
            cell['id'] = compiler.cell_id('frontend', cell)
        mutations = [foreign_role, lambda p: p['parts'][0].update(identity_plan_id='e' * 64),
                     lambda p: p['parts'][0]['unconfigured_identities'].pop()]
        for mutate in mutations:
            report = fixture(); plan = report['identity_policy_plan']; mutate(plan); rehash(plan)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): receipts.project_policy_plan(report)
        report = fixture(); report.pop('identity_plan')
        with self.assertRaises(ValueError): receipts.project_policy_plan(report)

    def test_removing_entire_part_cannot_turn_declared_identity_into_not_detected(self):
        report = fixture(); plan = report['identity_policy_plan']
        plan.update(parts=[], status='NOT_DETECTED'); rehash(plan)
        with self.assertRaises(ValueError): receipts.project_policy_plan(report)

    def test_conflicting_cells_for_one_role_and_exact_request_are_rejected(self):
        report = fixture(); plan = report['identity_policy_plan']; part = plan['parts'][0]
        cell = copy.deepcopy(part['cells'][0])
        cell.update(config_id='deny-items', config_pointer=cell['config_pointer'].rsplit('/', 1)[0] + '/1',
                    expected=dict(access='deny', denial=dict(kind='status', codes=[403])))
        cell['id'] = compiler.cell_id('frontend', cell)
        part['cells'].append(cell); rehash(plan)
        with self.assertRaises(ValueError): receipts.project_policy_plan(report)

    def test_monorepo_same_route_is_not_merged_and_selection_is_exact(self):
        report = fixture(parts=('frontend', 'portal')); result = receipts.project_policy_plan(report)
        self.assertEqual(result['counts']['required_cells'], 2)
        self.assertEqual(len({part['cells'][0]['id'] for part in result['parts']}), 2)
        selected = receipts.project_policy_plan(report, ['portal'])
        self.assertEqual([part['part'] for part in selected['parts']], ['portal'])
        self.assertEqual(selected['counts']['required_cells'], 1)
        for parts in (['missing'], ['portal', 'portal'], ['../portal'], 'portal'):
            with self.subTest(parts=parts), self.assertRaises(ValueError): receipts.project_policy_plan(report, parts)

    def test_projection_performs_no_io_network_process_or_entropy(self):
        report = fixture()
        with patch.object(builtins, 'open', side_effect=AssertionError('I/O forbidden')), \
             patch.object(Path, 'read_text', side_effect=AssertionError('I/O forbidden')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')), \
             patch.object(os, 'urandom', side_effect=AssertionError('entropy forbidden')):
            result = receipts.project_policy_plan(report)
        self.assertEqual(result['counts']['executed'], 0)


if __name__ == '__main__':
    unittest.main()
