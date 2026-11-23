"""Pure synthetic policy input and execution evidence, never real services."""
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
import helix_runtime_identity_policy as compiler
import helix_runtime_identity_policy_run as policy
import helix_runtime_login as login
import test_runtime_login as login_fixture
import test_runtime_identity_policy as policy_fixture
from test_runtime_identity_projection import public_fixture


def fixture_input():
    private = login_fixture.RuntimeLoginInput(); private.setUp()
    rules = policy_fixture.RuntimeIdentityPolicy(); rules.setUp()
    report = public_fixture()
    plan = compiler.policy_plan(rules.sources, rules.parts, report['identity_plan'], report['integrations'], rules.config)
    built = policy.build_policy_input(plan, 'frontend', report['identity_plan'], rules.raw, private.build(),
                                      policy_attempt_id='policy-' + 'c' * 32)
    report.update(identity_policy_plan=plan, identity_policy_receipts=[], identity_policy_executions=[])
    return report, built


def fixture_report(state='pass'):
    """Return only a runtime-shaped report; root owner tests share this fixture."""
    report, private = fixture_input(); part = private['public_plan_part']
    identity_id = part['cells'][0]['identity_id']
    def probe(status='PASS', code=401, reason='EXPECTED_DENIAL', **extra):
        return dict(status=status, http_status=code, reason_code=reason, **extra)
    row = dict(identity_id=identity_id, anonymous_session=probe(),
               session=probe(code=200, reason='SESSION_MATCHED', identity_matched=True, roles_matched=True), cleanup='closed')
    cell = dict(cell_id=part['cells'][0]['id'], identity_id=identity_id, anonymous=probe(),
                access=probe(code=200, reason='ACCESS_MATCHED', assertions_matched=True), result='PASS')
    if state == 'partial_failure':
        row['session'].update(status='FAIL', reason_code='SESSION_ROLES_MISMATCH', roles_matched=False)
        cell['access'].update(status='BLOCKED', http_status=None, reason_code='SESSION_NOT_CONFIRMED', assertions_matched=None)
        cell['result'] = 'FAIL'
    elif state == 'pending':
        report['identity_forms'] = []
        for target in (row['anonymous_session'], row['session'], cell['anonymous'], cell['access']):
            target.update(status='NOT_RUN', http_status=None, reason_code='NOT_ATTEMPTED')
            for key in set(target) - {'status', 'http_status', 'reason_code'}: target[key] = None
        row['cleanup'] = 'not_needed'; cell['result'] = 'NOT_RUN'
    elif state != 'pass':
        raise ValueError('unsupported fixture state')
    report['identity_policy_executions'] = [dict(schema_version=1, type='identity-policy-suite',
        binding=private['binding'], identities=[row], cells=[cell])]
    return report


class RuntimeIdentityPolicyRun(unittest.TestCase):
    def test_private_rebind_preserves_source_and_separates_public_literals(self):
        report, value = fixture_input(); before = copy.deepcopy((report, value))
        self.assertEqual(value['policy']['cells'][0]['expected']['json'][0]['equals_literal'], 'PRIVATE_CANARY_ASSERTION')
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', json.dumps(report))
        self.assertNotIn('client_secret', json.dumps(value))
        self.assertEqual(value['binding']['form_attempt_id'], value['form_input']['binding']['attempt_id'])
        self.assertEqual(value['limits']['accepted_json_bytes'], 1048576)
        result = policy.build_policy_input(report['identity_policy_plan'], 'frontend', report['identity_plan'],
            value['policy'], value['form_input'], policy_attempt_id=value['binding']['policy_attempt_id'])
        self.assertEqual(result, value); result['policy']['cells'][0]['expected']['json'][0]['equals_literal'] = 'changed'
        self.assertEqual((report, value), before)

    def test_builder_and_projector_are_pure_no_io_clock_environment_or_entropy(self):
        report, value = fixture_input()
        with patch.object(builtins, 'open', side_effect=AssertionError('file')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(os, 'urandom', side_effect=AssertionError('entropy')):
            built = policy.build_policy_input(report['identity_policy_plan'], 'frontend', report['identity_plan'], value['policy'],
                value['form_input'], policy_attempt_id=value['binding']['policy_attempt_id'])
            projected = policy.project_policy_execution(report)
        self.assertEqual(built, value); self.assertEqual(projected['execution_status'], 'NOT_RUN')

    def test_changed_private_policy_or_form_cannot_reuse_public_plan(self):
        for mutation in (lambda v: v['policy']['cells'][0]['expected']['json'][0].update(equals_literal='changed'),
                         lambda v: v['form_input'].update(client_id='another-client'),
                         lambda v: v['form_input']['identities'][0].update(username='another-user'),
                         lambda v: v['form_input']['identities'][0].update(email_verified=False),
                         lambda v: v['form_input'].update(issuer='https://outside.invalid:44200/realms/helix-fake'),
                         lambda v: v['form_input']['binding'].update(identity_plan_id='f' * 64),
                         lambda v: v['form_input'].update(operation_timeout_ms=True)):
            report, value = fixture_input(); mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                policy.build_policy_input(report['identity_policy_plan'], 'frontend', report['identity_plan'], value['policy'],
                    value['form_input'], policy_attempt_id='policy-' + 'c' * 32)

    def test_attempt_ids_and_private_extra_fields_fail_without_values(self):
        for attempt in (None, True, ['policy-' + 'a' * 32], 'policy-old', 'SECRET_CANARY'):
            report, value = fixture_input()
            with self.subTest(attempt=attempt), self.assertRaises(ValueError) as error:
                policy.build_policy_input(report['identity_policy_plan'], 'frontend', report['identity_plan'], value['policy'],
                    value['form_input'], policy_attempt_id=attempt)
            self.assertNotIn('SECRET_CANARY', str(error.exception))

    def test_complete_selected_matrix_separate_from_form_and_unconfigured_identities(self):
        report = fixture_report(); before = copy.deepcopy(report)
        result = policy.project_policy_execution(report)
        self.assertEqual((result['execution_status'], result['coverage_status'], result['outcome']), ('COMPLETE', 'RECORDED', 'PASS'))
        self.assertEqual(result['counts'], dict(required_sessions=1, completed_sessions=1, required_cells=1,
            completed_cells=1, passed_cells=1, failed_cells=0, blocked_cells=0, not_run_cells=0))
        part = result['parts'][0]
        self.assertEqual(part['config_pointer'], '/runtime/identity_policy/parts/frontend')
        self.assertEqual(part['cells'][0]['plan_status'], 'READY')
        self.assertIn('unverified-email', part['unconfigured_identities'])
        self.assertEqual(login.project_identity(report)['session_coverage'], 'NOT_RUN')
        assessment = policy.derive_identity_assessment(report)
        self.assertEqual(assessment['status'], 'PASS'); self.assertEqual(assessment['coverage_status'], 'RECORDED')
        self.assertTrue(assessment['unconfigured_identities']); self.assertEqual(report, before)
        encoded = json.dumps(result)
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', encoded); self.assertNotIn('synthetic-password', encoded)

    def test_failed_expectation_and_incomplete_remaining_coverage_both_survive(self):
        result = policy.project_policy_execution(fixture_report('partial_failure'))
        self.assertEqual((result['execution_status'], result['coverage_status'], result['outcome']), ('INCOMPLETE', 'INCOMPLETE', 'FAIL'))
        self.assertEqual(result['counts']['failed_cells'], 1); self.assertEqual(result['counts']['completed_cells'], 0)
        self.assertEqual(result['parts'][0]['cells'][0]['reason_code'], 'SESSION_ROLES_MISMATCH')
        assessment = policy.derive_identity_assessment(fixture_report('partial_failure'))
        self.assertEqual(assessment['status'], 'INCOMPLETE'); self.assertEqual(assessment['outcome'], 'FAIL')

    def test_completed_access_failure_is_recorded_fail(self):
        report = fixture_report(); cell = report['identity_policy_executions'][0]['cells'][0]
        cell['access'].update(status='FAIL', reason_code='ASSERTION_MISMATCH', assertions_matched=False); cell['result'] = 'FAIL'
        result = policy.project_policy_execution(report)
        self.assertEqual(result['execution_status'], 'COMPLETE'); self.assertEqual(result['outcome'], 'FAIL')
        self.assertEqual(policy.derive_identity_assessment(report)['status'], 'FAIL')

    def test_pending_and_legacy_unknown_are_not_conflated_with_zero(self):
        pending = policy.project_policy_execution(fixture_report('pending'))
        self.assertEqual(pending['execution_status'], 'NOT_RUN'); self.assertEqual(pending['counts']['completed_cells'], 0)
        self.assertEqual(pending['counts']['not_run_cells'], 1)
        legacy = policy.project_policy_execution({'parts': []})
        self.assertEqual(legacy['coverage_status'], 'NOT_RECORDED'); self.assertTrue(all(value is None for value in legacy['counts'].values()))

    def test_unknown_role_keeps_planning_blocker_and_unexecuted_count(self):
        rules = policy_fixture.RuntimeIdentityPolicy(); rules.setUp(); rules.raw['cells'][0]['identity']['role'] = 'unknown'
        report = dict(parts=rules.parts, identity_plan=rules.identities, identity_forms=[], identity_policy_plan=rules.compile(), identity_policy_receipts=[])
        result = policy.project_policy_execution(report)
        self.assertEqual(result['execution_status'], 'NOT_RUN'); self.assertEqual(result['counts']['blocked_cells'], 1)
        self.assertEqual(result['counts']['completed_cells'], 0); self.assertEqual(result['parts'][0]['cells'][0]['plan_status'], 'BLOCKED')

    def test_missing_policy_and_no_identity_assessments(self):
        rules = policy_fixture.RuntimeIdentityPolicy(); rules.setUp(); rules.config = {}
        report = dict(parts=rules.parts, identity_plan=rules.identities, identity_forms=[], identity_policy_plan=rules.compile(), identity_policy_receipts=[])
        self.assertEqual(policy.derive_identity_assessment(report)['status'], 'INCOMPLETE')
        report = dict(parts=[], identity_plan={'schema_version': 1, 'parts': []}, identity_forms=[])
        self.assertEqual(policy.derive_identity_assessment(report)['status'], 'NOT_DETECTED')

    def test_receipts_require_exact_plan_run_part_form_attempt_and_membership(self):
        for field, value in (('run_id', 'runtime-old'), ('policy_plan_id', 'f' * 64), ('policy_hash', 'e' * 64),
                             ('identity_plan_id', 'd' * 64), ('integration_id', 'keycloak:ffffffffffff'),
                             ('form_attempt_id', 'login-' + 'e' * 32), ('part', 'other')):
            report = fixture_report(); report['identity_policy_executions'][0]['binding'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): policy.project_policy_execution(report)
        for key in ('identities', 'cells'):
            report = fixture_report(); report['identity_policy_executions'][0][key].clear()
            with self.subTest(key=key), self.assertRaises(ValueError): policy.project_policy_execution(report)
        report = fixture_report(); report['identity_policy_executions'] *= 2
        with self.assertRaises(ValueError): policy.project_policy_execution(report)

    def test_forged_pass_cannot_hide_prerequisite_mismatch_or_unknown_cleanup(self):
        mutations = [lambda s: s['identities'][0]['session'].update(roles_matched=False),
            lambda s: s['identities'][0].update(cleanup='unknown'),
            lambda s: s['cells'][0]['anonymous'].update(http_status=302),
            lambda s: s['cells'][0]['access'].update(assertions_matched=None),
            lambda s: s['cells'][0]['access'].update(http_status=True),
            lambda s: s['identities'][0]['anonymous_session'].update(reason_code='SESSION_MATCHED')]
        for mutate in mutations:
            report = fixture_report(); mutate(report['identity_policy_executions'][0])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError): policy.project_policy_execution(report)
        report = fixture_report(); report['identity_forms'] = []
        with self.assertRaises(ValueError): policy.project_policy_execution(report)

    def test_public_shapes_reject_secret_values_arbitrary_reasons_and_counts(self):
        for mutate in (lambda s: s.update(body='PRIVATE_CANARY'),
                       lambda s: s['identities'][0]['session'].update(reason_code='PRIVATE_CANARY'),
                       lambda s: s['cells'][0]['access'].update(assertions_matched='PRIVATE_CANARY'),
                       lambda s: s.update(counts={'passed': 10})):
            report = fixture_report(); mutate(report['identity_policy_executions'][0])
            with self.assertRaises(ValueError) as error: policy.project_policy_execution(report)
            self.assertNotIn('PRIVATE_CANARY', str(error.exception))

    def test_partial_cleanup_retains_observations_without_completed_credit(self):
        report = fixture_report(); suite = report['identity_policy_executions'][0]
        suite['identities'][0]['cleanup'] = 'unknown'; suite['cells'][0]['result'] = 'BLOCKED'
        result = policy.project_policy_execution(report)
        self.assertEqual(result['counts']['completed_cells'], 0); self.assertEqual(result['coverage_status'], 'INCOMPLETE')
        self.assertEqual(result['parts'][0]['cells'][0]['reason_code'], 'CLEANUP_FAILED')

    def test_current_form_attempt_binds_even_unfinished_policy_observations(self):
        report = fixture_report('pending')
        report['identity_forms'] = public_fixture()['identity_forms']
        report['identity_policy_executions'][0]['binding']['form_attempt_id'] = 'login-' + 'e' * 32
        with self.assertRaises(ValueError): policy.project_policy_execution(report)

    def test_deny_pass_requires_exact_declared_status_and_no_json_assertion_credit(self):
        report, private = fixture_input()
        private['policy']['cells'][0]['expected'] = dict(access='deny', denial={'kind': 'status', 'codes': [403]})
        report['identity_policy_plan'] = compiler.policy_plan({}, [{'path': 'frontend'}], report['identity_plan'], report['integrations'],
            {'runtime': {'identity_policy': {'schema_version': 1, 'parts': {'frontend': private['policy']}}}})
        built = policy.build_policy_input(report['identity_policy_plan'], 'frontend', report['identity_plan'], private['policy'],
            private['form_input'], policy_attempt_id='policy-' + 'd' * 32)
        suite = fixture_report()['identity_policy_executions'][0]
        suite['binding'] = built['binding']; suite['cells'][0]['cell_id'] = built['public_plan_part']['cells'][0]['id']
        suite['cells'][0]['access'].update(http_status=403, reason_code='EXPECTED_DENIAL', assertions_matched=None)
        report['identity_policy_executions'] = [suite]
        self.assertEqual(policy.project_policy_execution(report)['outcome'], 'PASS')
        for changes in ({'http_status': 401}, {'assertions_matched': True}):
            mutated = copy.deepcopy(report); mutated['identity_policy_executions'][0]['cells'][0]['access'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError): policy.project_policy_execution(mutated)

    def test_valid_python_private_input_is_accepted_by_javascript_validator(self):
        _, private = fixture_input()
        script = "const fs=require('node:fs'),h=require('./bin/runtime-identity-policy.cjs'); const x=JSON.parse(fs.readFileSync(0,'utf8')); h.validatePolicyInput(x); process.stdout.write('VALID');"
        result = subprocess.run(['node', '-e', script], cwd=ROOT, input=json.dumps(private), text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stdout, 'VALID')

    def test_cross_language_unicode_safe_integer_and_changed_private_hash(self):
        report, private = fixture_input()
        script = "const fs=require('node:fs'),h=require('./bin/runtime-identity-policy.cjs');try{h.validatePolicyInput(JSON.parse(fs.readFileSync(0,'utf8')));process.stdout.write('VALID');}catch(e){process.stdout.write(e.code);process.exitCode=2;}"
        for literal in ('Zażółć gęślą jaźń 😀\u2028', 9007199254740991, -9007199254740991, None, True):
            raw = copy.deepcopy(private['policy']); raw['cells'][0]['expected']['json'][0]['equals_literal'] = literal
            plan = compiler.policy_plan({}, [{'path': 'frontend'}], report['identity_plan'], report['integrations'],
                {'runtime': {'identity_policy': {'schema_version': 1, 'parts': {'frontend': raw}}}})
            built = policy.build_policy_input(plan, 'frontend', report['identity_plan'], raw, private['form_input'], policy_attempt_id='policy-'+'e'*32)
            result = subprocess.run(['node', '-e', script], cwd=ROOT, input=json.dumps(built), text=True, capture_output=True, timeout=5)
            with self.subTest(literal=literal): self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            built['policy']['cells'][0]['expected']['json'][0]['equals_literal'] = 'TAMPERED_PRIVATE_CANARY'
            result = subprocess.run(['node', '-e', script], cwd=ROOT, input=json.dumps(built), text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2); self.assertEqual(result.stdout, 'INPUT_INVALID')
            self.assertNotIn('TAMPERED_PRIVATE_CANARY', result.stdout + result.stderr)

    def test_actual_javascript_checkpoints_retain_cleanup_failure_without_credit(self):
        import test_runtime_policy_execution_adversarial as execution_fixture
        fixture = execution_fixture.RuntimePolicyExecutionAdversarial(); fixture.setUp()
        data = fixture.call({'closeFailure': 3})
        report = dict(parts=fixture.args[1], identity_plan=fixture.args[2], identity_forms=[data['formResult']],
            run_id=fixture.input['binding']['run_id'], integrations={'plan_id': fixture.input['binding']['integration_plan_id'],
                'integrations': [{'id': fixture.input['binding']['integration_id'], 'provider': 'keycloak', 'parts': ['frontend']}]},
            identity_policy_plan=execution_fixture.pure_fixture.policy.policy_plan(*fixture.args), identity_policy_receipts=[],
            identity_policy_executions=[data['result']])
        result = policy.project_policy_execution(report)
        self.assertEqual(result['coverage_status'], 'INCOMPLETE'); self.assertEqual(result['counts']['completed_cells'], 0)
        session = next(row for row in result['parts'][0]['sessions'] if row['cleanup'] == 'unknown')
        self.assertEqual(session['status'], 'BLOCKED'); self.assertEqual(session['observation_status'], 'PASS')
        self.assertEqual(session['cleanup'], 'unknown')
        # Simulate interruption before final form-suite publication; the bound
        # pending initial suite must retain observations without session credit.
        report['identity_forms'] = [data['formEmits'][0]] if data.get('formEmits') else []
        result = policy.project_policy_execution(report)
        self.assertEqual(result['counts']['completed_cells'], 0); self.assertNotEqual(result['outcome'], 'PASS')


if __name__ == '__main__': unittest.main()
