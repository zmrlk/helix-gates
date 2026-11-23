"""Independent actual-JS WebAuthn execution boundaries on fake browser/CDP only."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'bin'), str(ROOT / 'tests')]
import helix_runtime_webauthn_run as webauthn_run
import helix_runtime_webauthn as webauthn_plan
from test_runtime_webauthn_run import fixture_input
from test_runtime_webauthn import fixture_inputs

NODE = shutil.which('node')
HELPER = ROOT / 'bin/runtime-webauthn.cjs'
POLICY = ROOT / 'bin/runtime-identity-policy.cjs'
LOGIN = ROOT / 'bin/runtime-keycloak-login.cjs'
DRIVER = ROOT / 'tests/fixtures/runtime-webauthn-fake.cjs'
CANARIES = ('PRIVATE_WEBAUTHN_EVENT_CANARY_22', 'PRIVATE_USER_HANDLE_CANARY_W22',
    'PRIVATE_CREDENTIAL_ID_WEBAUTHN_22', 'OTHER_PRIVATE_CREDENTIAL_ID_WEBAUTHN_22',
    'PRIVATE_CHALLENGE_', 'OTHER_PRIVATE_CHALLENGE_W22', 'OTHER_IDENTITY_CANARY_W22',
    'STATE_CANARY_W22', 'NONCE_CANARY_W22', 'SESSION_CODE_CANARY_W22',
    'EXECUTION_CANARY_W22', 'AUTH_CODE_CANARY_W22', 'REJECTED_CANARY_W22',
    'WRONG_CELL_CANARY_W22')


class RuntimeWebAuthnExecutionAdversarial(unittest.TestCase):
    def setUp(self):
        self.report, self.input = fixture_input()

    def call(self, scenario=None):
        self.assertTrue(NODE, 'Node is required; absent execution is not green evidence')
        self.assertTrue(HELPER.is_file())
        self.input['policy_input']['form_input'].update(
            deadline_unix_ms=int(time.time() * 1000) + 3000, operation_timeout_ms=120)
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'TMPDIR')}
        done = subprocess.run([NODE, str(DRIVER), str(HELPER), str(POLICY), str(LOGIN)],
            input=json.dumps(dict(input=self.input, scenario=scenario or {}), ensure_ascii=False),
            text=True, capture_output=True, env=env, timeout=6)
        self.assertEqual(done.returncode, 0, done.stderr)
        for canary in CANARIES:
            self.assertNotIn(canary, done.stdout)
            self.assertNotIn(canary, done.stderr)
        for phase in ('registration', 'authentication'):
            for assertion in self.input['webauthn'][phase]['verify']['json']:
                literal = assertion['equals_literal']
                if isinstance(literal, str) and len(literal) > 12:
                    self.assertNotIn(literal, done.stdout)
        for identity in self.input['policy_input']['form_input']['identities']:
            self.assertNotIn(identity['password'], done.stdout)
        data = json.loads(done.stdout)
        self.assertTrue(data['inputUnchanged'])
        self.assertEqual(data['counters']['forbidden'], 0)
        return data

    def suite(self, data):
        self.assertIsNone(data['error'], data['error'])
        self.assertIsInstance(data['result'], dict)
        return data['result']

    def project(self, data):
        report = copy.deepcopy(self.report)
        report['identity_forms'] = [data['formResult']] if data['formResult'] else []
        report['identity_policy_executions'] = [data['policyResult']] if data['policyResult'] else []
        report['webauthn_executions'] = [data['result']] if data['result'] else []
        return webauthn_run.project_webauthn_execution(report)

    def rebind_config(self, mutate):
        """Use real pure compilers, never reproduce hash or validation logic."""
        args = list(fixture_inputs())
        args[0]['frontend/package.json'] = json.dumps({'dependencies': {
            'keycloak-js': '26.0.0', '@simplewebauthn/browser': '13.3.0'}})
        raw = copy.deepcopy(self.input['webauthn']); mutate(raw)
        args[6]['runtime']['webauthn']['parts']['frontend'] = raw
        self.report['webauthn_plan'] = webauthn_plan.webauthn_plan(args[0], args[1],
            self.report['integrations'], self.report['identity_plan'], self.report['transport_plan'],
            self.report['identity_policy_plan'], args[6])
        self.input = webauthn_run.build_webauthn_input(self.report, 'frontend', raw,
            self.input['policy_input'], webauthn_attempt_id=self.input['binding']['webauthn_attempt_id'])

    def closed(self, data):
        c = data['counters']
        self.assertEqual(c['contexts'], c['closed'], c)
        self.assertEqual(c['alive'], 0, c)
        self.assertEqual(c['acquired'], c['released'], c)
        self.assertEqual(c['activePermits'], 0, c)
        self.assertLessEqual(c['maxPermits'], 1, c)
        self.assertLessEqual(c['maxAlive'], 1, c)
        self.assertEqual(c['devices'], c['removed'], c)
        self.assertEqual(c['cdp'], c['detached'], c)

    def test_actual_helpers_register_logout_authenticate_and_recheck_policy(self):
        data = self.call(); suite = self.suite(data)
        for name in ('capability', 'registration', 'logout', 'authentication', 'session_after_authentication'):
            self.assertEqual(suite[name]['status'], 'PASS', (name, suite))
        self.assertTrue(all(row['access']['status'] == 'PASS' for row in suite['cells']))
        self.assertEqual(suite['registration']['credential_alias'], suite['authentication']['credential_alias'])
        projected = self.project(data)
        self.assertEqual((projected['execution_status'], projected['coverage_status'], projected['outcome']),
                         ('COMPLETE', 'RECORDED', 'PASS'))
        self.assertEqual(data['formResult']['session_coverage'], 'NOT_RUN')
        self.closed(data)

    def test_device_readiness_without_credential_never_proves_registration(self):
        data = self.call({'noCredentialEvent': True}); suite = self.suite(data)
        self.assertEqual(suite['capability']['status'], 'PASS')
        self.assertNotEqual(suite['registration']['status'], 'PASS')
        self.assertNotEqual(suite['authentication']['status'], 'PASS')
        self.assertEqual(self.project(data)['counts']['completed_flows'], 0)
        self.closed(data)

    def test_credential_event_without_verify_response_is_incomplete(self):
        data = self.call({'eventOnly': True}); suite = self.suite(data)
        self.assertTrue(suite['registration']['credential_observed'])
        self.assertNotEqual(suite['registration']['status'], 'PASS')
        self.assertNotEqual(self.project(data)['coverage_status'], 'RECORDED')
        self.closed(data)

    def test_server_rejection_remains_fail_without_later_authentication(self):
        for scenario in ({'verifyStatus': 403}, {'verifyMismatch': True}):
            with self.subTest(scenario=scenario):
                data = self.call(scenario); suite = self.suite(data)
                self.assertEqual(suite['registration']['status'], 'FAIL')
                self.assertNotEqual(suite['authentication']['status'], 'PASS')
                result = self.project(data)
                self.assertEqual(result['outcome'], 'FAIL')
                self.assertEqual(result['coverage_status'], 'INCOMPLETE')
                self.closed(data)

    def test_current_challenge_id_origin_type_and_cross_origin_are_bound(self):
        for key in ('challengeMismatch', 'idMismatch', 'originMismatch', 'typeMismatch', 'crossOrigin',
                    'optionsRpMismatch', 'eventRpMismatch', 'foreignAuthenticator', 'otherCredential'):
            with self.subTest(key=key):
                data = self.call({key: True}); suite = self.suite(data)
                target = suite['authentication'] if key == 'otherCredential' else suite['registration']
                self.assertNotEqual(target['status'], 'PASS')
                self.assertNotEqual(self.project(data)['coverage_status'], 'RECORDED')
                self.closed(data)

    def test_fresh_post_key_session_must_match_same_identity_and_roles(self):
        for key in ('postIdentityMismatch', 'postRolesMismatch'):
            with self.subTest(key=key):
                data = self.call({key: True}); suite = self.suite(data)
                self.assertEqual(suite['authentication']['status'], 'PASS')
                self.assertEqual(suite['session_after_authentication']['status'], 'FAIL')
                self.assertTrue(all(row['access']['status'] != 'PASS' for row in suite['cells']))
                self.assertEqual(self.project(data)['outcome'], 'FAIL')
                self.closed(data)

    def test_logout_requires_observed_request_and_fresh_session_denial(self):
        for key in ('noLogoutRequest', 'logoutKeepsSession', 'duplicateLogout', 'logoutRedirect'):
            with self.subTest(key=key):
                data = self.call({key: True}); suite = self.suite(data)
                self.assertEqual(suite['registration']['status'], 'PASS')
                self.assertNotEqual(suite['logout']['status'], 'PASS')
                self.assertNotEqual(suite['authentication']['status'], 'PASS')
                if key in ('duplicateLogout', 'logoutRedirect'):
                    self.assertEqual(suite['logout']['status'], 'FAIL')
                    self.assertEqual(suite['logout']['reason_code'],
                        'DUPLICATE_CEREMONY_REQUEST' if key == 'duplicateLogout' else 'REDIRECT_NOT_SUPPORTED')
                self.assertNotEqual(self.project(data)['coverage_status'], 'RECORDED')
                self.closed(data)

    def test_post_key_cells_are_fresh_and_do_not_copy_initial_policy_pass(self):
        data = self.call({'postCellMismatch': True}); suite = self.suite(data)
        self.assertTrue(all(row['result'] == 'PASS' for row in data['policyResult']['cells']))
        self.assertEqual(suite['session_after_authentication']['status'], 'PASS')
        self.assertEqual({row['access']['status'] for row in suite['cells']}, {'FAIL'})
        self.assertEqual(self.project(data)['outcome'], 'FAIL')
        self.closed(data)

    def test_same_device_page_and_context_survive_all_ui_phases_without_export(self):
        data = self.call(); self.suite(data)
        clicks = [e for e in data['events'] if e['event'] in ('ceremony-click', 'logout-click')]
        self.assertEqual(len(clicks), 3)
        self.assertEqual(len({(e['context'], e['page']) for e in clicks}), 1)
        self.assertEqual(data['counters']['devices'], 1)
        blanks = [e for e in data['events'] if e['event'] == 'blank']
        self.assertGreaterEqual(len(blanks), 2)
        self.closed(data)

    def test_jobs_one_uses_existing_permit_and_closes_before_next_identity(self):
        data = self.call(); self.suite(data)
        self.assertEqual(data['counters']['maxPermits'], 1)
        self.assertEqual(data['counters']['maxAlive'], 1)
        self.closed(data)

    def test_exact_origin_path_frame_response_and_duplicate_request_boundaries(self):
        for key in ('verifyOutside', 'verifyOtherPath', 'iframeFlow', 'foreignResponse', 'duplicateOptions', 'duplicateVerify'):
            with self.subTest(key=key):
                data = self.call({key: True}); suite = self.suite(data)
                self.assertNotEqual(suite['registration']['status'], 'PASS')
                self.assertFalse(any(e.get('origin') == 'https://outside.invalid' or e.get('path') == '/collect'
                    for e in data['events'] if e['event'] == 'request'))
                self.closed(data)

    def test_private_cdp_fields_never_appear_in_public_receipts_or_errors(self):
        for scenario in ({}, {'foreignAuthenticator': True}, {'removeFailure': True}):
            with self.subTest(scenario=scenario):
                data = self.call(scenario); self.suite(data)
                public = json.dumps(data)
                self.assertNotIn('privateKey', public)
                self.assertNotIn('credentialId', public)
                self.assertNotIn('userHandle', public)

    def test_options_and_verify_body_acceptance_limits_and_content_type(self):
        for scenario in ({'optionsBodyBytes': 1048577}, {'optionsMime': 'text/html'},
                         {'verifyMime': 'text/html'}, {'optionsWrapper': True}, {'verifyWrapper': True}):
            with self.subTest(scenario=scenario):
                data = self.call(scenario); suite = self.suite(data)
                self.assertNotEqual(suite['registration']['status'], 'PASS')
                self.closed(data)

    def test_no_add_credential_get_credentials_or_navigator_override(self):
        data = self.call(); self.suite(data)
        commands = [e['method'] for e in data['events'] if e['event'] == 'cdp-command']
        self.assertIn('WebAuthn.addVirtualAuthenticator', commands)
        self.assertNotIn('WebAuthn.addCredential', commands)
        self.assertNotIn('WebAuthn.getCredentials', commands)
        self.assertNotIn('WebAuthn.setUserVerified', commands)
        self.assertEqual(data['counters']['forbidden'], 0)
        self.closed(data)

    def test_unsupported_cdp_is_explicit_without_any_ceremony_credit(self):
        for key in ('cdpUnsupported', 'authenticatorUnsupported'):
            with self.subTest(key=key):
                data = self.call({key: True}); suite = self.suite(data)
                self.assertEqual(suite['capability']['status'], 'BLOCKED')
                self.assertNotEqual(suite['registration']['status'], 'PASS')
                self.assertEqual(self.project(data)['counts']['completed_flows'], 0)
                self.closed(data)

    def test_late_authenticator_handle_is_removed_without_false_cleanup_credit(self):
        data = self.call({'lateAuthenticator': True, 'drainMs': 240}); suite = self.suite(data)
        self.assertNotEqual(suite['capability']['status'], 'PASS')
        self.assertNotEqual(self.project(data)['coverage_status'], 'RECORDED')
        self.closed(data)

    def test_late_page_and_cdp_are_owned_and_cleaned(self):
        for key in ('latePage', 'lateCDP'):
            with self.subTest(key=key):
                data = self.call({key: True, 'drainMs': 240}); self.suite(data)
                self.assertNotEqual(self.project(data)['coverage_status'], 'RECORDED')
                self.closed(data)

    def test_unknown_cleanup_stops_new_work_and_never_completes(self):
        for key in ('removeFailure', 'detachFailure', 'pageCloseFailure', 'contextCloseFailure'):
            with self.subTest(key=key):
                data = self.call({key: True}); suite = self.suite(data)
                self.assertIn('unknown', suite['cleanup'].values())
                self.assertEqual(self.project(data)['counts']['completed_flows'], 0)
                self.assertEqual(data['counters']['activePermits'], 0)

    def test_performed_failure_survives_cleanup_failure(self):
        data = self.call({'verifyMismatch': True, 'removeFailure': True}); suite = self.suite(data)
        self.assertEqual(suite['registration']['status'], 'FAIL')
        self.assertEqual(suite['cleanup']['authenticator'], 'unknown')
        result = self.project(data)
        self.assertEqual(result['outcome'], 'FAIL')
        self.assertEqual(result['coverage_status'], 'INCOMPLETE')

    def test_durable_write_failure_stops_following_ceremonies(self):
        data = self.call({'writerFailureAfterRegistration': True}); self.suite(data)
        self.assertTrue(any(e['event'] == 'webauthn-write-failed' for e in data['events']))
        self.assertFalse(any(e['event'] == 'ceremony-click' and e['phase'] == 'authentication' for e in data['events']))
        self.closed(data)
        data = self.call({'postRolesMismatch': True, 'writerFailureAfterPostSession': True})
        suite = self.suite(data)
        self.assertEqual(suite['session_after_authentication']['status'], 'FAIL')
        self.assertEqual(suite['session_after_authentication']['reason_code'], 'SESSION_ROLES_MISMATCH')
        self.assertTrue(any(e['event'] == 'webauthn-write-failed' for e in data['events']))
        projected = self.project(data)
        self.assertEqual(projected['outcome'], 'FAIL')
        self.assertEqual(projected['coverage_status'], 'INCOMPLETE')
        self.closed(data)

    def test_completed_checkpoint_follows_bound_form_and_policy_finals(self):
        data = self.call(); self.suite(data)
        seen_form = seen_policy = False
        report = copy.deepcopy(self.report)
        for event in data['events']:
            if event['event'] == 'form-checkpoint':
                suite = data['formEmits'][event['index']]
                report['identity_forms'] = [suite]
                seen_form |= any(r['identity_id'] == self.input['binding']['identity_id'] and
                    r['form_status'] == 'PASS' and r['cleanup'] == 'closed' for r in suite['identities'])
            if event['event'] == 'policy-checkpoint':
                suite = data['policyEmits'][event['index']]
                report['identity_policy_executions'] = [suite]
                seen_policy |= any(r['identity_id'] == self.input['binding']['identity_id'] and
                    r['session']['status'] == 'PASS' and r['cleanup'] == 'closed' for r in suite['identities'])
            if event['event'] == 'webauthn-checkpoint':
                suite = data['webauthnEmits'][event['index']]
                report['webauthn_executions'] = [suite]
                projected = webauthn_run.project_webauthn_execution(report)
                if suite['cleanup']['context'] == 'closed':
                    self.assertTrue(seen_form and seen_policy)
                else:
                    self.assertEqual(projected['counts']['completed_flows'], 0)
        self.assertTrue(seen_form and seen_policy)
        self.closed(data)

    def test_timeout_retains_partial_observations_without_next_authentication(self):
        data = self.call({'verifyBodyPending': True}); suite = self.suite(data)
        self.assertNotEqual(suite['registration']['status'], 'PASS')
        self.assertNotEqual(suite['authentication']['status'], 'PASS')
        self.assertNotEqual(self.project(data)['coverage_status'], 'RECORDED')
        self.closed(data)

    def test_private_reader_requires_regular_0600_file_and_owned_parents(self):
        script = "const h=require(process.argv[1]);try{h.readPrivateWebAuthnInput(process.argv[2],process.argv[3]);process.stdout.write('accepted');}catch{process.stdout.write('rejected');}"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); private = root / 'private'; private.mkdir(mode=0o700)
            value = private / 'input.json'; value.write_text(json.dumps(self.input)); value.chmod(0o600)
            def read(path=value):
                done = subprocess.run([NODE, '-e', script, str(HELPER), str(path), str(private)], capture_output=True, text=True, timeout=3)
                self.assertEqual(done.returncode, 0, done.stderr); return done.stdout
            self.assertEqual(read(), 'accepted')
            value.chmod(0o644); self.assertEqual(read(), 'rejected'); value.chmod(0o600)
            link = private / 'link.json'; link.symlink_to(value); self.assertEqual(read(link), 'rejected')
            outside = root / 'outside'; outside.mkdir(); target = outside / 'input.json'; target.write_text(value.read_text()); target.chmod(0o600)
            parent = private / 'linked'; parent.symlink_to(outside, target_is_directory=True)
            self.assertEqual(read(parent / 'input.json'), 'rejected')

    def test_unsupported_verify_format_stops_before_unsupported_request(self):
        self.rebind_config(lambda raw: raw['registration']['verify'].update(method='GET'))
        data = self.call(); suite = self.suite(data)
        self.assertEqual(suite['registration']['status'], 'BLOCKED')
        self.assertEqual(suite['registration']['reason_code'], 'UNSUPPORTED_REQUEST_FORMAT')
        verify_path = self.input['webauthn']['registration']['verify']['path']
        self.assertFalse(any(e.get('path') == verify_path for e in data['events'] if e['event'] == 'request'))
        self.assertEqual(self.project(data)['counts']['completed_flows'], 0)
        self.closed(data)

    def test_private_literal_hash_tampering_is_rejected_without_exposure(self):
        for value in ('\u017b\u00f3\u0142\u0107\U0001f9eaPRIVATE_UNICODE_W22', 9007199254740991):
            with self.subTest(value_type=type(value).__name__):
                self.rebind_config(lambda raw: raw['registration']['verify']['json'][0].update(equals_literal=value))
                data = self.call(); self.assertEqual(self.suite(data)['registration']['status'], 'PASS')
                self.assertEqual(self.project(data)['outcome'], 'PASS'); self.closed(data)
        self.input['webauthn']['registration']['verify']['json'][0]['equals_literal'] = '\u017b\u00f3\u0142\u0107\U0001f9eaPRIVATE_UNICODE_W22'
        data = self.call()
        self.assertIsNotNone(data['error'])
        self.assertEqual(data['counters']['contexts'], 0)


if __name__ == '__main__':
    unittest.main()
