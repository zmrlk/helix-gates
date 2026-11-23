"""Independent real-JS policy execution tests on a synthetic browser only."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest

ROOT=Path(os.environ.get('HELIX_SOURCE_ROOT',Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(ROOT/'bin'))
sys.path.insert(0,str(ROOT/'tests'))
if os.environ.get('HELIX_POLICY_PYTHON_DIR'):
    sys.path.insert(0,os.environ['HELIX_POLICY_PYTHON_DIR'])
import helix_runtime_login as login
import helix_runtime_identity_policy_run as policy_run
import test_runtime_policy_adversarial as pure_fixture

HELPER=Path(os.environ.get('HELIX_POLICY_HELPER',ROOT/'bin/runtime-identity-policy.cjs'))
FORM_HELPER=Path(os.environ.get('HELIX_LOGIN_HELPER',ROOT/'bin/runtime-keycloak-login.cjs'))
DRIVER=Path(os.environ.get('HELIX_POLICY_DRIVER',Path(__file__).resolve().parent/'fixtures/runtime-policy-fake.cjs'))
NODE=shutil.which('node')


class RuntimePolicyExecutionAdversarial(unittest.TestCase):
    def setUp(self):
        self.args=pure_fixture.fixture()
        self.declaration=self.args[4]['runtime']['identity_policy']['parts']['frontend']
        second=copy.deepcopy(self.declaration['cells'][0])
        second.update(id='editor-items',identity={'role':'editor'},
            expected={'access':'deny','denial':{'kind':'status','codes':[403]}})
        self.declaration['cells'].append(second)
        self.input=self.build()

    def build(self):
        plan=pure_fixture.policy.policy_plan(*self.args)
        identity_plan=self.args[2]['parts'][0]
        material={'realm':'helix-policy-fixture18','app_origin':'https://localhost:44301',
            'user_passwords':{row['id']:'PASSWORD_CANARY_POLICY_'+row['id'] for row in identity_plan['identities']}}
        form_binding={'run_id':'runtime-policy-independent','integration_id':'keycloak:0123456789ab',
            'integration_plan_id':'a'*64,'identity_plan_id':identity_plan['plan_id'],
            'attempt_id':'login-'+'5'*32,'part':'frontend'}
        private_form=login.build_login_input(identity_plan,material,binding=form_binding,
            issuer='https://127.0.0.1:44302/realms/'+material['realm'],
            deadline_unix_ms=int(time.time()*1000)+10000,operation_timeout_ms=120)
        return policy_run.build_policy_input(plan,'frontend',self.args[2],self.declaration,
            private_form,policy_attempt_id='policy-'+'6'*32)

    def call(self,scenario=None):
        self.assertTrue(NODE,'Node is required; no implied green result without implementation')
        self.assertTrue(HELPER.is_file());self.assertTrue(FORM_HELPER.is_file());self.assertTrue(DRIVER.is_file())
        self.input['form_input']['deadline_unix_ms']=int(time.time()*1000)+2000
        env={key:value for key,value in os.environ.items() if key in ('PATH','HOME','TMPDIR')}
        completed=subprocess.run([NODE,str(DRIVER),str(HELPER),str(FORM_HELPER)],
            input=json.dumps({'input':self.input,'scenario':scenario or {}}),capture_output=True,text=True,env=env,timeout=5)
        self.assertEqual(completed.returncode,0,completed.stderr)
        data=json.loads(completed.stdout)
        self.assertNotIn('PRIVATE_ASSERTION_LITERAL',completed.stdout)
        for secret in ('PASSWORD_CANARY_POLICY','OTHER_USERNAME_CANARY_POLICY','COOKIE_CANARY_POLICY',
                       'TOKEN_CANARY_POLICY','STATE_CANARY_POLICY','NONCE_CANARY_POLICY',
                       'AUTH_CODE_CANARY_POLICY','ANONYMOUS_BODY_CANARY'):
            self.assertNotIn(secret,completed.stdout)
            self.assertNotIn(secret,completed.stderr)
        return data

    def suite(self,data):
        self.assertIsNone(data['error'],data['error'])
        self.assertIsInstance(data['result'],dict)
        return data['result']

    def closed(self,data):
        counts=data['counters']
        self.assertEqual(counts['contexts'],counts['closed'],counts)
        self.assertEqual(counts['acquired'],counts['released'],counts)
        self.assertEqual(counts['alive'],0,counts)
        self.assertEqual(counts['activePermits'],0,counts)
        self.assertLessEqual(counts['maxPermits'],1,counts)
        self.assertLessEqual(counts['maxAlive'],1,counts)

    def test_real_form_and_policy_allow_deny_same_get_with_jobs_one(self):
        data=self.call();suite=self.suite(data)
        self.assertEqual(len(suite['cells']),2)
        self.assertEqual({row['result'] for row in suite['cells']},{'PASS'})
        self.assertEqual({row['session']['status'] for row in suite['identities']},{'PASS'})
        self.assertEqual({row['access']['http_status'] for row in suite['cells']},{200,403})
        self.assertEqual(data['formResult']['form_status'],'PASS')
        self.assertEqual(data['formResult']['session_coverage'],'NOT_RUN')
        self.assertEqual(data['formResult']['authorization_coverage'],'NOT_RUN')
        self.closed(data)

    def test_role_and_anonymous_contexts_do_not_share_authenticated_state(self):
        data=self.call();self.suite(data)
        actors={}
        for event in data['events']:
            if event['event']=='fill' and event['actor']:
                actors.setdefault(event['context'],set()).add(event['actor'])
        self.assertEqual(len(actors),2)
        self.assertTrue(all(len(values)==1 for values in actors.values()))
        self.assertEqual(len(set.union(*actors.values())),2)
        anonymous=[event for event in data['events'] if event['event']=='request' and
                   event['path'] in ('/api/session','/api/items') and not event['authenticated']]
        self.assertEqual(len(anonymous),4)
        self.assertEqual(len({event['context'] for event in anonymous}),4)
        self.assertTrue(all(event['context'] not in actors for event in anonymous))
        self.closed(data)

    def test_public_anonymous_session_json_does_not_prove_a_session(self):
        data=self.call({'anonymousSessionPublic':True});suite=self.suite(data)
        self.assertTrue(all(row['anonymous_session']['status']!='PASS' for row in suite['identities']))
        self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
        self.closed(data)

    def test_session_identity_mismatch_cannot_credit_allow_or_deny(self):
        data=self.call({'sessionMismatch':True});suite=self.suite(data)
        self.assertEqual({row['session']['status'] for row in suite['identities']},{'FAIL'})
        self.assertEqual({row['session']['reason_code'] for row in suite['identities']},{'SESSION_IDENTITY_MISMATCH'})
        self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
        self.assertEqual(data['formResult']['form_status'],'PASS')
        self.closed(data)

    def test_session_role_set_cannot_accept_missing_extra_or_wrong_type(self):
        for roles in ([],['reader','editor'],['owner'],'reader',None):
            with self.subTest(roles=roles):
                data=self.call({'sessionRoles':roles});suite=self.suite(data)
                self.assertTrue(all(row['session']['status']=='FAIL' for row in suite['identities']))
                self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
                self.closed(data)

    def test_session_pointer_missing_is_not_null_or_success(self):
        data=self.call({'missingUsername':True});suite=self.suite(data)
        self.assertTrue(all(row['session']['status']!='PASS' for row in suite['identities']))
        self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
        self.closed(data)

    def test_buffered_json_mime_invalid_and_real_size_are_enforced(self):
        cases=[({'sessionMime':'text/html'},'CONTENT_TYPE_MISMATCH'),
               ({'sessionBody':'{broken COOKIE_CANARY_POLICY'},'JSON_INVALID'),
               ({'sessionBodyBytes':1048577,'contentLength':1},'BODY_TOO_LARGE')]
        for scenario,reason in cases:
            with self.subTest(reason=reason):
                data=self.call(scenario);suite=self.suite(data)
                self.assertEqual({row['session']['reason_code'] for row in suite['identities']},{reason})
                self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
                self.closed(data)

    def test_successful_form_does_not_turn_wrong_resource_into_pass(self):
        data=self.call({'resourceValue':'unexpected-resource'});suite=self.suite(data)
        self.assertEqual({row['session']['status'] for row in suite['identities']},{'PASS'})
        allow=next(row for row in suite['cells'] if row['access']['http_status']==200)
        self.assertEqual(allow['result'],'FAIL')
        self.assertEqual(allow['access']['reason_code'],'ASSERTION_MISMATCH')
        self.assertEqual(data['formResult']['form_status'],'PASS')
        self.closed(data)

    def test_failed_form_then_403_is_not_rbac_success(self):
        data=self.call({'formFailure':True,'resourceStatus':403});suite=self.suite(data)
        self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
        self.assertTrue(all(row['session']['status']!='PASS' for row in suite['identities']))
        self.closed(data)

    def test_anonymous_canonical_and_foreign_redirects_are_never_denials(self):
        for location in ('/api/items/','https://outside.invalid/api/items?token=TOKEN_CANARY_POLICY'):
            with self.subTest(location=location):
                data=self.call({'anonymousRouteStatus':302,'anonymousLocation':location});suite=self.suite(data)
                self.assertTrue(all(row['anonymous']['status']!='PASS' for row in suite['cells']))
                self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
                requests=[event for event in data['events'] if event['event']=='request']
                self.assertFalse(any(event['origin']=='https://outside.invalid' or event['path']=='/api/items/' for event in requests))
                self.closed(data)

    def test_anonymous_404_or_500_never_proves_denial(self):
        for status in (404,500):
            with self.subTest(status=status):
                data=self.call({'anonymousRouteStatus':status});suite=self.suite(data)
                self.assertTrue(all(row['anonymous']['status']!='PASS' for row in suite['cells']))
                self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
                self.closed(data)

    def test_private_hash_tampering_is_rejected_before_form_fill(self):
        self.input['policy']['cells'][0]['expected']['json'][0]['equals_literal']='changed-literal'
        data=self.call()
        self.assertFalse(any(event['event']=='fill' for event in data['events']))
        self.assertIsNotNone(data['error'])
        self.assertEqual(data['counters']['contexts'],0)

    def test_pending_and_completed_checkpoints_are_snapshots(self):
        data=self.call();self.suite(data)
        self.assertGreaterEqual(len(data['policyEmits']),3)
        first=data['policyEmits'][0]
        self.assertEqual({row['result'] for row in first['cells']},{'NOT_RUN'})
        self.assertEqual({row['result'] for row in data['policyEmits'][-1]['cells']},{'PASS'})
        self.assertTrue(any(sum(row['result']=='PASS' for row in snapshot['cells'])==1 for snapshot in data['policyEmits']))
        self.closed(data)

    def test_session_timeout_is_bounded_and_cannot_credit_access(self):
        data=self.call({'sessionBodyPending':True});suite=self.suite(data)
        self.assertTrue(all(row['session']['status']!='PASS' for row in suite['identities']))
        self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))
        self.closed(data)

    def test_late_anonymous_context_is_owned_and_closed(self):
        data=self.call({'lateContext':1,'lateContextMs':180,'drainMs':220});suite=self.suite(data)
        self.assertTrue(any(row['anonymous_session']['status']!='PASS' for row in suite['identities']))
        self.closed(data)

    def test_setup_exception_and_private_error_leave_no_context(self):
        for scenario in ({'pageFailure':1},{'routeFailure':1},{'sessionException':True}):
            with self.subTest(scenario=scenario):
                data=self.call(scenario);suite=self.suite(data)
                self.assertTrue(any(row['result']!='PASS' for row in suite['cells']))
                self.closed(data)

    def test_resource_pause_does_not_start_second_role(self):
        data=self.call({'pauseAfter':1});suite=self.suite(data)
        self.assertEqual(data['counters']['acquired'],1)
        self.assertTrue(any(row['result']=='PASS' for row in suite['cells']))
        self.assertTrue(any(row['result']!='PASS' for row in suite['cells']))
        self.closed(data)

    def test_failed_durable_checkpoint_stops_before_second_role(self):
        data=self.call({'emitAfterCompletedCell':True});suite=self.suite(data)
        self.assertEqual(data['counters']['acquired'],1)
        self.assertTrue(any(event['event']=='policy-write-failed' for event in data['events']))
        self.assertTrue(any(row['result']!='PASS' for row in suite['cells']))
        self.closed(data)

    def test_failed_anonymous_cleanup_does_not_exceed_jobs_one(self):
        data=self.call({'closeFailure':1});suite=self.suite(data)
        self.assertEqual(data['counters']['contexts'],1)
        self.assertEqual(data['counters']['acquired'],1)
        self.assertLessEqual(data['counters']['maxAlive'],1)
        self.assertTrue(any(row['cleanup']=='unknown' for row in suite['identities']))
        self.assertTrue(all(row['result']!='PASS' for row in suite['cells']))


if __name__=='__main__':unittest.main()
