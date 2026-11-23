"""Phase receipts remain distinct from application session and route coverage."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(Path(os.environ.get('HELIX_SOURCE_ROOT',ROOT))/'bin'))
sys.path.insert(0,str(ROOT/'bin'))
import helix_runtime_login as login
import test_runtime_login as private_fixture


def public_fixture():
    fixture=private_fixture.RuntimeLoginInput();fixture.setUp();private=fixture.build()
    rows=[]
    for identity in private['identities']:
        phases=login._phases_not_run()
        for phase,reason in zip(phases[:3],('BOUND_AUTHORIZATION_OBSERVED','OWNED_FORM_SUBMITTED','BOUND_CALLBACK_RESPONSE_OBSERVED')):
            phase.update(status='PASS',reason_code=reason)
        rows.append(dict(type='identity-flow',binding=dict(fixture.binding),identity_id=identity['id'],status='INCOMPLETE',
            form_status='PASS',phases=phases,execution=dict(form_submitted=True,callback_observed=True,session_asserted=False,protected_routes_tested=0),
            limits=list(login.LIMITS),cleanup='closed'))
    suite=dict(type='identity-form-suite',binding=dict(fixture.binding),status='INCOMPLETE',form_status='PASS',identities=rows,
               session_coverage='NOT_RUN',authorization_coverage='NOT_RUN')
    report=dict(run_id=fixture.binding['run_id'],parts=[{'path':'frontend','name':'Application'}],
        identity_plan=dict(schema_version=1,parts=[fixture.plan]),identity_forms=[suite],
        integrations=dict(plan_id=fixture.binding['integration_plan_id'],integrations=[dict(id=fixture.binding['integration_id'],provider='keycloak',parts=['frontend'])]))
    return report


class RuntimeIdentityProjection(unittest.TestCase):
    def test_legacy_is_not_recorded(self):
        result=login.project_identity({'parts':[]})
        self.assertEqual(result['status'],'NOT_RECORDED');self.assertEqual(result['parts'],[])

    def test_no_keycloak_declaration_does_not_invent_missing_login(self):
        report=dict(parts=[{'path':'app'}],identity_plan={'schema_version':1,'status':'NOT_DETECTED','parts':[]},identity_forms=[])
        result=login.project_identity(report)
        self.assertEqual(result['status'],'NOT_DETECTED');self.assertEqual(result['parts'],[])
        self.assertEqual(result['form_status'],'NOT_RUN');self.assertEqual(result['gaps'],[])

    def test_form_observation_keeps_negative_variants_and_session_routes_unrun(self):
        report=public_fixture();before=copy.deepcopy(report);result=login.project_identity(report)
        self.assertEqual(result['status'],'INCOMPLETE');self.assertEqual(result['form_status'],'PASS')
        self.assertEqual(result['session_coverage'],'NOT_RUN');self.assertEqual(result['authorization_coverage'],'NOT_RUN')
        rows=result['parts'][0]['identities'];self.assertEqual(len(rows),4)
        self.assertTrue(all(row['form_status']=='NOT_RUN' for row in rows if row['variant']=='negative'))
        self.assertTrue(all(row['form_status']=='PASS' for row in rows if row['variant']=='positive'))
        self.assertEqual(report,before)
        result['parts'][0]['identities'][0]['phases'][0]['status']='changed'
        self.assertEqual(report,before)

    def test_callback_http_error_is_failed_observation_not_successful_app_callback(self):
        report=public_fixture();suite=report['identity_forms'][0];row=suite['identities'][0]
        row.update(status='FAIL',form_status='FAIL');row['phases'][2].update(status='FAIL',reason_code='CALLBACK_HTTP_ERROR')
        suite['form_status']='INCOMPLETE'
        result=login.project_identity(report);projected=result['parts'][0]['identities'][0]
        self.assertEqual(projected['form_status'],'FAIL');self.assertEqual(projected['phases'][2]['reason_code'],'CALLBACK_HTTP_ERROR')
        self.assertEqual(result['session_coverage'],'NOT_RUN')
        row['phases'][2].update(status='PASS')
        with self.assertRaises(ValueError):login.project_identity(report)

    def test_session_route_credit_or_success_without_observed_callback_is_rejected(self):
        mutations=[lambda r:r['identity_forms'][0].update(session_coverage='PASS'),
                   lambda r:r['identity_forms'][0]['identities'][0]['phases'][3].update(status='PASS'),
                   lambda r:r['identity_forms'][0]['identities'][0]['execution'].update(session_asserted=True),
                   lambda r:r['identity_forms'][0]['identities'][0]['execution'].update(protected_routes_tested=1),
                   lambda r:r['identity_forms'][0]['identities'][0]['execution'].update(callback_observed=False)]
        for mutate in mutations:
            report=public_fixture();mutate(report)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):login.project_identity(report)

    def test_form_http_error_and_credential_url_remain_explicit_failed_observations(self):
        for reason in ('FORM_HTTP_ERROR','CREDENTIAL_IN_URL'):
            report=public_fixture();suite=report['identity_forms'][0];row=suite['identities'][0]
            row.update(status='FAIL',form_status='FAIL');row['phases'][1].update(status='FAIL',reason_code=reason)
            row['phases'][2]=login._phases_not_run()[2];row['execution']['callback_observed']=False;suite['form_status']='INCOMPLETE'
            result=login.project_identity(report)
            projected=result['parts'][0]['identities'][0]
            self.assertEqual(projected['phases'][1]['reason_code'],reason)
            self.assertEqual(projected['phases'][2]['status'],'NOT_RUN')
            self.assertEqual(result['authorization_coverage'],'NOT_RUN')

    def test_binding_omission_duplicates_and_stale_attempt_are_rejected(self):
        for field,value in (('run_id','runtime-old'),('integration_plan_id','f'*64),('identity_plan_id','e'*64),('part','elsewhere')):
            report=public_fixture();report['identity_forms'][0]['binding'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):login.project_identity(report)
        report=public_fixture();report['identity_forms'][0]['identities'].pop()
        with self.assertRaises(ValueError):login.project_identity(report)
        report=public_fixture();report['identity_forms'].append(copy.deepcopy(report['identity_forms'][0]))
        with self.assertRaises(ValueError):login.project_identity(report)
        report=public_fixture();report['identity_forms'][0]['identities'][0]['binding']['attempt_id']='login-'+'d'*32
        with self.assertRaises(ValueError):login.project_identity(report)

    def test_private_fields_and_arbitrary_reason_text_cannot_enter_projection(self):
        for mutate in (lambda r:r['identity_forms'][0]['identities'][0].update(password='DO_NOT_PUBLISH'),
                       lambda r:r['identity_forms'][0]['identities'][0]['phases'][0].update(reason_code='DO_NOT_PUBLISH')):
            report=public_fixture();mutate(report)
            with self.assertRaises(ValueError) as error:login.project_identity(report)
            self.assertNotIn('DO_NOT_PUBLISH',str(error.exception))
        report=public_fixture();report['secret']='DO_NOT_PUBLISH'
        self.assertNotIn('DO_NOT_PUBLISH',json.dumps(login.project_identity(report)))

    def test_no_attempt_keeps_planned_identities_explicit_and_does_not_credit_forms(self):
        report=public_fixture();report['identity_forms']=[]
        result=login.project_identity(report)
        self.assertEqual(result['status'],'INCOMPLETE');self.assertEqual(result['parts'][0]['form_status'],'NOT_RUN')
        self.assertEqual(len(result['parts'][0]['identities']),4)
        self.assertTrue(all(row['form_status']=='NOT_RUN' for row in result['parts'][0]['identities']))

    def test_rehashed_plan_cannot_publish_arbitrary_identity_or_unsafe_part(self):
        for mutate in (lambda plan:plan['identities'][0].update(id='PRIVATE_CANARY_MALFORMED_ID'),
                       lambda plan:plan['identities'].append(copy.deepcopy(plan['identities'][0])),
                       lambda plan:plan['identities'].append('PRIVATE_CANARY'),
                       lambda plan:plan.update(part='../PRIVATE_CANARY')):
            report=public_fixture();report['identity_forms']=[];plan=report['identity_plan']['parts'][0]
            mutate(plan);bound=dict(plan);bound.pop('plan_id');plan['plan_id']=login._digest(bound)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError) as error:login.project_identity(report)
            self.assertNotIn('PRIVATE_CANARY',str(error.exception))

    def test_subset_uses_exact_part_and_missing_plan_is_error(self):
        report=public_fixture();self.assertEqual(login.project_identity(report,['frontend'])['parts'][0]['part'],'frontend')
        with self.assertRaises(ValueError):login.project_identity(report,['Application'])
        report.pop('identity_plan')
        with self.assertRaises(ValueError):login.project_identity(report)


if __name__=='__main__':unittest.main()
