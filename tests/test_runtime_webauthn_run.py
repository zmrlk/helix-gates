"""Synthetic WebAuthn private binding and public phase evidence, no services."""
import builtins
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_runtime_webauthn as plans
import helix_runtime_webauthn_run as run
import helix_runtime_identity as identity
import helix_runtime_identity_policy as policy_plan
import helix_runtime_identity_policy_run as policy_run
import helix_runtime_integrations as integrations
import helix_runtime_transport as transport
import helix_runtime_login as login
from test_runtime_webauthn import fixture_inputs


def fixture_input(config_only=False, with_sibling=False):
    args=list(fixture_inputs())
    if with_sibling:
        args[0]['other/src/app.ts']='export const unrelatedApp = true;'
        args[1].append({'path':'other'})
    dependencies={'keycloak-js':'26.0.0'}
    if not config_only:dependencies['@simplewebauthn/browser']='13.3.0'
    args[0]['frontend/package.json']=json.dumps({'dependencies':dependencies})
    args[2]=integrations.inventory(args[0],args[1],args[6]);args[3]=identity.identity_plan(args[0],args[1],args[6])
    args[4]=transport.transport_plan(args[0],args[1],args[2],args[6]);args[5]=policy_plan.policy_plan(args[0],args[1],args[3],args[2],args[6])
    selected=args[3]['parts'][0];entry=next(row for row in args[2]['integrations'] if row['provider']=='keycloak')
    binding=dict(run_id='runtime-webauthn-synthetic22',integration_id=entry['id'],integration_plan_id=args[2]['plan_id'],
                 identity_plan_id=selected['plan_id'],attempt_id='login-'+'a'*32,part='frontend')
    material=dict(realm='helix-webauthn22',app_origin='https://localhost:44100',
                  user_passwords={row['id']:'synthetic-private-password-'+row['id'] for row in selected['identities']})
    form=login.build_login_input(selected,material,binding=binding,issuer='https://127.0.0.1:44200/realms/'+material['realm'],
                                deadline_unix_ms=1900000000000)
    private_policy=policy_run.build_policy_input(args[5],'frontend',args[3],args[6]['runtime']['identity_policy']['parts']['frontend'],
                                                 form,policy_attempt_id='policy-'+'b'*32)
    report=dict(run_id=binding['run_id'],parts=[dict(path='frontend',name='Synthetic app',transport=dict(status='ready',public_origin=material['app_origin']))],
        integrations=args[2],identity_plan=args[3],transport_plan=args[4],identity_policy_plan=args[5],identity_policy_receipts=[],
        identity_forms=[],identity_policy_executions=[],webauthn_plan=plans.webauthn_plan(*args),webauthn_receipts=[],webauthn_executions=[])
    raw=args[6]['runtime']['webauthn']['parts']['frontend']
    private=run.build_webauthn_input(report,'frontend',raw,private_policy,webauthn_attempt_id='webauthn-'+'c'*32)
    return report,private


def final_dependencies(report,private):
    policy=private['policy_input'];form=policy['form_input'];rows=[]
    for person in form['identities']:
        phases=login._phases_not_run()
        for phase,reason in zip(phases[:3],('BOUND_AUTHORIZATION_OBSERVED','OWNED_FORM_SUBMITTED','BOUND_CALLBACK_RESPONSE_OBSERVED')):
            phase.update(status='PASS',reason_code=reason)
        rows.append(dict(type='identity-flow',binding=copy.deepcopy(form['binding']),identity_id=person['id'],status='INCOMPLETE',
            form_status='PASS',phases=phases,execution=dict(form_submitted=True,callback_observed=True,session_asserted=False,protected_routes_tested=0),
            limits=list(login.LIMITS),cleanup='closed'))
    report['identity_forms']=[dict(type='identity-form-suite',binding=copy.deepcopy(form['binding']),status='INCOMPLETE',form_status='PASS',
        identities=rows,session_coverage='NOT_RUN',authorization_coverage='NOT_RUN')]
    anonymous=dict(status='PASS',http_status=401,reason_code='EXPECTED_DENIAL')
    selected=private['public_plan_part'];ident=selected['identity_id']
    report['identity_policy_executions']=[dict(schema_version=1,type='identity-policy-suite',binding=copy.deepcopy(policy['binding']),
        identities=[dict(identity_id=ident,anonymous_session=copy.deepcopy(anonymous),session=dict(status='PASS',http_status=200,
            reason_code='SESSION_MATCHED',identity_matched=True,roles_matched=True),cleanup='closed')],
        cells=[dict(cell_id=cell['id'],identity_id=ident,anonymous=copy.deepcopy(anonymous),access=dict(status='PASS',http_status=200,
            reason_code='ACCESS_MATCHED',assertions_matched=True),result='PASS') for cell in policy['public_plan_part']['cells']])]


def fixture_report(state='pass'):
    report,private=fixture_input();selected=private['public_plan_part'];final_dependencies(report,private)
    suite=run._pending(selected);suite.update(schema_version=1,type='webauthn-suite',binding=copy.deepcopy(private['binding']))
    if state!='pending':
        suite['capability'].update(status='PASS',reason_code='VIRTUAL_AUTHENTICATOR_CREATED',authenticator_created=True,browser_version='130.0.6723.0')
        for key,reason in (('registration','REGISTRATION_VERIFIED'),('authentication','AUTHENTICATION_VERIFIED')):
            suite[key].update(status='PASS',reason_code=reason,options_http_status=200,http_status=200,
                credential_alias='credential-'+'d'*32,**{flag:True for flag in run.FLAGS})
        suite['logout'].update(status='PASS',reason_code='LOGOUT_SESSION_DENIED',request_observed=True,
            session_denial=dict(status='PASS',http_status=401,reason_code='EXPECTED_DENIAL'))
        suite['session_after_authentication'].update(status='PASS',http_status=200,reason_code='SESSION_MATCHED',identity_matched=True,roles_matched=True)
        for cell in suite['cells']:cell['access'].update(status='PASS',http_status=200,reason_code='ACCESS_MATCHED',assertions_matched=True)
        suite['cleanup']=dict(authenticator='removed',cdp='detached',page='closed',context='closed')
    if state=='partial_failure':
        suite['session_after_authentication'].update(status='FAIL',reason_code='SESSION_ROLES_MISMATCH',roles_matched=False)
        for cell in suite['cells']:cell['access'].update(status='BLOCKED',http_status=None,reason_code='SESSION_NOT_CONFIRMED',assertions_matched=None)
    elif state=='cleanup_unknown':suite['cleanup']['context']='unknown'
    elif state=='cell_failure':suite['cells'][0]['access'].update(status='FAIL',reason_code='ASSERTION_MISMATCH',assertions_matched=False)
    elif state not in ('pass','pending'):raise ValueError('unknown fixture state')
    report['webauthn_executions']=[suite]
    return report


class RuntimeWebAuthnRun(unittest.TestCase):
    def test_private_rebind_is_exact_and_immutable(self):
        report,value=fixture_input();before=copy.deepcopy((report,value))
        actual=run.build_webauthn_input(report,'frontend',value['webauthn'],value['policy_input'],webauthn_attempt_id=value['binding']['webauthn_attempt_id'])
        self.assertEqual(actual,value);self.assertEqual((report,value),before)
        self.assertEqual(value['limits'],{'accepted_json_bytes':1048576})
        self.assertIn('synthetic-private-password',json.dumps(value));self.assertNotIn('synthetic-private-password',json.dumps(report))
        self.assertNotIn('client_secret',json.dumps(value))

    def test_builder_and_reducer_are_pure(self):
        report,value=fixture_input();complete=fixture_report()
        with patch.object(builtins,'open',side_effect=AssertionError('file')),patch.object(socket,'socket',side_effect=AssertionError('network')),\
             patch.object(subprocess,'run',side_effect=AssertionError('process')),patch.object(os,'urandom',side_effect=AssertionError('random')),\
             patch.object(time,'time',side_effect=AssertionError('clock')):
            run.build_webauthn_input(report,'frontend',value['webauthn'],value['policy_input'],webauthn_attempt_id=value['binding']['webauthn_attempt_id'])
            self.assertEqual(run.project_webauthn_execution(complete)['status'],'PASS')

    def test_changed_private_inputs_and_owned_origin_are_rejected(self):
        changes=[lambda r,v:v['webauthn']['registration']['verify']['json'][0].update(equals_literal='PRIVATE_CANARY'),
            lambda r,v:v['policy_input']['policy']['cells'][0]['expected']['json'][0].update(equals_literal='PRIVATE_CANARY'),
            lambda r,v:v['policy_input']['form_input'].update(app_origin='https://localhost:44101'),
            lambda r,v:r.update(run_id='different-run'),lambda r,v:r['parts'][0]['transport'].update(status='starting'),
            lambda r,v:v['policy_input']['binding'].update(form_attempt_id='login-'+'e'*32)]
        for mutate in changes:
            report,value=fixture_input();mutate(report,value)
            with self.subTest(mutation=mutate),self.assertRaises(ValueError) as error:
                run.build_webauthn_input(report,'frontend',value['webauthn'],value['policy_input'],webauthn_attempt_id='webauthn-'+'c'*32)
            self.assertNotIn('PRIVATE_CANARY',str(error.exception))

    def test_config_only_flow_has_no_invented_inventory_entry(self):
        report,value=fixture_input(config_only=True)
        self.assertEqual(value['binding']['webauthn_integration_ids'],[])
        self.assertFalse(any(row['provider']=='webauthn' for row in report['integrations']['integrations']))

    def test_complete_selected_flow_is_separate_execution(self):
        report=fixture_report();before=copy.deepcopy(report);result=run.project_webauthn_execution(report)
        self.assertEqual((result['status'],result['execution_status'],result['coverage_status'],result['outcome']),('PASS','COMPLETE','RECORDED','PASS'))
        self.assertEqual(result['counts'],dict(required_flows=1,attempted_flows=1,completed_flows=1,registration_pass=1,authentication_pass=1,
            required_cells=1,completed_cells=1,passed_cells=1,failed_cells=0,blocked_cells=0,not_run_cells=0))
        self.assertEqual(report,before);self.assertEqual(plans.project_webauthn_plan(report)['execution_status'],'NOT_RUN')

    def test_known_empty_and_legacy_unknown_do_not_gain_credit(self):
        report,_=fixture_input();known=run.project_webauthn_execution(report)
        self.assertEqual(known['status'],'INCOMPLETE');self.assertEqual(known['counts']['completed_flows'],0)
        legacy=run.project_webauthn_execution({});self.assertEqual(legacy['status'],'NOT_RECORDED')
        self.assertTrue(all(value is None for value in legacy['counts'].values()))

    def test_capability_or_event_and_http_alone_never_complete_ceremony(self):
        for mutate in (lambda s:s['registration'].update(request_bound=False),lambda s:s['registration'].update(credential_observed=False,credential_alias=None),
                       lambda s:s['authentication'].update(credential_alias='credential-'+'e'*32),lambda s:s['logout']['session_denial'].update(http_status=200)):
            report=fixture_report();mutate(report['webauthn_executions'][0])
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):run.project_webauthn_execution(report)
        report=fixture_report('pending');suite=report['webauthn_executions'][0]
        suite['capability'].update(status='PASS',reason_code='VIRTUAL_AUTHENTICATOR_CREATED',authenticator_created=True)
        suite['cleanup'].update(authenticator='removed',cdp='detached',page='closed',context='closed')
        projected=run.project_webauthn_execution(report)
        self.assertEqual(projected['status'],'INCOMPLETE');self.assertEqual(projected['counts']['registration_pass'],0)

    def test_cleanup_unknown_preserves_observation_and_blocks_positive_credit(self):
        report=fixture_report('cleanup_unknown');result=run.project_webauthn_execution(report);row=result['parts'][0]
        self.assertEqual(result['status'],'INCOMPLETE');self.assertEqual(result['counts']['authentication_pass'],0)
        self.assertEqual(row['authentication']['status'],'BLOCKED');self.assertEqual(row['authentication']['observation_status'],'PASS')
        self.assertEqual(result['counts']['completed_flows'],0)

    def test_missing_final_dependencies_only_preserve_unknown_cleanup_observations(self):
        report=fixture_report('cleanup_unknown');report['identity_forms']=[]
        suite=report['identity_policy_executions'][0];suite['identities'][0]['cleanup']='unknown'
        for cell in suite['cells']:cell['result']='BLOCKED'
        self.assertEqual(run.project_webauthn_execution(report)['counts']['authentication_pass'],0)
        report['webauthn_executions'][0]['cleanup']['context']='closed'
        with self.assertRaises(ValueError):run.project_webauthn_execution(report)

    def test_executed_failure_survives_incomplete_phases_and_cleanup(self):
        report=fixture_report('partial_failure');result=run.project_webauthn_execution(report)
        self.assertEqual((result['status'],result['execution_status'],result['outcome']),('INCOMPLETE','INCOMPLETE','FAIL'))
        report['webauthn_executions'][0]['cleanup']['context']='unknown'
        self.assertEqual(run.project_webauthn_execution(report)['outcome'],'FAIL')
        complete=run.project_webauthn_execution(fixture_report('cell_failure'))
        self.assertEqual((complete['status'],complete['execution_status'],complete['outcome']),('FAIL','COMPLETE','FAIL'))

    def test_selected_sibling_remains_not_detected_and_all_receipts_are_validated(self):
        report,private=fixture_input(with_sibling=True)
        selected=run.project_webauthn_execution(report,['other'])
        self.assertEqual((selected['status'],selected['coverage_status']),('NOT_DETECTED','NOT_DETECTED'))
        self.assertEqual(selected['counts']['required_flows'],0)
        final_dependencies(report,private)
        suite=run._pending(private['public_plan_part']);suite.update(schema_version=1,type='webauthn-suite',binding=private['binding'])
        report['webauthn_executions']=[suite];self.assertEqual(run.project_webauthn_execution(report,['other'])['status'],'NOT_DETECTED')
        suite['binding']['form_attempt_id']='login-'+'f'*32
        with self.assertRaises(ValueError):run.project_webauthn_execution(report,['other'])

    def test_global_source_gap_preserves_partial_fail_without_aggregate_pass(self):
        for state,outcome in (('pass','UNKNOWN'),('cell_failure','FAIL')):
            report=fixture_report(state);report['integrations']['discovery']['errors']=[{'reason':'incomplete synthetic source snapshot'}]
            plan=report['webauthn_plan'];plan.update(status='BLOCKED',gaps=[plans._gap('SOURCE_SNAPSHOT_INCOMPLETE')])
            plan['plan_id']=plans._digest({key:value for key,value in plan.items() if key!='plan_id'})
            report['webauthn_executions'][0]['binding']['webauthn_plan_id']=plan['plan_id']
            result=run.project_webauthn_execution(report)
            self.assertEqual(result['status'],'INCOMPLETE');self.assertEqual(result['outcome'],outcome)

    def test_observed_logout_guard_failure_does_not_invent_session_denial(self):
        for reason in ('DUPLICATE_CEREMONY_REQUEST','REDIRECT_NOT_SUPPORTED'):
            report=fixture_report();suite=report['webauthn_executions'][0]
            selected=report['webauthn_plan']['parts'][0];pending=run._pending(selected)
            suite['logout'].update(status='FAIL',reason_code=reason,session_denial=pending['logout']['session_denial'])
            for key in ('authentication','session_after_authentication','cells'):suite[key]=pending[key]
            result=run.project_webauthn_execution(report)
            self.assertEqual((result['status'],result['outcome']),('INCOMPLETE','FAIL'))
            self.assertEqual(result['counts']['authentication_pass'],0)
            suite['logout']['request_observed']=False
            with self.assertRaises(ValueError):run.project_webauthn_execution(report)

    def test_foreign_binding_duplicate_suite_and_private_fields_are_rejected(self):
        mutations=[lambda r:r['webauthn_executions'][0]['binding'].update(run_id='old-run'),
            lambda r:r['webauthn_executions'][0]['binding'].update(form_attempt_id='login-'+'e'*32),
            lambda r:r['webauthn_executions'][0]['binding'].update(webauthn_config_hash='f'*64),
            lambda r:r['webauthn_executions'][0]['registration'].update(privateKey='PRIVATE_CANARY'),
            lambda r:r['webauthn_executions'][0]['capability'].update(authenticator_created=1),
            lambda r:r['webauthn_executions'].append(copy.deepcopy(r['webauthn_executions'][0]))]
        for mutate in mutations:
            report=fixture_report();mutate(report)
            with self.subTest(mutation=mutate),self.assertRaises(ValueError) as error:run.project_webauthn_execution(report)
            self.assertNotIn('PRIVATE_CANARY',str(error.exception))


if __name__=='__main__':unittest.main()
