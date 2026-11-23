"""WebAuthn plans from existing snapshots, with no execution or I/O."""
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

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_runtime_identity as identity
import helix_runtime_identity_policy as policy
import helix_runtime_integrations as inventory
import helix_runtime_transport as transport
import helix_runtime_webauthn as webauthn


def fixture_inputs(state='planned'):
    sources={'frontend/package.json':json.dumps({'dependencies':{'@simplewebauthn/browser':'^13.3.0'}}),
             'frontend/src/app.ts':'export const localFixture = true;'}
    parts=[{'path':'frontend'}]
    cfg={'runtime':{'https':{'enabled':True,'public_host':'localhost'},'keycloak':{'parts':{'frontend':dict(
        client_id='synthetic-app',client_type='public',login_path='/login',callback_paths=['/auth/callback'],
        pkce='S256',role_claim='realm_access.roles',roles=['reader'])}},'identity_policy':{'schema_version':1,'parts':{
        'frontend':dict(basis='explicit_config',session=dict(path='/api/session',method='GET',http_status=200,
            anonymous=dict(kind='status',codes=[401]),assertions=[dict(pointer='/user/name',equals_identity='username'),
                dict(pointer='/user/roles',equals_identity='app_roles',comparison='set_exact')]),cells=[dict(
            id='items',identity=dict(role='reader'),request=dict(method='GET',path='/api/items'),anonymous=dict(kind='status',codes=[401]),
            expected=dict(access='allow',http_status=200,json=[dict(pointer='/kind',equals_literal='items')]))])}}}}
    ids=identity.identity_plan(sources,parts,cfg);inv=inventory.inventory(sources,parts,cfg)
    tls=transport.transport_plan(sources,parts,inv,cfg);pol=policy.policy_plan(sources,parts,ids,inv,cfg)
    def flow(name):
        return dict(path='/passkeys/'+name,action=dict(test_id='passkey-'+name),options=dict(method='POST',path='/api/passkeys/'+name+'/options'),
            verify=dict(method='POST',path='/api/passkeys/'+name+'/verify',http_status=200,json=[dict(pointer='/verified',equals_literal=True)]))
    raw=dict(enabled=True,rp_owner='application',rp_id='localhost',role='reader',policy_cell_ids=[pol['parts'][0]['cells'][0]['id']],
             registration=flow('register'),authentication=flow('authenticate'),
             logout=dict(path='/account',action=dict(test_id='logout'),request=dict(method='POST',path='/auth/logout')))
    if state!='dependency':cfg['runtime']['webauthn']={'schema_version':1,'parts':{'frontend':{'enabled':False} if state=='disabled' else raw}}
    return sources,parts,inv,ids,tls,pol,cfg


def fixture_report(state='planned'):
    args=fixture_inputs(state)
    return dict(parts=args[1],integrations=args[2],identity_plan=args[3],transport_plan=args[4],identity_policy_plan=args[5],
                identity_policy_receipts=[],webauthn_plan=webauthn.webauthn_plan(*args),webauthn_receipts=[])


class RuntimeWebAuthn(unittest.TestCase):
    def test_planned_uses_existing_bindings_and_preserves_locations(self):
        report=fixture_report();plan=report['webauthn_plan'];view=webauthn.project_webauthn_plan(report)
        self.assertEqual(plan['status'],'PLANNED');self.assertEqual(view['coverage_status'],'INCOMPLETE')
        self.assertEqual(view['counts']['identities_planned'],1);self.assertEqual(view['counts']['ceremonies_executed'],0)
        declaration=view['parts'][0]['declarations'][0]
        self.assertEqual(declaration['declared_versions'],['^13.3.0'])
        self.assertEqual(declaration['evidence'][0]['path'],'frontend/package.json')
        self.assertEqual(plan['parts'][0]['profile'],webauthn.PROFILE)

    def test_dependency_disabled_and_legacy_are_distinct(self):
        for state,expected in (('dependency','BLOCKED'),('disabled','DISABLED')):
            view=webauthn.project_webauthn_plan(fixture_report(state))
            self.assertEqual(view['plan_status'],expected);self.assertEqual(view['execution_status'],'NOT_RUN')
            self.assertIn('DEPENDENCY_WITHOUT_FLOW_CONTRACT',json.dumps(view))
        legacy=webauthn.project_webauthn_plan({})
        self.assertEqual(legacy['plan_status'],'NOT_RECORDED');self.assertIsNone(legacy['counts']['parts'])

    def test_partial_config_is_blocked_with_exact_pointer(self):
        args=fixture_inputs();args[-1]['runtime']['webauthn']['parts']['frontend']={'enabled':True}
        result=webauthn.webauthn_plan(*args)
        self.assertEqual(result['status'],'BLOCKED')
        self.assertIn({'code':'CONTRACT_FIELD_MISSING','config_pointer':'/runtime/webauthn/parts/frontend/registration'},result['parts'][0]['gaps'])
        report=fixture_report();report['webauthn_plan']=result
        self.assertEqual(webauthn.project_webauthn_plan(report)['plan_status'],'BLOCKED')

    def test_missing_nested_contract_field_has_its_pointer(self):
        args=fixture_inputs();args[-1]['runtime']['webauthn']['parts']['frontend']['registration']['verify'].pop('http_status')
        plan=webauthn.webauthn_plan(*args)
        self.assertIn({'code':'CONTRACT_FIELD_MISSING','config_pointer':'/runtime/webauthn/parts/frontend/registration/verify/http_status'},plan['parts'][0]['gaps'])
        report=fixture_report();report['webauthn_plan']=plan;webauthn.project_webauthn_plan(report)

    def test_empty_action_points_to_missing_test_id(self):
        args=fixture_inputs();args[-1]['runtime']['webauthn']['parts']['frontend']['registration']['action']={}
        plan=webauthn.webauthn_plan(*args)
        self.assertIn({'code':'CONTRACT_FIELD_MISSING','config_pointer':'/runtime/webauthn/parts/frontend/registration/action/test_id'},plan['parts'][0]['gaps'])
        report=fixture_report();report['webauthn_plan']=plan;webauthn.project_webauthn_plan(report)

    def test_changed_sources_cannot_borrow_stale_policy_snapshot(self):
        args=fixture_inputs();args[0]['frontend/src/app.ts']='changed source'
        with self.assertRaises(ValueError):webauthn.webauthn_plan(*args)
        report=fixture_report();plan=report['webauthn_plan'];plan['source_digest']='f'*64
        plan['plan_id']=identity._digest({key:value for key,value in plan.items() if key!='plan_id'})
        with self.assertRaises(ValueError):webauthn.project_webauthn_plan(report)

    def test_development_dependency_is_preserved_as_declaration(self):
        args=list(fixture_inputs('dependency'))
        args[0]['frontend/package.json']=json.dumps({'devDependencies':{'@simplewebauthn/browser':'^13.3.0'}})
        args[2]=inventory.inventory(args[0],args[1],args[6]);args[4]=transport.transport_plan(args[0],args[1],args[2],args[6])
        args[5]=policy.policy_plan(args[0],args[1],args[3],args[2],args[6])
        self.assertEqual(webauthn.webauthn_plan(*args)['parts'][0]['declarations'][0]['evidence'][0]['kind'],'package_devDependencies')

    def test_null_config_and_nonboolean_public_profile_are_rejected(self):
        args=fixture_inputs();args[-1]['runtime']['webauthn']=None
        with self.assertRaises(ValueError):webauthn.webauthn_plan(*args)
        report=fixture_report();plan=report['webauthn_plan'];plan['parts'][0]['profile']['hasResidentKey']=1
        plan['plan_id']=identity._digest({key:value for key,value in plan.items() if key!='plan_id'})
        with self.assertRaises(ValueError):webauthn.project_webauthn_plan(report)

    def test_no_io_or_mutation_and_env_values_do_not_change_digest(self):
        args=fixture_inputs();before=copy.deepcopy(args)
        with patch.object(builtins,'open',side_effect=AssertionError('I/O')),patch.object(subprocess,'run',side_effect=AssertionError('process')),\
             patch.object(socket,'socket',side_effect=AssertionError('network')),patch.object(os,'urandom',side_effect=AssertionError('random')):
            first=webauthn.webauthn_plan(*args)
        self.assertEqual(args,before)
        args[0]['frontend/.env']='PASSWORD=NEVER_READ';args[0]['docs/private.md']='irrelevant'
        self.assertEqual(webauthn.webauthn_plan(*args)['source_digest'],first['source_digest'])

    def test_unsupported_owner_and_rp_are_visible_without_echoing_unknown_rp(self):
        args=fixture_inputs();raw=args[-1]['runtime']['webauthn']['parts']['frontend']
        raw['rp_owner']='keycloak';raw['rp_id']='private-domain-canary.invalid'
        result=webauthn.webauthn_plan(*args);self.assertEqual(result['status'],'BLOCKED')
        self.assertNotIn('private-domain-canary',json.dumps(result))
        report=fixture_report();report['webauthn_plan']=result
        self.assertEqual(webauthn.project_webauthn_plan(report)['plan_status'],'BLOCKED')

    def test_assertion_secret_never_appears_in_public_plan(self):
        args=fixture_inputs();raw=args[-1]['runtime']['webauthn']['parts']['frontend']
        raw['authentication']['verify']['json'][0]['equals_literal']='PRIVATE_ASSERTION_CANARY'
        plan=webauthn.webauthn_plan(*args);self.assertNotIn('PRIVATE_ASSERTION_CANARY',json.dumps(plan))
        report=fixture_report();report['webauthn_plan']=plan;self.assertNotIn('PRIVATE_ASSERTION_CANARY',json.dumps(webauthn.project_webauthn_plan(report)))

    def test_forged_summary_omission_and_raw_values_are_rejected(self):
        for mutate in (lambda p:p['parts'].clear(),lambda p:p['parts'][0].update(identity_id='role-000000000000'),
                       lambda p:p['parts'][0]['authentication']['verify']['json'][0].update(equals_literal='LEAK'),
                       lambda p:p['execution'].update(commands=True)):
            report=fixture_report();plan=report['webauthn_plan'];mutate(plan)
            plan['plan_id']=identity._digest({key:value for key,value in plan.items() if key!='plan_id'})
            with self.assertRaises(ValueError):webauthn.project_webauthn_plan(report)

    def test_runtime_inventory_changes_do_not_invalidate_static_binding(self):
        report=fixture_report();report['integrations']=inventory.execution_inventory(report['integrations'],[],run_id='synthetic-run')
        self.assertEqual(webauthn.project_webauthn_plan(report)['plan_status'],'PLANNED')

    def test_selected_sibling_does_not_inherit_another_parts_requirement(self):
        args=list(fixture_inputs());args[0]['other/src/app.ts']='export const sibling=true;';args[1].append({'path':'other'})
        args[2]=inventory.inventory(args[0],args[1],args[6]);args[3]=identity.identity_plan(args[0],args[1],args[6])
        args[4]=transport.transport_plan(args[0],args[1],args[2],args[6]);args[5]=policy.policy_plan(args[0],args[1],args[3],args[2],args[6])
        report=dict(parts=args[1],integrations=args[2],identity_plan=args[3],transport_plan=args[4],identity_policy_plan=args[5],
                    webauthn_plan=webauthn.webauthn_plan(*args),webauthn_receipts=[])
        self.assertEqual(webauthn.project_webauthn_plan(report)['plan_status'],'PLANNED')
        sibling=webauthn.project_webauthn_plan(report,['other'])
        self.assertEqual(sibling['plan_status'],'NOT_DETECTED');self.assertEqual(sibling['coverage_status'],'NOT_DETECTED')
        self.assertEqual(sibling['parts'],[]);self.assertEqual(sibling['counts']['parts'],0)

    def test_receipts_and_incomplete_report_are_not_legacy(self):
        report=fixture_report();report['webauthn_receipts']=[{'status':'PASS'}]
        with self.assertRaises(ValueError):webauthn.project_webauthn_plan(report)
        with self.assertRaises(ValueError):webauthn.project_webauthn_plan({'webauthn_receipts':[]})


if __name__=='__main__':unittest.main()
