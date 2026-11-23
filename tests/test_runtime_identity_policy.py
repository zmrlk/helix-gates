"""Explicit policy compilation, synthetic only and no execution credit."""
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
sys.path.insert(0,str(Path(os.environ.get('HELIX_SOURCE_ROOT',ROOT))/'bin'))
sys.path.insert(0,str(ROOT/'bin'))
import helix_runtime_identity as identity
import helix_runtime_identity_policy as policy


class RuntimeIdentityPolicy(unittest.TestCase):
    def setUp(self):
        self.sources={'frontend/src/auth.ts':'export const running=true;'};self.parts=[{'path':'frontend'}]
        values=dict(client_id='fixture-app',client_type='public',callback_paths=['/auth/callback'],login_path='/login',
                    pkce='S256',role_claim='realm_access.roles',roles=['reader','editor'])
        self.identities=identity.identity_plan({},self.parts,{'runtime':{'keycloak':{'parts':{'frontend':values}}}})
        self.raw=dict(basis='explicit_config',session=dict(path='/api/session',method='GET',http_status=200,
            anonymous={'kind':'status','codes':[401]},assertions=[{'pointer':'/user/name','equals_identity':'username'},
            {'pointer':'/user/roles','equals_identity':'app_roles','comparison':'set_exact'}]),cells=[self.cell()])
        self.config={'runtime':{'identity_policy':{'schema_version':1,'parts':{'frontend':self.raw}}}}

    def cell(self,role='reader',name='read-list',path='/api/items'):
        return dict(id=name,identity={'role':role},request={'method':'GET','path':path},anonymous={'kind':'status','codes':[401]},
                    expected={'access':'allow','http_status':200,'json':[{'pointer':'/kind','equals_literal':'PRIVATE_CANARY_ASSERTION'}]})

    def compile(self):return policy.policy_plan(self.sources,self.parts,self.identities,{'integrations':[]},self.config)

    def test_explicit_plan_binds_roles_locations_and_all_zero_execution(self):
        result=self.compile();row=result['parts'][0];cell=row['cells'][0]
        self.assertEqual(result['status'],'PLANNED');self.assertEqual(row['status'],'PLANNED')
        self.assertEqual(result['execution'],policy.EXECUTION)
        self.assertEqual(cell['role'],'reader');self.assertEqual(cell['identity_id'],'role-'+identity._digest('reader')[:12])
        self.assertEqual(cell['config_pointer'],'/runtime/identity_policy/parts/frontend/cells/0')
        self.assertEqual(cell['status'],'READY');self.assertEqual(cell['id'],policy.cell_id('frontend',cell))
        self.assertIn('no-app-role',row['unconfigured_identities']);self.assertIn('unverified-email',row['unconfigured_identities'])

    def test_public_plan_contains_only_literal_hash_and_private_config_immutable(self):
        before=copy.deepcopy((self.sources,self.parts,self.identities,self.config));result=self.compile()
        encoded=json.dumps(result);self.assertNotIn('PRIVATE_CANARY_ASSERTION',encoded)
        self.assertEqual(result['parts'][0]['cells'][0]['expected']['json'],[{'pointer':'/kind','kind':'literal','value_hash':identity._digest('PRIVATE_CANARY_ASSERTION')}])
        self.assertEqual((self.sources,self.parts,self.identities,self.config),before)

    def test_compiler_performs_no_io_network_process_or_entropy(self):
        with patch.object(builtins,'open',side_effect=AssertionError('I/O')),patch.object(Path,'read_text',side_effect=AssertionError('I/O')),\
             patch.object(socket,'socket',side_effect=AssertionError('network')),patch.object(subprocess,'run',side_effect=AssertionError('process')),\
             patch.object(subprocess,'Popen',side_effect=AssertionError('process')),patch.object(os,'urandom',side_effect=AssertionError('entropy')):
            self.assertEqual(self.compile(),self.compile())

    def test_same_route_for_two_roles_is_two_distinct_cells(self):
        self.raw['cells'].append(self.cell('editor','editor-list'))
        cells=self.compile()['parts'][0]['cells']
        self.assertEqual(len(cells),2);self.assertNotEqual(cells[0]['id'],cells[1]['id'])
        self.assertEqual(cells[0]['request'],cells[1]['request'])

    def test_duplicate_names_and_duplicate_semantics_are_errors(self):
        for second in (self.cell('editor','read-list'),self.cell('reader','other-label')):
            self.raw['cells']=[self.cell(),second]
            with self.assertRaises(ValueError):self.compile()

    def test_unknown_role_stays_blocked_without_exposing_unknown_raw_label(self):
        self.raw['cells'].append(self.cell('PRIVATE_CANARY_UNKNOWN_ROLE','unknown-role'))
        result=self.compile();cells=result['parts'][0]['cells']
        self.assertEqual(result['status'],'BLOCKED');self.assertEqual(len(cells),2)
        self.assertEqual(cells[1]['status'],'BLOCKED');self.assertIsNone(cells[1]['identity_id']);self.assertIsNone(cells[1]['role'])
        self.assertEqual(cells[1]['gaps'][0]['code'],'ROLE_NOT_DECLARED')
        self.assertNotIn('PRIVATE_CANARY_UNKNOWN_ROLE',json.dumps(result))

    def test_same_identity_route_cannot_have_conflicting_expectations(self):
        other=self.cell('reader','reader-denied')
        other['expected']={'access':'deny','denial':{'kind':'status','codes':[403]}}
        self.raw['cells'].append(other)
        with self.assertRaises(ValueError):self.compile()

    def test_unknown_part_and_missing_identity_remain_visible_blockers(self):
        self.config['runtime']['identity_policy']['parts']={'other':self.raw}
        result=self.compile();self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual([row['part'] for row in result['parts']],['frontend','other'])
        other=result['parts'][1];self.assertEqual(len(other['cells']),1)
        self.assertEqual({gap['code'] for gap in other['gaps']},{'PART_NOT_DECLARED','IDENTITY_PLAN_MISSING'})

    def test_missing_policy_and_no_identity_are_distinct(self):
        self.config={};result=self.compile()
        self.assertEqual(result['status'],'NOT_CONFIGURED');self.assertEqual(result['parts'][0]['cells'],[])
        self.identities=identity.identity_plan(self.sources,self.parts,{})
        self.assertEqual(self.compile()['status'],'NOT_DETECTED')

    def test_missing_session_identity_or_roles_assertion_is_blocked(self):
        original=copy.deepcopy(self.raw['session']['assertions'])
        for remaining,code in ((original[:1],'SESSION_ROLES_ASSERTION_MISSING'),(original[1:],'SESSION_IDENTITY_ASSERTION_MISSING')):
            self.raw['session']['assertions']=remaining;result=self.compile()
            self.assertEqual(result['status'],'BLOCKED');self.assertEqual(result['parts'][0]['gaps'][0]['code'],code)

    def test_hashes_change_for_sources_identity_policy_and_assertion_literal(self):
        baseline=self.compile();self.sources['frontend/src/auth.ts']+='changed'
        changed=self.compile();self.assertNotEqual(baseline['source_digest'],changed['source_digest']);self.assertNotEqual(baseline['plan_id'],changed['plan_id'])
        self.raw['cells'][0]['expected']['json'][0]['equals_literal']='different'
        changed=self.compile();self.assertNotEqual(baseline['parts'][0]['policy_hash'],changed['parts'][0]['policy_hash'])
        self.assertNotEqual(baseline['parts'][0]['cells'][0]['id'],changed['parts'][0]['cells'][0]['id'])

    def test_env_and_docs_are_not_source_evidence(self):
        baseline=self.compile();self.sources['frontend/.env']='REAL_SECRET=value';self.sources['docs/notes.md']='outsideactive'
        self.assertEqual(self.compile()['source_digest'],baseline['source_digest'])

    def test_unsafe_paths_wrong_types_and_unknown_fields_fail_without_values(self):
        original=copy.deepcopy(self.raw)
        mutations=[lambda: self.raw['session'].update(http_status=True),lambda:self.raw['session'].update(method='POST'),
            lambda:self.raw['cells'][0]['request'].update(path='//outside.invalid'),lambda:self.raw['cells'][0]['request'].update(path='/a/../b'),
            lambda:self.raw['cells'][0]['request'].update(path='/a?token=PRIVATE_CANARY'),lambda:self.raw['cells'][0]['expected'].update(ui='PRIVATE_CANARY'),
            lambda:self.raw['cells'][0]['anonymous'].update(codes=[302]),lambda:self.raw['cells'][0]['identity'].update(variant='no-app-role'),
            lambda:self.raw['session']['assertions'][0].update(pointer='/__proto__/x')]
        for mutate in mutations:
            self.raw.clear();self.raw.update(copy.deepcopy(original));mutate()
            with self.subTest(mutate=mutate),self.assertRaises(ValueError) as error:self.compile()
            self.assertNotIn('PRIVATE_CANARY',str(error.exception))

    def test_deny_uses_only_declared_401_or_403(self):
        self.raw['cells'][0]['expected']={'access':'deny','denial':{'kind':'status','codes':[403]}}
        self.assertEqual(self.compile()['parts'][0]['cells'][0]['expected']['denial']['codes'],[403])
        self.raw['cells'][0]['expected']['denial']['codes']=[500]
        with self.assertRaises(ValueError):self.compile()

    def test_literal_types_are_cross_language_canonical(self):
        row=self.raw['cells'][0]['expected']['json'][0]
        for value in ('',True,False,None,17,-17):
            row['equals_literal']=value;self.assertEqual(self.compile()['status'],'PLANNED')
        for value in (1.5,float('nan'),[],{},9007199254740992):
            row['equals_literal']=value
            with self.subTest(value=value),self.assertRaises(ValueError):self.compile()

    def test_invalid_rehashed_identity_shapes_do_not_create_cells(self):
        declaration=self.identities['parts'][0];declaration['identities'][0]['id']='PRIVATE_CANARY'
        bound=dict(declaration);bound.pop('plan_id');declaration['plan_id']=identity._digest(bound)
        with self.assertRaises(ValueError) as error:self.compile()
        self.assertNotIn('PRIVATE_CANARY',str(error.exception))


if __name__=='__main__':unittest.main()
