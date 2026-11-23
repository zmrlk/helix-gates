"""Transport declaration fixtures, zero application/process/network execution."""
import builtins
import copy
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_transport as transport
from helix_runtime_integrations import inventory


class RuntimeTransportTests(unittest.TestCase):
    def plan(self, source='', *, sources=None, settings=None, parts=None):
        sources = sources if sources is not None else {'app/auth.ts': source}
        parts = parts if parts is not None else [{'path': 'app'}]
        config = {'runtime': {'https': settings}} if settings is not None else {}
        return transport.transport_plan(sources, parts, inventory(sources, parts), config)

    def requirement(self, source, *, suffix='ts'):
        result = self.plan(sources={'app/auth.' + suffix: source})
        return result['parts'][0]['requirements']

    def test_keycloak_default_requires_https_and_never_claims_execution(self):
        result = self.plan("import Keycloak from 'keycloak-js';")
        part = result['parts'][0]
        self.assertEqual((part['selected'], part['selection'], part['status']), ('http', 'default', 'INCOMPLETE'))
        self.assertTrue(part['https_needed']); self.assertEqual(part['ports'], 'allocated_at_runtime')
        self.assertIn('https_not_enabled', [gap['kind'] for gap in part['gaps']])
        self.assertEqual(result['execution'], dict(files_opened=0, commands=0, models=0, network=0, application=False))
        self.assertEqual(part['execution'], 'not_run')

    def test_explicit_false_is_preserved_and_true_does_not_claim_readiness(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                result = self.plan("import Keycloak from 'keycloak-js';", settings={'enabled': enabled})
                part = result['parts'][0]
                self.assertEqual(part['selected'], 'https' if enabled else 'http')
                self.assertEqual(part['selection'], 'explicit')
                self.assertEqual(part['status'], 'PLANNED' if enabled else 'INCOMPLETE')
                self.assertEqual(part['execution'], 'not_run')
                self.assertTrue(any('localhost' in line for line in part['limits']))

    def test_invalid_config_rejected_without_reflecting_values(self):
        for setting in (True, [], {'enabled': 'SECRET'}, {'public_host': 'private.example'},
                        {'enabled': 1}, {'secret': 'PRIVATE_VALUE'}):
            with self.subTest(setting=setting), self.assertRaises(ValueError) as caught:
                self.plan(settings=setting)
            self.assertNotIn('SECRET', str(caught.exception)); self.assertNotIn('PRIVATE_VALUE', str(caught.exception))

    def test_secure_setter_location_multiline_quoted_property_and_conditional(self):
        source="""function login(cookies) {
 cookies.set('sid', token, {
   'secure': true,
   httpOnly: true
 });
 response.cookies.set({name: 'other', value: token, secure: !dev});
} """
        rows = self.requirement(source)
        self.assertEqual([(row['basis'], row['line']) for row in rows], [('conditional_setting', 6), ('explicit_setting', 3)])
        self.assertTrue(all(row['path'] == 'app/auth.ts' for row in rows))

    def test_false_and_unrelated_secure_objects_strings_and_comments_do_not_match(self):
        source="""const x = {secure: true};
 const quoted = "cookies.set('sid', token, {secure:true})";
 // response.cookies.set({secure: true});
 /* res.cookie('sid', token, {secure:true}); */
 cookies.set('sid', token, {secure: false});
 const stringSecure = 'secure: true';
"""
        self.assertEqual(self.requirement(source), [])

    def test_cookie_prefix_and_object_form_require_https_without_exposing_name_or_value(self):
        rows = self.requirement("cookies.set('__Host-private-name', 'SECRET_VALUE', {secure:false}); response.cookies.set({name:'__Secure-another',value:'OTHER_VALUE',secure:false});")
        self.assertEqual(len(rows), 1)  # Same signal and source line is one location.
        self.assertEqual(rows[0]['basis'], 'cookie_prefix')
        self.assertNotIn('private-name', json.dumps(rows)); self.assertNotIn('SECRET_VALUE', json.dumps(rows))

    def test_unresolved_cookie_options_remain_a_gap(self):
        part = self.plan("cookies.set('sid', value, makeOptions());")['parts'][0]
        self.assertFalse(part['https_needed'])
        self.assertEqual(part['status'], 'INCOMPLETE')
        self.assertIn('cookie_options_unresolved', [gap['kind'] for gap in part['gaps']])

    def test_cookie_serialize_requires_known_import_and_alias(self):
        source="import {serialize as cookieText} from 'cookie';\ncookieText('sid', token, {secure:true});\nserialize('sid', token, {secure:true});"
        rows = self.requirement(source)
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['line'], 2)
        self.assertEqual(self.requirement("serialize('sid', token, {secure:true});"), [])

    def test_express_session_secure_cookie_nested_options_only(self):
        source="import session from 'express-session';\napp.use(session({secret:'SECRET_VALUE', cookie:{secure:true}}));"
        rows = self.requirement(source)
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['line'], 2)
        self.assertNotIn('SECRET_VALUE', json.dumps(rows))
        self.assertEqual(self.requirement("session({cookie:{secure:true}})"), [])

    def test_set_cookie_header_is_contextual_and_never_keeps_value(self):
        rows = self.requirement("response.headers.append('Set-Cookie', 'sid=SECRET; HttpOnly; Secure; SameSite=Lax');")
        self.assertEqual(rows[0]['basis'], 'literal_cookie_header')
        self.assertNotIn('SECRET', json.dumps(rows))
        self.assertEqual(self.requirement("other.set('Set-Cookie','sid=x; Secure');"), [])
        self.assertEqual(self.requirement("response.setHeader('Set-Cookie','sid=Secure');"), [])

    def test_python_cookie_and_settings_true_false_and_dynamic(self):
        source="""response.set_cookie('sid', value, secure=True)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = os.getenv('PRIVATE_FLAG')
response.set_cookie('other', value, secure=False)
# SESSION_COOKIE_SECURE = True
text = 'response.set_cookie(secure=True)'
"""
        rows = self.requirement(source, suffix='py')
        self.assertEqual(len(rows), 3)
        self.assertEqual(sorted(row['line'] for row in rows), [1, 2, 3])
        self.assertNotIn('PRIVATE_FLAG', json.dumps(rows))

    def test_public_key_operation_and_unknown_credentials_are_distinct(self):
        known = self.plan("\nnavigator.credentials.get({publicKey: options});")['parts'][0]
        self.assertIn('public_key_operation', [row['basis'] for row in known['requirements']])
        self.assertTrue(any(row.get('line') == 2 for row in known['requirements']))
        unknown = self.plan("navigator.credentials.get(options);")['parts'][0]
        self.assertIn('possible_browser_credentials', [row['basis'] for row in unknown['requirements']])
        self.assertIn('credentials_options_unresolved', [gap['kind'] for gap in unknown['gaps']])

    def test_webauthn_package_is_a_declaration_not_a_completed_ceremony(self):
        sources = {'app/package.json': json.dumps({'dependencies': {'@simplewebauthn/browser': '^13.0.0'}})}
        part = self.plan(sources=sources)['parts'][0]
        self.assertTrue(part['https_needed']); self.assertEqual(part['execution'], 'not_run')
        self.assertIn('webauthn', [row['kind'] for row in part['requirements']])

    def test_ip_profile_cannot_claim_suitable_rp_domain(self):
        source="navigator.credentials.create({publicKey: options});"
        part = self.plan(source, settings={'enabled': True, 'public_host': '127.0.0.1'})['parts'][0]
        self.assertEqual(part['selected'], 'https'); self.assertEqual(part['public_host'], '127.0.0.1')
        self.assertIn('webauthn_rp_host', [gap['kind'] for gap in part['gaps']])
        localhost = self.plan(source, settings={'enabled': True})['parts'][0]
        self.assertNotIn('webauthn_rp_host', [gap['kind'] for gap in localhost['gaps']])

    def test_docs_legacy_tests_and_real_env_never_activate_runtime_requirements(self):
        sources = {'app/main.ts': 'export const value = 1;', 'docs/login.md': "cookies.set('a',b,{secure:true})",
                   'app/legacy/auth.ts': "import Keycloak from 'keycloak-js';", 'app/tests/passkey.ts': 'navigator.credentials.get({publicKey:x})',
                   'app/.env': 'PRIVATE_SECRET=CANARY_VALUE'}
        result = self.plan(sources=sources)
        self.assertEqual(result['parts'][0]['requirements'], [])
        self.assertEqual(len(result['excluded']), 4)
        self.assertNotIn('CANARY_VALUE', json.dumps(result))

    def test_shared_import_scopes_to_referencing_app_and_preserves_multiple_locations(self):
        sources = {'apps/a/main.ts': "import {login} from '../../shared/auth';", 'apps/b/main.ts': 'export const b=1;',
                   'shared/auth.ts': "cookies.set('one', a, {secure:true});\ncookies.set('two',b,{secure:!dev});"}
        result = self.plan(sources=sources, parts=[{'path':'apps/a'}, {'path':'apps/b'}])
        first, second = result['parts']
        self.assertEqual([row['line'] for row in first['requirements']], [2, 1])
        self.assertTrue(first['https_needed']); self.assertFalse(second['https_needed'])

    def test_nearest_monorepo_root_prevents_parent_from_claiming_child(self):
        sources={'main.ts':'export const x=1;', 'app/main.ts':"cookies.set('sid', x, {secure:true});"}
        result=self.plan(sources=sources,parts=[{'path':'.'},{'path':'app'}])
        self.assertFalse(result['parts'][0]['https_needed']);self.assertTrue(result['parts'][1]['https_needed'])

    def test_unrelated_database_import_is_not_a_transport_gap(self):
        part=self.plan("import db from '$lib/database'; db.query('select 1');")['parts'][0]
        self.assertEqual(part['status'],'PLANNED');self.assertEqual(part['gaps'],[])

    def test_missing_sources_and_unresolved_import_are_explicit_gaps(self):
        empty = self.plan(sources={})
        self.assertEqual(empty['status'], 'INCOMPLETE'); self.assertEqual(empty['gaps'][0]['kind'], 'source_unavailable')
        part = self.plan("import options from './missing'; cookies.set('x', y, options);")['parts'][0]
        self.assertIn('local_import_unresolved', [row['kind'] for row in part['gaps']])

    def test_hash_is_deterministic_binds_config_and_source_but_ignores_real_env_values(self):
        sources={'app/a.ts':"cookies.set('sid',token,{secure:true});",'app/.env':'PRIVATE=ONE'}
        initial=self.plan(sources=sources)
        self.assertEqual(initial['plan_id'], self.plan(sources=dict(reversed(list(sources.items()))))['plan_id'])
        sources['app/.env']='PRIVATE=TWO'
        self.assertEqual(initial['plan_id'],self.plan(sources=sources)['plan_id'])
        self.assertNotEqual(initial['plan_id'],self.plan(sources=sources,settings={'enabled':False})['plan_id'])
        sources['app/a.ts']+='\n// different snapshot'
        self.assertNotEqual(initial['plan_id'],self.plan(sources=sources)['plan_id'])

    def test_simple_cookie_alias_is_detected_without_running_the_alias(self):
        part=self.plan("const jar=cookies; jar.set('sid',token,{secure:true});")['parts'][0]
        self.assertTrue(part['https_needed'])
        self.assertIn('explicit_setting',[row['basis'] for row in part['requirements']])
        self.assertEqual(part['execution'],'not_run')

    def test_own_local_cookie_method_does_not_propose_https(self):
        part=self.plan("const value={cookie(){return 1}}; value.cookie('sid',token,{secure:true});")['parts'][0]
        self.assertFalse(part['https_needed']);self.assertEqual(part['requirements'],[])
        self.assertNotIn('cookie_receiver_unresolved',[gap['kind'] for gap in part['gaps']])

    def test_unknown_receiver_and_reassigned_alias_stay_candidates_not_tls_proposals(self):
        for source in ("response.cookie('sid',token,{secure:true});",
                       "const jar=cookies; jar=unknown(); jar.set('sid',token,{secure:true});",
                       "const jar=cookies; function nested(jar){jar.set('sid',token,{secure:true});}"):
            with self.subTest(source=source):
                part=self.plan(source)['parts'][0]
                self.assertFalse(part['https_needed']);self.assertEqual(part['status'],'INCOMPLETE')
                self.assertIn('cookie_receiver_unresolved',[gap['kind'] for gap in part['gaps']])

    def test_shadowed_cookies_local_set_method_is_not_framework_cookie(self):
        part=self.plan("const cookies={set(){return 1}}; cookies.set('sid',token,{secure:true});")['parts'][0]
        self.assertFalse(part['https_needed']);self.assertEqual(part['requirements'],[])

    def test_spread_computed_or_shorthand_cookie_options_are_explicitly_unresolved(self):
        for options in ('{secure:false, ...other}', '{[setting]:true}', '{secure}'):
            with self.subTest(options=options):
                part=self.plan("cookies.set('sid',token,"+options+");")['parts'][0]
                self.assertEqual(part['status'],'INCOMPLETE')
                self.assertIn('dynamic_object_properties',[gap.get('basis') for gap in part['gaps']])

    def test_malformed_source_and_part_fail_closed_without_values_in_output(self):
        clean_inventory={'integrations':[]}
        for sources in ({None:'SECRET_VALUE'}, {'../SECRET_VALUE.ts':'x'}, {'app/a.ts':None}):
            with self.subTest(sources=sources):
                result=transport.transport_plan(sources,[{'path':'app'}],clean_inventory)
                self.assertEqual(result['status'],'INCOMPLETE');self.assertNotIn('SECRET_VALUE',json.dumps(result))
        for parts in ([{}],[{'path':None}],[{'path':'../SECRET_VALUE'}]):
            with self.subTest(parts=parts),self.assertRaises(ValueError) as caught:
                transport.transport_plan({},parts,clean_inventory)
            self.assertNotIn('SECRET_VALUE',str(caught.exception))

    def test_malformed_integration_evidence_fails_closed(self):
        for evidence in (None,[{}],[{'path':None,'line':1}],[{'path':'app/a.ts','line':True}]):
            malformed={'integrations':[dict(provider='keycloak',area='active',parts=['app'],evidence=evidence)]}
            with self.subTest(evidence=evidence),self.assertRaises(ValueError):
                transport.transport_plan({'app/a.ts':'x'},[{'path':'app'}],malformed)

    def test_empty_sibling_app_remains_incomplete(self):
        result=self.plan(sources={'apps/a/main.ts':'export const x=1'},parts=[{'path':'apps/a'},{'path':'apps/b'}])
        self.assertEqual(result['parts'][1]['status'],'INCOMPLETE')
        self.assertIn('part_sources_unavailable',[gap['kind'] for gap in result['parts'][1]['gaps']])

    def test_does_not_mutate_inputs_or_open_probe_execute_import_project(self):
        sources={'app/a.ts':"import Keycloak from 'keycloak-js'; cookies.set('sid',token,{secure:true});"}
        parts=[{'path':'app'}];cfg={'runtime':{'https':{'enabled':True}}};integrations=inventory(sources,parts)
        before=copy.deepcopy((sources,parts,integrations,cfg))
        with patch.object(builtins,'open',side_effect=AssertionError('file I/O')), \
             patch.object(Path,'read_text',side_effect=AssertionError('file I/O')), \
             patch.object(subprocess,'run',side_effect=AssertionError('process')), \
             patch.object(subprocess,'Popen',side_effect=AssertionError('process')), \
             patch.object(socket,'socket',side_effect=AssertionError('network')):
            result=transport.transport_plan(sources,parts,integrations,cfg)
        self.assertEqual(before,(sources,parts,integrations,cfg));self.assertFalse(result['execution']['application'])


if __name__=='__main__':unittest.main()
