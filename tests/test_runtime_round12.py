"""Offline URL destination regressions; no live identity provider required."""
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime as rt


class RoundTwelveTests(unittest.TestCase):
    def test_public_app_url_remains_redirect_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            runner=object.__new__(rt.Runner)
            runner.oidc_stub=True
            runner.active_transport=None
            runner.tools={'openssl':'/fake/openssl','node':'/fake/node'}
            runner.tmp=runner.work=runner.out=Path(directory)
            runner.port_factory=lambda:9443
            runner.command=Mock()
            runner.executor=Mock()
            runner.cleanup_actions=[]
            runner.network_connect_ports=set()
            runner.owned_preloads=[]
            runner.budget=Mock()
            names=['PUBLIC_APP_URL','KC_URL','KC_REALM']
            part={'env':[dict(name=n,classification=rt.classification(n)) for n in names], 'oidc_dependencies':names}
            runner.env=rt.dummy_env(part,'postgresql://localhost/db',3000)
            runner.oidc(part)
            redirect_uri=runner.env['PUBLIC_APP_URL']+'/auth/callback'
            self.assertEqual(redirect_uri,'http://127.0.0.1:3000/auth/callback')
            self.assertEqual(runner.env['KC_URL'],'https://127.0.0.1:9443')
            self.assertEqual(runner.env['KC_REALM'],'synthetic')
            self.assertEqual(part['oidc_stub']['variable_roles'],dict(PUBLIC_APP_URL='app-url',KC_URL='issuer',KC_REALM='idp-path'))

    def test_app_names_and_callback_paths(self):
        names=['PUBLIC_APP_URL','PUBLIC_URL','SITE_URL','BASE_URL','ORIGIN','NEXTAUTH_URL','AUTH_URL','OIDC_REDIRECT_URI','AUTH_CALLBACK_URL']
        spec={'env':[dict(name=n,classification=rt.classification(n),example='https://example.invalid/auth/callback?secret=hidden') for n in names]}
        env=rt.dummy_env(spec,'postgresql://localhost/db',3000)
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(rt.url_role(name),'app-url')
                self.assertEqual(env[name],'http://127.0.0.1:3000'+('/auth/callback' if 'REDIRECT_URI' in name or 'CALLBACK_URL' in name else ''))
        for name in ['OIDC_BASE_URL','AUTH_BASE_URL','KC_BASE_URL','ISSUER_URL','IDP_BASE_URL']:
            self.assertEqual(rt.url_role(name),'issuer')

    def test_stub_404_names_suspect_and_assigned_role_only(self):
        reason=rt.stub_404_reason([dict(status=404,source='stub')],{'PUBLIC_APP_URL':'app-url','KC_URL':'issuer'})
        self.assertIn('PUBLIC_APP_URL (assigned app-url)',reason)
        self.assertIn('ASSUMPTION',reason)
        self.assertEqual(rt.stub_404_reason([dict(status=404,source='app')],{'PUBLIC_APP_URL':'app-url'}),'')

    def test_other_services_base_url_is_not_application_origin(self):
        names=['AI_BASE_URL','PAYMENT_BASE_URL','IDENTITY_BASE_URL']
        env=rt.dummy_env({'env':[dict(name=n,classification=rt.classification(n)) for n in names]},'postgresql://localhost/db',3000)
        for name in names:
            self.assertNotEqual(rt.url_role(name),'app-url')
            self.assertEqual(env[name],'http://127.0.0.1:1')
