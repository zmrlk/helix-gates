"""Actual JS sink/adapter through a fake transport; no sockets or SDK install."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from test_runtime_sinks import fixture_input
import helix_runtime_sinks as sinks

ROOT=Path(__file__).resolve().parents[1]
DRIVER=ROOT/'tests/fixtures/runtime-sinks-fake.cjs'
TOKEN='PRIVATE_TOKEN_CANARY_26'
CONTENT='PRIVATE_MESSAGE_CANARY_26'


class RuntimeSinksSecurity(unittest.TestCase):
    def setUp(self):
        self.report,self.input=fixture_input()

    def call(self,action='fetch',**extra):
        node=shutil.which('node');self.assertIsNotNone(node)
        value=dict(input=self.input,action=action,**extra)
        completed=subprocess.run([node,str(DRIVER)],input=json.dumps(value),capture_output=True,text=True,timeout=8)
        self.assertEqual(completed.returncode,0,completed.stderr)
        return json.loads(completed.stdout)

    def project(self,result):
        report=copy.deepcopy(self.report);report['sink_observations']=[result['snapshot']]
        return sinks.project_sinks(report)

    def assert_private(self,result):
        public=json.dumps(dict(snapshot=result['snapshot'],publications=result['publications'],projection=self.project(result)))
        for text in (TOKEN,CONTENT,self.input['bearer_token'],self.input['mailbox_path']):self.assertNotIn(text,public)

    def test_supported_provider_operations_reach_real_handler_without_delivery_credit(self):
        cases=[('resend.send','https://api.resend.com/emails',{},200),
            ('serwersms.send','https://api2.serwersms.pl/messages/send_sms','text='+CONTENT+'&password='+TOKEN,200),
            ('play.token','https://uslugidlafirm.play.pl/oauth/token-jwt',{},200),
            ('play.send','https://uslugidlafirm.play.pl/api/bramkasms/sendSms',{'text':CONTENT},204),
            ('meta.events','https://graph.facebook.com/v21.0/synthetic/events?access_token='+TOKEN,{'event':CONTENT},200),
            ('meta.feed','https://graph.facebook.com/v23.0/synthetic/feed',{'message':CONTENT},200),
            ('tiktok.video','https://open.tiktokapis.com/v2/post/publish/inbox/video/init/',{'source_url':'https://media.invalid/video'},200),
            ('tiktok.status','https://open.tiktokapis.com/v2/post/publish/status/fetch/',{},200)]
        for operation,url,body,status in cases:
            with self.subTest(operation=operation):
                headers={'authorization':'Bearer '+TOKEN,'cookie':'session='+TOKEN,
                    'content-type':'application/x-www-form-urlencoded' if operation=='serwersms.send' else 'application/json'}
                result=self.call(url=url,body=body,headers=headers)
                self.assertIsNone(result['error'],result)
                self.assertEqual(result['result']['status'],status)
                self.assertEqual(len(result['calls']),1)
                self.assertTrue(result['calls'][0]['url'].startswith(self.input['origin']+'/__helix_sink/'))
                self.assertEqual(result['snapshot']['observations'][0]['operation_id'],operation)
                self.assertEqual(result['snapshot']['observations'][0]['outcome'],'captured_local')
                self.assert_private(result)
                view=self.project(result)
                self.assertEqual(view['counts']['external_deliveries_verified'],0)
                self.assertEqual(view['counts']['application_routes_verified'],0)
                self.assertEqual(view['coverage_status'],'INCOMPLETE')
                self.assertIn('APPLICATION_CONFIGURATION_NOT_PROVEN',view['parts'][0]['gaps'])
                if operation=='tiktok.status':self.assertEqual(result['result']['body']['data']['status'],'PROCESSING')

    def test_string_url_and_request_inputs_use_effective_method_and_body(self):
        for flag in ({},{'urlObject':True},{'requestObject':True}):
            with self.subTest(flag=flag):
                result=self.call(url='https://api.resend.com/emails',body={'text':CONTENT},**flag)
                self.assertIsNone(result['error'],result)
                self.assertEqual(result['snapshot']['observations'][0]['operation_id'],'resend.send')
        overridden=self.call(url='https://api.resend.com/emails',requestObject=True,options={'method':'DELETE'})
        self.assertEqual(overridden['calls'],[])
        self.assertEqual(overridden['snapshot']['observations'],[])
        self.assertIsNotNone(overridden['error'])
        changed=self.call(url='https://api.resend.com/emails',requestObject=True,body={'text':'original'},
            options={'body':json.dumps({'text':CONTENT})})
        self.assertIsNone(changed['error'])
        self.assertEqual(changed['mailboxes'][0]['body'],{'text':CONTENT})

    def test_http_https_overloads_cannot_override_rewritten_target(self):
        for transport in ('http','https'):
            with self.subTest(transport=transport):
                result=self.call(transport,url='https://api.resend.com/emails',body={'text':CONTENT})
                self.assertIsNone(result['error'],result)
                self.assertEqual(result['snapshot']['observations'][0]['operation_id'],'resend.send')
        for options in ({'hostname':'external.invalid'},{'port':444},{'protocol':'http:'},
                        {'path':'https://external.invalid/private'},{'host':'external.invalid:443'},
                        {'agent':{}},{'lookup':True},{'createConnection':True}):
            for url in ('https://api.resend.com/emails',self.input['own_origins'][0]+'/health'):
                with self.subTest(options=options,url=url):
                    result=self.call('https',url=url,options=options)
                    self.assertEqual(result['calls'],[])
                    self.assertEqual(result['snapshot']['observations'],[])
                    self.assertIsNotNone(result['error'])
        options_form=self.call('https',url={'protocol':'https:','hostname':'api.resend.com','path':'/emails'},
            optionsObject=True,body={'text':CONTENT})
        self.assertIsNone(options_form['error'])
        self.assertEqual(options_form['snapshot']['observations'][0]['operation_id'],'resend.send')

    def test_unknown_hosts_ports_operations_and_whatsapp_fail_without_forwarding(self):
        for url in ('https://api.resend.com.evil.invalid/emails','https://api.resend.com:444/emails',
                    'http://api.resend.com/emails','https://name:'+TOKEN+'@api.resend.com/emails',
                    'https://api.resend.com/emails#private','https://api.resend.com/%2femails',
                    'https://api.resend.com/unsupported','https://graph.facebook.com/v23.0/synthetic/messages',
                    'https://external.invalid/emails','https://open.tiktokapis.com/v2/post/publish/unknown/'):
            with self.subTest(url=url):
                result=self.call(url=url)
                self.assertEqual(result['calls'],[],result)
                self.assertEqual(result['snapshot']['observations'],[])
                self.assertIsNotNone(result['error'])
                self.assertNotIn(TOKEN,json.dumps(result['error']))

    def test_only_exact_owned_origin_passes_through_and_redirect_is_not_followed(self):
        own=self.call(url=self.input['own_origins'][0]+'/health',options={'method':'GET','body':None})
        self.assertIsNone(own['error'],own)
        self.assertEqual(own['snapshot']['observations'],[])
        self.assertEqual(own['result']['body'],{'own':True})
        other=self.call(url='http://127.0.0.1:32125/health')
        self.assertEqual(other['calls'],[])
        for url in ('https://api.resend.com/emails',self.input['own_origins'][0]+'/health'):
            with self.subTest(url=url):
                redirected=self.call(url=url,scenario={'redirect':True})
                self.assertEqual(len(redirected['calls']),1)
                self.assertEqual(redirected['snapshot']['observations'],[])
                self.assertIsNotNone(redirected['error'])

    def test_sink_binding_auth_and_paths_are_required_before_private_write(self):
        for request in ({'headers':{'authorization':'Bearer wrong'}},
                        {'url':'https://external.invalid/__helix_sink/resend.send'},
                        {'url':self.input['origin']+'/__helix_sink/resend.send?token='+TOKEN},
                        {'method':'CONNECT'}, {'url':self.input['origin']+'/__helix_sink/unknown.operation'}):
            with self.subTest(request=request):
                result=self.call('handler',request=request)
                self.assertGreaterEqual(result['result']['status'],400)
                self.assertEqual(result['mailboxes'],[])
                self.assertEqual(result['snapshot']['observations'],[])
                self.assert_private(result)

    def test_public_metadata_never_contains_private_headers_body_or_query(self):
        result=self.call(url='https://graph.facebook.com/v21.0/synthetic/events?access_token='+TOKEN,
            headers={'authorization':TOKEN,'cookie':TOKEN},body={'text':CONTENT,'api_key':TOKEN,'nested':{'password':TOKEN}})
        self.assertIsNone(result['error'],result)
        self.assert_private(result)
        self.assertNotIn(TOKEN,json.dumps(result['mailboxes']))
        self.assertIn(CONTENT,json.dumps(result['mailboxes']))
        self.assertNotIn(TOKEN,json.dumps(result['calls'][0]['headers']))
        self.assertNotIn(TOKEN,result['calls'][0]['url'])

    def test_webpush_is_only_local_synthetic_endpoint_and_missing_subscription_gap_stays(self):
        result=self.call(url=self.input['webpush_endpoint'],body='encrypted-synthetic-bytes',headers={'content-type':'application/octet-stream'})
        self.assertIsNone(result['error'],result)
        self.assertEqual(result['result']['status'],201)
        self.assertIn('SYNTHETIC_SUBSCRIPTION_NOT_PROVEN',self.project(result)['parts'][0]['gaps'])
        unknown=self.call(url='https://push.external.invalid/subscription/'+TOKEN,body=CONTENT)
        self.assertEqual(unknown['calls'],[])
        self.assertEqual(unknown['snapshot']['observations'],[])
        material=self.call('material')['result']
        self.assertEqual((material['publicBytes'],material['privateBytes'],material['authBytes']),(65,32,16))

    def test_dns_is_synthetic_only_for_exact_generated_domain(self):
        result=self.call('dns',domain='helix-mail.invalid')
        self.assertEqual(result['dnsCalls'],[])
        self.assertNotIn('error',json.dumps(result['result']))
        for domain in ('customer.invalid','sub.helix-mail.invalid','helix-mail.invalid.evil.invalid'):
            with self.subTest(domain=domain):
                result=self.call('dns',domain=domain)
                self.assertEqual(result['dnsCalls'],[])
                self.assertTrue(all('error' in row for row in result['result'].values()))

    def test_limits_deadline_and_close_never_create_successful_late_capture(self):
        oversized=self.call('handler',body='x'*(1048576+1))
        self.assertEqual(oversized['result']['status'],413)
        self.assertEqual(oversized['mailboxes'],[])
        self.assertEqual(oversized['snapshot']['observations'][0]['outcome'],'rejected_local')
        for action in ('deadline','closed'):
            with self.subTest(action=action):
                result=self.call(action)
                self.assertGreaterEqual(result['result']['status'],400)
                self.assertEqual(result['mailboxes'],[])
                self.assertEqual(result['snapshot']['observations'],[])

    def test_writer_failure_halts_later_acceptance_and_preserves_partial(self):
        for scenario in ({'mailboxFailure':True},{'publicFailure':1}):
            with self.subTest(scenario=scenario):
                result=self.call('writer',scenario=scenario)
                self.assertNotIn('PRIVATE_WRITER_CANARY',json.dumps(result['error']))
                self.assertIn('SINK_WRITE_FAILED',result['snapshot']['gaps'])
                self.assertEqual(result['snapshot']['status'],'partial')
                self.assertEqual(self.project(result)['coverage_status'],'INCOMPLETE')
                self.assertEqual(result['result']['second']['status'],503)
                self.assertEqual(result['mailboxCalls'],result['result']['writesAfterFirst'])


if __name__=='__main__':unittest.main()
