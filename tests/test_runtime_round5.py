import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch
from test_runtime import FakeExecutor, TOOLS, FIX
import helix_runtime as rt


class RoundFiveTests(unittest.TestCase):
    def test_flyway_undo_is_never_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); directory=root/'db/migrations'; directory.mkdir(parents=True)
            for name,sql in [('V1__init.sql','CREATE TABLE items(id int);'),
                             ('U1__init.sql','DROP TABLE items;'),
                             ('R__view.sql','CREATE VIEW item_view AS SELECT * FROM items;')]:
                (directory/name).write_text(sql)
            self.assertEqual([Path(m['path']).name for m in rt.plan(root)['migrations']],
                             ['V1__init.sql','R__view.sql'])

    def test_previous_app_500_does_not_override_current_start_failure(self):
        executor=FakeExecutor(); original=executor.run
        def run(argv,cwd,env,timeout):
            if 'install' in argv:
                return 1,'synthetic install failure'
            return original(argv,cwd,env,timeout)
        executor.run=run
        executor.last_health=dict(state='http',status=500)
        with tempfile.TemporaryDirectory() as tmp:
            runner=rt.Runner(FIX/'sveltekit-pg',Path(tmp)/'out',executor=executor,
                             tools={'tools':TOOLS},port_factory=lambda:31234)
            part=runner.run()['parts'][0]
            self.assertEqual(part['startup']['health'],{})
            self.assertEqual(part['checks']['e2e']['status'],'BLOCKED')
            self.assertNotIn('HTTP 5xx',part['checks']['e2e']['reason'])

    def test_http_error_is_up_without_retry(self):
        for code in (401,404,500,503):
            executor=rt.Executor(); opener=Mock()
            opener.open.side_effect=urllib.error.HTTPError('http://127.0.0.1/',code,'synthetic',{},None)
            with patch.object(rt.urllib.request,'build_opener',return_value=opener):
                self.assertEqual(executor.health('http://127.0.0.1/',1),'http://127.0.0.1/')
            self.assertEqual(executor.last_health['status'],code)
            self.assertEqual(opener.open.call_count,1)

    def test_up_only_and_flyway_order(self):
        sql='-- migrate:up\nCREATE TABLE x(id int);\n-- migrate:down\nDROP TABLE x;'
        self.assertNotIn('DROP',rt.up_sql(sql))
        self.assertEqual(sorted(['V10__b.sql','R__a.sql','V2__a.sql'],key=rt.migration_order),['V2__a.sql','V10__b.sql','R__a.sql'])
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'db/migrations').mkdir(parents=True)
            (root/'db/migrations/1.up.sql').write_text('CREATE TABLE x(id int);')
            (root/'db/migrations/1.down.sql').write_text('DROP TABLE x;')
            self.assertEqual(len(rt.plan(root)['migrations']),1)

    def test_candidates_use_fresh_databases_and_report_counts(self):
        executor=FakeExecutor(); original=executor.run; seen={}
        def run(argv,cwd,env,timeout):
            if '-f' in argv and '/db/' in argv[-1]:
                db=argv[1]; name=Path(argv[-1]).name
                if name=='001.sql':
                    if db in seen: return 1,argv[-1]+':1: ERROR: relation runtime_items already exists'
                    seen[db]=True
            return original(argv,cwd,env,timeout)
        executor.run=run
        with tempfile.TemporaryDirectory() as tmp:
            runner=rt.Runner(FIX/'snapshot+migrations-duplicate',Path(tmp)/'out',executor=executor,tools={'tools':TOOLS},port_factory=lambda:31234)
            part=runner.run()['parts'][0]; check=part['checks']['schema-apply']
            self.assertEqual(check['status'],'PASS',check)
            group=part['database']['strategies'][0]
            self.assertEqual([c['failed'] for c in group['results']],[0,1,0])
            self.assertEqual(group['strategy'],'migrations');self.assertEqual(group['tag'],'ASSUMPTION')
            self.assertEqual(group['duplicates'][0]['object'],'runtime_items')
            creates=[a[-1] for a,_,_,_ in executor.calls if a[-1].startswith('CREATE DATABASE helix_trial_')]
            drops=[a[-1] for a,_,_,_ in executor.calls if a[-1].startswith('DROP DATABASE IF EXISTS helix_trial_')]
            self.assertEqual(len(set(creates)),3);self.assertEqual(len(drops),3)

    def test_5xx_fails_e2e_with_log_cause(self):
        executor=FakeExecutor();spawn=executor.spawn
        def start(argv,cwd,env,log):
            proc=spawn(argv,cwd,env,log);log.write_text('Listening on http://127.0.0.1:33333\nClientError: synthetic failure\n');return proc
        executor.spawn=start
        def health(url,timeout): executor.last_health=dict(state='http',status=500);return url
        executor.health=health
        with tempfile.TemporaryDirectory() as tmp:
            runner=rt.Runner(FIX/'sveltekit-pg',Path(tmp)/'out',executor=executor,tools={'tools':TOOLS},port_factory=lambda:31234)
            part=runner.run()['parts'][0]
            self.assertEqual(part['checks']['e2e']['status'],'FAIL')
            self.assertIn('synthetic failure',part['checks']['e2e']['reason'])
            self.assertIn(':33333/',part['startup']['url'])

    def test_stub_scoped_ca_and_cleanup(self):
        executor=FakeExecutor()
        with tempfile.TemporaryDirectory() as tmp, patch.object(rt,'locate',return_value='/fake/openssl'):
            runner=rt.Runner(FIX/'oidc-https-app',Path(tmp)/'out',executor=executor,tools={'tools':TOOLS},port_factory=lambda:31234)
            part=runner.run()['parts'][0]
            self.assertEqual(part['startup']['oidc']['status'],'synthetic')
            self.assertTrue(runner.env['OIDC_ISSUER'].startswith('https://127.0.0.1:'))
            self.assertEqual(runner.env['NODE_EXTRA_CA_CERTS'],runner.env['SSL_CERT_FILE'])
            self.assertNotIn('NODE_TLS_REJECT_UNAUTHORIZED',runner.env)
            self.assertCountEqual(executor.started,executor.stopped)
            self.assertFalse(runner.tmp.exists())

    def test_error_categories_keep_location_and_limit_examples(self):
        result=rt.error_summary([dict(path='db/migrations/2.sql',line=42,reason='column x does not exist')]*10)
        self.assertEqual(result[0]['count'],10);self.assertEqual(len(result[0]['examples']),2)
        self.assertEqual(result[0]['examples'][0]['line'],42)

    def test_oidc_discovery_code_token_and_redirect_restriction(self):
        import base64
        import io
        from urllib.parse import urlparse, parse_qs
        spec=importlib.util.spec_from_file_location('runtime_oidc',rt.HOME/'bin/runtime-oidc.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        server=Mock(); context=Mock()
        with patch.object(module,'public_jwk',return_value=dict(kty='RSA',kid='synthetic')), patch.object(module.http.server,'HTTPServer',return_value=server) as factory, patch.object(module.ssl,'SSLContext',return_value=context):
            module.serve(34567,'cert','key','openssl')
        Handler=factory.call_args.args[1]
        def request(path,body=None):
            handler=object.__new__(Handler);handler.path=path;handler.headers={}
            handler.wfile=io.BytesIO();handler.send_response=Mock();handler.send_header=Mock();handler.end_headers=Mock()
            if body is not None:
                handler.rfile=io.BytesIO(body.encode());handler.headers={'Content-Length':str(len(body))}
                with patch.object(module.subprocess,'check_output',return_value=b'signature'):handler.do_POST()
            else:handler.do_GET()
            return handler
        discovery=json.loads(request('/.well-known/openid-configuration').wfile.getvalue())
        self.assertEqual(discovery['issuer'],'https://127.0.0.1:34567')
        self.assertEqual(json.loads(request('/jwks').wfile.getvalue())['keys'][0]['kid'],'synthetic')
        blocked=request('/authorize?redirect_uri=https://example.test/callback')
        blocked.send_response.assert_called_with(400)
        authorized=request('/authorize?redirect_uri=http://127.0.0.1:3000/callback&client_id=client&nonce=test-nonce&state=test-state')
        location=authorized.send_header.call_args.args[1]; params=parse_qs(urlparse(location).query)
        self.assertEqual(params['state'],['test-state'])
        token=json.loads(request('/token','code='+params['code'][0]).wfile.getvalue())
        claims=json.loads(base64.urlsafe_b64decode(token['id_token'].split('.')[1]+'==='))
        self.assertEqual(claims['aud'],'client');self.assertEqual(claims['nonce'],'test-nonce')
        self.assertEqual(claims['sub'],'synthetic-user')
        reused=request('/token','code='+params['code'][0]);reused.send_response.assert_called_with(400)

    def test_health_distinguishes_refusal_and_timeout(self):
        import socket
        for cause,state in ((ConnectionRefusedError('refused'),'no-listener'),(socket.timeout('late'),'timeout')):
            executor=rt.Executor();opener=Mock();opener.open.side_effect=urllib.error.URLError(cause)
            with patch.object(rt.urllib.request,'build_opener',return_value=opener), patch.object(rt.time,'monotonic',side_effect=[0,0,.01,.02,2]), patch.object(rt.time,'sleep'):
                with self.assertRaisesRegex(rt.Blocked,state):executor.health('http://127.0.0.1/',1)
            self.assertEqual(executor.last_health['state'],state)

    def test_fixture_conventions(self):
        for fixture,convention in (('flyway-style','flyway'),('dbmate-style','dbmate')):
            group=rt.plan(FIX/fixture)['parts'][0]['schema_strategies'][0]
            self.assertEqual(group['convention'],convention)
        result=rt.error_summary([dict(path='2.sql',reason='NOTICE: extension already exists\nERROR: column x does not exist')])
        self.assertEqual(result[0]['category'],'does not exist')
