"""Round eleven: synthetic offline regression evidence only."""
import json
from pathlib import Path
import tempfile
import unittest
import test_runtime_round10 as round10
import helix_runtime as rt


class RoundElevenTests(unittest.TestCase):
    def test_runner_trials_preserved_when_snapshot_selected(self):
        # Reuse the disposable fake executor, without running its inherited tests.
        fixture=round10.RoundTenTests(); self.addCleanup(fixture.doCleanups)
        part,runner=fixture.fixture(always_fail=True)
        variants=part['database']['variants']
        self.assertTrue(any(v['status']=='REFUSED' for v in variants))
        self.assertTrue(any(v['selected'] and v['status']=='PASS' for v in variants))
        self.assertEqual([v['order'] for v in variants],list(range(1,len(variants)+1)))
        self.assertTrue(all('commands' in v and 'seconds' in v and 'first_error' in v for v in variants))
        markdown=(runner.out/'runtime.md').read_text()
        self.assertIn('| # | Variant |',markdown)
        self.assertIn('runtime-report.json/parts/database/variants',markdown)

    def test_fresh_failure_has_project_evidence(self):
        fresh=dict(path='db/migrate.sh',kind='runner',fresh=True,fresh_evidence=dict(path='db/README.md',line=53))
        result=dict(strategy='fresh',status='failed',applied=0,failed=1,first_error='psql:/tmp/runtime/project/db/002_auth.sql:7: ERROR: relation "users" does not exist',logs=['logs/013.log'],seconds=.1)
        variants,findings=rt.database_variants([dict(strategy='snapshot',candidates=[dict(strategy='fresh',migrations=[fresh])],results=[result])])
        finding=findings[0]
        self.assertEqual((finding['id'],finding['owner'],finding['tag']),('fresh-install-broken','project','VERIFIED'))
        self.assertEqual(finding['first_error'],dict(path='db/002_auth.sql',line=7))
        self.assertEqual(finding['recommendation'],[dict(path='db/README.md',line=53)])
        self.assertEqual(variants[0]['status'],'FAIL')

    def test_k6_blocks_without_reachable_e2e_routes(self):
        fixture=round10.RoundTenTests(); self.addCleanup(fixture.doCleanups)
        part,runner=fixture.fixture()
        runner.e2e_result={'pages':[]}
        status,data=runner.measure('load',{'routes':['/private'],'path':'.'},'http://127.0.0.1:31234/',rt.profile_budgets({}))
        self.assertEqual(status,'BLOCKED')
        self.assertEqual(data['excluded_routes'],['/private'])

    def test_k6_routes_and_status_summary(self):
        from test_runtime import FakeExecutor, TOOLS, FIX
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); executor=FakeExecutor(); original=executor.run
            def run(argv,cwd,env,timeout):
                result=original(argv,cwd,env,timeout)
                if str(argv[0]).endswith('k6') and '--version' not in argv:
                    stream=Path(argv[argv.index('--out')+1].removeprefix('json='))
                    tags=dict(method='GET',url='http://127.0.0.1:31234/items',status='404',source='app')
                    stream.write_text(json.dumps(dict(type='Point',metric='runtime_responses',data=dict(tags=tags,value=1)))+'\n')
                    Path(argv[argv.index('--summary-export')+1]).write_text(json.dumps(dict(metrics=dict(http_req_duration={'p(95)':20},http_req_failed={'rate':1}))))
                return result
            executor.run=run
            runner=rt.Runner(FIX/'sveltekit-pg',base/'out',executor=executor,tools={'tools':TOOLS})
            runner.tmp=base; runner.work=FIX/'sveltekit-pg'; runner.env={}
            (runner.out/'logs').mkdir(parents=True)
            runner.e2e_result={'pages':['/items']}
            status,data=runner.measure('load',{'path':'.','routes':['/items','/private']},'http://127.0.0.1:31234/',rt.profile_budgets({}))
            self.assertEqual(status,'FAIL')
            self.assertEqual(data['excluded_routes'],['/private'])
            self.assertEqual(data['status_by_url']['http://127.0.0.1:31234/items'],{'404':1})
            self.assertIn('404 from app',data['cause'])
            script=(base/'project-tmp/load.js').read_text()
            self.assertNotIn('/private',script)
            self.assertIn('redirects:0',script)
            self.assertIn('tags:{name:url}',script)

    def test_secret_env_redacted(self):
        command=rt.migration_command(dict(kind='runner',path='migrate.sh',env={'TOKEN':'hidden','FORCE_FRESH':'1'}))
        self.assertNotIn('hidden',json.dumps(command))
        self.assertEqual(command['env']['FORCE_FRESH'],'1')

    def test_lighthouse_runtime_error_keeps_response_source(self):
        raw=dict(runtimeError={'message':'404'},audits={'network-requests':{'details':{'items':[dict(url='https://127.0.0.1:9000/realm/auth?code=hidden',statusCode=404)]}}})
        result=rt.lighthouse_failure(raw,'https://127.0.0.1:9000')
        self.assertIn('404 from stub',result['cause'])
        self.assertNotIn('hidden',json.dumps(result))

    def test_prefixed_oidc_flow_and_logout(self):
        import io
        from unittest.mock import patch, Mock
        from test_runtime_round10 import module
        provider=module('round11_oidc',Path(rt.HOME)/'bin/runtime-oidc.py')
        captured=[]
        def server(address,handler):
            captured.append(handler); return Mock()
        with patch.object(provider,'public_jwk',return_value={}), patch.object(provider.http.server,'HTTPServer',side_effect=server), patch.object(provider.ssl,'SSLContext'):
            provider.serve(9000,'cert','key','openssl')
        handler=captured[0]
        def request(path,method='GET',body=''):
            instance=object.__new__(handler); instance.path=path
            instance.headers={'Content-Length':str(len(body))}; instance.rfile=io.BytesIO(body.encode()); instance.wfile=io.BytesIO()
            instance.send_response=Mock(); instance.send_header=Mock(); instance.end_headers=Mock()
            getattr(instance,'do_'+method)()
            return instance
        prefix='/arbitrary/realms/demo'
        discovery=request(prefix+'/.well-known/openid-configuration')
        endpoints=json.loads(discovery.wfile.getvalue())
        self.assertEqual(endpoints['authorization_endpoint'],'https://127.0.0.1:9000'+prefix+'/authorize')
        auth=request(prefix+'/authorize?response_type=code&client_id=test&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&state=state')
        location=next(c.args[1] for c in auth.send_header.call_args_list if c.args[0]=='Location')
        code=provider.parse_qs(provider.urlparse(location).query)['code'][0]
        with patch.object(provider.subprocess,'check_output',return_value=b'signed'):
            token=request(prefix+'/token','POST','code='+code)
        self.assertIn('id_token',json.loads(token.wfile.getvalue()))
        self.assertEqual(request(prefix+'/userinfo').send_response.call_args.args[0],200)
        for endpoint in ('/logout','/end_session','/protocol/openid-connect/logout'):
            response=request(prefix+endpoint+'?post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2F')
            self.assertEqual(response.send_response.call_args.args[0],302)
        invalid=request(prefix+'/logout?post_logout_redirect_uri=https%3A%2F%2Fexternal.invalid')
        self.assertFalse(invalid.send_header.call_args_list and any(c.args[0]=='Location' for c in invalid.send_header.call_args_list))

    def test_hook_executable_and_diagnostic(self):
        hook=Path(__file__).resolve().parents[1]/'.githooks/pre-push'
        self.assertTrue(hook.stat().st_mode & 0o111)
        self.assertIn('rebase na origin/master',hook.read_text())
        self.assertIn('helix_release.py',hook.read_text())


if __name__=='__main__': unittest.main()
