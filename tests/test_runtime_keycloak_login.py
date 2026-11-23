"""Form-only browser helper contracts with synthetic Playwright and no network."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = Path(os.environ.get('HELIX_SOURCE_ROOT', ROOT))
HELPER = ROOT / 'bin/runtime-keycloak-login.cjs'
sys.path[:0] = [str(ROOT / 'bin'), str(SOURCE_ROOT / 'bin')]

DRIVER = r'''
const fs=require('fs'), Module=require('module');
const data=JSON.parse(fs.readFileSync(0,'utf8'));
const load=Module._load;
Module._load=function(id,...rest){if(/^(?:node:)?(?:http|https|net|tls|dns|child_process)$/.test(id))throw Error('network/process forbidden');return load.call(this,id,...rest);};
global.fetch=()=>{throw Error('fetch forbidden');};
const H=require(process.argv[1]);
const input=data.input,s=data.scenario||{};
const events=[],receipts=[],suites=[];
let created=0,closed=0,acquired=0,released=0;
function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms));}
const browser={newContext:async options=>{
  if(s.contextDelay)await sleep(s.contextDelay);
  const index=++created;events.push({kind:'context',options});
  let handler,url='about:blank';const main={},listeners={};
  const request=(target,method,from)=>({url:()=>target,method:()=>method,isNavigationRequest:()=>true,frame:()=>main,redirectedFrom:()=>from||null});
  // realRedirects: jak prawdziwy Playwright, skok przekierowania nie trafia do trasy, tylko do nasłuchu żądań.
  async function nav(target,method='GET',status=200,from=null){
    const req=request(target,method,from);let aborted=false;
    if(s.realRedirects&&from){if(listeners.request)listeners.request(req);}
    else await handler({request:()=>req,continue:async()=>{},abort:async()=>{aborted=true;}});
    if(aborted)throw Error('PRIVATE_RAW_REQUEST_CANARY');
    url=target;
    if(listeners.response)listeners.response({url:()=>target,status:()=>status,request:()=>req});
    return req;
  }
  function locator(selector){const name=selector.split(' ').pop();return{
    count:async()=>1,
    getAttribute:async attr=>attr==='method'?'post':attr==='action'?input.issuer+'/login-actions/authenticate?client_id='+input.client_id+'&session_code=SESSION_CANARY':attr==='type'?(name==='#password'?'password':'submit'):null,
    locator:child=>locator(selector+' '+child),
    fill:async value=>events.push({kind:'fill',field:name}),
    click:async()=>{
      const posted=await nav(input.issuer+'/login-actions/authenticate?client_id='+input.client_id+'&session_code=SESSION_CANARY','POST',s.formStatus||200);
      const cb=new URL(input.app_origin+input.callback_paths[0]);cb.searchParams.set('state','STATE_CANARY');
      if(s.oidcError)cb.searchParams.set('error','private_error');else cb.searchParams.set('code','CODE_CANARY');
      await nav(cb.href,'GET',s.callbackStatus||200,posted);
    }
  };}
  const page={mainFrame:()=>main,url:()=>url,on:(event,fn)=>{listeners[event]=fn;},locator,
    goto:async target=>{
      const first=await nav(target);
      const auth=new URL(input.authorization_endpoint);
      for(const [key,value]of Object.entries({client_id:s.wrongClient?'other-app':input.client_id,response_type:'code',scope:'openid profile',redirect_uri:input.app_origin+input.callback_paths[0],state:'STATE_CANARY',nonce:'NONCE_CANARY'}))auth.searchParams.set(key,value);
      if(input.pkce==='S256'){auth.searchParams.set('code_challenge','C'.repeat(43));auth.searchParams.set('code_challenge_method','S256');}
      await nav(auth.href,'GET',200,first);
    },waitForURL:async predicate=>{if(!predicate(new URL(url)))throw Error('unexpected finalURL');}
  };
  return{route:async(_pattern,fn)=>{handler=fn;},newPage:async()=>page,close:async()=>{closed++;if(s.closeThrows)throw Error('CLOSE_CANARY');}};
}};
const gate={acquire:async()=>{if(s.acquireDelay)await sleep(s.acquireDelay);if(s.paused){const e=Error('PRIVATE_RESOURCE_CANARY');e.name='ResourcePaused';throw e;}acquired++;},release:()=>{released++;}};
(async()=>{
 let result,error;
 try{
  if(data.action==='validate'){
    const before=JSON.stringify(input),value=H.validateLoginInput(input);value.identities[0].password='changed';
    result={unchanged:JSON.stringify(input)===before,keys:Object.keys(value)};
  }else if(data.action==='read'){const value=H.readPrivateLoginInput(data.file,data.root);result={count:value.identities.length};}
  else if(data.action==='import'){result={loaded:true};}
  else{
    const emit=row=>{if(s.emitThrows)throw Error('PRIVATE_EMITTER_CANARY');receipts.push(row);};
    result=data.action==='suite'?await H.runLoginSuite({browser,input,gate,emit,emitSuite:row=>suites.push(row)}):await H.runIdentityFlow({browser,input,identityId:input.identities[0].id,gate,emit,sessionHook:s.sessionHook?async arg=>{events.push({kind:'session',identity:arg.identity,hasContext:!!arg.context});if(s.sessionHook==='throws')throw Error('SESSION_CANARY');}:undefined});
  }
 }catch(e){error={code:e.code,message:e.message};}
 if(s.drain)await sleep(s.drain);
 process.stdout.write(JSON.stringify({result,error,events,receipts,suites,created,closed,acquired,released}));
})().catch(()=>{process.stderr.write('safe test driver failure');process.exitCode=1;});
'''


class RuntimeKeycloakLoginTests(unittest.TestCase):
    def setUp(self):
        self.input = dict(schema_version=1, binding=dict(run_id='runtime-fixture',integration_id='keycloak:'+'1'*12,
            integration_plan_id='2'*64,identity_plan_id='3'*64,attempt_id='login-'+'4'*32,part='frontend'),
            app_origin='https://localhost:44100',issuer='https://127.0.0.1:44200/realms/helix-fixture17',
            authorization_endpoint='https://127.0.0.1:44200/realms/helix-fixture17/protocol/openid-connect/auth',
            client_id='test-app',callback_paths=['/auth/callback'],login_path='/login',pkce='S256',
            identities=[dict(id='role-'+'a'*12,username='helix-role-'+'a'*12,email_verified=True,app_roles=['reader'],password='PASSWORD_CANARY_17')],
            deadline_unix_ms=int(time.time()*1000)+60000,operation_timeout_ms=1000)

    def call(self, action='flow', **extra):
        node=shutil.which('node');self.assertIsNotNone(node)
        result=subprocess.run([node,'-e',DRIVER,str(HELPER)],input=json.dumps(dict(input=self.input,action=action,**extra)),
            capture_output=True,text=True,timeout=6)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)

    def test_import_is_passive_and_validation_does_not_mutate_input(self):
        self.assertEqual(self.call('import')['result'],{'loaded':True})
        self.assertTrue(self.call('validate')['result']['unchanged'])

    def test_private_contract_rejects_array_coercion_in_identifiers(self):
        original=copy.deepcopy(self.input)
        for field in self.input['binding']:
            self.input=copy.deepcopy(original)
            self.input['binding'][field]=[self.input['binding'][field]]
            with self.subTest(field=field):
                self.assertEqual(self.call('validate')['error']['code'],'INVALID_BINDING')
        self.input=copy.deepcopy(original);self.input['issuer']=[self.input['issuer']]
        self.assertEqual(self.call('validate')['error']['code'],'INVALID_ISSUER')
        self.input=copy.deepcopy(original);self.input['identities'][0]['id']=[self.input['identities'][0]['id']]
        self.assertEqual(self.call('validate')['error']['code'],'INVALID_POSITIVE_IDENTITY')

    def test_python_builder_output_matches_javascript_contract(self):
        import helix_runtime_identity as identity
        import helix_runtime_login as login
        values=dict(client_id='fixture-app',client_type='confidential',callback_paths=['/auth/callback'],login_path='/login',
                    pkce='S256',role_claim='realm_access.roles',roles=['reader','editor'])
        plan=identity.identity_plan({},[{'path':'frontend'}],{'runtime':{'keycloak':{'parts':{'frontend':values}}}})['parts'][0]
        material=dict(realm='helix-fixture17',app_origin=self.input['app_origin'],client_secret='PRIVATE_CLIENT_SECRET_'+'s'*24,
                      user_passwords={row['id']:'synthetic-password-'+row['id'] for row in plan['identities']})
        binding=dict(self.input['binding'],identity_plan_id=plan['plan_id'],run_id='runtime:fixture')
        self.input=login.build_login_input(plan,material,binding=binding,issuer=self.input['issuer'],deadline_unix_ms=self.input['deadline_unix_ms'])
        data=self.call('suite')
        self.assertNotIn('error',data)
        self.assertEqual(data['result']['form_status'],'PASS')
        self.assertEqual(data['result']['status'],'INCOMPLETE')
        self.assertEqual(data['created'],2);self.assertEqual(data['closed'],2)
        self.assertEqual([row['form_status'] for row in data['suites'][0]['identities']],['NOT_RUN','NOT_RUN'])
        self.assertEqual([row['form_status'] for row in data['suites'][1]['identities']],['PASS','NOT_RUN'])
        self.assertEqual(data['suites'][-1],data['result'])
        self.assertTrue(all(row['cleanup']=='closed' for row in data['suites'][-1]['identities']))
        self.assertNotIn('PRIVATE_CLIENT_SECRET',json.dumps(data))

    def test_redirect_hops_that_never_reach_the_route_handler_are_still_checked(self):
        # Przebieg 28 na projekcie A: /auth/login odpowiada 302 do Keycloak; Playwright woła trasę tylko dla pierwszego adresu.
        data=self.call(scenario=dict(realRedirects=True))
        self.assertNotIn('error',data)
        self.assertEqual(data['result']['form_status'],'PASS')
        phases={row['phase']:row for row in self.call(scenario=dict(realRedirects=True,wrongClient=True))['receipts'][-1]['phases']}
        self.assertEqual(phases['authorization']['status'],'BLOCKED')

    def test_session_hook_runs_only_after_a_passed_login_and_cannot_change_the_form_result(self):
        data=self.call(scenario=dict(sessionHook=True))
        sessions=[e for e in data['events'] if e['kind']=='session']
        self.assertEqual(sessions,[dict(kind='session',identity=dict(id='role-'+'a'*12,app_roles=['reader'],email_verified=True),hasContext=True)])
        self.assertNotIn('PASSWORD_CANARY_17',json.dumps(sessions))
        thrown=self.call(scenario=dict(sessionHook='throws'))
        self.assertEqual(thrown['result']['form_status'],'PASS');self.assertNotIn('SESSION_CANARY',json.dumps(thrown['result']))
        failed=self.call(scenario=dict(sessionHook=True,callbackStatus=500))
        self.assertEqual([e for e in failed['events'] if e['kind']=='session'],[])
        self.assertEqual([e for e in self.call()['events'] if e['kind']=='session'],[])

    def test_callback_500_is_visible_failure_and_never_a_successful_phase(self):
        data=self.call(scenario={'callbackStatus':500})
        result=data['result'];phases={row['phase']:row for row in result['phases']}
        self.assertEqual(result['form_status'],'FAIL')
        self.assertEqual(phases['callback']['status'],'FAIL')
        self.assertEqual(phases['callback']['reason_code'],'CALLBACK_HTTP_ERROR')
        self.assertEqual(phases['form']['status'],'PASS')
        self.assertEqual(phases['application_session']['status'],'NOT_RUN')

    def test_oidc_error_response_is_explicit_without_echoing_description(self):
        data=self.call(scenario={'oidcError':True})
        row=next(row for row in data['result']['phases'] if row['phase']=='callback')
        self.assertEqual(row['reason_code'],'OIDC_ERROR_RESPONSE')
        self.assertNotEqual(data['result']['form_status'],'PASS')
        self.assertNotIn('private_error',json.dumps(data))

    def test_form_http_failure_is_retained(self):
        data=self.call(scenario={'formStatus':401})
        self.assertNotEqual(data['result']['form_status'],'PASS')
        self.assertTrue(any(row['reason_code']=='FORM_HTTP_ERROR' for row in data['result']['phases']))

    def test_raw_credential_query_and_callback_values_never_reach_public_events(self):
        data=self.call();encoded=json.dumps(data)
        self.assertEqual(data['result']['form_status'],'PASS')
        for secret in ('PASSWORD_CANARY_17','STATE_CANARY','CODE_CANARY','NONCE_CANARY','SESSION_CANARY'):
            self.assertNotIn(secret,encoded)
        self.assertFalse(data['result']['execution']['session_asserted'])
        self.assertEqual(data['result']['execution']['protected_routes_tested'],0)

    def test_suite_publishes_pending_rows_and_pause_leaves_unrun_role_visible(self):
        self.input['identities'].append(dict(id='role-'+'b'*12,username='helix-role-'+'b'*12,email_verified=True,
                                            app_roles=['editor'],password='SECOND_PASSWORD_CANARY'))
        data=self.call('suite',scenario={'paused':True})
        self.assertEqual([row['identity_id'] for row in data['receipts'][:2]],[row['id'] for row in self.input['identities']])
        self.assertEqual([row['form_status'] for row in data['result']['identities']],['BLOCKED','NOT_RUN'])
        self.assertEqual(data['created'],0);self.assertEqual(data['result']['status'],'INCOMPLETE')

    def test_expired_budget_creates_no_context_and_late_admission_releases_slot(self):
        self.input['deadline_unix_ms']=int(time.time()*1000)-1
        data=self.call();self.assertEqual(data['created'],0);self.assertEqual(data['acquired'],0)
        # Use a controlled runtime deadline after the Node process is admitted.
        source=DRIVER.replace('const input=data.input,s=data.scenario||{};',"const input=data.input,s=data.scenario||{};input.deadline_unix_ms=Date.now()+20;")
        node=shutil.which('node')
        result=subprocess.run([node,'-e',source,str(HELPER)],input=json.dumps(dict(input=self.input,scenario={'acquireDelay':50,'drain':80})),capture_output=True,text=True,timeout=6)
        self.assertEqual(result.returncode,0,result.stderr)
        data=json.loads(result.stdout)
        self.assertEqual((data['created'],data['acquired'],data['released']),(0,1,1))

    def test_late_context_is_closed_and_cleanup_failure_cannot_pass(self):
        self.input['operation_timeout_ms']=5
        data=self.call(scenario={'contextDelay':40})
        self.assertEqual((data['created'],data['closed']),(1,1))
        self.assertEqual(data['result']['cleanup'],'closed')
        self.assertNotEqual(data['result']['form_status'],'PASS')
        self.input['operation_timeout_ms']=1000
        data=self.call(scenario={'closeThrows':True})
        self.assertEqual(data['result']['cleanup'],'unknown')
        self.assertEqual(data['result']['status'],'BLOCKED')
        self.assertEqual(data['acquired'],data['released'])

    def test_public_receipt_writer_failure_has_only_sanitized_error(self):
        data=self.call(scenario={'emitThrows':True})
        self.assertEqual(data['error']['code'],'PUBLIC_RECEIPT_WRITE_FAILED')
        self.assertNotIn('PRIVATE_EMITTER_CANARY',json.dumps(data))
        self.assertEqual(data['created'],0)

    def test_explicit_default_https_port_keeps_input_and_callback_binding(self):
        self.input['app_origin']='https://localhost:443'
        data=self.call();self.assertNotIn('error',data)
        self.assertEqual(data['result']['form_status'],'PASS')
        self.assertEqual(self.input['app_origin'],'https://localhost:443')

    def test_private_reader_rejects_hardlinks_and_oversized_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();source=root/'login.json';source.write_text(json.dumps(self.input));source.chmod(0o600)
            self.assertEqual(self.call('read',file=str(source),root=str(root))['result'],{'count':1})
            other=root/'hard.json';os.link(source,other)
            self.assertEqual(self.call('read',file=str(source),root=str(root))['error']['code'],'INVALID_PRIVATE_FILE')
            other.unlink();source.write_bytes(b'x'*(1024*1024+1))
            self.assertEqual(self.call('read',file=str(source),root=str(root))['error']['code'],'INVALID_PRIVATE_FILE')


if __name__=='__main__':unittest.main()
