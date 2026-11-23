"""Independent helper contract tests. Synthetic Playwright, no browser or network.

HELIX_LOGIN_HELPER can select a staged helper for independent review.
Missing implementation is an error, not a skip or an implied green result.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


HELPER = Path(os.environ.get('HELIX_LOGIN_HELPER', str(Path(__file__).resolve().parents[1] / 'bin/runtime-keycloak-login.cjs')))
NODE = shutil.which('node')
DRIVER = r'''
const fs=require('fs'),Module=require('module');
const originalLoad=Module._load;
Module._load=function(id,...args){if(/^(?:node:)?(?:http|https|net|tls|dns|child_process)$/.test(id))throw Error('forbidden external I/O module');return originalLoad.call(this,id,...args);};
global.fetch=()=>{throw Error('forbidden network fetch');};
const helper=require(process.argv[1]);
const spec=JSON.parse(fs.readFileSync(0,'utf8'));
const events=[],emitted=[];
const input=spec.input,scenario=spec.scenario||{};
const clone=value=>JSON.parse(JSON.stringify(value));
let contextCount=0,closed=0,acquired=0,released=0;
const identity=input.identities[0];
function request(url,method='GET',from=null,frame=null,navigation=true){return {
 url:()=>url,method:()=>method,redirectedFrom:()=>null,isNavigationRequest:()=>navigation,resourceType:()=>navigation?'document':'xhr',
 redirectedFrom:()=>from,frame:()=>frame,postData:()=>method==='POST'?'PRIVATE_POST_DATA':null
};}
function authorizeUrl(){
 const url=new URL(input.authorization_endpoint);
 const values={response_type:'code',scope:'openid',client_id:input.client_id,redirect_uri:input.app_origin+input.callback_paths[0],
 state:'STATE_CANARY_17',nonce:'NONCE_CANARY_17'};
 if(input.pkce==='S256'){values.code_challenge='C'.repeat(43);values.code_challenge_method='S256';}
 for(const [key,value] of Object.entries({...values,...scenario.authorizeParams})){
  if(value!==null)url.searchParams.set(key,value);
 }
 if(scenario.duplicateAuthorize)url.searchParams.append(scenario.duplicateAuthorize,'SECOND_CANARY');
 if(scenario.authorizationOrigin)url.host=new URL(scenario.authorizationOrigin).host;
 if(scenario.authorizationPath)url.pathname=scenario.authorizationPath;
 return url.href;
}
function formAction(){
 const action=new URL(input.issuer+'/login-actions/authenticate');
 action.searchParams.set('client_id',input.client_id);
 action.searchParams.set('session_code','FORM_SESSION_CANARY_17');
 action.searchParams.set('execution','FORM_EXECUTION_CANARY_17');
 return scenario.formAction||action.href;
}
const browser={newContext:async options=>{
 if(scenario.newContextDelayMs)await new Promise(resolve=>setTimeout(resolve,scenario.newContextDelayMs));
 const index=++contextCount;events.push({event:'context',index,options:clone(options)});
 let routeHandler,current='about:blank',filled=0,closedHere=false;
 const mainFrame={parentFrame:()=>null};
 const listeners=new Map();
 const emitEvent=(kind,value)=>{for(const fn of listeners.get(kind)||[])fn(value);};
 async function navigate(url,method='GET',from=null){
  const callback=String(url).startsWith(input.app_origin+input.callback_paths[0]);
  const req=request(url,method,from,scenario.iframeCallback&&callback?{parentFrame:()=>mainFrame}:mainFrame,
   !['GET','HEAD'].includes(method)?scenario.postNavigation!==false:true);let continued=false,aborted=false;
  if(routeHandler)await routeHandler({request:()=>req,continue:async()=>{continued=true;},
   abort:async()=>{aborted=true;events.push({event:'aborted',index});}});
  else continued=true;
  if(aborted||!continued)throw Error('synthetic request refused');
  current=url;events.push({event:'request',index,method,path:new URL(url).pathname});
  emitEvent('request',req);
  const response={url:()=>url,status:()=>200,request:()=>req,headers:()=>({})};
  emitEvent('response',response);return response;
 }
 function locator(selector){
  const form=selector.includes('kc-form-login'),user=selector.includes('username'),pass=selector.includes('password'),button=selector.includes('kc-login');
  return {
   count:async()=>scenario.missingSelector&&selector.includes(scenario.missingSelector)?0:scenario.duplicateSelector&&selector.includes(scenario.duplicateSelector)?2:(form||user||pass||button?1:0),
   getAttribute:async name=>{
    if(name==='method')return scenario.formMethod||'post';
    if(name==='action')return filled&&scenario.actionAfterFill?scenario.actionAfterFill:formAction();
    if(name==='formaction')return scenario.buttonAction||null;
    if(name==='type')return button?'submit':pass?'password':'text';
    return null;
   },
   fill:async value=>{filled++;events.push({event:'fill',index,field:pass?'password':'username',identityIndex:input.identities.findIndex(row=>(pass?row.password:row.username)===value)});if(scenario.fillThrows)throw Error('PASSWORD_CANARY_17 STATE_CANARY_17');},
   click:async()=>{
    events.push({event:'click',index});
    const post=scenario.postAction||scenario.buttonAction||(filled&&scenario.actionAfterFill)||formAction();
    await navigate(post,scenario.postMethod||'POST');
    if(scenario.replayPost)await navigate(scenario.replayPost,'POST',request(post,'POST'));
    const callback=new URL(input.app_origin+input.callback_paths[0]);
    const params={code:'AUTH_CODE_CANARY_17',state:'STATE_CANARY_17',...scenario.callbackParams};
    for(const [key,value] of Object.entries(params))if(value!==null)callback.searchParams.set(key,value);
    if(scenario.duplicateCallback)callback.searchParams.append(scenario.duplicateCallback,'OTHER_CALLBACK_CANARY');
    if(scenario.callbackOrigin)callback.host=new URL(scenario.callbackOrigin).host;
    if(scenario.callbackPath)callback.pathname=scenario.callbackPath;
    await navigate(callback.href);
   },
   locator:child=>locator(selector+' '+child),first(){return this;}
  };
 }
 const page={
  on:(kind,fn)=>listeners.set(kind,[...(listeners.get(kind)||[]),fn]),
  off:(kind,fn)=>listeners.set(kind,(listeners.get(kind)||[]).filter(item=>item!==fn)),
  goto:async url=>{events.push({event:'goto',index});await navigate(url);return navigate(authorizeUrl());},
  url:()=>current,locator,mainFrame:()=>mainFrame,
  waitForURL:async predicate=>{
   for(let i=0;i<200;i++){
    const candidate=new URL(current);
    if(typeof predicate==='function'?predicate(candidate):typeof predicate==='string'?candidate.href===predicate:predicate.test(candidate.href))return;
    await new Promise(resolve=>setTimeout(resolve,1));
   }
   throw Error('synthetic timeout with AUTH_CODE_CANARY_17');
  },
  close:async()=>events.push({event:'page-close',index})
 };
 return {
  route:async(pattern,handler)=>{routeHandler=handler;if(scenario.routeThrows)throw Error('route setup failure');},
  unroute:async()=>{},
  newPage:async()=>{if(scenario.newPageThrows)throw Error('page setup failure');return page;},
  cookies:async()=>[{name:'preferences',value:'COOKIE_VALUE_CANARY_17',domain:'localhost',path:'/',secure:true}],
  storageState:async()=>({cookies:[{name:'preferences',value:'COOKIE_VALUE_CANARY_17'}],origins:[]}),
  close:async()=>{if(!closedHere){closedHere=true;closed++;events.push({event:'context-close',index});}}
 };
}};
const gate={acquire:async()=>{acquired++;events.push({event:'acquire'});},release:()=>{released++;events.push({event:'release'});}};
(async()=>{
 let result=null,error=null;
 try{
  if(spec.action==='validate')result=helper.validateLoginInput(input);
  else if(spec.action==='read')result=helper.readPrivateLoginInput(spec.file,spec.privateRoot);
  else if(spec.action==='suite')result=await helper.runLoginSuite({browser,input,gate,emit:row=>emitted.push(clone(row))});
  else if(spec.action==='sequence'){
   result=[];
   for(const identity of input.identities)result.push(await helper.runIdentityFlow({browser,input,identityId:identity.id,gate,emit:row=>emitted.push(clone(row))}));
  }
  else result=await helper.runIdentityFlow({browser,input,identityId:spec.identityId||identity.id,gate,emit:row=>emitted.push(clone(row))});
 }catch(caught){error={name:caught.name,code:caught.code||caught.reason_code||null,message:caught.message};}
 if(scenario.drainMs)await new Promise(resolve=>setTimeout(resolve,scenario.drainMs));
 process.stdout.write(JSON.stringify({result,error,events,emitted,contextCount,closed,acquired,released}));
})().catch(()=>{process.stderr.write('synthetic driver failure');process.exitCode=2;});
'''


class KeycloakLoginAdversarial(unittest.TestCase):
    def setUp(self):
        self.input = dict(schema_version=1, binding=dict(run_id='runtime-'+'1'*32,
            integration_id='keycloak:'+'2'*12, integration_plan_id='3'*64,
            identity_plan_id='4'*64, attempt_id='login-'+'5'*32, part='frontend'),
            app_origin='https://localhost:44301', issuer='https://127.0.0.1:44302/realms/helix-fixture17',
            authorization_endpoint='https://127.0.0.1:44302/realms/helix-fixture17/protocol/openid-connect/auth',
            client_id='synthetic-app', callback_paths=['/auth/callback'], login_path='/sign-in', pkce='S256',
            identities=[dict(id='role-'+'a'*12,username='helix-role-'+'a'*12,email_verified=True,
                             app_roles=['reader'],password='PASSWORD_CANARY_17')],
            deadline_unix_ms=int(time.time()*1000)+60000, operation_timeout_ms=500)

    def call(self, scenario=None, action='flow', **options):
        self.assertTrue(HELPER.is_file(), 'Set HELIX_LOGIN_HELPER to the staged helper; missing implementation is not a green test')
        self.assertTrue(NODE, 'Node required for the synthetic JavaScript contract tests')
        env = {key:value for key,value in os.environ.items() if key in ('PATH','HOME','TMPDIR')}
        done = subprocess.run([NODE,'-e',DRIVER,str(HELPER)], input=json.dumps(dict(input=self.input,
            scenario=scenario or {},action=action,**options)), text=True,capture_output=True,timeout=5,env=env)
        self.assertEqual(done.returncode,0,done.stderr)
        return json.loads(done.stdout)

    def no_password(self, result):
        self.assertFalse(any(event['event'] in ('fill','click') for event in result['events']),result)

    def no_claims(self, result):
        self.assertIsNone(result['error'],result)
        flow=result['result']
        self.assertEqual(flow['status'],'INCOMPLETE')
        self.assertFalse(flow['execution']['session_asserted'])
        self.assertEqual(flow['execution']['protected_routes_tested'],0)
        phases={row['phase']:row for row in flow['phases']}
        self.assertEqual(phases['application_session']['status'],'NOT_RUN')
        self.assertEqual(phases['protected_routes']['status'],'NOT_RUN')
        return flow

    def test_positive_form_callback_is_incomplete_without_session_or_route_policy(self):
        data=self.call();flow=self.no_claims(data)
        self.assertEqual(flow['form_status'],'PASS')
        self.assertTrue(flow['execution']['form_submitted']);self.assertTrue(flow['execution']['callback_observed'])
        self.assertEqual((data['contextCount'],data['closed'],data['acquired'],data['released']),(1,1,1,1))
        phases={row['phase']:row['status'] for row in flow['phases']}
        self.assertEqual([phases[key] for key in ('authorization','form','callback')],['PASS']*3)
        context=next(event['options'] for event in data['events'] if event['event']=='context')
        self.assertEqual(context,dict(serviceWorkers='block',acceptDownloads=False))

    def test_wrong_authorize_client_redirect_response_type_and_pkce_never_fill(self):
        variants=[{'client_id':'other-client'},{'redirect_uri':'https://outside.invalid/callback'},
                  {'response_type':'token'},{'state':None},{'code_challenge':None},
                  {'code_challenge_method':'plain'}]
        for params in variants:
            with self.subTest(params=params):
                data=self.call({'authorizeParams':params});self.no_password(data)
                self.assertNotEqual((data['result'] or {}).get('form_status'),'PASS')

    def test_foreign_issuer_realm_or_port_never_fill(self):
        for scenario in ({'authorizationOrigin':'https://outside.invalid'},
                         {'authorizationOrigin':'https://127.0.0.1:44303'},
                         {'authorizationPath':'/realms/other/protocol/openid-connect/auth'}):
            with self.subTest(scenario=scenario):self.no_password(self.call(scenario))

    def test_duplicate_authorization_parameters_never_fill(self):
        for key in ('client_id','redirect_uri','response_type','state','code_challenge','code_challenge_method'):
            with self.subTest(key=key):self.no_password(self.call({'duplicateAuthorize':key}))

    def test_form_and_button_must_post_only_to_owned_realm(self):
        variants=[{'formAction':'https://outside.invalid/password'},
                  {'formAction':self.input['issuer'].replace('helix-fixture','other')+'/login-actions/authenticate'},
                  {'buttonAction':'https://outside.invalid/password'},{'formMethod':'get'}]
        for scenario in variants:
            with self.subTest(scenario=scenario):self.no_password(self.call(scenario))

    def test_missing_or_ambiguous_theme_controls_do_not_guess(self):
        for key in ('missingSelector','duplicateSelector'):
            for selector in ('kc-form-login','username','password','kc-login'):
                with self.subTest(key=key,selector=selector):self.no_password(self.call({key:selector}))

    def test_action_changed_after_fill_never_submits(self):
        data=self.call({'actionAfterFill':'https://outside.invalid/password'})
        self.assertTrue(any(event['event']=='fill' for event in data['events']))
        self.assertFalse(any(event['event']=='click' for event in data['events']))
        self.assertNotEqual((data['result'] or {}).get('form_status'),'PASS')

    def test_actual_post_guard_blocks_target_changed_at_click_and_redirect_replay(self):
        for scenario in ({'postAction':'https://outside.invalid/password'},
                         {'replayPost':'https://outside.invalid/password'}):
            with self.subTest(scenario=scenario):
                data=self.call(scenario)
                self.assertTrue(any(event['event']=='aborted' for event in data['events']))
                self.assertNotEqual((data['result'] or {}).get('form_status'),'PASS')

    def test_credential_xhr_to_other_allowed_origin_path_is_blocked_before_continue(self):
        for target in (self.input['app_origin']+'/collect',self.input['issuer'].replace('helix-fixture17','helix-otherrealm')+'/login-actions/authenticate'):
            for method in ('POST','PUT','PATCH'):
                with self.subTest(target=target,method=method):
                    data=self.call({'postAction':target,'postNavigation':False,'postMethod':method})
                    self.assertFalse(any(event['event']=='request' and event['method'] not in ('GET','HEAD') for event in data['events']))
                    self.assertTrue(any(event['event']=='aborted' for event in data['events']))

    def test_callback_state_code_exact_path_origin_and_duplicates_are_required(self):
        variants=[{'callbackParams':{'state':'WRONG_STATE'}},{'callbackParams':{'state':None}},
                  {'callbackParams':{'code':None}},{'callbackParams':{'error':'access_denied','code':None}},
                  {'callbackPath':'/wrong/callback'},{'callbackOrigin':'https://outside.invalid'},
                  {'callbackOrigin':'https://localhost:44303'},{'duplicateCallback':'state'},{'duplicateCallback':'code'}]
        for scenario in variants:
            with self.subTest(scenario=scenario):
                data=self.call(scenario)
                self.assertNotEqual((data['result'] or {}).get('form_status'),'PASS')
                self.assertFalse((data['result'] or {}).get('execution',{}).get('callback_observed',False))

    def test_secret_values_from_queries_and_exceptions_never_enter_public_results(self):
        for scenario in ({},{'fillThrows':True}):
            with self.subTest(scenario=scenario):
                data=self.call(scenario);public=json.dumps({key:data[key] for key in ('result','emitted','error')})
                for value in ('PASSWORD_CANARY_17','AUTH_CODE_CANARY_17','STATE_CANARY_17','NONCE_CANARY_17',
                              'COOKIE_VALUE_CANARY_17','FORM_SESSION_CANARY_17','FORM_EXECUTION_CANARY_17'):
                    self.assertNotIn(value,public)

    def test_context_setup_errors_always_close_and_release(self):
        for scenario in ({'routeThrows':True},{'newPageThrows':True}):
            with self.subTest(scenario=scenario):
                data=self.call(scenario)
                self.assertEqual(data['contextCount'],data['closed'])
                self.assertEqual(data['acquired'],data['released'])
                self.no_password(data)

    def test_late_created_context_is_closed_after_operation_timeout(self):
        self.input['operation_timeout_ms']=5
        data=self.call({'newContextDelayMs':20,'drainMs':40})
        self.assertEqual(data['contextCount'],1)
        self.assertEqual(data['contextCount'],data['closed'])
        self.assertEqual(data['acquired'],data['released'])
        self.no_password(data)

    def test_iframe_callback_is_not_top_level_callback_evidence(self):
        data=self.call({'iframeCallback':True})
        self.assertNotEqual((data['result'] or {}).get('form_status'),'PASS')
        self.assertFalse((data['result'] or {}).get('execution',{}).get('callback_observed',False))

    def test_two_positive_identities_have_fresh_contexts_without_storage_transfer(self):
        self.input['identities'].append(dict(id='role-'+'b'*12,username='helix-role-'+'b'*12,
            email_verified=True,app_roles=['editor'],password='SECOND_PASSWORD_CANARY'))
        data=self.call(action='sequence')
        self.assertIsNone(data['error'],data)
        self.assertEqual([flow['identity_id'] for flow in data['result']],[row['id'] for row in self.input['identities']])
        self.assertTrue(all(flow['form_status']=='PASS' and flow['status']=='INCOMPLETE' for flow in data['result']))
        contexts=[event for event in data['events'] if event['event']=='context']
        self.assertEqual(len(contexts),2)
        self.assertTrue(all('storageState' not in event['options'] for event in contexts))
        self.assertEqual([(event['index'],event['identityIndex']) for event in data['events'] if event['event']=='fill'],[(1,0),(1,0),(2,1),(2,1)])
        self.assertEqual((data['contextCount'],data['closed'],data['acquired'],data['released']),(2,2,2,2))

    def test_disabled_pkce_is_preserved_without_synthetic_challenge(self):
        self.input['pkce']='disabled'
        data=self.call();self.assertEqual(self.no_claims(data)['form_status'],'PASS')

    def test_unknown_identity_and_nonpositive_contract_do_not_start_login(self):
        data=self.call(identityId='role-'+'f'*12);self.no_password(data)
        self.assertNotEqual((data['result'] or {}).get('form_status'),'PASS')
        for changes in ({'email_verified':False},{'app_roles':[]}):
            with self.subTest(changes=changes):
                original=copy.deepcopy(self.input['identities'][0])
                self.input['identities'][0].update(changes)
                self.no_password(self.call())
                self.input['identities'][0]=original

    def test_private_reader_rejects_symlink_parent_leaf_and_unsafe_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();private=root/'private';private.mkdir(mode=0o700)
            source=private/'login.json';source.write_text(json.dumps(self.input));source.chmod(0o600)
            good=self.call(action='read',file=str(source),privateRoot=str(private))
            self.assertIsNone(good['error'])
            leaf=private/'leaf.json';leaf.symlink_to(source)
            nested=private/'nested';nested.mkdir(mode=0o700)
            nested_source=nested/'login.json';nested_source.write_text(json.dumps(self.input));nested_source.chmod(0o600)
            parent=private/'alias';parent.symlink_to(nested,target_is_directory=True)
            for path in (leaf,parent/'login.json'):
                with self.subTest(path=path):self.assertIsNotNone(self.call(action='read',file=str(path),privateRoot=str(private))['error'])
            source.chmod(0o644)
            self.assertIsNotNone(self.call(action='read',file=str(source),privateRoot=str(private))['error'])

    @unittest.skipUnless(hasattr(os,'mkfifo'),'FIFO not supported')
    def test_private_reader_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            private=Path(temporary).resolve();private.chmod(0o700)
            fifo=private/'input.json';os.mkfifo(fifo,0o600)
            started=time.monotonic()
            self.assertIsNotNone(self.call(action='read',file=str(fifo),privateRoot=str(private))['error'])
            self.assertLess(time.monotonic()-started,2)


if __name__=='__main__':unittest.main()
