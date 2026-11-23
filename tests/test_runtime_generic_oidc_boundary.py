"""Generic OIDC observations never establish a session or transfer cookies."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_runtime as runtime

FAKE_PLAYWRIGHT=r'''
const fs=require('fs'),Module=require('module'),load=Module._load;
Module._load=function(id,...args){if(/^(?:node:)?(?:net|tls|http|https|dns|child_process)$/.test(id))throw Error('external IO forbidden');return load.call(this,id,...args);};
global.fetch=()=>{throw Error('fetch forbidden');};
const app='http://127.0.0.1:3100',issuer='https://127.0.0.1:4400';
const mode=process.env.SYNTHETIC_CASE,events=[];
let count=0;
exports.chromium={launch:async()=>({
 newContext:async options=>{
  const id=++count;events.push({type:'context',id,hasStorageState:!!options.storageState});
  let handler;const listeners=[];let current='about:blank';
  async function navigation(value,status=200){
   const target=new URL(value),req={url:()=>value,method:()=> 'GET',isNavigationRequest:()=>true};
   let allowed=false;
   if(handler)await handler({request:()=>req,continue:async()=>{allowed=true;},abort:async()=>{}});else allowed=true;
   if(!allowed)throw Error('blocked');
   current=value;events.push({type:'navigation',id,origin:target.origin,path:target.pathname,status});
   const response={url:()=>value,status:()=>status,request:()=>req};
   for(const callback of listeners)callback(response);
   return response;
  }
  const page={on:(name,callback)=>{if(name==='response')listeners.push(callback);},
   goto:async value=>{
    if(new URL(value).pathname==='/login'){
     await navigation(issuer+'/authorize?response_type=code',200);
     await navigation(app+'/auth/callback?code=SYNTHETIC_CODE',302);
     return navigation(app+'/welcome',200);
    }
    if(mode==='canonical-public'){
     await navigation(value,301);return navigation(value+'?locale=pl',200);
    }
    return navigation(issuer+new URL(value).pathname,200);
   },url:()=>current,
   waitForURL:async predicate=>{if(!predicate(new URL(current)))throw Error('unexpected navigation');}
  };
  return {route:async(pattern,callback)=>{handler=callback;},newPage:async()=>page,
   cookies:async()=>{events.push({type:'cookie-read',id});return [{name:'preferences',value:'PREFERENCES_CANARY',domain:'127.0.0.1',path:'/'}];},
   storageState:async()=>{events.push({type:'storage-export',id});return {cookies:[{name:'preferences',value:'PREFERENCES_CANARY',domain:'127.0.0.1',path:'/'}],origins:[]};},
   request:{get:async(value,options)=>{events.push({type:'anonymous-api-probe',id,path:new URL(value).pathname,maxRedirects:options.maxRedirects});
     return {status:()=>mode==='canonical-public'?301:401,headers:()=>({location:'/items?locale=pl'})};}},
   close:async()=>events.push({type:'closed',id})};
 },
 close:async()=>{events.push({type:'browser-closed'});fs.writeFileSync(process.env.SYNTHETIC_EVENTS,JSON.stringify(events));}
})};
'''


class GenericOIDCBoundary(unittest.TestCase):
    def browser(self,scenario='canonical-public',*,issuer=True,identity_mode=None):
        node=shutil.which('node')
        self.assertTrue(node,'Node required for the actual script fixture; missing is not a passing test')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();project=root/'project';module=project/'node_modules/playwright'
            module.mkdir(parents=True);(project/'package.json').write_text('{}')
            (module/'package.json').write_text('{"name":"playwright","main":"index.cjs"}')
            (module/'index.cjs').write_text(FAKE_PLAYWRIGHT)
            output=root/'browser.json';events_path=root/'events.json';monitor=root/'resources.json'
            monitor.write_text(json.dumps({'state':'normal','effective_jobs':1,
                'updated_at':datetime.now(timezone.utc).isoformat(),'max_pause_s':.1,'poll_s':.001,'stale_after_s':15}))
            env={'PATH':os.defpath,'HELIX_RESOURCE_FILE':str(monitor),
                 'HELIX_RUNTIME_BROWSER_BUDGETS':'{"workers":1,"navigation_ms":500}',
                 'SYNTHETIC_CASE':scenario,'SYNTHETIC_EVENTS':str(events_path)}
            if issuer:env['HELIX_RUNTIME_OIDC_ISSUER']='https://127.0.0.1:4400'
            if identity_mode:env['HELIX_RUNTIME_IDENTITY_MODE']=identity_mode
            done=subprocess.run([node,str(ROOT/'bin/runtime-browser.cjs'),'http://127.0.0.1:3100/',
                str(output),'e2e','["/items"]',str(project)],env=env,capture_output=True,text=True,timeout=5)
            self.assertEqual(done.returncode,0,done.stderr)
            raw=json.loads(output.read_text());parsed=runtime.browser_results(output)
            events=json.loads(events_path.read_text());journal=Path(str(output)+'.jsonl').read_text()
            session_exists=Path(str(output)+'.session').exists()
        return raw,parsed,events,journal,session_exists

    def observation_only(self,data):
        auth=data['auth_flow']
        self.assertEqual(auth['status'],'BLOCKED')
        self.assertEqual(auth['reason_code'],'NO_EXPLICIT_IDENTITY_POLICY')
        self.assertEqual(auth['session_coverage'],'NOT_RUN')
        self.assertEqual(auth['authorization_coverage'],'NOT_RUN')
        return auth

    def no_transfer(self,events,session_exists):
        self.assertFalse(session_exists)
        self.assertFalse(any(row['type'] in ('cookie-read','storage-export','anonymous-api-probe') for row in events))
        self.assertFalse(any(row.get('hasStorageState') for row in events))
        self.assertEqual(sum(row['type']=='context' for row in events),sum(row['type']=='closed' for row in events))

    def test_cookie_preferences_and_canonical_301_public_200_do_not_prove_auth(self):
        raw,data,events,journal,session_exists=self.browser()
        self.observation_only(raw);self.observation_only(data)
        self.assertEqual(data['routes'][0]['status'],'PASS')
        self.assertTrue(data['routes'][0]['reachable'])
        self.assertFalse(any(row['step'] in ('session','protected-route') for row in raw['auth_flow']['steps']))
        self.assertNotIn('PREFERENCES_CANARY',json.dumps(raw)+journal)
        self.no_transfer(events,session_exists)

    def test_idp_origin_same_path_cannot_prove_protected_application_route(self):
        raw,data,events,journal,session_exists=self.browser('issuer-same-path')
        self.observation_only(raw);self.observation_only(data)
        self.assertEqual(data['routes'][0]['status'],'FAIL')
        self.assertFalse(data['routes'][0]['reachable'])
        self.no_transfer(events,session_exists)

    def test_no_issuer_does_not_invent_authentication_requirement(self):
        raw,data,events,journal,session_exists=self.browser(issuer=False)
        self.assertIsNone(raw['auth_flow']);self.assertIsNone(data['auth_flow'])
        self.assertEqual(data['routes'][0]['status'],'PASS')
        self.assertFalse(any(row['type']=='navigation' and row['path']=='/login' for row in events))
        self.no_transfer(events,session_exists)

    def test_keycloak_readiness_never_reenters_generic_observation(self):
        raw,data,events,journal,session_exists=self.browser(identity_mode='keycloak-readiness')
        self.assertIsNone(raw['auth_flow']);self.assertIsNone(data['auth_flow'])
        self.assertFalse(any(row['type']=='navigation' and row['path']=='/login' for row in events))
        self.no_transfer(events,session_exists)

    def test_historical_final_or_journal_pass_is_not_recredited(self):
        legacy={'type':'auth-flow','status':'PASS','break_at':None,
                'steps':[{'step':'session','url':'http://127.0.0.1:3100/items','code':200},
                         {'step':'protected-route','url':'https://127.0.0.1:4400/items','code':200}]}
        for journal in (False,True):
            with self.subTest(journal=journal),tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary)/'browser.json'
                output.write_text(json.dumps({'routes':[],'auth_flow':None if journal else legacy}))
                if journal:Path(str(output)+'.jsonl').write_text(json.dumps(legacy)+'\n')
                original=output.read_text()
                projected=runtime.browser_results(output)
                self.observation_only(projected)
                self.assertEqual(output.read_text(),original)

    def test_planted_session_after_child_is_ignored_by_next_check_and_k6(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'logs').mkdir()
            runner=object.__new__(runtime.Runner)
            runner.tmp=runner.work=runner.out=root
            runner.env={};runner.browser_tools=True;runner.browser_module_dir=str(root/'missing-node-modules')
            runner.tools={'node':'synthetic-node','k6':'synthetic-k6'};runner.steps=0
            runner.resource_wait=lambda:None
            def command(argv,*args,**kwargs):
                if any(str(value).endswith('runtime-browser.cjs') for value in argv):
                    output=Path(argv[3])
                    output.write_text(json.dumps({'routes':[{'route':'/items','status':'PASS','reachable':True,
                        'code':200,'errors':[],'violations':[]}],'requests':[],'auth_flow':None}))
                    Path(str(output)+'.session').write_text(json.dumps({'preferences':'PLANTED_SESSION_CANARY'}))
                elif 'run' in argv and '--summary-export' in argv:
                    Path(argv[argv.index('--summary-export')+1]).write_text(json.dumps({'metrics':{
                        'http_req_duration':{'values':{'p(95)':1}},'http_req_failed':{'values':{'rate':0}}}}))
                else:raise AssertionError('Unexpected process request')
            runner.command=command
            runner.project_command=command  # This fixture tests output aggregation, not process admission.
            part={'path':'.','routes':['/items']};budgets=runtime.profile_budgets({})
            runner.measure('e2e',part,'http://127.0.0.1:3100',budgets)
            self.assertEqual(getattr(runner,'session_cookies',{}),{})
            runner.measure('a11y',part,'http://127.0.0.1:3100',budgets)
            self.assertEqual(getattr(runner,'session_cookies',{}),{})
            status,_=runner.measure('load',part,'http://127.0.0.1:3100',budgets)
            self.assertEqual(status,'PASS')
            self.assertNotIn('PLANTED_SESSION_CANARY',(root/'project-tmp/load.js').read_text())


if __name__=='__main__':unittest.main()
