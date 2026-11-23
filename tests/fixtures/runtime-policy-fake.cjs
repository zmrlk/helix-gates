'use strict';
// Fake browser only. Policy and OIDC decisions are made by the actual helpers.
function createBrowserFixture(spec){
const input=spec.input,form=input.form_input,scenario=spec.scenario||{};
const clone=value=>JSON.parse(JSON.stringify(value));
const events=[],policyEmits=[],formEmits=[];
const counters={contexts:0,closed:0,acquired:0,released:0,activePermits:0,maxPermits:0,alive:0,maxAlive:0};
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const forever=()=>new Promise(()=>{});
let emitCount=0;

function request(url,method,frame,from=null){return {
  url:()=>url,method:()=>method,frame:()=>frame,redirectedFrom:()=>null,isNavigationRequest:()=>true,
  resourceType:()=> 'document',redirectedFrom:()=>from,postData:()=>method==='POST'?'PRIVATE_POST_BODY':null
};}
function authorizationURL(){
  const url=new URL(form.authorization_endpoint);
  for(const [key,value] of Object.entries({response_type:'code',scope:'openid',client_id:form.client_id,
    redirect_uri:form.app_origin+form.callback_paths[0],state:'STATE_CANARY_POLICY',nonce:'NONCE_CANARY_POLICY',
    ...(form.pkce==='S256'?{code_challenge:'C'.repeat(43),code_challenge_method:'S256'}:{})}))url.searchParams.set(key,value);
  return url.href;
}
function formAction(){
  const url=new URL(form.issuer+'/login-actions/authenticate');
  url.searchParams.set('client_id',form.client_id);url.searchParams.set('session_code','SESSION_CODE_CANARY_POLICY');
  url.searchParams.set('execution','EXECUTION_CANARY_POLICY');return url.href;
}

const browser={newContext:async options=>{
  const attempt=++counters.contexts;
  if(scenario.lateContext===attempt)await delay(scenario.lateContextMs||150);
  counters.alive++;counters.maxAlive=Math.max(counters.maxAlive,counters.alive);
  events.push({event:'context',context:attempt,options:clone(options)});
  if(options.ignoreHTTPSErrors||options.storageState)throw Error('unsafe context setup');
  let closed=false,actor=null,authenticated=false,current='about:blank',pageCount=0;
  const routes=[];
  let listeners=new Map(),mainFrame={parentFrame:()=>null};
  const emit=(kind,value)=>{for(const listener of [...(listeners.get(kind)||[])])listener(value);};
  async function routeRequest(req){
    let continued=false,aborted=false;
    async function dispatch(index){
      if(index<0){continued=true;return;}
      await routes[index]({request:()=>req,
        continue:async()=>{continued=true;},
        abort:async()=>{aborted=true;events.push({event:'aborted',context:attempt,origin:new URL(req.url()).origin,path:new URL(req.url()).pathname});},
        fallback:async()=>dispatch(index-1)});
    }
    await dispatch(routes.length-1);
    if(aborted||!continued)throw Error('synthetic navigation aborted');
  }
  function responseSpec(url){
    const parsed=new URL(url),path=parsed.pathname;
    if(parsed.origin!==form.app_origin)return {status:200,body:''};
    if(path===form.login_path)return {status:302,body:'',location:authorizationURL()};
    if(form.callback_paths.includes(path))return {status:scenario.formFailure?403:200,body:''};
    const session=path===input.policy.session.path;
    if(!authenticated){
      if(session&&scenario.anonymousSessionPublic)return {status:200,body:{user:clone(form.identities[0])}};
      if(!session&&scenario.anonymousRouteStatus!==undefined)return {status:scenario.anonymousRouteStatus,body:'ANONYMOUS_BODY_CANARY',location:scenario.anonymousLocation};
      return {status:401,body:''};
    }
    if(session){
      if(scenario.sessionException)throw Error('COOKIE_CANARY_POLICY TOKEN_CANARY_POLICY');
      const user={username:actor.username,roles:clone(actor.app_roles),emailVerified:actor.email_verified};
      if(scenario.sessionMismatch)user.username='OTHER_USERNAME_CANARY_POLICY';
      if(scenario.sessionRoles!==undefined)user.roles=scenario.sessionRoles;
      let body={user};
      if(scenario.missingUsername)delete user.username;
      if(scenario.sessionBody!==undefined)body=scenario.sessionBody;
      return {status:200,body,mime:scenario.sessionMime,bodyBytes:scenario.sessionBodyBytes,
              contentLength:scenario.contentLength,bodyPending:scenario.sessionBodyPending};
    }
    const role=actor.app_roles[0];
    if(scenario.resourceStatus!==undefined)return {status:scenario.resourceStatus,body:{kind:scenario.resourceValue}};
    if(role==='editor')return {status:403,body:''};
    const rawCell=input.policy.cells.find(cell=>cell.identity.role===role&&cell.request.path===path);
    const literal=rawCell?.expected?.json?.[0]?.equals_literal;
    return {status:200,body:{kind:scenario.resourceValue===undefined?literal:scenario.resourceValue}};
  }
  async function navigate(url,method='GET',from=null){
    const req=request(url,method,mainFrame,from);
    await routeRequest(req);
    const parsed=new URL(url);
    events.push({event:'request',context:attempt,origin:parsed.origin,path:parsed.pathname,method,actor:actor?actor.id:null,authenticated});
    emit('request',req);
    const data=responseSpec(url);current=url;
    const content=typeof data.body==='string'?data.body:JSON.stringify(data.body);
    const headers={'content-type':data.mime||'application/json',
      ...(data.location?{location:data.location}:{}),...(data.contentLength!==undefined?{'content-length':String(data.contentLength)}:{})};
    const body=async()=>{
      events.push({event:'body-read',context:attempt,path:parsed.pathname});
      if(data.bodyPending)return forever();
      if(data.bodyBytes)return Buffer.alloc(data.bodyBytes,65);
      return Buffer.from(content);
    };
    const response={url:()=>url,status:()=>data.status,request:()=>req,headers:()=>({...headers}),
      allHeaders:async()=>({...headers}),headerValue:async key=>headers[String(key).toLowerCase()]??null,
      body,text:async()=>(await body()).toString(),json:async()=>JSON.parse((await body()).toString()),ok:()=>data.status>=200&&data.status<300};
    emit('response',response);
    if(data.location)return navigate(new URL(data.location,url).href,'GET',req);
    return response;
  }
  function locator(selector){
    const isPassword=selector.includes('password'),isUser=selector.includes('username'),isForm=selector.includes('kc-form-login'),isButton=selector.includes('kc-login');
    return {count:async()=>isPassword||isUser||isForm||isButton?1:0,
      getAttribute:async name=>name==='method'?'post':name==='action'?formAction():name==='formaction'?null:name==='type'?(isButton?'submit':isPassword?'password':'text'):null,
      fill:async value=>{
        if(isUser)actor=form.identities.find(identity=>identity.username===value)||null;
        events.push({event:'fill',context:attempt,field:isPassword?'password':'username',actor:actor?actor.id:null});
      },
      click:async()=>{
        await navigate(formAction(),'POST');
        const callback=new URL(form.app_origin+form.callback_paths[0]);
        callback.searchParams.set('code','AUTH_CODE_CANARY_POLICY');callback.searchParams.set('state','STATE_CANARY_POLICY');
        await navigate(callback.href);
        authenticated=!scenario.formFailure;
      },locator:next=>locator(selector+' '+next),first(){return this;}};
  }
  const page={on:(name,fn)=>listeners.set(name,[...(listeners.get(name)||[]),fn]),
    off:(name,fn)=>listeners.set(name,(listeners.get(name)||[]).filter(item=>item!==fn)),
    goto:async url=>navigate(String(url)),url:()=>current,locator,mainFrame:()=>mainFrame,
    close:async()=>{listeners.clear();events.push({event:'page-close',context:attempt,page:pageCount});},
    waitForURL:async predicate=>{
      for(let i=0;i<250;i++){
        const url=new URL(current);
        if(typeof predicate==='function'?predicate(url):typeof predicate==='string'?url.href===predicate:predicate.test(url.href))return;
        await delay(1);
      }
      throw Error('synthetic URL timeout');
    }};
  return {route:async(pattern,handler)=>{routes.push(handler);if(scenario.routeFailure===attempt)throw Error('synthetic route setup error');},
    unroute:async(pattern,handler)=>{if(!handler)routes.length=0;else{const index=routes.indexOf(handler);if(index>=0)routes.splice(index,1);}},
    newPage:async()=>{
      if(scenario.pageFailure===attempt)throw Error('synthetic page setup error');
      pageCount++;listeners=new Map();mainFrame={parentFrame:()=>null};current='about:blank';
      events.push({event:'page',context:attempt,page:pageCount});return {...page};
    },
    get request(){throw Error('APIRequestContext is forbidden');},
    cookies:async()=>{throw Error('cookie inspection is forbidden');},
    storageState:async()=>{throw Error('storage export is forbidden');},
    close:async()=>{
      events.push({event:'close-attempt',context:attempt});
      if(scenario.closeFailure===attempt)throw Error('synthetic close error TOKEN_CANARY_POLICY');
      if(!closed){closed=true;counters.closed++;counters.alive--;events.push({event:'closed',context:attempt});}
    }};
}};

const gate={acquire:async()=>{
  if(scenario.admissionPending)return forever();
  if(scenario.pauseAfter!==undefined&&counters.acquired>=scenario.pauseAfter){const error=Error('resource pause');error.code='RESOURCE_PAUSED';throw error;}
  counters.acquired++;counters.activePermits++;counters.maxPermits=Math.max(counters.maxPermits,counters.activePermits);
  events.push({event:'acquire'});
  if(counters.activePermits>1)throw Error('nested admission while holding permit');
},release:()=>{counters.released++;counters.activePermits--;events.push({event:'release'});}};

function emitPolicy(row){
  emitCount++;
  if(scenario.emitFailureAt===emitCount || scenario.emitAfterCompletedCell&&row.cells.some(cell=>cell.result==='PASS')){
    events.push({event:'policy-write-failed'});throw Error('writer failure TOKEN_CANARY_POLICY');
  }
  policyEmits.push(clone(row));events.push({event:'policy-checkpoint',index:policyEmits.length-1});
}
return {browser,gate,events,counters,policyEmits,formEmits,emitPolicy,
  emitForm:row=>formEmits.push(clone(row))};
}

module.exports={createBrowserFixture};
if(require.main===module)(async()=>{
  const fs=require('fs'),Module=require('module'),originalLoad=Module._load;
  Module._load=function(id,...args){
    if(/^(?:node:)?(?:http|https|net|tls|dns|child_process)$/.test(id))throw Error('unexpected external IO');
    return originalLoad.call(this,id,...args);
  };
  global.fetch=()=>{throw Error('unexpected fetch');};
  const policy=require(process.argv[2]),login=require(process.argv[3]);
  const spec=JSON.parse(fs.readFileSync(0,'utf8')),input=spec.input,scenario=spec.scenario||{};
  const fixture=createBrowserFixture(spec);
  const {browser,gate,events,counters,policyEmits,formEmits}=fixture;
  let result=null,error=null,formResult=null;
  try{
    const hooks=policy.createPolicyHooks({input,emitSuite:fixture.emitPolicy});
    formResult=await login.runLoginSuite({browser,input:input.form_input,gate,policyHooks:hooks,
      emit:()=>{},emitSuite:fixture.emitForm});
    result=hooks.snapshot();
  }catch(caught){error={name:caught.name,code:caught.code||caught.reason_code||null,message:caught.message};}
  if(scenario.drainMs)await new Promise(resolve=>setTimeout(resolve,scenario.drainMs));
  process.stdout.write(JSON.stringify({result,error,formResult,events,policyEmits,formEmits,counters}));
})().catch(()=>{process.stderr.write('synthetic policy driver failure');process.exitCode=2;});
