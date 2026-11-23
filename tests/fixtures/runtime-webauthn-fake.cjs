'use strict';
// Browser/CDP stimuli only. The production helpers decide every observation.
const {EventEmitter}=require('node:events');
const clone=value=>JSON.parse(JSON.stringify(value));
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const pending=()=>new Promise(()=>{});
const b64url=value=>Buffer.from(value).toString('base64url');
const CREDENTIAL=Buffer.from('PRIVATE_CREDENTIAL_ID_WEBAUTHN_22');
const OTHER_CREDENTIAL=Buffer.from('OTHER_PRIVATE_CREDENTIAL_ID_WEBAUTHN_22');
const CANARY='PRIVATE_WEBAUTHN_EVENT_CANARY_22';

function put(root,pointer,value){
 const parts=pointer.slice(1).split('/').map(v=>v.replace(/~1/g,'/').replace(/~0/g,'~'));
 let node=root;for(const p of parts.slice(0,-1)){node[p]??={};node=node[p];}node[parts.at(-1)]=value;
}
function createBrowserFixture(spec){
 const input=spec.input,policy=input.policy_input,form=policy.form_input,raw=input.webauthn,scenario=spec.scenario||{};
 const events=[],formEmits=[],policyEmits=[],webauthnEmits=[];
 const counters={contexts:0,closed:0,alive:0,maxAlive:0,pages:0,pagesClosed:0,cdp:0,detached:0,
  devices:0,removed:0,acquired:0,released:0,activePermits:0,maxPermits:0,forbidden:0};
 let webWrites=0,requestSeq=0;const ownedContexts=[];
 const authorizationURL=()=>{
  const url=new URL(form.authorization_endpoint);
  for(const [k,v] of Object.entries({response_type:'code',scope:'openid',client_id:form.client_id,
   redirect_uri:form.app_origin+form.callback_paths[0],state:'STATE_CANARY_W22',nonce:'NONCE_CANARY_W22',
   ...(form.pkce==='S256'?{code_challenge:'C'.repeat(43),code_challenge_method:'S256'}:{})}))url.searchParams.set(k,v);
  return url.href;
 };
 const formAction=()=>{
  const u=new URL(form.issuer+'/login-actions/authenticate');
  u.searchParams.set('client_id',form.client_id);u.searchParams.set('session_code','SESSION_CODE_CANARY_W22');
  u.searchParams.set('execution','EXECUTION_CANARY_W22');return u.href;
 };
 const browser={version:()=>scenario.browserVersion??'130.0.6723.91',close:async()=>{for(const c of ownedContexts)await c.close();},newContext:async options=>{
  const contextId=++counters.contexts;counters.alive++;counters.maxAlive=Math.max(counters.maxAlive,counters.alive);
  events.push({event:'context',context:contextId});
  if(options.ignoreHTTPSErrors||options.storageState){counters.forbidden++;throw Error('unsafe browser options');}
  const routes=[],pages=[];let actor=null,authenticated=false,closed=false,loggedOut=false,postKey=false;
  const contextEmitter=new EventEmitter();
  const context={on:(...a)=>contextEmitter.on(...a),off:(...a)=>contextEmitter.off(...a),
   route:async(pattern,fn)=>{routes.push(fn);},unroute:async(pattern,fn)=>{if(!fn)routes.length=0;else{const n=routes.indexOf(fn);if(n>=0)routes.splice(n,1);}},
   request:new Proxy({},{get(){counters.forbidden++;throw Error('APIRequestContext forbidden');}}),
   cookies:async()=>{counters.forbidden++;throw Error('cookies forbidden');},
   storageState:async()=>{counters.forbidden++;throw Error('storage forbidden');},
   close:async()=>{
    events.push({event:'context-close-attempt',context:contextId});
    if(scenario.contextCloseFailure&&pages.some(p=>p._device))throw Error(CANARY);
    if(!closed){closed=true;counters.closed++;counters.alive--;for(const page of pages)page._closed=true;events.push({event:'context-closed',context:contextId});}
   },
   newCDPSession:async page=>{
    if(scenario.cdpUnsupported)throw Error('unsupported '+CANARY);
    if(scenario.lateCDP)await delay(scenario.lateMs||180);
    const cdpId=++counters.cdp,emitter=new EventEmitter();let detached=false,device=null;
    events.push({event:'cdp-created',context:contextId,page:page._id,cdp:cdpId});
    const cdp={on:(...a)=>emitter.on(...a),off:(...a)=>emitter.off(...a),removeListener:(...a)=>emitter.removeListener(...a),
     send:async(method,params={})=>{
      events.push({event:'cdp-command',context:contextId,page:page._id,cdp:cdpId,method});
      if(['WebAuthn.addCredential','WebAuthn.getCredentials','WebAuthn.setUserVerified'].includes(method)){counters.forbidden++;throw Error('forbidden CDP method');}
      if(method==='WebAuthn.enable'||method==='WebAuthn.disable')return {};
      if(method==='WebAuthn.addVirtualAuthenticator'){
       if(scenario.lateAuthenticator)await delay(scenario.lateMs||180);
       if(scenario.authenticatorUnsupported)throw Error(CANARY);
       counters.devices++;device='owned-device-'+cdpId;page._device={id:device,emitter,cdp,profile:clone(params.options)};
       events.push({event:'device-created',context:contextId,page:page._id,cdp:cdpId});return {authenticatorId:device};
      }
      if(method==='WebAuthn.removeVirtualAuthenticator'){
       if(scenario.removeFailure)throw Error(CANARY);
       if(params.authenticatorId!==device)throw Error('wrong owned device');
       if(device!==null){device=null;counters.removed++;events.push({event:'device-removed',context:contextId,page:page._id,cdp:cdpId});}return {};
      }
      throw Error('unexpected CDP method');
     },detach:async()=>{if(scenario.detachFailure)throw Error(CANARY);if(!detached){detached=true;counters.detached++;events.push({event:'cdp-detached',context:contextId,page:page._id,cdp:cdpId});}}};
    return cdp;
   },
   newPage:async()=>{
    // Login page + one initial session probe + each selected initial cell.
    // Do not accidentally exercise a policy timeout instead of late WebAuthn ownership.
    const initialCells=policy.public_plan_part.cells.filter(c=>c.identity_id===actor?.id).length;
    const isCeremony=authenticated&&actor?.id===input.binding.identity_id&&pages.length===2+initialCells;
    if(isCeremony&&scenario.latePage)await delay(scenario.lateMs||180);
    const pageId=++counters.pages,emitter=new EventEmitter(),pageRoutes=[],frame={parentFrame:()=>null};
    let current='about:blank';
    const page={_id:pageId,_closed:false,_device:null,
     mainFrame:()=>frame,context:()=>context,url:()=>current,isClosed:()=>page._closed,
     on:(...a)=>{emitter.on(...a);return page;},off:(...a)=>{emitter.off(...a);return page;},removeListener:(...a)=>{emitter.removeListener(...a);return page;},
     route:async(pattern,fn)=>pageRoutes.push(fn),unroute:async(pattern,fn)=>{const n=pageRoutes.indexOf(fn);if(n>=0)pageRoutes.splice(n,1);},
     evaluate:async()=>{counters.forbidden++;throw Error('navigator/page script replacement forbidden');},
     addInitScript:async()=>{counters.forbidden++;throw Error('init script forbidden');},
     waitForTimeout:delay,
     close:async()=>{events.push({event:'page-close-attempt',context:contextId,page:pageId});if(page._device&&scenario.pageCloseFailure)throw Error(CANARY);if(!page._closed){page._closed=true;counters.pagesClosed++;events.push({event:'page-closed',context:contextId,page:pageId});}},
     waitForURL:async predicate=>{for(let i=0;i<300;i++){const u=new URL(current);if(typeof predicate==='function'?predicate(u):typeof predicate==='string'?u.href===predicate:predicate.test(u.href))return;await delay(1);}throw Error('synthetic navigation timeout');},
    };
    const emit=(name,value)=>{emitter.emit(name,value);contextEmitter.emit(name,value);};
    async function route(req){
     const handlers=[...routes,...pageRoutes];let continued=false,aborted=false;
     async function dispatch(index){if(index<0){continued=true;return;}await handlers[index]({request:()=>req,
      continue:async()=>{continued=true;},abort:async()=>{aborted=true;events.push({event:'aborted',context:contextId,page:pageId,request:req._seq,path:new URL(req.url()).pathname});},fallback:async()=>dispatch(index-1)});}
     await dispatch(handlers.length-1);if(aborted||!continued)throw Error('synthetic request aborted');
    }
    function request(url,method,{body=null,navigation=false,from=null,foreignFrame=false}={}){
     const requestFrame=foreignFrame?{parentFrame:()=>frame}:frame;
     const headers={'content-type':'application/json'};
     return {_seq:++requestSeq,url:()=>url,method:()=>method,frame:()=>requestFrame,
      isNavigationRequest:()=>navigation,resourceType:()=>navigation?'document':'fetch',redirectedFrom:()=>from,
      postData:()=>body===null?null:JSON.stringify(body),postDataBuffer:()=>body===null?null:Buffer.from(JSON.stringify(body)),
      headers:()=>({...headers}),allHeaders:async()=>({...headers})};
    }
    function resultFor(url){
     const parsed=new URL(url),path=parsed.pathname;
     if(parsed.origin!==form.app_origin)return {status:200,body:''};
     if(path===form.login_path)return {status:302,body:'',location:authorizationURL()};
     if(form.callback_paths.includes(path))return {status:200,body:''};
     const isSession=path===policy.policy.session.path;
     if(isSession){
      if(!authenticated)return {status:401,body:''};
      const data={};
      for(const a of policy.policy.session.assertions){let value=a.equals_identity==='email'?actor.username+'@example.invalid':actor[a.equals_identity];
       if(postKey&&scenario.postIdentityMismatch&&['username','email'].includes(a.equals_identity))value='OTHER_IDENTITY_CANARY_W22';
       if(postKey&&scenario.postRolesMismatch&&a.equals_identity==='app_roles')value=['other-role'];
       put(data,a.pointer,clone(value));}
      return {status:200,body:data};
     }
     const rawCell=policy.policy.cells.find(c=>c.request.path===path&&actor?.app_roles.includes(c.identity.role));
     if(policy.policy.cells.some(c=>c.request.path===path)){
      if(!authenticated)return {status:401,body:''};
      if(rawCell?.expected.access==='deny')return {status:rawCell.expected.denial.codes[0],body:''};
      const data={};for(const a of rawCell?.expected.json||[])put(data,a.pointer,postKey&&scenario.postCellMismatch?'WRONG_CELL_CANARY_W22':a.equals_literal);
      return {status:200,body:data};
     }
     return {status:200,body:'',mime:'text/html'};
    }
    async function send(url,method='GET',options={}){
     if(url==='about:blank'){current=url;events.push({event:'blank',context:contextId,page:pageId});return null;}
     const req=request(url,method,options);await route(req);
     const parsed=new URL(url);
     events.push({event:'request',context:contextId,page:pageId,request:req._seq,origin:parsed.origin,path:parsed.pathname,method,authenticated,postKey});
     emit('request',req);
     const data=options.response||resultFor(url);if(options.navigation)current=url;
     const headers={'content-type':data.mime||'application/json',...(data.location?{location:data.location}:{}),...(data.contentLength!==undefined?{'content-length':String(data.contentLength)}:{})};
     const response={url:()=>url,status:()=>data.status,request:()=>data.foreignRequest?request(url,method,options):req,
      headers:()=>({...headers}),allHeaders:async()=>({...headers}),headerValue:async name=>headers[String(name).toLowerCase()]??null,
      body:async()=>{if(data.bodyPending)return pending();if(data.bodyBytes)return Buffer.alloc(data.bodyBytes,65);return Buffer.from(typeof data.body==='string'?data.body:JSON.stringify(data.body));}};
     response.text=async()=>(await response.body()).toString();response.json=async()=>JSON.parse(await response.text());
     emit('response',response);emit('requestfinished',req);
     if(data.location)return send(new URL(data.location,url).href,'GET',{navigation:true,from:req});
     return response;
    }
    page.goto=async url=>send(String(url),'GET',{navigation:true});
    function credentialEvent(phase,id){
     if(scenario.noCredentialEvent||scenario.noCredentialEvent===phase)return;
     const device=page._device;if(!device)return;
     const kind=phase==='registration'?'WebAuthn.credentialAdded':'WebAuthn.credentialAsserted';
     device.emitter.emit(kind,{authenticatorId:scenario.foreignAuthenticator?'foreign-device':device.id,
      credential:{credentialId:id.toString('base64'),rpId:scenario.eventRpMismatch?'other.invalid':'localhost',
       privateKey:CANARY,userHandle:'PRIVATE_USER_HANDLE_CANARY_W22',signCount:1,isResidentCredential:true},
      unexpected_private_field:CANARY});
     events.push({event:'credential-event',phase,context:contextId,page:pageId});
    }
    async function ceremony(phase){
     events.push({event:'ceremony-click',phase,context:contextId,page:pageId});
     const flow=raw[phase],isRegistration=phase==='registration',challenge=Buffer.from('PRIVATE_CHALLENGE_'+phase+'_W22');
     const id=!isRegistration&&scenario.otherCredential?OTHER_CREDENTIAL:CREDENTIAL;
     const options={challenge:challenge.toString('base64url'),...(isRegistration?{rp:{id:'localhost',name:'Synthetic RP'},user:{id:b64url('PRIVATE_USER_HANDLE_CANARY_W22'),name:actor.username,displayName:'Synthetic'}}:{rpId:'localhost'})};
     if(scenario.optionsRpMismatch)if(isRegistration)options.rp.id='other.invalid';else options.rpId='other.invalid';
     const optResponse={status:scenario.optionsStatus??200,body:scenario.optionsWrapper?{publicKey:options}:options,
      mime:scenario.optionsMime||'application/json',bodyBytes:scenario.optionsBodyBytes,foreignRequest:scenario.foreignResponse,
      location:scenario.optionsRedirect||undefined};
     await send(form.app_origin+flow.options.path,flow.options.method,{body:flow.options.method==='POST'?{}:null,response:optResponse,foreignFrame:scenario.iframeFlow});
     if(scenario.duplicateOptions)await send(form.app_origin+flow.options.path,flow.options.method,{response:optResponse});
     credentialEvent(phase,id);
     if(scenario.eventOnly)return;
     const clientData={type:isRegistration?'webauthn.create':'webauthn.get',origin:form.app_origin,challenge:challenge.toString('base64url'),crossOrigin:false};
     if(scenario.challengeMismatch)clientData.challenge=b64url('OTHER_PRIVATE_CHALLENGE_W22');
     if(scenario.originMismatch)clientData.origin='https://outside.invalid';
     if(scenario.typeMismatch)clientData.type=isRegistration?'webauthn.get':'webauthn.create';
     if(scenario.crossOrigin)clientData.crossOrigin=true;
     const body={id:(scenario.idMismatch?OTHER_CREDENTIAL:id).toString('base64url'),rawId:id.toString('base64url'),type:'public-key',
      response:{clientDataJSON:b64url(JSON.stringify(clientData)),attestationObject:b64url(CANARY),authenticatorData:b64url(CANARY),signature:b64url(CANARY)}};
     const responseBody={};for(const a of flow.verify.json)put(responseBody,a.pointer,scenario.verifyMismatch?'REJECTED_CANARY_W22':a.equals_literal);
     const verifyTarget=scenario.verifyOutside?'https://outside.invalid/collect':scenario.verifyOtherPath?form.app_origin+'/collect':form.app_origin+flow.verify.path;
     await send(verifyTarget,flow.verify.method,{body:scenario.verifyWrapper?{credential:body}:body,foreignFrame:scenario.iframeFlow,
      response:{status:scenario.verifyStatus??200,body:responseBody,mime:scenario.verifyMime||'application/json',bodyPending:scenario.verifyBodyPending}});
     if(scenario.duplicateVerify)await send(verifyTarget,flow.verify.method,{body,response:{status:200,body:responseBody}});
     if(!isRegistration){authenticated=true;postKey=true;events.push({event:'key-session',context:contextId,page:pageId});}
    }
    function locator(selector){
     const password=selector.includes('password'),user=selector.includes('username'),loginForm=selector.includes('kc-form-login'),loginButton=selector.includes('kc-login');
     const phase=['registration','authentication'].find(p=>selector.includes(raw[p].action.test_id));
     const logout=selector.includes(raw.logout.action.test_id);
     return {count:async()=>phase&&scenario.ambiguousAction?2:password||user||loginForm||loginButton||phase||logout?1:0,
      isVisible:async()=>!scenario.invisibleAction,
      getAttribute:async name=>name==='method'?'post':name==='action'?formAction():name==='formaction'?null:name==='type'?(loginButton?'submit':password?'password':'text'):null,
      fill:async value=>{if(user)actor=form.identities.find(i=>i.username===value)||null;events.push({event:'fill',context:contextId,page:pageId,field:password?'password':'username',identity:actor?.id||null});},
      click:async opts=>{if(opts?.force){counters.forbidden++;throw Error('force forbidden');}
       if(phase)return ceremony(phase);
       if(logout){events.push({event:'logout-click',context:contextId,page:pageId});
        if(!scenario.noLogoutRequest){
         const args={body:raw.logout.request.method==='POST'?{}:null,response:{status:scenario.logoutRedirect?302:200,body:{},location:scenario.logoutRedirect?'/after-logout':undefined}};
         await send(form.app_origin+raw.logout.request.path,raw.logout.request.method,args);
         if(scenario.duplicateLogout)await send(form.app_origin+raw.logout.request.path,raw.logout.request.method,args);
        }
        if(!scenario.logoutKeepsSession){authenticated=false;loggedOut=true;}return;}
       await send(formAction(),'POST',{navigation:true});const callback=new URL(form.app_origin+form.callback_paths[0]);
       callback.searchParams.set('code','AUTH_CODE_CANARY_W22');callback.searchParams.set('state','STATE_CANARY_W22');
       await send(callback.href,'GET',{navigation:true});authenticated=true;
      },locator:next=>locator(selector+' '+next),first(){return this;}};
    }
    page.locator=locator;page.getByTestId=id=>locator('[data-testid="'+id+'"]');
    pages.push(page);events.push({event:'page',context:contextId,page:pageId});return page;
   }};
  ownedContexts.push(context);return context;
 }};
 const gate={acquire:async()=>{counters.acquired++;counters.activePermits++;counters.maxPermits=Math.max(counters.maxPermits,counters.activePermits);events.push({event:'acquire'});if(counters.activePermits>1)throw Error('nested permit');},release:()=>{counters.released++;counters.activePermits--;events.push({event:'release'});}};
 const emitForm=row=>{formEmits.push(clone(row));events.push({event:'form-checkpoint',index:formEmits.length-1});};
 const emitPolicy=row=>{policyEmits.push(clone(row));events.push({event:'policy-checkpoint',index:policyEmits.length-1});};
 const emitWebAuthn=row=>{
  webWrites++;
  if(scenario.writerFailureAt===webWrites||scenario.writerFailureAfterRegistration&&row.registration.status==='PASS'||
     scenario.writerFailureAfterPostSession&&row.session_after_authentication.status==='FAIL'){
   events.push({event:'webauthn-write-failed'});throw Error(CANARY);
  }
  webauthnEmits.push(clone(row));events.push({event:'webauthn-checkpoint',index:webauthnEmits.length-1});
 };
 return {browser,gate,events,counters,formEmits,policyEmits,webauthnEmits,emitForm,emitPolicy,emitWebAuthn};
}
module.exports={createBrowserFixture};

if(require.main===module)(async()=>{
 const fs=require('node:fs'),Module=require('node:module'),original=Module._load;
 Module._load=function(id,...args){if(/^(?:node:)?(?:http|https|net|tls|dns|child_process)$/.test(id))throw Error('unexpected external IO');return original.call(this,id,...args);};
 global.fetch=()=>{throw Error('unexpected fetch');};
 const web=require(process.argv[2]),policy=require(process.argv[3]),login=require(process.argv[4]);
 const spec=JSON.parse(fs.readFileSync(0,'utf8')),fixture=createBrowserFixture(spec),before=JSON.stringify(spec.input);
 let result=null,formResult=null,policyResult=null,error=null,hooks=null;
 try{
  const policyHooks=policy.createPolicyHooks({input:spec.input.policy_input,emitSuite:fixture.emitPolicy});
  hooks=web.createWebAuthnHooks({input:spec.input,policyHooks,emitSuite:fixture.emitWebAuthn,randomBytes:()=>Buffer.alloc(16,7)});
  formResult=await login.runLoginSuite({browser:fixture.browser,input:spec.input.policy_input.form_input,gate:fixture.gate,
   policyHooks,webauthnHooks:hooks,emit:()=>{},emitSuite:fixture.emitForm});
  result=hooks.snapshot();policyResult=policyHooks.snapshot();
 }catch(caught){error={name:caught.name,code:caught.code||caught.reason_code||null};if(hooks)result=hooks.snapshot();}
 if(spec.scenario?.drainMs)await delay(spec.scenario.drainMs);
 process.stdout.write(JSON.stringify({result,formResult,policyResult,error,inputUnchanged:before===JSON.stringify(spec.input),
  events:fixture.events,counters:fixture.counters,formEmits:fixture.formEmits,policyEmits:fixture.policyEmits,webauthnEmits:fixture.webauthnEmits}));
})().catch(()=>{process.stderr.write('synthetic WebAuthn driver failure');process.exitCode=2;});
