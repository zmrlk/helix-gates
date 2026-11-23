'use strict';
/* Owned application WebAuthn. Import performs no I/O; credentials never leave memory. */
const crypto=require('node:crypto');
const {readPrivateJSON}=require('./runtime-keycloak-login.cjs');
const {validatePolicyInput,canonical,digest,routePath,pointer,atPointer}=require('./runtime-identity-policy.cjs');
const clone=v=>JSON.parse(JSON.stringify(v));
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const fields=(v,keys)=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const same=(a,b)=>canonical(a)===canonical(b);
const PROFILE={basis:'declared_emulation_profile',capabilities:'not_checked',protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true};
const BINDING=['run_id','integration_id','integration_plan_id','identity_plan_id','policy_plan_id','policy_hash','form_attempt_id','policy_attempt_id','part','webauthn_plan_id','webauthn_config_hash','webauthn_attempt_id','transport_plan_id','app_origin','identity_id','webauthn_integration_ids'];
const RAW=['enabled','rp_owner','rp_id','role','policy_cell_ids','registration','logout','authentication'];
const PLAN=['part','enabled','status','config_pointer','config_hash','declarations','identity_plan_id','identity_selector','identity_id','role','policy_hash','policy_cell_ids','transport_part_digest','rp_owner','rp_id','profile','registration','logout','authentication','gaps','contract_gaps'];
const FAIL=new Set(['UNEXPECTED_STATUS','REDIRECT_NOT_SUPPORTED','JSON_POINTER_MISSING','ASSERTION_MISMATCH','SESSION_IDENTITY_MISMATCH','SESSION_ROLES_MISMATCH','RP_MISMATCH','REQUEST_NOT_BOUND','CREDENTIAL_MISMATCH','DUPLICATE_CEREMONY_REQUEST']);
class WebAuthnError extends Error{constructor(code){super(code);this.code=code;}}
const fail=code=>{throw new WebAuthnError(code);};
const requireValue=ok=>{if(!ok)fail('INPUT_INVALID');};
function validateWebAuthnInput(value){try{
 requireValue(fields(value,['schema_version','kind','binding','policy_input','public_plan_part','webauthn','limits'])&&value.schema_version===1&&value.kind==='webauthn-input'&&fields(value.limits,['accepted_json_bytes'])&&value.limits.accepted_json_bytes===1048576);
 const policy=validatePolicyInput(value.policy_input),b=value.binding,p=value.public_plan_part,raw=value.webauthn;
 requireValue(fields(b,BINDING)&&BINDING.filter(k=>k!=='webauthn_integration_ids').every(k=>typeof b[k]==='string'));
 for(const key of Object.keys(policy.binding))requireValue(b[key]===policy.binding[key]);
 for(const key of ['webauthn_plan_id','webauthn_config_hash','transport_plan_id'])requireValue(/^[0-9a-f]{64}$/.test(b[key]));
 requireValue(/^webauthn-[0-9a-f]{32}$/.test(b.webauthn_attempt_id)&&b.app_origin===policy.form_input.app_origin);
 const app=new URL(b.app_origin);requireValue(app.protocol==='https:'&&app.hostname==='localhost'&&app.pathname==='/'&&!app.search&&!app.hash&&!app.username&&!app.password);
 requireValue(fields(p,PLAN)&&p.status==='PLANNED'&&p.enabled===true&&p.part===b.part&&p.config_hash===b.webauthn_config_hash&&p.identity_id===b.identity_id&&p.identity_plan_id===b.identity_plan_id&&p.policy_hash===b.policy_hash&&same(p.profile,PROFILE)&&same(p.gaps,[])&&same(p.contract_gaps,[]));
 requireValue(fields(raw,RAW)&&raw.enabled===true&&raw.rp_owner==='application'&&raw.rp_id==='localhost'&&digest(raw)===b.webauthn_config_hash&&p.rp_owner===raw.rp_owner&&p.rp_id===raw.rp_id);
 const identity=policy.form_input.identities.find(i=>i.id===b.identity_id);
 requireValue(identity&&identity.app_roles.length===1&&identity.app_roles[0]===raw.role&&p.role===raw.role&&same(p.identity_selector,{role_sha256:digest(raw.role)}));
 requireValue(Array.isArray(raw.policy_cell_ids)&&raw.policy_cell_ids.length>0&&new Set(raw.policy_cell_ids).size===raw.policy_cell_ids.length&&same(raw.policy_cell_ids,p.policy_cell_ids)&&raw.policy_cell_ids.every(id=>policy.public_plan_part.cells.some(c=>c.id===id&&c.identity_id===b.identity_id&&c.status==='READY')));
 requireValue(Array.isArray(b.webauthn_integration_ids)&&same(b.webauthn_integration_ids,[...new Set(p.declarations.map(d=>d.integration_id))].sort())&&b.webauthn_integration_ids.every(id=>typeof id==='string'&&/^webauthn:[0-9a-f]{12}$/.test(id)));
 for(const phase of ['registration','logout','authentication']){
  const row=raw[phase],pub=p[phase],keys=phase==='logout'?['path','action','request']:['path','action','options','verify'];requireValue(fields(row,keys)&&fields(pub,keys)&&routePath(row.path)&&fields(row.action,['test_id'])&&typeof row.action.test_id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(row.action.test_id));
  requireValue(pub.path===row.path&&same(pub.action,row.action));
  for(const kind of phase==='logout'?['request']:['options','verify']){
   const request=row[kind];requireValue(fields(request,kind==='verify'?['method','path','http_status','json']:['method','path'])&&['GET','POST'].includes(request.method)&&routePath(request.path));
   if(kind!=='verify'){requireValue(same(pub[kind],request));continue;}
   requireValue(request.http_status===200&&Array.isArray(request.json)&&request.json.length>0);const seen=new Set();
   const assertions=request.json.map(a=>{requireValue(fields(a,['pointer','equals_literal'])&&pointer(a.pointer)&&!seen.has(a.pointer)&&(a.equals_literal===null||['string','boolean'].includes(typeof a.equals_literal)||Number.isSafeInteger(a.equals_literal)));seen.add(a.pointer);return {pointer:a.pointer,kind:'literal',value_hash:digest(a.equals_literal)};});
   requireValue(same(pub.verify,{method:request.method,path:request.path,http_status:200,json:assertions}));
  }
 }
 return clone(value);
}catch{fail('INPUT_INVALID');}}
function readPrivateWebAuthnInput(file,root){try{return validateWebAuthnInput(readPrivateJSON(file,root));}catch{fail('INPUT_INVALID');}}
const pending=()=>({status:'NOT_RUN',http_status:null,reason_code:'NOT_ATTEMPTED'});
const ceremony=()=>({status:'NOT_RUN',reason_code:'NOT_ATTEMPTED',options_http_status:null,http_status:null,options_observed:false,verify_observed:false,credential_observed:false,rp_matched:false,request_bound:false,assertions_matched:false,credential_alias:null});
function binary(value,max=4096){
 if(typeof value!=='string'||value.length>max*2||!value.length||!/[A-Za-z0-9]/.test(value)||!/^[A-Za-z0-9_+/-]+={0,2}$/.test(value))fail('REQUEST_NOT_BOUND');
 const norm=value.replace(/-/g,'+').replace(/_/g,'/').replace(/=+$/,'');const decoded=Buffer.from(norm,'base64');
 if(!decoded.length||decoded.length>max||decoded.toString('base64').replace(/=+$/,'')!==norm)fail('REQUEST_NOT_BOUND');return decoded;
}
function createWebAuthnHooks(options){
 const input=validateWebAuthnInput(options.input),b=input.binding,raw=input.webauthn,policyHooks=options.policyHooks;
 requireValue(policyHooks&&typeof policyHooks.snapshot==='function'&&typeof policyHooks.runAuthenticatedProbes==='function'&&typeof policyHooks.runAnonymousSessionProbe==='function');
 const suite={schema_version:1,type:'webauthn-suite',binding:clone(b),capability:{status:'NOT_RUN',reason_code:'NOT_ATTEMPTED',authenticator_created:false,browser_version:null},registration:ceremony(),logout:{status:'NOT_RUN',reason_code:'NOT_ATTEMPTED',request_observed:false,session_denial:pending()},authentication:ceremony(),session_after_authentication:{...pending(),identity_matched:null,roles_matched:null},cells:raw.policy_cell_ids.map(id=>({cell_id:id,identity_id:b.identity_id,access:{...pending(),assertions_matched:null}})),cleanup:{authenticator:'not_needed',cdp:'not_needed',page:'not_needed',context:'not_needed'}};
 let stopped=false,stopReason=null,attempted=false;
 const halt=reason=>{stopped=true;stopReason ||= reason;};
 const snapshot=()=>clone(suite);
 function emit(){try{if(options.emitSuite)options.emitSuite(snapshot());}catch{halt('PUBLIC_RECEIPT_WRITE_FAILED');fail('PUBLIC_RECEIPT_WRITE_FAILED');}}
 function errorCode(error){return error instanceof WebAuthnError?error.code:typeof error?.code==='string'&&FAIL.has(error.code)?error.code:'EXECUTOR_ERROR';}
 function failed(target,error){const code=errorCode(error);if(['PUBLIC_RECEIPT_WRITE_FAILED','DEADLINE_EXHAUSTED','RESOURCE_PAUSED','CLEANUP_FAILED'].includes(code))halt(code);if(target.status==='FAIL')return;Object.assign(target,{status:FAIL.has(code)?'FAIL':'BLOCKED',reason_code:code});if(code==='RP_MISMATCH'&&'rp_matched' in target)target.rp_matched=false;}
 function clock(args){
  const remaining=()=>{let value;try{value=args.remainingMs();}catch{fail('DEADLINE_EXHAUSTED');}if(!Number.isFinite(value)||value<1)fail('DEADLINE_EXHAUSTED');return Math.min(2147483647,Math.floor(value));};
  const timeout=()=>Math.min(remaining(),args.operationTimeoutMs);
  async function wait(work){const ms=timeout();let timer;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new WebAuthnError(ms<args.operationTimeoutMs?'DEADLINE_EXHAUSTED':'OPERATION_TIMEOUT')),ms);})]);}finally{clearTimeout(timer);}}
  return {remaining,timeout,wait};
 }
 async function cleanup(work){let timer;try{await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new WebAuthnError('CLEANUP_FAILED')),3000);})]);return true;}catch{return false;}finally{clearTimeout(timer);}}
 function jsonBuffer(buffer,headers){
  if(!/^application\/(?:[a-z0-9!#$&^_.+-]+\+)?json(?:\s*;|\s*$)/i.test(headers['content-type']||''))fail('CONTENT_TYPE_MISMATCH');
  if(headers['content-length']!==undefined&&/^\d+$/.test(headers['content-length'])&&Number(headers['content-length'])>input.limits.accepted_json_bytes)fail('BODY_TOO_LARGE');
  if(!Buffer.isBuffer(buffer)||buffer.length>input.limits.accepted_json_bytes)fail('BODY_TOO_LARGE');
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer));}catch{fail('JSON_INVALID');}
 }
 async function readResponse(response,c){const headers=await c.wait(()=>response.headers());if(headers['content-length']!==undefined&&/^\d+$/.test(headers['content-length'])&&Number(headers['content-length'])>input.limits.accepted_json_bytes)fail('BODY_TOO_LARGE');return jsonBuffer(await c.wait(()=>response.body()),headers);}
 function prerequisites(){const current=policyHooks.snapshot(),row=current.identities.find(r=>r.identity_id===b.identity_id);return same(current.binding,input.policy_input.binding)&&row?.session.status==='PASS'&&row.anonymous_session.status==='PASS'&&raw.policy_cell_ids.every(id=>{const cell=current.cells.find(c=>c.cell_id===id&&c.identity_id===b.identity_id);return cell?.anonymous.status==='PASS'&&cell.access.status==='PASS';});}
 async function afterPolicy(args){
  if(args.identityId!==b.identity_id||attempted)return;attempted=true;
  if(!prerequisites()){Object.assign(suite.capability,{status:'BLOCKED',reason_code:'PREREQUISITE_NOT_CONFIRMED'});emit();return;}
  const c=clock(args);let page,cdp,authenticatorId,closing=false,credential=null,alias=null,active=null;
  const creation=[];suite.cleanup.context='unknown';
  async function own(work,accept,dispose){const task=Promise.resolve().then(work).then(async value=>{accept(value);if(closing){await cleanup(()=>dispose(value));fail('DEADLINE_EXHAUSTED');}return value;});creation.push(task);task.catch(()=>{});return c.wait(()=>task);}
  async function stopPage(){if(page)await c.wait(()=>page.goto('about:blank',{waitUntil:'commit',timeout:c.timeout()}));}
  function event(kind,data){if(!active||data?.authenticatorId!==authenticatorId)return;try{
   if(kind!==active.kind||active.credential||!active.actionStarted||!active.optionsResponseSeen)fail('CREDENTIAL_MISMATCH');
   const value=data.credential;if(!object(value)||value.rpId!=='localhost')fail('RP_MISMATCH');
   const id=binary(value.credentialId);if(kind==='authentication'&&(!credential||!id.equals(credential)))fail('CREDENTIAL_MISMATCH');
   active.credential=id;active.target.credential_observed=true;
   if(kind==='registration')alias='credential-'+(options.randomBytes||crypto.randomBytes)(16).toString('hex');
   active.target.credential_alias=alias;active.eventDone.resolve();
  }catch(error){active.failure=error;active.eventDone.resolve();}}
  const added=data=>event('registration',data),asserted=data=>event('authentication',data);
  function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
  async function ui(phase){
   const flow=raw[phase],target=suite[phase],logout=phase==='logout';let handler,observe,failure=null;
   const optionsDone=deferred(),verifyDone=deferred(),eventDone=deferred(),logoutDone=deferred();
   const state={kind:phase,target,actionStarted:false,optionsResponseSeen:false,credential:null,failure:null,eventDone,optionsRequest:null,verifyRequest:null,logoutRequest:null,options:null,verify:null};active=logout?null:state;
   if(!logout&&flow.verify.method!=='POST')fail('UNSUPPORTED_REQUEST_FORMAT');
   async function guard(route){try{
    c.remaining();if(state.closed)fail('DEADLINE_EXHAUSTED');const request=route.request(),u=new URL(request.url()),main=request.frame()===page.mainFrame();
    if(u.origin!==new URL(b.app_origin).origin||u.username||u.password||u.hash)fail('ORIGIN_MISMATCH');
    if(request.redirectedFrom?.())fail('REDIRECT_NOT_SUPPORTED');
    const exact=(value)=>main&&u.href===new URL(b.app_origin+value.path).href&&request.method()===value.method;
    if(logout&&exact(flow.request)){if(state.logoutRequest)fail('DUPLICATE_CEREMONY_REQUEST');state.logoutRequest=request;target.request_observed=true;logoutDone.resolve();}
    else if(!logout&&exact(flow.options)){if(state.optionsRequest)fail('DUPLICATE_CEREMONY_REQUEST');state.optionsRequest=request;}
    else if(!logout&&exact(flow.verify)){
     if(state.verifyRequest)fail('DUPLICATE_CEREMONY_REQUEST');state.verifyRequest=request;
     await c.wait(()=>optionsDone.promise);await c.wait(()=>eventDone.promise);if(state.failure)throw state.failure;if(state.closed)fail('DEADLINE_EXHAUSTED');
     if(!state.options||!state.credential)fail('REQUEST_NOT_BOUND');
     const payload=jsonBuffer(await c.wait(()=>request.postDataBuffer()),await c.wait(()=>request.headers()));
     if(!object(payload)||payload.type!=='public-key'||!object(payload.response))fail('UNSUPPORTED_REQUEST_FORMAT');
     if(!binary(payload.id).equals(state.credential)||!binary(payload.rawId).equals(state.credential))fail('CREDENTIAL_MISMATCH');
     let client;try{client=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(binary(payload.response.clientDataJSON,16384)));}catch{fail('REQUEST_NOT_BOUND');}
     if(!object(client)||client.type!==(phase==='registration'?'webauthn.create':'webauthn.get')||client.origin!==new URL(b.app_origin).origin||client.crossOrigin===true||!binary(client.challenge).equals(state.options.challenge))fail('REQUEST_NOT_BOUND');
     target.request_bound=true;
    }else if(request.isNavigationRequest()){
     if(!main||request.method()!=='GET'||u.href!==new URL(b.app_origin+flow.path).href)fail('REQUEST_PATH_MISMATCH');
    }else if(!['GET','HEAD'].includes(request.method())||!['script','stylesheet','image','font','media'].includes(request.resourceType?.()))fail('REQUEST_PATH_MISMATCH');
    await route.continue();
   }catch(error){failure=error;state.failure=error;optionsDone.resolve();eventDone.resolve();verifyDone.resolve();logoutDone.resolve();try{await route.abort();}catch{}}}
   observe=response=>{const request=response.request();if(request!==state.optionsRequest&&request!==state.verifyRequest)return;
    const task=(async()=>{try{
     if(request.frame()!==page.mainFrame())fail('REQUEST_PATH_MISMATCH');const code=response.status();if(!Number.isInteger(code)||code<100||code>599)fail('TRANSPORT_ERROR');
     if(request===state.optionsRequest){state.optionsResponseSeen=true;target.options_observed=true;target.options_http_status=code;if(code!==200)fail('UNEXPECTED_STATUS');const data=await readResponse(response,c);
      if(state.closed)return;if(!object(data))fail('UNSUPPORTED_REQUEST_FORMAT');const rp=phase==='registration'?data.rp?.id:data.rpId;
      if(rp!=='localhost')fail('RP_MISMATCH');state.options={challenge:binary(data.challenge)};target.rp_matched=true;optionsDone.resolve();
     }else{target.verify_observed=true;target.http_status=code;if(code!==200)fail('UNEXPECTED_STATUS');const data=await readResponse(response,c);
      if(state.closed)return;for(const a of flow.verify.json)if(!same(atPointer(data,a.pointer),a.equals_literal))fail('ASSERTION_MISMATCH');target.assertions_matched=true;state.verify=true;verifyDone.resolve();}
    }catch(error){failure=error;state.failure=error;optionsDone.resolve();verifyDone.resolve();eventDone.resolve();}})();task.catch(()=>{});
   };
   try{
    handler=guard;await c.wait(()=>args.context.route('**/*',handler));page.on('response',observe);
    const response=await c.wait(()=>page.goto(b.app_origin+flow.path,{waitUntil:'domcontentloaded',timeout:c.timeout()}));
    if(failure)throw failure;if(!response||response.status()<200||response.status()>=300||new URL(page.url()).href!==new URL(b.app_origin+flow.path).href)fail('UNEXPECTED_STATUS');
    const locator=page.getByTestId(flow.action.test_id);if(await c.wait(()=>locator.count())!==1)fail('UI_ACTION_AMBIGUOUS');if(!await c.wait(()=>locator.isVisible()))fail('UI_ACTION_UNAVAILABLE');
    state.actionStarted=true;await c.wait(()=>locator.click({timeout:c.timeout()}));
    if(logout){await c.wait(()=>logoutDone.promise);if(!state.logoutRequest)fail('LOGOUT_REQUEST_NOT_OBSERVED');Object.assign(target,{status:'BLOCKED',reason_code:'PREREQUISITE_NOT_CONFIRMED'});}
    else{await c.wait(()=>verifyDone.promise);if(state.failure)throw state.failure;if(!state.optionsRequest)fail('OPTIONS_NOT_OBSERVED');if(!state.credential)fail('CREDENTIAL_NOT_OBSERVED');if(!state.verify)fail('VERIFY_NOT_OBSERVED');
     target.credential_observed=true;
     if(phase==='registration'){credential=state.credential;alias=target.credential_alias;}
     Object.assign(target,{status:'PASS',reason_code:phase==='registration'?'REGISTRATION_VERIFIED':'AUTHENTICATION_VERIFIED'});
    }
    if(failure)throw failure;
   }catch(error){failed(target,failure||state.failure||error);}
   finally{state.closed=true;active=null;if(observe)page.off('response',observe);if(handler&&!await cleanup(()=>args.context.unroute('**/*',handler))){halt('CLEANUP_FAILED');if(target.status!=='FAIL')failed(target,new WebAuthnError('CLEANUP_FAILED'));}emit();}
  }
  try{
   c.remaining();if(typeof args.context.newCDPSession!=='function')fail('UNSUPPORTED_BROWSER');
   const version=await c.wait(()=>args.browser.version());if(typeof version==='string'&&/^\d+(?:\.\d+){1,3}$/.test(version))suite.capability.browser_version=version;
   suite.cleanup.page='unknown';await own(()=>args.context.newPage(),value=>{page=value;},value=>value.close());
   suite.cleanup.cdp='unknown';await own(()=>args.context.newCDPSession(page),value=>{cdp=value;},value=>value.detach());
   cdp.on('WebAuthn.credentialAdded',added);cdp.on('WebAuthn.credentialAsserted',asserted);
   await c.wait(()=>cdp.send('WebAuthn.enable'));
   const {basis,capabilities,...profile}=PROFILE;suite.cleanup.authenticator='unknown';
   await own(()=>cdp.send('WebAuthn.addVirtualAuthenticator',{options:profile}),value=>{if(typeof value?.authenticatorId!=='string'||!value.authenticatorId)fail('VIRTUAL_AUTHENTICATOR_UNAVAILABLE');authenticatorId=value.authenticatorId;},value=>cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:value.authenticatorId}));
   Object.assign(suite.capability,{status:'PASS',reason_code:'VIRTUAL_AUTHENTICATOR_CREATED',authenticator_created:true});emit();
   await ui('registration');if(suite.registration.status!=='PASS'||stopped)return;await stopPage();
   await ui('logout');if(!suite.logout.request_observed||suite.logout.status==='FAIL'||suite.logout.status==='BLOCKED'&&suite.logout.reason_code!=='PREREQUISITE_NOT_CONFIRMED'||stopped)return;await stopPage();
   suite.logout.session_denial=await policyHooks.runAnonymousSessionProbe({...args,onCheckpoint:value=>{suite.logout.session_denial=value;}});
   Object.assign(suite.logout,{status:suite.logout.session_denial.status,reason_code:suite.logout.session_denial.status==='PASS'?'LOGOUT_SESSION_DENIED':suite.logout.session_denial.reason_code});emit();
   if(suite.logout.status!=='PASS'||stopped)return;
   await ui('authentication');if(suite.authentication.status!=='PASS'||stopped)return;await stopPage();
   const result=await policyHooks.runAuthenticatedProbes({...args,cellIds:raw.policy_cell_ids,onCheckpoint:value=>{suite.session_after_authentication=value.session;suite.cells=value.cells;emit();}});
   suite.session_after_authentication=result.session;suite.cells=result.cells;emit();
  }catch(error){const target=suite.capability.status==='NOT_RUN'?suite.capability:suite.registration.status==='NOT_RUN'?suite.registration:suite.logout.status==='NOT_RUN'?suite.logout:suite.authentication.status==='NOT_RUN'?suite.authentication:suite.session_after_authentication;failed(target,error);emit();}
  finally{
   closing=true;active=null;
   await cleanup(()=>Promise.allSettled(creation));
   if(authenticatorId){suite.cleanup.authenticator=await cleanup(()=>cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId}))?'removed':'unknown';}
   if(cdp){cdp.off('WebAuthn.credentialAdded',added);cdp.off('WebAuthn.credentialAsserted',asserted);const disabled=await cleanup(()=>cdp.send('WebAuthn.disable'));const detached=await cleanup(()=>cdp.detach());suite.cleanup.cdp=disabled&&detached?'detached':'unknown';}
   if(page)suite.cleanup.page=await cleanup(()=>page.close())?'closed':'unknown';
   credential=null;alias=null;
   if(['authenticator','cdp','page'].some(k=>suite.cleanup[k]==='unknown'))halt('CLEANUP_FAILED');emit();
  }
 }
 function finishIdentity(args){if(args.identityId!==b.identity_id||!attempted)return;
  if(suite.cleanup.context==='unknown'&&args.formResult.cleanup==='closed'&&args.formResult.form_status==='PASS'&&same(args.policySuite.binding,input.policy_input.binding))suite.cleanup.context='closed';
  if(suite.cleanup.context==='unknown')halt('CLEANUP_FAILED');emit();
 }
 emit();return {afterPolicy,finishIdentity,snapshot,shouldStop:()=>stopped,stopReason:()=>stopReason};
}
module.exports={WebAuthnError,validateWebAuthnInput,readPrivateWebAuthnInput,createWebAuthnHooks};
