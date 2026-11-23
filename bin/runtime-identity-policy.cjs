'use strict';
/* Explicit positive identity policy. Importing performs no I/O. */
const crypto=require('node:crypto');
const {validateLoginInput,readPrivateJSON}=require('./runtime-keycloak-login.cjs');
const clone=value=>JSON.parse(JSON.stringify(value));
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const fields=(value,keys)=>object(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
class PolicyError extends Error { constructor(code){super(code);this.code=code;} }
const fail=code=>{throw new PolicyError(code);};
function canonical(value){
 if(value===null||typeof value==='boolean'||typeof value==='string'||Number.isSafeInteger(value))return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(object(value))return '{'+Object.keys(value).sort((a,b)=>{const x=Array.from(a),y=Array.from(b);for(let i=0;i<Math.min(x.length,y.length);i++){const d=x[i].codePointAt(0)-y[i].codePointAt(0);if(d)return d;}return x.length-y.length;}).map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 fail('INPUT_INVALID');
}
const digest=value=>crypto.createHash('sha256').update(canonical(value)).digest('hex');
const same=(a,b)=>canonical(a)===canonical(b);
function routePath(value){return typeof value==='string'&&value.length>0&&value.length<=500&&value.startsWith('/')&&!value.includes('//')&&!/[\\?#%*${}\s]/.test(value)&&new URL(value,'https://localhost:44100').pathname===value;}
function pointer(value){return typeof value==='string'&&value.startsWith('/')&&value.length<=1000&&value.slice(1).split('/').every(p=>p&&!/~(?![01])/.test(p)&&!['__proto__','prototype','constructor'].includes(p.replace(/~1/g,'/').replace(/~0/g,'~'))&&!p.includes('*'));}
function denial(value){return fields(value,['kind','codes'])&&value.kind==='status'&&Array.isArray(value.codes)&&value.codes.length>0&&new Set(value.codes).size===value.codes.length&&value.codes.every(n=>[401,403].includes(n));}
function validatePolicyInput(value){
 try{
  if(!fields(value,['schema_version','kind','binding','form_input','public_plan_part','policy','limits'])||value.schema_version!==1||value.kind!=='identity-policy-input'||!fields(value.limits,['accepted_json_bytes'])||value.limits.accepted_json_bytes!==1048576)fail('INPUT_INVALID');
  const form=validateLoginInput(value.form_input),b=value.binding,p=value.public_plan_part,raw=value.policy;
  if(!fields(b,['run_id','integration_id','integration_plan_id','identity_plan_id','policy_plan_id','policy_hash','form_attempt_id','policy_attempt_id','part'])||Object.values(b).some(value=>typeof value!=='string')||!/^policy-[0-9a-f]{32}$/.test(b.policy_attempt_id)||!/^([0-9a-f]{64})$/.test(b.policy_plan_id)||b.form_attempt_id!==form.binding.attempt_id)fail('INPUT_INVALID');
  for(const k of ['run_id','integration_id','integration_plan_id','identity_plan_id','part'])if(b[k]!==form.binding[k])fail('INPUT_INVALID');
  if(!fields(raw,['basis','session','cells'])||raw.basis!=='explicit_config'||!fields(p,['part','identity_plan_id','policy_hash','status','config_pointer','session','cells','gaps','unconfigured_identities'])||p.status!=='PLANNED'||p.part!==b.part||p.identity_plan_id!==b.identity_plan_id||p.policy_hash!==b.policy_hash||digest(raw)!==b.policy_hash||!Array.isArray(p.gaps)||p.gaps.length||!same({...raw.session,anonymous:{...raw.session.anonymous,codes:[...(raw.session.anonymous?.codes||[])].sort()}},p.session))fail('INPUT_INVALID');
  const s=raw.session;
  if(!fields(s,['path','method','http_status','anonymous','assertions'])||!routePath(s.path)||s.method!=='GET'||s.http_status!==200||!denial(s.anonymous)||!Array.isArray(s.assertions)||!s.assertions.length)fail('INPUT_INVALID');
  const assertionPointers=new Set();
  for(const a of s.assertions){
   const role=a.equals_identity==='app_roles';
   if(!fields(a,role?['pointer','equals_identity','comparison']:['pointer','equals_identity'])||!pointer(a.pointer)||assertionPointers.has(a.pointer)||!['username','email','email_verified','app_roles'].includes(a.equals_identity)||role&&a.comparison!=='set_exact')fail('INPUT_INVALID');
   assertionPointers.add(a.pointer);
  }
  if(!s.assertions.some(a=>['username','email'].includes(a.equals_identity))||!s.assertions.some(a=>a.equals_identity==='app_roles'))fail('INPUT_INVALID');
  if(!Array.isArray(raw.cells)||!raw.cells.length||!Array.isArray(p.cells)||raw.cells.length!==p.cells.length)fail('INPUT_INVALID');
  const seen=new Set(),names=new Set(),ids=new Set();
  for(let i=0;i<raw.cells.length;i++){
   const r=raw.cells[i],c=p.cells[i];
   if(!fields(r,['id','identity','request','anonymous','expected'])||!fields(r.identity,['role'])||!fields(r.request,['method','path'])||r.request.method!=='GET'||!routePath(r.request.path)||!denial(r.anonymous)||!object(c)||c.status!=='READY'||!Array.isArray(c.gaps)||c.gaps.length)fail('INPUT_INVALID');
   const identity=form.identities.find(v=>v.id===c.identity_id);
   if(!identity||c.role!==r.identity.role||identity.app_roles[0]!==c.role||identity.id!=='role-'+digest(c.role).slice(0,12)||!same(c.identity_selector,{role_sha256:digest(c.role)})||c.config_id!==r.id||!same(c.request,r.request)||!same(c.anonymous,{...r.anonymous,codes:[...r.anonymous.codes].sort()}))fail('INPUT_INVALID');
   let expected;
   if(r.expected.access==='allow'){
    if(!fields(r.expected,['access','http_status','json'])||r.expected.http_status!==200||!Array.isArray(r.expected.json)||!r.expected.json.length)fail('INPUT_INVALID');
    const paths=new Set();expected={access:'allow',http_status:200,json:r.expected.json.map(a=>{
     if(!fields(a,['pointer','equals_literal'])||!pointer(a.pointer)||paths.has(a.pointer)||!(a.equals_literal===null||['string','boolean'].includes(typeof a.equals_literal)||Number.isSafeInteger(a.equals_literal)))fail('INPUT_INVALID');
     paths.add(a.pointer);return {pointer:a.pointer,kind:'literal',value_hash:digest(a.equals_literal)};
    })};
   }else{if(!fields(r.expected,['access','denial'])||r.expected.access!=='deny'||!denial(r.expected.denial))fail('INPUT_INVALID');expected={access:'deny',denial:{...r.expected.denial,codes:[...r.expected.denial.codes].sort()}};}
   if(!same(c.expected,expected))fail('INPUT_INVALID');
   const payload={part:b.part};for(const k of ['identity_selector','identity_id','role','request','anonymous','expected'])payload[k]=c[k];
   const requestKey=c.identity_id+' '+r.request.path;
   if(c.id!=='cell-'+digest(payload).slice(0,16)||seen.has(requestKey)||names.has(r.id)||ids.has(c.id))fail('INPUT_INVALID');
   seen.add(requestKey);names.add(r.id);ids.add(c.id);
  }
  return clone(value);
 }catch(error){if(error instanceof PolicyError)throw error;fail('INPUT_INVALID');}
}
function readPrivatePolicyInput(file,root){try{return validatePolicyInput(readPrivateJSON(file,root));}catch{fail('INPUT_INVALID');}}
const pending=()=>({status:'NOT_RUN',http_status:null,reason_code:'NOT_ATTEMPTED'});
function atPointer(value,p){for(const token of p.slice(1).split('/').map(t=>t.replace(/~1/g,'/').replace(/~0/g,'~'))){if(!object(value)&&!Array.isArray(value)||!Object.hasOwn(value,token))fail('JSON_POINTER_MISSING');value=value[token];}return value;}
function createPolicyHooks(options){
 const input=validatePolicyInput(options.input),plan=input.public_plan_part,raw=input.policy;
 const selected=input.form_input.identities.filter(i=>plan.cells.some(c=>c.identity_id===i.id));
 const suite={schema_version:1,type:'identity-policy-suite',binding:clone(input.binding),identities:selected.map(i=>({identity_id:i.id,anonymous_session:pending(),session:{...pending(),identity_matched:null,roles_matched:null},cleanup:'not_needed'})),cells:plan.cells.map(c=>({cell_id:c.id,identity_id:c.identity_id,anonymous:pending(),access:{...pending(),assertions_matched:null},result:'NOT_RUN'}))};
 let stopped=false,stopReason=null;
 const halt=reason=>{stopped=true;stopReason ||= reason;};
 const snapshot=()=>clone(suite);
 const emit=()=>{for(const row of suite.identities)recalculate(row.identity_id);try{if(options.emitSuite)options.emitSuite(snapshot());}catch{halt('PUBLIC_RECEIPT_WRITE_FAILED');fail('PUBLIC_RECEIPT_WRITE_FAILED');}};
 const active=new Map();
 function failPending(identityId,reason){const row=suite.identities.find(r=>r.identity_id===identityId);if(!row)return;for(const p of [row.anonymous_session,row.session,...suite.cells.filter(c=>c.identity_id===identityId).flatMap(c=>[c.anonymous,c.access])])if(p.status==='NOT_RUN')Object.assign(p,{status:'BLOCKED',reason_code:reason});}
 function recalculate(identityId){const row=suite.identities.find(r=>r.identity_id===identityId);if(!row)return;for(const c of suite.cells.filter(c=>c.identity_id===identityId)){
  const probes=[row.anonymous_session,row.session,c.anonymous,c.access];
  c.result=probes.some(p=>p.status==='FAIL')?'FAIL':probes.every(p=>p.status==='PASS')&&row.cleanup==='closed'?'PASS':probes.every(p=>p.status==='NOT_RUN')?'NOT_RUN':'BLOCKED';
 }}
 function timing(args){
  const remain=()=>{let n;try{n=args.remainingMs();}catch{fail('DEADLINE_EXHAUSTED');}if(!Number.isFinite(n)||n<1)fail('DEADLINE_EXHAUSTED');return Math.min(2147483647,Math.floor(n));};
  const timeout=()=>Math.min(remain(),args.operationTimeoutMs);
  const wait=async work=>{let timer;try{return await Promise.race([work,new Promise((_,reject)=>{const n=timeout();timer=setTimeout(()=>reject(new PolicyError(n<args.operationTimeoutMs?'DEADLINE_EXHAUSTED':'OPERATION_TIMEOUT')),n);})]);}finally{clearTimeout(timer);}};
  return {remain,timeout,wait};
 }
 async function cleanWait(work){let timer;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new PolicyError('CLEANUP_FAILED')),3000);})]);}finally{clearTimeout(timer);}}
 async function closeOwned(context,clock){let timer;try{await Promise.race([Promise.resolve().then(()=>context.close()),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new PolicyError('CLEANUP_FAILED')),3000);})]);return true;}catch{return false;}finally{clearTimeout(timer);}}
 async function probe(context,location,expected,target,args,evaluate,observeCheckpoint=emit){
  const clock=timing(args);let page,first,guardFailure,handler;let status=null;
  const targetURL=new URL(input.form_input.app_origin+location).href;
  try{
   clock.remain();page=await clock.wait(context.newPage());
   handler=async route=>{try{
    clock.remain();const r=route.request(),u=new URL(r.url());
    if(u.origin!==new URL(input.form_input.app_origin).origin)fail('ORIGIN_MISMATCH');
    if(typeof r.redirectedFrom==='function'&&r.redirectedFrom())fail('REDIRECT_NOT_SUPPORTED');
    if(!r.isNavigationRequest()||r.frame()!==page.mainFrame()||r.method()!=='GET'||u.href!==targetURL)fail('REQUEST_PATH_MISMATCH');
    await route.continue();
   }catch(error){guardFailure=error instanceof PolicyError?error.code:'EXECUTOR_ERROR';try{await route.abort();}catch{}}};
   await clock.wait(context.route('**/*',handler));
   const observe=response=>{try{const r=response.request();if(!first&&r.isNavigationRequest()&&r.frame()===page.mainFrame()&&r.url()===targetURL)first=response;}catch{guardFailure='EXECUTOR_ERROR';}};
   page.on('response',observe);
   let navigationError;
   try{const returned=await clock.wait(page.goto(targetURL,{waitUntil:'commit',timeout:clock.timeout()}));if(!first)first=returned;}catch(error){navigationError=error;}
   if(first){status=first.status();if(!Number.isInteger(status)||status<100||status>599)fail('TRANSPORT_ERROR');target.http_status=status;}
   if(status>=300&&status<400)fail('REDIRECT_NOT_SUPPORTED');
   if(guardFailure)fail(guardFailure);
   if(navigationError)throw navigationError;
   if(!first||new URL(first.url()).href!==targetURL||new URL(page.url()).href!==targetURL)fail('REQUEST_PATH_MISMATCH');
   if(!expected.includes(status)){Object.assign(target,{status:'FAIL',reason_code:'UNEXPECTED_STATUS'});return;}
   if(!evaluate){Object.assign(target,{status:'PASS',reason_code:'EXPECTED_DENIAL'});return;}
   const headers=await clock.wait(Promise.resolve(first.headers()));
   if(!/^application\/(?:[a-z0-9!#$&^_.+-]+\+)?json(?:\s*;|\s*$)/i.test(headers['content-type']||''))fail('CONTENT_TYPE_MISMATCH');
   const declared=headers['content-length'];if(declared!==undefined&&/^\d+$/.test(declared)&&Number(declared)>input.limits.accepted_json_bytes)fail('BODY_TOO_LARGE');
   clock.remain();const body=await clock.wait(first.body());
   if(!Buffer.isBuffer(body)||body.length>input.limits.accepted_json_bytes)fail('BODY_TOO_LARGE');
   let data;try{data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));}catch{fail('JSON_INVALID');}
   evaluate(data);clock.remain();
  }catch(error){const code=error instanceof PolicyError?error.code:'TRANSPORT_ERROR';Object.assign(target,{status:['UNEXPECTED_STATUS','REDIRECT_NOT_SUPPORTED','JSON_POINTER_MISSING','ASSERTION_MISMATCH','SESSION_IDENTITY_MISMATCH','SESSION_ROLES_MISMATCH'].includes(code)?'FAIL':'BLOCKED',reason_code:code});}
  finally{
   try{if(handler)await cleanWait(()=>context.unroute('**/*',handler));}catch{halt('CLEANUP_FAILED');if(target.status!=='FAIL')Object.assign(target,{status:'BLOCKED',reason_code:'CLEANUP_FAILED'});}
   try{if(page)await cleanWait(()=>page.close());}catch{halt('CLEANUP_FAILED');if(target.status!=='FAIL')Object.assign(target,{status:'BLOCKED',reason_code:'CLEANUP_FAILED'});}
   observeCheckpoint();
  }
 }
 async function beforeForm(args){
  const row=suite.identities.find(r=>r.identity_id===args.identityId);if(!row)return;
  const clock=timing(args);active.set(args.identityId,{anonymousClean:true});
  const tasks=[{path:raw.session.path,codes:raw.session.anonymous.codes,target:row.anonymous_session},...plan.cells.map((cell,i)=>({cell,i})).filter(v=>v.cell.identity_id===args.identityId).map(({cell,i})=>({path:cell.request.path,codes:cell.anonymous.codes,target:suite.cells[i].anonymous}))];
  for(const task of tasks){if(stopped)break;let context,creation,closing=false;row.cleanup='unknown';
   try{clock.remain();creation=Promise.resolve(args.browser.newContext({serviceWorkers:'block',acceptDownloads:false})).then(async value=>{context=value;if(closing){await closeOwned(value,clock);fail('DEADLINE_EXHAUSTED');}return value;});context=await clock.wait(creation);await probe(context,task.path,task.codes,task.target,args);}
   catch(error){Object.assign(task.target,{status:'BLOCKED',reason_code:error instanceof PolicyError?error.code:'EXECUTOR_ERROR'});}
   finally{closing=true;let clean=true;if(context)clean=await closeOwned(context,clock);else if(creation){clean=false;creation.catch(()=>{});}active.get(args.identityId).anonymousClean&&=clean;row.cleanup=clean?'closed':'unknown';if(!clean)halt('CLEANUP_FAILED');emit();}
   if(task.target.reason_code==='DEADLINE_EXHAUSTED')break;
  }
  // The upcoming authenticated context has not yet been closed. Baseline
  // cleanup must never credit an in-flight authenticated policy checkpoint.
  row.cleanup='unknown';emit();
 }
 async function sessionProbe(context,identityId,target,args,observer){
  const identity=selected.find(r=>r.id===identityId);if(!identity)fail('UNSUPPORTED_IDENTITY');
  await probe(context,raw.session.path,[200],target,args,data=>{
   let identityMatch=true,rolesMatch=true;
   for(const a of raw.session.assertions){const actual=atPointer(data,a.pointer),expected=a.equals_identity==='email'?identity.username+'@example.invalid':identity[a.equals_identity];
    if(a.equals_identity==='app_roles')rolesMatch&&=Array.isArray(actual)&&actual.every(v=>typeof v==='string')&&new Set(actual).size===actual.length&&same([...actual].sort(),[...expected].sort());
    else identityMatch&&=same(actual,expected);
   }
   target.identity_matched=identityMatch;target.roles_matched=rolesMatch;
   if(!identityMatch)fail('SESSION_IDENTITY_MISMATCH');if(!rolesMatch)fail('SESSION_ROLES_MISMATCH');Object.assign(target,{status:'PASS',reason_code:'SESSION_MATCHED'});
  },observer);
 }
 async function accessProbe(context,cellId,target,args,observer){
  const index=plan.cells.findIndex(c=>c.id===cellId);if(index<0)fail('INPUT_INVALID');
  const cell=plan.cells[index],expected=raw.cells[index].expected;
  await probe(context,cell.request.path,expected.access==='deny'?expected.denial.codes:[200],target,args,expected.access==='deny'?null:data=>{
   let matched=true;for(const a of expected.json)matched&&=same(atPointer(data,a.pointer),a.equals_literal);
   target.assertions_matched=matched;if(!matched)fail('ASSERTION_MISMATCH');Object.assign(target,{status:'PASS',reason_code:'ACCESS_MATCHED'});
  },observer);
 }
 async function runAuthenticatedProbes(args){
  if(!Array.isArray(args.cellIds)||new Set(args.cellIds).size!==args.cellIds.length||args.cellIds.some(id=>!plan.cells.some(c=>c.id===id&&c.identity_id===args.identityId)))fail('INPUT_INVALID');
  const result={session:{...pending(),identity_matched:null,roles_matched:null},cells:args.cellIds.map(id=>({cell_id:id,identity_id:args.identityId,access:{...pending(),assertions_matched:null}}))};
  const observe=()=>{if(args.onCheckpoint)args.onCheckpoint(clone(result));};
  await sessionProbe(args.context,args.identityId,result.session,args,observe);
  for(const cell of result.cells){if(stopped||result.session.status!=='PASS')break;await accessProbe(args.context,cell.cell_id,cell.access,args,observe);}
  return clone(result);
 }
 async function runAnonymousSessionProbe(args){
  const result=pending();await probe(args.context,raw.session.path,raw.session.anonymous.codes,result,args,null,()=>{if(args.onCheckpoint)args.onCheckpoint(clone(result));});return clone(result);
 }
 async function afterForm(args){
  const row=suite.identities.find(r=>r.identity_id===args.identityId);if(!row)return;
  const identity=selected.find(r=>r.id===args.identityId),clock=timing(args);
  try{
   await clock.wait(args.page.close()); // Keep the session in its context, stop callback-page scripts.
   if(row.anonymous_session.status!=='PASS'){Object.assign(row.session,{status:'BLOCKED',reason_code:'BASELINE_NOT_CONFIRMED'});return;}
   await sessionProbe(args.context,args.identityId,row.session,args);
   for(let i=0;i<plan.cells.length;i++){if(stopped)break;const cell=plan.cells[i],result=suite.cells[i];if(cell.identity_id!==args.identityId)continue;
    if(row.session.status!=='PASS'){Object.assign(result.access,{status:'BLOCKED',reason_code:'SESSION_NOT_CONFIRMED'});continue;}
    if(result.anonymous.status!=='PASS'){Object.assign(result.access,{status:'BLOCKED',reason_code:'BASELINE_NOT_CONFIRMED'});continue;}
    await accessProbe(args.context,cell.id,result.access,args);
   }
  }catch(error){failPending(args.identityId,error instanceof PolicyError?error.code:'EXECUTOR_ERROR');}
  finally{recalculate(args.identityId);emit();}
 }
 function finishIdentity(args){const row=suite.identities.find(r=>r.identity_id===args.identityId);if(!row)return;
  const clean=active.get(args.identityId)?.anonymousClean!==false&&args.formResult.cleanup==='closed';row.cleanup=clean?'closed':args.formResult.cleanup==='not_needed'&&row.cleanup==='not_needed'?'not_needed':'unknown';
  if(row.cleanup==='unknown')halt('CLEANUP_FAILED');
  failPending(args.identityId,args.error|| (args.formResult.form_status==='PASS'?'SESSION_NOT_CONFIRMED':'FORM_NOT_CONFIRMED'));
  recalculate(args.identityId);emit();
 }
 emit();return {beforeForm,afterForm,finishIdentity,runAuthenticatedProbes,runAnonymousSessionProbe,snapshot,shouldStop:()=>stopped,stopReason:()=>stopReason};
}
module.exports={PolicyError,validatePolicyInput,readPrivatePolicyInput,createPolicyHooks,canonical,digest,routePath,pointer,atPointer};
