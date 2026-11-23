'use strict';
// Owned local capture only. This module never follows media URLs or contacts a provider.
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const VERSION=1;
function fail(code='SINK_INPUT_INVALID'){const e=new Error(code);e.code=code;return e;}
function clone(value){return JSON.parse(JSON.stringify(value));}
function validateSinkInput(input){
  if(!input||input.schema_version!==1||input.kind!=='runtime-sinks-input'||!input.binding||!/^sink-[a-f0-9]{32}$/.test(input.binding.attempt_id)||! /^[a-f0-9]{64}$/.test(input.bearer_token||''))throw fail();
  const origin=new URL(input.origin);if(origin.protocol!=='http:'||origin.hostname!=='127.0.0.1'||!origin.port||origin.origin!==input.origin)throw fail();
  if(!Number.isSafeInteger(input.deadline_unix_ms)||!input.limits||input.limits.max_body_bytes!==1048576||input.limits.max_requests!==1000)throw fail();
  if(!Array.isArray(input.operations)||!input.operations.length||!Array.isArray(input.own_origins)||!Array.isArray(input.synthetic_domains))throw fail();
  for(const value of input.own_origins){const u=new URL(value);if(!['http:','https:'].includes(u.protocol)||!['127.0.0.1','localhost','[::1]'].includes(u.hostname)||!u.port||u.origin!==value)throw fail();}
  if(input.synthetic_domains.some(x=>!['helix-mail.invalid','example.invalid'].includes(x)))throw fail();
  if(input.browser_control_origins!==undefined&&(!Array.isArray(input.browser_control_origins)||input.browser_control_origins.length>1||input.browser_control_origins.some(x=>{if(typeof x!=='string')return true;const m=/^http:\/\/127\.0\.0\.1:([1-9]\d{3,4})$/.exec(x);return !m||+m[1]<1024||+m[1]>65535;})))throw fail();
  const seen=new Set();for(const op of input.operations){if(!op||typeof op.id!=='string'||! /^[a-z]+\.[a-z]+$/.test(op.id)||seen.has(op.id)||!Array.isArray(op.hosts)||op.hosts.some(x=>typeof x!=='string'||! /^[a-z0-9.-]+$/.test(x))||op.method!=='POST'||!['json','form','empty','binary'].includes(op.encoding)||!['capture','control'].includes(op.effect)||typeof op.path_pattern!=='string'||op.path_pattern.length>200||!op.path_pattern.startsWith('^/')||!op.path_pattern.endsWith('$')||!Number.isInteger(op.response_status))throw fail();new RegExp(op.path_pattern);seen.add(op.id);}
  for(const name of ['mailbox_path','public_path'])if(typeof input[name]!=='string'||!path.isAbsolute(input[name])||input[name].includes('\0')||path.normalize(input[name])!==input[name])throw fail();
  return input;
}
function classifyRequest(input,request){
  let u;try{u=new URL(request.url);}catch{return {kind:'unsupported'};}
  const method=String(request.method||'GET').toUpperCase();
  if(u.username||u.password||u.hash||/%(?:2f|5c|00)/i.test(u.pathname)||u.pathname.includes('//'))return {kind:'unsupported'};
  for(const op of input.operations){
    const external=u.protocol==='https:'&&(!u.port||u.port==='443')&&op.hosts.includes(u.hostname);
    const local=(u.origin===input.origin&&(op.provider==='play-sms'||op.provider==='web-push'));
    if((external||local)&&op.method===method&&new RegExp(op.path_pattern).test(u.pathname)&&[...u.searchParams.keys()].every(k=>op.query_keys.includes(k)))return {kind:'capture',operation:op};
  }
  if(input.own_origins.includes(u.origin)&&u.origin!==input.origin)return {kind:'own'};
  return {kind:'unsupported'};
}
function headersObject(headers){if(!headers)return {};if(typeof headers.entries==='function')return Object.fromEntries(headers.entries());return Object.fromEntries(Object.entries(headers).map(([k,v])=>[k.toLowerCase(),String(v)]));}
function sanitize(value){
  if(Array.isArray(value))return value.map(sanitize);
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,/(?:token|secret|password|authorization|cookie|api.?key)/i.test(k)?'[REDACTED]':sanitize(v)]));
  return value;
}
function response(status,body){return {status,headers:{'content-type':'application/json','x-helix-simulation':'local-capture'},body:body===null?'':JSON.stringify(body)};}
function createHandler(input,{writeMailbox=()=>{},writePublic=()=>{},now=Date.now}={}){
  validateSinkInput(input);
  const state={schema_version:1,binding:clone(input.binding),status:'not_run',cleanup:'not_needed',observations:[],gaps:[]};
  let stopped=false;
  function publish(){try{writePublic(clone(state));}catch{stopped=true;state.status='partial';if(!state.gaps.includes('SINK_WRITE_FAILED'))state.gaps.push('SINK_WRITE_FAILED');throw fail('SINK_WRITE_FAILED');}}
  function gap(code){if(!state.gaps.includes(code))state.gaps.push(code);}
  async function handle(request){
    if(stopped)return response(503,{error:'SINK_UNAVAILABLE'});
    if(now()>=input.deadline_unix_ms){gap('DEADLINE_EXCEEDED');state.status='partial';publish();return response(503,{error:'DEADLINE_EXCEEDED'});}
    const headers=headersObject(request.headers);
    if(headers.authorization!=='Bearer '+input.bearer_token)return response(403,{error:'REQUEST_REJECTED'});
    let u;try{u=new URL(request.url,input.origin);}catch{return response(400,{error:'REQUEST_REJECTED'});}
    if(u.origin!==input.origin||u.search||u.hash||String(request.method).toUpperCase()!=='POST')return response(400,{error:'REQUEST_REJECTED'});
    const op=input.operations.find(x=>u.pathname==='/__helix_sink/'+x.id);
    if(!op)return response(501,{error:'UNSUPPORTED_TRANSPORT'});
    if(state.observations.length>=input.limits.max_requests){gap('LIMIT_EXCEEDED');state.status='partial';publish();return response(429,{error:'LIMIT_EXCEEDED'});}
    const body=Buffer.isBuffer(request.body)?request.body:Buffer.from(request.body||'');
    let code=op.response_status,parsed=null,rejected=false;
    if(body.length>input.limits.max_body_bytes){code=413;rejected=true;gap('LIMIT_EXCEEDED');}
    else try{
      const content=(headers['content-type']||'').split(';')[0].trim().toLowerCase();
      if(op.encoding==='json'){if(content!=='application/json')throw fail();parsed=JSON.parse(body.toString('utf8'));if(!parsed||typeof parsed!=='object')throw fail();}
      else if(op.encoding==='form'){if(content!=='application/x-www-form-urlencoded')throw fail();parsed=Object.fromEntries(new URLSearchParams(body.toString('utf8')));}
      else if(op.encoding==='binary')parsed={bytes:body.length,base64:body.toString('base64')};
      else parsed={bytes:body.length};
    }catch{code=400;rejected=true;gap('REQUEST_REJECTED');}
    const sequence=state.observations.length+1;
    try{if(!rejected)writeMailbox({sequence,operation_id:op.id,provider:op.provider,body:sanitize(parsed),simulation:true});}
    catch{gap('SINK_WRITE_FAILED');state.status='partial';stopped=true;publish();return response(503,{error:'SINK_WRITE_FAILED'});}
    state.observations.push({sequence,operation_id:op.id,provider:op.provider,http_status:code,outcome:rejected?'rejected_local':'captured_local'});
    state.status=state.gaps.length?'partial':'ready';state.cleanup='unknown';publish();
    if(rejected)return response(code,{error:'REQUEST_REJECTED'});
    const ident='helix-sim-'+crypto.createHash('sha256').update(input.binding.attempt_id+':'+sequence).digest('hex').slice(0,24);
    const substitute=value=>typeof value==='string'?(value==='$id'?ident:value==='$token'?'helix-synthetic-token':value):Array.isArray(value)?value.map(substitute):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,substitute(v)])):value;
    return response(code,op.response_body===undefined?null:substitute(op.response_body));
  }
  return {handle,snapshot:()=>clone(state),ready(){state.status='ready';state.cleanup='unknown';publish();},close(){stopped=true;state.cleanup='closed';state.status=state.gaps.length?'partial':'closed';publish();}};
}
function readPrivate(file){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const st=fs.fstatSync(fd);if(!st.isFile()||(st.mode&0o077)||st.size>1048576)throw fail();return validateSinkInput(JSON.parse(fs.readFileSync(fd,'utf8')));}finally{fs.closeSync(fd);}}
function exclusive(file,value){const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,JSON.stringify(value));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function atomic(file,value){const temp=file+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';exclusive(temp,value);try{if(fs.existsSync(file)&&!fs.lstatSync(file).isFile())throw fail();fs.renameSync(temp,file);}finally{try{fs.unlinkSync(temp);}catch{}}}
function syntheticMaterial(input){const vapid=crypto.createECDH('prime256v1');vapid.generateKeys();const subscriber=crypto.createECDH('prime256v1');subscriber.generateKeys();return {vapid:{public_key:vapid.getPublicKey().toString('base64url'),private_key:Buffer.from(vapid.getPrivateKey().toString('hex').padStart(64,'0'),'hex').toString('base64url'),subject:'mailto:helix@helix-mail.invalid'},subscription:{endpoint:input.webpush_endpoint,expirationTime:null,keys:{p256dh:subscriber.getPublicKey().toString('base64url'),auth:crypto.randomBytes(16).toString('base64url')}},simulation:true};}
function startSink(input){
  validateSinkInput(input);const http=require('node:http');
  const st=fs.lstatSync(input.mailbox_path);if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077))throw fail();
  exclusive(path.join(input.mailbox_path,'generated-material.json'),syntheticMaterial(input));
  const handler=createHandler(input,{writeMailbox:row=>exclusive(path.join(input.mailbox_path,'capture-'+String(row.sequence).padStart(6,'0')+'.json'),row),writePublic:row=>atomic(input.public_path,row)});
  const sockets=new Set();const server=http.createServer(async(req,res)=>{let size=0,chunks=[];try{for await(const chunk of req){size+=chunk.length;if(size>input.limits.max_body_bytes){chunks=[Buffer.alloc(input.limits.max_body_bytes+1)];break;}chunks.push(chunk);}const result=await handler.handle({url:req.url,method:req.method,headers:req.headers,body:Buffer.concat(chunks)});res.writeHead(result.status,result.headers);res.end(result.body);}catch{res.writeHead(503,{'content-type':'application/json'});res.end('{"error":"SINK_UNAVAILABLE"}');}});
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  server.requestTimeout=5000;server.headersTimeout=5000;
  let closed=false,timer;const close=()=>{if(closed)return;closed=true;clearTimeout(timer);server.close();for(const socket of sockets)socket.destroy();handler.close();};
  for(const sig of ['SIGINT','SIGTERM'])process.once(sig,close);
  server.on('error',()=>{try{close();}finally{process.exitCode=2;}});
  server.listen(Number(new URL(input.origin).port),'127.0.0.1',()=>{handler.ready();process.stdout.write(JSON.stringify({type:'runtime-sinks',event:'listening'})+'\n');});
  timer=setTimeout(close,Math.max(1,input.deadline_unix_ms-Date.now()));return {close,server,handler};
}
module.exports={validateSinkInput,classifyRequest,createHandler,readPrivate,syntheticMaterial,startSink,headersObject};
if(require.main===module){try{startSink(readPrivate(process.argv[2]));}catch{process.stderr.write('runtime sinks: SINK_INPUT_INVALID\n');process.exitCode=2;}}
