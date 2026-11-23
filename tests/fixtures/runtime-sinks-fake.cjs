'use strict';
// Real sink/adapter helpers, no listener or external transport.
const {Readable,Writable}=require('node:stream');
const fs=require('node:fs');
const path=require('node:path');
const H=require('../../bin/runtime-sinks.cjs');
const forbidden=()=>{throw Error('UNEXPECTED_NETWORK_OR_PROCESS');};
require('node:net').Socket.prototype.connect=forbidden;
require('node:net').Server.prototype.listen=forbidden;
require('node:tls').connect=forbidden;
for(const name of ['node:http','node:https']){const m=require(name);m.request=forbidden;m.get=forbidden;}
for(const name of ['lookup','resolve','resolveMx'])require('node:dns')[name]=forbidden;
for(const name of ['spawn','exec','execFile'])require('node:child_process')[name]=forbidden;
globalThis.fetch=forbidden;
function clone(value){return JSON.parse(JSON.stringify(value));}
function asBody(value){return value==null?Buffer.alloc(0):Buffer.isBuffer(value)?value:Buffer.from(typeof value==='string'?value:JSON.stringify(value));}
function answer(value){let body=value.body;try{body=JSON.parse(body);}catch{}return {status:value.status,headers:value.headers,body};}

function createTransportFixture(input,scenario={}){
  const mailboxes=[],publications=[],calls=[],dnsCalls=[];
  let mailboxCalls=0,publicCalls=0,now=1000;
  const handler=H.createHandler(input,{
    now:()=>now,
    writeMailbox(row){mailboxCalls++;if(scenario.mailboxFailure)throw Error('PRIVATE_WRITER_CANARY');mailboxes.push(clone(row));},
    writePublic(row){publicCalls++;if(scenario.publicFailure&&publicCalls>=scenario.publicFailure)throw Error('PRIVATE_WRITER_CANARY');publications.push(clone(row));}
  });
  async function delivery(url,options={}){
    const target=new URL(url),headers=Object.fromEntries(new Headers(options.headers||{}));
    const body=asBody(options.body),method=String(options.method||'GET').toUpperCase();
    calls.push({url:target.href,method,headers,body:body.toString('utf8')});
    if(scenario.redirect&&(target.origin===input.origin||input.own_origins.includes(target.origin)))return {status:302,headers:{location:'https://external.invalid/private'},body:''};
    if(target.origin!==input.origin){
      if(input.own_origins.includes(target.origin))return {status:200,headers:{'content-type':'application/json'},body:'{"own":true}'};
      throw Error('UNEXPECTED_EXTERNAL_FORWARD');
    }
    return handler.handle({url:target.href,method,headers,body});
  }
  async function fetchTransport(value,options){
    const req=value instanceof Request?new Request(value,options):new Request(value,options);
    const row=await delivery(req.url,{method:req.method,headers:req.headers,body:Buffer.from(await req.arrayBuffer())});
    if(row.status===302&&req.redirect!=='manual'){
      if(req.redirect==='error')throw Error('REDIRECT_NOT_ALLOWED');
      // Standard fetch follows redirects unless the adapter explicitly refuses.
      await delivery(row.headers.location,{method:'GET'});
    }
    return new Response([204,205,304].includes(row.status)?null:row.body,{status:row.status,headers:row.headers});
  }
  function httpTransport(value,options,callback){
    if(typeof options==='function'){callback=options;options={};}
    options=options||{};
    let u;if(typeof value==='string'||value instanceof URL)u=new URL(value);
    else{options={...value,...options};u=new URL((options.protocol||'http:')+'//'+(options.hostname||options.host)+(options.port?':'+options.port:'')+(options.path||'/'));}
    // Node's overload applies options after the URL. The fixture deliberately
    // preserves that precedence so an unsafe rewrite cannot hide in a test.
    if(options.protocol)u.protocol=options.protocol;
    if(options.hostname||options.host)u.hostname=options.hostname||options.host;
    if(options.port!==undefined)u.port=String(options.port);
    if(options.path)u=new URL(options.path,u.origin);
    const chunks=[];
    const request=new Writable({write(chunk,_encoding,done){chunks.push(Buffer.from(chunk));done();},
      final(done){delivery(u.href,{...options,body:Buffer.concat(chunks)}).then(result=>{
        const response=Readable.from([Buffer.from(result.body||'')]);response.statusCode=result.status;response.headers=result.headers;
        if(callback)callback(response);request.emit('response',response);done();
      },error=>done(error));}});
    request.setTimeout=()=>request;request.abort=()=>request.destroy();
    return request;
  }
  const dns={resolveMx(...args){dnsCalls.push(args[0]);throw Error('UNEXPECTED_DNS_FORWARD');},lookup(...args){dnsCalls.push(args[0]);throw Error('UNEXPECTED_DNS_FORWARD');}};
  return {handler,mailboxes,publications,calls,dnsCalls,fetchTransport,httpTransport,dns,
    counts:()=>({mailboxCalls,publicCalls}),setNow:value=>{now=value;}};
}

async function runCase(data){
  const {input,action='fetch',scenario={}}=data;
  const fixture=createTransportFixture(input,scenario);
  let result=null,error=null;
  try{
    if(action==='validate'){result={valid:!!H.validateSinkInput(input)};}
    else if(action==='material'){const m=H.syntheticMaterial(input);result={endpoint:m.subscription.endpoint,
      publicBytes:Buffer.from(m.subscription.keys.p256dh,'base64url').length,authBytes:Buffer.from(m.subscription.keys.auth,'base64url').length,
      privateBytes:Buffer.from(m.vapid.private_key,'base64url').length,simulation:m.simulation};}
    else if(action==='handler'||action==='closed'||action==='deadline'||action==='writer'){
      if(action==='closed')fixture.handler.close();
      if(action==='deadline')fixture.setNow(input.deadline_unix_ms);
      const request={url:input.origin+'/__helix_sink/'+(data.operation||'resend.send'),method:'POST',
        headers:{authorization:'Bearer '+input.bearer_token,'content-type':'application/json',...data.headers},body:asBody(data.body||{})};
      if(action==='writer'){
        let first,second;
        try{first=answer(await fixture.handler.handle(request));}catch(e){first={error:e.code||e.message};}
        const writesAfterFirst=fixture.counts().mailboxCalls;
        try{second=answer(await fixture.handler.handle(request));}catch(e){second={error:e.code||e.message};}
        result={first,second,writesAfterFirst};
      }else result=answer(await fixture.handler.handle({...request,...data.request,body:request.body}));
    }else{
      const P=require('../../bin/runtime-sinks-preload.cjs');
      const adapter=P.createAdapter(input,{fetch:fixture.fetchTransport,httpRequest:fixture.httpTransport,
        httpsRequest:fixture.httpTransport,dns:fixture.dns});
      if(action==='dns'){
        result={};for(const method of ['resolveMx','lookup']){try{result[method]=await adapter[method](data.domain);}catch(e){result[method]={error:e.code||e.message};}}
      }else if(action==='http'||action==='https'){
        result=await new Promise((resolve,reject)=>{
          const fn=action==='http'?adapter.httpRequest:adapter.httpsRequest;
          const options={method:'POST',headers:{'content-type':'application/json',...data.headers},...data.options};
          const callback=res=>{
            const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve(answer({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString()})));
          };
          const req=data.optionsObject?fn({...data.url,...options},callback):fn(data.url,options,callback);
          req.on('error',reject);req.end(asBody(data.body||{}));
        });
      }else{
        let value=data.url;
        const base={method:'POST',headers:{'content-type':'application/json',...data.headers},body:asBody(data.body||{})};
        if(data.urlObject)value=new URL(value);
        if(data.requestObject)value=new Request(value,base);
        const options=data.requestObject?data.options:{...base,...data.options};
        const response=await adapter.fetch(value,options);
        result=answer({status:response.status,headers:Object.fromEntries(response.headers),body:await response.text()});
      }
    }
  }catch(e){error={code:e.code||null,message:e.message};}
  if(action!=='closed')try{fixture.handler.close();}catch(e){error=error||{code:e.code||null,message:e.message};}
  return {result,error,mailboxes:fixture.mailboxes,publications:fixture.publications,calls:fixture.calls,
    dnsCalls:fixture.dnsCalls,snapshot:fixture.handler.snapshot(),...fixture.counts()};
}
module.exports={createTransportFixture,runCase};
if(require.main===module){const data=JSON.parse(fs.readFileSync(0,'utf8'));runCase(data).then(value=>process.stdout.write(JSON.stringify(value)),()=>{process.stderr.write('safe fixture failure');process.exitCode=1;});}
