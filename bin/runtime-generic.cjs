'use strict';
const {Writable,Readable}=require('node:stream');
function install(input,{target=globalThis,http=require('node:http'),https=require('node:https'),module=require('node:module')}={}) {
  const fetch=target.fetch,request=http.request,secure=https.request,load=module._load,get=http.get,sget=https.get;
  const own=url=>input.own_origins.includes(new URL(url).origin);
  async function capture(url,method,headers,body) {
    if(Buffer.byteLength(body||'')>65536)throw new Error('HELIX_CAPTURE_LIMIT');
    let parsed=null;try{parsed=body?JSON.parse(body):null;}catch{try{parsed=Object.fromEntries(new URLSearchParams(body));}catch{}}
    return fetch(input.origin+'/capture',{method:'POST',redirect:'error',headers:{authorization:'Bearer '+input.token,'content-type':'application/json'},
      body:JSON.stringify({url,method,headers:Object.fromEntries(new Headers(headers)),body:parsed}),signal:AbortSignal.timeout(15000)});
  }
  target.fetch=async(resource,options)=>{
    if(options&&(options.dispatcher||options.agent))throw new Error('HELIX_CUSTOM_TRANSPORT_UNSUPPORTED');
    const req=new Request(resource,options);if(own(req.url))return fetch(req,{redirect:'error'});
    let size=0,parts=[];if(req.body){const reader=req.body.getReader();try{for(;;){const x=await reader.read();if(x.done)break;size+=x.value.byteLength;if(size>65536){await reader.cancel();throw new Error('HELIX_CAPTURE_LIMIT');}parts.push(Buffer.from(x.value));}}finally{reader.releaseLock();}}
    return capture(req.url,req.method,req.headers,Buffer.concat(parts).toString());
  };
  function wrapped(tls,...args) {
    let url,opts={},callback=args.find(x=>typeof x==='function');
    if(typeof args[0]==='string'||args[0] instanceof URL){url=new URL(args[0]);opts=typeof args[1]==='object'?args[1]:{};
      if(['host','hostname','port','path','protocol'].some(k=>Object.hasOwn(opts,k)))throw new Error('HELIX_URL_OVERRIDE_UNSUPPORTED');
    }else{opts=args[0]||{};url=new URL((opts.protocol||(tls?'https:':'http:'))+'//'+(opts.hostname||opts.host||'localhost')+(opts.port?':'+opts.port:'')+(opts.path||'/'));}
    if(opts.socketPath||opts.createConnection||opts.lookup||(opts.agent&&opts.agent!==false))throw new Error('HELIX_CUSTOM_TRANSPORT_UNSUPPORTED');
    if(own(url.href))return (tls?secure:request)(...args);
    const chunks=[];let size=0;const headers={...(opts.headers||{})};
    const stream=new Writable({write(chunk,enc,done){size+=chunk.length;if(size>65536)return done(new Error('HELIX_CAPTURE_LIMIT'));chunks.push(Buffer.from(chunk));done();},
      final(done){capture(url.href,opts.method||'GET',headers,Buffer.concat(chunks).toString()).then(async res=>{
        const body=Buffer.from(await res.arrayBuffer());const response=Readable.from(body);response.statusCode=res.status;response.headers=Object.fromEntries(res.headers);
        if(callback)callback(response);stream.emit('response',response);done();
      },()=>done(new Error('HELIX_CAPTURE_FAILED')));}});
    stream.setHeader=(k,v)=>{headers[k]=v;};stream.getHeader=k=>headers[k];stream.removeHeader=k=>delete headers[k];stream.setTimeout=()=>stream;stream.flushHeaders=()=>{};stream.abort=()=>stream.destroy();
    return stream;
  }
  http.request=(...args)=>wrapped(false,...args);https.request=(...args)=>wrapped(true,...args);
  http.get=(...args)=>{const r=http.request(...args);r.end();return r;};https.get=(...args)=>{const r=https.request(...args);r.end();return r;};
  module._load=function(name,...args){if(input.disabled_packages.some(p=>name===p||name.startsWith(p+'/')))throw new Error('HELIX_INTEGRATION_DISABLED');return load.call(this,name,...args);};
  return()=>{target.fetch=fetch;http.request=request;https.request=secure;http.get=get;https.get=sget;module._load=load;};
}
module.exports={install};
if(process.env.HELIX_GENERIC_INPUT){const fs=require('node:fs');const p=process.env.HELIX_GENERIC_INPUT;const stat=fs.lstatSync(p);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>1048576||(stat.mode&0o077))throw new Error('HELIX_INPUT_INVALID');install(JSON.parse(fs.readFileSync(p,'utf8')));}
