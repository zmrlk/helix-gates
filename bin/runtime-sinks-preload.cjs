'use strict';
const {Writable}=require('node:stream');
const {validateSinkInput,classifyRequest,readPrivate,headersObject}=require('./runtime-sinks.cjs');
function unsupported(code='HELIX_SINK_UNSUPPORTED'){const error=new Error(code);error.code=code;return error;}
function plainData(value){
  if(value===undefined)return Object.create(null);
  if(value===null||typeof value!=='object'||![null,Object.prototype].includes(Object.getPrototypeOf(value)))throw unsupported();
  const result=Object.create(null);
  for(const key of Reflect.ownKeys(value)){
    const desc=Object.getOwnPropertyDescriptor(value,key);
    if(typeof key!=='string'||!desc||!Object.hasOwn(desc,'value'))throw unsupported();
    result[key]=desc.value;
  }
  return result;
}
function requestOptions(value){
  const result=plainData(value);
  const strings=['protocol','hostname','host','path','method'];
  for(const key of Object.keys(result)){
    const value=result[key];
    if(strings.includes(key)){if(typeof value!=='string')throw unsupported();}
    else if(key==='port'){if(!['string','number'].includes(typeof value)||!/^\d+$/.test(String(value))||+value<1||+value>65535)throw unsupported();}
    else if(key==='timeout'){if(typeof value!=='number'||!Number.isFinite(value)||value<0)throw unsupported();}
    else if(key==='agent'){if(value!==false)throw unsupported();}
    else if(key==='signal'){if(!(value instanceof AbortSignal))throw unsupported();}
    else if(key!=='headers')throw unsupported();
  }
  const headers=plainData(result.headers);
  for(const key of Object.keys(headers)){
    const value=headers[key];
    if(typeof value!=='string'&&typeof value!=='number')throw unsupported();
  }
  result.headers=headers;
  return result;
}
function createAdapter(input,{fetch:originalFetch,httpRequest,httpsRequest,dns={}}={}){
  validateSinkInput(input);
  const limit=input.limits.max_body_bytes;
  const local=op=>input.origin+'/__helix_sink/'+op.id;
  function check(){if(Date.now()>=input.deadline_unix_ms)throw unsupported('HELIX_SINK_DEADLINE');}
  function route(url,method){check();const match=classifyRequest(input,{url:String(url),method});if(match.kind==='unsupported')throw unsupported();return match;}
  async function boundedBody(request){
    if(!request.body)return Buffer.alloc(0);
    const reader=request.body.getReader();const chunks=[];let size=0;
    try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){await reader.cancel();throw unsupported('HELIX_SINK_LIMIT');}chunks.push(Buffer.from(value));}return Buffer.concat(chunks);}finally{reader.releaseLock();}
  }
  async function fetchAdapter(resource,options){
    if(options&&(options.dispatcher||options.agent))throw unsupported();
    let request;try{request=new Request(resource,options);}catch{throw unsupported();}
    // Ten sam jedyny wyjątek co dla http.request: odczyt (GET) z własnej przeglądarki pomiarowej. Do natywnego fetch idzie
    // nowe żądanie z samym adresem; nagłówki, treść i opcje wywołującego nie są przekazywane.
    if(request.method==='GET'&&control.includes(new URL(request.url).origin))return originalFetch(new Request(request.url,{method:'GET',signal:request.signal}),{redirect:'error'});
    const matched=route(request.url,request.method);
    if(matched.kind==='own')return originalFetch(request,{redirect:'error'});
    const body=await boundedBody(request);
    return originalFetch(local(matched.operation),{method:'POST',headers:{authorization:'Bearer '+input.bearer_token,'content-type':request.headers.get('content-type')||''},body,signal:request.signal,redirect:'error'});
  }
  function rejectRequest(error,callback){
    const stream=new Writable({write(chunk,encoding,done){done(error);}});
    stream.setTimeout=()=>stream;stream.setHeader=()=>stream;stream.getHeader=()=>undefined;stream.removeHeader=()=>{};stream.flushHeaders=()=>{};stream.abort=()=>stream.destroy();
    process.nextTick(()=>stream.destroy(error));return stream;
  }
  // Jedyny wyjątek od straży: połączenie sterujące z własną przeglądarką pomiarową na porcie wpisanym przez Helix do wejścia.
  const control=Array.isArray(input.browser_control_origins)?input.browser_control_origins:[];
  // Zwraca nowe, własne opcje żądania albo null. Do natywnego żądania nie trafia żaden obiekt wywołującego:
  // cel jest składany od zera z zatwierdzonego adresu, więc agent, createConnection, lookup, socketPath ani
  // drugi zestaw opcji nie mogą skierować połączenia gdzie indziej.
  function controlRequest(secure,args){
    if(secure||!control.length)return null;
    try{
      const own=(value,key)=>{const d=Object.getOwnPropertyDescriptor(value,key);return d&&Object.hasOwn(d,'value')?d.value:undefined;};
      const first=args[0];let url,extra;
      if(typeof first==='string'||first instanceof URL){url=new URL(String(first));extra=args[1]&&typeof args[1]==='object'?args[1]:null;}
      else if(first&&typeof first==='object'){
        const host=own(first,'hostname')===undefined?own(first,'host'):own(first,'hostname');const port=own(first,'port');
        if(typeof host!=='string'||!['string','number'].includes(typeof port)||!/^\d+$/.test(String(port)))return null;
        const path=own(first,'path');if(path!==undefined&&(typeof path!=='string'||!path.startsWith('/')))return null;
        url=new URL('http://'+host+':'+port+(path||'/'));extra=first;
      }else return null;
      if(!['http:','ws:'].includes(url.protocol)||url.username||url.password||!control.includes('http://'+url.host))return null;
      if(extra){
        for(const key of ['socketPath','createConnection','lookup','auth','localAddress','family','hints']){
          // ws (Playwright) podaje własne createConnection i lookup; nie są przekazywane dalej, połączenie idzie
          // domyślną drogą Node wprost do zatwierdzonego adresu IP.
          if(key==='createConnection'||key==='lookup')continue;
          if(own(extra,key)!==undefined)return null;
        }
        const agent=own(extra,'agent');if(agent!==undefined&&agent!==false&&agent!==null)return null;
        for(const key of ['host','hostname','port','protocol']){
          const value=own(extra,key);if(value===undefined||extra===first)continue;
          return null;
        }
      }
      const headers=Object.create(null);const source=extra?own(extra,'headers'):undefined;
      if(source!==undefined){
        if(source===null||typeof source!=='object')return null;
        for(const key of Object.keys(source)){const value=own(source,key);if(typeof value!=='string'&&typeof value!=='number')return null;if(key.toLowerCase()==='host')continue;headers[key]=value;}
      }
      const method=extra&&own(extra,'method')!==undefined?String(own(extra,'method')).toUpperCase():'GET';
      if(!/^[A-Z]+$/.test(method))return null;
      const options=Object.assign(Object.create(null),{protocol:'http:',host:url.hostname,port:Number(url.port),path:url.pathname+url.search,method,headers,agent:false});
      const timeout=extra?own(extra,'timeout'):undefined;if(typeof timeout==='number'&&Number.isFinite(timeout)&&timeout>=0)options.timeout=timeout;
      return options;
    }catch{return null;}
  }
  function requestAdapter(secure,...args){
    const controlled=controlRequest(secure,args);
    if(controlled)return httpRequest(controlled,args.find(x=>typeof x==='function'));
    let url,options={},callback;
    try{
      if(typeof args[0]==='string'||args[0] instanceof URL){url=new URL(args[0]);options=requestOptions(typeof args[1]==='function'?undefined:args[1]);callback=args.find(x=>typeof x==='function');if(['protocol','hostname','host','port','path','href'].some(key=>Object.hasOwn(options,key)))throw unsupported();}
      else{options=requestOptions(args[0]);callback=typeof args[1]==='function'?args[1]:undefined;const protocol=options.protocol||(secure?'https:':'http:');const hostname=options.hostname||options.host||'localhost';url=new URL(protocol+'//'+hostname+(options.port?':'+options.port:'')+(options.path||'/'));}
      if(options.socketPath||options.createConnection||options.lookup||(options.agent&&options.agent!==false)||options.auth||url.username||url.password)throw unsupported();
      const method=String(options.method||'GET').toUpperCase();const matched=route(url.href,method);
      if(matched.kind==='own'){
        // Classification and native dispatch use the same snapshot. Never pass
        // the caller's descriptors, prototype or a second read of its options.
        const forwarded=Object.assign(Object.create(null),{method,headers:options.headers,agent:false});
        for(const key of ['signal','timeout'])if(Object.hasOwn(options,key))forwarded[key]=options[key];
        return (secure?httpsRequest:httpRequest)(url.href,forwarded,callback);
      }
      const headers=headersObject(options.headers);
      const request=httpRequest(local(matched.operation),{method:'POST',headers:{authorization:'Bearer '+input.bearer_token,'content-type':headers['content-type']||''},signal:options.signal,timeout:options.timeout},callback);
      let total=0;const write=request.write.bind(request),end=request.end.bind(request);
      const count=(chunk,encoding)=>{if(chunk===undefined||chunk===null||typeof chunk==='function')return;total+=Buffer.isBuffer(chunk)?chunk.length:Buffer.byteLength(chunk,typeof encoding==='string'?encoding:undefined);if(total>limit)throw unsupported('HELIX_SINK_LIMIT');};
      request.write=function(chunk,encoding,cb){try{count(chunk,encoding);return write(chunk,encoding,cb);}catch(error){request.destroy(error);return false;}};
      request.end=function(chunk,encoding,cb){try{count(chunk,encoding);return end(chunk,encoding,cb);}catch(error){request.destroy(error);return request;}};
      const set=request.setHeader?.bind(request);if(set)request.setHeader=(name,value)=>{if(String(name).toLowerCase()==='content-type')set(name,value);return request;};
      return request;
    }catch(error){return rejectRequest(unsupported(error.code==='HELIX_SINK_LIMIT'?'HELIX_SINK_LIMIT':'HELIX_SINK_UNSUPPORTED'),callback);}
  }
  function dnsResult(kind,hostname,options,callback){
    if(typeof options==='function'){callback=options;options=undefined;}
    const allowed=typeof hostname==='string'&&input.synthetic_domains.includes(hostname);
    const localHost=['localhost','127.0.0.1','::1'].includes(hostname)&&input.own_origins.some(value=>new URL(value).hostname.replace(/^\[|\]$/g,'')===hostname);
    if(!allowed&&localHost&&kind==='lookup'&&typeof dns[kind]==='function'){if(typeof callback==='function')return options===undefined?dns[kind](hostname,callback):dns[kind](hostname,options,callback);return new Promise((resolve,reject)=>dns[kind](hostname,options||{},(error,address,family)=>error?reject(unsupported('ENOTFOUND')):resolve(kind==='lookup'&&!(options&&options.all)?{address,family}:address)));}
    const error=allowed?null:unsupported('ENOTFOUND');
    const result=kind==='resolveMx'?[{priority:0,exchange:'helix-mail.invalid'}]:(options&&options.all?[{address:'127.0.0.1',family:4}]:'127.0.0.1');
    if(typeof callback==='function'){process.nextTick(()=>kind==='lookup'&&!(options&&options.all)?callback(error,error?undefined:result,4):callback(error,error?undefined:result));return;}
    return error?Promise.reject(error):Promise.resolve(kind==='lookup'&&!(options&&options.all)?{address:result,family:4}:result);
  }
  return {fetch:fetchAdapter,httpRequest:(...args)=>requestAdapter(false,...args),httpsRequest:(...args)=>requestAdapter(true,...args),resolveMx:(host,options,cb)=>dnsResult('resolveMx',host,options,cb),lookup:(host,options,cb)=>dnsResult('lookup',host,options,cb)};
}
function installAdapter(input,{globalObject=globalThis,http=require('node:http'),https=require('node:https'),dns=require('node:dns')}={}){
  const original={fetch:globalObject.fetch,httpRequest:http.request,httpsRequest:https.request,httpGet:http.get,httpsGet:https.get,resolveMx:dns.resolveMx,lookup:dns.lookup,promiseMx:dns.promises?.resolveMx,promiseLookup:dns.promises?.lookup};
  const adapter=createAdapter(input,{fetch:original.fetch?.bind(globalObject),httpRequest:original.httpRequest.bind(http),httpsRequest:original.httpsRequest.bind(https),dns:{lookup:original.lookup?.bind(dns),resolveMx:original.resolveMx?.bind(dns)}});
  globalObject.fetch=adapter.fetch;http.request=adapter.httpRequest;https.request=adapter.httpsRequest;
  http.get=(...args)=>{const req=http.request(...args);req.end();return req;};https.get=(...args)=>{const req=https.request(...args);req.end();return req;};
  dns.resolveMx=adapter.resolveMx;dns.lookup=adapter.lookup;
  if(dns.promises){dns.promises.resolveMx=host=>adapter.resolveMx(host);dns.promises.lookup=(host,options)=>adapter.lookup(host,options);}
  return ()=>{globalObject.fetch=original.fetch;http.request=original.httpRequest;https.request=original.httpsRequest;http.get=original.httpGet;https.get=original.httpsGet;dns.resolveMx=original.resolveMx;dns.lookup=original.lookup;if(dns.promises){dns.promises.resolveMx=original.promiseMx;dns.promises.lookup=original.promiseLookup;}};
}
module.exports={createAdapter,installAdapter};
if(process.env.HELIX_RUNTIME_SINK_INPUT){try{installAdapter(readPrivate(process.env.HELIX_RUNTIME_SINK_INPUT));}catch{process.stderr.write('runtime sink adapter: SINK_INPUT_INVALID\n');process.exitCode=2;throw unsupported('HELIX_SINK_INPUT_INVALID');}}
