"""HTTPS proxy with fake Node transports. No sockets, services or network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROXY = ROOT / 'bin' / 'runtime-https.cjs'
HARNESS = r'''
const assert=require('node:assert/strict'), {EventEmitter}=require('node:events');
const {PassThrough,Writable}=require('node:stream');
const P=require(process.argv[2]);
const scenario=process.argv[3];
const config={schema_version:1,public_origin:'https://localhost:44000',backend_origin:'http://127.0.0.1:44001',
 cert_path:'/private/own/cert.pem',key_path:'/private/own/key.pem',deadline_unix_ms:10000,request_timeout_ms:1000};
let clock=0, server, calls=[], events=[], timers=[], tlsOptions;
const schedule=(callback,delay)=>{const timer={callback,delay,active:true,unref(){}};timers.push(timer);return timer;};
const cancel=timer=>{timer.active=false;};
class Server extends EventEmitter {
 constructor(handler){super();this.handler=handler;this.closed=0;this.bound=[];}
 listen(port,host,done){this.bound.push({port,host});if(scenario==='bind_failure')this.emit('error',new Error('PRIVATE_ERROR'));else if(scenario==='cancel_pending_listen')this.pending=done;else queueMicrotask(done);}
 close(done){this.closed++;done();}
}
class Response extends Writable {
 constructor(){super();this.status=null;this.headers=null;this.chunks=[];this.headersSent=false;}
 _write(chunk,encoding,done){this.chunks.push(chunk.toString());done();}
 writeHead(status,headers){this.status=status;this.headers=headers;this.headersSent=true;return this;}
}
function request(url='/stream',headers={host:'localhost:44000'},method='GET',rawHeaders){
 const req=new PassThrough();Object.assign(req,{url,headers,method,rawHeaders:rawHeaders||Object.entries(headers).flat(),socket:{remoteAddress:'127.0.0.1'}});return req;
}
function answer(call,status=200,headers={}){const response=new PassThrough();response.statusCode=status;response.headers=headers;call.answer(response);return response;}
const deps={now:()=>clock,wallNow:()=>0,setTimeout:schedule,clearTimeout:cancel,onEvent:e=>events.push(e),
 https:{createServer:(options,handler)=>{tlsOptions=options;server=new Server(handler);return server;}},
 http:{request:(options,callback)=>{const stream=new PassThrough();const body=[];stream.on('data',data=>body.push(data.toString()));calls.push({options,stream,body,answer:callback});return stream;}}};
const tls={cert:Buffer.from('PRIVATE_CERT'),key:Buffer.from('PRIVATE_KEY')};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 if(scenario==='invalid_configs'){
  for(const changes of [{public_origin:'http://localhost:44000'},{public_origin:'https://public.invalid:44000'},
   {public_origin:'https://localhost:44000/'},{backend_origin:'http://localhost:44001'},
   {backend_origin:'http://169.254.169.254:44001'},{backend_origin:'http://127.0.0.1:44000'},
   {backend_origin:'http://user:SECRET@127.0.0.1:44001'},{deadline_unix_ms:0},{request_timeout_ms:0},
   {request_timeout_ms:60001},{key_path:'relative'},{extra:'SECRET'}])assert.throws(()=>P.validateConfig({...config,...changes}),P.ProxyError);
  assert.equal(P.validateConfig({...config,public_origin:'https://[::1]:44000'}).public_origin,'https://[::1]:44000');
  assert.equal(server,undefined);return;
 }
 if(scenario==='expired_before_start'){
  assert.throws(()=>P.createProxy({...config,deadline_unix_ms:1},tls,{...deps,wallNow:()=>2}),/DEADLINE_EXHAUSTED/);assert.equal(server,undefined);return;
 }
 const proxy=P.createProxy(config,tls,deps);
 if(scenario==='cancel_pending_listen'){
  const pending=proxy.listen();await proxy.close('signal');server.pending();await assert.rejects(pending,/LISTEN_CANCELLED/);
  assert.equal(server.closed,1);assert.equal(timers.length,0);assert(!proxy.snapshot().listening);assert(!events.some(e=>e.event==='listening'));return;
 }
 if(scenario==='bind_failure'){
  await assert.rejects(proxy.listen(),/LISTEN_FAILED/);await proxy.close('error');assert.equal(timers.length,0);assert(!JSON.stringify(events).includes('PRIVATE_ERROR'));return;
 }
 await proxy.listen();
 assert.deepEqual(server.bound,[{port:44000,host:'127.0.0.1'}]);
 assert.equal(tlsOptions.minVersion,'TLSv1.2');assert.equal(tlsOptions.key,tls.key);
 if(scenario==='host_and_target_rejection'){
  const fixtures=[request('/',{host:'other.invalid:44000'}),request('/',{host:'localhost:44000'},'GET',['Host','localhost:44000','hOsT','localhost:44000']),
   request('https://remote.invalid/path'),request('//remote.invalid/path'),request('/bad\r\npath'),request('/bad%0dpath'),request('/bad\\path'),request('/',undefined,'CONNECT')];
  for(const req of fixtures){const res=new Response();server.handler(req,res);assert.equal(res.status,400);}
  assert.equal(calls.length,0);
 }else if(scenario==='fixed_backend_and_spoofed_proxy_headers'){
  const req=request('/api?q=one',{host:'localhost:44000',origin:'https://wrong-origin.invalid',cookie:'PRIVATE_SESSION',
   forwarded:'host=evil;proto=http','x-forwarded-host':'evil','x-forwarded-proto':'http','x-forwarded-port':'80',
   'x-forwarded-for':'198.51.100.2','x-forwarded-secret':'SECRET',connection:'keep-alive, X-Custom',
   'x-custom':'DROP_ME','keep-alive':'100','proxy-authorization':'SECRET'});
  const res=new Response();server.handler(req,res);req.end('stream-body');await tick();
  assert.equal(calls.length,1);const options=calls[0].options;
  assert.equal(options.hostname,'127.0.0.1');assert.equal(options.port,44001);assert.equal(options.path,'/api?q=one');
  assert.equal(options.headers.host,'localhost:44000');assert.equal(options.headers['x-forwarded-proto'],'https');
  assert.equal(options.headers['x-forwarded-host'],'localhost:44000');assert.equal(options.headers['x-forwarded-port'],'44000');
  assert.equal(options.headers['x-forwarded-for'],'127.0.0.1');assert.equal(options.headers.origin,'https://wrong-origin.invalid');
  assert.equal(options.headers.cookie,'PRIVATE_SESSION');assert.equal(calls[0].body.join(''),'stream-body');
  for(const field of ['forwarded','x-forwarded-secret','x-custom','keep-alive','proxy-authorization','connection'])assert(!(field in options.headers));
  answer(calls[0]).end('ok');await tick();
 }else if(scenario==='streaming_and_multiple_cookies'){
  const req=request();const res=new Response();server.handler(req,res);req.end();
  const cookies=['session=PRIVATE; Path=/; Secure; HttpOnly; SameSite=Lax','hint=OTHER; Path=/auth; SameSite=None'];
  const backend=answer(calls[0],200,{'set-cookie':cookies,'content-type':'text/event-stream','x-helix-runtime-proxy-error':'spoof',connection:'keep-alive, x-hop','x-hop':'remove'});
  backend.write('first chunk');assert.equal(res.chunks.join(''),'first chunk');assert(!res.writableEnded);
  assert.equal(res.headers['set-cookie'],cookies);assert(!('x-helix-runtime-proxy-error' in res.headers));assert(!('connection' in res.headers));assert(!('x-hop' in res.headers));
  backend.end(' second chunk');await tick();assert.equal(res.chunks.join(''),'first chunk second chunk');assert.equal(proxy.snapshot().active_requests,0);
  assert.equal(timers.filter(t=>t.active).length,1);
 }else if(scenario==='location_is_not_rewritten'){
  const req=request(),res=new Response();server.handler(req,res);req.end();
  answer(calls[0],302,{location:'http://bad-origin.invalid/callback?code=PRIVATE'}).end();await tick();
  assert.equal(res.headers.location,'http://bad-origin.invalid/callback?code=PRIVATE');
 }else if(scenario==='request_timeout'){
  const req=request(),res=new Response();server.handler(req,res);
  const timer=timers.find(t=>t.delay===1000);clock=1000;timer.callback();await tick();
  assert.equal(res.status,504);assert.equal(res.headers['x-helix-runtime-proxy-error'],'1');assert(calls[0].stream.destroyed);assert.equal(proxy.snapshot().active_requests,0);
 }else if(scenario==='remaining_budget_caps_request'){
  clock=9750;const req=request(),res=new Response();server.handler(req,res);
  assert(timers.some(t=>t.delay===250));clock=10001;
  const another=new Response();server.handler(request(),another);assert.equal(another.status,503);assert.equal(calls.length,1);
 }else if(scenario==='backend_failure_before_headers'){
  const req=request(),res=new Response();server.handler(req,res);
  calls[0].stream.emit('error',new Error('PRIVATE_BACKEND'));await tick();assert.equal(res.status,502);assert.equal(res.headers['x-helix-runtime-proxy-error'],'1');assert(calls[0].stream.destroyed);
 }else if(scenario==='backend_failure_after_headers'){
  const req=request(),res=new Response();server.handler(req,res);req.end();
  const backend=answer(calls[0]);backend.write('partial');backend.emit('error',new Error('PRIVATE_BACKEND'));
  await tick();assert(res.destroyed);assert.equal(res.status,200);assert(backend.destroyed);assert.equal(proxy.snapshot().active_requests,0);
 }else if(scenario==='client_abort'){
  const req=request(),res=new Response();server.handler(req,res);req.emit('aborted');await tick();
  assert(calls[0].stream.destroyed);assert(res.destroyed);assert.equal(proxy.snapshot().active_requests,0);
 }else if(scenario==='deadline_closes_only_owned'){
  const own=new EventEmitter();own.destroyed=false;own.destroy=function(){this.destroyed=true;this.emit('close')};
  const foreign={destroyed:false};server.emit('connection',own);
  const req=request(),res=new Response();server.handler(req,res);clock=10000;
  timers.find(t=>t.delay===10000).callback();await tick();
  assert(own.destroyed);assert(!foreign.destroyed);assert(calls[0].stream.destroyed);assert(res.destroyed);
  assert.equal(server.closed,1);await proxy.close();assert.equal(server.closed,1);assert(proxy.snapshot().stopped);
 }else if(scenario==='unsupported_tunnels'){
  for(const event of ['connect','upgrade']){const socket={closed:false,destroyed:false,end(value){this.closed=value},destroy(){this.destroyed=true}};
   server.emit(event,{},socket);assert(socket.closed.includes('405'));assert(socket.destroyed);}
  assert.equal(calls.length,0);
 }else if(scenario==='late_backend_response'){
  const req=request(),res=new Response();server.handler(req,res);await proxy.close('signal');
  const backend=answer(calls[0]);assert(backend.destroyed);assert(res.destroyed);assert.equal(proxy.snapshot().active_requests,0);
 }else if(scenario==='no_import_side_effects'){
  assert.equal(calls.length,0);assert.equal(events[0].event,'listening');
 }else throw Error('Unknown scenario');
 await proxy.close();
 const journal=JSON.stringify(events);
 for(const value of ['PRIVATE','SECRET','DROP_ME','wrong-origin.invalid','bad-origin.invalid','q=one'])assert(!journal.includes(value),journal);
 assert.equal(timers.filter(t=>t.active).length,0);
})().then(()=>process.stdout.write('OK\n')).catch(error=>{console.error(error.stack);process.exitCode=1;});
'''


class RuntimeHttpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which('node')
        if not cls.node: raise unittest.SkipTest('Node unavailable')

    def run_case(self, scenario):
        result = subprocess.run([self.node, '-', str(PROXY), scenario], input=HARNESS, text=True,
                                capture_output=True, timeout=5, env={'PATH': os.defpath})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'OK')

    def test_config_rejects_remote_backend_and_nonexact_public_origins(self): self.run_case('invalid_configs')
    def test_expired_deadline_never_creates_server(self): self.run_case('expired_before_start')
    def test_bind_failure_is_redacted_and_has_no_live_timer(self): self.run_case('bind_failure')
    def test_stop_while_bind_is_pending_never_reopens_listener(self): self.run_case('cancel_pending_listen')
    def test_exact_host_and_local_request_target_are_required(self): self.run_case('host_and_target_rejection')
    def test_fixed_backend_cannot_be_overridden_by_forwarded_headers(self): self.run_case('fixed_backend_and_spoofed_proxy_headers')
    def test_streams_responses_and_preserves_every_cookie_attribute(self): self.run_case('streaming_and_multiple_cookies')
    def test_does_not_repair_application_location_header(self): self.run_case('location_is_not_rewritten')
    def test_absolute_request_timeout_aborts_owned_upstream(self): self.run_case('request_timeout')
    def test_global_remaining_budget_caps_new_request(self): self.run_case('remaining_budget_caps_request')
    def test_backend_error_before_headers_yields_502_without_details(self): self.run_case('backend_failure_before_headers')
    def test_backend_error_after_stream_start_destroys_response(self): self.run_case('backend_failure_after_headers')
    def test_client_abort_releases_upstream(self): self.run_case('client_abort')
    def test_deadline_and_cleanup_close_only_owned_resources(self): self.run_case('deadline_closes_only_owned')
    def test_connect_and_websocket_upgrade_are_not_tunnels(self): self.run_case('unsupported_tunnels')
    def test_late_backend_response_cannot_reopen_closed_front(self): self.run_case('late_backend_response')

    def test_import_has_no_network_or_file_reads(self):
        script = "const fs=require('node:fs'),http=require('node:http'),https=require('node:https');http.request=()=>{throw Error('network')};https.createServer=()=>{throw Error('socket')};const p=require(process.argv[1]);console.log(typeof p.createProxy);"
        result = subprocess.run([self.node, '-e', script, str(PROXY)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stdout.strip(), 'function')

    def test_private_config_regular_files_only_and_no_secret_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); root.chmod(0o700)
            cert = root / 'cert.pem'; key = root / 'key.pem'; file = root / 'proxy.json'
            cert.write_text('PRIVATE_CERT'); key.write_text('PRIVATE_KEY')
            config = dict(schema_version=1, public_origin='https://localhost:44000', backend_origin='http://127.0.0.1:44001',
                          cert_path=str(cert), key_path=str(key), deadline_unix_ms=10000, request_timeout_ms=1000)
            file.write_text(json.dumps(config)); file.chmod(0o600)
            script = "const p=require(process.argv[1]),{EventEmitter}=require('node:events');try{const v=p.readConfig(process.argv[2]);const proxy=p.createProxy(v.config,v.tls,{wallNow:()=>0,now:()=>0,https:{createServer:()=>new EventEmitter()}});console.log(v.config.public_origin)}catch(e){console.log(e.code||'ERROR');process.exitCode=3}"
            def run(): return subprocess.run([self.node, '-e', script, str(PROXY), str(file)], capture_output=True, text=True, timeout=5)
            result = run(); self.assertEqual(result.returncode, 0, result.stderr)
            key.unlink(); key.symlink_to(cert)
            result = run(); self.assertEqual(result.returncode, 3); self.assertNotIn('PRIVATE', result.stdout)
            key.unlink(); os.mkfifo(key)
            result = run(); self.assertEqual(result.returncode, 3); self.assertNotIn('PRIVATE_KEY', result.stdout)
            key.unlink(); key.write_text('PRIVATE_KEY'); file.chmod(0o644)
            result = run(); self.assertEqual(result.returncode, 3)


if __name__ == '__main__': unittest.main()
