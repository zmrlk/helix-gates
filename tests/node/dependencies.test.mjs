import test from 'node:test';
import assert from 'node:assert/strict';
import { launchBrowser } from '../../scripts/lib/dependencies.mjs';
function fake({ hang=false, closeError=false, connectError=false }={}) {
 let kills=0, disconnects=0, options;
 const server={wsEndpoint:()=> 'ws://127.0.0.1/test',close:()=>closeError?Promise.reject(new Error('close failed')):hang?new Promise(()=>{}):Promise.resolve(),kill:async()=>{kills++;}};
 const chromium={launchServer:async o=>{options=o;return server;},connect:async()=>{if(connectError)throw new Error('connect failed');return {close:async()=>{disconnects++;}};}};
 return {chromium,stats:()=>({kills,disconnects,options})};
}
test('browser shutdown is idempotent and never exposes its control endpoint outside loopback',async()=>{
 const f=fake();const browser=await launchBrowser(f.chromium);
 await Promise.all([browser.close(),browser.close()]);
 assert.equal(f.stats().options.host,'127.0.0.1');assert.equal(f.stats().kills,0);assert.equal(f.stats().disconnects,1);
});
test('stalled owned browser is killed after the grace period',async()=>{
 const f=fake({hang:true});const browser=await launchBrowser(f.chromium);const started=performance.now();
 await browser.close();assert.ok(performance.now()-started<3000);assert.equal(f.stats().kills,1);assert.equal(browser.helixCleanup.forced,true);
});
test('connection or graceful-close failure releases the launched browser',async()=>{
 const connection=fake({connectError:true});await assert.rejects(launchBrowser(connection.chromium),/connect failed/);assert.equal(connection.stats().kills,1);
 const closing=fake({closeError:true});const browser=await launchBrowser(closing.chromium);await assert.rejects(browser.close(),/close failed/);assert.equal(closing.stats().kills,1);
});
test('run-owned TLS keys and the run-owned control port reach the browser only when valid',async()=>{
 const names=['HELIX_RUNTIME_TLS_SPKI_LIST','HELIX_RUNTIME_OIDC_SPKI','HELIX_BROWSER_PORT'];const saved=Object.fromEntries(names.map(n=>[n,process.env[n]]));
 const keys='t2ICmjBInpF2s4/N3hBjck6P6FMiaVQbEiYW3qQEVA0=,P84/loEFAzY1gX/kqUiM6GAgijLRB9ZtzJi0C0XAHg0=';
 try{
  for(const n of names)delete process.env[n];
  let f=fake();await (await launchBrowser(f.chromium)).close();assert.deepEqual(f.stats().options.args,['--lang=pl-PL']);assert.equal(f.stats().options.port,undefined);
  process.env.HELIX_RUNTIME_TLS_SPKI_LIST=keys;process.env.HELIX_BROWSER_PORT='41777';
  f=fake();await (await launchBrowser(f.chromium)).close();
  assert.deepEqual(f.stats().options.args,['--lang=pl-PL','--ignore-certificate-errors-spki-list='+keys]);assert.equal(f.stats().options.port,41777);
  assert.ok(!f.stats().options.args.includes('--ignore-certificate-errors'));
  delete process.env.HELIX_RUNTIME_TLS_SPKI_LIST;process.env.HELIX_RUNTIME_OIDC_SPKI=keys.split(',')[1];
  f=fake();await (await launchBrowser(f.chromium)).close();assert.equal(f.stats().options.args[1],'--ignore-certificate-errors-spki-list='+keys.split(',')[1]);
  for(const bad of ['abc --remote-debugging-port=1',keys+' --no-sandbox','']){
   if(bad==='')continue;process.env.HELIX_RUNTIME_TLS_SPKI_LIST=bad;f=fake();await assert.rejects(launchBrowser(f.chromium),/invalid owned TLS key list/);assert.equal(f.stats().options,undefined);
  }
  process.env.HELIX_RUNTIME_TLS_SPKI_LIST=keys;
  for(const bad of ['80','0','70000','41777x','-1']){process.env.HELIX_BROWSER_PORT=bad;f=fake();await assert.rejects(launchBrowser(f.chromium),/HELIX_BROWSER_PORT/);assert.equal(f.stats().options,undefined);}
 }finally{for(const n of names){if(saved[n]===undefined)delete process.env[n];else process.env[n]=saved[n];}}
});
