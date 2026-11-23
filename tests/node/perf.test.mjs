import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
const probe=spawnSync(process.execPath,['--version'],{encoding:'utf8'});
const test=(name,fn)=>nodeTest(name,{skip:probe.error ? 'Node child processes unavailable: '+probe.error.code : false},fn);
const script=fileURLToPath(new URL('../../scripts/perf-audit.mjs',import.meta.url));
const random=n=>Buffer.concat(Array.from({length:Math.ceil(n/32)},(_,i)=>crypto.createHash('sha256').update('fixture'+i).digest())).subarray(0,n);
function fixture(){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'helix-perf-'));
 fs.mkdirSync(path.join(root,'.git'));
 const output=path.join(root,'.svelte-kit/output');
 const client=path.join(output,'client');const server=path.join(output,'server');
 for(const sub of ['entry','nodes','chunks','assets'])fs.mkdirSync(path.join(client,'_app/immutable',sub),{recursive:true});
 fs.mkdirSync(path.join(server,'nodes'),{recursive:true});fs.mkdirSync(path.join(client,'.vite'),{recursive:true});
 fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({type:'module'}));
 const app='_app/immutable/entry/app.a.js',start='_app/immutable/entry/start.a.js',leaf='_app/immutable/nodes/1.a.js';
 fs.writeFileSync(path.join(client,app),'const app=1;');fs.writeFileSync(path.join(client,start),'const start=1;');fs.writeFileSync(path.join(client,leaf),random(2048));
 fs.writeFileSync(path.join(client,'.vite/manifest.json'),JSON.stringify({app:{file:app},start:{file:start},leaf:{file:leaf,name:'nodes/1'}}));
 fs.writeFileSync(path.join(server,'manifest.js'),'export const manifest='+JSON.stringify({_:{client:{app,start,imports:[],stylesheets:[]},routes:[{id:'/one',page:{layouts:[null,0],leaf:1}}]}})+';');
 for(const id of [0,1])fs.writeFileSync(path.join(server,'nodes',`${id}.js`),`export const imports = ${JSON.stringify(id?[leaf]:[])};\nexport const stylesheets = [];`);
 const run=(args=[])=>{
  const r=spawnSync(process.execPath,[script,root,'--out',path.join(root,'results'),...args],{encoding:'utf8'});
  let report;try{report=JSON.parse(fs.readFileSync(path.join(root,'results/perf-audit.json'),'utf8'));}catch{}
  return {...r,report};
 };
 return {root,client,leaf,run,base:path.join(root,'scripts/perf-baseline.json')};
}
test('performance ratchet measures start/app and nullable layout slots; cannot self-approve regression',()=>{
 const f=fixture();try{
  assert.equal(f.run().status,1);
  const init=f.run(['--init-baseline']);assert.equal(init.status,0,init.stderr+init.stdout);assert.equal(init.report.routes[0].files,3);
  const before=fs.readFileSync(f.base,'utf8');
  assert.equal(f.run(['--init-baseline']).status,2);assert.equal(fs.readFileSync(f.base,'utf8'),before);
  fs.writeFileSync(path.join(f.client,f.leaf),random(16000));
  const grown=f.run(['--update-baseline']);assert.equal(grown.status,1,grown.stdout);assert.equal(grown.report.baselineUpdated,false);assert.equal(fs.readFileSync(f.base,'utf8'),before);
  fs.writeFileSync(path.join(f.client,f.leaf),random(1000));
  assert.equal(f.run(['--update-baseline']).status,0);
  assert.ok(JSON.parse(fs.readFileSync(f.base,'utf8')).routes['/one'].js_gz<JSON.parse(before).routes['/one'].js_gz);
 }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});
test('malformed baseline and invalid budget fail closed with incomplete artifact',()=>{
 const f=fixture();try{
  assert.equal(f.run(['--init-baseline']).status,0);
  const base=JSON.parse(fs.readFileSync(f.base,'utf8'));delete base.routes['/one'].js_gz;fs.writeFileSync(f.base,JSON.stringify(base));
  const bad=f.run();assert.equal(bad.status,2);assert.equal(bad.report.status,'incomplete');
  fs.writeFileSync(path.join(f.root,'scripts/perf-budget.json'),JSON.stringify({tolerance_kib:-1}));assert.equal(f.run().status,2);
 }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});

test('stale bundle cannot certify newer source code',()=>{
 const f=fixture();try{
  assert.equal(f.run(['--init-baseline']).status,0);
  fs.mkdirSync(path.join(f.root,'src'));const source=path.join(f.root,'src/page.svelte');fs.writeFileSync(source,'new import');
  const future=new Date(Date.now()+2000);fs.utimesSync(source,future,future);
  const r=f.run();assert.equal(r.status,2);assert.equal(r.report.status,'incomplete');assert.match(r.report.errors[0],/starszy/);
 }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});

test('SSR redirects and timeouts are not accepted as timing samples',async()=>{
 const f=fixture(); const server=http.createServer((req,res)=>{
  if(req.url==='/redirect'){res.writeHead(302,{location:'/login'});res.end();}
  else if(req.url==='/stall')return;
  else res.end('<html>OK</html>');
 });
 try{
  assert.equal(f.run(['--init-baseline']).status,0);
  await new Promise(r=>server.listen(0,'127.0.0.1',r));const url=`http://127.0.0.1:${server.address().port}`;
  const child=spawn(process.execPath,[script,f.root,'--out',path.join(f.root,'ssr-results'),'--ssr',url,'--routes','/ok,/redirect,/stall','--ssr-timeout','200']);
  child.stdout.resume();child.stderr.resume();const code=await new Promise(r=>child.once('exit',r));
  assert.equal(code,1);
  const report=JSON.parse(fs.readFileSync(path.join(f.root,'ssr-results/perf-audit.json'),'utf8'));
  assert.equal(report.ssr[0].valid,true);assert.equal(report.ssr[0].samples,5);
  for(const row of report.ssr.slice(1)){assert.equal(row.valid,false);assert.equal(row.ttfb_ms,null);assert.equal(row.total_ms,null);}
 }finally{server.closeAllConnections();await new Promise(r=>server.close(r));fs.rmSync(f.root,{recursive:true,force:true});}
});

test('unrecognized bundle node format is incomplete instead of zero bytes',()=>{
 const f=fixture();try{
  assert.equal(f.run(['--init-baseline']).status,0);
  fs.writeFileSync(path.join(f.root,'.svelte-kit/output/server/nodes/1.js'),'const imports=[]; export {imports};');
  const r=f.run();assert.equal(r.status,2);assert.equal(r.report.status,'incomplete');assert.match(r.report.errors[0],/Nieznany format/);
 }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});
test('unknown performance options are rejected',()=>{
 const f=fixture();try{assert.equal(f.run(['--budgte','/tmp/typo']).status,2);}finally{fs.rmSync(f.root,{recursive:true,force:true});}
});
