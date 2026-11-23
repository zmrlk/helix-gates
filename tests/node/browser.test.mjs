import { test as nodeTest, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadDependencies, launchBrowser } from '../../scripts/lib/dependencies.mjs';
import { auditDOM } from '../../scripts/dom-audit.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));
const script=path.resolve(here,'../../scripts/ui-audit.mjs');
const approve=path.resolve(here,'../../scripts/visual-baseline.mjs');
const clean=fs.readFileSync(path.join(here,'fixtures/clean.html'),'utf8');
let browser, dir, server, origin, requestCount=0;
let unavailable;
if(process.env.HELIX_TEST_BROWSER==='0') unavailable='Browser execution reserved for wrapper (HELIX_TEST_BROWSER=0)';
else try { browser=await launchBrowser(loadDependencies().chromium); }
catch(error) {
 if(!/Brak Playwright|Executable doesn't exist|Missing|EPERM|Operation not permitted|Failed to launch browser|Host system is missing/i.test(error.message))throw error;
 unavailable='Playwright/Chromium unavailable: '+error.message.split('\n')[0].slice(0,250);
}
const test=(name,fn)=>nodeTest(name,{skip:unavailable||false},fn);
const modified=body=>clean.replace('</body>',body+'</body>');
const exec=(file,args=[])=>new Promise(resolve=>{
 const p=spawn(process.execPath,[file,...args],{env:process.env}); let stdout='',stderr='';
 p.stdout.on('data',c=>stdout+=c);p.stderr.on('data',c=>stderr+=c);
 p.on('close',code=>resolve({code,stdout,stderr}));
});
const reached=[];
async function cli(name,target,options=[]){
 const out=path.join(dir,name);
 const defaults=['--widths','390','--themes','light','--settle','30'].filter((v,i,a)=>!options.includes(a[i-i%2]));
 const result=await exec(script,[target,'--out',out,'--case','fixture',...defaults,...options]);
 let report;try{report=JSON.parse(fs.readFileSync(path.join(out,'audit.json'),'utf8'));}catch{}
 return {...result,report,out};
}
async function dom(body){
 const page=await browser.newPage({viewport:{width:390,height:900}});
 try {await page.setContent(body);return await page.evaluate(auditDOM,[[11,12,13,15,18,22,28],44,2,[4,8,12,16,24,32,48,64]]);}finally{await page.close();}
}
before(async()=>{
 if(unavailable)return;
 dir=fs.mkdtempSync(path.join(os.tmpdir(),'helix-browser-'));
 server=http.createServer((req,res)=>{
  requestCount++;
  if(req.url==='/data'){setTimeout(()=>res.end('{}'),350);return;}
  if(/^\/(items\/1\/delete|auth\/logout|items\/%64elete|items\/1\?action=delete)$/.test(req.url)){reached.push(req.url);res.end('{}');return;}
  if(req.url==='/missing'){res.writeHead(404);res.end('missing');return;}
  if(req.url==='/redirect'){res.writeHead(302,{location:'/login'});res.end();return;}
  if(req.url==='/stall'){return;}
  if(req.url==='/blank'){res.end('<html><body></body></html>');return;}
  res.setHeader('content-type','text/html; charset=utf-8');
  if(req.url==='/badjs')res.end(modified('<script>throw new Error("injected-defect")</script>'));
  else if(req.url==='/image')res.end(modified('<img alt="Logo" width="80" height="40" src="/missing">'));
  else if(req.url==='/unstable')res.end(modified('<script>let n=0;setInterval(()=>document.querySelector("h1").textContent=String(n++),20)</script>'));
  else if(req.url==='/slow')res.end(modified('<script>fetch("/data").then(()=>document.querySelector("h1").style.fontSize="77px")</script>'));
  else if(req.url==='/client-redirect')res.end(modified('<script>fetch("/data").then(()=>history.replaceState({},"","/login"))</script>'));
  else if(req.url==='/aborted')res.end(modified('<script>let c=new AbortController();fetch("/stall",{signal:c.signal}).catch(()=>{});setTimeout(()=>c.abort(),50)</script>'));
  else if(req.url==='/masked')res.end(modified('<div class=clock style="width:80px;height:40px"></div><script>let n=0;setInterval(()=>document.querySelector(".clock").style.background=(n++%2?"red":"blue"),20)</script>'));
  else if(req.url==='/frame')res.end(modified('<iframe sandbox srcdoc="<h1>obca</h1>"></iframe>'));
  else if(req.url==='/sandboxed-frame')res.end(modified('<iframe sandbox="allow-scripts" src="/tiny-font" style="width:300px;height:200px"></iframe>'));
  else if(req.url==='/limited')res.end(modified('<script>fetch("/api/limited")</script>'));
  else if(req.url==='/api/limited'){res.statusCode=429;res.end('{}');}
  else if(req.url==='/modal')res.end(modified('<dialog id="d"><h2 style="font-size:22px;line-height:28px">Witaj w nowej wersji</h2><button onclick="d.close()">Zaczynamy</button></dialog><script>d.showModal();d.addEventListener("cancel",e=>e.preventDefault())</script>'));
  else if(req.url==='/modal-font')res.end('<!doctype html><html lang="pl"><title>m</title><body><main><h1 style="font-size:30px;line-height:36px">Ekran</h1></main><dialog id="d"><p style="font-size:19px;line-height:24px">Tekst okna poza drabinką pisma</p></dialog><script>d.showModal()</script></body></html>');
  else if(req.url==='/window-plain')res.end('<!doctype html><html lang="pl"><title>m</title><body><main><h1 style="font-size:30px;line-height:36px">Ekran</h1></main><dialog id="d" open style="position:fixed;inset:10% 20%;width:60%;height:70%;margin:0"><h2 style="font-size:22px;line-height:28px">Co nowego</h2><button style="min-width:120px;min-height:44px" onclick="d.close()">Zaczynamy</button></dialog></body></html>');
  else if(req.url==='/modal-esc')res.end(modified('<dialog id="d"><h2 style="font-size:22px;line-height:28px">Nowości</h2></dialog><script>d.showModal()</script>'));
  else if(req.url==='/modal-defect')res.end('<!doctype html><html lang="pl"><title>m</title><body><main><h1 style="font-size:30px;line-height:36px">Ekran</h1></main><div id="d" role="dialog" aria-modal="true" aria-label="Nowości"><button aria-label="Zamknij" style="width:10px;height:10px;padding:0;border:0" onclick="d.hidden=true"></button></div></body></html>');
  else if(req.url==='/age-gate')res.end('<!doctype html><html lang="pl"><title>g</title><body><main><h1 style="font-size:30px;line-height:36px">Katalog</h1></main><div id="g" role="dialog" aria-modal="true" aria-label="Czy masz ukończone 18 lat?" style="position:fixed;inset:0;background:#fff"><button style="min-width:160px;min-height:44px" onclick="g.remove()">Tak, mam 18 lat</button> <button style="min-width:120px;min-height:44px" onclick="g.dataset.no=1">Nie</button></div></body></html>');
  else if(req.url==='/rows'||req.url==='/row/5')res.end('<!doctype html><html lang="pl"><title>r</title><body><main><h1 style="font-size:30px;line-height:36px">'+(req.url==='/rows'?'Lista':'Szczegóły')+'</h1>'+(req.url==='/rows'?'<table><tbody><tr style="cursor:pointer" onclick="location.href=\'/row/5\'"><td style="height:44px">Pozycja pierwsza</td></tr><tr style="cursor:pointer" onclick="location.href=\'/row/6\'"><td style="height:44px">Pozycja druga</td></tr><tr><td style="height:44px">Bez kliknięcia</td></tr></tbody></table>':'')+'</main></body></html>');
  else if(req.url==='/modal-stuck')res.end(modified('<dialog id="d"><h2>Blokada</h2></dialog><script>d.showModal();d.addEventListener("cancel",e=>e.preventDefault())</script>'));
  else if(req.url==='/states')res.end('<!doctype html><html lang="pl"><title>s</title><body><main><h1 style="font-size:30px;line-height:36px">Stany</h1>'
   +'<button style="min-width:120px;min-height:44px" onclick="p.hidden=false">Panel boczny</button> <button style="min-width:120px;min-height:44px" onclick="fetch(\'/data\',{method:\'POST\'})">Zapisz szkic</button> <button style="min-width:120px;min-height:44px" onclick="fetch(\'/items/1/delete\')">Skasuj pozycję</button>'
   +' <button style="min-width:120px;min-height:44px" onclick="fetch(\'/items/%64elete\')">Porządki</button> <button style="min-width:120px;min-height:44px" onclick="fetch(\'/items/1?action=delete\')">Przenieś</button> <button style="min-width:120px;min-height:44px" onclick="location.href=\'/auth/logout\'">Zmień konto</button>'
   +' <button style="min-width:120px;min-height:44px" onclick="throw new Error(\'zepsuty przycisk\')">Zepsuty</button>'
   +' <button style="min-width:120px;min-height:44px" aria-pressed="false" onclick="this.setAttribute(\'aria-pressed\',\'true\')">Tylko moje</button> <button style="min-width:120px;min-height:44px" onclick="f.click()">Wgraj plik</button><input id="f" type="file" hidden>'
   +'</main><nav><button style="min-width:120px;min-height:44px" onclick="m.hidden=false">Konto</button><div id="m" role="menu" hidden>Wyloguj</div><button style="min-width:120px;min-height:44px" onclick="location.href=\'/clean\'">Wyloguj się</button></nav><main>'
   +'<div id="p" role="dialog" aria-modal="true" aria-label="Panel" hidden><button aria-label="Zamknij" style="width:10px;height:10px;padding:0;border:0"></button>'
   +'<button style="min-width:120px;min-height:44px" onclick="c.hidden=false">Potwierdź usunięcie</button></div>'
   +'<div id="c" role="alertdialog" aria-modal="true" aria-label="Na pewno" hidden><p style="font-size:15px;line-height:22px">Tej operacji nie da się cofnąć</p></div></main></body></html>');
  else if(req.url==='/scrolled')res.end('<!doctype html><html lang="pl"><title>s</title><body><main style="height:200px;overflow:auto"><div style="height:120px;margin:8px;border-radius:12px;box-shadow:0 0 0 2px #555"><p style="font-size:15px;line-height:22px">Pierwsza karta</p></div><div style="height:320px;margin:8px;border-radius:12px;box-shadow:0 0 0 2px #555"><p style="font-size:15px;line-height:22px">Karta dalej na liście</p></div></main></body></html>');
  else if(req.url==='/own-frame')res.end(modified('<iframe src="/tiny-font" style="width:300px;height:200px"></iframe>'));
  else if(req.url==='/tiny-font')res.end('<!doctype html><html lang="pl"><title>t</title><body><main><p style="font-size:19px">ramka</p></main></body></html>');
  else res.end(clean);
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin=`http://127.0.0.1:${server.address().port}`;
});
after(async()=>{await browser?.close();if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}if(dir)fs.rmSync(dir,{recursive:true,force:true});});

test('clean fixture has no blockers',async()=>{
 const r=await dom(clean); for(const k of ['tap','clip','contrast','axis','edge','gap','lead','rhythm','a11y'])assert.deepEqual(r[k],[],k);assert.equal(r.hscroll,false);
});
test('injecting overflow, number clipping and tiny/unnamed controls produces defects',async()=>{
 const r=await dom(modified('<div style="width:900px">Szeroki</div><div style="width:20px;overflow:hidden;white-space:nowrap">12345,67</div><button style="min-width:0;min-height:0;width:12px;height:12px;padding:0"></button>'));
 assert.ok(r.hscroll);assert.ok(r.tap.length);assert.ok(r.clip.length);assert.ok(r.a11y.length);
});
test('18px normal text is not large text, opacity and alpha do not bypass contrast',async()=>{
 const r=await dom(modified('<p style="font-size:18px;color:#888">Normalny tekst</p><p style="opacity:.4">Przezroczysty</p><p style="color:rgba(0,0,0,.4)">Alfa</p>'));
 assert.equal(r.contrast.length,3,JSON.stringify(r.contrast));
});
test('opacity-zero ancestor and closed details do not create ghost defects',async()=>{
 const r=await dom(modified('<div style="opacity:0"><button style="width:10px;height:10px;min-width:0;min-height:0;padding:0;font-size:99px">Niewidoczny</button></div><details><summary style="min-height:44px">Więcej</summary><p style="font-size:77px">Ukryty</p></details>'));
 assert.deepEqual(r.font,{});assert.deepEqual(r.tap,[]);
});
test('unsupported contrast backgrounds are reported for review, not invented',async()=>{
 const r=await dom(modified('<p style="background:linear-gradient(black,white)">Gradient</p>'));
 assert.ok(r.warn.some(x=>x.includes('kontrast wymaga')));
});
test('real CLI captures a stable matrix and compares an explicitly approved synthetic baseline',async()=>{
 const initial=await cli('initial',origin+'/clean',['--widths','390,768','--themes','light,dark']);
 assert.equal(initial.code,0,initial.stderr+JSON.stringify(initial.report));assert.equal(initial.report.runs.length,4);
 assert.equal(initial.report.summary.visual,'not_checked');
 for(const r of initial.report.runs){assert.ok(fs.existsSync(path.join(initial.out,r.shot)));assert.equal(r.shotSha256.length,64);}
 const baseline=path.join(dir,'approved');
 const approval=await exec(approve,['--from',path.join(initial.out,'audit.json'),'--out',baseline,'--approved-by','SYNTHETIC TEST','--note','Automated fixture, no product approval']);
 assert.equal(approval.code,0,approval.stderr);
 const matched=await cli('matched',origin+'/clean',['--baseline',baseline,'--widths','390,768','--themes','light,dark']);
 assert.equal(matched.code,0,matched.stderr+JSON.stringify(matched.report));assert.equal(matched.report.summary.visual,'passed');
 // A visual-only regression: valid geometry, changed marker color.
 const changed=path.join(dir,'changed.html');fs.writeFileSync(changed,clean.replace('#17643d','#a62222'));
 const mismatch=await cli('changed',changed,['--baseline',baseline,'--widths','390,768','--themes','light,dark']);
 assert.equal(mismatch.code,1,mismatch.stderr+JSON.stringify(mismatch.report));assert.equal(mismatch.report.summary.blockers,0);
 assert.equal(mismatch.report.summary.visual,'failed');assert.ok(mismatch.report.runs[0].visual.differentPixels>0);assert.ok(mismatch.report.runs[0].diff);
 const subset=await cli('subset',origin+'/clean',['--baseline',baseline]);assert.equal(subset.code,2);
 const relaxed=await cli('relaxed',origin+'/clean',['--baseline',baseline,'--widths','390,768','--themes','light,dark','--pixel-threshold','255']);assert.equal(relaxed.code,2);
 const repeatedApproval=await exec(approve,['--from',path.join(initial.out,'audit.json'),'--out',baseline,'--approved-by','TEST','--note','test']);
 assert.equal(repeatedApproval.code,2);
 const missing=await cli('no-reference',origin+'/clean',['--baseline',baseline,'--widths','1024']);
 assert.equal(missing.code,2);assert.equal(missing.report.summary.status,'incomplete');
});
test('HTTP errors, page exceptions and missing images cannot pass',async()=>{
 for(const [name,target] of [['http','/missing'],['js','/badjs'],['image','/image']]){
  const r=await cli(name,origin+target,['--no-shots']);assert.equal(r.code,1,r.stderr+JSON.stringify(r.report));assert.ok(r.report.summary.blockers>0);
 }
});
test('redirect, blank page, iframe and navigation timeout leave an incomplete JSON report',async()=>{
 for(const [name,target] of [['redirect','/redirect'],['blank','/blank'],['frame','/frame'],['timeout','/stall']]){
  const r=await cli(name,origin+target,['--no-shots','--goto-timeout','800']);assert.equal(r.code,2,r.stderr+JSON.stringify(r.report));assert.equal(r.report.summary.complete,false);
 }
});
test('own same-origin frame is measured together with the document',async()=>{
 const r=await cli('own-frame',origin+'/own-frame',['--no-shots','--goto-timeout','1500']);
 assert.ok(!JSON.stringify(r.report.errors||[]).includes('iframe'),JSON.stringify(r.report.errors));
 assert.equal(r.report.runs[0].frames,1);assert.equal(r.report.runs[0].status,'complete');assert.ok(r.report.runs[0].fontOffLadder.some(x=>x.startsWith("19px")),JSON.stringify(r.report.runs[0]));
});
test('sandboxed frame with the application URL has an opaque origin and stays unmeasured',async()=>{
 const r=await cli('sandboxed-frame',origin+'/sandboxed-frame',['--no-shots','--goto-timeout','1500']);
 assert.equal(r.code,2,r.stderr);assert.ok(JSON.stringify(r.report).includes('iframe wymaga'),JSON.stringify(r.report.errors));
});
test('429 burdens the screen unless the owner declared that exact path as rate limited',async()=>{
 const plain=await cli('limited',origin+'/limited',['--no-shots','--goto-timeout','1500']);
 assert.equal(plain.code,1,plain.stderr+JSON.stringify(plain.report.summary));assert.ok(plain.report.summary.blockers>0);
 const declared=await cli('limited-declared',origin+'/limited',['--no-shots','--goto-timeout','1500','--throttled-paths','/api/limited']);
 assert.equal(declared.code,0,declared.stderr+JSON.stringify(declared.report.runs[0]));assert.ok(declared.report.runs[0].warn.some(x=>x.includes('429')));
});
test('a modal open on arrival is closed before the screen is measured; only an unclosable one obscures it',async()=>{
 for(const [target,how] of [['/modal-esc','Escape'],['/modal','przycisk „Zaczynamy”']]){
  const r=await cli('m'+target.length,origin+target,['--no-shots','--goto-timeout','1500']);
  assert.equal(r.code,0,r.stderr+JSON.stringify(r.report.runs[0]));assert.equal(r.report.runs[0].arrival.closed,how);
  assert.ok(r.report.runs[0].warn.some(x=>x.includes('zamknięte przed pomiarem')));
 }
 // okno bez trybu modalnego, ale zajmujące środek ekranu, też jest zamykane przed pomiarem
 const plain=await cli('window-plain',origin+'/window-plain',['--no-shots','--goto-timeout','1500','--widths','1280']);
 assert.equal(plain.report.runs[0].arrival?.closed,'przycisk „Zaczynamy”',plain.stderr+JSON.stringify(plain.report.runs[0]));
 const defect=await cli('modal-defect',origin+'/modal-defect',['--no-shots','--goto-timeout','1500','--widths','1280']);
 assert.equal(defect.code,1,defect.stderr+JSON.stringify(defect.report.runs[0]));assert.ok(defect.report.runs[0].arrival.blockers>0&&defect.report.runs[0].blockers>=defect.report.runs[0].arrival.blockers,JSON.stringify(defect.report.runs[0].arrival));
 const font=await cli('modal-font',origin+'/modal-font',['--no-shots','--goto-timeout','1500','--widths','1280']);
 assert.equal(font.code,1,font.stderr+JSON.stringify(font.report.runs[0]));assert.ok(font.report.runs[0].arrival.findings.some(x=>x.startsWith('font: 19px')),JSON.stringify(font.report.runs[0].arrival));
 const r=await cli('modal-stuck',origin+'/modal-stuck',['--no-shots','--goto-timeout','1500','--workers','1','--sweep','280-1600:40']);
 assert.equal(r.code,2,r.stderr);assert.equal(r.report.runs.filter(Boolean).length,1);assert.equal(r.report.runs[0].obscured,'Blokada');
 assert.ok(r.report.errors.some(x=>x.includes('Ekran zasłonięty oknem')),JSON.stringify(r.report.errors));
});
test('a consent gate without a close button is passed by confirming, as a person would',async()=>{
 const r=await cli('age-gate',origin+'/age-gate',['--no-shots','--goto-timeout','1500','--widths','1280','--themes','light']);
 assert.equal(r.report.runs[0].arrival?.closed,'potwierdzenie „Tak, mam 18 lat”',r.stderr+JSON.stringify(r.report.runs[0]));assert.ok(!r.report.runs[0].obscured);
});
test('the first clickable row of a list leads to the detail screen and records its address',async()=>{
 const r=await cli('rows',origin+'/rows',['--no-shots','--goto-timeout','1500','--widths','1280','--themes','light','--states','20']);
 const rows=r.report.runs[0].states.filter(x=>x.trigger.startsWith('wiersz listy'));
 assert.equal(rows.length,1,r.stderr+JSON.stringify(r.report.runs[0].states));assert.equal(rows[0].kind,'navigation');assert.equal(rows[0].target,'/row/5');
});
test('states opened by a click are measured, writes are cut off',async()=>{
 const r=await cli('states',origin+'/states',['--no-shots','--goto-timeout','1500','--widths','1280','--themes','light','--states','20']);
 const run=r.report.runs[0];assert.ok(run.states?.length>=2,r.stderr+JSON.stringify(run));
 const panel=run.states.find(x=>x.trigger==='Panel boczny'),save=run.states.find(x=>x.trigger==='Zapisz szkic');
 assert.equal(panel.kind,'dialog',JSON.stringify(run.states));assert.ok(panel.blockers>0&&panel.findings.some(x=>x.startsWith('tap')),JSON.stringify(panel));
 assert.ok(run.blockedWrites>=1);
 const shell=run.states.find(x=>x.trigger==='Konto');assert.equal(shell.kind,'menu',JSON.stringify(run.states));assert.equal(shell.shell,true);
 assert.equal(run.statesFound,10);
 // okno otwierane z okna: wyzwalacz znaleziony w otwartym panelu jest klikany po ponownym otwarciu panelu
 const inner=run.states.find(x=>x.trigger==='Panel boczny › Potwierdź usunięcie');assert.ok(inner&&inner.nested&&inner.kind==='dialog',JSON.stringify(run.states));
 assert.ok(!run.states.some(x=>x.trigger==='Panel boczny › Zamknij'));
 const html=fs.readFileSync(path.join(r.out,'report.html'),'utf8');assert.ok(html.includes('Stany po kliknięciu')&&html.includes('Panel boczny'));
 assert.equal(save.kind,'write-cut');assert.equal(run.states.find(x=>x.trigger==='Tylko moje').kind,'toggled');assert.equal(run.states.find(x=>x.trigger==='Wgraj plik').kind,'file-chooser');assert.equal(run.statesSkipped,0);
 // akcje wykonywane żądaniem GET (także zakodowanym) i wylogowanie nawigacją nigdy nie docierają do serwera
 assert.deepEqual(reached,[]);assert.ok(run.blockedWrites>=5,String(run.blockedWrites));
 // błąd po kliknięciu jest usterką, choć nic się nie otworzyło
 const broken=run.states.find(x=>x.trigger==='Zepsuty');assert.equal(broken.kind,'no-change');assert.ok(broken.blockers>0,JSON.stringify(broken));
assert.ok(!run.states.some(x=>/Wyloguj/.test(x.trigger)));
 // wyzwalacz powłoki obejrzany raz: drugi ekran tego samego przebiegu już go nie klika
 const seen=path.join(r.out,'seen.json');
 await cli('states-a',origin+'/states',['--no-shots','--goto-timeout','1500','--widths','1280','--themes','light','--states','20','--states-seen',seen]);
 const again=await cli('states-b',origin+'/states',['--no-shots','--goto-timeout','1500','--widths','1280','--themes','light','--states','20','--states-seen',seen]);
 assert.ok(!again.report.runs[0].states.some(x=>x.trigger==='Konto'),JSON.stringify(again.report.runs[0].states));
});
test('content further down a scrolling container is not reported as a clipped frame',async()=>{
 const r=await cli('scrolled',origin+'/scrolled',['--no-shots','--goto-timeout','1500','--widths','1280']);
 assert.ok(!JSON.stringify(r.report.runs[0].clip).includes('ramka ucięta'),JSON.stringify(r.report.runs[0].clip));
});
test('a route that redirects stops after the first measurements instead of repeating the whole sweep',async()=>{
 const r=await cli('redirect-sweep',origin+'/redirect',['--no-shots','--goto-timeout','800','--workers','1','--sweep','280-1600:40']);
 assert.equal(r.code,2,r.stderr);assert.equal(r.report.summary.complete,false);
 assert.ok(r.report.planned>30,String(r.report.planned));assert.equal(r.report.runs.filter(Boolean).length,1);
 assert.ok(r.report.errors.some(x=>x.includes('pominięto pozostałe pomiary')),JSON.stringify(r.report.errors));
});
test('continuous mutation and missing readiness selector cannot pass',async()=>{
 for(const [name,target,opts] of [['mutating','/unstable',[]],['not-ready','/clean',['--ready-selector','#missing']]]){
  const r=await cli(name,origin+target,['--no-shots','--goto-timeout','500','--settle','100',...opts]);assert.equal(r.code,2,JSON.stringify(r.report));
 }
});
test('both theme sweeps run; no-shots never masquerades as visual approval',async()=>{
 const r=await cli('sweep',origin+'/clean',['--no-shots','--themes','light,dark','--widths','390','--sweep','280-400:40']);
 assert.equal(r.code,0,r.stderr+JSON.stringify(r.report));assert.equal(r.report.runs.length,10);assert.equal(r.report.summary.visual,'not_checked');
 assert.ok(r.report.runs.every(x=>x.shot===null));
});

test('explicit dynamic mask stabilizes evidence and is recorded',async()=>{
 const r=await cli('masked',origin+'/masked',['--mask','.clock','--goto-timeout','1500']);
 assert.equal(r.code,0,r.stderr+JSON.stringify(r.report));assert.equal(r.report.contract.mask,'.clock');
 const bad=await cli('bad-mask',origin+'/clean',['--mask','.absent','--goto-timeout','1500']);
 assert.equal(bad.code,2);assert.ok(bad.report.runs[0].errors.some(x=>x.includes('Maska')));
});
test('output ownership and interruption preserve an incomplete report without a dangling lock',async()=>{
 const out=path.join(dir,'interrupt');
 const child=spawn(process.execPath,[script,origin+'/stall','--out',out,'--widths','390','--themes','light','--goto-timeout','5000'],{env:process.env,stdio:'ignore'});
 const completion=new Promise(r=>child.once('exit',r));
 const deadline=Date.now()+5000;
 while(!fs.existsSync(path.join(out,'audit.json')) && Date.now()<deadline)await new Promise(r=>setTimeout(r,20));
 assert.ok(fs.existsSync(path.join(out,'audit.json')));
 const second=await exec(script,[origin+'/clean','--out',out]);assert.equal(second.code,2);assert.ok(second.stderr.includes('EEXIST'));
 child.kill('SIGTERM');assert.equal(await completion,2);
 const report=JSON.parse(fs.readFileSync(path.join(out,'audit.json'),'utf8'));
 assert.equal(report.summary.status,'incomplete');assert.ok(report.errors.some(x=>x.includes('SIGTERM')));
 assert.equal(fs.existsSync(path.join(out,'.helix-lock')),false);
});

test('pending SPA data is awaited, client-side login redirect is rejected, aborted fetch is a warning',async()=>{
 const delayed=await cli('delayed',origin+'/slow',['--no-shots']);
 assert.equal(delayed.code,1,delayed.stderr+JSON.stringify(delayed.report));assert.ok(delayed.report.runs[0].fontOffLadder.some(x=>x.startsWith('77px')));
 const redirected=await cli('client-redirect',origin+'/client-redirect',['--no-shots']);
 assert.equal(redirected.code,2,JSON.stringify(redirected.report));assert.ok(redirected.report.runs[0].errors.some(x=>x.includes('Przekierowanie')));
 const aborted=await cli('aborted',origin+'/aborted',['--no-shots']);
 assert.equal(aborted.code,0,aborted.stderr+JSON.stringify(aborted.report));assert.ok(aborted.report.runs[0].warn.some(x=>x.includes('Anulowane')));
});
test('scrolling SPA content below the viewport is captured and a hidden regression is caught',async()=>{
 const html=clean.replace('</style>','html,body{height:100%;overflow:hidden}body{margin:0}main{height:900px;overflow:auto} .spacer{height:1100px}</style>').replace('<body>','<body><main>').replace('</body>','<div class="spacer"></div><div class="marker below"></div></main></body>');
 const source=path.join(dir,'scroll.html');fs.writeFileSync(source,html);
 const initial=await cli('scroll',source);assert.equal(initial.code,0,initial.stderr+JSON.stringify(initial.report));
 assert.ok(initial.report.runs[0].captures.length>0);
 const base=path.join(dir,'scroll-base');
 assert.equal((await exec(approve,['--from',path.join(initial.out,'audit.json'),'--out',base,'--approved-by','SYNTHETIC TEST','--note','scroll fixture only'])).code,0);
 const unchanged=await cli('scroll-match',source,['--baseline',base]);assert.equal(unchanged.code,0,unchanged.stderr+JSON.stringify(unchanged.report));
 fs.writeFileSync(source,html.replace('class="marker below"','class="marker below" style="background:#a62222"'));
 const changed=await cli('scroll-diff',source,['--baseline',base]);assert.equal(changed.code,1,changed.stderr+JSON.stringify(changed.report));
 assert.ok(changed.report.runs[0].captures.some(c=>c.visual.status==='mismatch'));
});

test('ignored subtrees are explicitly disclosed in the evidence',async()=>{
 const r=await dom(modified('<div data-helix-ignore><button style="font-size:99px">Excluded fixture</button></div>'));
 assert.deepEqual(r.font,{});assert.ok(r.warn.some(x=>x.includes('Pominięto 1 elementów')));
});


test('typography, field padding, gap ladder and heading axis have concrete geometry failures',async()=>{
 const html=modified('<p style="font-size:77px">Large fixture</p><input aria-label="Field" style="border:1px solid black;padding:0;width:160px;height:44px"><div style="display:flex;flex-direction:column;gap:20px"><div style="background:#eee;height:40px">First</div><div style="background:#eee;height:40px">Second</div></div><div style="display:flex;align-items:flex-start"><h2 style="font-size:22px;line-height:22px;margin:0">Heading</h2><button>Action</button></div>');
 const r=await dom(html);assert.ok(r.font['77']);assert.ok(r.edge.length);assert.ok(r.gap.length);assert.ok(r.axis.length);
});
test('list rhythm, leading axes, numeric wrapping and overlapping text are measured',async()=>{
 const cards=[0,24,48].map(n=>`<section style="border-radius:12px;width:330px"><div style="min-height:36px;padding-left:${n}px">Alpha</div><div style="min-height:36px;padding-left:${n}px">Beta</div></section>`).join('');
 const lead='<section style="border-radius:12px;width:330px">'+[1,2].map(()=>'<div style="display:flex;min-height:64px"><span style="width:32px;height:20px;margin-top:30px">A</span><div style="flex:1">Text</div></div>').join('')+'</section>';
 const r=await dom(modified(cards+lead+'<div style="width:10px;overflow-wrap:anywhere">123456789</div><div style="position:relative;height:40px"><span style="position:absolute;left:0;top:0">Overlap alpha</span><span style="position:absolute;left:0;top:0">Overlap beta</span></div>'));
 assert.ok(r.rhythm.length);assert.ok(r.lead.length);assert.ok(r.clip.some(x=>x.includes('liczba złamana')));assert.ok(r.clip.some(x=>x.includes('tekst na tekście')));
});
test('a bare loading caption is waited out and a passing notification is recorded with its geometry instead of destabilising the run',async()=>{
 const source=path.join(dir,'loading-notice.html');
 fs.writeFileSync(source,modified(`<p>Etykieta <b>Ładowanie...</b> oznacza pobieranie danych</p><div id="slot"><p>Ładowanie...</p></div><script>
  setTimeout(()=>{const t=document.createElement('div');t.setAttribute('data-sonner-toast','');t.style.cssText='width:120px;overflow:hidden;white-space:nowrap';t.innerHTML='Błąd pobierania <button aria-label="Zamknij" style="width:20px;height:20px;min-width:0;min-height:0;padding:0;border:0"></button>';document.body.append(t);setTimeout(()=>t.remove(),900);},200);
  setTimeout(()=>{document.getElementById('slot').innerHTML='<p style="font-size:77px">Dane</p>';},700);
 </script>`));
 const started=Date.now(),r=await cli('loading-notice',source),run=r.report.runs[0];
 assert.deepEqual(run.errors,[],JSON.stringify(run.errors));
 assert.ok(run.fontOffLadder.some(x=>x.startsWith('77px')),'ekran zmierzony po danych');
 assert.ok(run.warn.some(x=>x.includes('„Błąd pobierania”')&&x.includes('Zamknij 20×20')),JSON.stringify(run.warn));
 // ucięcie na samym dymku jest widoczne; późniejsza zmiana ekranu nie zgłasza ukrytego dymka drugi raz
 assert.equal(run.warn.filter(x=>x.startsWith('Powiadomienie')).length,1);assert.ok(run.warn.some(x=>x.includes('tekst ucięty')),JSON.stringify(run.warn));
 assert.ok(Date.now()-started<8000,'objaśnienie ze słowem „Ładowanie...” w zdaniu nie jest wskaźnikiem');
});
