/* Disposable local runtime only. Journals contain sanitized URLs and no credentials. */
const fs=require('fs'), path=require('path'), {createRequire}=require('module');
const {createGate,ResourcePaused}=require('./resources.cjs');
const [url,output,mode,routesJSON,project]=process.argv.slice(2);
const requires=[createRequire(path.join(project,'package.json')),require];
if(process.env.HELIX_RUNTIME_NODE_MODULES) requires.unshift(createRequire(path.join(process.env.HELIX_RUNTIME_NODE_MODULES,'../package.json')));
function resolve(name){for(const req of requires){try{return req.resolve(name);}catch{}}throw Error('offline dependency unavailable: '+name);}
const budgets=JSON.parse(process.env.HELIX_RUNTIME_BROWSER_BUDGETS||'{}');
const clean=value=>{try{const u=new URL(value);return u.origin+u.pathname;}catch{return '';}};
const journal=record=>fs.appendFileSync(output+'.jsonl',JSON.stringify(record)+'\n');
function bounded(work,ms){let timer;return Promise.race([work,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('route operation timeout')),ms);})]).finally(()=>clearTimeout(timer));}
(async()=>{
 const {chromium}=require(resolve('playwright'));
 const gate=createGate({path:process.env.HELIX_RESOURCE_FILE,requestedJobs:budgets.workers||Math.max(1,Math.min(4,Math.floor(require('os').cpus().length/2)))});
 let browser,auth=null,identityForm=null,identityPolicy=null,webauthnResult=null,resourcePause=null;
 const origin=new URL(url).origin, issuer=process.env.HELIX_RUNTIME_OIDC_ISSUER;
 const tlsKeys=process.env.HELIX_RUNTIME_TLS_SPKI_LIST||process.env.HELIX_RUNTIME_OIDC_SPKI;
 if(tlsKeys&&!tlsKeys.split(',').every(key=>/^[A-Za-z0-9+/]{43}=$/.test(key)))throw Error('invalid owned TLS key list');
 const routes=JSON.parse(routesJSON), results=[], requests=[];
 // Trasy z parametrem (np. /leads/[id]): konkretny adres bierzemy z odnośników na obejrzanych ekranach, po jednym na wzorzec.
 const patterns=JSON.parse(process.env.HELIX_RUNTIME_ROUTE_PATTERNS||'[]').map(pattern=>({pattern,test:new RegExp('^'+pattern.split('/').map(part=>/^\[.+\]$/.test(part)?'[^/]+':part.replace(/[.*+?^${}()|\\]/g,'\\$&')).join('/')+'$')}));
 const found=new Map();
 // Sesja roli wskazanej przez właściciela (runtime.keycloak.parts.<część>.screen_role). Bez deklaracji obu zmiennych nie ma i trasy idą bez sesji.
 const screenRole=process.env.HELIX_RUNTIME_SCREEN_ROLE,screenFile=process.env.HELIX_RUNTIME_SCREEN_SESSION;let screenState=null;
 // e2e samo tworzy sesję roli z Keycloaka; gdy roli nie ma, a sesję dał scenariusz logowania właściciela, e2e też ją czyta
 if(screenFile&&(mode!=='e2e'||!screenRole)&&fs.existsSync(screenFile))screenState=JSON.parse(fs.readFileSync(screenFile,'utf8'));
// Syntetyczne odpowiedzi funkcji serwerowych (helix_function_stubs.py, projekt B): plik z HELIX_FUNCTION_STUBS.
// Funkcje nie startują w kopii (wołają systemy zewnętrzne); przeglądarka odpowiada na /functions/v1/<nazwa> odpowiedzią napisaną z kodu.
let FUNCTION_STUBS;
function functionStubs() {
  if (FUNCTION_STUBS === undefined) {
    try { FUNCTION_STUBS = process.env.HELIX_FUNCTION_STUBS ? JSON.parse(fs.readFileSync(process.env.HELIX_FUNCTION_STUBS, 'utf8')) : null; }
    catch (e) { FUNCTION_STUBS = null; }
  }
  return FUNCTION_STUBS;
}
async function routeFunctionStubs(ctx) {
  const stubs = functionStubs(); if (!stubs) return;
  const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS' };
  await ctx.route('**/functions/v1/**', (route) => {
    const name = (new URL(route.request().url()).pathname.split('/functions/v1/')[1] || '').split('/')[0];
    if (!Object.prototype.hasOwnProperty.call(stubs, name)) return route.fallback();
    if (route.request().method() === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
    return route.fulfill({ status: 200, headers: { ...cors, 'content-type': 'application/json' }, body: JSON.stringify(stubs[name]) });
  });
}
 async function context(){const ctx=await browser.newContext({serviceWorkers:'block',...(screenState?{storageState:screenState}:{})});try{await ctx.route('**/*',r=>{const target=new URL(r.request().url());return target.origin===origin||(issuer&&target.origin===new URL(issuer).origin)?r.continue():r.abort();});await routeFunctionStubs(ctx);return ctx;}catch(error){await ctx.close();throw error;}}
 try{
  await gate.run(async()=>{browser=await chromium.launch({headless:true,...(tlsKeys?{args:['--ignore-certificate-errors-spki-list='+tlsKeys]}:{}),...(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{})});});
  const identityMode=process.env.HELIX_RUNTIME_IDENTITY_MODE;
  if(mode==='e2e'&&identityMode==='keycloak-form'&&process.env.HELIX_RUNTIME_IDENTITY_INPUT){
   const {readPrivateLoginInput,runLoginSuite}=require('./runtime-keycloak-login.cjs');
   const input=readPrivateLoginInput(process.env.HELIX_RUNTIME_IDENTITY_INPUT,process.env.HELIX_RUNTIME_PRIVATE_ROOT);
   if(new URL(input.app_origin).origin!==origin||input.issuer!==issuer)throw Error('identity runtime binding mismatch');
   let policyHooks,policyInput,webauthnHooks;
   if(process.env.HELIX_RUNTIME_POLICY_INPUT){
    const {readPrivatePolicyInput,createPolicyHooks}=require('./runtime-identity-policy.cjs');
    policyInput=readPrivatePolicyInput(process.env.HELIX_RUNTIME_POLICY_INPUT,process.env.HELIX_RUNTIME_PRIVATE_ROOT);
    if(JSON.stringify(policyInput.form_input)!==JSON.stringify(input))throw Error('identity policy form binding mismatch');
    policyHooks=createPolicyHooks({input:policyInput,emitSuite:suite=>{identityPolicy=suite;journal(suite);}});
   }
   if(process.env.HELIX_RUNTIME_WEBAUTHN_INPUT){
    const {readPrivateWebAuthnInput,createWebAuthnHooks}=require('./runtime-webauthn.cjs');
    const privateInput=readPrivateWebAuthnInput(process.env.HELIX_RUNTIME_WEBAUTHN_INPUT,process.env.HELIX_RUNTIME_PRIVATE_ROOT);
    if(!policyInput||JSON.stringify(privateInput.policy_input)!==JSON.stringify(policyInput))throw Error('WebAuthn policy binding mismatch');
    webauthnHooks=createWebAuthnHooks({input:privateInput,policyHooks,emitSuite:suite=>{webauthnResult=suite;journal(suite);}});
   }
   // Sesja każdej roli (do sprawdzenia, co która rola widzi) trafia do prywatnego katalogu przebiegu; sesja roli ekranów jak dotąd do własnego pliku.
   const roleDir=process.env.HELIX_RUNTIME_ROLE_SESSIONS;
   const sessionHook=(screenRole&&screenFile)||roleDir?async({context,identity})=>{
    if(identity.email_verified!==true||identity.app_roles.length!==1)return;
    const role=identity.app_roles[0];let state=null;
    if(roleDir&&/^[A-Za-z0-9_.-]{1,128}$/.test(role)){state=await context.storageState();try{fs.writeFileSync(require('path').join(roleDir,'role-'+role+'.json'),JSON.stringify(state),{mode:0o600,flag:'wx'});}catch{}}
    if(screenState||!screenFile||role!==screenRole)return;
    screenState=state||await context.storageState();fs.writeFileSync(screenFile,JSON.stringify(screenState),{mode:0o600,flag:'wx'});
   }:undefined;
   identityForm=await runLoginSuite({browser,input,gate,policyHooks,webauthnHooks,sessionHook,emit:journal,emitSuite:journal});
   if(policyHooks)identityPolicy=policyHooks.snapshot();
   if(webauthnHooks)webauthnResult=webauthnHooks.snapshot();
   journal(identityForm);
  }
  // Keycloak form observations do not establish an application session. Keep
  // public-route contexts separate and never invoke the legacy stub flow.
  auth=mode==='e2e'&&issuer&&!['keycloak-readiness','keycloak-form'].includes(identityMode)?{
   type:'auth-flow',scope:'legacy_oidc_observation',status:'BLOCKED',reason_code:'NO_EXPLICIT_IDENTITY_POLICY',
   session_coverage:'NOT_RUN',authorization_coverage:'NOT_RUN',steps:[],break_at:'login',cleanup:'not_needed'}:null;
  if(auth){
   await gate.acquire();let ctx;
   try{
    journal(auth);ctx=await context();auth.cleanup='unknown';const page=await ctx.newPage();
    page.on('response',r=>{if(r.request().isNavigationRequest()){const u=new URL(r.url());const step=u.origin===origin?(u.pathname.includes('callback')?'callback':'app'):(u.searchParams.get('response_type')==='code'?'authorize':'stub');auth.steps.push({step,url:clean(r.url()),code:r.status()});auth.break_at=step;journal({...auth});}});
    auth.steps.push({step:'login',url:clean(new URL('/login',url).href),code:null});
    await page.goto(new URL('/login',url).href,{waitUntil:'domcontentloaded',timeout:budgets.navigation_ms||15000});
    await bounded(page.waitForURL(u=>u.origin===origin&&!/login|callback/.test(u.pathname),{timeout:budgets.navigation_ms||15000}),budgets.navigation_ms||15000);
    if(new URL(page.url()).origin!==origin)throw Error('legacy return origin differs');
    auth.break_at='identity-policy';
   }catch{auth.observation_error='LEGACY_NAVIGATION_INCOMPLETE';}
   finally{try{if(ctx){await ctx.close();auth.cleanup='closed';}}finally{gate.release();journal(auth);}}
  }
  let cursor=0;
  async function worker(){while(cursor<routes.length){await gate.acquire();if(cursor>=routes.length){gate.release();return;}const route=routes[cursor++],start=Date.now();const result={type:'route',route,status:'FAIL',code:null,seconds:0,errors:[],violations:[],reachable:false,...(found.has(route)?{pattern:found.get(route)}:{})};let ctx;
   try{
    const target=new URL(route,url);if(target.origin!==origin) throw Error('nonlocal route');
    ctx=await context();const page=await ctx.newPage();
    page.on('pageerror',()=>result.errors.push('page error'));
    // Adres kończący się wartością zastępczą Helixa (np. obraz o nazwie 'synthetic-item') daje 404 z danych syntetycznych, nie z błędu aplikacji.
    const synthetic=address=>{try{return /\/(synthetic-item|bardzo długa nazwa pozycji testowej)[^/]*$/.test(decodeURIComponent(new URL(address).pathname));}catch{return false;}};
    // Pomijany jest wyłącznie komunikat przeglądarki o nieudanym wczytaniu takiego zasobu; każdy inny błąd konsoli zostaje.
    // Zasób z obcego adresu ucina sam Helix (aplikacja nie ma wyjścia do sieci): to nie błąd aplikacji, tylko zapis, z jakich hostów ekran korzysta.
    const outside=u=>{try{const o=new URL(u).origin;return o!==origin&&!(issuer&&o===new URL(issuer).origin);}catch{return false;}};
    page.on('console',m=>{if(m.type()!=='error')return;const from=m.location().url||'';
     if(/^Failed to load resource/.test(m.text())&&outside(from)){const host=new URL(from).host;result.external_hosts=result.external_hosts||[];if(!result.external_hosts.includes(host)&&result.external_hosts.length<20)result.external_hosts.push(host);return;}
     if(!(/^Failed to load resource/.test(m.text())&&synthetic(from))) result.errors.push('browser console error');});
    page.on('response',r=>{const item={method:r.request().method(),url:clean(r.url()),status:r.status(),source:new URL(r.url()).origin===origin?'app':'stub'};requests.push(item);if(item.status>=400&&!(item.status===404&&synthetic(r.url()))) result.errors.push('HTTP '+item.status+' '+item.url);});
    const response=await page.goto(target.href,{waitUntil:'domcontentloaded',timeout:budgets.navigation_ms||15000});
    // Ekran bywa dociągany po wczytaniu dokumentu (dane, ramka z treścią): bez tej chwili axe i odnośniki widziałyby pustą powłokę.
    await Promise.resolve().then(()=>page.waitForLoadState('networkidle',{timeout:budgets.settle_ms||4000})).catch(()=>{});
    result.code=response?response.status():null;
    result.reachable=!!response&&response.status()>=200&&response.status()<300&&new URL(page.url()).origin===origin&&new URL(page.url()).pathname===target.pathname;
    // Trasa, która z sesją odsyła na inny ekran tej samej aplikacji, dostaje cel odesłania (identyfikatory w ścieżce zamaskowane).
    if(!result.reachable){const end=new URL(page.url());
     const moved=response&&response.status()>=200&&response.status()<300&&end.origin===origin&&end.pathname!==target.pathname;
     // Odesłanie jest oczekiwane tylko z sesją ekranów i tylko na inny oglądany ekran (nie logowanie, nie strona błędu); każde inne zostaje usterką.
     if(moved&&screenState&&routes.includes(end.pathname)&&!/log(in|owanie)|sign-?in|auth|error|b[lł][aą]d|denied|forbidden|unauthori|odmow|brak-?dost|not-?found|(^|\/)(40[134]|50\d)(\/|$)/i.test(end.pathname))result.redirected_to=end.pathname;
     else result.errors.push(moved?'route redirected to '+end.pathname.replace(/\/(\d+|[0-9a-f-]{20,})(?=\/|$)/gi,'/:id'):'route unavailable or redirected');}
    if(result.reachable&&patterns.length>found.size){
     const known=new Set(found.values());
     for(const frame of page.frames()){let links=[];try{links=await frame.evaluate(()=>[...document.querySelectorAll('a[href]')].slice(0,400).map(a=>a.href));}catch{}
      for(const href of links){let link;try{link=new URL(href);}catch{continue;}
       // Odnośniki, których samo otwarcie coś zmienia (wylogowanie, wypisanie, usunięcie), nie są odwiedzane.
       let plain=link.pathname;try{plain=decodeURIComponent(link.pathname);}catch{continue;}
       if(link.origin!==origin||routes.includes(link.pathname)||/log-?out|wylog|sign-?out|unsubscribe|wypisz|delete|usun|remove|destroy|revoke|cancel|anuluj|reset|archiv|archiw/i.test(plain))continue;
       const hit=patterns.find(item=>!known.has(item.pattern)&&item.test.test(link.pathname));
       if(hit){known.add(hit.pattern);found.set(link.pathname,hit.pattern);routes.push(link.pathname);}}}
    }
    if(mode==='a11y'&&!result.redirected_to){
     await bounded((async()=>{for(const frame of page.frames()){try{await frame.addScriptTag({path:resolve('axe-core/axe.min.js')});}catch(error){if(frame===page.mainFrame())throw error;}}const data=await page.evaluate(()=>axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}}));result.violations=data.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length}));})(),budgets.axe_ms||10000);
    }
    result.status=result.errors.length||result.violations.length?'FAIL':result.redirected_to?'REDIRECTED':'PASS';
   }catch{result.errors.push('navigation or axe failed/timeout');}
   finally{result.seconds=(Date.now()-start)/1000;results.push(result);journal(result);try{if(ctx) await ctx.close();}finally{gate.release();}}
  }}
  // Drain active routes before closing their browser, even if another admission pauses.
  const completed=await Promise.allSettled(Array.from({length:budgets.workers||Math.max(1,Math.min(4,Math.floor(require('os').cpus().length/2)))},worker));
  const rejected=completed.find(result=>result.status==='rejected');
  if(rejected)throw rejected.reason;
  fs.writeFileSync(output,JSON.stringify({routes:results,requests,auth_flow:auth,identity_form:identityForm,identity_policy:identityPolicy,webauthn:webauthnResult,auth_coverage:auth?'NOT_RUN: legacy OIDC observations only; explicit identity policy unavailable':identityPolicy?'Explicit policy observations recorded separately; form phases remain form-only':identityForm?'FORM_PHASES_ONLY; application session and protected routes NOT_RUN':issuer&&process.env.HELIX_RUNTIME_IDENTITY_MODE==='keycloak-readiness'?'NOT_RUN: Keycloak login form not configured; protected routes not covered':'not configured; login not tested'}),{mode:0o600});
 }catch(error){
  if(!(error instanceof ResourcePaused))throw error;
  resourcePause={type:'resource-paused',status:'resource_paused',reason:error.message,decision:error.decision};journal(resourcePause);
  fs.writeFileSync(output,JSON.stringify({routes:results,requests,auth_flow:auth,identity_form:identityForm,identity_policy:identityPolicy,webauthn:webauthnResult,resource_paused:resourcePause}),{mode:0o600});
  process.exitCode=3;
 }finally{if(browser)await browser.close();}
})().catch(error=>{console.error('browser execution failed; partial results in journal: '+String(error&&error.message||error).split('\n')[0].slice(0,300));process.exitCode=2;});
