'use strict';
/* Synthetic form observation only. Importing this module performs no I/O. */
const fs = require('node:fs');
const path = require('node:path');
const {performance} = require('node:perf_hooks');
const LIMIT = 1024 * 1024;
class LoginError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new LoginError(code); };
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const text = (value, max = 500) => typeof value === 'string' && value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const exactFields = (value, fields) => object(value) && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/;
const clone = value => JSON.parse(JSON.stringify(value));
function localOrigin(value) {
  if (!text(value)) fail('INVALID_ORIGIN');
  let url; try { url = new URL(value); } catch { fail('INVALID_ORIGIN'); }
  const explicit = /^https:\/\/(localhost|127\.0\.0\.1):([0-9]+)$/.exec(value);
  if (!explicit || Number(explicit[2]) < 1 || Number(explicit[2]) > 65535 || String(Number(explicit[2])) !== explicit[2] ||
      url.origin !== 'https://' + explicit[1] + (explicit[2] === '443' ? '' : ':' + explicit[2])) fail('INVALID_ORIGIN');
  return url;
}
function localPath(value) {
  if (!text(value, 500) || !value.startsWith('/') || value.startsWith('//') || /[\\?#%*${}\s]/.test(value)) return false;
  return new URL(value, 'https://localhost:44100').pathname === value;
}
function validateLoginInput(value) {
  const fields = ['schema_version','binding','app_origin','issuer','authorization_endpoint','client_id',
    'callback_paths','login_path','pkce','identities','deadline_unix_ms','operation_timeout_ms'];
  if (!exactFields(value, fields) || value.schema_version !== 1) fail('INVALID_INPUT');
  const b = value.binding;
  if (!exactFields(b, ['run_id','integration_id','integration_plan_id','identity_plan_id','attempt_id','part']) ||
      Object.values(b).some(value => typeof value !== 'string') ||
      !text(b.run_id, 100) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/.test(b.run_id) ||
      !/^keycloak:[a-f0-9]{12}$/.test(b.integration_id) || !/^[a-f0-9]{64}$/.test(b.integration_plan_id) ||
      !/^[a-f0-9]{64}$/.test(b.identity_plan_id) || !/^login-[a-f0-9]{32}$/.test(b.attempt_id) ||
      !text(b.part) || b.part.startsWith('/') || /[\\:?%]/.test(b.part) ||
      b.part !== path.posix.normalize(b.part) || b.part.split('/').includes('..')) fail('INVALID_BINDING');
  const app = localOrigin(value.app_origin);
  if (!text(value.issuer, 500)) fail('INVALID_ISSUER');
  let issuer; try { issuer = new URL(value.issuer); } catch { fail('INVALID_ISSUER'); }
  const issuerOrigin = value.issuer.split('/realms/', 1)[0]; localOrigin(issuerOrigin);
  if (issuer.protocol !== 'https:' || issuer.hostname !== '127.0.0.1' ||
      issuer.username || issuer.password || issuer.search || issuer.hash ||
      !/^\/realms\/helix-[A-Za-z0-9_-]{8,80}$/.test(issuer.pathname) ||
      value.issuer !== issuerOrigin + issuer.pathname || (issuer.port || '443') === (app.port || '443') ||
      value.authorization_endpoint !== value.issuer + '/protocol/openid-connect/auth') fail('INVALID_ISSUER');
  if (!text(value.client_id, 128) || !ID.test(value.client_id) || !localPath(value.login_path) ||
      !Array.isArray(value.callback_paths) || !value.callback_paths.length ||
      value.callback_paths.some(p => !localPath(p)) || new Set(value.callback_paths).size !== value.callback_paths.length ||
      value.callback_paths.includes(value.login_path) || !['S256','disabled'].includes(value.pkce)) fail('INVALID_CLIENT');
  if (!Number.isSafeInteger(value.deadline_unix_ms) || value.deadline_unix_ms <= 0 ||
      !Number.isSafeInteger(value.operation_timeout_ms) || value.operation_timeout_ms < 1 || value.operation_timeout_ms > 60000) fail('INVALID_DEADLINE');
  if (!Array.isArray(value.identities) || !value.identities.length) fail('NO_POSITIVE_IDENTITIES');
  const ids = new Set(), passwords = new Set();
  for (const row of value.identities) {
    if (!exactFields(row, ['id','username','email_verified','app_roles','password']) ||
        !text(row.id, 17) || !/^role-[a-f0-9]{12}$/.test(row.id) || row.username !== 'helix-' + row.id || row.email_verified !== true ||
        !Array.isArray(row.app_roles) || row.app_roles.length !== 1 || !text(row.app_roles[0], 128) || !ID.test(row.app_roles[0]) ||
        !text(row.password, 512) || row.password.length < 16 || ids.has(row.id) || passwords.has(row.password)) fail('INVALID_POSITIVE_IDENTITY');
    ids.add(row.id); passwords.add(row.password);
  }
  return clone(value);
}
function readPrivateJSON(file, privateRoot) {
  if (!text(file, 4096) || !text(privateRoot, 4096) || !path.isAbsolute(file) || !path.isAbsolute(privateRoot) ||
      path.resolve(file) !== file || path.resolve(privateRoot) !== privateRoot) fail('INVALID_PRIVATE_PATH');
  const relative = path.relative(privateRoot, file);
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) fail('INVALID_PRIVATE_PATH');
  let current = path.parse(privateRoot).root;
  try {
    for (const chunk of privateRoot.slice(current.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, chunk);
      const stat = fs.lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail('UNSAFE_PRIVATE_PATH');
    }
    const rootStat = fs.lstatSync(privateRoot);
    if (rootStat.mode & 0o077) fail('UNSAFE_PRIVATE_PERMISSIONS');
    for (const chunk of relative.split(path.sep).slice(0, -1)) {
      current = path.join(current, chunk);
      const stat = fs.lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink() || stat.mode & 0o077) fail('UNSAFE_PRIVATE_PATH');
    }
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.mode & 0o077 || stat.nlink !== 1 || stat.size < 1 || stat.size > LIMIT) fail('INVALID_PRIVATE_FILE');
      const bytes = Buffer.alloc(LIMIT + 1); let count = 0;
      while (count < bytes.length) {
        const size = fs.readSync(fd, bytes, count, bytes.length - count, null);
        if (!size) break;
        count += size;
      }
      if (count > LIMIT) fail('INVALID_PRIVATE_FILE');
      return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0, count)));
    } finally { fs.closeSync(fd); }
  } catch (error) { if (error instanceof LoginError) throw error; fail('PRIVATE_INPUT_UNREADABLE'); }
}
function readPrivateLoginInput(file, privateRoot) { return validateLoginInput(readPrivateJSON(file, privateRoot)); }
function publicResult(input, identity) {
  return {type:'identity-flow',binding:clone(input.binding),identity_id:identity.id,status:'INCOMPLETE',form_status:'NOT_RUN',
    phases:['authorization','form','callback','application_session','protected_routes'].map(phase => ({phase,status:'NOT_RUN',
      reason_code:phase === 'application_session' ? 'NO_SESSION_ASSERTION' : phase === 'protected_routes' ? 'NO_ROUTE_POLICY' : 'NOT_ATTEMPTED'})),
    execution:{form_submitted:false,callback_observed:false,session_asserted:false,protected_routes_tested:0},
    limits:['FORM_FLOW_ONLY','TOKEN_VALIDATION_NOT_TESTED','COOKIE_POLICY_NOT_TESTED','GLOBAL_EGRESS_ISOLATION_NOT_ESTABLISHED'],cleanup:'not_needed'};
}
function single(url, name, required = true) {
  const values = url.searchParams.getAll(name);
  if (values.length > 1 || required && values.length !== 1 || values.some(value => !text(value, 8192))) fail('INVALID_AUTHORIZATION_PARAMETERS');
  return values[0];
}
async function runIdentityFlow(options) {
  const input = validateLoginInput(options.input);
  const identity = input.identities.find(row => row.id === options.identityId);
  if (!identity) fail('UNKNOWN_IDENTITY');
  const {browser, gate} = options;
  if (!browser || typeof browser.newContext !== 'function' || !gate || typeof gate.acquire !== 'function' || typeof gate.release !== 'function') fail('INVALID_EXECUTOR');
  const now = options.now || (() => performance.now()), wallNow = options.wallNow || Date.now;
  const end = now() + Math.max(0, input.deadline_unix_ms - wallNow());
  const result = publicResult(input, identity);
  let ctx, page, loginGuard, policyError, acquired = false, finalizing = false, contextClosing, creation, phase = 'authorization', guardFailure = null, state, redirect, action, submitting = false;
  let callbackResponse; const callbackDone = new Promise(resolve => { callbackResponse = resolve; });
  const publish = () => { try { if (options.emit) options.emit(clone(result)); } catch { fail('PUBLIC_RECEIPT_WRITE_FAILED'); } };
  const remaining = (operation = true) => { const value = Math.min(operation ? input.operation_timeout_ms : 2147483647, Math.floor(end - now())); if (value < 1) fail('FLOW_DEADLINE_EXHAUSTED'); return value; };
  async function wait(work, operation = true) {
    let timer;
    try { return await Promise.race([work, new Promise((_, reject) => { timer = setTimeout(() => reject(new LoginError('FLOW_DEADLINE_EXHAUSTED')), remaining(operation)); })]); }
    finally { clearTimeout(timer); }
  }
  function closeContext() {
    if (contextClosing) return contextClosing;
    if (!ctx) return Promise.resolve();
    contextClosing = Promise.resolve().then(() => ctx.close());
    return contextClosing;
  }
  function mark(name, status, reason_code) { Object.assign(result.phases.find(row => row.phase === name), {status,reason_code}); publish(); }
  function rejected(code) { guardFailure ||= code; callbackResponse(false); }
  function enforceGuard() { if (guardFailure) fail(guardFailure); remaining(); }
  const issuer = new URL(input.issuer), app = new URL(input.app_origin);
  const formPath = issuer.pathname + '/login-actions/authenticate';
  const allowedPage = () => {
    let url; try { url = new URL(page.url()); } catch { fail('UNEXPECTED_FORM_PAGE'); }
    if (url.origin !== issuer.origin || ![new URL(input.authorization_endpoint).pathname, formPath].includes(url.pathname) || url.username || url.password || url.hash) fail('UNEXPECTED_FORM_PAGE');
  };
  async function formAction() {
    allowedPage();
    const form = page.locator('#kc-form-login');
    for (const selector of ['#kc-form-login','#username','#password','#kc-login']) {
      if (await wait(page.locator(selector).count()) !== 1) fail('UNSUPPORTED_LOGIN_FORM');
    }
    for (const selector of ['#username','#password','#kc-login']) {
      if (await wait(form.locator(selector).count()) !== 1) fail('UNSUPPORTED_LOGIN_FORM');
    }
    if (await wait(form.locator('#password').getAttribute('type')) !== 'password' ||
        await wait(form.locator('#kc-login').getAttribute('type')) !== 'submit') fail('UNSUPPORTED_LOGIN_FORM');
    if ((await wait(form.getAttribute('method')) || '').toLowerCase() !== 'post') fail('UNSAFE_FORM_ACTION');
    const raw = await wait(form.getAttribute('action'));
    if (!text(raw, 16384)) fail('UNSAFE_FORM_ACTION');
    let url; try { url = new URL(raw, page.url()); } catch { fail('UNSAFE_FORM_ACTION'); }
    if (url.origin !== issuer.origin || url.pathname !== formPath || url.username || url.password || url.hash) fail('UNSAFE_FORM_ACTION');
    for (const name of ['session_code','execution','tab_id','client_data','auth_session_id']) single(url, name, false);
    const client = single(url, 'client_id', false);
    if (client !== undefined && client !== input.client_id) fail('UNSAFE_FORM_ACTION');
    const buttonAction = await wait(page.locator('#kc-login').getAttribute('formaction'));
    if (buttonAction !== null && new URL(buttonAction, page.url()).href !== url.href) fail('UNSAFE_FORM_ACTION');
    return url.href;
  }
  try {
    publish(); remaining();
    const admission = Promise.resolve(gate.acquire()).then(() => {
      acquired = true;
      if (finalizing) { gate.release(); acquired = false; }
    });
    await wait(admission, false); remaining();
    if (options.policyHooks) {
      try { await options.policyHooks.beforeForm({browser,identityId:identity.id,remainingMs:()=>remaining(false),operationTimeoutMs:input.operation_timeout_ms}); }
      catch { policyError='EXECUTOR_ERROR'; }
      if (options.policyHooks.shouldStop()) fail(options.policyHooks.stopReason()==='PUBLIC_RECEIPT_WRITE_FAILED'?'PUBLIC_RECEIPT_WRITE_FAILED':'BROWSER_OPERATION_FAILED');
    }
    result.cleanup='unknown';
    creation = Promise.resolve(browser.newContext({serviceWorkers:'block',acceptDownloads:false})).then(async context => {
      ctx = context;
      if (finalizing) { await closeContext(); fail('FLOW_DEADLINE_EXHAUSTED'); }
      return context;
    });
    ctx = await wait(creation);
    // Wspólna kontrola żądania. Playwright woła trasę tylko dla pierwszego adresu w łańcuchu przekierowań,
    // więc kolejne skoki (aplikacja -> autoryzacja, formularz -> callback) sprawdza nasłuch żądań poniżej.
    const inspected = new WeakSet();
    const inspect = request => {
        if (inspected.has(request)) return;
        inspected.add(request);
        const url = new URL(request.url());
        if (![app.origin, issuer.origin].includes(url.origin) || url.username || url.password || url.hash) fail('OUTSIDE_IDENTITY_ALLOWLIST');
        if ([...url.searchParams.values(),decodeURIComponent(url.pathname)].some(value => value.includes(identity.password))) fail('CREDENTIAL_IN_URL');
        const navigation = request.isNavigationRequest();
        const main = navigation && page && request.frame() === page.mainFrame();
        if (!['GET','HEAD'].includes(request.method())) {
          if (request.method() !== 'POST' || !main || !submitting || url.href !== action) fail('UNSAFE_CREDENTIAL_SUBMISSION');
          result.execution.form_submitted = true;
        }
        if (main && url.origin === issuer.origin && url.pathname === new URL(input.authorization_endpoint).pathname) {
          if (state !== undefined || submitting || request.method() !== 'GET') fail('UNEXPECTED_AUTHORIZATION_RESTART');
          if (single(url, 'client_id') !== input.client_id || single(url, 'response_type') !== 'code' ||
              !(single(url, 'scope') || '').split(/\s+/).includes('openid')) fail('INVALID_AUTHORIZATION_PARAMETERS');
          redirect = single(url, 'redirect_uri');
          if (!input.callback_paths.map(value => input.app_origin + value).includes(redirect)) fail('INVALID_CALLBACK_TARGET');
          state = single(url, 'state'); single(url, 'nonce', false);
          const method = single(url, 'code_challenge_method', false), challenge = single(url, 'code_challenge', false);
          if (input.pkce === 'S256' ? method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge || '') : method !== undefined || challenge !== undefined) fail('PKCE_CONTRACT_MISMATCH');
          mark('authorization','PASS','BOUND_AUTHORIZATION_OBSERVED');
        }
        if (main && submitting && url.origin === app.origin && !result.execution.callback_observed && !input.callback_paths.includes(url.pathname)) {
          phase='callback'; fail('INVALID_CALLBACK_TARGET');
        }
        if (main && url.origin === app.origin && input.callback_paths.includes(url.pathname)) {
          phase='callback';
          if (!submitting || !result.execution.form_submitted || url.origin + url.pathname !== new URL(redirect).origin + new URL(redirect).pathname || single(url, 'state') !== state) fail('CALLBACK_BINDING_MISMATCH');
          if (single(url, 'error', false) !== undefined) fail('OIDC_ERROR_RESPONSE');
          single(url, 'code');
          result.execution.callback_observed = true;
        }
    };
    loginGuard = async route => {
      try {
        enforceGuard();
        inspect(route.request());
        await route.continue();
      } catch (error) {
        rejected(error instanceof LoginError ? error.code : 'IDENTITY_REQUEST_REJECTED');
        try { await route.abort(); } catch { /* no credentials or request data are logged */ }
      }
    };
    await wait(ctx.route('**/*', loginGuard));
    page = await wait(ctx.newPage());
    page.on('request', request => {
      if (!request.redirectedFrom()) return;
      try { inspect(request); }
      catch (error) { rejected(error instanceof LoginError ? error.code : 'IDENTITY_REQUEST_REJECTED'); }
    });
    page.on('response', response => {
      try {
        const request = response.request(), url = new URL(response.url());
        if (request.isNavigationRequest() && request.frame() === page.mainFrame() && request.method() === 'POST' &&
            result.execution.form_submitted && url.href === action) {
          const status = response.status();
          if (!Number.isInteger(status) || status < 200 || status >= 400) { phase='form'; rejected('FORM_HTTP_ERROR'); }
          else mark('form','PASS','OWNED_FORM_SUBMITTED');
        }
        if (request.isNavigationRequest() && request.frame() === page.mainFrame() && result.execution.callback_observed &&
            url.origin === app.origin && url.origin + url.pathname === new URL(redirect).origin + new URL(redirect).pathname) {
          const status = response.status();
          if (!Number.isInteger(status) || status < 200 || status >= 400) rejected('CALLBACK_HTTP_ERROR');
          else callbackResponse(true);
        }
      } catch { rejected('CALLBACK_RESPONSE_INVALID'); }
    });
    const landed = await wait(page.goto(input.app_origin + input.login_path, {waitUntil:'domcontentloaded',timeout:remaining()}));
    enforceGuard();
    if (state === undefined) {
      // Diagnoza bez danych logowania: tylko czyj to adres, ścieżka i kod HTTP strony, na której skończyła się nawigacja.
      try { const at = new URL(page.url()); console.error('keycloak login: authorization not observed; landed on ' + (at.origin === app.origin ? 'app' : at.origin === issuer.origin ? 'issuer' : 'other') + (at.origin === issuer.origin && at.pathname === new URL(input.authorization_endpoint).pathname ? ' authorization endpoint' : at.origin === app.origin && at.pathname === input.login_path ? ' login path' : ' other path') + ' status ' + (landed ? landed.status() : 'none')); } catch { /* diagnoza nie może zmienić wyniku */ }
      fail('AUTHORIZATION_NOT_OBSERVED');
    }
    phase = 'form'; action = await formAction(); enforceGuard();
    await wait(page.locator('#kc-form-login').locator('#username').fill(identity.username, {timeout:remaining()}));
    enforceGuard();
    await wait(page.locator('#kc-form-login').locator('#password').fill(identity.password, {timeout:remaining()}));
    if (await formAction() !== action) fail('FORM_ACTION_CHANGED');
    enforceGuard(); submitting = true;
    await wait(page.locator('#kc-form-login').locator('#kc-login').click({timeout:remaining()}));
    enforceGuard();
    if (!result.execution.form_submitted) fail('CREDENTIAL_SUBMISSION_NOT_OBSERVED');
    mark('form','PASS','OWNED_FORM_SUBMITTED'); phase = 'callback';
    await wait(callbackDone); enforceGuard();
    await wait(page.waitForURL(value => value.origin === app.origin, {timeout:remaining()}));
    enforceGuard();
    mark('callback','PASS','BOUND_CALLBACK_RESPONSE_OBSERVED'); result.form_status = 'PASS';
    publish();
    if (options.sessionHook) {
      // Sesja dla przeglądu ekranów to osobny dowód; jej brak nie zmienia wyniku formularza.
      try { await wait(options.sessionHook({context:ctx,identity:{id:identity.id,app_roles:[...identity.app_roles],email_verified:identity.email_verified}})); } catch { /* bez sesji ekrany chronione zostają nieocenione */ }
    }
    if (options.policyHooks) {
      // Policy failure is separate evidence. A successful form/callback must
      // never become a failed form merely because a session probe failed.
      try {
        await wait(ctx.unroute('**/*',loginGuard));
        await options.policyHooks.afterForm({context:ctx,page,identityId:identity.id,remainingMs:()=>remaining(false),operationTimeoutMs:input.operation_timeout_ms});
      } catch { policyError='EXECUTOR_ERROR'; }
    }
    if (options.webauthnHooks && options.policyHooks && !options.policyHooks.shouldStop()) {
      // A ceremony has its own evidence; it cannot rewrite form or policy outcomes.
      try { await options.webauthnHooks.afterPolicy({browser,context:ctx,identityId:identity.id,remainingMs:()=>remaining(false),operationTimeoutMs:input.operation_timeout_ms}); }
      catch { /* The owned helper records failure and latches failed publication. */ }
    }
  } catch (error) {
    const code = guardFailure || (error instanceof LoginError ? error.code : error && error.name === 'ResourcePaused' ? 'RESOURCE_PAUSED' : 'BROWSER_OPERATION_FAILED');
    result.form_status = result.execution.form_submitted ? 'FAIL' : 'BLOCKED';
    result.status = result.form_status;
    Object.assign(result.phases.find(row => row.phase === phase), {status:result.form_status,reason_code:code});
  } finally {
    finalizing = true;
    let timer;
    try {
      // A timed-out newContext may still complete. Own its late handle and allow
      // a bounded cleanup window; never report it as a never-created resource.
      await Promise.race([(async () => { if (creation) await creation.catch(() => {}); await closeContext(); })(),
        new Promise((_, reject) => { timer=setTimeout(() => reject(new LoginError('CLEANUP_TIMEOUT')),3000); })]);
      result.cleanup=ctx ? 'closed' : 'not_needed';
    } catch { result.status='BLOCKED';result.form_status='BLOCKED';result.cleanup='unknown'; }
    finally { clearTimeout(timer); }
    if (acquired) { try { gate.release(); } catch { result.status='BLOCKED';result.form_status='BLOCKED';result.cleanup='unknown'; } }
  }
  publish();
  // Publish the closed form before a policy receipt can credit its session.
  // A failed form checkpoint leaves the preceding policy snapshot incomplete.
  if (options.completedForm) options.completedForm(clone(result));
  if (options.policyHooks) {
    try { options.policyHooks.finishIdentity({identityId:identity.id,formResult:clone(result),error:policyError}); }
    catch { /* The helper latches write failure and stops further admission. */ }
  }
  if (options.webauthnHooks && options.policyHooks && !options.policyHooks.shouldStop()) {
    // Dependencies are on disk before the ceremony can credit closed context.
    try { options.webauthnHooks.finishIdentity({identityId:identity.id,formResult:clone(result),policySuite:options.policyHooks.snapshot()}); }
    catch { /* Preserve the preceding incomplete checkpoint on writer failure. */ }
  }
  return result;
}
async function runLoginSuite(options) {
  const input = validateLoginInput(options.input);
  const results = input.identities.map(identity => publicResult(input, identity));
  const snapshot = () => ({type:'identity-form-suite',binding:clone(input.binding),status:'INCOMPLETE',
    form_status:results.every(row => row.form_status === 'PASS') ? 'PASS' : 'INCOMPLETE',
    identities:clone(results),session_coverage:'NOT_RUN',authorization_coverage:'NOT_RUN'});
  const checkpoint = () => { if (options.emitSuite) { try { options.emitSuite(snapshot()); } catch { fail('PUBLIC_RECEIPT_WRITE_FAILED'); } } };
  checkpoint();
  if (options.emit) for (const row of results) { try { options.emit(clone(row)); } catch { fail('PUBLIC_RECEIPT_WRITE_FAILED'); } }
  for (let index = 0; index < results.length; index++) {
    if (options.policyHooks && options.policyHooks.shouldStop() || options.webauthnHooks && options.webauthnHooks.shouldStop()) break;
    if ((options.wallNow || Date.now)() >= input.deadline_unix_ms) break;
    results[index] = await runIdentityFlow({...options,input,identityId:results[index].identity_id,
      completedForm:row=>{results[index]=row;checkpoint();}});
    if (results[index].phases.some(row => ['RESOURCE_PAUSED','FLOW_DEADLINE_EXHAUSTED'].includes(row.reason_code))) break;
  }
  return snapshot();
}
module.exports = {LoginError,validateLoginInput,readPrivateJSON,readPrivateLoginInput,runIdentityFlow,runLoginSuite};
