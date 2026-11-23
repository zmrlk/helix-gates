// Helix UX pack runner (Playwright). Modes:
//   node ux.cjs engines                 -> JSON {chromium:true,...} (which engines actually launch)
//   node ux.cjs scan  <job.json>        -> <out>/scan.json + screenshots (device matrix x pages x variants)
//   node ux.cjs flows <job.json>        -> <out>/flows.json + per-step screenshots (scripted persona flows)
//   node ux.cjs serve                   -> line protocol on stdin/stdout for the agentic explorer (driven by bin/helix)
// The job file is produced by `helix ux`; see README (sekcja "Pakiet UX").
'use strict';
const fs = require('fs'), path = require('path'), readline = require('readline');
const resolveDependency = require('./dependencies.cjs');
// Without Playwright the pure rules (findingsFor, hostAllowed, worst) stay usable; the missing
// dependency error surfaces on the first browser use, and the CLI below still fails up front.
let PW = null, pwModule = null, pwError = null;
try { PW = resolveDependency('playwright'); pwModule = require(PW); } catch (e) { PW = null; pwError = e; }
function playwright() { if (!pwModule) throw pwError; return pwModule; }
let AXE; try { AXE = process.env.HELIX_AXE || require('path').join(require('path').dirname(resolveDependency('axe-core')), 'axe.min.js'); } catch (_) { AXE = ''; }
const { createGate, ResourcePaused } = require('./resources.cjs');

const LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'];
function hostAllowed(host, allow) {
  host = (host || '').toLowerCase();
  if (LOCAL_HOSTS.includes(host) || /\.(localhost|local|test)$/.test(host)) return true;
  return (allow || []).some((a) => host === a.toLowerCase() || (a.startsWith('*.') && host.endsWith(a.slice(1).toLowerCase())));
}

// ------------------------------------------------------------------ device resolution
function resolveTarget(t) {
  // t: {id, pw_device?, orientation?, viewport?, deviceScaleFactor?, isMobile?, hasTouch?, userAgent?, engine}
  let opts = {};
  if (t.pw_device) {
    const name = t.pw_device + (t.orientation === 'landscape' ? ' landscape' : '');
    const d = playwright().devices[name] || playwright().devices[t.pw_device];
    if (!d) throw new Error(`unknown Playwright device ${name}`);
    opts = { ...d };
  } else {
    let [w, h] = t.viewport || [1280, 800];
    if (t.orientation === 'landscape' && h > w) [w, h] = [h, w];
    if (t.orientation === 'portrait' && w > h) [w, h] = [h, w];
    opts = { viewport: { width: w, height: h }, deviceScaleFactor: t.deviceScaleFactor || 1,
      isMobile: !!t.isMobile, hasTouch: !!t.hasTouch };
    if (t.userAgent) opts.userAgent = t.userAgent;
  }
  delete opts.defaultBrowserType;
  if (t.engine === 'firefox') delete opts.isMobile;          // Firefox has no isMobile emulation
  return opts;
}

// ------------------------------------------------------------------ in-page audits (serialised into the page)
const PERF_INIT = `(() => { window.__ux = { lcp: null, cls: 0 };
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) window.__ux.lcp = e.renderTime || e.loadTime || e.startTime; })
        .observe({ type: 'largest-contentful-paint', buffered: true }); } catch (e) { window.__ux.lcp_unsupported = true; }
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.__ux.cls += e.value; })
        .observe({ type: 'layout-shift', buffered: true }); } catch (e) { window.__ux.cls_unsupported = true; }
})();`;

function layoutAudit(o) {
  // use the emulated viewport size: with isMobile, mobile browsers widen the layout viewport to fit overflowing content
  const vw = o.vw || window.innerWidth, vh = o.vh || window.innerHeight;
  const doc = document.scrollingElement || document.documentElement;
  const sel = (el) => {
    if (!el || !el.tagName) return '?';
    if (el.id) return '#' + el.id;
    let s = el.tagName.toLowerCase();
    if (el.classList && el.classList.length) s += '.' + [...el.classList].slice(0, 2).join('.');
    const t = ((el.getAttribute && el.getAttribute('aria-label')) || el.innerText || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 28);
    return t ? `${s} "${t}"` : s;
  };
  const visible = (el) => {
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    return r.width > 1 && r.height > 1 && cs.visibility !== 'hidden' && cs.display !== 'none' && +cs.opacity > 0.05;
  };
  // content of a closed <details> (outside its <summary>) is not on screen, even when CSS keeps its boxes laid out
  // (e.g. ::details-content animations); hit-testing it gives false "covered by fixed bar" alarms
  const inClosedDetails = (el) => {
    for (let d = el.closest('details:not([open])'); d; d = d.parentElement && d.parentElement.closest('details:not([open])')) {
      if (d === el) continue;
      const s = [...d.children].find((c) => c.tagName === 'SUMMARY');
      if (!(s && s.contains(el))) return true;
    }
    return false;
  };
  const isEffectivelyHidden = (el) => !visible(el) || inClosedDetails(el);
  const clippedByAncestor = (el) => {
    for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
      if (getComputedStyle(p).overflowX !== 'visible') return p;
    }
    return null;
  };
  const INTERACTIVE = 'a[href],button,input:not([type=hidden]),select,textarea,summary,[role=button],[role=link],[role=checkbox],[role=tab],[role=menuitem],[tabindex]:not([tabindex="-1"])';
  const out = { viewport: [vw, vh], scroll_height: doc.scrollHeight, overflow_px: 0, offenders: [], clipped: [], overlaps: [],
    small_targets: [], tiny_targets: [], small_text: [], fixed: [], fixed_cover_ratio: 0, covered: [], broken_images: [],
    meta_viewport: null, interactive_count: 0, text_chars: (document.body.innerText || '').trim().length };
  const mv = document.querySelector('meta[name=viewport]'); out.meta_viewport = mv ? mv.getAttribute('content') : null;
  out.theme_color = document.querySelector('meta[name="theme-color"]')?.getAttribute('content') || null;
  const edge = (y) => {
    const el = document.elementFromPoint(Math.max(1, Math.floor(vw / 2)), y);
    return { element: sel(el), color: el ? getComputedStyle(el).backgroundColor : null };
  };
  out.safari_edges = { top: edge(1), bottom: edge(Math.max(1, vh - 2)),
    fixed_background: [document.documentElement, document.body, ...document.querySelectorAll('body *')].slice(0, 3000)
      .some(el => getComputedStyle(el).backgroundAttachment === 'fixed') };
  // 1. horizontal overflow (page-level) + outermost offenders not inside a scroll/clip container
  out.overflow_px = Math.max(0, doc.scrollWidth - vw);
  if (out.overflow_px > 1) {
    for (const el of document.body.querySelectorAll('*')) {
      const r = el.getBoundingClientRect();
      if (r.right <= vw + 1 || isEffectivelyHidden(el) || clippedByAncestor(el)) continue;
      const p = el.parentElement, pr = p && p.getBoundingClientRect();
      if (!p || p === document.body || pr.right <= vw + 1) out.offenders.push({ sel: sel(el), right: Math.round(r.right) });
      if (out.offenders.length >= 8) break;
    }
  }
  // 2. clipped text (overflow hidden, content larger than box, no ellipsis = silently cut)
  const all = [...document.body.querySelectorAll('*')].slice(0, 4000);
  for (const el of all) {
    if (!el.childNodes.length || ![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
    if (isEffectivelyHidden(el)) continue;
    const cs = getComputedStyle(el);
    const hid = (v) => v === 'hidden' || v === 'clip';
    const cutX = hid(cs.overflowX) && el.scrollWidth > el.clientWidth + 2;
    const cutY = hid(cs.overflowY) && el.scrollHeight > el.clientHeight + 2;
    if ((cutX || cutY) && out.clipped.length < 10)
      out.clipped.push({ sel: sel(el), ellipsis: cs.textOverflow === 'ellipsis', axis: cutX ? 'x' : 'y' });
    // small text
    const fs_ = parseFloat(cs.fontSize);
    if (fs_ < o.min_font_px && out.small_text.length < 10) out.small_text.push({ sel: sel(el), px: fs_ });
  }
  // 3. broken images
  for (const img of document.images) if (img.complete && img.naturalWidth === 0 && !isEffectivelyHidden(img)) out.broken_images.push(sel(img));
  // 4. fixed / sticky elements and their share of the viewport
  let fixedArea = 0;
  for (const el of all) {
    const cs = getComputedStyle(el);
    if ((cs.position === 'fixed' || cs.position === 'sticky') && !isEffectivelyHidden(el)) {
      const r = el.getBoundingClientRect();
      const a = Math.max(0, Math.min(r.right, vw) - Math.max(r.left, 0)) * Math.max(0, Math.min(r.bottom, vh) - Math.max(r.top, 0));
      if (cs.position === 'fixed') fixedArea += a;
      out.fixed.push({ sel: sel(el), position: cs.position, ratio: +(a / (vw * vh)).toFixed(3) });
    }
  }
  out.fixed_cover_ratio = +(fixedArea / (vw * vh)).toFixed(3);
  // 5. interactive elements: tap size, covered/overlapped (scroll each into view, hit-test centre)
  const inter = [...document.querySelectorAll(INTERACTIVE)].filter((el) => !isEffectivelyHidden(el));
  out.interactive_count = inter.length;
  const startY = window.scrollY;
  for (const el of inter.slice(0, o.max_interactive)) {
    const r0 = el.getBoundingClientRect();
    if (o.touch) {
      const inlineLink = el.tagName === 'A' && getComputedStyle(el).display === 'inline' &&
        [...el.parentElement.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 3);
      const m = Math.min(r0.width, r0.height);
      if (!inlineLink && m < 24 && out.tiny_targets.length < 10) out.tiny_targets.push({ sel: sel(el), w: Math.round(r0.width), h: Math.round(r0.height) });
      else if (!inlineLink && m < o.tap_min && out.small_targets.length < 10) out.small_targets.push({ sel: sel(el), w: Math.round(r0.width), h: Math.round(r0.height) });
    }
    el.scrollIntoView({ block: 'center', inline: 'nearest' });
    const r = el.getBoundingClientRect();
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    if (cx < 0 || cy < 0 || cx > window.innerWidth || cy > window.innerHeight) continue;   // cannot hit-test off-screen
    const top = document.elementFromPoint(cx, cy);
    if (top && top !== el && !el.contains(top) && !top.contains(el) && !(el.labels && [...el.labels].some((l) => l.contains(top)))) {
      let p = top, fixed = false;
      for (; p && p !== document.body; p = p.parentElement) { const ps = getComputedStyle(p).position; if (ps === 'fixed' || ps === 'sticky') { fixed = true; break; } }
      if (out.covered.length < 10) out.covered.push({ sel: sel(el), by: sel(fixed ? p : top), fixed });
    }
  }
  window.scrollTo(0, startY);
  // 6. overlapping text blocks (leaf text elements whose boxes intersect substantially)
  const leaves = all.filter((el) => el.children.length === 0 && (el.innerText || '').trim() && !isEffectivelyHidden(el)).slice(0, 400);
  const boxes = leaves.map((el) => [el, el.getBoundingClientRect()]);
  for (let i = 0; i < boxes.length && out.overlaps.length < 8; i++) for (let j = i + 1; j < boxes.length; j++) {
    const [a, ra] = boxes[i], [b, rb] = boxes[j];
    const ix = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left), iy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
    if (ix <= 2 || iy <= 2) continue;
    const small = Math.min(ra.width * ra.height, rb.width * rb.height);
    if (ix * iy > 0.25 * small && !a.contains(b) && !b.contains(a)) { out.overlaps.push({ a: sel(a), b: sel(b) }); break; }
  }
  return out;
}

function keyboardProbe() {          // called repeatedly after each Tab press
  const el = document.activeElement;
  if (!el || el === document.body) return { sel: null };
  const cs = getComputedStyle(el);
  window.__kbd = window.__kbd || []; window.__kbd.push(el);
  const F = [...document.querySelectorAll('a[href],button:not([disabled]),input:not([type=hidden]):not([disabled]),select,textarea,summary,[tabindex]:not([tabindex="-1"])')]
    .filter((x) => x.getClientRects().length && getComputedStyle(x).visibility !== 'hidden');
  const idx = F.indexOf(el), last = idx === F.length - 1;
  const r = el.getBoundingClientRect();
  const top = document.elementFromPoint(Math.min(Math.max(r.left + r.width / 2, 1), innerWidth - 1), Math.min(Math.max(r.top + r.height / 2, 1), innerHeight - 1));
  const obscured = !!top && top !== el && !el.contains(top) && !top.contains(el);
  // focus ring may live on ::before/::after or on a :focus-within ancestor (WCAG 2.4.7 accepts both)
  const sig = (e) => { const out = []; for (let n = e, d = 0; n && n !== document.body && d < 3; n = n.parentElement, d++)
    for (const ps of d ? [null] : [null, '::before', '::after']) { const c = getComputedStyle(n, ps);
      out.push([c.outlineStyle, c.outlineWidth, c.outlineColor, c.boxShadow, c.borderColor, c.backgroundColor, c.textDecorationLine, c.color].join('|')); }
    return out.join('#'); };
  const st = sig(el);
  window.__kbdStyles = window.__kbdStyles || []; window.__kbdStyles.push(st);
  const id = el.id ? '#' + el.id : el.tagName.toLowerCase() + ((el.innerText || el.value || el.getAttribute('aria-label') || '').trim() ? ` "${(el.innerText || el.value || el.getAttribute('aria-label')).trim().slice(0, 24)}"` : '');
  return { sel: id, idx, last, obscured, outline: cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0 };
}
function keyboardFinish() {         // compare focused vs unfocused styles; find pointer-only clickables
  document.activeElement && document.activeElement.blur && document.activeElement.blur();
  // focus ring may live on ::before/::after or on a :focus-within ancestor (WCAG 2.4.7 accepts both)
  const sig = (e) => { const out = []; for (let n = e, d = 0; n && n !== document.body && d < 3; n = n.parentElement, d++)
    for (const ps of d ? [null] : [null, '::before', '::after']) { const c = getComputedStyle(n, ps);
      out.push([c.outlineStyle, c.outlineWidth, c.outlineColor, c.boxShadow, c.borderColor, c.backgroundColor, c.textDecorationLine, c.color].join('|')); }
    return out.join('#'); };
  const res = [];
  (window.__kbd || []).forEach((el, i) => {
    res.push(sig(el) !== window.__kbdStyles[i]);
  });
  const focusable = (el) => el.matches('a[href],button,input,select,textarea,summary,[tabindex]') || !!el.closest('a[href],button,label,summary,[tabindex]');
  const pointerOnly = [...document.body.querySelectorAll('*')].filter((el) => {
    const cs = getComputedStyle(el); if (cs.cursor !== 'pointer' || focusable(el)) return false;
    const p = el.parentElement; return !(p && getComputedStyle(p).cursor === 'pointer');   // outermost only
  }).slice(0, 8).map((el) => (el.id ? '#' + el.id : el.tagName.toLowerCase()) + ` "${(el.innerText || '').trim().slice(0, 24)}"`);
  return { focus_changed: res, pointer_only: pointerOnly };
}

const LONG_TEXT = ' – Przedsiębiorstwo Handlowo-Usługowe „Żółta Gęś” Spółka z ograniczoną odpowiedzialnością sp.k. ul. Źródlana 123/45';
function injectLongContent(longText) {
  let n = 0;
  for (const el of document.body.querySelectorAll('td,th,li,h1,h2,h3,label,button,a,span,p,dd,dt,strong')) {
    const tn = [...el.childNodes].find((x) => x.nodeType === 3 && x.textContent.trim());
    if (!tn || el.closest('script,style')) continue;
    tn.textContent = /^[\s\d.,]+(zł|PLN)?\s*$/.test(tn.textContent) ? ' 1 234 567 890,99 zł ' : tn.textContent + longText;
    if (++n > 150) break;
  }
  return n;
}
const TEXT_SPACING_CSS = '* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; } p { margin-bottom: 2em !important; }';

// ------------------------------------------------------------------ helpers
const mkdirp = (d) => fs.mkdirSync(d, { recursive: true });
const slug = (s) => String(s).replace(/[^a-zA-Z0-9._-]+/g, '_');
const ERROR_TEXT = /błąd|blad|error|nie udało|nie mozna|nie można|spróbuj|spróbuj ponownie|try again|failed|niedostęp|offline|brak połączenia/i;
const EMPTY_TEXT = /brak|pusto|nie ma|no results|empty|nothing|0 wyników|nie znaleziono/i;

async function launch(engine, cache) {
  // Certyfikat przebiegu (HTTPS runtime): Chromium ufa wyłącznie przypiętym kluczom tego przebiegu, jak runtime-browser.cjs.
  const spki = process.env.HELIX_RUNTIME_TLS_SPKI_LIST;
  if (spki && !spki.split(',').every((key) => /^[A-Za-z0-9+/]{43}=$/.test(key))) throw new Error('invalid owned TLS key list');
  // WebKit i Firefox nie przypinają klucza: przy HTTPS przebiegu nie łączą się (bez obejścia), a cele są niesprawdzone, nie zaliczone.
  if (spki && engine !== 'chromium') throw new Error(engine + ': brak zaufania do certyfikatu przebiegu (HTTPS), cel niesprawdzony');
  const options = { headless: true, ...(spki && engine === 'chromium' ? { args: ['--ignore-certificate-errors-spki-list=' + spki] } : {}) };
  if (!cache[engine]) cache[engine] = playwright()[engine].launch(options);   // cache the promise: no duplicate browsers under concurrency
  return cache[engine];
}

async function executionTools(browsers) {
  // Read the library already loaded and browsers already launched. Never probe or launch here.
  // Without a loaded Playwright there is nothing it ran, so no receipt claims it.
  const receipts = [{ tool: 'node', version: process.versions.node, used: true }];
  if (pwModule) {
    let version = null;
    try { version = JSON.parse(fs.readFileSync(path.join(path.dirname(PW), 'package.json'), 'utf8')).version; } catch (_) {}
    receipts.push({ tool: 'playwright', version, used: true });
  }
  for (const [engine, pending] of Object.entries(browsers)) {
    let browser; try { browser = await pending; } catch (_) { continue; }
    let version = null; try { version = browser.version(); } catch (_) {}
    receipts.push({ tool: engine, version, used: true });
  }
  return receipts;
}

function executionProvenance(job, tools) {
  if (!job.provenance) return null;
  return { ...job.provenance, tools: { ...job.provenance.tools,
    ...Object.fromEntries(tools.map(({ tool, version, used }) => [tool,
      { version: version || null, used, status: version ? 'recorded' : 'unknown' }])) } };
}

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
async function newContext(browser, target, job, extra = {}) {
  const opts = { ...resolveTarget(target), locale: job.locale || 'pl-PL', timezoneId: job.timezone || 'Europe/Warsaw',
    acceptDownloads: true, ...extra };
  // storage_state: zalogowana sesja (Playwright storageState JSON) zamiast logowania na każdej stronie (limity logowań w API)
  if (opts.storageState === undefined && job.storage_state) opts.storageState = job.storage_state;
  if (opts.storageState === null) delete opts.storageState;
  const ctx = await browser.newContext(opts);
  const external = new Set(), blocked = new Set();
  if (job.block_external !== false) {
    await ctx.route('**/*', (route) => {
      let host = ''; try { host = new URL(route.request().url()).hostname; } catch (e) {}
      const u = route.request().url();
      if (u.startsWith('data:') || u.startsWith('blob:') || hostAllowed(host, job.allow_hosts)) return route.fallback();
      external.add(host); blocked.add(u); return route.abort('blockedbyclient');
    });
  }
  await routeFunctionStubs(ctx);
  ctx.__external = external; ctx.__blocked = blocked;
  return ctx;
}

function attachCollectors(page, ctx) {
  const c = { console_errors: [], page_errors: [], failed_requests: [], http_errors: [] };
  page.on('console', (m) => { if (m.type() === 'error' && c.console_errors.length < 20) c.console_errors.push(m.text().slice(0, 300)); });
  page.on('pageerror', (e) => { if (c.page_errors.length < 20) c.page_errors.push(String(e.message || e).slice(0, 300)); });
  page.on('requestfailed', (r) => {
    const f = r.failure() && r.failure().errorText; if (ctx && ctx.__blocked.has(r.url())) return;
    if (c.failed_requests.length < 20) c.failed_requests.push(`${r.method()} ${r.url().slice(0, 200)} (${f})`);
  });
  page.on('response', (r) => { if (r.status() >= 400 && c.http_errors.length < 20) c.http_errors.push(`${r.status()} ${r.url().slice(0, 200)}`); });
  return c;
}

async function runActions(page, actions, baseUrl) {
  for (const a of actions || []) {
    if (a.goto) await page.goto(new URL(a.goto, baseUrl).href, { waitUntil: 'networkidle', timeout: 30000 });
    if (a.click) await page.locator(a.click).first().click({ timeout: 10000 });
    if (a.fill) await page.locator(a.fill).first().fill(String(a.value ?? ''), { timeout: 10000 });
    if (a.select) await page.locator(a.select).first().selectOption(String(a.value ?? ''), { timeout: 10000 });
    if (a.press) await page.keyboard.press(a.press);
    if (a.wait) await page.waitForTimeout(a.wait);
    if (a.waitFor) await page.waitForSelector(a.waitFor, { timeout: 15000 });
  }
}

async function perfSnapshot(page) {
  return page.evaluate(() => {
    const n = performance.getEntriesByType('navigation')[0] || {};
    const res = performance.getEntriesByType('resource');
    return { lcp_ms: window.__ux && window.__ux.lcp != null ? Math.round(window.__ux.lcp) : null,
      cls: window.__ux ? +(+window.__ux.cls).toFixed(4) : null,
      lcp_supported: !(window.__ux && window.__ux.lcp_unsupported), cls_supported: !(window.__ux && window.__ux.cls_unsupported),
      ttfb_ms: n.responseStart ? Math.round(n.responseStart) : null, dcl_ms: n.domContentLoadedEventEnd ? Math.round(n.domContentLoadedEventEnd) : null,
      load_ms: n.loadEventEnd ? Math.round(n.loadEventEnd) : null, requests: res.length + 1,
      transfer_kb: Math.round((res.reduce((s, r) => s + (r.transferSize || 0), 0) + (n.transferSize || 0)) / 1024) };
  });
}

async function runAxe(page, rules) {
  try {
    await page.addScriptTag({ path: AXE });
    return await page.evaluate(async (r) => {
      const opt = r ? { runOnly: { type: 'rule', values: r } } :
        { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] } };
      opt.resultTypes = ['violations'];
      const res = await window.axe.run(document, opt);
      return res.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, tags: v.tags.filter((t) => /wcag|best/.test(t)),
        nodes: v.nodes.length, targets: v.nodes.slice(0, 3).map((n) => String(n.target[0]).slice(0, 80)) }));
    }, rules || null);
  } catch (e) { return { error: String(e.message || e).slice(0, 200) }; }
}

async function keyboardAudit(page, maxTabs) {
  const seq = []; let same = 0, trap = false;
  // WebKit on macOS skips links and buttons on plain Tab (Safari default); Option+Tab walks every control
  const browser = page.context().browser();
  const tabKey = browser && browser.browserType().name() === 'webkit' && process.platform === 'darwin' ? 'Alt+Tab' : 'Tab';
  for (let i = 0; i < maxTabs; i++) {
    await page.keyboard.press(tabKey);
    const p = await page.evaluate(keyboardProbe);
    if (!p.sel) { if (i > 0) break; continue; }
    const prev = seq[seq.length - 1];
    if (prev && prev.idx === p.idx) {           // focus did not move: end of page (focus left to browser UI) or a trap
      if (++same >= 2) { trap = !p.last && p.idx >= 0; break; } continue;
    } else same = 0;
    if (seq.length > 2 && seq[0].idx === p.idx) break;   // wrapped around
    seq.push(p);
  }
  const fin = await page.evaluate(keyboardFinish);
  const noIndicator = seq.filter((s, i) => !fin.focus_changed[i] && !s.outline).map((s) => s.sel);
  return { tab_stops: seq.length, trap, no_focus_indicator: [...new Set(noIndicator)].slice(0, 10),
    obscured: [...new Set(seq.filter((s) => s.obscured).map((s) => s.sel))].slice(0, 10), pointer_only: fin.pointer_only };
}

// ------------------------------------------------------------------ findings (severity rules live here, thresholds from job)
function findingsFor(r, th, kind) {
  const F = []; const add = (check, severity, message, detail) => F.push({ check, severity, message, ...(detail ? { detail } : {}) });
  const L = r.layout;
  if (L) {
    if (r.mobile && !L.meta_viewport) add('meta-viewport', 'fail', 'brak <meta name=viewport> – na telefonie strona renderuje się jak desktop (980px)');
    if (r.engine === 'webkit' && r.mobile) {
      if (!/viewport-fit\s*=\s*cover/i.test(L.meta_viewport || '')) add('safari-viewport-cover', 'warn', 'Safari: brak viewport-fit=cover');
      if (!L.theme_color) add('safari-theme-color', 'warn', 'Safari: brak theme-color');
      const e = L.safari_edges;
      if (e && (e.fixed_background || e.top.color !== e.bottom.color))
        add('safari-chrome-tint', 'info', 'Safari dobiera kolor chromu z elementów przy krawędziach; sprawdź górę i dół na iPhonie', e);
    }
    if (L.overflow_px > 1) add('overflow', 'fail', `poziomy scroll strony: +${L.overflow_px}px`, L.offenders);
    if (L.clipped.filter((c) => !c.ellipsis).length) add('clipped', 'warn', `obcięty tekst (overflow hidden) w ${L.clipped.filter((c) => !c.ellipsis).length} miejscach`, L.clipped.filter((c) => !c.ellipsis));
    if (L.clipped.filter((c) => c.ellipsis).length) add('truncated', 'info', `tekst skracany wielokropkiem w ${L.clipped.filter((c) => c.ellipsis).length} miejscach (sprawdź, czy nie ucina kwot/nazw)`, L.clipped.filter((c) => c.ellipsis));
    if (L.overlaps.length) add('overlap', 'warn', `nachodzące na siebie teksty: ${L.overlaps.length}`, L.overlaps);
    const cov = L.covered.filter((c) => c.fixed), cov2 = L.covered.filter((c) => !c.fixed);
    if (cov.length) add('fixed-covers', 'fail', `element fixed/sticky zasłania ${cov.length} klikalnych elementów`, cov);
    if (cov2.length) add('covered', 'warn', `klikalne elementy przykryte innymi: ${cov2.length}`, cov2);
    if (L.fixed_cover_ratio > th.fixed_cover_max) add('fixed-area', 'warn', `elementy fixed zajmują ${Math.round(L.fixed_cover_ratio * 100)}% ekranu`, L.fixed);
    if (L.tiny_targets.length) add('tap-target', 'fail', `cele dotyku < 24px (WCAG 2.5.8): ${L.tiny_targets.length}`, L.tiny_targets);
    if (L.small_targets.length) add('tap-target', 'warn', `cele dotyku < ${th.tap_min}px: ${L.small_targets.length}`, L.small_targets);
    if (L.small_text.length) add('small-text', L.small_text.some((s) => s.px < th.min_font_fail_px) ? 'fail' : 'warn', `tekst mniejszy niż ${th.min_font_px}px: ${L.small_text.length}`, L.small_text);
    if (L.broken_images.length) add('broken-image', 'fail', `niezaładowane obrazki: ${L.broken_images.length}`, L.broken_images);
    if (L.text_chars === 0) add('blank', 'fail', 'pusta strona (brak widocznego tekstu)');
  }
  const C = r.collect || {};
  if (C.page_errors && C.page_errors.length) add('js-error', 'fail', `nieobsłużone wyjątki JS: ${C.page_errors.length}`, C.page_errors);
  if (C.console_errors && C.console_errors.length) add('console', 'warn', `błędy w konsoli: ${C.console_errors.length}`, C.console_errors);
  if (C.failed_requests && C.failed_requests.length) add('request-failed', 'warn', `nieudane żądania: ${C.failed_requests.length}`, C.failed_requests);
  if (C.http_errors && C.http_errors.length) add('http-error', 'warn', `odpowiedzi HTTP >= 400: ${C.http_errors.length}`, C.http_errors);
  if (r.external_blocked && r.external_blocked.length) add('external', 'info', `zablokowane żądania do zewnętrznych hostów (ochrona produkcji): ${r.external_blocked.join(', ')}`);
  if (Array.isArray(r.axe)) for (const v of r.axe) {
    const sev = v.tags.includes('best-practice') && !v.tags.some((t) => t.startsWith('wcag')) ? (v.impact === 'critical' || v.impact === 'serious' ? 'warn' : 'info')
      : (v.impact === 'critical' || v.impact === 'serious' ? 'fail' : v.impact === 'moderate' ? 'warn' : 'info');
    add('a11y:' + v.id, sev, `axe ${v.id} (${v.impact}, ${v.nodes} el.): ${v.help}`, v.targets);
  } else if (r.axe && r.axe.error) add('a11y', 'info', 'axe nie uruchomił się: ' + r.axe.error);
  const P = r.perf;
  if (P && kind !== 'variant') {
    if (P.lcp_ms != null && P.lcp_ms > th.lcp_fail_ms) add('perf:lcp', 'fail', `LCP ${P.lcp_ms} ms > ${th.lcp_fail_ms}`);
    else if (P.lcp_ms != null && P.lcp_ms > th.lcp_warn_ms) add('perf:lcp', 'warn', `LCP ${P.lcp_ms} ms > ${th.lcp_warn_ms}`);
    if (P.cls != null && P.cls > th.cls_fail) add('perf:cls', 'fail', `CLS ${P.cls} > ${th.cls_fail}`);
    else if (P.cls != null && P.cls > th.cls_warn) add('perf:cls', 'warn', `CLS ${P.cls} > ${th.cls_warn}`);
    if (P.transfer_kb > th.transfer_warn_kb) add('perf:weight', 'warn', `strona waży ${P.transfer_kb} KB (> ${th.transfer_warn_kb})`);
  }
  const K = r.keyboard;
  if (K) {
    if (K.trap) add('kbd:trap', 'fail', 'pułapka klawiatury: Tab nie wychodzi z elementu');
    if (K.tab_stops === 0 && (r.layout || {}).interactive_count > 0) add('kbd:unreachable', 'fail', 'Tab nie dochodzi do żadnego elementu');
    if (K.no_focus_indicator.length) add('kbd:focus-visible', 'fail', `brak widocznego fokusu na ${K.no_focus_indicator.length} elementach (WCAG 2.4.7)`, K.no_focus_indicator);
    if (K.obscured.length) add('kbd:focus-obscured', 'warn', `fokus zasłonięty przez inny element (WCAG 2.4.11): ${K.obscured.length}`, K.obscured);
    if (K.pointer_only.length) add('kbd:pointer-only', 'warn', `elementy wyglądające na klikalne, niedostępne z klawiatury: ${K.pointer_only.length}`, K.pointer_only);
  }
  for (const x of r.extra_findings || []) F.push(x);
  return F;
}
const worst = (F) => F.some((f) => f.severity === 'fail') ? 'fail' : F.some((f) => f.severity === 'warn') ? 'warn' : 'pass';

// ------------------------------------------------------------------ scan one (target, page, variant)
async function scanOne(browser, target, pg, variant, job, outDir) {
  const th = job.thresholds; const touch = !!resolveTarget(target).hasTouch; const mobile = !!resolveTarget(target).isMobile || !!target.mobile;
  const ctxExtra = {};
  if (pg.storage_state !== undefined) ctxExtra.storageState = pg.storage_state;
  if (variant === 'dark') ctxExtra.colorScheme = 'dark';
  if (variant === 'reduced-motion') ctxExtra.reducedMotion = 'reduce';
  if (variant === 'zoom200') {
    const o = resolveTarget(target);
    ctxExtra.viewport = { width: Math.round(o.viewport.width / 2), height: Math.round(o.viewport.height / 2) };
    ctxExtra.deviceScaleFactor = (o.deviceScaleFactor || 1) * 2;
  }
  const ctx = await newContext(browser, target, job, ctxExtra);
  await ctx.addInitScript(PERF_INIT);
  const page = await ctx.newPage(); const collect = attachCollectors(page, ctx);
  const url = new URL(pg.path || '/', job.base_url).href;
  const res = { target: target.id, engine: target.engine, page: pg.name, variant: variant || 'base', url: pg.path || '/', mobile, touch, collect,
    engine_note: target.engine_note || null, extra_findings: [] };
  const rel = path.join('shots', slug(target.id), slug(pg.name) + (variant ? '.' + variant : ''));
  const shotDir = path.join(outDir, path.dirname(rel)); mkdirp(shotDir);
  try {
    for (const rt of [...(pg.routes || []), ...(variant === 'api-error' ? [{ url: job.api_pattern, status: 500, body: '{"error":"helix simulated failure"}' }] : []),
      ...(variant === 'api-empty' ? [{ url: job.api_pattern, status: 200, body: job.empty_body || '[]' }] : [])]) {
      if (!rt.url) continue;
      await page.route(rt.url, (route) => { res.api_hits = (res.api_hits || 0) + 1; return rt.abort ? route.abort() : route.fulfill({ status: rt.status || 200, contentType: rt.contentType || 'application/json', body: rt.body ?? '' }); });
    }
    let cdp = null;
    if (variant === 'slow3g') {
      cdp = await ctx.newCDPSession(page);
      await cdp.send('Network.enable');
      await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: 400, downloadThroughput: 500 * 1024 / 8 * 0.8, uploadThroughput: 500 * 1024 / 8 * 0.8 });
      await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
      const t0 = Date.now();
      await page.goto(url, { waitUntil: 'commit', timeout: 60000 });
      await page.waitForTimeout(3000);
      const chars3s = await page.evaluate(() => (document.body ? document.body.innerText.trim().length : 0)).catch(() => 0);
      await page.screenshot({ path: path.join(outDir, rel + '.3s.png') }).catch(() => {});
      await page.waitForLoadState('load', { timeout: 90000 }).catch(() => {});
      res.slow3g = { load_s: +((Date.now() - t0) / 1000).toFixed(1), visible_chars_at_3s: chars3s };
      if (chars3s === 0) res.extra_findings.push({ check: 'slow3g:blank', severity: 'warn', message: 'na wolnym 3G po 3 s ekran jest pusty (brak szkieletu/loadera)' });
      if (res.slow3g.load_s > th.slow3g_load_warn_s) res.extra_findings.push({ check: 'slow3g:load', severity: 'warn', message: `ładowanie na wolnym 3G: ${res.slow3g.load_s} s` });
    } else {
      await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
    }
    await runActions(page, pg.actions, job.base_url);
    if (variant !== 'slow3g' && variant !== 'offline' && !(await waitReady(page)))
      res.extra_findings.push({ check: 'loading:stuck', severity: 'warn', message: 'wskaźnik ładowania nie znika po 8 s; ekran oceniany w stanie ładowania' });
    if (pg.wait_for && variant !== 'api-error' && variant !== 'api-empty') await page.waitForSelector(pg.wait_for, { timeout: 15000 });
    if (variant === 'text-spacing') await page.addStyleTag({ content: TEXT_SPACING_CSS });
    if (variant === 'long-content') res.long_content_nodes = await page.evaluate(injectLongContent, LONG_TEXT);
    if (variant === 'large-text') {
      const before = await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector('main,p,td,li,body') || document.body).fontSize));
      await page.addStyleTag({ content: 'html { font-size: 200% !important; }' });
      const after = await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector('main,p,td,li,body') || document.body).fontSize));
      res.large_text = { before_px: before, after_px: after };
      if (after < before * 1.3) res.extra_findings.push({ check: 'large-text:px', severity: 'warn', message: `tekst nie skaluje się z ustawieniem dużej czcionki (${before}px -> ${after}px; rozmiary w px zamiast rem)` });
    }
    await page.waitForTimeout(variant === 'reduced-motion' ? 300 : 150);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: path.join(outDir, rel + '.png') });
    if (!variant) {
      const o = resolveTarget(target);
      const maxH = Math.min(await page.evaluate(() => document.documentElement.scrollHeight), o.viewport.height * 4);
      await page.screenshot({ path: path.join(outDir, rel + '.full.png'), fullPage: true, clip: { x: 0, y: 0, width: o.viewport.width, height: maxH } }).catch(() => {});
      res.full_shot = rel + '.full.png';
    }
    res.shot = rel + '.png';
    if (!variant) {   // stan zrzutu (projekt B): przekierowanie i widoczny komunikat błędu; resztę liczy helix_ux.screen_state
      const norm = (p) => p.replace(/\/+$/, '') || '/';
      const txt = await page.evaluate(() => (document.body ? document.body.innerText : '')).catch(() => '');
      const finalPath = new URL(page.url()).pathname;
      res.screen = { final_path: finalPath, redirected: norm(finalPath) !== norm(new URL(url).pathname), error_text: ERROR_TEXT.test(txt.slice(0, 4000)) };
    }
    const layoutVariants = [null, undefined, 'zoom200', 'text-spacing', 'long-content', 'large-text', 'dark', 'api-error', 'api-empty'];
    if (layoutVariants.includes(variant)) res.layout = await page.evaluate(layoutAudit, { vw: page.viewportSize().width, vh: page.viewportSize().height, touch, tap_min: th.tap_min, min_font_px: mobile ? th.min_font_px : th.min_font_px_desktop, max_interactive: 80 });
    if (variant && res.layout) {            // variants: only layout regressions matter (perf/console checked in base)
      const keep = variant === 'zoom200' || variant === 'text-spacing' || variant === 'long-content' || variant === 'large-text'
        ? ['overflow_px', 'offenders', 'clipped', 'overlaps'] : ['text_chars'];
      for (const k of Object.keys(res.layout)) if (![...keep, 'viewport', 'interactive_count', 'text_chars', 'meta_viewport'].includes(k)) res.layout[k] = Array.isArray(res.layout[k]) ? [] : 0;
      res.layout.meta_viewport = 'n/a'; if (variant !== 'api-error' && variant !== 'api-empty') res.layout.text_chars = 1;
    }
    if (!variant && job.checks.axe) res.axe = await runAxe(page);
    if (variant === 'dark') {
      res.axe = await runAxe(page, ['color-contrast']);
      const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
      res.dark = { body_bg: bg, supports_dark: !/rgba?\(255, 255, 255|rgba\(0, 0, 0, 0\)/.test(bg) };
      if (!res.dark.supports_dark) res.extra_findings.push({ check: 'dark:unsupported', severity: 'info', message: 'brak trybu ciemnego (prefers-color-scheme: dark nie zmienia tła)' });
    }
    if (variant === 'reduced-motion') {
      const anim = await page.evaluate(() => document.getAnimations ? document.getAnimations().filter((a) => a.playState === 'running' &&
        (a.effect && a.effect.getComputedTiming && (a.effect.getComputedTiming().iterations === Infinity || a.effect.getComputedTiming().duration > 500))).length : 0);
      res.reduced_motion = { running_animations: anim };
      if (anim) res.extra_findings.push({ check: 'motion', severity: 'warn', message: `${anim} animacji działa mimo prefers-reduced-motion: reduce` });
    }
    if ((variant === 'api-error' || variant === 'api-empty') && !res.api_hits) {
      res.skipped = 'strona nie wywołuje API pasującego do ux.api_pattern'; collect.console_errors = []; collect.http_errors = []; collect.page_errors = [];
    } else if (variant === 'api-error') {
      const txt = await page.evaluate(() => document.body.innerText);
      res.api_error = { error_message_visible: ERROR_TEXT.test(txt) };
      if (!res.api_error.error_message_visible) res.extra_findings.push({ check: 'state:api-error', severity: 'warn', message: 'przy błędzie API (500) użytkownik nie widzi komunikatu o błędzie' });
      collect.console_errors = []; collect.http_errors = [];      // expected under simulated failure
    }
    else if (variant === 'api-empty') {
      const txt = await page.evaluate(() => document.body.innerText);
      res.api_empty = { empty_message_visible: EMPTY_TEXT.test(txt) };
      if (!res.api_empty.empty_message_visible) res.extra_findings.push({ check: 'state:empty', severity: 'warn', message: 'pusta lista z API nie pokazuje stanu pustego („brak…”)' });
    }
    if (variant === 'offline') {
      const swc = await page.evaluate(() => !!(navigator.serviceWorker && navigator.serviceWorker.controller));
      await ctx.setOffline(true);
      let reloadOk = true; try { await page.reload({ timeout: 8000 }); } catch (e) { reloadOk = false; }
      const txt = reloadOk ? await page.evaluate(() => document.body.innerText).catch(() => '') : '';
      await page.screenshot({ path: path.join(outDir, rel + '.png') }).catch(() => {});
      res.offline = { service_worker: swc, reload_ok: reloadOk, offline_message: ERROR_TEXT.test(txt) };
      const sev = job.thresholds.offline_required ? 'warn' : 'info';
      if (!reloadOk || !res.offline.offline_message) res.extra_findings.push({ check: 'offline', severity: sev, message: `offline: ${swc ? 'service worker jest' : 'brak service workera'}, po odświeżeniu ${reloadOk ? 'strona bez komunikatu offline' : 'błąd przeglądarki zamiast komunikatu'}` });
      collect.failed_requests = []; collect.console_errors = [];
    }
    if (!variant) {
      res.perf = await perfSnapshot(page);
      if (job.checks.keyboard && !touch) res.keyboard = await keyboardAudit(page, Math.min(60, (res.layout.interactive_count || 0) + 5));
    }
    if (variant === 'slow3g') { res.perf = await perfSnapshot(page); collect.console_errors = []; }
  } catch (e) {
    res.error = String(e.message || e).split('\n')[0].slice(0, 300);
    res.extra_findings.push({ check: 'run-error', severity: 'fail', message: 'nie udało się wykonać sprawdzenia: ' + res.error });
    await page.screenshot({ path: path.join(outDir, rel + '.png') }).then(() => { res.shot = rel + '.png'; }).catch(() => {});
  }
  res.external_blocked = [...ctx.__external];
  await ctx.close();
  res.findings = findingsFor(res, th, variant ? 'variant' : 'base');
  if (variant === 'slow3g' && res.perf && res.perf.lcp_ms > th.lcp_fail_ms * 2) res.findings.push({ check: 'perf:lcp-3g', severity: 'warn', message: `LCP na wolnym 3G: ${res.perf.lcp_ms} ms` });
  res.status = worst(res.findings);
  return res;
}

function writeJSON(file, value) {
  const temporary = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(temporary, JSON.stringify(value, null, 1)); fs.renameSync(temporary, file);
}
function resourceGate(job) {
  return createGate({path: job.resources?.path, requestedJobs: job.parallel || 3,
    maxPauseMs: (job.resources?.max_pause_s || 300) * 1000,
    pollMs: (job.resources?.poll_s || 5) * 1000,
    staleAfterMs: (job.resources?.stale_after_s || 15) * 1000,
    onDecision: d => process.stderr.write(`[ux resources] ${d.state}: jobs ${d.effective_jobs}/${d.requested_jobs}; ${d.reason || ''}\n`)});
}
async function pool(items, n, fn, gate, checkpoint = async () => {}) {
  const results = new Array(items.length); let cursor = 0, paused = null;
  const workers = Array.from({length: Math.min(n, items.length)}, async () => {
    while (cursor < items.length && !paused) {
      let acquired = false;
      try {
        if (gate) { await gate.acquire(); acquired = true; }
        if (cursor >= items.length || paused) break;
        const index = cursor++;
        results[index] = await fn(items[index], index);
        await checkpoint(results, paused);
      } catch (error) {
        if (!(error instanceof ResourcePaused)) throw error;
        paused = error;
      } finally { if (acquired) gate.release(); }
    }
  });
  // Drain active work before closing its browsers, even if another admission pauses.
  const settled = await Promise.allSettled(workers);
  await checkpoint(results, paused);
  const failed = settled.find(r => r.status === 'rejected');
  if (failed) throw failed.reason;
  return {results: results.filter(Boolean), not_checked: items.map((_, i) => i).filter(i => !results[i]), paused};
}

async function closeOwnedBrowsers(browsers) {
  await Promise.allSettled(Object.values(browsers).map(async pending => {
    try { await (await pending).close(); } catch (_) {}
  }));
}

async function cmdScan(job) {
  const outDir = job.out; mkdirp(outDir); const browsers = {};
  const units = [];
  for (const t of job.targets) for (const pg of job.pages) units.push([t, pg, null]);
  for (const v of job.variants || []) for (const t of job.targets.filter((x) => (x.variants || []).includes(v))) for (const pg of job.pages) units.push([t, pg, v]);
  const t0 = Date.now(), gate = resourceGate(job);
  let completed = [];
  const checkpoint = async (results, paused, failed = false) => {
    completed = results;
    const tools = await executionTools(browsers);
    writeJSON(path.join(outDir, 'scan.json'), {kind: 'scan', at: new Date().toISOString(), base_url: job.base_url,
      seconds: Math.round((Date.now() - t0) / 1000), results: results.filter(Boolean), tools, provenance: executionProvenance(job, tools),
      run_status: failed ? 'error' : paused ? 'resource_paused' : results.filter(Boolean).length === units.length ? 'complete' : 'in_progress',
      resources: {decisions: gate.history, max_pause_s: job.resources?.max_pause_s || 300},
      not_checked: units.map(([target, page, variant], i) => results[i] ? null : {target: target.id, page: page.name, variant: variant || 'base'}).filter(Boolean)});
  };
  try {
    await checkpoint([], null);
    await pool(units, job.parallel || 3, async ([t, pg, v]) => {
      const b = await launch(t.engine, browsers);
      const r = await scanOne(b, t, pg, v, job, outDir);
      process.stderr.write(`[ux] ${r.status.toUpperCase().padEnd(4)} ${t.id} ${pg.name}${v ? ' [' + v + ']' : ''}\n`);
      return r;
    }, gate, checkpoint);
    return JSON.parse(fs.readFileSync(path.join(outDir, 'scan.json'), 'utf8'));
  } catch (error) {
    // Preserve the original failure if the checkpoint destination is also broken.
    try { await checkpoint(completed, null, true); } catch (_) {}
    throw error;
  } finally { await closeOwnedBrowsers(browsers); }
}

// ------------------------------------------------------------------ scripted flows
async function cmdFlows(job) {
  const outDir = job.out; mkdirp(outDir); const browsers = {}; const th = job.thresholds;
  const units = (job.flows || []).flatMap(flow => job.targets.filter(t => !flow.devices || flow.devices.includes(t.preset) || flow.devices.includes(t.id)).map(t => [flow, t]));
  const gate = resourceGate(job);
  let completed = [];
  const checkpoint = async (results, paused, failed = false) => {
    completed = results;
    const tools = await executionTools(browsers);
    writeJSON(path.join(outDir, 'flows.json'), {kind: 'flows', at: new Date().toISOString(), results: results.filter(Boolean), tools, provenance: executionProvenance(job, tools),
      run_status: failed ? 'error' : paused ? 'resource_paused' : results.filter(Boolean).length === units.length ? 'complete' : 'in_progress',
      resources: {decisions: gate.history, max_pause_s: job.resources?.max_pause_s || 300},
      not_checked: units.map(([flow, target], i) => results[i] ? null : {flow: flow.id, target: target.id}).filter(Boolean)});
  };
  try {
    await checkpoint([], null);
    await pool(units, 1, async ([flow, t]) => {
      const b = await launch(t.engine, browsers);
      const ctx = await newContext(b, t, job, flow.storage_state !== undefined ? { storageState: flow.storage_state } : {}); const page = await ctx.newPage(); const collect = attachCollectors(page, ctx);
      const touch = !!resolveTarget(t).hasTouch;
      const r = { flow: flow.id, persona: flow.persona || null, goal: flow.goal || '', target: t.id, engine: t.engine, steps: [], ok: true, friction: [] };
      const dir = path.join('flows', slug(flow.id), slug(t.id)); mkdirp(path.join(outDir, dir));
      const t0 = Date.now(); let n = 0;
      for (const s of flow.steps || []) {
        n++; const st = { n, step: s, ok: true, ms: 0 }; const s0 = Date.now();
        try {
          if (s.goto) await page.goto(new URL(s.goto, job.base_url).href, { waitUntil: 'networkidle', timeout: 30000 });
          for (const k of ['click', 'tap', 'check']) if (s[k]) {
            const loc = page.locator(s[k]).first(); await loc.waitFor({ state: 'visible', timeout: 10000 });
            const box = await loc.boundingBox();
            if (touch && box && Math.min(box.width, box.height) < th.tap_min) r.friction.push({ step: n, severity: 'medium', description: `mały cel dotyku w kroku ${n} (${Math.round(box.width)}x${Math.round(box.height)}px): ${s[k]}` });
            if (k === 'check') await loc.check({ timeout: 10000 }); else if (k === 'tap' && touch) await loc.tap({ timeout: 10000 }); else await loc.click({ timeout: 10000 });
          }
          if (s.fill) await page.locator(s.fill).first().fill(String(s.value ?? ''), { timeout: 10000 });
          if (s.select) await page.locator(s.select).first().selectOption(String(s.value ?? ''), { timeout: 10000 });
          if (s.press) await page.keyboard.press(s.press);
          if (s.wait) await page.waitForTimeout(s.wait);
          if (s.waitFor) await page.waitForSelector(s.waitFor, { timeout: 15000 });
          if (s.offline !== undefined) await ctx.setOffline(!!s.offline);
          if (s.download) {
            const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 15000 }), page.locator(s.download).first().click({ timeout: 10000 })]);
            const fp = path.join(outDir, dir, slug(dl.suggestedFilename())); await dl.saveAs(fp);
            st.download = { file: require('./paths.cjs').relative(outDir, fp), bytes: fs.statSync(fp).size };
            if (!st.download.bytes) throw new Error('pobrany plik jest pusty');
            if (s.expect_filename && !new RegExp(s.expect_filename).test(dl.suggestedFilename())) throw new Error(`nazwa pliku ${dl.suggestedFilename()} != /${s.expect_filename}/`);
          }
          if (s.expect) {
            const e = s.expect;
            if (e.text) await page.getByText(e.text, { exact: false }).first().waitFor({ state: 'visible', timeout: e.timeout || 10000 });
            if (e.text_re) await page.getByText(new RegExp(e.text_re, 'i')).first().waitFor({ state: 'visible', timeout: e.timeout || 10000 });
            if (e.selector) await page.locator(e.selector).first().waitFor({ state: 'visible', timeout: e.timeout || 10000 });
            if (e.url) { await page.waitForURL(new RegExp(e.url), { timeout: e.timeout || 10000 }); }
            if (e.no_text && await page.getByText(e.no_text).count()) throw new Error(`niepożądany tekst: ${e.no_text}`);
          }
          await page.waitForTimeout(100);
        } catch (e) {
          st.ok = false; st.error = String(e.message || e).split('\n')[0].slice(0, 300);
          if (s.expect && /Timeout/.test(st.error)) st.error = `nie pojawiło się: ${JSON.stringify(s.expect)} (${st.error})`.slice(0, 300);
        }
        st.ms = Date.now() - s0; st.url = page.url().replace(job.base_url.replace(/\/$/, ''), '');
        st.shot = path.join(dir, String(n).padStart(2, '0') + '.png');
        await page.screenshot({ path: path.join(outDir, st.shot) }).catch(() => { st.shot = null; });
        r.steps.push(st);
        if (!st.ok) { r.ok = false; r.failed_step = n; break; }
      }
      r.seconds = +((Date.now() - t0) / 1000).toFixed(1); r.collect = collect; r.external_blocked = [...ctx.__external];
      r.interactions = r.steps.filter((s) => ['click', 'tap', 'fill', 'select', 'check', 'download', 'press'].some((k) => s.step[k])).length;
      if (collect.page_errors.length) r.friction.push({ severity: 'high', description: `wyjątki JS w trakcie flow: ${collect.page_errors[0]}` });
      if (flow.max_interactions && r.interactions > flow.max_interactions) r.friction.push({ severity: 'medium', description: `${r.interactions} interakcji (limit ${flow.max_interactions})` });
      r.status = !r.ok ? 'fail' : r.friction.some((f) => f.severity === 'high') ? 'fail' : r.friction.length ? 'warn' : 'pass';
      process.stderr.write(`[ux] flow ${r.status.toUpperCase().padEnd(4)} ${flow.id} ${t.id} (${r.steps.length} kroków, ${r.seconds}s)\n`);
      await ctx.close(); return r;
    }, gate, checkpoint);
    return JSON.parse(fs.readFileSync(path.join(outDir, 'flows.json'), 'utf8'));
  } catch (error) {
    // Preserve the original failure if the checkpoint destination is also broken.
    try { await checkpoint(completed, null, true); } catch (_) {}
    throw error;
  } finally { await closeOwnedBrowsers(browsers); }
}

// ------------------------------------------------------------------ explorer server (one JSON command per line)
function domSummary() {
  const INTER = 'a[href],button,input:not([type=hidden]),select,textarea,summary,[role=button],[role=link],[role=tab],[role=menuitem],[role=checkbox],[onclick]';
  const els = [...document.querySelectorAll(INTER)].filter((el) => { const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    return r.width > 1 && r.height > 1 && cs.visibility !== 'hidden' && cs.display !== 'none'; });
  document.querySelectorAll('[data-helix-i]').forEach((e) => e.removeAttribute('data-helix-i'));
  const list = els.slice(0, 120).map((el, i) => { el.setAttribute('data-helix-i', i); const r = el.getBoundingClientRect();
    const lab = el.labels && el.labels[0] ? el.labels[0].innerText.trim() : '';
    return { i, tag: el.tagName.toLowerCase(), type: el.type || null, role: el.getAttribute('role'), name: (el.getAttribute('aria-label') || lab || el.placeholder || '').slice(0, 60),
      text: (el.innerText || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 60), disabled: !!el.disabled,
      in_view: r.top < innerHeight && r.bottom > 0, box: [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)] }; });
  return { url: location.pathname + location.search, title: document.title, elements: list,
    text: (document.body.innerText || '').trim().replace(/\n{2,}/g, '\n').slice(0, 2500) };
}

// Ekran startowy albo napis „Ładowanie...”: człowiek czeka, aż zniknie, i dopiero ocenia ekran (ta sama reguła co w ui-audit.mjs).
const LOADING_SELECTOR = '[aria-busy="true"],[role="progressbar"],.animate-spin,.animate-pulse,[class*="spinner" i],[class*="skeleton" i],[data-loading="true"]';
const LOADING_TEXT = '^(trwa\\s+)?(ładowanie|wczytywanie|pobieranie|loading|please wait|proszę czekać)(\\s+\\S+){0,3}\\s*(\\.{2,3}|…)$';
async function waitReady(page, ms = 8000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const busy = await page.evaluate(([selector, words]) => {
      const shown = (el) => { const box = el.getBoundingClientRect(), style = getComputedStyle(el);
        return box.width > 0 && box.height > 0 && style.visibility !== 'hidden' && style.display !== 'none' && box.bottom > 0 && box.top < innerHeight; };
      if ([...document.querySelectorAll(selector)].some(shown)) return true;
      const pattern = new RegExp(words, 'i'); const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
      const block = (el) => { while (el.parentElement && getComputedStyle(el).display.startsWith('inline')) el = el.parentElement; return el; };
      for (let node; (node = walker.nextNode());) if (node.nodeValue.length < 60 && pattern.test(node.nodeValue.trim()) && node.parentElement && shown(node.parentElement)
        && pattern.test((block(node.parentElement).innerText || '').trim())) return true;
      return false;
    }, [LOADING_SELECTOR, LOADING_TEXT]).catch(() => false);
    if (!busy) return true;
    await page.waitForTimeout(150);
  }
  return false;
}

async function cmdServe() {
  const rl = readline.createInterface({ input: process.stdin }); const browsers = {}; let ctx = null, page = null, job = null, collect = null;
  const reply = (o) => process.stdout.write(JSON.stringify(o) + '\n');
  for await (const line of rl) {
    if (!line.trim()) continue; let m; try { m = JSON.parse(line); } catch (e) { reply({ ok: false, error: 'bad json' }); continue; }
    try {
      if (m.cmd === 'open') {
        job = m.job; const b = await launch(m.target.engine, browsers);
        ctx = await newContext(b, m.target, job); page = await ctx.newPage(); collect = attachCollectors(page, ctx);
        await page.goto(new URL(m.path || '/', job.base_url).href, { waitUntil: 'networkidle', timeout: 30000 });
        await waitReady(page);
        reply({ ok: true, tools: await executionTools(browsers) });
      } else if (m.cmd === 'observe') {
        await page.waitForTimeout(200); await waitReady(page); const d = await page.evaluate(domSummary);
        if (m.shot) await page.screenshot({ path: m.shot });
        reply({ ok: true, ...d, js_errors: collect.page_errors.slice(-3) });
      } else if (m.cmd === 'act') {
        const loc = m.i != null ? page.locator(`[data-helix-i="${m.i}"]`) : null; const a = m.action;
        if (a === 'click') await loc.click({ timeout: 8000 });
        else if (a === 'fill') await loc.fill(String(m.value ?? ''), { timeout: 8000 });
        else if (a === 'select') await loc.selectOption({ label: String(m.value ?? '') }, { timeout: 8000 }).catch(() => loc.selectOption(String(m.value ?? '')));
        else if (a === 'check') await loc.check({ timeout: 8000 });
        else if (a === 'press') await page.keyboard.press(String(m.value || 'Enter'));
        else if (a === 'scroll') { const dy = +(m.value || 600); await page.mouse.wheel(0, dy).catch(() => page.evaluate((y) => window.scrollBy(0, y), dy)); }   // mobile WebKit: brak mouse.wheel
        else if (a === 'back') await page.goBack({ timeout: 8000 });
        else if (a === 'goto') await page.goto(new URL(String(m.value || '/'), job.base_url).href, { timeout: 15000 });
        else throw new Error('unknown action ' + a);
        await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
        reply({ ok: true });
      } else if (m.cmd === 'close') {
        if (ctx) await ctx.close(); ctx = null; reply({ ok: true, external_blocked: [] });
      } else if (m.cmd === 'quit') { reply({ ok: true }); break; }
      else reply({ ok: false, error: 'unknown cmd' });
    } catch (e) { reply({ ok: false, error: String(e.message || e).split('\n')[0].slice(0, 300), tools: await executionTools(browsers) }); }
  }
  for (const b of Object.values(browsers)) await (await b).close().catch(() => {});
}

async function cmdEngines() {
  const res = {};
  for (const n of ['chromium', 'webkit', 'firefox']) {
    try { const b = await playwright()[n].launch(); res[n] = b.version(); await b.close(); } catch (e) { res[n] = false; }
  }
  res.devices = Object.keys(playwright().devices).length; res.axe = fs.existsSync(AXE);
  console.log(JSON.stringify(res));
}

module.exports = { hostAllowed, resolveTarget, findingsFor, worst, layoutAudit, executionTools, executionProvenance, pool, resourceGate, cmdScan, cmdFlows };
if (require.main === module) {
  playwright();
  const [mode, jobFile] = process.argv.slice(2);
  const job = jobFile ? JSON.parse(fs.readFileSync(jobFile, 'utf8')) : null;
  if (job && job.base_url) {
    const h = new URL(job.base_url).hostname;
    if (!hostAllowed(h, job.allow_hosts)) { console.error(`refusing non-local base_url host ${h} (add to ux.allow_hosts only for staging, never production)`); process.exit(3); }
  }
  ({ engines: cmdEngines, scan: () => cmdScan(job), flows: () => cmdFlows(job), serve: cmdServe }[mode] || (() => { console.error('usage: ux.cjs engines|scan|flows|serve [job.json]'); process.exit(1); }))()
    .then(() => process.exit(0)).catch((e) => { console.error(e.stack || e); process.exit(1); });
}
