#!/usr/bin/env node
// Helix 2: isolated viewport runs, explicit evidence, sealed visual references.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, HELP } from './lib/config.mjs';
import { loadDependencies, launchBrowser } from './lib/dependencies.mjs';
import { hash, keyOf, renderContract, loadBaseline, baselineImage, comparePNG } from './lib/visual.mjs';
import { finalize, writeReport } from './lib/report.mjs';
import { auditDOM } from './dom-audit.mjs';

const cleanURL = value => {
  try { const u = new URL(value); u.username = ''; u.password = ''; u.search = ''; return u.href; } catch { return value; }
};
const message = error => String(error.message ?? error).slice(0, 1500);
let config, report, browser, lockPath, lockOwned = false, interrupted = false;
const contexts = new Set();
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
async function interrupt(signal) {
  if (interrupted) return;
  interrupted = true;
  if (report) report.errors.push(`Przerwano: ${signal}`);
  await Promise.allSettled([...contexts].map(c => c.close()));
  await browser?.close().catch(() => {});
}
process.once('SIGINT', () => void interrupt('SIGINT'));
process.once('SIGTERM', () => void interrupt('SIGTERM'));

const LOADING = '[aria-busy="true"],[role="progressbar"],.animate-spin,.animate-pulse,[class*="spinner" i],[class*="skeleton" i],[data-loading="true"]';
const LOADING_TEXT = /^(trwa\s+)?(ładowanie|wczytywanie|pobieranie|loading|please wait|proszę czekać)(\s+\S+){0,3}\s*(\.{2,3}|…)$/;
const STUCK_LOADING = new Set();

async function ready(page) {
  await page._networkQuiet();
  await page.evaluate(([a, t]) => document.documentElement.setAttribute(a, t), [config.themeAttr, page._helixTheme]);
  if (config.readySelector) await page.locator(config.readySelector).first().waitFor({ state: 'visible', timeout: config.gotoTimeout });
  // Fonts can complete after DOMContentLoaded; missing fonts invalidate reference evidence.
  const fonts = await page.evaluate(async timeout => {
    let timer;
    try {
      await Promise.race([document.fonts.ready, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Fonty nie są gotowe')), timeout); })]);
      return [...document.fonts].filter(f => f.status === 'error').map(f => f.family);
    } finally { clearTimeout(timer); }
  }, config.gotoTimeout);
  if (fonts.length) throw new Error(`Niezaładowane fonty: ${fonts.join(', ')}`);
  if (!page._helixStyle) {
    await page.addStyleTag({ content: '*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important;scroll-behavior:auto!important}' });
    page._helixStyle = true;
  }
  // Full-page evidence must include lazy images rather than silently skipping them.
  const missing = await page.evaluate(async ({ timeout, fullPage }) => {
    const imgs = [...document.images].filter(i => i.currentSrc || i.src);
    const relevant = imgs.filter(i => {
      const r = i.getBoundingClientRect();
      return r.width && r.height && getComputedStyle(i).visibility !== 'hidden' && (fullPage || r.top < innerHeight && r.bottom > 0);
    });
    for (const i of relevant) if (i.loading === 'lazy') i.loading = 'eager';
    await Promise.all(relevant.map(i => i.complete ? null : new Promise(resolve => {
      const done = () => { clearTimeout(timer); i.removeEventListener('load', done); i.removeEventListener('error', done); resolve(); };
      const timer = setTimeout(done, timeout);
      i.addEventListener('load', done, { once: true }); i.addEventListener('error', done, { once: true });
      if (i.complete) done();
    })));
    return relevant.filter(i => !i.complete || !i.naturalWidth).map(i => (i.currentSrc || i.src).split('?')[0]);
  }, { timeout: Math.min(config.gotoTimeout, 5000), fullPage: config.fullPage });
  if (config.wait) await page.waitForTimeout(config.wait);
  // Bounded DOM quiet period replaces a fixed 600ms wait and networkidle (which hangs on polling).
  await page.evaluate(({ settle, timeout, mask }) => new Promise((resolve, reject) => {
    let quiet;
    const stop = () => { observer.disconnect(); clearTimeout(quiet); clearTimeout(limit); };
    const changed = () => { clearTimeout(quiet); quiet = setTimeout(() => { stop(); resolve(); }, settle); };
    const observer = new MutationObserver(records => {
      if (records.some(record => { const el = record.target.nodeType === 1 ? record.target : record.target.parentElement; return !mask || !el?.closest(mask); })) changed();
    });
    const limit = setTimeout(() => { stop(); reject(new Error('DOM ciągle się zmienia; ustaw --ready-selector lub ustabilizuj dane')); }, timeout);
    observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true }); changed();
  }), { settle: config.settle, timeout: config.gotoTimeout, mask: config.mask });
  await page._networkQuiet();
  // Ekran startowy albo wskaźnik ładowania: człowiek czeka, aż zniknie, i dopiero ocenia ekran. Cisza DOM tego nie rozróżnia
  // (wskaźnik potrafi stać nieruchomo dłużej niż okres ciszy). Czekanie jest ograniczone; ekran, na którym wskaźnik zostaje
  // na stałe, jest oceniany taki, jaki jest, a przy kolejnych wejściach pod ten adres Helix już na niego nie czeka.
  const address = page.url();
  if (!STUCK_LOADING.has(address)) {
    // Wskaźnikiem bywa też sam napis („Ładowanie...”) bez animacji: liczy się tekst, który jest wyłącznie takim komunikatem.
    const busy = () => page.evaluate(([selector, words]) => {
      const shown = el => { const box = el.getBoundingClientRect(), style = getComputedStyle(el);
        return box.width > 0 && box.height > 0 && style.visibility !== 'hidden' && style.display !== 'none' && box.bottom > 0 && box.top < innerHeight; };
      if ([...document.querySelectorAll(selector)].some(shown)) return true;
      const pattern = new RegExp(words, 'i'), walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
      // Liczy się cały blok tekstu: słowo „Ładowanie...” w środku zdania (objaśnienie, etykieta) nie jest wskaźnikiem.
      const block = el => { while (el.parentElement && getComputedStyle(el).display.startsWith('inline')) el = el.parentElement; return el; };
      for (let node; (node = walker.nextNode());) if (node.nodeValue.length < 60 && pattern.test(node.nodeValue.trim()) && node.parentElement && shown(node.parentElement)
        && pattern.test((block(node.parentElement).innerText || '').trim())) return true;
      return false;
    }, [LOADING, LOADING_TEXT.source]);
    const until = Date.now() + Math.min(config.gotoTimeout, 8000); let waited = false;
    while (Date.now() < until && await busy()) { waited = true; await page.waitForTimeout(100); }
    if (waited && Date.now() >= until) STUCK_LOADING.add(address);
    if (waited) { await page.waitForTimeout(Math.max(200, config.settle)); await page._networkQuiet(); }
  }
  return missing;
}

async function stableShot(page) {
  const options = { fullPage: config.fullPage, animations: 'disabled', caret: 'hide', timeout: config.gotoTimeout,
    ...(config.mask ? { mask: [page.locator(config.mask)], maskColor: '#ff00ff' } : {}) };
  if (config.mask && await page.locator(config.mask).count() === 0) throw new Error('Maska nie pasuje do żadnego elementu');
  let previous = await page.screenshot(options);
  for (let i = 0; i < 3; i++) {
    await page.waitForTimeout(Math.max(50, config.settle));
    const current = await page.screenshot(options);
    if (previous.equals(current)) return current;
    previous = current;
  }
  throw new Error('Niestabilny zrzut: 4 kolejne obrazy są różne; zamroź dane lub jawnie zamaskuj zmienny fragment');
}

const NOTICES = '[data-sonner-toast], [role="region"][aria-label^="Notifications"] li, .Toastify__toast, [data-rht-toaster] > *, .MuiSnackbar-root, .notistack-Snackbar';
const UNSTABLE = /Wynik DOM zmienił się|Panel zmienił rozmiar|Niestabilny zrzut|Sieć nie jest gotowa|Żądania w toku/;
let shellSeen = new Set();
// Uwaga, którą już pokazał wcześniejszy stan tego przebiegu (np. zwinięte menu boczne przy każdym otwartym panelu), liczy się raz.
let stateSeen = new Set();
const LISTS = ['tap', 'contrast', 'clip', 'lead', 'edge', 'axis', 'gap', 'a11y'];
// Jedna definicja blokerów dla ekranu i dla okna otwartego od wejścia: żadna klasa usterki nie znika razem z zamkniętym oknem.
const defectsOf = dom => [...(dom.hscroll ? ['poziome przewijanie'] : []), ...Object.entries(dom.font).map(([k, v]) => `font: ${k}px ×${v.length}`),
  ...(dom.rhythm.length ? ['rytm: ' + dom.rhythm[0]] : []), ...LISTS.flatMap(k => dom[k].map(v => `${k}: ${v}`))];
// Podczas klikania aplikacja nie może niczego zmienić: odcinane są wszystkie żądania inne niż GET oraz żądania GET, których adres
// (ścieżka i parametry) wygląda na akcję (usunięcie, wylogowanie, anulowanie), także gdy jest zakodowany. Zasoby i zwykłe odczyty
// przechodzą. Akcji pod adresem neutralnym straż nie rozpozna; dlatego po każdym stanie sprawdzane jest, czy ekran nadal jest dostępny.
const ACTION = /log-?out|wylog|sign-?out|delete|usun|remove|destroy|revoke|cancel|anuluj|reset|unsubscribe|wypisz|archiv|archiw/i;
const readOnly = counter => route => {
  const request = route.request(); let target = '';
  try { const u = new URL(request.url()); target = decodeURIComponent(u.pathname + u.search); } catch { target = request.url(); }
  if (request.method() === 'GET' && !ACTION.test(target)) return route.fallback();
  // Funkcja z odpowiedzią syntetyczną niczego nie zapisuje (odpowiada przeglądarka): idzie do reguły odpowiedzi, nie jest odcinana.
  const stubs = functionStubs(), fn = (target.split('/functions/v1/')[1] || '').split(/[/?]/)[0];
  if (stubs && fn && Object.prototype.hasOwnProperty.call(stubs, fn)) return route.fallback();
  counter.cut++; return route.abort('blockedbyclient');
};
async function runCase(job, deps, baseline) {
  const started = performance.now(), timings = {};
  const result = { ...job, captures: [], status: 'incomplete', shot: null, errors: [], runtime: [], warn: [], visual: { status: 'not_checked' }, blockers: 0 };
  let context, page, timer, expired = false, documentNavigations = 0;
  let sink = result.runtime;
  const addRuntime = value => { if (sink.length < 200 && !sink.includes(value)) sink.push(value); };
  try {
    context = await browser.newContext({ viewport: { width: job.width, height: config.height }, deviceScaleFactor: config.dpr,
      colorScheme: job.theme, reducedMotion: 'reduce', locale: 'pl-PL', timezoneId: 'Europe/Warsaw',
      ...(config.storageState ? { storageState: config.storageState } : {}) });
    contexts.add(context);
    await routeFunctionStubs(context);
    timer = setTimeout(() => { expired = true; void context.close().catch(() => {}); }, config.runTimeout);
    // Dymek powiadomienia znika sam po kilku sekundach: człowiek czyta go i ogląda ekran pod spodem. Treść jest zapisywana jako uwaga,
    // a dymek ukrywany, żeby jego pojawienie się i zniknięcie nie zmieniało pomiaru ekranu między zdjęciami.
    await context.addInitScript(selector => {
      // Kolejka do odczytu jest opróżniana po każdym stanie; historia treści nie, żeby ten sam dymek nie został zgłoszony drugi raz.
      const seen = window.__helixNotices = [], known = new Set();
      const text = el => (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160);
      const take = el => {
        // '1' = czeka na pomiar wymiarów, '2' = zmierzony i ukryty (odtąd liczy się tylko zmiana treści).
        if (el.dataset.helixNotice === '1') return;
        if (el.dataset.helixNotice === '2') { const now = text(el); if (now && !known.has(now)) { known.add(now); seen.push({ text: now }); } return; }
        el.dataset.helixNotice = '1';
        // Wymiary dymka i jego przycisków są zapisywane przed ukryciem: za mały przycisk zamknięcia albo ucięty tekst zostają w raporcie.
        setTimeout(() => {
          const box = el.getBoundingClientRect(), size = r => `${Math.round(r.width)}×${Math.round(r.height)}`;
          const buttons = [...el.querySelectorAll('button, [role="button"], a[href]')].map(b => `${(b.getAttribute('aria-label') || b.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 30) || 'bez nazwy'} ${size(b.getBoundingClientRect())}`);
          const clipped = [el, ...el.querySelectorAll('*')].some(node => node.scrollWidth > node.clientWidth + 1 && getComputedStyle(node).overflowX !== 'visible');
          const now = text(el);
          if (now && !known.has(now)) { known.add(now); seen.push({ text: now, box: size(box), buttons, clipped }); }
          el.style.setProperty('display', 'none', 'important'); el.dataset.helixNotice = '2';
        }, 0);
      };
      new MutationObserver(() => document.querySelectorAll(selector).forEach(take)).observe(document, { childList: true, subtree: true, characterData: true });
    }, NOTICES);
    page = await context.newPage();
    page._helixTheme = job.theme;
    const pending = new Set(); let networkChanged = performance.now();
    const watched = req => !['websocket', 'eventsource', 'media'].includes(req.resourceType()) && !/\/favicon\.ico(?:\?|$)/.test(req.url());
    page.on('request', req => { if (watched(req)) { pending.add(req); networkChanged = performance.now(); } });
    const finished = req => { if (pending.delete(req)) networkChanged = performance.now(); };
    page.on('requestfinished', finished); page.on('requestfailed', finished);
    page._networkQuiet = async () => {
      const deadline = performance.now() + config.gotoTimeout;
      while (pending.size || performance.now() - networkChanged < config.settle) {
        if (performance.now() >= deadline) throw new Error(`Sieć nie jest gotowa: ${pending.size} żądań w toku`);
        await page.waitForTimeout(Math.min(50, config.settle));
      }
    };
    page._assertNetwork = () => { if (pending.size) throw new Error(`Żądania w toku podczas zapisu dowodów: ${pending.size}`); };
    const assertTarget = () => {
      result.finalURL = cleanURL(page.url());
      const canonical = value => { const u = new URL(value); u.pathname = u.pathname.replace(/\/$/, '') || '/'; return u.href; };
      if (canonical(page.url()) !== canonical(config.url)) throw new Error('Przekierowanie na inny ekran lub stan (np. logowanie); podaj prawidłowy URL i sesję przez --storage-state');
    };
    page.setDefaultTimeout(config.gotoTimeout);
    page.on('pageerror', error => addRuntime(`JS: ${message(error)}`));
    // 429 na ścieżce wskazanej przez właściciela (--throttled-paths) to ogranicznik zapytań uruchomiony tempem samego pomiaru, nie usterka ekranu.
    const throttled = value => { try { return config.throttled.includes(new URL(value).pathname); } catch { return false; } };
    // Zasób spod obcego adresu nie dociera, bo przeglądarka pomiarowa nie ma wyjścia do sieci: to ostrzeżenie o zależności
    // ekranu od zewnętrznego hosta, nie usterka aplikacji.
    const offsite = value => { try { return new URL(value).origin !== new URL(config.url).origin; } catch { return false; } };
    const outside = value => { const note = `Zasób z zewnętrznego hosta niedostępny w pomiarze: ${new URL(value).host}`; if (!result.warn.includes(note)) result.warn.push(note); };
    page.on('console', msg => { if (msg.type() === 'error' && /^Failed to load resource/.test(msg.text()) && offsite(msg.location()?.url)) return;
      if (msg.type() === 'error' && !/ERR_BLOCKED_BY_CLIENT/.test(msg.text()) && !(/status of 429\b/.test(msg.text()) && throttled(msg.location()?.url))) addRuntime(`console: ${msg.text().slice(0, 500)}`); });
    page.on('response', res => {
      if (res.status() === 429 && throttled(res.url())) result.warn.push(`Ogranicznik zapytań (429) przy tempie pomiaru: ${cleanURL(res.url())}`);
      else if (res.status() >= 400 && !/\/favicon\.ico(?:\?|$)/.test(res.url())) addRuntime(`HTTP ${res.status()}: ${cleanURL(res.url())}`);
    });
    page.on('requestfailed', req => {
      if (/\/favicon\.ico(?:\?|$)/.test(req.url()) || req.failure()?.errorText.includes('BLOCKED_BY_CLIENT')) return;
      if (offsite(req.url())) return outside(req.url());
      if (req.failure()?.errorText.includes('ERR_ABORTED') && ['fetch', 'xhr'].includes(req.resourceType())) result.warn.push(`Anulowane żądanie: ${cleanURL(req.url())}`);
      else addRuntime(`Sieć ${req.failure()?.errorText}: ${cleanURL(req.url())}`);
    });
    page.on('framenavigated', frame => { if (frame === page.mainFrame()) documentNavigations++; });
    page.on('websocket', ws => ws.on('framereceived', frame => {
      try { if (['update', 'full-reload'].includes(JSON.parse(String(frame.payload)).type)) result.errors.push('HMR zmienił aplikację w trakcie pomiaru; uruchom ponownie po zakończeniu edycji'); } catch {}
    }));
    const t0 = performance.now();
    const response = await page.goto(config.url, { waitUntil: 'domcontentloaded', timeout: config.gotoTimeout });
    timings.navigationMs = Math.round(performance.now() - t0);
    result.httpStatus = response?.status() ?? null; result.finalURL = cleanURL(page.url());

    const t1 = performance.now();
    const missing = await ready(page);
    for (const image of missing) addRuntime(`Brak obrazu: ${image}`);
    assertTarget();
    timings.readyMs = Math.round(performance.now() - t1);
    // Własna ramka aplikacji (ten sam origin, np. powłoka z kartami) jest mierzona razem z dokumentem;
    // zawartości obcej ramki (inny origin, sandbox) nie da się sprawdzić, więc zostaje błędem.
    const origin = new URL(page.url()).origin; let docs, foreign;
    const findDocs = async () => {
      docs = [page.mainFrame()]; foreign = 0;
      for (const doc of docs) for (const child of doc.childFrames()) {
        const shown = await (await child.frameElement()).evaluate(f => { const r = f.getBoundingClientRect(); return !f.closest('[data-helix-ignore]') && f.checkVisibility({ opacityProperty: true, visibilityProperty: true }) && r.width > 1 && r.height > 1; });
        if (!shown) continue;
        // Liczy się rzeczywisty origin dokumentu: ramka z sandbox ma origin nieprzejrzysty mimo adresu aplikacji.
        let own = false; try { own = await child.evaluate(() => window.origin) === origin; } catch {}
        if (own) docs.push(child); else foreign++;
      }
    };
    await findDocs();
    // Okno modalne otwarte od wejścia zasłania ekran: pomiar opisywałby okno, a nie ekran, i powtarzał te same uwagi na każdej trasie.
    const modal = () => {
      const shown = el => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 && !el.closest('[data-helix-ignore]') && el.checkVisibility({ opacityProperty: true, visibilityProperty: true }); };
      // Okno liczy się, gdy jest modalne albo gdy zajmuje środek ekranu (okno bez trybu modalnego też zasłania treść).
      const middle = document.elementFromPoint(innerWidth / 2, innerHeight / 2);
      const covers = e => { const r = e.getBoundingClientRect(); return r.width * r.height >= innerWidth * innerHeight * 0.15 && !!middle && e.contains(middle); };
      const el = [...document.querySelectorAll('dialog[open], [role="dialog"], [aria-modal="true"], [role="alertdialog"]')].find(e => shown(e)
        && ((e.tagName === 'DIALOG' ? e.matches(':modal') : e.getAttribute('aria-modal') === 'true' || e.getAttribute('role') === 'alertdialog') || covers(e)));
      if (!el) return null;
      const named = el.getAttribute('aria-label') || document.getElementById(el.getAttribute('aria-labelledby') || '')?.innerText || el.querySelector('h1,h2,h3')?.innerText || el.innerText || '';
      return named.replace(/\s+/g, ' ').trim().slice(0, 60) || el.tagName.toLowerCase();
    };
    const openModal = async () => (await Promise.all(docs.map(doc => doc.evaluate(modal)))).find(Boolean);
    const arrival = await openModal();
    const blank = (await Promise.all(docs.map(doc => doc.evaluate(() => !document.body?.innerText.trim() && !document.querySelector('img,svg,canvas,video'))))).every(Boolean);
    if (blank) result.errors.push('Pusty ekran nie jest dowodem poprawnego UI');
    if (foreign) result.errors.push('Widoczny iframe wymaga osobnego audytu jego URL; pomiar ramy nie sprawdza zawartości');
    if (docs.length > 1) result.frames = docs.length - 1;
    const auditArgs = [config.ladder, job.width >= 1024 ? config.tapDesktop : config.tap, config.leadMax, config.space];
    const measure = async () => {
      const parts = []; for (const doc of docs) parts.push(await doc.evaluate(auditDOM, auditArgs));
      const all = parts[0];
      for (const part of parts.slice(1)) for (const [key, value] of Object.entries(part)) {
        if (Array.isArray(value)) all[key].push(...value);
        else if (key === 'font') for (const [size, items] of Object.entries(value)) (all.font[size] ||= []).push(...items);
        else all[key] ||= value;
      }
      return all;
    };
    if (arrival) {
      // Okno jest mierzone raz jako osobny stan, potem zamykane tak, jak zamknąłby je człowiek: klawiszem Escape, a gdy to nie działa,
      // jego własnym przyciskiem (zapisy są na ten moment odcięte). Dopiero okno, którego nie da się zamknąć, zasłania ekran.
      result.arrival = { window: arrival, closed: null };
      const seen = await measure();
      const defects = defectsOf(seen);
      result.arrival.blockers = defects.length; result.arrival.findings = defects.slice(0, 20);
      if (job.states && !config.noShots) { result.arrival.shot = `arrival-${keyOf(job)}.png`; fs.writeFileSync(path.join(config.out, result.arrival.shot), await page.screenshot({ animations: 'disabled', caret: 'hide', timeout: config.gotoTimeout })); }
      const closing = { cut: 0 }, cutWrites = readOnly(closing), before = sink; sink = [];
      await context.route('**/*', cutWrites);
      await page.keyboard.press('Escape'); await page.waitForTimeout(config.settle + 200);
      if (!await openModal()) result.arrival.closed = 'Escape';
      else {
        const used = (await Promise.all(docs.map(doc => doc.evaluate(() => {
          const shown = el => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 && el.checkVisibility({ opacityProperty: true, visibilityProperty: true }); };
          const boxes = [...document.querySelectorAll('dialog[open], [role="dialog"], [aria-modal="true"], [role="alertdialog"]')].filter(shown);
          const box = boxes.find(e => e.tagName !== 'DIALOG' || e.matches(':modal')) || boxes[0];
          if (!box) return null;
          const name = el => (el.getAttribute('aria-label') || el.innerText || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
          const buttons = [...box.querySelectorAll('button, [role="button"]')].filter(el => shown(el) && !el.disabled);
          const pick = buttons.find(el => /^(zamknij|close|ok|rozumiem|zaczynamy|dalej|później|pomiń|anuluj|nie teraz|got it|skip|dismiss|×|x)$/i.test(name(el))) || (buttons.length === 1 ? buttons[0] : null);
          if (!pick) return null;
          pick.click(); return name(pick).slice(0, 40) || 'przycisk';
        })))).find(Boolean);
        await page.waitForTimeout(config.settle + 300);
        if (used && !await openModal()) result.arrival.closed = `przycisk „${used}”`;
      }
      if (!result.arrival.closed) {
        // Bramka zgody (wiek, regulamin, pliki cookie) nie ma przycisku zamknięcia: człowiek przechodzi ją, potwierdzając.
        // Zapisy do serwera są nadal odcięte; potwierdzenie zostaje w przeglądarce tej jednej próby.
        const agreed = (await Promise.all(docs.map(doc => doc.evaluate(() => {
          const shown = el => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 && el.checkVisibility({ opacityProperty: true, visibilityProperty: true }); };
          const boxes = [...document.querySelectorAll('dialog[open], [role="dialog"], [aria-modal="true"], [role="alertdialog"]')].filter(shown);
          const box = boxes.find(e => e.tagName !== 'DIALOG' || e.matches(':modal')) || boxes[0];
          if (!box) return null;
          const name = el => (el.getAttribute('aria-label') || el.innerText || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
          const pick = [...box.querySelectorAll('button, [role="button"], a[href]')].filter(el => shown(el) && !el.disabled)
            .find(el => /^(tak\b|akceptuj|zaakceptuj|zgadzam|potwierdzam|wchodzę|wejdź|przejdź dalej|kontynuuj|mam (ukończone )?18|yes\b|accept|agree|i agree|i am|enter\b|continue)/i.test(name(el)));
          if (!pick) return null;
          pick.click(); return name(pick).slice(0, 40);
        })))).find(Boolean);
        await page.waitForTimeout(config.settle + 300);
        if (agreed && !await openModal()) result.arrival.closed = `potwierdzenie „${agreed}”`;
      }
      // Po potwierdzeniu bramki zgody zapisy zostają odcięte do końca tej próby: skutek kliknięcia bywa opóźniony,
      // więc stała pauza nie jest granicą, za którą można je znów przepuścić.
      if (!String(result.arrival.closed).startsWith('potwierdzenie')) await context.unroute('**/*', cutWrites);
      sink = before;
      if (!result.arrival.closed) { result.obscured = arrival; throw new Error(`Ekran zasłonięty po wejściu przez okno „${arrival}”, którego nie da się zamknąć klawiszem Escape ani jego przyciskiem`); }
      result.warn.push(`Okno „${arrival}” otwarte po wejściu; zamknięte przed pomiarem (${result.arrival.closed})`);
      await findDocs();
    }
    // Powiadomienia zebrane od poprzedniego odczytu (ekran po wejściu albo jeden stan po kliknięciu); odczyt opróżnia listę.
    const notices = async () => (await Promise.all(docs.map(doc => doc.evaluate(() => (window.__helixNotices || []).splice(0)).catch(() => [])))).flat()
      .map(item => `Powiadomienie na ekranie (ukryte na czas pomiaru): „${item.text}”${item.box ? ` [${item.box}${item.buttons.length ? `; przyciski: ${item.buttons.join(', ')}` : ''}${item.clipped ? '; tekst ucięty' : ''}]` : ''}`);
    const beforeNavigation = documentNavigations;
    const t2 = performance.now();
    const dom = await measure();
    const runtimeWarn = result.warn;
    Object.assign(result, dom);
    result.warn = [...runtimeWarn, ...dom.warn];
    result.fontOffLadder = Object.entries(dom.font).map(([k, v]) => `${k}px ×${v.length} (np. ${v[0]})`); delete result.font;
    timings.domMs = Math.round(performance.now() - t2);
    result.blockers = (dom.hscroll ? 1 : 0) + result.fontOffLadder.length + (dom.rhythm.length ? 1 : 0)
      + ['tap', 'contrast', 'clip', 'lead', 'edge', 'axis', 'gap', 'a11y'].reduce((n, k) => n + dom[k].length, 0) + (result.arrival?.blockers ?? 0);
    if (!job.sweep && !config.noShots) {
      const t3 = performance.now();
      const capture = async id => {
        // Ekran, który sam odświeża dane, człowiek fotografuje między odświeżeniami: czekamy, aż żądanie w toku się skończy.
        await page._networkQuiet(); page._assertNetwork(); assertTarget();
        const buffer = await stableShot(page);
        page._assertNetwork(); assertTarget();
        const key = keyOf(job) + (id ? '-' + id : '');
        const item = { id, shot: `shot-${key}.png`, shotSha256: hash(buffer), visual: { status: 'not_checked' } };
        fs.writeFileSync(path.join(config.out, item.shot), buffer);
        if (baseline) {
          const t4 = performance.now();
          const expected = baselineImage(config.baseline, baseline, key);
          const { diffBuffer, ...details } = comparePNG(buffer, expected, deps.PNG, config);
          item.visual = details;
          item.expected = `expected-${key}.png`; fs.writeFileSync(path.join(config.out, item.expected), expected);
          if (diffBuffer) { item.diff = `diff-${key}.png`; fs.writeFileSync(path.join(config.out, item.diff), diffBuffer); }
          timings.comparisonMs = (timings.comparisonMs ?? 0) + Math.round(performance.now() - t4);
        }
        return item;
      };
      Object.assign(result, await capture(''));
      // fullPage cannot reveal clipped SPA panels. Capture their viewport at overlapping scroll offsets.
      const panels = config.fullPage ? await page.evaluate(() => {
        const elements = [...document.querySelectorAll('body *')].filter(el => {
          if (el.closest('[data-helix-ignore]')) return false;
          const st = getComputedStyle(el), r = el.getBoundingClientRect();
          return /auto|scroll/.test(st.overflowY) && el.scrollHeight > el.clientHeight + 1
            && r.width >= innerWidth * .4 && r.height >= innerHeight * .4
            && el.checkVisibility({ opacityProperty: true, visibilityProperty: true });
        });
        return elements.map((el, index) => {
          el.setAttribute('data-helix-scroll-id', String(index));
          return { index, top: el.scrollTop, height: el.clientHeight, total: el.scrollHeight };
        });
      }) : [];
      let scrollShots = 0;
      for (const panel of panels) {
        if (panel.top !== 0) throw new Error('Panel przewijania nie zaczyna się od góry; przygotuj stan początkowy');
        const step = Math.max(1, panel.height - 80), max = panel.total - panel.height;
        for (let offset = Math.min(step, max); ; offset = Math.min(offset + step, max)) {
          if (++scrollShots > 20) throw new Error('Ponad 20 zrzutów paneli na widok; podziel ekran na krótsze stany');
          await page.locator(`[data-helix-scroll-id="${panel.index}"]`).evaluate((el, y) => { el.scrollTop = y; }, offset);
          const scrollMissing = await ready(page);
          for (const image of scrollMissing) addRuntime(`Brak obrazu: ${image}`);
          const state = await page.locator(`[data-helix-scroll-id="${panel.index}"]`).evaluate(el => ({ top: el.scrollTop, total: el.scrollHeight }));
          if (Math.abs(state.top - offset) > 1 || state.total !== panel.total) throw new Error('Panel zmienił rozmiar/pozycję w trakcie przewijania; ustabilizuj dane');
          const item = await capture(`scroll-${panel.index}-${offset}`);
          item.scroll = { panel: panel.index, offset, height: panel.height, total: panel.total };
          result.captures.push(item);
          if (item.visual.status === 'mismatch') result.visual.status = 'mismatch';
          if (offset === max) break;
        }
        await page.locator(`[data-helix-scroll-id="${panel.index}"]`).evaluate(el => { el.scrollTop = 0; });
      }
      if (panels.length) await ready(page);
      if (baseline) {
        const captured = new Set([keyOf(job), ...result.captures.map(c => keyOf(job) + '-' + c.id)]);
        const missingCoverage = Object.keys(baseline.images).filter(key => key.startsWith(keyOf(job) + '-scroll-') && !captured.has(key));
        if (missingCoverage.length) result.visual = { status: 'mismatch', reason: 'scroll-coverage', missing: missingCoverage };
      }
      timings.screenshotMs = Math.round(performance.now() - t3);
    }
    assertTarget();
    if (documentNavigations !== beforeNavigation) result.errors.push('Dokument przeładowano podczas pomiaru');
    // Do not pair an earlier DOM measurement with a later rendering after data changes.
    const after = await measure();
    if (JSON.stringify(after) !== JSON.stringify(dom)) {
      const moved = Object.keys(after).filter(key => JSON.stringify(after[key]) !== JSON.stringify(dom[key]));
      // Przykład różnicy: pierwsza pozycja, która jest tylko w jednym z dwóch pomiarów.
      const flat = value => Array.isArray(value) ? value.map(String) : value && typeof value === 'object' ? Object.entries(value).flatMap(([k, v]) => [].concat(v).map(item => `${k}: ${item}`)) : [String(value)];
      const [was, now] = [flat(dom[moved[0]]), flat(after[moved[0]])];
      const sample = now.find(item => !was.includes(item)) ?? was.find(item => !now.includes(item)) ?? '';
      result.errors.push(`Wynik DOM zmienił się podczas zapisu dowodów (${moved.join(', ')}${sample ? `; np. ${sample.slice(0, 120)}` : ''})`);
    }
    for (const line of await notices()) result.warn.push(line);
    if (!result.errors.length) result.status = 'complete';
    if (job.states && result.status === 'complete') {
      // Stany ekranu: to, co widać dopiero po kliknięciu (panel boczny, okno, menu, zakładka). Każdy wyzwalacz jest klikany raz,
      // żądania inne niż GET są odcinane (kliknięcie niczego nie zapisze), a po każdym stanie ekran jest wczytywany od nowa.
      clearTimeout(timer);
      const deadline = performance.now() + config.statesTimeout; const sweep = { cut: 0 };
      timer = setTimeout(() => { expired = true; void context.close().catch(() => {}); }, config.statesTimeout + config.gotoTimeout);
      await context.route('**/*', readOnly(sweep));
      const selector = 'button, [role="button"], [role="tab"], summary, [aria-haspopup], [aria-expanded="false"], tbody tr, [role="row"]';
      // layer=true: tylko wyzwalacze wewnątrz najwyższej otwartej warstwy (okno, menu), do oglądania okien otwieranych z okna
      const list = ([selector, max, layer]) => {
        const shown = el => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 && el.checkVisibility({ opacityProperty: true, visibilityProperty: true }); };
        const main = document.querySelector('main, [role="main"]'), out = [], seen = new Set(), rows = new Set();
        const root = layer ? [...document.querySelectorAll('dialog[open], [role="dialog"], [role="alertdialog"], [aria-modal="true"], [role="menu"], [role="listbox"], [popover]:popover-open')].filter(shown).pop() : document;
        if (!root) return out;
        [...root.querySelectorAll(selector)].forEach((el, index) => {
          if (layer && (out.length >= max || /^(zamknij|close|anuluj|cancel|×|x)$/i.test((el.getAttribute('aria-label') || el.innerText || '').trim()))) return;
          if (!shown(el) || el.disabled || el.getAttribute('aria-disabled') === 'true' || (el.type === 'submit' && el.form)) return;
          if (el.closest('a[href], [data-helix-ignore]') || el.matches('[role="tab"][aria-selected="true"]')) return;
          // Wiersz listy otwierany kliknięciem (bez odnośnika) prowadzi na ekran szczegółów: klikamy pierwszy taki wiersz każdej listy.
          const row = el.matches('tbody tr, [role="row"]');
          if (row && (layer || getComputedStyle(el).cursor !== 'pointer' || el.querySelector('a[href]') || rows.has(el.parentElement))) return;
          if (row) rows.add(el.parentElement);
          const name = (row ? 'wiersz listy: ' : '') + (el.getAttribute('aria-label') || el.innerText || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim().slice(0, row ? 30 : 50);
          // Wylogowanie bywa zwykłą nawigacją GET: kliknięte zamknęłoby sesję wszystkim kolejnym ekranom przebiegu.
          if (/wylog|log\s?out|sign\s?out|zakończ sesję/i.test(name)) return;
          if (name && !seen.has(name)) { seen.add(name); out.push({ index, name, shell: !!main && !main.contains(el) }); }
        });
        return out;
      };
      const press = ([selector, index, name, layer]) => {
        const shown = el => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 && el.checkVisibility({ opacityProperty: true, visibilityProperty: true }); };
        const root = layer ? [...document.querySelectorAll('dialog[open], [role="dialog"], [role="alertdialog"], [aria-modal="true"], [role="menu"], [role="listbox"], [popover]:popover-open')].filter(shown).pop() : document;
        const el = root && root.querySelectorAll(selector)[index];
        const row = el && el.matches('tbody tr, [role="row"]');
        const label = el && (row ? 'wiersz listy: ' : '') + (el.getAttribute('aria-label') || el.innerText || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim().slice(0, row ? 30 : 50);
        if (label !== name) return false;
        el.click(); return true;
      };
      const layers = () => {
        const shown = el => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 && el.checkVisibility({ opacityProperty: true, visibilityProperty: true }); };
        const count = q => [...document.querySelectorAll(q)].filter(shown).length;
        return { dialog: count('dialog[open], [role="dialog"], [role="alertdialog"], [aria-modal="true"]'), menu: count('[role="menu"], [role="listbox"], [popover]:popover-open'),
          tab: [...document.querySelectorAll('[role="tab"][aria-selected="true"]')].map(el => el.innerText.trim()).join('|'),
          open: count('[aria-expanded="true"], details[open]'), text: document.body.innerText.length,
          flags: [...document.querySelectorAll('[aria-sort], [aria-pressed], [aria-checked], [aria-current], [aria-selected="true"]')].map(el => ['aria-sort', 'aria-pressed', 'aria-checked', 'aria-current'].map(a => el.getAttribute(a) || '').join(',')).join(';') };
      };
      const snapshot = async () => { const parts = await Promise.all(docs.map(doc => doc.evaluate(layers))); return parts.reduce((a, b) => ({ dialog: a.dialog + b.dialog, menu: a.menu + b.menu, tab: a.tab + '/' + b.tab, open: a.open + b.open, text: a.text + b.text, flags: a.flags + '/' + b.flags })); };
      const known = new Set(['tap', 'contrast', 'clip', 'lead', 'edge', 'axis', 'gap', 'a11y'].flatMap(k => dom[k].map(v => `${k}: ${v}`)));
      const canonicalNow = () => { const u = new URL(page.url()); return u.origin + (u.pathname.replace(/\/$/, '') || '/'); };
      const home = canonicalNow();
      result.states = [];
      try {
        // Wyzwalacze wspólnej powłoki (menu boczne, górny pasek) są takie same na każdym ekranie: oglądane raz na przebieg i szerokość.
        const targets = []; let found = 0;
        for (let d = 0; d < docs.length; d++) for (const t of await docs[d].evaluate(list, [selector, config.states])) {
          if (targets.some(x => x.name === t.name)) continue;
          found++;
          const key = `${job.width}:${t.name}`;
          if (t.shell) { if (shellSeen.has(key)) continue; shellSeen.add(key); }
          if (targets.length < config.states) targets.push({ ...t, doc: d });
        }
        result.statesFound = found; result.statesSkipped = found - targets.length;
        // Kolejka rośnie o wyzwalacze znalezione w otwartym oknie albo menu (jeden poziom w głąb): okno otwierane z okna też jest oglądane.
        const queue = [...targets]; let nested = 0;
        // Każde ponowne wczytanie sprawdza, czy ekran nadal odpowiada pod swoim adresem (zamknięta sesja, zmienione dane): inaczej dalsze stany nic nie znaczą.
        const reload = async after => {
          await page.goto(config.url, { waitUntil: 'domcontentloaded', timeout: config.gotoTimeout }); await page.waitForTimeout(config.settle + 400); await findDocs();
          if (canonicalNow() !== home) throw new Error(`po kliknięciu „${after}” ekran nie jest już dostępny pod swoim adresem; przegląd stanów przerwany`);
        };
        for (let position = 0; position < queue.length; position++) {
          const target = queue[position];
          const title = target.parent ? `${target.parent.name} › ${target.name}` : target.name;
          if (performance.now() > deadline) { result.states.push({ trigger: title, kind: 'not-run', reason: 'limit czasu stanów' }); continue; }
          const state = { trigger: title, kind: 'no-change', runtime: [], findings: [], blockers: 0, ...(target.shell ? { shell: true } : {}), ...(target.parent ? { nested: true } : {}) };
          result.states.push(state); sink = state.runtime;
          if (target.parent) {
            // najpierw ponownie otwieramy okno nadrzędne
            if (!await docs[target.parent.doc]?.evaluate(press, [selector, target.parent.index, target.parent.name, false])) { state.kind = 'not-run'; state.reason = 'okno nadrzędne nie otworzyło się ponownie'; await reload(title); continue; }
            await page.waitForTimeout(config.settle + 400); await findDocs();
          }
          const before = await snapshot(); const cutBefore = sweep.cut; let chooser = false, download = false;
          const onChooser = () => { chooser = true; }, onDownload = item => { download = true; void item.cancel().catch(() => {}); };
          page.once('filechooser', onChooser); page.on('download', onDownload);
          let pressed = false;
          // wyzwalacz z okna jest klikany wyłącznie w dokumencie, w którym został znaleziony
          if (target.parent) pressed = !!docs[target.doc] && await docs[target.doc].evaluate(press, [selector, target.index, target.name, true]);
          else pressed = await docs[target.doc].evaluate(press, [selector, target.index, target.name, false]);
          if (!pressed) { page.off('filechooser', onChooser); page.off('download', onDownload); state.kind = 'not-run'; state.reason = 'wyzwalacz zmienił miejsce po wczytaniu'; if (target.parent) await reload(title); continue; }
          await page.waitForTimeout(config.settle + 400);
          page.off('filechooser', onChooser); page.off('download', onDownload);
          if (canonicalNow() !== home) { state.kind = 'navigation'; state.target = new URL(page.url()).pathname; }
          else {
            await findDocs(); const after = await snapshot();
            state.kind = after.dialog > before.dialog ? 'dialog' : after.menu > before.menu ? 'menu' : after.tab !== before.tab ? 'tab' : after.open > before.open || after.text !== before.text ? 'expanded'
              : chooser ? 'file-chooser' : download ? 'download' : sweep.cut > cutBefore ? 'write-cut' : after.flags !== before.flags ? 'toggled' : 'no-change';
            if (['dialog', 'menu', 'tab', 'expanded'].includes(state.kind)) {
              const seen = await measure();
              state.findings = ['tap', 'contrast', 'clip', 'lead', 'edge', 'axis', 'gap', 'a11y'].flatMap(k => seen[k].map(v => `${k}: ${v}`)).filter(v => !known.has(v));
              state.repeated = state.findings.filter(v => stateSeen.has(`${job.width}|${v}`)).length;
              state.findings = state.findings.filter(v => !stateSeen.has(`${job.width}|${v}`)); for (const v of state.findings) stateSeen.add(`${job.width}|${v}`);
              state.blockers = state.findings.length; state.findings = state.findings.slice(0, 10);
              if (!target.parent && ['dialog', 'menu'].includes(state.kind) && nested < 30) {
                for (let d = 0; d < docs.length; d++) for (const inner of await docs[d].evaluate(list, [selector, config.statesNested, true])) {
                  if (nested >= 30 || queue.some(item => item.parent === target && item.doc === d && item.name === inner.name)) continue;
                  queue.push({ ...inner, shell: false, doc: d, parent: target }); nested++;
                }
              }
              if (!config.noShots) { state.shot = `state-${keyOf(job)}-${result.states.length}.png`; fs.writeFileSync(path.join(config.out, state.shot), await page.screenshot({ animations: 'disabled', caret: 'hide', timeout: config.gotoTimeout })); }
            }
          }
          // Błąd po kliknięciu jest usterką także wtedy, gdy nic widocznego się nie otworzyło albo ekran przeszedł gdzie indziej.
          state.blockers += state.runtime.length;
          const shown = await notices(); if (shown.length) state.notices = shown;
          await reload(title);
        }
      } catch (error) {
        result.statesIncomplete = expired ? 'limit czasu stanów' : message(error).slice(0, 200);
        result.states.push({ kind: 'not-run', reason: result.statesIncomplete }); result.warn.push(`Przegląd stanów przerwany: ${result.statesIncomplete}`);
      }
      sink = [];
      result.blockedWrites = sweep.cut;
      result.stateBlockers = result.states.reduce((n, state) => n + (state.blockers ?? 0), 0);
      result.blockers += result.stateBlockers;
    }
  } catch (error) { result.errors.push(expired ? `Limit ${config.runTimeout} ms na szerokość` : message(error)); }
  finally {
    clearTimeout(timer);
    if (context) { await context.close().catch(() => {}); contexts.delete(context); }
    result.blockers += result.runtime.length;
    if (result.errors.length) console.error(`${job.theme}/${job.width}: ${result.errors.join(' | ')}`);
    result.durationMs = Math.round(performance.now() - started); result.timings = timings;
  }
  return result;
}

try {
  config = parseArgs(process.argv.slice(2));
  if (config.help) { console.log(HELP); process.exit(0); }
  fs.mkdirSync(config.out, { recursive: true });
  if (config.baseline) {
    const realOut = fs.realpathSync(config.out), realBase = fs.realpathSync(config.baseline);
    if (realOut === realBase || realOut.startsWith(realBase + path.sep)) throw new Error('Wyniki nie mogą nadpisać wzorca (także przez symlink)');
  }
  lockPath = path.join(config.out, '.helix-lock');
  fs.writeFileSync(lockPath, `${process.pid}\n`, { flag: 'wx' }); lockOwned = true;
  const jobs = config.themes.flatMap((theme, i) => [
    ...config.widths.map(width => ({ theme, width, sweep: false, ...(config.states && i === 0 && [Math.max(...config.widths), Math.min(...config.widths)].includes(width) ? { states: true } : {}) })),
    ...(i === 0 || config.sweepThemes === 'all' ? config.extra.map(width => ({ theme, width, sweep: true })) : []),
  ]);
  const localFile = config.url.startsWith('file:') ? fileURLToPath(config.url) : null;
  const sourceHash = localFile ? hash(fs.readFileSync(localFile)) : null;
  const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
  const toolFiles = ['ui-audit.mjs', 'dom-audit.mjs', ...fs.readdirSync(path.join(scriptRoot, 'lib')).filter(f => f.endsWith('.mjs')).sort().map(f => 'lib/' + f)];
  const toolchainHash = () => hash(Buffer.concat(toolFiles.map(f => fs.readFileSync(path.join(scriptRoot, f)))));
  const toolHash = toolchainHash();
  report = { schemaVersion: 2, generated: new Date().toISOString(), _started: performance.now(),
    url: cleanURL(config.url), caseId: config.caseId, ladder: config.ladder,
    config: { widths: config.widths, extra: config.extra, themes: config.themes, workers: config.workers, noShots: config.noShots,
      readySelector: config.readySelector, wait: config.wait, settle: config.settle, sweepThemes: config.sweepThemes,
      pixelThreshold: config.pixelThreshold, maxDiffPixels: config.maxDiffPixels, maxDiffRatio: config.maxDiffRatio,
      tap: config.tap, tapDesktop: config.tapDesktop, space: config.space, leadMax: config.leadMax,
      gotoTimeout: config.gotoTimeout, runTimeout: config.runTimeout, sessionProvided: !!config.storageState },
    source: { fileSha256: sourceHash, toolchainSha256: toolHash },
    planned: jobs.length, errors: [], runs: [], baseline: config.baseline ? { path: config.baseline, status: 'loading' } : null,
  };
  finalize(report, false); writeReport(report, config.out);
  const deps = loadDependencies();
  if (config.baseline && !deps.PNG) throw new Error('Brak pngjs obok Playwright; ustaw HELIX_PNG_MODULE');
  browser = await launchBrowser(deps.chromium);
  report.contract = renderContract(config, { browser: browser.version(), playwright: deps.playwrightVersion, platform: process.platform, arch: process.arch });
  const baseline = config.baseline ? loadBaseline(config.baseline, report.contract, config.caseId) : null;
  if (baseline) {
    report.baseline = { path: config.baseline, approval: baseline.approval };
    if (!deps.PNG) throw new Error('Brak pngjs obok Playwright; nie można porównać wzorca');
    // Validate ALL requested baseline images before navigating anything.
    for (const job of jobs.filter(j => !j.sweep)) baselineImage(config.baseline, baseline, keyOf(job));
  }
  if (config.statesSeen && fs.existsSync(config.statesSeen)) {
    const stored = JSON.parse(fs.readFileSync(config.statesSeen, 'utf8'));
    shellSeen = new Set(Array.isArray(stored) ? stored : stored.shell); stateSeen = new Set(Array.isArray(stored) ? [] : stored.findings);
  }
  // Trasa, która odsyła na inny ekran (logowanie), odeśle tak samo przy każdej szerokości: kolejne pomiary nic nie wnoszą.
  let next = 0, redirected = false;
  await Promise.all(Array.from({ length: Math.min(config.workers, jobs.length) }, async () => {
    while (!interrupted && !redirected) {
      const index = next++;
      if (index >= jobs.length) return;
      let result = await runCase(jobs[index], deps, baseline);
      // Ekran, który zmienił się w trakcie jednego pomiaru (dane doszły później, lista się odświeżyła), człowiek obejrzałby jeszcze raz.
      // Kolejny pomiar zaczyna od nowego wczytania; dopiero zmiana w trzech podejściach z rzędu jest cechą ekranu.
      for (let again = 0; again < 2 && !interrupted && result.errors.length && result.errors.every(e => UNSTABLE.test(String(e))); again++) {
        // Wynik odrzuconego podejścia zostaje w raporcie, a jego zdjęcia są usuwane, żeby nie uchodziły za dowód kolejnego.
        const first = result.errors[0], history = [...(result.attempts || []), { errors: result.errors, blockers: result.blockers, runtime: result.runtime, warn: result.warn.filter(line => line.startsWith('Powiadomienie')) }];
        for (const name of [result.shot, result.expected, result.diff, result.arrival?.shot, ...result.captures.flatMap(c => [c.shot, c.expected, c.diff])]) if (name) fs.rmSync(path.join(config.out, name), { force: true });
        result = await runCase(jobs[index], deps, baseline);
        result.attempts = history;
        if (!result.errors.length) result.warn.push(`Pomiar powtórzony (${again + 1}×): ${first}`);
      }
      report.runs[index] = result;
      if (!redirected && result.errors.some(e => /Przekierowanie na inny ekran|Ekran zasłonięty po wejściu/.test(String(e)))) {
        redirected = true; report.errors.push(`${result.obscured ? 'Ekran zasłonięty oknem' : 'Trasa odsyła na inny ekran'}; pominięto pozostałe pomiary (${jobs.length - next > 0 ? jobs.length - next : 0} z ${jobs.length})`);
      }
      finalize(report, false); writeReport(report, config.out, false);
      console.log(`${result.errors.length ? 'NIEKOMPLETNY' : result.blockers || result.visual.status === 'mismatch' ? 'BŁĄD' : 'OK'} ${result.theme} ${result.width}px${result.sweep ? ' sweep' : ''} · ${result.blockers} blokerów · ${result.errors.length} błędów wykonania · wzorzec:${result.visual.status} · ${result.durationMs}ms`);
    }
  }));
  for (const width of config.widths) {
    const sameWidth = report.runs.filter(r => r?.width === width && r.shotSha256);
    if (sameWidth.length === 2 && sameWidth[0].shotSha256 === sameWidth[1].shotSha256) sameWidth.forEach(r => r.warn.push('Jasny i ciemny motyw mają identyczny obraz; sprawdź przełączanie motywu'));
  }
  if (config.statesSeen) fs.writeFileSync(config.statesSeen, JSON.stringify({ shell: [...shellSeen], findings: [...stateSeen] }));
  if (toolchainHash() !== toolHash) report.errors.push('Kod Helixa zmienił się w trakcie audytu');
  if (localFile && hash(fs.readFileSync(localFile)) !== sourceHash) report.errors.push('Plik źródłowy zmienił się w trakcie audytu');
  process.exitCode = finalize(report, !interrupted && report.runs.filter(Boolean).length === jobs.length);
} catch (error) {
  console.error(`Helix: ${message(error)}`);
  if (report) { report.errors.push(message(error)); finalize(report, false); }
  process.exitCode = 2;
} finally {
  const cleanupStarted = performance.now();
  await browser?.close().catch(error => { if (report && !interrupted) report.errors.push(`Zamknięcie przeglądarki: ${message(error)}`); });
  if (report) {
    report.cleanupMs = Math.round(performance.now() - cleanupStarted);
    report.cleanupForced = !!browser?.helixCleanup?.forced;
    process.exitCode = finalize(report, !interrupted && report.runs.filter(Boolean).length === report.planned);
    writeReport(report, config.out);
    console.log(`Helix: ${report.summary.status}; zgodność wyglądu: ${report.summary.visual}; ${(report.durationMs / 1000).toFixed(1)}s → ${path.join(config.out, 'report.html')}`);
  }
  if (lockOwned) {
    try { fs.unlinkSync(lockPath); }
    catch (error) {
      const problem = `Nie udało się zwolnić blokady: ${error.message}`;
      console.error(problem);
      if (report) { report.errors.push(problem); finalize(report, false); writeReport(report, config.out); }
      process.exitCode = 2;
    }
  }
}
// All contexts and browser have been awaited. Driver timers must not keep a finished CLI alive.
process.exit(process.exitCode ?? 0);
