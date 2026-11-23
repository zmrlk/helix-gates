// Helix UI consistency runner (Playwright). Mode:
//   node consistency.cjs scan <job.json>  -> <out>/raw.json + full-page screenshots (pages x targets)
// Extracts computed-style fingerprints of UI components by role (button, input, select, checkbox, badge, alert/toast,
// table, heading, icon, card, dialog/drawer, nav/header/footer/bottom-nav, empty/loading/error states), UI copy,
// API error texts and the 'details' pattern. Analysis (clustering, drift, patterns, copy) is done in helix_consistency.py.
'use strict';
const fs = require('fs'), path = require('path');
const resolveDependency = require('./dependencies.cjs');
const PW = resolveDependency('playwright');
const pw = require(PW);
const LOCAL = ['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'];
const okHost = (h, allow) => LOCAL.includes((h || '').toLowerCase()) || /\.(localhost|local|test)$/.test(h) || (allow || []).includes(h);
const slug = (s) => String(s).replace(/[^\w.-]+/g, '_');

function targetOpts(t) {
  if (t.pw_device) { const d = pw.devices[t.pw_device]; if (!d) throw new Error('unknown device ' + t.pw_device); const o = { ...d }; delete o.defaultBrowserType; return o; }
  const [w, h] = t.viewport || [1440, 900];
  return { viewport: { width: w, height: h }, deviceScaleFactor: t.deviceScaleFactor || 1, isMobile: !!t.isMobile, hasTouch: !!t.hasTouch, ...(t.userAgent ? { userAgent: t.userAgent } : {}) };
}

// ------------------------------------------------------------------ in-page extractor (serialised into the page)
function EXTRACT(opt) {
  const vw = innerWidth, vh = innerHeight, sx = scrollX, sy = scrollY, OUT = [];
  const _cv = document.createElement('canvas'); _cv.width = _cv.height = 1; const _cx = _cv.getContext('2d', { willReadFrequently: true }); const _cc = new Map();
  const norm = (c) => { if (!c || c === 'transparent') return 'rgba(0,0,0,0)'; if (/^rgba?\(/.test(c) && !/\//.test(c)) return c; if (_cc.has(c)) return _cc.get(c);
    _cx.clearRect(0, 0, 1, 1); _cx.fillStyle = '#000'; _cx.fillStyle = c; _cx.fillRect(0, 0, 1, 1); const d = _cx.getImageData(0, 0, 1, 1).data;
    const v = d[3] === 0 ? 'rgba(0,0,0,0)' : `rgba(${d[0]},${d[1]},${d[2]},${+(d[3] / 255).toFixed(2)})`; _cc.set(c, v); return v; };
  const rgba = (c) => { c = norm(c); const m = String(c).match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
  const transparent = (c) => { const v = rgba(c); return !v || v[3] < 0.04; };
  const hsl = (c) => { const v = rgba(c); if (!v) return null; let [r, g, b] = v.map((x, i) => i < 3 ? x / 255 : x); const mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2; let h = 0, s = 0;
    if (mx !== mn) { const d = mx - mn; s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h *= 60; } return { h, s, l, a: v[3] }; };
  const visible = (el) => { const r = el.getBoundingClientRect(); if (r.width < 1 || r.height < 1) return false; const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || +cs.opacity < 0.05) return false; if (el.closest('[aria-hidden=true]') && !el.matches('svg')) return false; return true; };
  const text = (el) => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
  const label = (el) => (text(el) || el.getAttribute('aria-label') || el.getAttribute('title') || el.value || el.getAttribute('placeholder') || '').replace(/\s+/g, ' ').trim().slice(0, 80);
  const rect = (el) => { const r = el.getBoundingClientRect(); return [Math.round(r.left + sx), Math.round(r.top + sy), Math.round(r.width), Math.round(r.height)]; };
  const cssPath = (el) => { const parts = []; let e = el; for (let i = 0; e && e.nodeType === 1 && i < 5; i++, e = e.parentElement) { let s = e.tagName.toLowerCase(); if (e.id) { parts.unshift(s + '#' + e.id); break; }
      const sib = e.parentElement ? [...e.parentElement.children].filter((x) => x.tagName === e.tagName) : []; if (sib.length > 1) s += `:nth-of-type(${sib.indexOf(e) + 1})`; parts.unshift(s); } return parts.join('>'); };
  const iconOf = (el) => { const cands = el.matches('svg') ? [el] : [...el.querySelectorAll('svg, img, i[class*=icon], span[class*=icon]')].filter((x) => !x.parentElement.closest('svg'));
    const s = cands.find((x) => { const r = x.getBoundingClientRect(); return visible(x) && r.width <= 48 && r.height <= 48; }); if (!s) return null; const r = s.getBoundingClientRect();
    const cs = getComputedStyle(s); let set = s.tagName.toLowerCase();
    if (set === 'svg') set = `svg vb=${s.getAttribute('viewBox') || '-'} ${s.getAttribute('fill') === 'none' || cs.fill === 'none' ? 'stroke' : 'fill'} sw=${s.getAttribute('stroke-width') || (cs.fill === 'none' ? parseFloat(cs.strokeWidth) : '-')}`;
    return { w: Math.round(r.width), h: Math.round(r.height), set, cls: (s.getAttribute('class') || '').toString().slice(0, 60), color: norm(cs.color) }; };
  const st = (el) => { const cs = getComputedStyle(el), r = el.getBoundingClientRect(); return {
    fs: +parseFloat(cs.fontSize).toFixed(2), fw: +cs.fontWeight || 400, ff: cs.fontFamily.split(',')[0].replace(/["']/g, '').trim(), lh: cs.lineHeight === 'normal' ? 'normal' : +parseFloat(cs.lineHeight).toFixed(1),
    color: norm(cs.color), bg: norm(cs.backgroundColor), bgimg: cs.backgroundImage !== 'none', radius: Math.min(9999, +parseFloat(cs.borderTopLeftRadius).toFixed(1)), bw: +parseFloat(cs.borderTopWidth).toFixed(1),
    bc: transparent(cs.borderTopColor) || parseFloat(cs.borderTopWidth) === 0 ? null : norm(cs.borderTopColor), pt: parseFloat(cs.paddingTop), pr: parseFloat(cs.paddingRight), pb: parseFloat(cs.paddingBottom), pl: parseFloat(cs.paddingLeft),
    h: Math.round(r.height), w: Math.round(r.width), shadow: cs.boxShadow !== 'none', tt: cs.textTransform, ls: cs.letterSpacing, gap: cs.gap === 'normal' ? null : cs.gap, pos: cs.position, display: cs.display, ul: cs.textDecorationLine.includes('underline') }; };
  const ctxOf = (el) => el.closest('[role=dialog],[role=alertdialog],dialog') ? 'dialog' : el.closest('header,[role=banner]') ? 'header' : el.closest('nav,aside,[role=navigation]') ? 'nav' : el.closest('footer') ? 'footer' : el.closest('table,[role=table],[role=grid]') ? 'table' : 'main';
  const srcOf = (el) => { try {
      const m = el.__svelte_meta; if (m) { const own = m.loc || m.parent; let u = m.parent; const ownFile = own && own.file;
        while (u && !(u.type === 'component' && u.file !== ownFile)) u = u.parent;
        return { src: own ? `${own.file}:${own.line}` : null, used_in: u ? `${u.file}:${u.line}` : null }; }
      const fk = Object.keys(el).find((k) => k.startsWith('__reactFiber$')); if (fk) { let f = el[fk]; while (f && !f._debugSource) f = f.return; if (f) return { src: `${f._debugSource.fileName}:${f._debugSource.lineNumber}`, used_in: null }; }
      const v = el.__vueParentComponent; if (v && v.type && v.type.__file) return { src: v.type.__file, used_in: null };
    } catch (_) {} return null; };
  const push = (role, el, extra) => { if (OUT.length > opt.max) return; OUT.push({ role, tag: el.tagName.toLowerCase(), label: label(el), rect: rect(el), sel: cssPath(el), ctx: ctxOf(el), cls: (el.getAttribute('class') || '').toString().slice(0, 200), style: st(el), icon: iconOf(el), comp: (el.closest('[data-hx-c],[data-component]') || { getAttribute: () => null }).getAttribute('data-hx-c') || (el.closest('[data-component]') || { getAttribute: () => null }).getAttribute('data-component'), ...(srcOf(el) || {}), ...(extra || {}) }); };
  const seen = new Set();
  // buttons / button-like links
  for (const el of document.querySelectorAll('button, [role=button], a[href], input[type=submit], input[type=button]')) {
    if (!visible(el) || seen.has(el)) continue; seen.add(el); const cs = getComputedStyle(el);
    const filled = !transparent(cs.backgroundColor) || cs.backgroundImage !== 'none', bordered = parseFloat(cs.borderTopWidth) > 0 && !transparent(cs.borderTopColor);
    const isBtn = el.tagName !== 'A' || ((filled || bordered) && parseFloat(cs.paddingLeft) >= 4 && cs.display !== 'inline');
    const lab = label(el), ic = iconOf(el); const h = hsl(cs.backgroundColor), fg = hsl(cs.color);
    let variant = 'ghost';
    if (!lab.replace(/[^\p{L}\p{N}]/gu, '') && ic) variant = 'icon';
    else if (filled && h && ((h.h < 15 || h.h > 345) && h.s > 0.5 && h.l < 0.6)) variant = 'danger';
    else if (filled && h && h.a > 0.5 && (h.l < 0.35 || (h.s > 0.35 && h.l < 0.7))) variant = 'primary';
    else if (filled || bordered) variant = 'secondary';
    else if (fg && fg.s > 0.5 && (fg.h < 15 || fg.h > 345)) variant = 'danger-ghost';
    if (!isBtn) { push('link', el, { variant: 'link', active: el.matches('[aria-current]:not([aria-current=false]), .active') }); continue; }
    const active = el.matches('[aria-current]:not([aria-current=false]), [aria-selected=true], [aria-pressed=true], [data-active=true], .active') || /(^|\s)(is-)?active(\s|$)/.test(el.getAttribute('class') || '');
    push('button', el, { variant: active ? variant + '-active' : variant, active, disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true' });
  }
  for (const el of document.querySelectorAll('input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]):not([type=button]):not([type=file]):not([type=range]), textarea'))
    if (visible(el)) push('input', el, { variant: el.tagName === 'TEXTAREA' ? 'textarea' : (el.type === 'search' || /szukaj|search/i.test(el.placeholder || '') ? 'search' : 'text') });
  for (const el of document.querySelectorAll('select, [role=combobox]:not(input)')) if (visible(el)) push('select', el, { variant: 'select' });
  for (const el of document.querySelectorAll('input[type=checkbox], [role=checkbox], [role=switch]')) {
    const v = visible(el) ? el : (el.closest('label') && visible(el.closest('label')) ? el : null); if (!v || !visible(el)) continue; push('checkbox', el, { variant: el.getAttribute('role') === 'switch' ? 'switch' : 'checkbox' }); }
  for (const el of document.querySelectorAll('h1, h2, h3, [role=heading]')) if (visible(el)) push('heading', el, { variant: el.tagName.match(/^H\d$/) ? el.tagName.toLowerCase() : 'h' + (el.getAttribute('aria-level') || '?') });
  // badges / status pills: small leaf boxes with tinted bg or border
  for (const el of document.querySelectorAll('span, small, mark, div, p, li, td > *')) {
    if (seen.has(el) || el.closest('button, a, [role=button], select, svg') || el.children.length > 2 || !visible(el)) continue;
    const t = text(el); if (!t || t.length > 32) continue; const cs = getComputedStyle(el), r = el.getBoundingClientRect();
    if (r.height < 12 || r.height > 34 || r.width > 260) continue;
    const filled = !transparent(cs.backgroundColor), bordered = parseFloat(cs.borderTopWidth) > 0 && !transparent(cs.borderTopColor);
    if (!(filled || bordered) || parseFloat(cs.borderTopLeftRadius) < 2 || parseFloat(cs.paddingLeft) < 2) continue;
    const pr = el.parentElement && getComputedStyle(el.parentElement); if (pr && pr.backgroundColor === cs.backgroundColor && el.parentElement.getBoundingClientRect().height <= r.height + 2) continue;
    seen.add(el); const h = hsl(cs.backgroundColor) || {}; const tone = !filled || (h.s < 0.12) ? 'neutral' : (h.h < 20 || h.h > 340) ? 'danger' : h.h < 65 ? 'warning' : h.h < 170 ? 'success' : h.h < 260 ? 'info' : 'other';
    push('badge', el, { variant: tone });
  }
  // notifications: live regions, alerts, toasts and inline tinted boxes
  const ALERT_SEL = '[role=alert], [role=status], [aria-live]:not([aria-live=off]), [data-sonner-toast], .toast, [class*=toast], [class*=alert], [class*=notice], [class*=banner]';
  const alertEls = new Set([...document.querySelectorAll(ALERT_SEL)].filter((el) => visible(el) && text(el).length > 2 && !el.closest('button,a')));
  for (const el of document.querySelectorAll('div, p, section')) {
    if (alertEls.has(el) || !visible(el)) continue; const t = text(el); if (t.length < 12 || t.length > 320) continue; const cs = getComputedStyle(el), h = hsl(cs.backgroundColor);
    if (!h || h.a < 0.05 || h.s < 0.25 || h.l < 0.55 || el.querySelector('input,select,textarea,table,img') || el.querySelectorAll('button,a').length > 2) continue;
    const r = el.getBoundingClientRect(); if (r.height > 220 || r.width < 120) continue; if (el.parentElement && alertEls.has(el.parentElement)) continue; alertEls.add(el); }
  for (const el of alertEls) {
    if ([...alertEls].some((o) => o !== el && o.contains(el) && text(o) === text(el))) continue;
    const cs = getComputedStyle(el), r = el.getBoundingClientRect(); let fixed = false; const dlg = el.closest('[role=dialog],[role=alertdialog],dialog'); for (let e = el; e && e !== document.body && !(dlg && e === dlg); e = e.parentElement) if (['fixed', 'sticky'].includes(getComputedStyle(e).position)) { fixed = true; break; }
    const h = hsl(cs.backgroundColor) || {}; const tone = transparent(cs.backgroundColor) ? 'neutral' : (h.s < 0.12 ? 'neutral' : (h.h < 20 || h.h > 340) ? 'error' : h.h < 65 ? 'warning' : h.h < 170 ? 'success' : h.h < 260 ? 'info' : 'other');
    const kind = fixed && (r.top < 120 || r.bottom > vh - 160) && r.height < vh * 0.3 ? 'toast' : (fixed ? 'banner-fixed' : 'inline');
    push('alert', el, { variant: kind + ':' + tone, kind, tone, text: text(el).slice(0, 200), in_dialog: !!dlg });
  }
  // tables
  for (const el of document.querySelectorAll('table, [role=table], [role=grid]')) {
    if (!visible(el)) continue; const th = el.querySelector('th, [role=columnheader]'), td = el.querySelector('td, [role=cell]'), tr = el.querySelector('tbody tr, [role=row]:nth-of-type(2)');
    const r = el.getBoundingClientRect(); let sc = el.parentElement; while (sc && sc !== document.body && !/(auto|scroll)/.test(getComputedStyle(sc).overflowX)) sc = sc.parentElement;
    push('table', el, { variant: 'table', th: th ? st(th) : null, td: td ? st(td) : null, row_h: tr ? Math.round(tr.getBoundingClientRect().height) : null,
      cols: el.querySelectorAll('th, [role=columnheader]').length, display: getComputedStyle(el).display, row_display: tr ? getComputedStyle(tr).display : null, thead_visible: !!(el.querySelector('thead') && visible(el.querySelector('thead'))), overflow_x: Math.round(Math.max(0, r.right - vw)), scroll_container: !!(sc && sc !== document.body), scroll_w: el.scrollWidth });
  }
  // icons (standalone + inside controls)
  let ni = 0; for (const el of document.querySelectorAll('svg')) { if (el.parentElement.closest('svg') || !visible(el) || ni++ > 250) continue; const r = el.getBoundingClientRect(); if (r.width > 64 || r.height > 64) continue;
    const host = el.closest('button, a, [role=button]'); push('icon', el, { variant: host ? 'in-control' : 'standalone', host_label: host ? label(host) : null }); }
  // cards
  let nc = 0; for (const el of document.querySelectorAll('div, section, article, li, aside, form')) {
    if (nc > 150 || !visible(el)) continue; const cs = getComputedStyle(el), r = el.getBoundingClientRect(); if (r.width < 140 || r.height < 60) continue;
    const bordered = parseFloat(cs.borderTopWidth) > 0 && !transparent(cs.borderTopColor) && parseFloat(cs.borderLeftWidth) > 0;
    if (!(bordered || cs.boxShadow !== 'none') || parseFloat(cs.borderTopLeftRadius) < 4 || parseFloat(cs.paddingTop) + parseFloat(cs.paddingLeft) < 8) continue;
    if (el.matches('[role=dialog],[role=alertdialog],dialog') || alertEls.has(el)) continue; nc++; push('card', el, { variant: el.closest('nav,aside') ? 'nav-card' : 'card' }); }
  // dialogs / drawers
  for (const el of document.querySelectorAll('[role=dialog], [role=alertdialog], dialog[open], [aria-modal=true]')) {
    if (!visible(el)) continue; const r = el.getBoundingClientRect(); let kind = 'modal';
    if (r.width >= vw * 0.95 && r.height >= vh * 0.9) kind = 'fullscreen'; else if (r.right >= vw - 2 && r.height >= vh * 0.85) kind = 'drawer-right'; else if (r.left <= 2 && r.height >= vh * 0.85) kind = 'drawer-left';
    else if (r.bottom >= vh - 2 && r.width >= vw * 0.9) kind = 'sheet-bottom'; push('dialog', el, { variant: kind, title: text(el.querySelector('h1,h2,h3,[class*=title]') || el).slice(0, 80) }); }
  // chrome: header / nav / sidebar / footer / bottom-nav
  const chrome = []; const chromeEls = new Set([...document.querySelectorAll('header, [role=banner], nav, aside, [role=navigation], footer')].filter(visible));
  for (const el of document.querySelectorAll('body *')) { const cs = getComputedStyle(el); if (cs.position !== 'fixed' || !visible(el)) continue; const r = el.getBoundingClientRect();
    if (r.bottom >= vh - 2 && r.width >= vw * 0.9 && r.height < 110 && el.querySelectorAll('a,button').length >= 3) chromeEls.add(el); }
  for (const el of chromeEls) { if ([...chromeEls].some((o) => o !== el && o.contains(el))) continue; const cs = getComputedStyle(el), r = el.getBoundingClientRect();
    let kind = el.matches('footer') ? 'footer' : el.matches('header,[role=banner]') ? 'header' : el.matches('aside') ? 'sidebar' : 'nav';
    if (cs.position === 'fixed' && r.bottom >= vh - 2 && r.height < 110) kind = 'bottom-nav'; else if (kind === 'nav' && r.height > r.width && r.width < vw * 0.5) kind = 'sidebar';
    if ((kind === 'sidebar' || kind === 'nav') && el.querySelectorAll('input, select, [role=checkbox], [role=slider]').length >= 2) kind = 'filters';
    const skel = (e, d) => d > 3 ? '' : e.tagName.toLowerCase() + ([...e.children].length ? '(' + [...e.children].filter((c) => !['SCRIPT', 'STYLE'].includes(c.tagName)).slice(0, 14).map((c) => skel(c, d + 1)).join(',') + ')' : '');
    const items = [...el.querySelectorAll('a, button')].filter(visible).map(label).filter(Boolean).slice(0, 40);
    const cardish = !transparent(cs.backgroundColor) && parseFloat(cs.borderTopLeftRadius) >= 4 && (parseFloat(cs.borderTopWidth) > 0 || cs.boxShadow !== 'none');
    const inner = [...el.querySelectorAll('div,section')].find((c) => { const s = getComputedStyle(c); return visible(c) && parseFloat(s.borderTopLeftRadius) >= 6 && (parseFloat(s.borderTopWidth) > 0 || s.boxShadow !== 'none') && c.getBoundingClientRect().height > 120; });
    const heading = el.querySelector('h1,h2,h3,h4,[class*=title]');
    const links = [...el.querySelectorAll('a, button')].filter(visible); const act = links.find((a) => a.matches('[aria-current=page], [aria-current=true], .active, [data-active=true], [aria-selected=true]'));
    const plain = links.find((a) => a !== act && label(a).length > 2);
    chrome.push({ kind, rect: rect(el), sel: cssPath(el), items, skeleton: skel(el, 0).slice(0, 1500), style: st(el), card: cardish || !!inner, heading: heading ? text(heading).slice(0, 60) : null, item_style: plain ? st(plain) : null, active_style: act ? st(act) : null, inner_card: inner ? st(inner) : null, fixed: cs.position === 'fixed' || cs.position === 'sticky' }); }
  // states
  const STATE_RE = { empty: /^(brak\b|nie ma\b|nie znaleziono|pusto|no (results|items|data))/i, loading: /^(ładowanie|wczytywanie|trwa ładowanie|loading)/i, error: /^(błąd|wystąpił błąd|nie udało się|coś poszło nie tak|error|failed)/i };
  const states = []; const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let n;
  while ((n = tw.nextNode()) && states.length < 60) { const t = n.textContent.replace(/\s+/g, ' ').trim(); if (!t || t.length > 160) continue; const el = n.parentElement; if (!el || !visible(el) || el.closest('button,a,option,script,style')) continue;
    for (const [k, re] of Object.entries(STATE_RE)) if (re.test(t)) { const box = el.closest('div,section,td,li') || el; states.push({ role: 'state', variant: k, tag: el.tagName.toLowerCase(), label: t.slice(0, 120), rect: rect(box), sel: cssPath(el), ctx: ctxOf(el), cls: '', style: st(el), icon: iconOf(box), box: st(box) }); break; } }
  OUT.push(...states);
  // copy: UI strings (not product data): headings, labels, th, placeholders, nav items, alerts, buttons
  const ui = new Set(); const add = (s, where) => { s = (s || '').replace(/\s+/g, ' ').trim(); if (s && s.length <= 140) ui.add(where + '\u0001' + s); };
  for (const el of document.querySelectorAll('label, th, [role=columnheader], legend, h1, h2, h3, h4, [role=tab], option')) if (visible(el) || el.tagName === 'OPTION') add(text(el), el.tagName.toLowerCase());
  for (const el of document.querySelectorAll('[placeholder]')) if (visible(el)) add(el.getAttribute('placeholder'), 'placeholder');
  for (const el of document.querySelectorAll('[aria-label], [title]')) if (visible(el)) add(el.getAttribute('aria-label') || el.getAttribute('title'), 'aria');
  const body = document.body.innerText;
  const dates = [...new Set((body.match(/\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?\b|\b\d{1,2} (?:sty|lut|mar|kwi|maj|cze|lip|sie|wrz|paź|lis|gru)[a-ząćęłńóśźż]*\.? \d{4}\b/gi) || []))].slice(0, 40);
  const NUM = '\\d{1,3}(?:[ \\u00a0\\u202f.]\\d{3})+(?:[.,]\\d{2})?|\\d+(?:[.,]\\d{2})?';
  const money = [...new Set((body.match(new RegExp(`(?:PLN|zł)[ \\u00a0]?-?(?:${NUM})|-?(?:${NUM})[ \\u00a0]?(?:zł|PLN)(?![\\p{L}])`, 'gu')) || []).map((s) => s.replace(/[\u00a0\u202f]/g, ' ')))].slice(0, 60);
  return { components: OUT, chrome, copy: { ui: [...ui].map((s) => s.split('\u0001')), dates, money }, meta: { url: location.href, title: document.title, lang: document.documentElement.lang, vw, vh,
    doc_w: document.documentElement.scrollWidth, doc_h: document.documentElement.scrollHeight } };
}

// ------------------------------------------------------------------ details probe: how does "details" open on a list page?
async function probeDetails(page, spec, job) {
  const re = new RegExp(job.details_re || '^(Szczegóły|Podgląd|Zobacz|Pokaż|Otwórz|Więcej|Detale|Details|View)\\b', 'i');
  const before = page.url();
  const found = await page.evaluate(([src, rowSel]) => { const re = new RegExp(src, 'i'); const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
    const lab = (e) => (e.innerText || e.getAttribute('aria-label') || e.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
    let el = [...document.querySelectorAll('button, a, [role=button]')].find((e) => vis(e) && re.test(lab(e))), how = 'button';
    if (!el) { el = [...document.querySelectorAll(rowSel)].find(vis); how = 'row-link'; }
    const rows = document.querySelectorAll('table tbody tr, [role=row]').length;
    if (!el) return { rows }; el.setAttribute('data-helix-probe', '1'); return { rows, how, label: lab(el).slice(0, 40) }; },
    [job.details_re || '^(Szczegóły|Podgląd|Zobacz|Pokaż|Otwórz|Więcej|Detale|Details|View)(\\s|$)', spec.row_selector || 'table tbody tr a[href], [role=row] a[href], tbody tr[onclick], tbody tr[role=button]']);
  const rows = found.rows, how = found.how;
  if (!found.how) return { pattern: 'none', trigger: null, rows, note: 'brak przycisku "Szczegóły" ani klikalnego wiersza' };
  const trig = page.locator('[data-helix-probe]').first();
  const labelTxt = found.label;
  const dialogsBefore = await page.locator('[role=dialog]:visible, dialog[open]').count();
  let clickNote = null; await trig.click({ timeout: 5000 }).catch(async (e) => { clickNote = 'klik JS (Playwright: ' + e.message.split('\n')[0].slice(0, 80) + ')'; await trig.evaluate((el) => el.click()).catch(() => {}); });
  await page.waitForTimeout(job.settle_ms ?? 900);
  let pattern = 'no-op';
  if (page.url() !== before) pattern = 'page';
  else {
    const dl = page.locator('[role=dialog]:visible, dialog[open]'); if (await dl.count() > dialogsBefore) {
      const r = await dl.last().evaluate((el) => { const b = el.getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom, w: b.width, h: b.height, vw: innerWidth, vh: innerHeight }; });
      pattern = r.w >= r.vw * 0.95 && r.h >= r.vh * 0.9 ? 'fullscreen' : r.r >= r.vw - 2 && r.h >= r.vh * 0.85 ? 'drawer-right' : r.b >= r.vh - 2 && r.w >= r.vw * 0.9 ? 'sheet-bottom' : 'modal';
    } else pattern = 'inline-expand';
  }
  return { pattern, trigger: labelTxt, how, rows, click_note: clickNote };
}

async function runAction(page, a) {
  if (a.click) await page.locator(a.click).first().click({ timeout: 8000 });
  else if (a.tap) await page.locator(a.tap).first().tap({ timeout: 8000 }).catch(() => page.locator(a.tap).first().click({ timeout: 8000 }));
  else if (a.fill) await page.locator(a.fill).first().fill(String(a.value ?? ''), { timeout: 8000 });
  else if (a.wait) await page.waitForTimeout(+a.wait);
  else if (a.wait_for) await page.locator(a.wait_for).first().waitFor({ timeout: 15000 });
  else if (a.goto) await page.goto(a.goto, { waitUntil: 'networkidle', timeout: 30000 });
  else if (a.scroll) await page.evaluate((y) => window.scrollBy(0, y), +a.scroll);
}

async function scan(job) {
  const out = job.out; fs.mkdirSync(path.join(out, 'shots'), { recursive: true });
  const browser = await pw.chromium.launch(); const results = [];
  for (const t of job.targets) for (const spec of job.pages) {
    if (spec.targets && !spec.targets.includes(t.id)) continue;
    const base = spec.base_url || job.base_url; const ss = spec.storage_state === undefined ? job.storage_state : spec.storage_state;
    const ctx = await browser.newContext({ ...targetOpts(t), locale: job.locale || 'pl-PL', timezoneId: job.timezone || 'Europe/Warsaw', ...(ss ? { storageState: ss } : {}) });
    const api = [], blocked = new Set();
    await ctx.route('**/*', (r) => { const u = new URL(r.request().url()); if (/^(data|blob):/.test(u.protocol) || okHost(u.hostname, job.allow_hosts)) return r.continue(); blocked.add(u.hostname); return r.abort(); });
    const page = await ctx.newPage();
    page.on('response', async (res) => { try { if (res.status() < 400) return; const u = res.url(); if (!/\/api\//.test(u)) return; const b = (await res.text()).slice(0, 600); let d = b;
      try { const j = JSON.parse(b); d = typeof j.detail === 'string' ? j.detail : j.detail ? JSON.stringify(j.detail) : (j.message || j.error || b); } catch (_) {} api.push({ status: res.status(), url: u.replace(/^https?:\/\/[^/]+/, ''), detail: String(d).slice(0, 300) }); } catch (_) {} });
    const r = { page: spec.name, state: spec.state || 'base', area: spec.area || null, target: t.id, kind: t.kind, ok: true, steps: [], user: ss ? path.basename(ss).replace(/\.json$/, '') : null, base_url: base };
    try {
      await page.goto(new URL(spec.path, base).href, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => {});
      if (spec.wait_for) await page.locator(spec.wait_for).first().waitFor({ timeout: 15000 }).catch((e) => r.steps.push('wait_for: ' + e.message.split('\n')[0]));
      for (const a of spec.actions || []) { try { await runAction(page, a); r.steps.push('ok ' + JSON.stringify(a)); } catch (e) { r.steps.push((a.optional ? 'SKIP ' : 'FAIL ') + JSON.stringify(a) + ': ' + e.message.split('\n')[0]); } }
      await page.waitForTimeout(job.settle_ms ?? 700);
      const ex = await page.evaluate(EXTRACT, { max: job.max_components || 2500 });
      Object.assign(r, ex);
      const shot = path.join('shots', slug(`${spec.name}--${r.state}--${t.id}`) + '.png');
      await page.screenshot({ path: path.join(out, shot), fullPage: true, timeout: 30000 }).catch(() => page.screenshot({ path: path.join(out, shot) }));
      r.shot = shot; r.dpr = targetOpts(t).deviceScaleFactor || 1;
      if (spec.probe_details) { r.details = await probeDetails(page, spec, job).catch((e) => ({ pattern: 'error', note: e.message.split('\n')[0] }));
        if (r.details && !['none', 'error'].includes(r.details.pattern)) { const ds = path.join('shots', slug(`${spec.name}--${r.state}--${t.id}--details`) + '.png'); await page.screenshot({ path: path.join(out, ds) }).catch(() => {}); r.details.shot = ds; } }
    } catch (e) { r.ok = false; r.error = e.message.split('\n')[0]; }
    r.api_errors = api; r.blocked_hosts = [...blocked]; results.push(r);
    process.stderr.write(`[consistency] ${spec.name}/${r.state} @ ${t.id}: ${r.ok ? (r.components || []).length + ' komponentów' : 'BŁĄD ' + r.error}\n`);
    await ctx.close();
  }
  await browser.close();
  fs.writeFileSync(path.join(out, 'raw.json'), JSON.stringify({ created: new Date().toISOString(), base_url: job.base_url, targets: job.targets, results }, null, 1));
}

(async () => {
  const [mode, jf] = process.argv.slice(2);
  if (mode !== 'scan' || !jf) { console.error('usage: node consistency.cjs scan <job.json>'); process.exit(64); }
  await scan(JSON.parse(fs.readFileSync(jf, 'utf8')));
})().catch((e) => { console.error(e.stack || e); process.exit(1); });
