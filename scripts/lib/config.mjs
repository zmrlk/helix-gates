import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const HELP = `Helix UI 2 — DOM + dowody + porównanie PNG
node ui-audit.mjs <url|plik.html> --out <folder>
  --widths 1440,1280,1024,768,390,280 --themes light,dark
  --sweep 280-1600:40 [--sweep-themes all|first (domyślnie all)]
  --workers 2 (1–4) --height 900 --dpr 2
  --ready-selector '[data-ready]' --wait 0 --settle 120
  --goto-timeout 30000 --run-timeout 90000
  --baseline <folder> --case <stała-nazwa-ekranu>
  --pixel-threshold 0 --max-diff-pixels 0 --max-diff-ratio 0
  --mask '.zegar,.dane-dynamiczne' --storage-state <plik.json>
  --ladder 11,12,13,15,18,22,28 --tap 44 --tap-desktop 44
  --space 4,8,12,16,24,32,48,64 (lub off) --lead-max 2
  --theme-attr data-theme --no-shots --viewport-only
Exit: 0 automat zaliczony, 1 wykryte błędy, 2 niekompletny/błędny audyt.
Bez --baseline zgodność wyglądu = not_checked. Exit 0 nie oznacza całego G2/G3.`;

export function parseArgs(args) {
  const flags = new Set(['no-shots', 'viewport-only', 'help']);
  const names = new Set(['out', 'widths', 'themes', 'sweep', 'sweep-themes', 'workers', 'height', 'dpr', 'ready-selector', 'wait', 'settle', 'goto-timeout', 'run-timeout', 'baseline', 'case', 'pixel-threshold', 'max-diff-pixels', 'max-diff-ratio', 'mask', 'storage-state', 'throttled-paths', 'states', 'states-timeout', 'states-nested', 'states-seen', 'ladder', 'tap', 'tap-desktop', 'space', 'lead-max', 'theme-attr']);
  const raw = {}, positional = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith('--')) { positional.push(arg); continue; }
    const k = arg.slice(2);
    if (Object.hasOwn(raw, k)) throw new Error(`Powtórzony argument --${k}`);
    if (flags.has(k)) raw[k] = true;
    else if (names.has(k) && args[i + 1] !== undefined && !args[i + 1].startsWith('--')) raw[k] = args[++i];
    else throw new Error(`Nieznany argument lub brak wartości: ${arg}`);
  }
  if (raw.help) return { help: true };
  if (positional.length !== 1) throw new Error('Podaj dokładnie jeden URL lub plik HTML');
  const num = (k, d, min, max, integer = false) => {
    const value = raw[k] === undefined ? d : Number(raw[k]);
    if (!Number.isFinite(value) || value < min || value > max || (integer && !Number.isInteger(value))) throw new Error(`Nieprawidłowe --${k} (${min}–${max})`);
    return value;
  };
  const list = (k, d) => {
    const values = (raw[k] ?? d).split(',').map(Number);
    if (!values.length || values.length > 100 || values.some(v => !Number.isFinite(v) || v <= 0 || v > 10000)) throw new Error(`Nieprawidłowe --${k}`);
    return [...new Set(values)];
  };
  const widths = list('widths', '1440,1280,1024,768,390,280');
  if (widths.some(v => !Number.isInteger(v) || v > 4096 || v < 100)) throw new Error('Szerokości muszą być całkowite: 100–4096');
  const themes = [...new Set((raw.themes ?? 'light,dark').split(','))];
  if (themes.some(v => !['light', 'dark'].includes(v))) throw new Error('Motywy: light,dark');
  const extra = [];
  if (raw.sweep) {
    const m = /^(\d+)-(\d+)(?::(\d+))?$/.exec(raw.sweep);
    if (!m) throw new Error('Przegląd: --sweep 280-1600:40');
    const [, a, b, step = '40'] = m.map((v, i) => i ? Number(v) : v);
    const stride = step || (m[3] === undefined ? 40 : 0);
    if (a < 100 || b > 4096 || b < a || stride < 1 || (b - a) / stride > 200) throw new Error('Nieprawidłowy zakres/krok przeglądu (maks. 201 szerokości)');
    for (let w = a; w <= b; w += stride) if (!widths.includes(w)) extra.push(w);
  }
  if (raw['sweep-themes'] && !['all', 'first'].includes(raw['sweep-themes'])) throw new Error('--sweep-themes: all|first');
  let url;
  const target = positional[0];
  if (/^[a-z][a-z\d+.-]*:/i.test(target)) {
    url = new URL(target);
    if (!['http:', 'https:', 'file:'].includes(url.protocol)) throw new Error('Obsługiwane protokoły: http, https, file');
    if (url.username || url.password) throw new Error('Nie umieszczaj hasła w URL; użyj --storage-state');
  } else {
    const hashAt = target.indexOf('#');
    url = pathToFileURL(path.resolve(hashAt < 0 ? target : target.slice(0, hashAt)));
    if (hashAt >= 0) url.hash = target.slice(hashAt);
  }
  if (url.protocol === 'file:' && !fs.existsSync(url)) throw new Error(`Nie ma pliku ${url.pathname}`);
  const out = path.resolve(raw.out ?? 'helix-ui');
  const baseline = raw.baseline ? path.resolve(raw.baseline) : null;
  if (baseline && (out === baseline || out.startsWith(baseline + path.sep))) throw new Error('Wyniki muszą być poza katalogiem wzorca');
  if (baseline && raw['no-shots']) throw new Error('--baseline wymaga zrzutów');
  const storageState = raw['storage-state'] ? path.resolve(raw['storage-state']) : undefined;
  if (storageState && !fs.existsSync(storageState)) throw new Error('Brak pliku --storage-state');
  const themeAttr = raw['theme-attr'] ?? 'data-theme';
  if (!/^[a-zA-Z_][\w:.-]*$/.test(themeAttr)) throw new Error('Nieprawidłowy --theme-attr');
  return {
    url: url.href, out, baseline, storageState, caseId: raw.case ?? url.pathname + url.hash,
    widths, extra, themes, sweepThemes: raw['sweep-themes'] ?? 'all',
    workers: num('workers', 2, 1, 4, true), height: num('height', 900, 100, 4096, true), dpr: num('dpr', 2, 1, 3),
    wait: num('wait', 0, 0, 60000), settle: num('settle', 120, 16, 5000),
    gotoTimeout: num('goto-timeout', 30000, 100, 300000), runTimeout: num('run-timeout', 90000, 100, 600000),
    pixelThreshold: num('pixel-threshold', 0, 0, 255, true), maxDiffPixels: num('max-diff-pixels', 0, 0, 100000000, true), maxDiffRatio: num('max-diff-ratio', 0, 0, 1),
    throttled: (raw['throttled-paths'] ?? '').split(',').filter(Boolean),
    states: num('states', 0, 0, 200, true), statesTimeout: num('states-timeout', 90000, 1000, 600000, true), statesNested: num('states-nested', 6, 0, 20, true), statesSeen: raw['states-seen'] ? path.resolve(raw['states-seen']) : '',
    mask: raw.mask ?? '', readySelector: raw['ready-selector'] ?? '',
    ladder: list('ladder', '11,12,13,15,18,22,28'), tap: num('tap', 44, 1, 100), tapDesktop: num('tap-desktop', num('tap', 44, 1, 100), 1, 100),
    space: raw.space === 'off' ? [] : list('space', '4,8,12,16,24,32,48,64'), leadMax: num('lead-max', 2, 1, 100, true),
    themeAttr, noShots: !!raw['no-shots'], fullPage: !raw['viewport-only'],
  };
}
