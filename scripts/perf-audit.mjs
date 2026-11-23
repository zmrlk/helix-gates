#!/usr/bin/env node
// Helix G1-perf — deterministyczny audyt ciężaru tras SvelteKit (po `npm run build`, adapter-node/auto).
// Użycie: node perf-audit.mjs [<katalog z .svelte-kit, domyślnie .>] [--out helix-perf] [--top 20]
//   [--budget scripts/perf-budget.json] [--baseline scripts/perf-baseline.json] [--update-baseline]
//   [--ssr http://localhost:3000] [--routes /dashboard,/orders/1] [--cookie 'sid=…']   pomiar SSR: 5 prób, mediana
// Per trasa liczy zbiór plików ładowanych przy PIERWSZYM wejściu (wejście + layouty + strona, dokładnie to,
// co SvelteKit wpisuje w modulepreload): JS i CSS surowo i gzip (poziom 6 = `gzip -c`), plik strony (leaf),
// co już jest leniwe (dynamiczne importy z tego zbioru) i największe pliki JS. Źródła: server/manifest.js
// (trasy → węzły), server/nodes/N.js (imports/stylesheets), client/.vite/manifest.json (nazwy chunków).
// Budżet (scripts/perf-budget.json w repo, domyślne): trasa ≤ 150 KiB gzip JS, plik strony ≤ 40 KiB gzip.
// Zapadka jak conventions-baseline.txt: trasa cięższa niż w scripts/perf-baseline.json (+tolerancja) = fail,
// nowa trasa ponad budżetem = fail, stary dług ponad budżetem = wypisany, nie blokuje (baza = zgoda na stan).
// Wynik: <out>/perf-audit.json. Exit 1 = nie przechodzi, 2 = brak builda / zły argument.
import fs from 'node:fs';
import { genericBuild } from './lib/build-weight.mjs';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

let reportOut;
try {
const args = process.argv.slice(2);
if (args.includes('--help')) { console.log('Helix perf: node perf-audit.mjs [root] --out dir [--budget file] [--baseline file] [--init-baseline | --update-baseline] [--top 20] [--ssr URL --routes /a,/b --cookie COOKIE --ssr-timeout 5000]'); process.exit(0); }
const valueOptions = new Set(['--out', '--budget', '--baseline', '--top', '--ssr', '--routes', '--cookie', '--ssr-timeout']);
const seenOptions = new Set(); let positionals = 0;
for (let i = 0; i < args.length; i++) {
 const argument = args[i];
 if (!argument.startsWith('--')) { if (++positionals > 1) throw new Error('Podaj najwyżej jeden katalog builda'); continue; }
 if (seenOptions.has(argument)) throw new Error('Powtórzony argument: ' + argument); seenOptions.add(argument);
 if (['--init-baseline', '--update-baseline'].includes(argument)) continue;
 if (!valueOptions.has(argument) || args[i + 1] === undefined || args[i + 1].startsWith('--')) throw new Error('Nieznany argument lub brak wartości: ' + argument);
 i++;
}
const BOOL = new Set(['--update-baseline', '--init-baseline']);
const opt = (k, d) => {
	const i = args.indexOf(`--${k}`);
	return i >= 0 ? args[i + 1] : d;
};
const root = path.resolve(args.find((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--') && !BOOL.has(args[i - 1]))) || '.');
const out = path.resolve(opt('out', 'helix-perf'));
reportOut = out;
if (args.includes('--init-baseline') && args.includes('--update-baseline')) throw new Error('Wybierz --init-baseline albo --update-baseline');
const top = Number(opt('top', '20'));
if (!Number.isInteger(top) || top < 1 || top > 1000) throw new Error('Nieprawidłowe --top');
const outDir = path.join(root, '.svelte-kit/output');
const clientDir = path.join(outDir, 'client');
const serverDir = path.join(outDir, 'server');
const isSvelte = fs.existsSync(path.join(serverDir, 'manifest.js')) && fs.existsSync(path.join(clientDir, '.vite/manifest.json'));
const generic = isSvelte ? null : genericBuild(root, top);
const buildStamp = generic?.stamp || path.join(clientDir, '.vite/manifest.json');
// A manifest without a fresh build must not certify code that was edited later.
const buildTime = fs.statSync(buildStamp).mtimeMs;
const sourceRoots = ['src', 'static', 'app', 'pages', 'public', 'next.config.js', 'next.config.mjs', 'next.config.ts', 'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb', 'vite.config.js', 'vite.config.ts', 'svelte.config.js', 'svelte.config.ts', 'tsconfig.json', 'svelte.config.mjs', 'svelte.config.cjs', 'vite.config.mjs', 'vite.config.cjs', 'postcss.config.js', 'postcss.config.cjs', 'postcss.config.mjs', 'tailwind.config.js', 'tailwind.config.ts', 'tailwind.config.cjs'].map(p => path.join(root, p));
const newer = [];
const checkFresh = p => {
	if (!fs.existsSync(p)) return;
	const stat = fs.lstatSync(p);
	if (stat.isSymbolicLink()) return; // external source roots need their own build provenance
	if (stat.mtimeMs > buildTime + 1) newer.push(path.relative(root, p));
	if (stat.isDirectory()) for (const name of fs.readdirSync(p)) checkFresh(path.join(p, name));
};
for (const source of sourceRoots) checkFresh(source);
if (newer.length) throw new Error(`Build jest starszy niż źródła (${newer.slice(0, 5).join(', ')}); wykonaj npm run build`);

// repo = najbliższy przodek z .git (worktree ma plik .git); tam scripts/perf-budget.json + perf-baseline.json
const repo = (() => {
	for (let d = root, i = 0; i < 4; i++, d = path.dirname(d)) if (fs.existsSync(path.join(d, '.git'))) return d;
	return root;
})();
const budgetPath = path.resolve(opt('budget', path.join(repo, 'scripts/perf-budget.json')));
const basePath = path.resolve(opt('baseline', path.join(repo, 'scripts/perf-baseline.json')));
const budget = {
	route_js_gzip_kib: 150,
	page_chunk_gzip_kib: 40,
	tolerance_kib: 0.5, // szum tablicy tras w entry/app.js (nowa trasa = +~0,1 KiB na każdej trasie)
	ssr_routes: [],
	...(fs.existsSync(budgetPath) ? JSON.parse(fs.readFileSync(budgetPath, 'utf8')) : {})
};
for (const k of ['route_js_gzip_kib', 'page_chunk_gzip_kib', 'tolerance_kib']) if (!Number.isFinite(budget[k]) || budget[k] < 0) throw new Error('Nieprawidłowy budżet: ' + k);
const commit = (() => {
	try {
		return execFileSync('git', ['-C', repo, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
	} catch {
		return null;
	}
})();

// manifest.js jest samodzielnym ESM: importy węzłów są leniwe (__memo), więc import nie uruchamia kodu serwera
let rows, totals, biggest;
if (isSvelte) {
const { manifest } = await import(pathToFileURL(path.join(serverDir, 'manifest.js')).href);
const client = manifest._.client; // { start, app, imports, stylesheets }
const routes = manifest._.routes.filter((r) => r.page);
if (!routes.length) throw new Error('Manifest nie zawiera tras UI');
const vite = JSON.parse(fs.readFileSync(path.join(clientDir, '.vite/manifest.json'), 'utf8'));
const byFile = new Map(Object.entries(vite).map(([key, v]) => [v.file, { key, ...v }]));

const nodeCache = new Map();
const node = (i) => {
	if (!nodeCache.has(i)) {
		const src = fs.readFileSync(path.join(serverDir, 'nodes', `${i}.js`), 'utf8');
		const arr = k => {
			const match = src.match(new RegExp(`export const ${k}\\s*=\\s*(\\[[\\s\\S]*?\\]);`));
			if (!match) throw new Error(`Nieznany format server/nodes/${i}.js: brak ${k}`);
			const values = JSON.parse(match[1]);
			if (!Array.isArray(values) || values.some(value => typeof value !== 'string')) throw new Error(`Nieprawidłowa tablica ${k} w server/nodes/${i}.js`);
			return values;
		};
		// etykieta = ścieżka komponentu z wygenerowanego węzła klienta (src/routes/…/+page.svelte)
		const gen = path.join(root, '.svelte-kit/generated/client-optimized/nodes', `${i}.js`);
		const label = fs.existsSync(gen) ? fs.readFileSync(gen, 'utf8').match(/from "(?:\.\.\/)*(src\/[^"]+)"/)?.[1] : null;
		nodeCache.set(i, { imports: arr('imports'), stylesheets: arr('stylesheets'), label: label || `nodes/${i}` });
	}
	return nodeCache.get(i);
};
const sizeCache = new Map();
const size = (file) => {
	if (!sizeCache.has(file)) {
		const buf = fs.readFileSync(path.join(clientDir, file));
		sizeCache.set(file, { raw: buf.length, gz: zlib.gzipSync(buf, { level: 6 }).length });
	}
	return sizeCache.get(file);
};
const sum = (files, k) => files.reduce((a, f) => a + size(f)[k], 0);
const kib = (b) => Math.round((b / 1024) * 10) / 10;
const label = (file) => {
	const v = byFile.get(file);
	const m = v?.name?.match(/^nodes\/(\d+)$/);
	return m ? node(+m[1]).label : v?.name || file;
};
const uniq = (a) => [...new Set(a)];

rows = routes.map((r) => {
	const nodes = [...(r.page.layouts ?? []), r.page.leaf].filter(i => i != null).map(node);
	const js = uniq([client.start, client.app, ...client.imports, ...nodes.flatMap((n) => n.imports)]);
	const css = uniq([...client.stylesheets, ...nodes.flatMap((n) => n.stylesheets)]);
	const leaf = node(r.page.leaf);
	const pageFile = leaf.imports.find((f) => /\/nodes\/\d+\./.test(f));
	// Trasa bez pliku klienta (np. samo odesłanie po stronie serwera) nie ma własnej wagi strony; nieznany układ importów nadal jest błędem.
	if (!pageFile && leaf.imports.length) throw new Error(`Nieznany plik strony w server/nodes/${r.page.leaf}.js (trasa ${r.id}; importy: ${leaf.imports.join(', ')})`);
	// leniwe = chunki importowane dynamicznie z plików pierwszego wejścia (bez entry/app, które importuje wszystkie węzły)
	const lazy = uniq(
		js.flatMap((f) =>
			f === client.app || f === client.start
				? []
				: (byFile.get(f)?.dynamicImports ?? []).map((k) => vite[k]?.file).filter((x) => x && !/\/nodes\//.test(x) && !js.includes(x))
		)
	);
	return {
		route: r.id,
		page: leaf.label,
		files: js.length,
		js_raw: kib(sum(js, 'raw')),
		js_gz: kib(sum(js, 'gz')),
		css_files: css.length,
		css_raw: kib(sum(css, 'raw')),
		css_gz: kib(sum(css, 'gz')),
		page_gz: pageFile ? kib(size(pageFile).gz) : 0,
		lazy: lazy.length,
		lazy_gz: kib(sum(lazy, 'gz')),
		top: js.map((f) => ({ file: f, name: label(f), gz: kib(size(f).gz) })).sort((a, b) => b.gz - a.gz).slice(0, 5)
	};
});
rows.sort((a, b) => b.js_gz - a.js_gz);

const listDir = (sub, ext) => fs.readdirSync(path.join(clientDir, '_app/immutable', sub)).filter((f) => f.endsWith(ext)).map((f) => `_app/immutable/${sub}/${f}`);
const allJs = [...listDir('entry', '.js'), ...listDir('nodes', '.js'), ...listDir('chunks', '.js')];
const allCss = listDir('assets', '.css');
const entryJs = uniq([client.start, client.app, ...client.imports]);
const shellJs = uniq([...entryJs, ...(fs.existsSync(path.join(serverDir, 'nodes/0.js')) ? node(0).imports : [])]);
totals = {
	js_files: allJs.length,
	js_raw: kib(sum(allJs, 'raw')),
	js_gz: kib(sum(allJs, 'gz')),
	css_files: allCss.length,
	css_raw: kib(sum(allCss, 'raw')),
	css_gz: kib(sum(allCss, 'gz')),
	entry_gz: kib(sum(entryJs, 'gz')),
	shell_gz: kib(sum(shellJs, 'gz'))
};
biggest = allJs.map((f) => ({ file: f, name: label(f), raw: kib(size(f).raw), gz: kib(size(f).gz) })).sort((a, b) => b.gz - a.gz).slice(0, top);

} else { ({ rows, totals, biggest } = generic); }

// ── SSR: 5 prób GET, mediana czasu do nagłówków i całości (informacyjnie; 3xx = brak sesji) ──
const ssrBase = opt('ssr', '');
const ssrPaths = (opt('routes', '') || budget.ssr_routes.join(',')).split(',').filter(Boolean);
const ssr = [];
const ssrTimeout = Number(opt('ssr-timeout', '5000'));
if (!Number.isFinite(ssrTimeout) || ssrTimeout < 100 || ssrTimeout > 60000) throw new Error('Nieprawidłowe --ssr-timeout');
if (ssrBase && !ssrPaths.length) throw new Error('--ssr wymaga --routes lub ssr_routes w budżecie');
if (ssrBase) {
	const cookie = opt('cookie', '');
	for (const p of ssrPaths) {
		const t = [];
		let status = 0, bytes = 0, error = null;
		for (let i = 0; i < 5; i++) {
			try {
				const t0 = performance.now();
				const res = await fetch(ssrBase + p, { redirect: 'manual', headers: cookie ? { cookie } : {}, signal: AbortSignal.timeout(ssrTimeout) });
				const ttfb = performance.now() - t0;
				status = res.status;
				if (status < 200 || status >= 300) { await res.body?.cancel(); error = `HTTP ${status}: to nie jest pomiar strony`; break; }
				bytes = (await res.arrayBuffer()).byteLength;
				t.push({ ttfb, total: performance.now() - t0 });
			} catch (e) { error = e.name; break; }
		}
		const med = (k) => error ? null : Math.round(t.map((x) => x[k]).sort((a, b) => a - b)[2]);
		ssr.push({ path: p, status, bytes, valid: !error, error, samples: t.length, ttfb_ms: med('ttfb'), total_ms: med('total') });
	}
}

// ── zapadka ──
const snapshot = {
	generated: new Date().toISOString(),
	commit,
	total_js_gzip_kib: totals.js_gz,
	total_css_gzip_kib: totals.css_gz,
	routes_over_budget: rows.filter((r) => r.js_gz > budget.route_js_gzip_kib).length,
	routes: Object.fromEntries(rows.map((r) => [r.route, { js_gz: r.js_gz, css_gz: r.css_gz, page_gz: r.page_gz }]))
};
const base = fs.existsSync(basePath) ? JSON.parse(fs.readFileSync(basePath, 'utf8')) : null;
if (args.includes('--init-baseline') && base) throw new Error('Baza już istnieje; --init-baseline nie nadpisuje');
if (base && (!base.routes || typeof base.routes !== 'object')) throw new Error('Nieprawidłowa baza tras');
if (base) for (const [route, values] of Object.entries(base.routes)) for (const k of ['js_gz', 'css_gz', 'page_gz'])
	if (!Number.isFinite(values[k]) || values[k] < 0) throw new Error(`Nieprawidłowa baza ${route}: ${k}`);
const fails = [];
const notes = [];
const tol = budget.tolerance_kib;
if (!base && !args.includes('--init-baseline')) fails.push(`brak bazy ${basePath} (pierwszy świadomy zapis: --init-baseline)`);
if (base)
	for (const r of rows) {
		const b = base.routes[r.route];
		if (!b) {
			if (r.js_gz > budget.route_js_gzip_kib) fails.push(`nowa trasa ${r.route}: ${r.js_gz} KiB gzip JS > budżet ${budget.route_js_gzip_kib}`);
			if (r.page_gz > budget.page_chunk_gzip_kib) fails.push(`nowa trasa ${r.route}: plik strony ${r.page_gz} KiB gzip > budżet ${budget.page_chunk_gzip_kib}`);
			continue;
		}
		for (const [k, name] of [['js_gz', 'JS'], ['css_gz', 'CSS'], ['page_gz', 'plik strony']]) {
			if (r[k] > b[k] + tol) fails.push(`ZAPADKA ${r.route} ${name}: ${b[k]} → ${r[k]} KiB gzip (+${(r[k] - b[k]).toFixed(1)}) · najcięższe: ${r.top.slice(0, 3).map((t) => `${t.name} ${t.gz}`).join(', ')}`);
			else if (r[k] < b[k] - tol) notes.push(`📉 ${r.route} ${name}: ${b[k]} → ${r[k]} KiB gzip. Obniż bazę: --update-baseline`);
		}
	}

for (const sample of ssr) if (!sample.valid) fails.push(`SSR ${sample.path}: ${sample.error}`);
let baselineUpdated = false;
if ((args.includes('--update-baseline') || args.includes('--init-baseline')) && !fails.length) {
	fs.mkdirSync(path.dirname(basePath), { recursive: true });
	// The ratchet can only stay or decrease. Compare BEFORE writing, never reset away a regression.
	const next = base ? { ...snapshot, routes: { ...base.routes, ...Object.fromEntries(rows.map(r => [r.route,
		Object.fromEntries(['js_gz', 'css_gz', 'page_gz'].map(k => [k, Math.min(r[k], base.routes[r.route]?.[k] ?? r[k])]))])) } } : snapshot;
	if (args.includes('--init-baseline')) fs.writeFileSync(basePath, JSON.stringify(next, null, '\t') + '\n', { flag: 'wx' });
	else { fs.writeFileSync(basePath + '.tmp-' + process.pid, JSON.stringify(next, null, '\t') + '\n'); fs.renameSync(basePath + '.tmp-' + process.pid, basePath); }
	baselineUpdated = true;
}

// ── raport ──
const d = (cur, prev) => (prev == null ? '' : ` (baza ${prev}, ${cur - prev >= 0 ? '+' : ''}${(cur - prev).toFixed(1)})`);
const pad = (s, n) => String(s).padStart(n);
const mtime = fs.statSync(buildStamp).mtime.toISOString().slice(0, 16).replace('T', ' ');
console.log(`Helix G1-perf · ${repo}${commit ? ' @ ' + commit : ''} · build ${mtime} UTC`);
console.log(`Klient razem: JS ${totals.js_files} plików ${totals.js_raw} KiB surowo / ${totals.js_gz} gzip${d(totals.js_gz, base?.total_js_gzip_kib)} · CSS ${totals.css_files} plików ${totals.css_raw} / ${totals.css_gz} gzip${d(totals.css_gz, base?.total_css_gzip_kib)}`);
console.log(`Wejście (start+app+importy): ${totals.entry_gz} KiB gzip · powłoka (wejście + layout 0): ${totals.shell_gz} KiB gzip`);
console.log(`\nTrasy przy pierwszym wejściu (KiB gzip), ${Math.min(top, rows.length)} z ${rows.length} najcięższych JS · budżet JS ≤ ${budget.route_js_gzip_kib}, strona ≤ ${budget.page_chunk_gzip_kib}, tolerancja ${tol}:`);
console.log(`${pad('JS', 7)} ${pad('CSS', 6)} ${pad('strona', 7)} ${pad('leniwie', 13)} ${pad('Δ baza', 8)}  trasa`);
for (const r of rows.slice(0, top)) {
	const b = base?.routes[r.route];
	const delta = b ? `${r.js_gz - b.js_gz >= 0 ? '+' : ''}${(r.js_gz - b.js_gz).toFixed(1)}` : 'nowa';
	const flags = [r.js_gz > budget.route_js_gzip_kib ? `JS > ${budget.route_js_gzip_kib}` : '', r.page_gz > budget.page_chunk_gzip_kib ? `strona > ${budget.page_chunk_gzip_kib}` : ''].filter(Boolean).join(' · ');
	console.log(`${pad(r.js_gz, 7)} ${pad(r.css_gz, 6)} ${pad(r.page_gz, 7)} ${pad(r.lazy ? `${r.lazy} (${r.lazy_gz})` : '-', 13)} ${pad(delta, 8)}  ${r.route}${flags ? '   ⚠️ ' + flags : ''}`);
}
const over = rows.filter((r) => r.js_gz > budget.route_js_gzip_kib).length;
const pageOver = rows.filter((r) => r.page_gz > budget.page_chunk_gzip_kib).length;
console.log(`Ponad budżetem: ${over} tras JS > ${budget.route_js_gzip_kib}${d(over, base?.routes_over_budget)}, ${pageOver} plików strony > ${budget.page_chunk_gzip_kib} — dług, blokuje tylko wzrost.`);
console.log(`\nNajwiększe pliki JS (KiB surowo / gzip), top ${biggest.length}:`);
for (const b of biggest) console.log(`${pad(b.raw, 7)} / ${pad(b.gz, 6)}  ${b.name}${b.name !== b.file ? '  ' + path.basename(b.file) : ''}`);
if (ssr.length) {
	console.log(`\nSSR ${ssrBase} (mediana z 5 prób, ms do nagłówków / całość, bajty):`);
	for (const s of ssr) console.log(`${pad(s.ttfb_ms, 6)} / ${pad(s.total_ms, 6)}  ${pad(s.bytes, 8)}  ${s.status}  ${s.path}${s.status >= 300 && s.status < 400 ? '   ⚠️ przekierowanie (brak sesji? --cookie)' : ''}`);
}
if (baselineUpdated) console.log(`\n📌 Zapisano bazę: ${basePath} (${rows.length} tras, commit ${commit ?? '?'})`);
for (const n of notes) console.log(n);
for (const f of fails) console.log(`❌ ${f}`);
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, 'perf-audit.json'), JSON.stringify({ schemaVersion: 2, adapter: generic?.kind || 'sveltekit', status: fails.length ? 'failed' : 'passed', baselineUpdated, repo, commit, build: mtime, budget: { ...budget, path: budgetPath }, baseline: basePath, totals, routes: rows, biggest, ssr, fails, notes }, null, 2));
console.log(`\n${fails.length ? '❌ G1-perf: ' + fails.length + ' blokerów' : '✅ G1-perf OK'} · perf-audit.json → ${out}`);
process.exit(fails.length ? 1 : 0);

} catch (error) {
 console.error(`Helix perf: ${error.message}`);
 if (reportOut) { fs.mkdirSync(reportOut, { recursive: true }); fs.writeFileSync(path.join(reportOut, 'perf-audit.json'), JSON.stringify({ schemaVersion: 2, status: 'incomplete', errors: [error.message] }, null, 2)); }
 process.exitCode = 2;
}
