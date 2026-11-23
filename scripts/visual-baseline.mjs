#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { hash, keyOf } from './lib/visual.mjs';

// Deliberate separate command: audits NEVER create or update approved baselines.
// Records a declaration of human approval; it cannot authenticate the reviewer.
try {
  const args = process.argv.slice(2), options = {};
  if (args.includes('--help')) {
    console.log('Po obejrzeniu report.html i jawnej akceptacji: node visual-baseline.mjs --from <audit.json> --out <NOWY-folder> --approved-by <osoba> --note <zakres-zgody>');
    process.exit(0);
  }
  for (let i = 0; i < args.length; i += 2) {
    if (!['--from', '--out', '--approved-by', '--note'].includes(args[i]) || !args[i + 1] || args[i + 1].startsWith('--') || options[args[i]]) throw new Error('Nieprawidłowe argumenty; zobacz --help');
    options[args[i]] = args[i + 1];
  }
  for (const name of ['--from', '--out', '--approved-by', '--note']) if (!options[name]?.trim()) throw new Error(`Wymagane ${name}`);
  const source = path.resolve(options['--from']), out = path.resolve(options['--out']);
  const report = JSON.parse(fs.readFileSync(source, 'utf8'));
  if (report.schemaVersion !== 2 || report.summary?.status !== 'passed' || !report.summary.complete || !report.contract || !report.caseId) throw new Error('Wzorzec wymaga kompletnego, zielonego raportu Helix 2');
  const images = {}, buffers = [];
  for (const run of report.runs) {
    if (run.sweep) continue;
    if (run.status !== 'complete') throw new Error('Niekompletny przebieg');
    for (const item of [run, ...(run.captures ?? [])]) {
    if (!item.shot || !item.shotSha256 || !/^shot-[\w-]+\.png$/.test(item.shot)) throw new Error('Brak stabilnego zrzutu');
    const buffer = fs.readFileSync(path.join(path.dirname(source), item.shot));
    if (hash(buffer) !== item.shotSha256) throw new Error(`Zmieniony zrzut ${item.shot}`);
    images[keyOf(run) + (item.id ? '-' + item.id : '')] = { file: item.shot, sha256: item.shotSha256 };
    buffers.push([item.shot, buffer]);
    }
  }
  if (!buffers.length) throw new Error('Raport nie zawiera zrzutów');
  // mkdir without recursive/exist_ok intentionally refuses ANY existing destination.
  fs.mkdirSync(out);
  for (const [file, buffer] of buffers) fs.writeFileSync(path.join(out, file), buffer, { flag: 'wx' });
  fs.writeFileSync(path.join(out, 'baseline.json'), JSON.stringify({
    schemaVersion: 1, caseId: report.caseId, contract: report.contract,
    approval: { reviewer: options['--approved-by'], note: options['--note'], at: new Date().toISOString() },
    sourceReportSha256: hash(fs.readFileSync(source)), images,
  }, null, 2) + '\n', { flag: 'wx' });
  console.log(`Zapisano ${buffers.length} zatwierdzonych zrzutów → ${out}`);
} catch (error) { console.error(error.message); process.exitCode = 2; }
