import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from '../../scripts/lib/config.mjs';
import { loadDependencies } from '../../scripts/lib/dependencies.mjs';
import { comparePNG, hash, baselineImage, loadBaseline, renderContract } from '../../scripts/lib/visual.mjs';
import { finalize, escapeHTML } from '../../scripts/lib/report.mjs';
import { PNG } from '../../scripts/lib/png.mjs';
const options = { pixelThreshold: 0, maxDiffPixels: 0, maxDiffRatio: 0 };
function png(width = 3, height = 2, color = 255) { const p = new PNG({ width, height }); p.data.fill(color); return PNG.sync.write(p); }

test('argument validation cannot hang sweeps or silently skip coverage', () => {
  for (const args of [['--sweep','280-1600:0'],['--sweep','1600-280:40'],['--sweep','280-1600:1'],['--widths','NaN'],['--widths','0'],['--themes','oops'],['--workers','Infinity'],['--workers','0'],['--no-shots','--baseline','x'],['--nonsense','1'],['--wait'],['--widths','390','--widths','280']])
    assert.throws(() => parseArgs(['https://example.test', ...args]), args.join(' '));
  const cfg = parseArgs(['--no-shots', 'https://example.test', '--sweep', '280-400:40']);
  assert.equal(cfg.noShots, true); assert.deepEqual(cfg.extra, [320,360,400]);
  assert.deepEqual(parseArgs(['https://example.test','--sweep','280-400']).extra,[320,360,400]);
});
test('URL paths are encoded and baseline cannot be overwritten by output', () => {
  assert.throws(() => parseArgs(['https://x','--out','/tmp/base/output','--baseline','/tmp/base']));
  assert.throws(() => parseArgs(['https://me:password@x']));
  assert.throws(() => parseArgs(['javascript:alert(1)']));
});
test('exact PNG comparison catches a single changed pixel', () => {
  const expected = png(); const current = PNG.sync.read(expected); current.data[0] = 0;
  const r = comparePNG(PNG.sync.write(current), expected, PNG, options);
  assert.equal(r.status, 'mismatch'); assert.equal(r.differentPixels, 1); assert.ok(r.diffBuffer);
  assert.deepEqual(r.bounds, { left: 0, top: 0, right: 0, bottom: 0 });
  assert.equal(comparePNG(expected, expected, PNG, options).status, 'match');
});
test('dimensions, corrupt PNG, both budgets and explicit channel tolerance', () => {
  assert.equal(comparePNG(png(4), png(), PNG, options).reason,'dimensions');
  assert.throws(() => comparePNG(Buffer.alloc(24), png(), PNG, options));
  const a = PNG.sync.read(png()); a.data[0]--;
  assert.equal(comparePNG(PNG.sync.write(a),png(),PNG,{...options,pixelThreshold:1}).status,'match');
  assert.equal(comparePNG(png(3,2,0),png(),PNG,{...options,maxDiffRatio:1}).status,'mismatch');
  assert.equal(comparePNG(png(3,2,0),png(),PNG,{...options,maxDiffRatio:1,maxDiffPixels:6}).status,'match');
});
test('reference digest, missing viewport and incompatible environment fail closed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'helix-unit-'));
  try {
    const buffer=png(); fs.writeFileSync(path.join(dir,'shot-light-390.png'),buffer);
    const manifest={schemaVersion:1,caseId:'test',contract:{dpr:2},approval:{reviewer:'TEST',note:'fixture',at:'2026-01-01'},images:{'light-390':{file:'shot-light-390.png',sha256:hash(buffer)}}};
    fs.writeFileSync(path.join(dir,'baseline.json'),JSON.stringify(manifest));
    assert.equal(loadBaseline(dir,{dpr:2},'test').caseId,'test');
    assert.throws(()=>loadBaseline(dir,{dpr:1},'test'));
    assert.throws(()=>loadBaseline(dir,{dpr:2},'other'));
    assert.throws(()=>baselineImage(dir,manifest,'dark-390'));
    assert.deepEqual(baselineImage(dir,manifest,'light-390'),buffer);
    fs.writeFileSync(path.join(dir,'shot-light-390.png'),png(4));
    assert.throws(()=>baselineImage(dir,manifest,'light-390'));
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
test('report distinguishes incomplete, defects and unverified visual acceptance', () => {
  const report={_started:performance.now(),planned:1,errors:[],runs:[{errors:[],blockers:0}],baseline:null};
  assert.equal(finalize(report,true),0); assert.equal(report.summary.visual,'not_checked');
  assert.equal(finalize(report,false),2);
  report.runs[0].blockers=1; assert.equal(finalize(report,true),1);
  report.runs[0].errors.push('screenshot failed'); assert.equal(finalize(report,true),2);
  assert.equal(escapeHTML('<script>"&'), '&lt;script&gt;&quot;&amp;');
});

test('approved render contract seals viewport/theme coverage and pixel tolerance', () => {
 const config=parseArgs(['https://example.test']);const base=renderContract(config,{browser:'test'});
 assert.notDeepEqual(renderContract({...config,widths:[1440]},base.environment),base);
 assert.notDeepEqual(renderContract({...config,themes:['light']},base.environment),base);
 assert.notDeepEqual(renderContract({...config,pixelThreshold:255},base.environment),base);
 assert.deepEqual(renderContract({...config,widths:[...config.widths].reverse(),themes:[...config.themes].reverse()},base.environment),base);
});

test('report cannot certify an unperformed visual comparison even if a caller bypasses CLI validation',()=>{
 const report={_started:performance.now(),planned:1,errors:[],baseline:{},runs:[{errors:[],blockers:0,sweep:false,visual:{status:'not_checked'}}]};
 assert.equal(finalize(report,true),2);assert.equal(report.summary.visual,'incomplete');
 report.runs[0].visual.status='match';assert.equal(finalize(report,true),0);
 report.runs[0].captures=[{visual:{status:'not_checked'}}];assert.equal(finalize(report,true),2);
 report.runs=[];assert.equal(finalize(report,true),2);
});
