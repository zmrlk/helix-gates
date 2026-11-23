import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { PNG as BuiltinPNG } from './png.mjs';

export const hash = data => crypto.createHash('sha256').update(data).digest('hex');
export const keyOf = run => `${run.theme}-${run.width}`;
export const renderContract = (config, environment) => ({
  environment, height: config.height, dpr: config.dpr, fullPage: config.fullPage,
  themeAttr: config.themeAttr, mask: config.mask, locale: 'pl-PL', timezone: 'Europe/Warsaw',
  widths: [...config.widths].sort((a, b) => a - b), themes: [...config.themes].sort(),
  tolerance: { pixelThreshold: config.pixelThreshold, maxDiffPixels: config.maxDiffPixels, maxDiffRatio: config.maxDiffRatio },
});
export function loadBaseline(folder, contract, caseId) {
  const manifest = JSON.parse(fs.readFileSync(path.join(folder, 'baseline.json'), 'utf8'));
  if (manifest.schemaVersion !== 1 || !manifest.approval?.reviewer?.trim() || !manifest.approval?.note?.trim() || !manifest.approval?.at || !manifest.images) throw new Error('Wzorzec nie ma kompletnego manifestu zatwierdzenia');
  if (manifest.caseId !== caseId) throw new Error(`Inny ekran we wzorcu: ${manifest.caseId}`);
  if (JSON.stringify(manifest.contract) !== JSON.stringify(contract)) throw new Error('Warunki wzorca są inne (środowisko, rozmiary, motywy, maski lub tolerancja). Użyj zatwierdzonego zakresu/progów albo świadomie zatwierdź nowy wzorzec.');
  return manifest;
}
export function baselineImage(folder, manifest, key) {
  const entry = manifest.images[key];
  if (!entry || !/^[\w.-]+\.png$/.test(entry.file)) throw new Error(`Brak zatwierdzonego obrazu ${key}`);
  const resolved = fs.realpathSync(path.join(folder, entry.file));
  if (!resolved.startsWith(fs.realpathSync(folder) + path.sep)) throw new Error('Obraz wzorca wychodzi poza katalog');
  const buffer = fs.readFileSync(resolved);
  if (hash(buffer) !== entry.sha256) throw new Error(`Zmieniony plik wzorca ${key}: SHA-256 nie zgadza się z zatwierdzeniem`);
  return buffer;
}

// Absolute per-channel RGBA distance, exact by default. No undocumented image dependencies.
export function comparePNG(actualBuffer, expectedBuffer, PNG, options) {
  PNG ||= BuiltinPNG;
  const dimensions = buffer => {
    if (buffer.length < 24 || buffer.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') throw new Error('Nieprawidłowy PNG');
    const width = buffer.readUInt32BE(16), height = buffer.readUInt32BE(20);
    if (!width || !height || width * height > 40000000) throw new Error('PNG przekracza 40 mln pikseli; użyj --viewport-only lub podziel ekran');
    return { width, height };
  };
  const ad = dimensions(actualBuffer), ed = dimensions(expectedBuffer);
  if (ad.width !== ed.width || ad.height !== ed.height) return { status: 'mismatch', reason: 'dimensions', actualSize: ad, expectedSize: ed, differentPixels: null };
  const a = PNG.sync.read(actualBuffer), b = PNG.sync.read(expectedBuffer);
  if (actualBuffer.equals(expectedBuffer)) return { status: 'match', differentPixels: 0, ratio: 0, size: ad };
  const diff = new PNG({ width: a.width, height: a.height });
  let differentPixels = 0, left = a.width, top = a.height, right = 0, bottom = 0;
  for (let i = 0; i < a.data.length; i += 4) {
    const changed = Math.abs(a.data[i] - b.data[i]) > options.pixelThreshold
      || Math.abs(a.data[i + 1] - b.data[i + 1]) > options.pixelThreshold
      || Math.abs(a.data[i + 2] - b.data[i + 2]) > options.pixelThreshold
      || Math.abs(a.data[i + 3] - b.data[i + 3]) > options.pixelThreshold;
    if (changed) {
      differentPixels++;
      const p = i / 4, x = p % a.width, y = Math.floor(p / a.width);
      left = Math.min(left, x); top = Math.min(top, y); right = Math.max(right, x); bottom = Math.max(bottom, y);
      diff.data[i] = 255; diff.data[i + 1] = 0; diff.data[i + 2] = 96;
    } else {
      const gray = Math.round(220 + (a.data[i] + a.data[i + 1] + a.data[i + 2]) / 3 * 35 / 255);
      diff.data[i] = diff.data[i + 1] = diff.data[i + 2] = gray;
    }
    diff.data[i + 3] = 255;
  }
  const ratio = differentPixels / (a.width * a.height);
  // Both budgets must hold: increasing only the percentage cannot conceal a small important defect.
  const status = differentPixels <= options.maxDiffPixels && ratio <= options.maxDiffRatio ? 'match' : 'mismatch';
  return { status, differentPixels, ratio, size: ad, bounds: differentPixels ? { left, top, right, bottom } : null,
    diffBuffer: differentPixels ? PNG.sync.write(diff) : null };
}
