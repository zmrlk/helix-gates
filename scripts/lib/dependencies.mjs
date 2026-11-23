import fs from 'node:fs';
import resolveDependency from '../../bin/dependencies.cjs';
import { PNG as BuiltinPNG } from './png.mjs';
import path from 'node:path';
import { createRequire } from 'node:module';

// Explicit override wins. No install, no dependence on Playwright's private APIs.
export function loadDependencies() {
  const candidates = [process.env.PLAYWRIGHT_MODULE, path.join(process.cwd(), 'node_modules/playwright'), path.join(process.cwd(), 'frontend/node_modules/playwright')].filter(Boolean);
  const local = createRequire(import.meta.url);
  try { candidates.unshift(local.resolve('playwright/package.json')); } catch {}
  if (process.env.PLAYWRIGHT_MODULE) { candidates.unshift(candidates.splice(candidates.indexOf(process.env.PLAYWRIGHT_MODULE), 1)[0]); }
  try { candidates.push(resolveDependency('playwright')); } catch {}
  for (const entry of [...new Set(candidates)]) {
    const pkg = entry.endsWith('.json') ? entry : entry.endsWith('.js') || entry.endsWith('.mjs') ? path.join(path.dirname(entry), 'package.json') : path.join(entry, 'package.json');
    if (!fs.existsSync(pkg)) {
      if (entry === process.env.PLAYWRIGHT_MODULE) throw new Error('Nieprawidłowy PLAYWRIGHT_MODULE: brak package.json');
      continue;
    }
    try {
      const req = createRequire(pkg);
      const { chromium } = req(path.dirname(pkg));
      let PNG;
      try { PNG = req(process.env.HELIX_PNG_MODULE || 'pngjs').PNG; } catch (error) { if (process.env.HELIX_PNG_MODULE) throw error; }
      return { chromium, PNG: PNG || BuiltinPNG, playwrightVersion: JSON.parse(fs.readFileSync(pkg, 'utf8')).version };
    } catch (error) {
      if (entry === process.env.PLAYWRIGHT_MODULE) throw error;
    }
  }
  throw new Error('Brak Playwright. Ustaw PLAYWRIGHT_MODULE na istniejący katalog node_modules/playwright.');
}

export async function launchBrowser(chromium) {
  const options = { args: ['--lang=pl-PL'], host: '127.0.0.1' };
  // W przebiegu runtime aplikacja i lokalny dostawca tożsamości mają własne certyfikaty jednorazowe. Przeglądarka ufa
  // wyłącznie kluczom przypiętym przez przebieg (tak samo jak runtime-browser.cjs), bez wyłączania sprawdzania certyfikatów.
  const tlsKeys = process.env.HELIX_RUNTIME_TLS_SPKI_LIST || process.env.HELIX_RUNTIME_OIDC_SPKI;
  if (tlsKeys) {
    if (!tlsKeys.split(',').every(key => /^[A-Za-z0-9+/]{43}=$/.test(key))) throw new Error('invalid owned TLS key list');
    options.args.push('--ignore-certificate-errors-spki-list=' + tlsKeys);
  }
  if (process.env.HELIX_BROWSER_EXECUTABLE) options.executablePath = process.env.HELIX_BROWSER_EXECUTABLE;
  // Pod izolacją Helixa nasłuch jest dozwolony tylko na porcie przydzielonym przez przebieg.
  if (process.env.HELIX_BROWSER_PORT) {
    const port = Number(process.env.HELIX_BROWSER_PORT);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('HELIX_BROWSER_PORT: wymagany port 1024-65535');
    options.port = port;
  }
  let server;
  try { server = await chromium.launchServer(options); }
  catch (error) {
    if (options.executablePath || !error.message.includes("Executable doesn't exist")) throw error;
    // Use an installed browser, never download one. Actual version is sealed in the baseline.
    if (process.platform === 'darwin' && fs.existsSync('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')) {
      console.log('Helix: brak przypiętego Chromium; używam istniejącego Google Chrome (wersja w raporcie).');
      server = await chromium.launchServer({ ...options, channel: 'chrome' });
    } else {
      throw error;
    }
  }
  let browser;
  try { browser = await chromium.connect(server.wsEndpoint(), { timeout: 10000 }); }
  catch (error) { await server.kill(); throw error; }
  const disconnect = browser.close.bind(browser);
  let closing;
  browser.helixCleanup = { forced: false };
  // BrowserServer owns this freshly launched process and temp profile. No shared/user browser is touched.
  browser.close = () => closing ??= (async () => {
    let timer;
    try {
      await Promise.race([
        server.close(),
        new Promise((resolve, reject) => {
          timer = setTimeout(() => { browser.helixCleanup.forced = true; server.kill().then(resolve, reject); }, 1500);
        }),
      ]);
    } catch (error) {
      await server.kill().catch(() => {});
      throw error;
    } finally {
      clearTimeout(timer);
      await disconnect().catch(() => {});
    }
  })();
  return browser;
}
