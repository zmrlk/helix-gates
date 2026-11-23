#!/usr/bin/env node
// Scenariusze właściciela: krótkie ścieżki „wejdź, wpisz, kliknij, sprawdź” wykonywane w jednorazowej kopii aplikacji,
// z prawdziwymi zapisami. Służą do dwóch rzeczy, których samo oglądanie ekranów nie daje:
//  - sprawdzenia, że zapis albo formularz działa (kroki expect_*),
//  - wejścia tam, gdzie logowanie jest własne dla aplikacji (PIN, kod), i oddania tej sesji przeglądowi wskazanych tras.
// Użycie: node scenarios.mjs <plik wejściowy JSON> ; wynik: <out>/scenarios.json, zrzuty <out>/<id>.png
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { loadDependencies, launchBrowser } from './lib/dependencies.mjs';

const KINDS = ['goto', 'click', 'fill', 'press', 'wait_for', 'expect_path', 'expect_text', 'request', 'capture'];
const fail = (code, detail) => Object.assign(new Error(detail ? `${code}: ${detail}` : code), { code });
// Powody w raporcie to wyłącznie te stałe kody; surowe komunikaty przeglądarki i parserów mogą nieść wpisane albo przechwycone wartości.
const PUBLIC = new Set(['NO_SCREEN_SESSION', 'ELEMENT_NOT_FOUND', 'UNKNOWN_CAPTURE', 'CAPTURE_EMPTY', 'CAPTURE_UNSAFE', 'CAPTURE_TIMEOUT', 'REQUEST_STATUS', 'REQUEST_REDIRECT', 'REQUEST_FAILED', 'SESSION_SAVE_FAILED']);
// Przechwycona wartość trafia potem do ścieżki, selektora albo JSON-u: dopuszczamy tylko litery, cyfry, podkreślenie i łącznik.
// Kropka odpada, bo „..” zmienia ścieżkę, a „a.b” znaczenie selektora; to wystarcza na identyfikatory, kody i numery.
const SAFE_CAPTURE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

export function validate(input) {
  if (!input || typeof input !== 'object') throw fail('INVALID_INPUT');
  const origin = new URL(input.origin).origin;
  if (!Array.isArray(input.scenarios) || input.scenarios.length > 20) throw fail('INVALID_SCENARIOS');
  const ids = new Set();
  for (const scenario of input.scenarios) {
    if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(scenario.id || '') || ids.has(scenario.id)) throw fail('INVALID_SCENARIO_ID');
    ids.add(scenario.id);
    if (!['screen', 'none'].includes(scenario.session ?? 'screen')) throw fail('INVALID_SESSION', scenario.id);
    if (!Array.isArray(scenario.steps) || !scenario.steps.length || scenario.steps.length > 40) throw fail('INVALID_STEPS', scenario.id);
    for (const step of scenario.steps) {
      const kinds = KINDS.filter(kind => kind in step);
      // „capture” bywa dodatkiem do kroku „request”; poza tym jeden krok = jedna czynność
      if (kinds.length !== 1 && !(kinds.length === 2 && kinds.includes('request') && kinds.includes('capture'))) throw fail('INVALID_STEP', scenario.id);
      for (const key of ['goto', 'expect_path']) if (key in step && !(typeof step[key] === 'string' && step[key].startsWith('/') && !step[key].startsWith('//'))) throw fail('INVALID_PATH', scenario.id);
      if ('request' in step) {
        const r = step.request;
        if (!r || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method) || typeof r.path !== 'string' || !r.path.startsWith('/') || r.path.startsWith('//')) throw fail('INVALID_REQUEST', scenario.id);
      }
      if (step.capture && !(typeof step.capture.name === 'string' && /^[a-z0-9_]{1,40}$/.test(step.capture.name)
        && (step.capture.regex === undefined || (typeof step.capture.regex === 'string' && step.capture.regex.length <= 200)))) throw fail('INVALID_CAPTURE', scenario.id);
    }
    // sesja scenariusza służy wąskiej grupie tras; sam ukośnik przejąłby wszystkie
    if (scenario.save_session && !(scenario.save_session.as_screen_session === true && scenario.save_session.routes_prefix === undefined)
      && !(typeof scenario.save_session.routes_prefix === 'string' && /^\/[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]*)*$/.test(scenario.save_session.routes_prefix))) throw fail('INVALID_SAVE_SESSION', scenario.id);
  }
  return { ...input, origin };
}

const pointer = (value, ref) => String(ref).split('/').slice(1).reduce((node, key) => node == null ? undefined : node[key.replace(/~1/g, '/').replace(/~0/g, '~')], value);

async function runScenario(browser, input, scenario) {
  const result = { id: scenario.id, status: 'FAIL', steps: scenario.steps.length, completed: 0 };
  const captured = {};
  // {nazwa} w ścieżkach i wartościach = wartość przechwycona wcześniejszym krokiem tego scenariusza (tylko bezpieczne znaki)
  const fillIn = text => String(text).replace(/\{([a-z0-9_]+)\}/g, (whole, name) => { if (!(name in captured)) throw fail('UNKNOWN_CAPTURE'); return captured[name]; });
  const keep = (name, value) => { const text = String(value ?? ''); if (!SAFE_CAPTURE.test(text)) throw fail(text ? 'CAPTURE_UNSAFE' : 'CAPTURE_EMPTY'); captured[name] = text; };
  const sessionFile = path.join(input.session_dir, `scenario-${scenario.id}.json`);
  let context, page;
  try {
    const wanted = (scenario.session ?? 'screen') === 'screen';
    const state = wanted && input.storage_state && fs.existsSync(input.storage_state) ? JSON.parse(fs.readFileSync(input.storage_state, 'utf8')) : undefined;
    if (wanted && !state) return { ...result, status: 'BLOCKED', reason: 'NO_SCREEN_SESSION' };
    context = await browser.newContext({ locale: 'pl-PL', timezoneId: 'Europe/Warsaw', viewport: { width: 1440, height: 900 }, serviceWorkers: 'block', ...(state ? { storageState: state } : {}) });
    // Scenariusz nie wychodzi poza aplikację: każde żądanie przeglądarki pod inny adres (także po przekierowaniu) jest odcinane.
    await context.route('**/*', route => new URL(route.request().url()).origin === input.origin ? route.fallback() : route.abort('blockedbyclient'));
    page = await context.newPage();
    const timeout = input.step_timeout_ms ?? 8000;
    page.setDefaultTimeout(timeout);
    // Ekran bywa osadzony w ramce tej samej aplikacji (powłoka z kartami): element i tekst szukane są we wszystkich ramkach.
    const locate = async make => {
      const deadline = Date.now() + timeout;
      for (;;) {
        for (const frame of page.frames()) { const found = make(frame).first(); if (await found.isVisible().catch(() => false)) return found; }
        if (Date.now() > deadline) throw fail('ELEMENT_NOT_FOUND');
        await page.waitForTimeout(150);
      }
    };
    const bySelector = selector => locate(frame => frame.locator(fillIn(selector)));
    for (const [index, step] of scenario.steps.entries()) {
      result.failed_step = index;
      if ('goto' in step) await page.goto(input.origin + fillIn(step.goto), { waitUntil: 'domcontentloaded' });
      else if ('click' in step) await (await bySelector(step.click)).click();
      else if ('fill' in step) await (await bySelector(step.fill)).fill(fillIn(step.value ?? ''));
      else if ('press' in step) await page.keyboard.press(step.press);
      else if ('wait_for' in step) await bySelector(step.wait_for);
      else if ('expect_path' in step) await page.waitForURL(url => url.origin === input.origin && url.pathname === fillIn(step.expect_path));
      else if ('expect_text' in step) await locate(frame => frame.getByText(fillIn(step.expect_text), { exact: false }));
      else if ('request' in step) {
        const target = new URL(input.origin + fillIn(step.request.path));
        if (target.origin !== input.origin) throw fail('REQUEST_REDIRECT');
        // Żądanie wysyła przeglądarka, nie proces Node: w przebiegu straż sieciowa blokuje połączenia Node, a zaufanie do jednorazowego
        // certyfikatu aplikacji (przypięte klucze) ma tylko przeglądarka. Idzie z osobnej, pustej karty tej samej sesji: jej dokument
        // podstawia Helix, więc nie działa w niej żaden skrypt aplikacji i fetch jest nietknięty. Przekierowań nie śledzi wcale:
        // odpowiedź 3xx kończy krok. Błąd transportu kończy krok bez ponowienia.
        const data = step.request.json !== undefined ? JSON.parse(fillIn(JSON.stringify(step.request.json))) : undefined;
        let answer;
        const blank = await context.newPage();
        try {
          const anchor = input.origin + '/__helix_request__';
          await blank.route(anchor, route => route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>helix</title>' }));
          await blank.goto(anchor);
          // limit czasu obejmuje żądanie i odczyt treści; po jego upływie krok kończy się bez ponowienia
          answer = await blank.evaluate(async ({ href, method, data, limit }) => {
            const response = await fetch(href, { method, redirect: 'manual', credentials: 'same-origin', signal: AbortSignal.timeout(limit),
              ...(data !== undefined ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(data) } : {}) });
            return { status: response.status, moved: response.type === 'opaqueredirect', text: response.type === 'opaqueredirect' ? '' : await response.text() };
          }, { href: target.href, method: step.request.method, data, limit: timeout });
        } catch { throw fail('REQUEST_FAILED'); } finally { await blank.close().catch(() => {}); }
        const status = answer.status, readBody = () => JSON.parse(answer.text);
        if (answer.moved) throw fail('REQUEST_REDIRECT');
        if (status >= 300 && status < 400) throw fail('REQUEST_REDIRECT');
        if (status >= 400) throw fail('REQUEST_STATUS');
        if (step.capture) { let body; try { body = await readBody(); } catch { throw fail('CAPTURE_EMPTY'); } keep(step.capture.name, pointer(body, step.capture.pointer)); }
      } else if ('capture' in step) {
        // wartość z atrybutu albo tekstu elementu, opcjonalnie pierwsza grupa wyrażenia
        // Pasujących elementów bywa wiele (np. odnośniki menu obok odnośnika do rekordu): bierzemy pierwszy, którego wartość pasuje do wyrażenia.
        await bySelector(step.capture.selector);
        const values = [];
        for (const frame of page.frames()) {
          const found = frame.locator(fillIn(step.capture.selector));
          const count = Math.min(await found.count().catch(() => 0), 200);
          for (let i = 0; i < count && values.length < 200; i++) {
            const item = found.nth(i);
            values.push(String((step.capture.attribute ? await item.getAttribute(step.capture.attribute).catch(() => '') : await item.innerText().catch(() => '')) ?? '').slice(0, 4000));
          }
        }
        let match = null;
        for (const raw of values) {
          if (!step.capture.regex) { match = [raw, raw]; break; }
          // Wyrażenie właściciela działa na treści z aplikacji: wykonanie ma twardy limit czasu, żeby nie zawiesiło całego procesu.
          try { match = vm.runInNewContext('new RegExp(pattern).exec(text)', { pattern: step.capture.regex, text: raw }, { timeout: 250 }); }
          catch { throw fail('CAPTURE_TIMEOUT'); }
          if (match && match[1]) break;
        }
        keep(step.capture.name, match && match[1]);
      }
      result.completed = index + 1;
    }
    delete result.failed_step;
    // ścieżka końcowa bez przechwyconych wartości
    result.final_path = Object.entries(captured).reduce((text, [name, value]) => text.split(value).join(`{${name}}`), new URL(page.url()).pathname);
    if (scenario.save_session) {
      // Sukces dopiero po zapisaniu sesji; plik powstaje wyłącznie tutaj (wx), istniejący nigdy nie jest przejmowany.
      try { fs.writeFileSync(sessionFile, JSON.stringify(await context.storageState()), { mode: 0o600, flag: 'wx' }); }
      catch { throw fail('SESSION_SAVE_FAILED'); }
      result.session_saved = true;
      if (scenario.save_session.routes_prefix) result.routes_prefix = scenario.save_session.routes_prefix;
    }
    result.status = 'PASS';
  } catch (error) {
    result.status = 'FAIL';
    result.reason = PUBLIC.has(error && error.code) ? error.code : error && error.name === 'TimeoutError' ? 'TIMEOUT' : 'STEP_FAILED';
  } finally {
    if (page) await page.screenshot({ path: path.join(input.out, `${scenario.id}.png`), animations: 'disabled' }).then(() => { result.shot = `${scenario.id}.png`; }).catch(() => {});
    if (context) await context.close().catch(() => {});
  }
  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let browser, code = 0;
  try {
    const input = validate(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')));
    fs.mkdirSync(input.out, { recursive: true });
    browser = await launchBrowser(loadDependencies().chromium);
    const results = [];
    // Wynik jest zapisywany po każdym scenariuszu: przerwanie procesu nie gubi tego, co już się wykonało.
    for (const scenario of input.scenarios) {
      results.push(await runScenario(browser, input, scenario));
      fs.writeFileSync(path.join(input.out, 'scenarios.json'), JSON.stringify({ scenarios: results }, null, 2) + '\n');
    }
    code = results.every(row => row.status === 'PASS') ? 0 : 1;
  } catch (error) { console.error(`Helix scenarios: ${PUBLIC.has(error.code) || /^INVALID_/.test(error.code || '') ? error.code : 'RUN_FAILED'}`); code = 2; }
  finally { await browser?.close().catch(() => {}); }
  process.exitCode = code;
}
