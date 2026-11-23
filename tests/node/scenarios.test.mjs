import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validate } from '../../scripts/scenarios.mjs';

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../scripts/scenarios.mjs');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'helix-scenarios-'));
const notes = [], reachedAway = [], stolen = [];
let second, other;
let server, origin;
const page = body => `<!doctype html><html lang="pl"><title>t</title><body><main>${body}</main></body></html>`;
test.before(async () => {
  server = http.createServer((req, res) => {
    const cookie = req.headers.cookie || '';
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      res.setHeader('content-type', 'text/html; charset=utf-8');
      if (req.method === 'POST' && req.url === '/api/pin') { res.setHeader('content-type', 'application/json'); res.end('{"pin":"4821"}'); }
      else if (req.url === '/hub') res.end(page('<form method="post" action="/hub/login"><input name="pin"><button>Wejdź</button></form>'));
      else if (req.method === 'POST' && req.url === '/hub/login') {
        if (body === 'pin=4821') { res.statusCode = 303; res.setHeader('set-cookie', 'hub=ok; Path=/; HttpOnly'); res.setHeader('location', '/hub/start'); res.end(); }
        else { res.statusCode = 303; res.setHeader('location', '/hub'); res.end(); }
      } else if (req.url === '/hub/start') res.end(page(cookie.includes('hub=ok') ? '<h1>Witaj na hali</h1>' : '<h1>Brak wejścia</h1>'));
      else if (req.url === '/notes') res.end(page('<form method="post" action="/notes/add"><input name="text"><button>Zapisz</button></form><ul>' + notes.map(n => `<li>${n}</li>`).join('') + '</ul>'));
      else if (req.method === 'POST' && req.url === '/notes/add') { notes.push(decodeURIComponent(body.replace('text=', '').replace(/\+/g, ' '))); res.statusCode = 303; res.setHeader('location', '/notes'); res.end(); }
      else if (req.url === '/api/away') { reachedAway.push('redirected'); res.statusCode = 307; res.setHeader('location', other + '/steal'); res.end(); }
      else if (req.url === '/api/secret') { res.setHeader('content-type', 'application/json'); res.end('{"token":"TOP/SECRET \\"x\\""}'); }
      else if (req.url === '/evil') res.end(page('<a id="t" href="/people/../admin/reset">x</a><a id="dots" href="/people/..">y</a><a id="sel" href="/people/foo.bar">z</a><p id="long">' + 'a'.repeat(3000) + '!</p>'));
      else if (req.url === '/shell') res.end(page('<iframe src="/list" style="width:600px;height:300px"></iframe>'));
      else if (req.url === '/list') res.end(page('<a href="/people/lista">Lista</a><a href="/people/3f2a9c1e-0000-4000-8000-00000000abcd">Jan</a>'));
      else { res.statusCode = 404; res.end(page('brak')); }
    });
  });
  second = http.createServer((req, res) => { stolen.push(req.url); res.end('x'); });
  await new Promise(resolve => second.listen(0, '127.0.0.1', resolve));
  other = `http://127.0.0.1:${second.address().port}`;
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => { server.close(); second.close(); fs.rmSync(dir, { recursive: true, force: true }); });

const run = (name, scenarios, env = process.env) => new Promise(resolve => {
  const out = path.join(dir, name); fs.mkdirSync(out, { recursive: true });
  const input = path.join(dir, name + '.json');
  fs.writeFileSync(input, JSON.stringify({ origin, out, session_dir: out, storage_state: null, step_timeout_ms: 2500, scenarios }));
  execFile(process.execPath, [script, input], { timeout: 60000, env }, (error, stdout, stderr) => {
    let report; try { report = JSON.parse(fs.readFileSync(path.join(out, 'scenarios.json'), 'utf8')); } catch {}
    resolve({ code: error ? error.code : 0, stderr, report, out });
  });
});

test('a scenario captures a value, logs in through the application form and saves that session', async () => {
  const r = await run('hub', [{ id: 'hub-pin', session: 'none', save_session: { routes_prefix: '/hub/' }, steps: [
    { request: { method: 'POST', path: '/api/pin' }, capture: { name: 'pin', pointer: '/pin' } },
    { goto: '/hub' }, { fill: 'input[name=pin]', value: '{pin}' }, { click: 'button' }, { expect_path: '/hub/start' }, { expect_text: 'Witaj na hali' }] }]);
  assert.equal(r.code, 0, r.stderr + JSON.stringify(r.report));
  const row = r.report.scenarios[0];
  assert.equal(row.status, 'PASS'); assert.equal(row.completed, 6); assert.equal(row.routes_prefix, '/hub/');
  const file = path.join(r.out, 'scenario-hub-pin.json');
  assert.equal(row.session_saved, true); assert.ok(!('session_file' in row));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.ok(JSON.parse(fs.readFileSync(file, 'utf8')).cookies.some(c => c.name === 'hub'));
});

test('the same scenario passes under the network guard that every Node process of a real run is started with', async () => {
  // Przebieg ładuje straż do każdego procesu Node; bez niej test przechodził, a krok request padał w przebiegu (A58).
  const free = await new Promise(resolve => { const s = http.createServer().listen(0, '127.0.0.1', () => { const port = s.address().port; s.close(() => resolve(port)); }); });
  const guard = path.join(dir, 'guard.json'), box = path.join(dir, 'box'); fs.mkdirSync(box, { mode: 0o700 });
  fs.writeFileSync(guard, JSON.stringify({ schema_version: 1, kind: 'runtime-sinks-input', binding: { attempt_id: 'sink-' + 'a'.repeat(32) }, bearer_token: 'b'.repeat(64),
    origin: 'http://127.0.0.1:9', deadline_unix_ms: Date.now() + 600000, limits: { max_body_bytes: 1048576, max_requests: 1000 }, own_origins: [origin], synthetic_domains: [],
    operations: [{ id: 'mail.send', provider: 'mail', hosts: ['example.invalid'], method: 'POST', encoding: 'json', effect: 'capture', path_pattern: '^/x$', query_keys: [], response_status: 200 }],
    browser_control_origins: ['http://127.0.0.1:' + free], mailbox_path: box, public_path: box }), { mode: 0o600 });
  const env = { ...process.env, NODE_OPTIONS: '--require ' + JSON.stringify(path.join(path.dirname(script), '..', 'bin', 'runtime-sinks-preload.cjs')), HELIX_RUNTIME_SINK_INPUT: guard, HELIX_BROWSER_PORT: String(free) };
  const blocked = await new Promise(resolve => execFile(process.execPath, ['-e', `fetch(${JSON.stringify(other)}).then(() => process.exit(0), () => process.exit(7))`], { env }, error => resolve(error ? error.code : 0)));
  assert.equal(blocked, 7, 'straż nie jest aktywna w procesie testowym');
  const r = await run('guarded', [{ id: 'hub-pin', session: 'none', steps: [
    { request: { method: 'POST', path: '/api/pin' }, capture: { name: 'pin', pointer: '/pin' } },
    { goto: '/hub' }, { fill: 'input[name=pin]', value: '{pin}' }, { click: 'button' }, { expect_path: '/hub/start' }] }], env);
  assert.equal(r.report?.scenarios[0].status, 'PASS', r.stderr + JSON.stringify(r.report));
});

test('a real write is performed and its result is checked on the screen', async () => {
  const r = await run('notes', [{ id: 'note-save', session: 'none', steps: [
    { goto: '/notes' }, { fill: 'input[name=text]', value: 'Notatka z testu' }, { click: 'button' }, { expect_text: 'Notatka z testu' }] }]);
  assert.equal(r.code, 0, r.stderr + JSON.stringify(r.report)); assert.deepEqual(notes, ['Notatka z testu']);
});

test('a failed expectation names the step and does not echo typed values', async () => {
  const r = await run('fail', [{ id: 'wrong-pin', session: 'none', steps: [
    { goto: '/hub' }, { fill: 'input[name=pin]', value: '9999' }, { click: 'button' }, { expect_text: 'Witaj na hali' }] }]);
  assert.equal(r.code, 1, r.stderr);
  const row = r.report.scenarios[0];
  assert.equal(row.status, 'FAIL'); assert.equal(row.failed_step, 3); assert.ok(!JSON.stringify(row).includes('9999'));
});

test('a scenario that needs the screen session is blocked without it; malformed steps are rejected', async () => {
  const r = await run('nosession', [{ id: 'needs-session', steps: [{ goto: '/notes' }] }]);
  assert.equal(r.report.scenarios[0].status, 'BLOCKED');
  assert.throws(() => validate({ origin: 'http://127.0.0.1:1', scenarios: [{ id: 'x', steps: [{ goto: 'https://example.invalid/' }] }] }), /INVALID_PATH/);
  assert.throws(() => validate({ origin: 'http://127.0.0.1:1', scenarios: [{ id: 'x', steps: [{ goto: '/a', click: 'b' }] }] }), /INVALID_STEP/);
});

test('elements inside a same-application frame are found and captured', async () => {
  const r = await run('frame', [{ id: 'frame-capture', session: 'none', steps: [
    { goto: '/shell' }, { capture: { name: 'who', selector: 'a[href^="/people/"]', attribute: 'href', regex: '/people/([0-9a-f-]{36})' } }, { goto: '/people/{who}' }] }]);
  assert.equal(r.report.scenarios[0].status, 'PASS', JSON.stringify(r.report));
  // ścieżka końcowa pokazuje nazwę przechwyconej wartości, nie ją samą
  assert.equal(r.report.scenarios[0].final_path, '/people/{who}');
});

test('an API redirect to another origin is not followed and nothing reaches that origin', async () => {
  const r = await run('away', [{ id: 'redirect', session: 'none', steps: [{ request: { method: 'POST', path: '/api/away', json: { secret: 'S3CRET' } } }] }]);
  assert.equal(r.report.scenarios[0].reason, 'REQUEST_REDIRECT'); assert.deepEqual(stolen, []); assert.deepEqual(reachedAway, ['redirected']);
});

test('unsafe captured values, runaway expressions and secrets never reach paths, reasons or the report', async () => {
  const r = await run('evil', [
    { id: 'traversal', session: 'none', steps: [{ goto: '/evil' }, { capture: { name: 'id', selector: '#t', attribute: 'href', regex: '/people/(.+)' } }, { goto: '/people/{id}' }] },
    { id: 'dots', session: 'none', steps: [{ goto: '/evil' }, { capture: { name: 'id', selector: '#dots', attribute: 'href', regex: '/people/(.+)' } }, { goto: '/people/{id}/reset' }] },
    { id: 'selector', session: 'none', steps: [{ goto: '/evil' }, { capture: { name: 'id', selector: '#sel', attribute: 'href', regex: '/people/(.+)' } }, { click: '#{id}' }] },
    { id: 'redos', session: 'none', steps: [{ goto: '/evil' }, { capture: { name: 'x', selector: '#long', regex: '^((a+)+)$' } }] },
    { id: 'secret', session: 'none', steps: [{ request: { method: 'GET', path: '/api/secret' }, capture: { name: 'tok', pointer: '/token' } }] },
    { id: 'after', session: 'none', steps: [{ goto: '/notes' }, { expect_text: 'Zapisz' }] }]);
  const by = Object.fromEntries(r.report.scenarios.map(row => [row.id, row]));
  assert.equal(by.traversal.reason, 'CAPTURE_UNSAFE'); assert.equal(by.dots.reason, 'CAPTURE_UNSAFE'); assert.equal(by.selector.reason, 'CAPTURE_UNSAFE'); assert.equal(by.redos.reason, 'CAPTURE_TIMEOUT'); assert.equal(by.secret.reason, 'CAPTURE_UNSAFE');
  assert.equal(by.after.status, 'PASS', 'later scenarios still run');
  assert.ok(!JSON.stringify(r.report).includes('SECRET') && !r.stderr.includes('SECRET'));
});

test('an existing session file is never adopted: the scenario fails and reports no saved session', async () => {
  const out = path.join(dir, 'exists'); fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'scenario-taken.json'), '{"cookies":[]}');
  const r = await run('exists', [{ id: 'taken', session: 'none', save_session: { routes_prefix: '/hub/' }, steps: [{ goto: '/notes' }] }]);
  const row = r.report.scenarios[0];
  assert.equal(row.status, 'FAIL'); assert.equal(row.reason, 'SESSION_SAVE_FAILED'); assert.ok(!row.session_saved && !row.routes_prefix);
  assert.throws(() => validate({ origin: 'http://127.0.0.1:1', scenarios: [{ id: 'x', save_session: { routes_prefix: '/' }, steps: [{ goto: '/a' }] }] }), /INVALID_SAVE_SESSION/);
});

test('a request step works against the run-owned HTTPS certificate that only the browser trusts', async () => {
  const key = path.join(dir, 'tls.key'), cert = path.join(dir, 'tls.crt');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const spki = crypto.createHash('sha256').update(new crypto.X509Certificate(fs.readFileSync(cert)).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const posts = [], hits = [];
  const secure = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
    hits.push(req.url);
    if (req.url === '/api/list') { res.setHeader('content-type', 'application/json'); res.end('[{"id":"3f2a9c1e-0000-4000-8000-00000000abcd"}]'); }
    else if (req.url === '/api/drop') { posts.push(1); req.socket.destroy(); }
    else if (req.url === '/api/hang') { res.setHeader('content-type', 'application/json'); res.write('[{"id":'); }
    else if (req.url === '/api/moved') { res.statusCode = 302; res.setHeader('location', '/api/list'); res.end(); }
    else { res.setHeader('content-type', 'text/html; charset=utf-8'); res.end(page('<h1>Start</h1>')); }
  });
  await new Promise(resolve => secure.listen(0, '127.0.0.1', resolve));
  const secureOrigin = 'https://localhost:' + secure.address().port, out = path.join(dir, 'tls-out');
  fs.mkdirSync(out, { recursive: true });
  const input = path.join(dir, 'tls-input.json');
  fs.writeFileSync(input, JSON.stringify({ origin: secureOrigin, out, session_dir: dir, storage_state: null, scenarios: [
    { id: 'tls', session: 'none', steps: [{ request: { method: 'GET', path: '/api/list' }, capture: { name: 'kto', pointer: '/0/id' } }, { goto: '/' }, { expect_text: 'Start' }] },
    { id: 'tls-moved', session: 'none', steps: [{ request: { method: 'GET', path: '/api/moved' } }] },
    { id: 'tls-hang', session: 'none', steps: [{ request: { method: 'GET', path: '/api/hang' } }] }], step_timeout_ms: 1500 }));
  // zapis, po którym połączenie pada: błąd transportu nie może ponowić żądania
  const plain = path.join(dir, 'tls-drop.json'), dropOut = path.join(dir, 'tls-drop-out'); fs.mkdirSync(dropOut, { recursive: true });
  fs.writeFileSync(plain, JSON.stringify({ origin: secureOrigin, out: dropOut, session_dir: dropOut, storage_state: null, scenarios: [{ id: 'drop', session: 'none', steps: [{ request: { method: 'POST', path: '/api/drop', json: { a: 1 } } }] }] }));
  const env = { ...process.env, HELIX_RUNTIME_TLS_SPKI_LIST: spki }; delete env.NODE_EXTRA_CA_CERTS;
  await new Promise(resolve => execFile(process.execPath, [script, plain], { timeout: 60000, env }, () => resolve()));
  const dropped = JSON.parse(fs.readFileSync(path.join(dropOut, 'scenarios.json'), 'utf8')).scenarios[0];
  assert.equal(dropped.reason, 'REQUEST_FAILED', JSON.stringify(dropped)); assert.equal(posts.length, 1);
  await new Promise(resolve => execFile(process.execPath, [script, input], { timeout: 60000, env }, () => resolve()));
  secure.closeAllConnections(); secure.close();
  const rows = JSON.parse(fs.readFileSync(path.join(out, 'scenarios.json'), 'utf8')).scenarios;
  // serwer z innym kluczem niż przypięty przez przebieg nie dostaje żądania
  const wrong = { ...env, HELIX_RUNTIME_TLS_SPKI_LIST: crypto.createHash('sha256').update('inny').digest('base64') };
  const before = hits.length;
  await new Promise(resolve => execFile(process.execPath, [script, input], { timeout: 60000, env: wrong }, () => resolve()));
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'scenarios.json'), 'utf8')).scenarios[0].reason, 'REQUEST_FAILED'); assert.equal(hits.length, before);
  assert.equal(rows[0].status, 'PASS', JSON.stringify(rows));
  assert.equal(rows[1].reason, 'REQUEST_REDIRECT', JSON.stringify(rows));
  // odpowiedź, która nigdy się nie kończy, zamyka krok po limicie czasu i zostawia wynik w raporcie
  assert.equal(rows[2].reason, 'REQUEST_FAILED', JSON.stringify(rows));
});
