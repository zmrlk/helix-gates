'use strict';
/* Owned local HTTPS front. Importing this module never opens a socket. */
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const {performance} = require('node:perf_hooks');

const MAX_FILE = 1024 * 1024;
const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
class ProxyError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function fail(code) { throw new ProxyError(code); }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function origin(value, protocol, hosts) {
  if (typeof value !== 'string') fail('INVALID_ORIGIN');
  let u;
  try { u = new URL(value); } catch { fail('INVALID_ORIGIN'); }
  if (u.protocol !== protocol || !hosts.includes(u.hostname) || !u.port ||
      value !== u.origin || u.username || u.password || u.search || u.hash) fail('INVALID_ORIGIN');
  return u;
}
function validateConfig(value) {
  const fields = ['schema_version', 'public_origin', 'backend_origin', 'cert_path', 'key_path',
    'deadline_unix_ms', 'request_timeout_ms'];
  if (!object(value) || Object.keys(value).some(k => !fields.includes(k)) ||
      fields.some(k => !(k in value)) || value.schema_version !== 1) fail('INVALID_CONFIG');
  const front = origin(value.public_origin, 'https:', ['localhost', '127.0.0.1', '[::1]']);
  const back = origin(value.backend_origin, 'http:', ['127.0.0.1', '[::1]']);
  if (front.port === back.port) fail('PORT_CONFLICT');
  if (!Number.isSafeInteger(value.deadline_unix_ms) || value.deadline_unix_ms <= 0 ||
      !Number.isInteger(value.request_timeout_ms) || value.request_timeout_ms < 1 ||
      value.request_timeout_ms > 60000) fail('INVALID_DEADLINE');
  for (const name of ['cert_path', 'key_path']) {
    if (typeof value[name] !== 'string' || !path.isAbsolute(value[name]) || /[\0\r\n]/.test(value[name])) fail('INVALID_TLS_PATH');
  }
  return Object.freeze({...value});
}
function regularFile(file, root, privateMode = false) {
  const target = path.resolve(file), relative = path.relative(root, target);
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) fail('TLS_PATH_OUTSIDE_PRIVATE_ROOT');
  let current = root;
  for (const component of relative.split(path.sep).slice(0, -1)) {
    current = path.join(current, component);
    const item = fs.lstatSync(current);
    if (!item.isDirectory() || item.isSymbolicLink()) fail('SYMLINK_PRIVATE_PATH');
  }
  const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size < 1 || info.size > MAX_FILE || privateMode && (info.mode & 0o077)) fail('INVALID_PRIVATE_FILE');
    const buffer = Buffer.alloc(MAX_FILE + 1); let count = 0;
    while (count < buffer.length) {
      const read = fs.readSync(fd, buffer, count, buffer.length - count, null);
      if (!read) break;
      count += read;
    }
    if (count > MAX_FILE) fail('PRIVATE_FILE_TOO_LARGE');
    return buffer.subarray(0, count);
  } finally { fs.closeSync(fd); }
}
function readConfig(file) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) fail('CONFIG_PATH_REQUIRED');
  const directory = path.dirname(file), root = fs.realpathSync(directory);
  const parent = fs.lstatSync(directory);
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.mode & 0o077) fail('PRIVATE_DIRECTORY_REQUIRED');
  let value;
  try { value = JSON.parse(regularFile(path.join(root, path.basename(file)), root, true).toString('utf8')); }
  catch (error) { if (error instanceof ProxyError) throw error; fail('INVALID_CONFIG_FILE'); }
  const config = validateConfig(value);
  return {config, tls: {cert: regularFile(config.cert_path, root), key: regularFile(config.key_path, root)}};
}
function headersWithoutHop(headers) {
  const connection = String(headers.connection || '').split(',').map(s => s.trim().toLowerCase());
  const excluded = new Set([...HOP, ...connection, 'x-helix-runtime-proxy-error']);
  const result = Object.create(null);
  for (const [name, value] of Object.entries(headers)) {
    if (!excluded.has(name.toLowerCase())) result[name.toLowerCase()] = value;
  }
  return result;
}
function requestHeaders(req, config) {
  const headers = headersWithoutHop(req.headers);
  for (const name of Object.keys(headers)) {
    if (name === 'forwarded' || name.startsWith('x-forwarded-')) delete headers[name];
  }
  headers.host = config.public_host;
  headers['x-forwarded-proto'] = 'https';
  headers['x-forwarded-host'] = config.public_host;
  headers['x-forwarded-port'] = String(config.public_port);
  const remote = req.socket && req.socket.remoteAddress;
  if (net.isIP(remote)) headers['x-forwarded-for'] = remote;
  return headers;
}
function validRequest(req, config) {
  let hostCount = 0;
  for (let i = 0; i < (req.rawHeaders || []).length; i += 2) {
    if (String(req.rawHeaders[i]).toLowerCase() === 'host') hostCount++;
  }
  return hostCount === 1 && req.headers.host === config.public_host &&
    typeof req.method === 'string' && /^[A-Z]+$/.test(req.method) && req.method !== 'CONNECT' &&
    typeof req.url === 'string' && req.url.startsWith('/') && !req.url.startsWith('//') &&
    !/[\s\\\x00-\x1f\x7f]/.test(req.url) && !/%(?:00|0a|0d|5c)/i.test(req.url);
}
function createProxy(rawConfig, tls, dependencies = {}) {
  const input = validateConfig(rawConfig), front = new URL(input.public_origin), back = new URL(input.backend_origin);
  const config = Object.freeze({...input, public_host: front.host, public_port: Number(front.port),
    bind_host: front.hostname === '[::1]' ? '::1' : '127.0.0.1',
    backend_host: back.hostname === '[::1]' ? '::1' : back.hostname, backend_port: Number(back.port)});
  if (!object(tls) || !Buffer.isBuffer(tls.cert) || !Buffer.isBuffer(tls.key) || !tls.cert.length || !tls.key.length) fail('TLS_MATERIAL_REQUIRED');
  const httpModule = dependencies.http || http, httpsModule = dependencies.https || https;
  const now = dependencies.now || (() => performance.now());
  const wallNow = dependencies.wallNow || Date.now;
  const schedule = dependencies.setTimeout || setTimeout, cancel = dependencies.clearTimeout || clearTimeout;
  const notify = dependencies.onEvent || (() => {});
  const initialRemaining = config.deadline_unix_ms - wallNow();
  if (initialRemaining <= 0) fail('DEADLINE_EXHAUSTED');
  const end = now() + initialRemaining;
  const remaining = () => end - now();
  const sockets = new Set(), transactions = new Set();
  let server, deadlineTimer, closing, listening = false, starting = false, stopped = false;
  const emit = (event, extra = {}) => notify({type: 'runtime-https', event, ...extra});
  function reject(res, status) {
    if (!res.headersSent && !res.destroyed) {
      res.writeHead(status, {'content-type': 'text/plain; charset=utf-8', 'connection': 'close', 'x-helix-runtime-proxy-error': '1'});
      res.end(status === 400 ? 'Bad request\n' : 'Proxy unavailable\n');
    } else if (!res.destroyed) res.destroy();
  }
  function finish(transaction, abort = false) {
    if (transaction.done) return;
    transaction.done = true;
    if (transaction.timer) cancel(transaction.timer);
    transactions.delete(transaction);
    if (abort) {
      if (transaction.upstream) transaction.upstream.destroy();
      if (transaction.response) transaction.response.destroy();
    }
  }
  function forward(req, res) {
    if (stopped || remaining() <= 0) return reject(res, 503);
    if (!validRequest(req, config)) { emit('request_rejected', {status: 400}); return reject(res, 400); }
    const transaction = {upstream: null, response: null, timer: null, done: false, client: res};
    transactions.add(transaction);
    function failed(status) { if (!transaction.done) { reject(res, status); finish(transaction, true); } }
    const timeout = Math.max(1, Math.min(config.request_timeout_ms, Math.floor(remaining())));
    transaction.timer = schedule(() => { emit('request_timeout'); failed(504); }, timeout);
    if (transaction.timer && transaction.timer.unref) transaction.timer.unref();
    res.once('finish', () => finish(transaction));
    res.once('close', () => { if (!res.writableEnded) finish(transaction, true); });
    req.once('aborted', () => { finish(transaction, true); if (!res.destroyed) res.destroy(); });
    req.once('error', () => failed(502));
    try {
      const upstream = httpModule.request({hostname: config.backend_host, port: config.backend_port,
        method: req.method, path: req.url, headers: requestHeaders(req, config), agent: false}, response => {
        transaction.response = response;
        if (transaction.done || stopped || remaining() <= 0) { response.destroy(); failed(503); return; }
        response.once('error', () => failed(502));
        response.once('aborted', () => failed(502));
        const status = response.statusCode;
        if (!Number.isInteger(status) || status < 200 || status > 599) { failed(502); return; }
        res.writeHead(status, headersWithoutHop(response.headers));
        response.pipe(res);
      });
      transaction.upstream = upstream;
      upstream.once('error', () => failed(502));
      req.pipe(upstream);
    } catch { failed(502); }
  }
  server = httpsModule.createServer({cert: tls.cert, key: tls.key, minVersion: 'TLSv1.2'}, forward);
  server.headersTimeout = config.request_timeout_ms;
  server.requestTimeout = config.request_timeout_ms;
  server.keepAliveTimeout = Math.min(5000, config.request_timeout_ms);
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  for (const event of ['connect', 'upgrade']) {
    server.on(event, (_req, socket) => {
      emit('unsupported_protocol', {protocol: event});
      socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      socket.destroy();
    });
  }
  server.on('clientError', (_error, socket) => { emit('client_error'); socket.destroy(); });
  server.on('tlsClientError', () => emit('tls_client_error'));
  async function close(reason = 'closed') {
    if (closing) return closing;
    stopped = true;
    if (deadlineTimer) cancel(deadlineTimer);
    closing = new Promise(resolve => {
      for (const transaction of [...transactions]) { finish(transaction, true); transaction.client.destroy(); }
      for (const socket of [...sockets]) socket.destroy();
      if (listening || starting) {
        try { server.close(resolve); } catch { resolve(); }
      } else resolve();
    }).then(() => { listening = false; emit('closed', {reason: ['deadline', 'signal', 'error', 'closed'].includes(reason) ? reason : 'closed'}); });
    return closing;
  }
  server.on('error', () => { emit('server_error'); if (listening) void close('error'); });
  async function listen() {
    if (stopped || starting || listening || remaining() <= 0) fail('INVALID_LISTEN_STATE');
    starting = true;
    return new Promise((resolve, rejectPromise) => {
      const onError = () => { starting = false; stopped = true; rejectPromise(new ProxyError('LISTEN_FAILED')); };
      server.once('error', onError);
      try {
        server.listen(config.public_port, config.bind_host, () => {
          server.removeListener('error', onError); starting = false;
          if (stopped) { rejectPromise(new ProxyError('LISTEN_CANCELLED')); return; }
          listening = true;
          if (remaining() <= 0) { void close('deadline'); rejectPromise(new ProxyError('DEADLINE_EXHAUSTED')); return; }
          deadlineTimer = schedule(() => { void close('deadline'); }, remaining());
          if (deadlineTimer && deadlineTimer.unref) deadlineTimer.unref();
          emit('listening', {origin: config.public_origin, backend: config.backend_origin});
          resolve({origin: config.public_origin, backend: config.backend_origin});
        });
      } catch { server.removeListener('error', onError); starting = false; stopped = true; rejectPromise(new ProxyError('LISTEN_FAILED')); }
    });
  }
  return {listen, close, snapshot: () => ({listening, stopped, active_requests: transactions.size, owned_sockets: sockets.size})};
}
async function main(argv = process.argv.slice(2)) {
  if (argv.length !== 1) fail('CONFIG_PATH_REQUIRED');
  const {config, tls} = readConfig(argv[0]);
  const proxy = createProxy(config, tls, {onEvent: event => process.stdout.write(JSON.stringify(event) + '\n')});
  const stop = () => { void proxy.close('signal'); };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  try { await proxy.listen(); }
  catch (error) { await proxy.close('error'); throw error; }
}
module.exports = {ProxyError, validateConfig, readConfig, headersWithoutHop, createProxy, main};
if (require.main === module) main().catch(error => {
  process.stderr.write(JSON.stringify({type: 'runtime-https', event: 'failed', reason: error instanceof ProxyError ? error.code : 'PROXY_ERROR'}) + '\n');
  process.exitCode = 3;
});
