'use strict';
// This preloader is instrumentation, not a replacement for OS network isolation.
const fs = require('node:fs');
const Module = require('node:module');
function failure(code) { const error = new Error(code); error.code = code; return error; }
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
function install(input, {target = globalThis, module = Module, observe = () => {}} = {}) {
  if (!input || !Array.isArray(input.recordings)) throw failure('HELIX_REPLAY_INVALID');
  const previousFetch = target.fetch, previousLoad = module._load;
  module._load = function(name, ...args) {
    if (typeof name === 'string' && (input.disabled_packages||[]).some(p=>name===p||name.startsWith(p+'/'))) {
      observe({adapter: 'disabled', package: name.split('/')[0]});
      throw failure('HELIX_RUNTIME_PACKAGE_DISABLED');
    }
    return previousLoad.call(this, name, ...args);
  };
  target.fetch = async function(resource, options) {
    if (options && (options.dispatcher || options.agent)) throw failure('HELIX_REPLAY_UNSUPPORTED');
    const request = new Request(resource, options);
    const url = new URL(request.url);
    const candidates = input.recordings.filter(row => row.request.url === url.href && row.request.method === request.method);
    // Unknown paths on replay hosts cannot leak to the original transport.
    const replayHost = input.recordings.some(row => new URL(row.request.url).host === url.host);
    if (!candidates.length && !replayHost) return previousFetch.call(this, resource, options);
    let body = null, size = 0; const chunks = [];
    if (request.body) {
      const reader = request.body.getReader();
      try { for (;;) { const item = await reader.read(); if (item.done) break; size += item.value.byteLength;
        if (size > 65536) { await reader.cancel(); throw failure('HELIX_REPLAY_LIMIT'); } chunks.push(Buffer.from(item.value));
      }} finally { reader.releaseLock(); }
      try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch { throw failure('HELIX_REPLAY_UNMATCHED'); }
    }
    const row = candidates.find(item => canonical(item.request.body) === canonical(body));
    if (!row) throw failure('HELIX_REPLAY_UNMATCHED');
    observe({adapter: 'replay', id: row.id, provider: row.provider, sha256: row.sha256});
    return new Response(JSON.stringify(row.response.body), {status: row.response.status, headers: {'content-type': 'application/json'}});
  };
  return () => { target.fetch = previousFetch; module._load = previousLoad; };
}
module.exports = {install, canonical};
if (process.env.HELIX_RUNTIME_ADAPTER_INPUT) {
  try {
    const path = process.env.HELIX_RUNTIME_ADAPTER_INPUT;
    const stat = fs.lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4000000 || (stat.mode & 0o077)) throw failure('HELIX_REPLAY_INVALID');
    install(JSON.parse(fs.readFileSync(path, 'utf8')), {observe: row => process.stderr.write('HELIX_ADAPTER ' + JSON.stringify(row) + '\n')});
  } catch { throw failure('HELIX_RUNTIME_ADAPTER_INVALID'); }
}
