/* Synthetic runtime diagnostics: never log URLs, headers or credentials. */
'use strict';
const original = globalThis.fetch;
if (original) globalThis.fetch = async function (input, init) {
  try { return await original.call(this, input, init); }
  catch (error) {
    let host = 'unknown';
    try { host = new URL(typeof input === 'string' || input instanceof URL ? input : input.url).host; } catch {}
    const causes = [];
    const visit = (cause, depth = 0) => {
      if (!cause || depth > 5) return;
      if (typeof cause.code === 'string' && /^[A-Z0-9_]+$/.test(cause.code)) causes.push(cause.code);
      visit(cause.cause, depth + 1);
      if (Array.isArray(cause.errors)) cause.errors.slice(0, 5).forEach(c => visit(c, depth + 1));
    };
    visit(error);
    console.error('HELIX_FETCH_FAILURE ' + JSON.stringify({host, causes: [...new Set(causes)].slice(0, 5)}));
    throw error;
  }
};
