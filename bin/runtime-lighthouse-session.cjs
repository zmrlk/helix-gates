#!/usr/bin/env node
// Sesja roli ekranów dla Lighthouse: ciasteczka trafiają do przeglądarki pomiaru jako zwykłe ciasteczka (z domeną, ścieżką i flagami),
// a nie jako nagłówek. Przeglądarka sama pilnuje, do którego adresu je wysłać, a wynik Lighthouse nie zawiera ich wartości.
// Użycie: node runtime-lighthouse-session.cjs <plik sesji> <host aplikacji> <port przeglądarki> -- <polecenie lighthouse...>
'use strict';
const fs = require('fs'), path = require('path'), { spawn } = require('child_process');
const [stateFile, host, port, separator, ...command] = process.argv.slice(2);
(async () => {
  if (!stateFile || !host || !/^\d{2,5}$/.test(port || '') || separator !== '--' || !command.length) throw new Error('invalid arguments');
  const cookies = (JSON.parse(fs.readFileSync(stateFile, 'utf8')).cookies || []).filter(cookie => cookie && typeof cookie.name === 'string'
    && typeof cookie.value === 'string' && String(cookie.domain || '').replace(/^\./, '') === host);
  if (!cookies.length) throw new Error('no application cookies in the screen session');
  const modules = process.env.HELIX_RUNTIME_NODE_MODULES;
  const { chromium } = require(modules ? path.join(modules, 'playwright') : 'playwright');
  const browser = await chromium.connectOverCDP('http://127.0.0.1:' + port, { timeout: 15000 });
  try { await (browser.contexts()[0] || await browser.newContext()).addCookies(cookies); }
  finally { await browser.close().catch(() => {}); } // rozłącza sterowanie; przeglądarka pomiaru zostaje
  const child = spawn(command[0], command.slice(1), { stdio: 'inherit' });
  child.on('error', () => process.exit(127));
  child.on('exit', (code, signal) => process.exit(signal ? 1 : code ?? 1));
})().catch(error => { console.error('lighthouse session: ' + String(error && error.message || error).split('\n')[0]); process.exit(2); });
