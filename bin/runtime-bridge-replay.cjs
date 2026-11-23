'use strict';
async function replay(input, transport = fetch) {
  const url = new URL(input.url);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname) || !url.port || url.username || url.password || url.search || url.hash ||
      !url.pathname.startsWith('/') || !['GET','POST','PUT','PATCH','DELETE'].includes(input.method)) throw new Error('BRIDGE_INPUT_INVALID');
  const response = await transport(url.href, {method: input.method, redirect: 'error', signal: AbortSignal.timeout(15000),
    headers: {'content-type': 'application/json', ...input.headers}, body: input.method==='GET'?undefined:JSON.stringify(input.body)});
  await response.body?.cancel();
  return {status: response.status};
}
module.exports = {replay};
if (require.main === module) {
  const fs = require('node:fs');
  Promise.resolve().then(() => {
    const path = process.argv[2], stat = fs.lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536 || (stat.mode & 0o077)) throw new Error('BRIDGE_INPUT_INVALID');
    return replay(JSON.parse(fs.readFileSync(path, 'utf8')));
  }).then(result => process.stdout.write(JSON.stringify(result)), () => {process.stderr.write('BRIDGE_REPLAY_FAILED\n'); process.exitCode = 2;});
}
