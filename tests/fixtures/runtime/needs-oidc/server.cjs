const http = require('node:http');
const https = require('node:https');
const issuer = process.env.OIDC_ISSUER;
if (!issuer) throw Error('OIDC_ISSUER required');
const request = (issuer.startsWith('https:') ? https : http).get(issuer + '/.well-known/openid-configuration', response => {
  if (response.statusCode !== 200) { console.error('OIDC_ISSUER discovery failed: HTTP ' + response.statusCode); process.exitCode = 1; response.resume(); return; }
  response.resume();
  response.on('end', () => http.createServer((req,res)=>res.end('Synthetic')).listen(process.env.PORT,'127.0.0.1'));
});
request.setTimeout(1500, () => request.destroy(Error('issuer timeout')));
request.on('error', error => {console.error('OIDC_ISSUER discovery connection failed: ' + error.message); process.exitCode=1;});
