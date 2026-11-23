const https = require('node:https');
const http = require('node:http');
if (!process.env[['IDENTITY','ISSUER','URL'].join('_')].startsWith('https://')) throw Error('only requests to HTTPS are allowed');
function discover(attempt=0) {
  const req=https.get(process.env[['IDENTITY','ISSUER','URL'].join('_')]+'/.well-known/openid-configuration', res=> {
    let body='';res.on('data', chunk=>body+=chunk);res.on('end',()=> {
      const discovery=JSON.parse(body);
      if(discovery.issuer!==process.env[['IDENTITY','ISSUER','URL'].join('_')]) throw Error('issuer mismatch');
      http.createServer((req,res)=>res.end('<html lang="en"><title>OIDC test</title><main><h1>Synthetic login</h1></main></html>')).listen(Number(process.env.PORT),'127.0.0.1');
    });
  });
  req.on('error',error=> {if(attempt<20) setTimeout(()=>discover(attempt+1),100);else throw error;});
}
discover();
