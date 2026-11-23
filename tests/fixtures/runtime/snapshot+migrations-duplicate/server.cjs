const http = require('node:http');
http.createServer((req,res)=>res.end('<html lang="en"><title>Synthetic app</title><main><h1>Runtime</h1></main></html>')).listen(Number(process.env.PORT),'127.0.0.1');
