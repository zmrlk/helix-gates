"""Native-request argument boundary, exercised in Node without sockets."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from test_runtime_sinks import fixture_input

ROOT = Path(__file__).resolve().parents[1]


class ReviewPreload(unittest.TestCase):
    def test_own_request_never_forwards_descriptors_or_original_options(self):
        source = r'''
const assert = require('node:assert/strict');
const {Writable} = require('node:stream');
const {createAdapter,installAdapter} = require('./bin/runtime-sinks-preload.cjs');
const input = JSON.parse(process.argv[1]);
const bad = [
  () => Object.assign(Object.create({socketPath:'/private/fixture.sock'}), {hostname:'127.0.0.1',port:32124}),
  () => Object.defineProperty({hostname:'127.0.0.1',port:32124},'socketPath',{value:'/private/fixture.sock'}),
  () => Object.defineProperty({port:32124}, 'hostname', {enumerable:true, get(){return ++reads === 1 ? '127.0.0.1' : 'evil.invalid';}}),
  () => ({hostname:'127.0.0.1',port:32124,headers:Object.defineProperty({},'host',{get(){throw Error('getter executed');}})})
];
let reads = 0, calls = 0;
function native(url, opts, cb) {
  calls++;
  assert.equal(typeof url,'string');
  assert.equal(new URL(url).origin,input.own_origins[0]);
  assert.equal(Object.getPrototypeOf(opts),null);
  assert.equal(Object.getPrototypeOf(opts.headers),null);
  assert.ok(!Object.hasOwn(opts,'socketPath'));
  return new Writable({write(c,e,next){next();}});
}
const adapter=createAdapter(input,{httpRequest:native,httpsRequest:native});
for (const make of bad) {
  const req=adapter.httpRequest(make(),()=>{});req.on('error',()=>{});
}
assert.equal(calls,0);assert.equal(reads,0);
const options={hostname:'127.0.0.1',port:32124,path:'/health',headers:{accept:'application/json'}};
adapter.httpRequest(options,()=>{}).end();
adapter.httpRequest(input.own_origins[0]+'/health',{headers:{}},()=>{}).end();
assert.equal(calls,2);assert.equal(Object.getPrototypeOf(options),Object.prototype);
const http={request:native,get:native},https={request:native,get:native};
const restore=installAdapter(input,{globalObject:{},http,https,dns:{}});
const req=http.get(bad[1](),()=>{});req.on('error',()=>{});
assert.equal(calls,2);restore();
'''
        result = subprocess.run([shutil.which('node'), '-e', source, json.dumps(fixture_input()[1])],
                                cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__': unittest.main()
