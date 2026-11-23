"""Synthetic acceptance tests for the portable legacy scripts; no installs/network."""
import hashlib
import io
from unittest.mock import patch
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node')


@unittest.skipUnless(NODE, 'Node.js unavailable')
class OldPort(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='helix-port-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def node(self, script, *args):
        return subprocess.run([NODE, str(ROOT/'scripts'/script), *map(str, args)],
                              text=True, capture_output=True, timeout=30)

    def fixture(self, kind):
        root = self.root/kind
        root.mkdir()
        (root/'.git').mkdir()
        payload = b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(100))
        if kind == 'vite':
            out = root/'dist'; (out/'.vite').mkdir(parents=True)
            (out/'app.js').write_bytes(payload)
            (out/'lazy.js').write_bytes(payload[:300])
            (out/'shared.js').write_bytes(payload[:500])
            (out/'app.css').write_text('/*'+payload.hex()+'*/body{color:red}')
            (out/'.vite/manifest.json').write_text(json.dumps({
                'index.html': {'file': 'app.js', 'isEntry': True, 'imports': ['shared'], 'css': ['app.css'], 'dynamicImports': ['lazy']},
                'shared': {'file': 'shared.js'}, 'lazy': {'file': 'lazy.js'}}))
        elif kind == 'next':
            out = root/'.next'; out.mkdir()
            (out/'app.js').write_bytes(payload)
            (out/'shared.js').write_bytes(payload[:500])
            (out/'build-manifest.json').write_text(json.dumps({'pages': {'/_app': ['shared.js'], '/': ['app.js']}}))
        elif kind == 'static':
            out = root/'dist'; out.mkdir()
            (out/'app.js').write_bytes(payload)
            (out/'index.html').write_text('<script src="/app.js"></script>')
        elif kind == 'svelte':
            out = root/'.svelte-kit/output/client'
            for name in ('entry', 'nodes', 'chunks', 'assets'):
                (out/'_app/immutable'/name).mkdir(parents=True)
            server = root/'.svelte-kit/output/server'; (server/'nodes').mkdir(parents=True)
            (root/'package.json').write_text('{"type":"module"}')
            files = ['_app/immutable/entry/start.js', '_app/immutable/entry/app.js', '_app/immutable/nodes/1.js']
            for file in files:
                (out/file).write_bytes(payload)
            (out/'.vite').mkdir()
            (out/'.vite/manifest.json').write_text('{}')
            (server/'manifest.js').write_text('export const manifest='+json.dumps({'_': {'client': {'start': files[0], 'app': files[1], 'imports': [], 'stylesheets': []}, 'routes': [{'id': '/', 'page': {'layouts': [None, 0], 'leaf': 1}}]}})+';')
            for i in (0, 1):
                (server/'nodes'/f'{i}.js').write_text('export const imports = '+json.dumps([files[2]] if i else [])+';\nexport const stylesheets = [];')
        return root

    def perf(self, root, *args):
        run = self.node('perf-audit.mjs', root, '--out', root/'results', *args)
        report = json.loads((root/'results/perf-audit.json').read_text())
        return run, report

    def test_arguments_and_compatible_entries(self):
        for script in ('ui-audit.mjs', 'visual-baseline.mjs', 'perf-audit.mjs'):
            self.assertEqual(self.node(script, '--help').returncode, 0, script)
            self.assertEqual(self.node(script, '--unknown').returncode, 2, script)
        for command in (('visual', 'audit'), ('visual', 'baseline'), ('perf', 'weight'), ('review', 'screenshots')):
            run = subprocess.run(['python3', str(ROOT/'bin/helix'), *command, '--help'], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_build_adapters(self):
        for kind in ('svelte', 'vite', 'next', 'static'):
            with self.subTest(kind=kind):
                root = self.fixture(kind)
                run, report = self.perf(root, '--init-baseline')
                self.assertEqual(run.returncode, 0, run.stderr+run.stdout)
                row = report['routes'][0]
                self.assertGreater(row['js_gz'], 0)
                if kind == 'vite':
                    self.assertEqual(row['files'], 2)
                    self.assertEqual(row['lazy'], 1)
                    self.assertGreater(row['css_gz'], 0)
                self.assertEqual(report['adapter'], 'sveltekit' if kind == 'svelte' else kind)

    def test_unknown_build_is_incomplete(self):
        run, report = self.perf(self.root)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(report['status'], 'incomplete')
        self.assertTrue(report['errors'])

    def test_ratchet_cannot_overwrite_or_approve_growth(self):
        root = self.fixture('vite')
        self.assertEqual(self.perf(root)[0].returncode, 1)
        self.assertEqual(self.perf(root, '--init-baseline')[0].returncode, 0)
        base = root/'scripts/perf-baseline.json'; before = base.read_bytes()
        self.assertEqual(self.perf(root, '--init-baseline')[0].returncode, 2)
        (root/'dist/app.js').write_bytes(os.urandom(20000))
        self.assertEqual(self.perf(root, '--update-baseline')[0].returncode, 1)
        self.assertEqual(base.read_bytes(), before)
        (root/'dist/app.js').write_text('small')
        self.assertEqual(self.perf(root, '--update-baseline')[0].returncode, 0)
        self.assertLess(json.loads(base.read_text())['routes']['/']['js_gz'], json.loads(before)['routes']['/']['js_gz'])

    def test_new_route_and_old_debt(self):
        root = self.fixture('next')
        budget = root/'budget.json';budget.write_text('{"route_js_gzip_kib":0,"page_chunk_gzip_kib":0}')
        self.assertEqual(self.perf(root, '--budget', budget, '--init-baseline')[0].returncode, 0)
        self.assertEqual(self.perf(root, '--budget', budget)[0].returncode, 0)
        manifest = root/'.next/build-manifest.json'
        data = json.loads(manifest.read_text());data['pages']['/new'] = ['app.js'];manifest.write_text(json.dumps(data))
        run, report = self.perf(root, '--budget', budget)
        self.assertEqual(run.returncode, 1)
        self.assertTrue(any('nowa trasa' in f for f in report['fails']))

    def test_stale_build_and_bad_budget(self):
        root = self.fixture('vite'); src = root/'src';src.mkdir(); file = src/'entry.js';file.write_text('new')
        future = (root/'dist/.vite/manifest.json').stat().st_mtime+20
        os.utime(file, (future, future))
        run, report = self.perf(root, '--init-baseline')
        self.assertEqual(run.returncode, 2);self.assertIn('starszy', report['errors'][0])

    def test_png_and_config_node_acceptance(self):
        for name in ('config-visual', 'dependencies'):
            run = subprocess.run([NODE, str(ROOT/'tests/node'/f'{name}.test.mjs')], text=True, capture_output=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)

    def test_png_without_pngjs(self):
        module = (ROOT/'scripts/lib/visual.mjs').as_uri()
        codec = (ROOT/'scripts/lib/png.mjs').as_uri()
        code = f'''import {{PNG}} from {json.dumps(codec)};import {{comparePNG}} from {json.dumps(module)};
        const p=new PNG({{width:2,height:2}});p.data.fill(255);const a=PNG.sync.write(p);p.data[0]=0;
        const r=comparePNG(a,PNG.sync.write(p),null,{{pixelThreshold:0,maxDiffPixels:0,maxDiffRatio:0}});
        if(r.status!=='mismatch'||r.differentPixels!==1)throw Error('diff');
        const corrupt=Buffer.from(a);corrupt[40]^=1;let rejected=false;try{{PNG.sync.read(corrupt)}}catch{{rejected=true}};
        if(!rejected)throw Error('CRC');'''
        run = subprocess.run([NODE, '--input-type=module', '-e', code], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_review_rejects_incomplete_responses(self):
        spec = importlib.util.spec_from_file_location('screenshot_review_test', ROOT/'scripts/review-screenshots.py')
        review = importlib.util.module_from_spec(spec); spec.loader.exec_module(review)
        for data, expected in (({'status': 'SUCCESS', 'response': 'No differences. HELIX_REVIEW_COMPLETE'}, 0),
                               ({'status': 'SUCCESS', 'response': ''}, 1),
                               ({'status': 'SUCCESS', 'response': 'partial'}, 1),
                               ({'status': 'SUCCESS', 'response': 'No differences. HELIX_REVIEW_COMPLETE', 'denied_actions': ['shell']}, 1),
                               ({'status': 'SUCCESS', 'response': 'I cannot review. HELIX_REVIEW_COMPLETE'}, 1)):
            response = subprocess.CompletedProcess([], 0, json.dumps(data), '')
            with patch.object(review.sys, 'argv', ['review', str(self.root)]), patch.object(review.sys, 'stdin', io.StringIO('Untrusted request')), patch.object(review.sys, 'stdout', io.StringIO()), patch.object(review.sys, 'stderr', io.StringIO()), patch.object(review.subprocess, 'run', return_value=response) as execute:
                self.assertEqual(review.main(), expected)
                argv = execute.call_args.args[0]
                self.assertEqual(argv[argv.index('--mode') + 1], 'plan')
                self.assertIn('--sandbox', argv)
                self.assertNotIn('--dangerously-skip-permissions', argv)

    def test_missing_browser_incomplete_and_unlock(self):
        env = dict(os.environ, PLAYWRIGHT_MODULE=str(self.root/'absent'))
        out = self.root/'audit'
        run = subprocess.run([NODE, str(ROOT/'scripts/ui-audit.mjs'), 'http://127.0.0.1:1', '--out', str(out), '--case', 'fixture', '--sweep', '280-400:40', '--ready-selector', '#ready'], env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads((out/'audit.json').read_text())['summary']['status'], 'incomplete')
        self.assertFalse((out/'.helix-lock').exists())

    def test_output_lock_does_not_replace_owner_report(self):
        out = self.root/'locked';out.mkdir()
        (out/'.helix-lock').write_text('synthetic owner')
        (out/'audit.json').write_text('owner evidence')
        run = self.node('ui-audit.mjs','http://127.0.0.1:1','--out',out)
        self.assertEqual(run.returncode,2)
        self.assertEqual((out/'audit.json').read_text(),'owner evidence')
        self.assertEqual((out/'.helix-lock').read_text(),'synthetic owner')

    def test_report_html_and_json_artifacts(self):
        module = (ROOT/'scripts/lib/report.mjs').as_uri()
        code = 'import {finalize,writeReport} from '+json.dumps(module)+';const r={schemaVersion:2,_started:performance.now(),planned:1,errors:[],baseline:null,caseId:"fixture",runs:[{errors:[],blockers:1,theme:"light",width:390,contrast:["<script>unsafe</script>"],visual:{status:"not_checked"}}]};finalize(r,true);writeReport(r,process.argv[1]);'
        run = subprocess.run([NODE,'--input-type=module','-e',code,str(self.root)],text=True,capture_output=True)
        self.assertEqual(run.returncode,0,run.stderr)
        report = json.loads((self.root/'audit.json').read_text())
        self.assertEqual(report['summary']['status'],'failed')
        html = (self.root/'report.html').read_text()
        self.assertIn('&lt;script&gt;unsafe&lt;/script&gt;',html)
        self.assertNotIn('<script>unsafe',html)

    def test_runtime_projection_and_routes(self):
        import sys
        sys.path.insert(0, str(ROOT/'bin'))
        import helix_visual
        calls = []
        def execute(argv, cwd, maximum):
            calls.append(argv)
        data = helix_visual.runtime_audits(execute, NODE, self.root, 'http://127.0.0.1:1', ['/', '/other'], self.root/'evidence')
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(v['status']=='needs-runtime' for v in data['visual']))
        self.assertEqual(data['weight']['status'], 'needs-runtime')

    def test_ssr_offline_samples(self):
        root = self.fixture('vite')
        self.assertEqual(self.perf(root, '--init-baseline')[0].returncode, 0)
        argv = ['node', str(ROOT/'scripts/perf-audit.mjs'), str(root), '--out', str(root/'ssr'), '--ssr', 'http://127.0.0.1:1', '--routes', '/ok,/redirect,/timeout', '--cookie', 'fixture_cookie=synthetic']
        code = 'process.argv='+json.dumps(argv)+';globalThis.fetch=async(url)=>{if(url.endsWith("timeout"))throw new DOMException("fixture timeout","TimeoutError");return {status:url.endsWith("redirect")?302:200,body:{cancel:async()=>{}},arrayBuffer:async()=>new ArrayBuffer(20)}};await import('+json.dumps((ROOT/'scripts/perf-audit.mjs').as_uri())+');'
        run = subprocess.run([NODE, '--input-type=module', '-e', code], text=True, capture_output=True)
        self.assertEqual(run.returncode, 1, run.stderr)
        raw = (root/'ssr/perf-audit.json').read_text()
        self.assertNotIn('fixture_cookie', raw+run.stdout+run.stderr)
        rows = json.loads(raw)['ssr']
        self.assertEqual(rows[0]['samples'], 5)
        self.assertTrue(rows[0]['valid'])
        self.assertIsNotNone(rows[0]['ttfb_ms'])
        for row in rows[1:]:
            self.assertFalse(row['valid']);self.assertIsNone(row['ttfb_ms'])

    def test_png_filters_and_color_types(self):
        import struct
        def chunk(name, data):
            return struct.pack('>I',len(data))+name+data+struct.pack('>I',zlib.crc32(name+data))
        for color, channels in ((0,1),(2,3),(3,1),(4,2),(6,4)):
            for filt in range(5):
                # Two pixels, two rows. Encode each PNG filter independently.
                pixels = bytes([1,2]*channels*2)
                stride = 2*channels
                raw = bytearray()
                for y in range(2):
                    raw.append(filt)
                    for x in range(stride):
                        i = y*stride+x
                        a = pixels[i-channels] if x>=channels else 0
                        b = pixels[i-stride] if y else 0
                        c = pixels[i-stride-channels] if y and x>=channels else 0
                        v = a+b-c
                        ds = [abs(v-a),abs(v-b),abs(v-c)]
                        paeth = [a,b,c][ds.index(min(ds))]
                        raw.append((pixels[i]-[0,a,b,(a+b)//2,paeth][filt])%256)
                header = struct.pack('>IIBBBBB',2,2,8,color,0,0,0)
                buf = bytes.fromhex('89504e470d0a1a0a')+chunk(b'IHDR',header)
                if color==3:
                    buf += chunk(b'PLTE',bytes([0,0,0,20,30,40,50,60,70]))
                buf += chunk(b'IDAT',zlib.compress(bytes(raw)))+chunk(b'IEND',b'')
                file = self.root/'synthetic.png';file.write_bytes(buf)
                code = 'import {PNG} from '+json.dumps((ROOT/'scripts/lib/png.mjs').as_uri())+';import fs from "node:fs";const p=PNG.sync.read(fs.readFileSync(process.argv[1]));console.log(JSON.stringify([...p.data]));'
                run = subprocess.run([NODE,'--input-type=module','-e',code,str(file)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                data = json.loads(run.stdout)
                self.assertEqual(len(data),16)
                self.assertEqual(data[0],20 if color==3 else 1)
                self.assertEqual(data[3],2 if color==4 else 2 if color==6 else 255)

    def test_ssr_median_and_http_failure(self):
        import http.server
        import threading
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302 if self.path == '/redirect' else 200)
                self.end_headers()
                self.wfile.write(b'<html>synthetic</html>')
            def log_message(self, *args):
                pass
        try:
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        except PermissionError as error:
            self.skipTest('Loopback HTTP server unavailable in sandbox: '+str(error))
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            root = self.fixture('vite')
            self.assertEqual(self.perf(root, '--init-baseline')[0].returncode, 0)
            run, report = self.perf(root, '--ssr', 'http://127.0.0.1:'+str(server.server_port), '--routes', '/ok,/redirect')
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertEqual(report['ssr'][0]['samples'], 5)
            self.assertTrue(report['ssr'][0]['valid'])
            self.assertIsNotNone(report['ssr'][0]['ttfb_ms'])
            self.assertFalse(report['ssr'][1]['valid'])
            self.assertIsNone(report['ssr'][1]['ttfb_ms'])
        finally:
            server.shutdown();server.server_close();worker.join()

    def test_approval_explicit_and_no_overwrite(self):
        out = self.root/'audit';out.mkdir()
        codec = (ROOT/'scripts/lib/png.mjs').as_uri()
        code = 'import {PNG} from '+json.dumps(codec)+';import fs from "node:fs";fs.writeFileSync(process.argv[1],PNG.sync.write(new PNG({width:2,height:2})));'
        image = out/'shot-light-390.png'
        subprocess.run([NODE, '--input-type=module', '-e', code, str(image)], check=True)
        audit = out/'audit.json'
        audit.write_text(json.dumps({'schemaVersion':2,'caseId':'synthetic','contract':{'dpr':1},'summary':{'status':'passed','complete':True},'runs':[{'theme':'light','width':390,'status':'complete','shot':image.name,'shotSha256':hashlib.sha256(image.read_bytes()).hexdigest()}]}))
        base = self.root/'approved'
        self.assertEqual(self.node('visual-baseline.mjs','--from',audit,'--out',base).returncode,2)
        args = ('--from',audit,'--out',base,'--approved-by','SYNTHETIC TEST','--note','fixture only')
        self.assertEqual(self.node('visual-baseline.mjs',*args).returncode,0)
        before = (base/'baseline.json').read_bytes()
        self.assertEqual(self.node('visual-baseline.mjs',*args).returncode,2)
        self.assertEqual((base/'baseline.json').read_bytes(),before)

    def test_process_contract(self):
        text = (ROOT/'SKILL.md').read_text()
        for rule in ('≤5 min','najpierw paść','autor ≠ recenzent','1:1','Raport checkpointu','G0','G1','G2','G3','G4'):
            self.assertIn(rule,text)

    def test_browser_suite(self):
        if os.environ.get('HELIX_TEST_BROWSER') == '0':
            self.skipTest('Browser execution reserved for wrapper (HELIX_TEST_BROWSER=0)')
        # Probe availability only; browser execution itself belongs to the wrapper.
        code = "import {loadDependencies} from './scripts/lib/dependencies.mjs';try{const d=loadDependencies(); console.log(d.chromium.executablePath())}catch(e){console.error(e.message);process.exitCode=2}"
        probe = subprocess.run([NODE, '--input-type=module', '-e', code], cwd=ROOT, text=True, capture_output=True)
        if probe.returncode or not Path(probe.stdout.strip()).is_file():
            self.skipTest('Playwright/Chromium unavailable: '+probe.stderr.strip())
        run = subprocess.run([NODE, str(ROOT/'tests/node/browser.test.mjs')], text=True, capture_output=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
        if '# pass 0' in run.stdout and '# skipped ' in run.stdout:
            self.skipTest('Playwright/Chromium launch unavailable; Node browser suite skipped all tests')
