import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_runtime as runtime
import helix_runtime_adapters as adapters
from test_runtime import FakeExecutor, TOOLS, FIX


def recording(provider='anthropic'):
    return dict(id='synthetic-response', provider=provider, synthetic=True,
                request=dict(url='https://api.anthropic.com/v1/messages' if provider == 'anthropic' else 'http://subiekt.invalid/status',
                             method='POST', body={'model': 'helix-synthetic', 'messages': []}),
                response=dict(status=200, body={'type': 'message', 'content': [{'type': 'text', 'text': 'synthetic answer'}]}))


class AdapterTests(unittest.TestCase):
    def test_worker_discovery_and_nearest_integration_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'worker').mkdir()
            (root / 'worker/requirements.txt').write_text('requests\npsycopg[binary]\n')
            (root / 'worker/call_worker.py').write_text('import requests\nimport os\nx=os.environ["PLAY_CLIENT_ID"]\n')
            spec = runtime.plan(root, {})
            self.assertEqual(spec['parts'][0]['framework'], 'python-worker')
            row = next(row for row in spec['integrations']['integrations'] if row['provider'] == 'play-sms')
            self.assertEqual(row['parts'], ['worker'])
            self.assertEqual(spec['adapters']['parts'][0]['worker']['status'], 'DISABLED')

    def test_timezone_declaration_cron_flags_and_native_warning(self):
        parts = [dict(path='.', framework='node', env=[{'name': 'CRON_SECRET'}, {'name': 'CRON_ENABLED'}])]
        sources = {'Dockerfile': 'ENV TZ=Europe/Warsaw\n', 'server.js': "require('whatsapp-web.js'); require('sharp'); require('satori');",
                   'src/routes/api/cron/sync/+server.ts': 'export function POST() {}'}
        row = adapters.adapter_plan(sources, parts, {'runtime':{'adapters':{'scheduler_routes':['/api/cron/sync']}}})['parts'][0]
        env = adapters.adapter_env(row)
        self.assertEqual(env['TZ'], 'Europe/Warsaw'); self.assertEqual(env['CRON_SECRET'], '')
        self.assertEqual(env['CRON_ENABLED'], ''); self.assertFalse(row['timezone']['production_verified'])
        self.assertEqual(row['cron']['routes'], ['/api/cron/sync'])
        self.assertEqual(row['native']['packages'], ['sharp', 'satori'])

    def test_invalid_timezone_and_recording_rejected(self):
        with self.assertRaises(ValueError): adapters.adapter_plan({}, [], {'runtime': {'adapters': {'timezone': 'bad/timezone'}}})
        for mutate in (lambda r: r.update(synthetic=False), lambda r: r['request'].update(url='https://user:password@host.invalid/x'),
                       lambda r: r['response'].update(status=302)):
            row = recording(); mutate(row)
            with self.assertRaises(ValueError): adapters.recordings({'runtime': {'adapters': {'recordings': [row]}}})
        with self.assertRaises(ValueError): adapters.recordings({'runtime': {'adapters': {'recordings': [recording(), recording()]}}})

    def test_replay_capability_binds_config_and_does_not_claim_python_transport(self):
        from helix_runtime_integrations import inventory
        sources = {'server.ts': "import Anthropic from '@anthropic-ai/sdk';"}
        parts = [dict(path='.', package_manager='npm')]
        config = {'runtime': {'adapters': {'recordings': [recording()]}, 'integrations': {'ai': {'strategy': 'replay'}}}}
        first = inventory(sources, parts, config)
        self.assertTrue(first['integrations'][0]['strategy']['implemented'])
        config['runtime']['adapters']['recordings'][0]['response']['body'] = {'changed': True}
        second = inventory(sources, parts, config)
        self.assertNotEqual(first['plan_id'], second['plan_id'])
        self.assertEqual(second['integrations'][0]['execution']['status'], 'not_run')
        self.assertFalse(inventory(sources, [dict(path='.', package_manager='pip')], config)['integrations'][0]['strategy']['implemented'])

    def test_inbound_requires_explicit_synthetic_project_contract(self):
        for status in (200,500):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'logs').mkdir();calls=[]
                def command(argv,*args,**kwargs):
                    calls.append(argv);return json.dumps({'status':status})
                runner=SimpleNamespace(out=root,work=root,private_logs={},env={'CUSTOM_TOKEN':'synthetic'},tool=lambda n:n,project_temporary=lambda:root,project_command=command,write_sink_input=lambda v,p:p.write_text(json.dumps(v)))
                config={'runtime':{'adapters':{'inbound_replay':[{'synthetic':True,'path':'/callbacks/jobs/42','headers':{'x-test-token':{'env':'CUSTOM_TOKEN'}},'body':{'ok':True}}]}}}
                result=adapters.inbound_replay(runner,{'path':'.'},'http://127.0.0.1:31234/',ROOT,config)
                self.assertEqual(result['status'],'PASS' if status==200 else 'FAIL')
                self.assertEqual(len(calls),1);self.assertNotIn('psql',str(calls))
                self.assertIn('persistence not verified',result['reason'])
        self.assertEqual(adapters.settings_sql({}),'')
        with self.assertRaises(ValueError):adapters.settings_sql({'runtime':{'adapters':{'synthetic_rows':[{'synthetic':True,'table':'public.x;DROP TABLE x','values':{'a':1}}]}}})

    def test_browser_detection_macos_and_executable_bit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Library/Caches/ms-playwright/chromium-123/chrome-mac/Chromium.app/Contents/MacOS/Chromium'
            path.parent.mkdir(parents=True); path.write_text('test'); path.chmod(0o700)
            with patch.object(adapters.os, 'access', side_effect=lambda p, _: p == path):
                self.assertEqual(adapters.chromium_path(directory), str(path))
            with patch.object(adapters.os, 'access', return_value=False):
                self.assertIsNone(adapters.chromium_path(directory))

    def test_checksum_parser_rejects_legacy_malformed_and_duplicate_receipts(self):
        row = dict(table='public.x|odd', rows=2, checksum='a'*32)
        self.assertEqual(adapters.checksum_rows(json.dumps(row)), [row])
        for raw in ('public.x|2', '{"table":"x"}', json.dumps(row)+'\n'+json.dumps(row)):
            with self.assertRaises(ValueError): adapters.checksum_rows(raw)
        self.assertIn('ORDER BY h COLLATE "C"', adapters.CHECKSUM_SQL)
        self.assertIn("SET timezone TO 'UTC'", adapters.CHECKSUM_SQL)

    def test_backup_same_row_count_different_data_fails(self):
        executor = FakeExecutor(); original = executor.run
        def execute(argv, cwd, env, timeout):
            if '-f' in argv and str(argv[-1]).endswith('counts.sql'):
                return 0, json.dumps(dict(table='public.x', rows=3, checksum=('b' if '/helix_restore_' in argv[1] else 'a')*32))
            return original(argv, cwd, env, timeout)
        executor.run = execute
        with tempfile.TemporaryDirectory() as directory:
            runner = runtime.Runner(FIX/'sveltekit-pg', Path(directory)/'out', executor=executor, tools={'tools': TOOLS}, port_factory=lambda: 31234)
            result = runner.run()['parts'][0]['checks']['backup']
            self.assertEqual(result['status'], 'FAIL'); self.assertEqual(result['metrics']['comparison'], 'row_counts_and_checksums')
            self.assertTrue(result['metrics']['fresh_database'])
            self.assertTrue(any('pg_restore' in str(a) for a, _, _, _ in executor.calls))

    def test_worker_never_installs_or_inherits_frontend_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'project'; root.mkdir(); (root/'worker').mkdir()
            (root/'worker/requirements.txt').write_text('requests')
            (root/'worker/call_worker.py').write_text('raise RuntimeError("must not run")')
            executor = FakeExecutor()
            report = runtime.Runner(root, Path(directory)/'out', executor=executor, tools={'tools': TOOLS}).run()
            self.assertFalse(executor.started)
            self.assertFalse(any('install' in a or 'pg_dump' in str(a) for a, _, _, _ in executor.calls))
            # część bez własnych testów: nic nie jest instalowane ani uruchamiane, sprawdzenia ekranowe i HTTP nie dotyczą workera
            self.assertEqual(report['parts'][0]['checks']['backup']['status'], 'SKIPPED')
            self.assertEqual(report['parts'][0]['checks']['worker-tests']['status'], 'SKIPPED')

    def test_primary_timezone_and_utc_restart_have_separate_environment(self):
        executor = FakeExecutor(); spawn = executor.spawn; zones = []
        def capture(argv, cwd, env, log):
            zones.append(env['TZ']); return spawn(argv, cwd, env, log)
        executor.spawn = capture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'project'; shutil.copytree(FIX/'sveltekit-pg', root)
            (root/'Dockerfile').write_text('ENV TZ=Europe/Warsaw')
            report = runtime.Runner(root, Path(directory)/'out', executor=executor, tools={'tools': TOOLS}, port_factory=lambda: 31234).run()
            self.assertEqual(zones, ['Europe/Warsaw', 'UTC'])
            self.assertEqual(report['parts'][0]['checks']['timezone-utc']['status'], 'PASS')
            self.assertEqual(executor.started, executor.stopped)

    def test_missing_chromium_has_explicit_check_and_no_pdf_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'project'; shutil.copytree(FIX/'sveltekit-pg', root)
            pkg = json.loads((root/'package.json').read_text()); pkg.setdefault('dependencies', {})['puppeteer'] = '1.0.0'
            (root/'package.json').write_text(json.dumps(pkg))
            runner = runtime.Runner(root, Path(directory)/'out', executor=FakeExecutor(), tools={'tools': TOOLS}, port_factory=lambda: 31234)
            result = runner.run()['parts'][0]['checks']['pdf-render']
            self.assertEqual(result['status'], 'BLOCKED'); self.assertEqual(result['reason'], 'CHROMIUM_MISSING')

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_real_preload_replays_and_rejects_unknown_without_network(self):
        cases = adapters.recordings({'runtime': {'adapters': {'recordings': [recording(), dict(recording('subiekt'), id='bridge-response')]}}})
        program = r"""
const assert = require('node:assert/strict');
const {install} = require(process.argv[1]);
const input = JSON.parse(process.argv[2]); let calls = 0; const observed=[];
const target={fetch: async()=>{calls++;return new Response('local');}};
const module={_load:()=>{calls++;return 'normal';}};
const undo=install(input,{target,module,observe:r=>observed.push(r)});
(async()=>{
  for(const row of input.recordings){const response=await target.fetch(row.request.url,{method:'POST',body:JSON.stringify(row.request.body)});assert.equal(response.status,200);assert.equal((await response.json()).type,'message');}
  for(const url of ['https://api.anthropic.com/v1/messages','http://subiekt.invalid/unrecorded'])
    await assert.rejects(()=>target.fetch(url,{method:'POST',body:'{}'}),{code:'HELIX_REPLAY_UNMATCHED'});
  for(const name of ['whatsapp-web.js','whatsapp-web.js/src/Client','node-cron','cron']) assert.throws(()=>module._load(name),{code:'HELIX_RUNTIME_PACKAGE_DISABLED'});
  assert.equal(calls,0);assert.equal(observed.filter(r=>r.adapter==='replay').length,2);
  undo();assert.equal(await (await target.fetch('http://localhost/')).text(),'local');
})().catch(e=>{console.error(e);process.exitCode=1});
"""
        result = subprocess.run(['node', '-e', program, str(ROOT/'bin/runtime-adapters.cjs'), json.dumps({'recordings': cases,'disabled_packages':['whatsapp-web.js','node-cron','cron']})], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_bridge_helper_only_loopback_and_no_redirects(self):
        program = r"""
const assert=require('node:assert/strict');const {replay}=require(process.argv[1]);
(async()=>{let calls=0;const input={url:'http://127.0.0.1:31234/callbacks/jobs/42',method:'POST',headers:{'x-token':'synthetic'},body:{ok:true}};
const response=await replay(input,async(url,options)=>{calls++;assert.equal(options.redirect,'error');assert.equal(options.headers['x-token'],'synthetic');return new Response('{}',{status:200});});
assert.deepEqual(response,{status:200});
await assert.rejects(()=>replay({...input,url:input.url.replace('127.0.0.1','prod.invalid')},()=>{calls++;}));assert.equal(calls,1);
})().catch(e=>{console.error(e);process.exitCode=1});
"""
        result = subprocess.run(['node', '-e', program, str(ROOT/'bin/runtime-bridge-replay.cjs')], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__': unittest.main()
