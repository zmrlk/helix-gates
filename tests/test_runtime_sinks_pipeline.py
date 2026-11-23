"""Real Runner plus owned Node adapter/handler, with no listening sockets."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from test_runtime import FakeExecutor, TOOLS, FIX
import helix_runtime as rt
import helix_runtime_sinks as sinks
import helix_pro

NODE=shutil.which('node')
DRIVER=r'''
const fs=require('node:fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const h=require(process.argv[1]);const a=require(process.argv[2]);
const value=input.value;const mailbox=[];
const handler=h.createHandler(value,{writeMailbox:row=>mailbox.push(row),writePublic:row=>fs.writeFileSync(value.public_path,JSON.stringify(row),{mode:0o600})});
(async()=>{handler.ready();
if(input.capture){const adapter=a.createAdapter(value,{fetch:async(url,init)=>{const result=await handler.handle({url,method:init.method,headers:init.headers,body:Buffer.from(init.body||'')});return new Response(result.body,{status:result.status,headers:result.headers});}});await adapter.fetch('https://api.resend.com/emails',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer PRIVATE_CANARY'},body:JSON.stringify({to:'helix@helix-mail.invalid',text:'PRIVATE_MAILBOX_CANARY'})});}
if(input.closed)handler.close();
if(input.corrupt){const row=handler.snapshot();row.binding.attempt_id='sink-'+ 'f'.repeat(32);fs.writeFileSync(value.public_path,JSON.stringify(row));}
if(input.failure){const row=handler.snapshot();row.status='partial';row.gaps.push('SINK_WRITE_FAILED');fs.writeFileSync(value.public_path,JSON.stringify(row));}
fs.writeFileSync(value.mailbox_path+'/generated-material.json',JSON.stringify(h.syntheticMaterial(value)),{mode:0o600});
for(const row of mailbox)fs.writeFileSync(value.mailbox_path+'/capture-'+row.sequence+'.json',JSON.stringify(row),{mode:0o600});
process.stdout.write(JSON.stringify({snapshot:handler.snapshot(),mailbox_count:mailbox.length}));
})().catch(()=>{process.exitCode=2;});
'''

class SinkExecutor(FakeExecutor):
    def __init__(self,scenario='captured'):
        super().__init__();self.scenario=scenario;self.sink_processes={};self.sink_inputs=[];self.sink_envs=[];self.captured=set()
    def emit(self,value,**kwargs):
        result=subprocess.run([NODE,'-e',DRIVER,str(rt.HOME/'bin/runtime-sinks.cjs'),str(rt.HOME/'bin/runtime-sinks-preload.cjs')],input=json.dumps(dict(value=value,**kwargs)),text=True,capture_output=True,timeout=10)
        if result.returncode:raise AssertionError('owned fake sink driver failed: '+result.stderr)
        return json.loads(result.stdout)
    def spawn(self,argv,cwd,env,log):
        if any(str(item).endswith('runtime-sinks.cjs') for item in argv):
            value=json.loads(Path(argv[-1]).read_text());self.sink_inputs.append(copy.deepcopy(value));self.sink_envs.append(dict(env))
            if self.scenario=='start_failure':raise OSError('PRIVATE_START_CANARY')
            process=object();self.started.append(process);self.sink_processes[process]=value
            self.emit(value);log.write_text('runtime-sinks listening synthetic transport\n');return process
        return super().spawn(argv,cwd,env,log)
    def run(self,argv,cwd,env,timeout):
        value=None
        if env.get('HELIX_RUNTIME_SINK_INPUT'):
            value=json.loads(Path(env['HELIX_RUNTIME_SINK_INPUT']).read_text())
            if value['binding']['part'] not in self.captured and 'build' in argv and self.scenario!='ready':
                self.emit(value,capture=True,failure=self.scenario=='writer_failure');self.captured.add(value['binding']['part'])
        return super().run(argv,cwd,env,timeout)
    def stop(self,process):
        if process in self.sink_processes:
            value=self.sink_processes[process]
            self.emit(value,capture=value['binding']['part'] in self.captured,closed=self.scenario!='cleanup_unknown',
                failure=self.scenario=='writer_failure',corrupt=self.scenario=='wrong_binding')
        super().stop(process)


@unittest.skipUnless(NODE,'Node unavailable')
class RuntimeSinksPipeline(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.project=self.base/'project';shutil.copytree(FIX/'sveltekit-pg',self.project)
        self.out=self.base/'out'
    def setup_channels(self):
        file=self.project/'src/sender.ts';file.parent.mkdir(exist_ok=True)
        file.write_text("import mail from 'resend';\nconsume(process.env.PLAY_BASE_URL);\nimport push from 'web-push';\nconsume(process.env.VAPID_PUBLIC_KEY,process.env.VAPID_PRIVATE_KEY);\n")
    def run_pipeline(self,scenario='captured',keep=False):
        self.setup_channels();self.executor=SinkExecutor(scenario);ports=iter(range(34000,34100))
        self.current=rt.Runner(self.project,self.out,executor=self.executor,tools={'tools':TOOLS},port_factory=lambda:next(ports),keep=keep)
        return self.current.run()
    def test_adapters_before_install_build_migration_and_composed_owned_loader(self):
        report=self.run_pipeline();value=self.executor.sink_inputs[0]
        calls=[row for row in self.executor.calls if row[2].get('HELIX_RUNTIME_SINK_INPUT')]
        self.assertTrue(calls);self.assertTrue(any('install' in row[0] for row in calls));self.assertTrue(any('build' in row[0] for row in calls))
        for _,_,env,_ in calls:self.assertIn('runtime-sinks-preload.cjs',env['NODE_OPTIONS'])
        self.assertTrue(all('VAPID_PRIVATE_KEY' not in env and 'NODE_OPTIONS' not in env for env in self.executor.sink_envs))
        policies=self.current.isolation_backend().policies
        self.assertTrue(any(int(value['origin'].rsplit(':',1)[1]) in p['connect_tcp'] for p in policies if p['scope']=='project'))
        self.current.env['NODE_OPTIONS']='--require /hostile/project.js';self.current.add_owned_preload(rt.HOME/'bin/runtime-fetch.cjs')
        self.assertIn('runtime-fetch.cjs',self.current.env['NODE_OPTIONS']);self.assertIn('runtime-sinks-preload.cjs',self.current.env['NODE_OPTIONS']);self.assertNotIn('hostile',self.current.env['NODE_OPTIONS'])
        rt.validate_report(report)
    def test_capture_private_retention_and_zero_delivery_route_credit(self):
        report=self.run_pipeline();view=sinks.project_sinks(report)
        self.assertEqual(view['counts']['captured_local'],1);self.assertEqual(view['counts']['external_deliveries_verified'],0)
        self.assertEqual(view['counts']['application_routes_verified'],0);self.assertEqual(view['execution_status'],'OBSERVED')
        self.assertEqual(report['status'],'INCOMPLETE')
        for row in report['integration_receipts']:
            if row['strategy']=='emulator':self.assertEqual(row['tested_routes'],[]);self.assertEqual(row['readiness'],'ready')
        serialized=json.dumps(report);self.assertNotIn('PRIVATE_MAILBOX_CANARY',serialized);self.assertNotIn('PRIVATE_CANARY',serialized)
        value=self.executor.sink_inputs[0];mailbox=Path(value['mailbox_path']);self.assertEqual(mailbox.stat().st_mode&0o777,0o700)
        self.assertIn('PRIVATE_MAILBOX_CANARY',(mailbox/'capture-1.json').read_text())
        for path in mailbox.iterdir():self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertFalse(self.current.tmp.exists());self.assertFalse(Path(self.current.env['HELIX_RUNTIME_SINK_INPUT']).exists())
        self.assertEqual(len(self.executor.started),len(self.executor.stopped))
    def test_readiness_is_not_capture_and_missing_subscription_remains_gap(self):
        report=self.run_pipeline('ready');view=sinks.project_sinks(report)
        self.assertEqual(view['counts']['captured_local'],0);self.assertEqual(view['execution_status'],'READY')
        self.assertIn('SYNTHETIC_SUBSCRIPTION_NOT_PROVEN',view['parts'][0]['gaps'])
    def test_failure_binding_and_cleanup_preserve_partial_without_false_capture(self):
        for scenario in ('writer_failure','cleanup_unknown','wrong_binding'):
            with self.subTest(scenario=scenario):
                self.out=self.base/scenario;report=self.run_pipeline(scenario);view=sinks.project_sinks(report)
                self.assertEqual(view['execution_status'],'PARTIAL');self.assertNotEqual(report['status'],'PASS')
                self.assertEqual(view['counts']['external_deliveries_verified'],0)
    def test_start_failure_blocks_before_project_install_without_secret_error(self):
        report=self.run_pipeline('start_failure')
        self.assertFalse(any('install' in row[0] for row in self.executor.calls))
        self.assertNotIn('PRIVATE_START_CANARY',json.dumps(report));self.assertEqual(report['sink_observations'][0]['status'],'blocked')
        self.assertFalse(any(row['strategy']=='emulator' for row in report['integration_receipts']))
    def test_import_projection_preserves_private_boundary(self):
        report=self.run_pipeline();maturity=helix_pro.assess(self.project,'XL')
        rt.import_evidence(maturity,self.out/'runtime-report.json',self.project)
        self.assertEqual(maturity['runtime_sinks']['counts']['captured_local'],1)
        self.assertEqual(maturity['runtime_sinks']['counts']['application_routes_verified'],0)
    def test_synthetic_private_scalar_is_always_padded_to_32_bytes(self):
        script="const c=require('node:crypto');c.createECDH=()=>({generateKeys(){},getPublicKey(){return Buffer.alloc(65,4)},getPrivateKey(){return Buffer.from([1])}});const h=require(process.argv[1]);const m=h.syntheticMaterial({webpush_endpoint:'http://127.0.0.1:32123/web-push/helix-synthetic'});process.stdout.write(String(Buffer.from(m.vapid.private_key,'base64url').length));"
        result=subprocess.run([NODE,'-e',script,str(rt.HOME/'bin/runtime-sinks.cjs')],text=True,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,'32')

    def test_keep_collects_latest_capture_without_claiming_cleanup(self):
        report=self.run_pipeline(keep=True);self.addCleanup(shutil.rmtree,self.current.tmp,True)
        view=sinks.project_sinks(report)
        self.assertEqual(view['counts']['captured_local'],1)
        self.assertEqual(view['execution_status'],'PARTIAL')
        self.assertEqual(view['parts'][0]['cleanup'],'unknown')
        self.assertTrue(self.current.tmp.exists());self.assertEqual(self.executor.stopped,[])

    def test_later_owned_idp_origin_is_added_without_external_passthrough(self):
        self.run_pipeline(keep=True);self.addCleanup(shutil.rmtree,self.current.tmp,True)
        runner=self.current;runner.env['HELIX_RUNTIME_OIDC_ISSUER']='https://127.0.0.1:35555/realms/synthetic'
        runner.network_connect_ports.add(35555);runner.refresh_sink_input()
        value=json.loads(runner.active_sink['config'].read_text())
        self.assertIn('https://127.0.0.1:35555',value['own_origins'])
        runner.env['HELIX_RUNTIME_OIDC_ISSUER']='https://external.invalid/realms/hostile';runner.refresh_sink_input()
        self.assertNotIn('https://external.invalid',runner.active_sink['input']['own_origins'])

    def test_unknown_or_stale_public_receipt_rejected(self):
        report=self.run_pipeline();report['sink_observations'][0]['binding']['run_id']='old'
        with self.assertRaises(ValueError):rt.validate_report(report)

if __name__=='__main__':unittest.main()
