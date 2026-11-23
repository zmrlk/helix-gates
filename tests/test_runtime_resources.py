"""Runtime pauses admission, retains partial evidence and cleans its own children."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_runtime import FakeExecutor, TOOLS, FIX
import helix_resources as R
import helix_runtime as runtime
from helix_config import configure


class RuntimeResources(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()

    def governor(self,sample,**policy):
        gate=R.Governor(snapshot_fn=sample,requested_jobs=4,out=self.root/'out',policy=policy)
        clock=[0.0];gate._clock=lambda:clock[0];gate._sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds)
        return gate,clock

    def runner(self,executor=None,governor=None,project=None):
        return runtime.Runner(project or FIX/'sveltekit-pg',self.root/'out',executor=executor or FakeExecutor(),
                              tools={'tools':dict(TOOLS)},port_factory=lambda:31234,resource_governor=governor)

    def test_critical_before_start_never_runs_application_and_is_not_pass(self):
        gate,clock=self.governor(lambda:dict(FakeExecutor.resource_snapshot(),load_ratio=4),max_pause_s=10)
        runner=self.runner(governor=gate);report=runner.run()
        self.assertEqual(report['run_status'],'resource_paused');self.assertEqual(report['status'],'BLOCKED')
        self.assertTrue(report['partial']);self.assertEqual(runner.executor.calls,[]);self.assertEqual(runner.executor.started,[])
        self.assertFalse(runner.tmp.exists());self.assertEqual(clock[0],10)
        self.assertEqual(report['resources']['decisions'][0]['effective_jobs'],0)
        self.assertIn('INCOMPLETE',(runner.out/'runtime.md').read_text())
        runtime.validate_report(report)

    def test_resource_wait_uses_global_budget_without_oversleep_or_new_process(self):
        gate,clock=self.governor(lambda:dict(FakeExecutor.resource_snapshot(),load_ratio=4))
        runner=self.runner(governor=gate);runner.budget=runtime.Budget(1,clock=lambda:clock[0])
        report=runner.run()
        self.assertEqual(clock[0],1)
        self.assertEqual(report['status'],'BLOCKED');self.assertIn('budget exhausted',report['reason'])
        self.assertEqual(runner.executor.calls,[])

    def test_pressure_after_start_drains_and_cleanup_bypasses_resource_gate(self):
        sample=FakeExecutor.resource_snapshot()
        gate,clock=self.governor(lambda:sample,max_pause_s=10,sample_s=.1)
        executor=FakeExecutor();spawn=executor.spawn
        def started(*args):
            process=spawn(*args);sample['load_ratio']=4;clock[0]+=1;return process
        executor.spawn=started
        runner=self.runner(executor,gate);report=runner.run()
        self.assertEqual(report['run_status'],'resource_paused')
        self.assertEqual(executor.started,executor.stopped);self.assertFalse(runner.tmp.exists())
        self.assertTrue(any('rm' in c[0] for c in executor.calls))
        checks=report['parts'][0]['checks']
        self.assertEqual(checks['schema-apply']['status'],'PASS')
        self.assertTrue(all(c['status']=='BLOCKED' for name,c in checks.items() if name!='schema-apply'))
        self.assertEqual(clock[0],11)

    def test_browser_resource_pause_preserves_completed_routes_and_journal(self):
        class BrowserPaused(FakeExecutor):
            def run(self,argv,*args):
                if any(str(x).endswith('runtime-browser.cjs') for x in argv):
                    self.calls.append((argv,*args));output=Path(argv[3]);route=json.loads(argv[5])[0]
                    row=dict(type='route',route=route,status='PASS',reachable=True,errors=[],violations=[])
                    pause=dict(type='resource-paused',status='resource_paused',reason='synthetic pressure pause',decision=dict(state='critical',effective_jobs=0))
                    output.write_text(json.dumps(dict(routes=[row],requests=[],resource_paused=pause)))
                    Path(str(output)+'.jsonl').write_text(json.dumps(row)+'\n'+json.dumps(pause)+'\n')
                    return 3,'resource pause'
                return super().run(argv,*args)
        runner=self.runner(BrowserPaused());report=runner.run()
        self.assertEqual(report['run_status'],'resource_paused')
        measured=report['parts'][0]['checks']['e2e']
        self.assertEqual(measured['status'],'BLOCKED');self.assertEqual(measured['metrics']['pages_tested'],1)
        self.assertGreater(measured['metrics']['not_completed'],0)
        self.assertTrue((runner.out/measured['metrics']['journal']).is_file())
        self.assertEqual(runner.executor.started,runner.executor.stopped)
        runtime.validate_report(report)

    def test_high_pressure_only_changes_admission_not_experiment_parameters(self):
        project=self.root/'project';shutil.copytree(FIX/'sveltekit-pg',project)
        config=self.root/'external-config.json';config.write_text(json.dumps({'profile':'M','resources':{'high_load_ratio':1.25},'runtime':{'budgets':{'workers':4}}}))
        configure(project,config)
        class High(FakeExecutor):
            @staticmethod
            def resource_snapshot():return dict(FakeExecutor.resource_snapshot(),load_ratio=1.5)
        runner=self.runner(High(),project=project);report=runner.run()
        # Successful measurements do not prove that database-dependent routes exercised the integration.
        self.assertEqual(report['measurement_status'],'PASS');self.assertEqual(report['coverage_status'],'INCOMPLETE')
        self.assertEqual(report['status'],'INCOMPLETE');self.assertEqual(report['resources']['policy']['high_load_ratio'],1.25)
        self.assertEqual(report['resources']['decisions'][0]['effective_jobs'],2)
        browser=next(c for c in runner.executor.calls if any(str(x).endswith('runtime-browser.cjs') for x in c[0]))
        budgets=json.loads(browser[2]['HELIX_RUNTIME_BROWSER_BUDGETS'])
        expected=runtime.profile_budgets(json.loads(config.read_text()))
        for key in ('workers','vus','duration','route_sample','p95_ms','lcp_ms'):
            self.assertEqual(budgets[key],expected[key])
        self.assertEqual(Path(browser[2]['HELIX_RESOURCE_FILE']),runner.out/'resource-current.json')
        self.assertFalse(hasattr(runtime.Executor(),'resource_snapshot'))

    @unittest.skipUnless(shutil.which('node'),'Node unavailable')
    def test_browser_admission_pause_finishes_active_route_and_keeps_unstarted_routes_unchecked(self):
        project=self.root/'project';module=project/'node_modules/playwright';module.mkdir(parents=True)
        (project/'package.json').write_text('{}');(module/'package.json').write_text('{"name":"playwright","main":"index.cjs"}')
        decision=self.root/'resource-current.json';output=self.root/'browser.json'
        normal=dict(updated_at=R._iso(),state='normal',effective_jobs=1,max_pause_s=.02,poll_s=.001,stale_after_s=15)
        decision.write_text(json.dumps(normal))
        (module/'index.cjs').write_text('''
const fs=require('fs');
exports.chromium={launch:async()=>({newContext:async()=>({route:async()=>{},newPage:async()=>({on:()=>{},goto:async url=>{
 const file=process.env.HELIX_RESOURCE_FILE;const state=JSON.parse(fs.readFileSync(file));state.state='critical';state.effective_jobs=0;state.updated_at=new Date().toISOString();fs.writeFileSync(file,JSON.stringify(state));
 await new Promise(r=>setTimeout(r,5));return {status:()=>200};},url:()=>process.env.FIXTURE_URL+'/'}),close:async()=>{}}),close:async()=>{fs.writeFileSync(process.env.CLOSED_MARKER,'closed')}})};
''')
        import os
        environment=dict(os.environ,HELIX_RESOURCE_FILE=str(decision),FIXTURE_URL='http://127.0.0.1:3000',CLOSED_MARKER=str(self.root/'closed'),HELIX_RUNTIME_BROWSER_BUDGETS=json.dumps({'workers':2}))
        environment.pop('HELIX_RUNTIME_NODE_MODULES',None);environment.pop('HELIX_RUNTIME_OIDC_ISSUER',None)
        result=subprocess.run(['node',str(Path(runtime.__file__).parent/'runtime-browser.cjs'),'http://127.0.0.1:3000',str(output),'e2e',json.dumps(['/','/not-started']),str(project)],env=environment,capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,3,result.stderr)
        data=json.loads(output.read_text());self.assertEqual([r['route'] for r in data['routes']],['/'])
        self.assertEqual(data['routes'][0]['status'],'PASS');self.assertEqual(data['resource_paused']['status'],'resource_paused')
        self.assertTrue((self.root/'closed').is_file())


if __name__=='__main__':unittest.main()
