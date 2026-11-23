"""Small offline regressions, no installations, browser or database."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime as rt


class RoundThirteenTests(unittest.TestCase):
    def test_categories(self):
        for route,category in [('/auth/callback','auth'),('/logowanie','auth'),('/faktury','money'),('/zamówienia','money'),('/paiement','money'),('/docs','public'),('/','public'),('/items/new','crud')]:
            self.assertEqual(rt.route_category(route),category)

    def test_profile_sampling(self):
        routes=['/login','/checkout','/docs','/items/new','/items/[id]']+['/items/'+str(i) for i in range(100)]
        # Domyślnie (każdy profil) wszystkie trasy; próbka tylko przy jawnym runtime.budgets.route_sample.
        for profile in ('S','M','L','XL'):
            self.assertEqual(rt.sample_routes(routes,rt.profile_budgets({'profile':profile})['route_sample']),routes)
        for maximum in (10,20,30,40):
            budgets=rt.profile_budgets({'runtime':{'budgets':{'route_sample':maximum}}})
            sample=rt.sample_routes(routes,budgets['route_sample'])
            self.assertEqual(len(sample),maximum)
            self.assertTrue({'/login','/checkout','/docs','/items/new','/items/[id]'}.issubset(sample))
            self.assertEqual(len(sample),len(set(sample)))

    def test_most_applied_and_recommended_tie(self):
        a=dict(strategy='recommended',applied=1)
        b=dict(strategy='other',applied=5)
        self.assertIs(rt.migration_winner([a,b],'recommended'),b)
        a['applied']=5
        self.assertIs(rt.migration_winner([b,a],'recommended'),a)
        b['objects']=30
        self.assertIs(rt.migration_winner([a,b],'recommended'),b)

    def test_partial_timeout_fake_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner=object.__new__(rt.Runner)
            runner.tmp=runner.work=runner.out=Path(tmp)
            runner.browser_tools=True;runner.browser_module_dir=tmp;runner.env={}
            runner.tools={'node':'node'};runner.steps=0
            def fake(argv,*args,**kwargs):
                output=Path(argv[3])
                with Path(str(output)+'.jsonl').open('w') as f:
                    f.write(json.dumps(dict(type='route',route='/',status='PASS',reachable=True,errors=[]))+'\n')
                    f.write(json.dumps(dict(type='route',route='/slow',status='FAIL',reachable=False,errors=['timeout']))+'\n')
                    f.write('{incomplete')
                raise subprocess.TimeoutExpired('fake browser',1)
            runner.command=fake
            runner.project_command=fake  # Isolated recovery fixture; the child remains synthetic.
            status,data=runner.measure('e2e',{'path':'.','routes':['/','/slow','/unfinished']},'http://127.0.0.1:3000',rt.profile_budgets({}))
            self.assertEqual(status,'FAIL')
            self.assertEqual(data['pages'],['/'])
            self.assertEqual(data['pages_tested'],2)
            self.assertEqual(data['not_completed'],1)

    def test_interruption_before_first_control_preserves_blocked_report(self):
        from unittest.mock import patch
        from test_runtime import FIX, TOOLS, FakeExecutor
        import helix_visual
        with tempfile.TemporaryDirectory() as tmp:
            runner=rt.Runner(FIX/'sveltekit-pg',Path(tmp)/'out',executor=FakeExecutor(),
                             tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
            # Przegląd tras idzie teraz po sprawdzeniach; przerwanie przed pierwszym sprawdzeniem wstrzykujemy w ostatni krok przed pętlą.
            with patch.object(rt.Runner,'screen_session',side_effect=rt.Blocked('synthetic interruption before controls')):
                result=runner.run()
            self.assertEqual(result['status'],'BLOCKED')
            checks=result['parts'][0]['checks']
            self.assertEqual(set(checks),set(rt.CHECKS))
            for control in checks.values():
                self.assertEqual(control['status'],'BLOCKED')
                self.assertEqual(control['reason'],'synthetic interruption before controls')
                self.assertTrue((runner.out/control['log']).is_file())
            self.assertTrue((runner.out/'runtime-report.json').is_file())
            self.assertFalse(runner.tmp.exists())
            self.assertEqual(runner.executor.started,runner.executor.stopped)

    def test_browser_final_json_without_journal_is_normalized(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'browser.json'
            output.write_text(json.dumps({'routes':[dict(route='/items',status='PASS',reachable=True,errors=[],violations=[])],'requests':[]}))
            data=rt.browser_results(output)
            self.assertEqual(data['pages'],['/items'])
            self.assertEqual(data['pages_tested'],1)
            self.assertEqual(data['errors'],[])

    def test_auth_flow_points_to_existing_control_log(self):
        from test_runtime import FIX, TOOLS, FakeExecutor
        class AuthExecutor(FakeExecutor):
            def run(self,argv,*args):
                result=super().run(argv,*args)
                if any(str(x).endswith('runtime-browser.cjs') for x in argv):
                    auth=dict(type='auth-flow',status='PASS',steps=[dict(step='protected-route',code=200)],break_at=None)
                    with Path(str(argv[3])+'.jsonl').open('a') as stream:stream.write(json.dumps(auth)+'\n')
                return result
        with tempfile.TemporaryDirectory() as tmp:
            runner=rt.Runner(FIX/'sveltekit-pg',Path(tmp)/'out',executor=AuthExecutor(),tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
            data=runner.run()
            control=data['parts'][0]['checks']['auth-flow']
            self.assertEqual(control['status'],'BLOCKED')
            self.assertTrue((runner.out/control['log']).is_file())
            self.assertIn('NO_EXPLICIT_IDENTITY_POLICY',control['reason'])
            self.assertEqual(control['metrics']['session_coverage'],'NOT_RUN')
            self.assertEqual(control['metrics']['authorization_coverage'],'NOT_RUN')

    def test_equivalent_legacy_claims_fail_import_and_normalize_without_credit(self):
        from test_runtime import FIX,TOOLS,FakeExecutor
        with tempfile.TemporaryDirectory() as tmp:
            report=rt.Runner(FIX/'sveltekit-pg',Path(tmp)/'out',executor=FakeExecutor(),tools={'tools':dict(TOOLS)},port_factory=lambda:31234).run()
        variants=[dict(status='BLOCKED',session_coverage='PASS'),dict(status='BLOCKED',authorization_coverage='PASS'),
                  dict(status='FAIL',steps=[dict(step='session',code=200)]),dict(status='BLOCKED',steps=[dict(step='protected-route',code=201)])]
        for flow in variants:
            original=json.dumps(flow,sort_keys=True)
            normalized=rt.normalize_legacy_auth(flow)
            self.assertEqual(normalized['status'],'BLOCKED');self.assertTrue(normalized['legacy_claims_ignored'])
            self.assertEqual(normalized['session_coverage'],'NOT_RUN')
            self.assertEqual(normalized,rt.normalize_legacy_auth(normalized))
            self.assertEqual(json.dumps(flow,sort_keys=True),original)
            forged=json.loads(json.dumps(report));forged['parts'][0]['checks']['e2e']['metrics']['auth_flow']=flow
            forged['controls']=[dict(result,id=name,part=part['name']) for part in forged['parts'] for name,result in part['checks'].items()]
            with self.subTest(flow=flow),self.assertRaisesRegex(ValueError,'^legacy_auth_claim_unverified$'):rt.validate_report(forged)

    def test_public_browser_run_does_not_invent_authentication_failure(self):
        import os,shutil
        node=shutil.which('node')
        if not node:self.skipTest('Node unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'package.json').write_text('{}')
            module=root/'node_modules/playwright';module.mkdir(parents=True)
            module.joinpath('index.js').write_text("""
exports.chromium={launch:async()=>({close:async()=>{},newContext:async()=>({route:async()=>{},close:async()=>{},newPage:async()=>{let url;return {on:()=>{},goto:async(value)=>{url=value;return {status:()=>200}},url:()=>url}}})})};
""")
            output=root/'browser.json'
            from datetime import datetime, timezone
            monitor=root/'resource-current.json'
            monitor.write_text(json.dumps(dict(state='normal',effective_jobs=4,updated_at=datetime.now(timezone.utc).isoformat())))
            result=subprocess.run([node,str(rt.HOME/'bin/runtime-browser.cjs'),'http://127.0.0.1:3000/',str(output),'e2e','["/","/items"]',str(root)],capture_output=True,text=True,env={'PATH':os.defpath,'HELIX_RESOURCE_FILE':str(monitor.resolve())},timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            data=rt.browser_results(output)
            self.assertIsNone(data['auth_flow'])
            self.assertIn('not configured',data['auth_coverage'])
            self.assertEqual(data['pages'],['/','/items'])
            self.assertTrue(all(r['status']=='PASS' for r in data['routes']))

    def test_no_results_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner=object.__new__(rt.Runner)
            runner.tmp=runner.work=runner.out=Path(tmp);runner.env={};runner.browser_tools=True;runner.browser_module_dir=tmp;runner.tools={'node':'node'};runner.steps=0
            runner.command=lambda *a,**k: None
            runner.project_command=runner.command
            self.assertEqual(runner.measure('e2e',{'path':'.','routes':['/']},'http://127.0.0.1',rt.profile_budgets({}))[0],'BLOCKED')

if __name__=='__main__': unittest.main()
