"""Actual browser entry point against a Playwright module fake, no services."""
from datetime import datetime, timezone
import contextlib
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import socket
import tempfile
import unittest
from unittest.mock import patch

import test_runtime_keycloak_login_adversarial as login_fixture
import test_runtime_transport_pipeline as transport_fixture
import test_runtime_keycloak_pipeline as keycloak_fixture
import helix_environment
import helix_runtime as runtime
import helix_runtime_keycloak as keycloak
from helix_runtime_login import project_identity
import helix_visual


SOURCE = Path(os.environ.get('HELIX_SOURCE_ROOT', Path(__file__).resolve().parents[1]))
NODE_RUN = subprocess.run
NODE_POPEN = subprocess.Popen


def fake_playwright_module():
    # Reuse only the fake browser implementation. Its input is a test fixture,
    # separate from the private path the real entry point is meant to validate.
    body = 'const events=[],emitted=[];' + login_fixture.DRIVER.split('const events=[],emitted=[];',1)[1].split('const gate=',1)[0]
    body = body.replace("goto:async url=>{events.push({event:'goto',index});await navigate(url);return navigate(authorizeUrl());}",
        "goto:async url=>{events.push({event:'goto',index,path:new URL(url).pathname});const response=await navigate(url);return new URL(url).pathname===input.login_path?navigate(authorizeUrl()):response;}")
    body = body.replace('url:()=>current,locator,mainFrame:()=>mainFrame,',
        'url:()=>current,locator,mainFrame:()=>mainFrame,addScriptTag:async()=>{},evaluate:async()=>({violations:[]}),')
    prefix = """const fs=require('fs'),Module=require('module');
const originalLoad=Module._load;
Module._load=function(id,...args){if(/^(?:node:)?(?:http|https|net|tls|dns|child_process)$/.test(id))throw Error('forbidden external I/O module');return originalLoad.call(this,id,...args);};
global.fetch=()=>{throw Error('forbidden network fetch');};
const spec=JSON.parse(fs.readFileSync(process.env.LOGIN_FIXTURE_SPEC,'utf8'));
"""
    suffix = """
exports.chromium={launch:async options=>{events.push({event:'launch',options});return {
 newContext:browser.newContext,
 close:async()=>{events.push({event:'browser-close'});fs.writeFileSync(process.env.LOGIN_FIXTURE_RECORDS,JSON.stringify({events,contextCount,closed}));}
};}};
"""
    return prefix + body + suffix


class RuntimeIdentityBrowserWiring(unittest.TestCase):
    def setUp(self):
        login_fixture.KeycloakLoginAdversarial.setUp(self)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve()
        self.project=self.base/'synthetic-project';self.project.mkdir()
        (self.project/'package.json').write_text('{}')
        modules=self.project/'node_modules'
        playwright=modules/'playwright';playwright.mkdir(parents=True)
        (playwright/'package.json').write_text('{"name":"playwright","main":"index.cjs"}')
        (playwright/'index.cjs').write_text(fake_playwright_module())
        axe=modules/'axe-core';axe.mkdir()
        (axe/'package.json').write_text('{"name":"axe-core","main":"axe.min.js"}')
        (axe/'axe.min.js').write_text('// Synthetic module, never evaluates a page.')
        self.private=self.base/'private';self.private.mkdir(mode=0o700)
        self.input_path=self.private/'identity.json'
        self.output=self.base/'browser.json'
        self.records=self.base/'records.json'
        self.spec=self.private/'test-fixture.json'
        self.resource=self.base/'resource.json'
        self.resource.write_text(json.dumps(dict(updated_at=datetime.now(timezone.utc).isoformat(),state='normal',
            effective_jobs=1,max_pause_s=.1,poll_s=.001,stale_after_s=30)))

    def run_browser(self, mode='e2e', scenario=None, input_path=None):
        self.input_path.write_text(json.dumps(self.input));self.input_path.chmod(0o600)
        self.spec.write_text(json.dumps(dict(input=self.input,scenario=scenario or {})));self.spec.chmod(0o600)
        env={key:value for key,value in os.environ.items() if key in ('PATH','HOME','TMPDIR')}
        env.update(HELIX_RUNTIME_IDENTITY_MODE='keycloak-form',HELIX_RUNTIME_IDENTITY_INPUT=str(input_path or self.input_path),
            HELIX_RUNTIME_PRIVATE_ROOT=str(self.private),HELIX_RUNTIME_OIDC_ISSUER=self.input['issuer'],
            HELIX_RUNTIME_TLS_SPKI_LIST='A'*43+'='+','+'B'*43+'=',HELIX_RESOURCE_FILE=str(self.resource),
            HELIX_RUNTIME_BROWSER_BUDGETS=json.dumps(dict(workers=1,navigation_ms=500,axe_ms=500)),
            LOGIN_FIXTURE_SPEC=str(self.spec),LOGIN_FIXTURE_RECORDS=str(self.records))
        done=subprocess.run([shutil.which('node') or 'node',str(SOURCE/'bin/runtime-browser.cjs'),
            self.input['app_origin']+'/',str(self.output),mode,'["/private"]',str(self.project)],
            env=env,text=True,capture_output=True,timeout=8)
        result=json.loads(self.output.read_text()) if self.output.exists() else {}
        records=json.loads(self.records.read_text()) if self.records.exists() else {'events':[]}
        return done,result,records

    def test_actual_entry_point_observes_two_forms_without_claiming_session_or_routes(self):
        self.input['identities'].append(dict(id='role-'+'b'*12,username='helix-role-'+'b'*12,
            email_verified=True,app_roles=['editor'],password='SECOND_PASSWORD_CANARY'))
        done,data,records=self.run_browser()
        self.assertEqual(done.returncode,0,done.stderr)
        suite=data['identity_form']
        self.assertEqual(suite['binding'],self.input['binding'])
        self.assertEqual(suite['form_status'],'PASS');self.assertEqual(suite['status'],'INCOMPLETE')
        self.assertEqual(suite['session_coverage'],'NOT_RUN');self.assertEqual(suite['authorization_coverage'],'NOT_RUN')
        self.assertEqual([flow['identity_id'] for flow in suite['identities']],[row['id'] for row in self.input['identities']])
        self.assertTrue(all(flow['execution']['protected_routes_tested']==0 and not flow['execution']['session_asserted'] for flow in suite['identities']))
        fills=[event for event in records['events'] if event['event']=='fill']
        self.assertEqual(len(fills),4)
        self.assertEqual(records['contextCount'],records['closed'])
        self.assertTrue(all('storageState' not in event['options'] for event in records['events'] if event['event']=='context'))
        self.assertNotEqual((data.get('auth_flow') or {}).get('status'),'PASS')
        public=done.stdout+done.stderr+self.output.read_text()+Path(str(self.output)+'.jsonl').read_text()
        for secret in ('PASSWORD_CANARY_17','SECOND_PASSWORD_CANARY','AUTH_CODE_CANARY_17','STATE_CANARY_17',
                       'NONCE_CANARY_17','FORM_SESSION_CANARY_17','COOKIE_VALUE_CANARY_17'):
            self.assertNotIn(secret,public)
        self.assertFalse(Path(str(self.output)+'.session').exists())

    def test_a11y_does_not_repeat_login_or_inherit_unproven_session(self):
        done,data,records=self.run_browser(mode='a11y')
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertIsNone(data.get('identity_form'))
        self.assertFalse(any(event['event'] in ('fill','click') for event in records['events']))
        self.assertTrue(all('storageState' not in event['options'] for event in records['events'] if event['event']=='context'))
        self.assertFalse(Path(str(self.output)+'.session').exists())

    def test_actual_callback_failure_does_not_become_successful_auth_flow(self):
        done,data,records=self.run_browser(scenario={'callbackParams':{'state':'wrong-current-attempt'}})
        suite=data['identity_form']
        self.assertNotEqual(suite['form_status'],'PASS')
        self.assertNotEqual((data.get('auth_flow') or {}).get('status'),'PASS')
        self.assertEqual(suite['session_coverage'],'NOT_RUN')
        self.assertEqual(suite['authorization_coverage'],'NOT_RUN')
        self.assertEqual(records['contextCount'],records['closed'])

    def test_private_input_symlink_is_rejected_before_filling_credentials(self):
        alias=self.private/'alias.json';alias.symlink_to(self.input_path)
        done,data,records=self.run_browser(input_path=alias)
        self.assertFalse(any(event['event'] in ('fill','click') for event in records['events']))
        self.assertNotEqual((data.get('identity_form') or {}).get('form_status'),'PASS')
        self.assertNotEqual((data.get('auth_flow') or {}).get('status'),'PASS')


class LoginExecutor(transport_fixture.TransportExecutor):
    def __init__(self):
        super().__init__()
        self.browser_calls=[]
        self.browser_failure=False
        self.truncate_final=False
        fixture=login_fixture.KeycloakLoginAdversarial('runTest');fixture.setUp()
        self.latest_input=fixture.input

    def run(self, argv, cwd, env, timeout):
        if len(argv)>1 and str(argv[1]).endswith('runtime-browser.cjs'):
            self.calls.append((list(argv),Path(cwd),dict(env),timeout))
            input_path=Path(env['HELIX_RUNTIME_IDENTITY_INPUT']) if env.get('HELIX_RUNTIME_IDENTITY_INPUT') else None
            if input_path:self.latest_input=json.loads(input_path.read_text())
            record=dict(env=dict(env),input=copy.deepcopy(self.latest_input) if input_path else None,
                input_path=str(input_path) if input_path else None,mode=argv[4],
                permissions=input_path.stat().st_mode&0o777 if input_path else None,
                parent_permissions=input_path.parent.stat().st_mode&0o777 if input_path else None)
            self.browser_calls.append(record)
            if self.browser_failure:return 2,'synthetic browser failure'
            module=Path(env['HELIX_RUNTIME_NODE_MODULES'])/'playwright';module.mkdir(parents=True,exist_ok=True)
            (module/'package.json').write_text('{"name":"playwright","main":"index.cjs"}')
            (module/'index.cjs').write_text(fake_playwright_module())
            axe=module.parent/'axe-core';axe.mkdir(exist_ok=True)
            (axe/'package.json').write_text('{"name":"axe-core","main":"axe.min.js"}')
            (axe/'axe.min.js').write_text('// No browser or page execution.')
            output=Path(argv[3])
            spec=output.parent/('fake-'+argv[4]+'.json');spec.write_text(json.dumps(dict(input=self.latest_input)));spec.chmod(0o600)
            records=output.parent/('fake-'+argv[4]+'-records.json')
            execution_env=dict(env,LOGIN_FIXTURE_SPEC=str(spec),LOGIN_FIXTURE_RECORDS=str(records))
            # This is the only permitted real child: Node executing Helix against
            # the fake module above. Application/Docker/OpenSSL are all fakes.
            done=NODE_RUN([shutil.which('node') or 'node',*[str(value) for value in argv[1:]]],
                cwd=cwd,env=execution_env,text=True,capture_output=True,timeout=8)
            record['returncode']=done.returncode
            record['events']=json.loads(records.read_text()) if records.exists() else {}
            if self.truncate_final and argv[4]=='e2e':
                output.write_text('{"routes":')
                return 2,'synthetic interruption after durable form checkpoint'
            return done.returncode,done.stdout+done.stderr
        return super().run(argv,cwd,env,timeout)


class RuntimeIdentityRunnerWiring(unittest.TestCase):
    app=transport_fixture.RuntimeTransportPipeline.app
    snapshot=transport_fixture.RuntimeTransportPipeline.snapshot
    configure=transport_fixture.RuntimeTransportPipeline.configure
    application=transport_fixture.RuntimeTransportPipeline.application

    def setUp(self):
        transport_fixture.RuntimeTransportPipeline.setUp(self)
        self.executor=LoginExecutor()

    def setup_identity(self, *, login_path=True):
        self.application(identity=True)
        self.parts['frontend']['roles']=['reader','editor']
        self.parts['frontend']['client_type']='confidential'
        if login_path:self.parts['frontend']['login_path']='/sign-in'
        self.configure()

    def run_pipeline(self, skip=()):
        ports=iter(range(44200,44300))
        resources=keycloak_fixture.PipelineResources(self.executor)
        resources.current_path=self.base/'resources.json'
        resources.current_path.write_text(json.dumps(dict(updated_at=datetime.now(timezone.utc).isoformat(),state='normal',
            effective_jobs=1,max_pause_s=.1,poll_s=.001,stale_after_s=30)))
        self.runner=runtime.Runner(self.project,self.out,executor=self.executor,skip=skip,
            tools={'tools':{name:'/fake/'+name for name in ('docker','node','npm','openssl','k6')}},
            port_factory=lambda:next(ports),resource_governor=resources)
        self.executor.identity.runner=self.runner
        measured=self.runner.measure
        self.restored_app_env=False
        def measure(check,part,url,budgets):
            if check in ('e2e','a11y','load'):return measured(check,part,url,budgets)
            if check=='backup':self.restored_app_env=bool(self.runner.env.get('EXAMPLE_KC_CLIENT_SECRET'))
            return 'PASS',dict(synthetic_measurement=1)
        def database():
            self.runner.db='postgresql://helix@127.0.0.1:44199/helix';self.runner.used_engine='native'
        def only_fake_browser(argv,*args,**kwargs):
            if (len(argv)>1 and argv[0]==shutil.which('node') and
                    Path(argv[1]).resolve()==(SOURCE/'bin/runtime-browser.cjs').resolve() and
                    kwargs.get('env',{}).get('LOGIN_FIXTURE_SPEC')):
                return NODE_POPEN(argv,*args,**kwargs)
            raise AssertionError('unapproved process')
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(subprocess,'run',side_effect=AssertionError('unapproved process')))
            stack.enter_context(patch.object(subprocess,'Popen',side_effect=only_fake_browser))
            stack.enter_context(patch.object(socket,'socket',side_effect=AssertionError('real network')))
            stack.enter_context(patch.object(helix_environment,'_git_ref',return_value={'head':None,'dirty':None,'status':'unknown','reason':'synthetic'}))
            stack.enter_context(patch.object(keycloak,'local_docker_endpoint',return_value={'host':'unix:///synthetic/docker.sock','kind':'unix','source':'test_fixture'}))
            stack.enter_context(patch.object(self.runner,'database',side_effect=database))
            stack.enter_context(patch.object(self.runner,'select_schema'))
            stack.enter_context(patch.object(self.runner,'migrate'))
            stack.enter_context(patch.object(self.runner,'measure',side_effect=measure))
            stack.enter_context(patch.object(helix_visual,'runtime_weight',return_value={'status':'needs-runtime'}))
            stack.enter_context(patch.object(helix_visual,'runtime_audits',return_value={'status':'needs-runtime'}))
            return self.runner.run()

    def test_real_runner_builds_private_current_input_and_retains_form_after_cleanup(self):
        self.setup_identity();before=self.snapshot()
        report=self.run_pipeline()
        e2e=next(row for row in self.executor.browser_calls if row['mode']=='e2e')
        private=e2e['input'];suite,=report['identity_forms']
        self.assertEqual(suite['binding'],private['binding'])
        self.assertEqual(suite['binding']['run_id'],report['run_id'])
        self.assertEqual(suite['binding']['integration_plan_id'],report['integrations']['plan_id'])
        self.assertEqual(private['app_origin'],report['parts'][0]['transport']['public_origin'])
        self.assertEqual(private['binding']['identity_plan_id'],report['identity_plan']['parts'][0]['plan_id'])
        self.assertEqual(suite['form_status'],'PASS');self.assertEqual(suite['status'],'INCOMPLETE')
        self.assertEqual(len(suite['identities']),2)
        identity=project_identity(report)
        self.assertEqual(identity['session_coverage'],'NOT_RUN')
        self.assertEqual(identity['authorization_coverage'],'NOT_RUN')
        self.assertEqual(report['integration_receipts'][0]['tested_routes'],[])
        self.assertEqual(report['coverage_status'],'INCOMPLETE');self.assertNotEqual(report['status'],'PASS')
        self.assertTrue(self.executor.identity.removed)
        self.assertEqual(before,self.snapshot());self.assertFalse(self.runner.tmp.exists())
        runtime.validate_report(report)

    def test_browser_environment_has_no_application_credentials_and_input_is_deleted(self):
        self.setup_identity();report=self.run_pipeline()
        e2e=next(row for row in self.executor.browser_calls if row['mode']=='e2e')
        self.assertEqual((e2e['permissions'],e2e['parent_permissions']),(0o600,0o700))
        self.assertFalse(Path(e2e['input_path']).is_relative_to(self.project))
        self.assertFalse(Path(e2e['input_path']).exists())
        for call in self.executor.browser_calls:
            self.assertNotIn('EXAMPLE_KC_CLIENT_SECRET',call['env'])
            self.assertNotIn('DATABASE_URL',call['env'])
            self.assertNotIn('NODE_OPTIONS',call['env'])
            self.assertNotIn('DOCKER_HOST',call['env'])
            if call['mode']=='a11y':self.assertNotIn('HELIX_RUNTIME_IDENTITY_INPUT',call['env'])
        self.assertTrue(self.restored_app_env)
        public=json.dumps(report)+''.join(path.read_text() for path in self.out.rglob('*') if path.is_file())
        for identity in e2e['input']['identities']:self.assertNotIn(identity['password'],public)
        secret=self.executor.app_starts[0]['env']['EXAMPLE_KC_CLIENT_SECRET']
        self.assertTrue(secret);self.assertNotIn(secret,public);self.assertNotIn(secret,json.dumps(e2e['input']))
        self.assertNotIn('AUTH_CODE_CANARY_17',public);self.assertNotIn('STATE_CANARY_17',public)
        self.assertFalse(any(path.name.endswith('.session') for path in self.out.rglob('*')))

    def test_wrong_attempt_plan_part_and_run_cannot_replace_current_form_receipt(self):
        self.setup_identity();report=self.run_pipeline();suite=report['identity_forms'][0]
        path=self.out/'logs'/(suite['binding']['attempt_id']+'.json');before=path.read_bytes()
        for field,value in (('attempt_id','login-'+'f'*32),('run_id','runtime-'+'f'*32),
                            ('integration_plan_id','f'*64),('identity_plan_id','f'*64),('part','other')):
            forged=copy.deepcopy(suite);forged['binding'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.runner.record_identity_suite({'path':'frontend'},forged)
            self.assertEqual(path.read_bytes(),before)

    def test_missing_explicit_login_path_preserves_readiness_but_form_not_run(self):
        self.setup_identity(login_path=False);report=self.run_pipeline()
        self.assertEqual(report['identity_forms'],[])
        self.assertTrue(all(row['input'] is None for row in self.executor.browser_calls))
        self.assertEqual(project_identity(report)['parts'][0]['form_status'],'NOT_RUN')
        self.assertEqual(report['integration_receipts'][0]['tested_routes'],[])
        self.assertNotEqual(report['status'],'PASS')
        self.assertTrue(self.executor.identity.removed)

    def test_failed_browser_command_still_deletes_private_input_and_cleans_owned_identity(self):
        self.setup_identity();self.executor.browser_failure=True;report=self.run_pipeline()
        e2e=next(row for row in self.executor.browser_calls if row['mode']=='e2e')
        self.assertIsNotNone(e2e['input_path']);self.assertFalse(Path(e2e['input_path']).exists())
        self.assertEqual(report['identity_forms'],[])
        self.assertNotEqual(report['status'],'PASS')
        self.assertTrue(self.executor.identity.removed)
        self.assertFalse(self.runner.tmp.exists())

    def test_truncated_final_output_preserves_form_checkpoint_but_blocks_e2e(self):
        self.setup_identity();self.executor.truncate_final=True;report=self.run_pipeline()
        suite,=report['identity_forms']
        self.assertEqual(suite['form_status'],'PASS')
        control=report['parts'][0]['checks']['e2e']
        self.assertEqual(control['status'],'BLOCKED')
        self.assertTrue(control['metrics']['artifact_gaps'])
        self.assertNotEqual(report['status'],'PASS')
        self.assertEqual(project_identity(report)['session_coverage'],'NOT_RUN')
        self.assertTrue(self.executor.identity.removed);self.assertFalse(self.runner.tmp.exists())


if __name__=='__main__':unittest.main()
