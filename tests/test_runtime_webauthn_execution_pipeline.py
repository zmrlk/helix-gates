"""Actual Runner/browser/helpers with an independent fake browser/CDP, no services."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_config
import helix_pro
import helix_runtime as runtime
import helix_runtime_webauthn_run as execution
import test_runtime_keycloak_login_pipeline as login_fixture
import test_runtime_policy_execution_pipeline as policy_fixture
from test_runtime_webauthn import fixture_inputs


def webauthn_playwright_module(wrapper,scenario):
    fixture=ROOT/'tests/fixtures/runtime-webauthn-fake.cjs'
    return """const fs=require('fs'),Module=require('module'),load=Module._load;
Module._load=function(id,...args){if(/^(?:node:)?(?:http|https|net|tls|dns|child_process)$/.test(id))throw Error('forbidden external I/O');return load.call(this,id,...args);};
global.fetch=()=>{throw Error('forbidden network');};
const fixture=require(__FIXTURE__).createBrowserFixture({input:__WRAPPER__,scenario:__SCENARIO__});
exports.chromium={launch:async options=>{
 if(options.ignoreHTTPSErrors)throw Error('global TLS disabled');
 return {version:()=>fixture.browser.version(),newContext:async options=>{const ctx=await fixture.browser.newContext(options),newPage=ctx.newPage;
  ctx.newPage=async()=>Object.assign(await newPage(),{addScriptTag:async()=>{},evaluate:async()=>({violations:[]})});return ctx;},
  close:async()=>{try{await fixture.browser.close();}finally{fs.writeFileSync(process.env.LOGIN_FIXTURE_RECORDS,JSON.stringify({events:fixture.events,counters:fixture.counters}));}}};
}};
""".replace('__FIXTURE__',json.dumps(str(fixture))).replace('__WRAPPER__',json.dumps(wrapper)).replace('__SCENARIO__',json.dumps(scenario))


class WebAuthnExecutor(login_fixture.LoginExecutor):
    def __init__(self):
        super().__init__();self.latest_webauthn=None;self.webauthn_calls=[];self.scenario={}
    def run(self,argv,cwd,env,timeout):
        if len(argv)>1 and str(argv[1]).endswith('runtime-browser.cjs'):
            if env.get('HELIX_RUNTIME_WEBAUTHN_INPUT'):
                path=Path(env['HELIX_RUNTIME_WEBAUTHN_INPUT']);self.latest_webauthn=json.loads(path.read_text())
                self.webauthn_calls.append(dict(input=copy.deepcopy(self.latest_webauthn),path=str(path),mode=path.stat().st_mode&0o777,parent_mode=path.parent.stat().st_mode&0o777))
            if self.latest_webauthn is not None:
                with patch.object(login_fixture,'fake_playwright_module',side_effect=lambda:webauthn_playwright_module(self.latest_webauthn,self.scenario)):
                    return super().run(argv,cwd,env,timeout)
        return super().run(argv,cwd,env,timeout)


class RuntimeWebAuthnExecutionPipeline(unittest.TestCase):
    app=policy_fixture.RuntimePolicyExecutionPipeline.app
    snapshot=policy_fixture.RuntimePolicyExecutionPipeline.snapshot
    application=policy_fixture.RuntimePolicyExecutionPipeline.application
    setup_identity=policy_fixture.RuntimePolicyExecutionPipeline.setup_identity
    run_pipeline=policy_fixture.RuntimePolicyExecutionPipeline.run_pipeline

    def setUp(self):
        policy_fixture.RuntimePolicyExecutionPipeline.setUp(self)
        self.executor=WebAuthnExecutor()

    def configure(self):
        config=policy_fixture.RuntimePolicyExecutionPipeline.configure(self)
        config['runtime']['https']['public_host']='localhost'
        planned=runtime.plan(self.project,config)
        cell=next(c for p in planned['identity_policy_plan']['parts'] for c in p['cells'] if c['role']=='reader')
        raw=fixture_inputs()[6]['runtime']['webauthn']['parts']['frontend'];raw['policy_cell_ids']=[cell['id']]
        config['runtime']['webauthn']={'schema_version':1,'parts':{'frontend':raw}}
        self.config_path.write_text(json.dumps(config));helix_config.configure(self.project,self.config_path)
        return config

    def test_current_flow_uses_real_helpers_and_preserves_dependency_checkpoint_order(self):
        self.setup_identity();before=self.snapshot();report=self.run_pipeline()
        view=execution.project_webauthn_execution(report)
        self.assertEqual(view['outcome'],'PASS');self.assertEqual(view['coverage_status'],'RECORDED')
        self.assertEqual(view['counts']['completed_flows'],1)
        chrome=report['provenance']['tools']['chromium']
        self.assertEqual(chrome['version'],'130.0.6723.91');self.assertTrue(chrome['used'])
        self.assertEqual(report['identity_assessment']['status'],'PASS')
        self.assertNotEqual(report['status'],'PASS') # Unexecuted integration routes remain separate.
        self.assertEqual(self.snapshot(),before);runtime.validate_report(report)
        records=[json.loads(line) for path in self.out.glob('logs/browser-*-e2e.jsonl') for line in path.read_text().splitlines()]
        forms={};policy=None;final=False
        for row in records:
            if row.get('type')=='identity-form-suite':forms={i['identity_id']:i for i in row['identities']}
            if row.get('type')=='identity-policy-suite':policy=row
            if row.get('type')=='webauthn-suite' and row['cleanup']['context']=='closed':
                identity=row['binding']['identity_id'];self.assertEqual(forms[identity]['cleanup'],'closed')
                self.assertEqual(forms[identity]['form_status'],'PASS')
                self.assertTrue(any(i['identity_id']==identity and i['cleanup']=='closed' for i in policy['identities']));final=True
        self.assertTrue(final)

    def test_private_input_is_owned_deleted_and_not_exposed(self):
        self.setup_identity();report=self.run_pipeline();private,=self.executor.webauthn_calls
        self.assertEqual((private['mode'],private['parent_mode']),(0o600,0o700));self.assertFalse(Path(private['path']).exists())
        public=json.dumps(report)+''.join(p.read_text() for p in self.out.rglob('*') if p.is_file())
        for person in private['input']['policy_input']['form_input']['identities']:self.assertNotIn(person['password'],public)
        for canary in ('PRIVATE_CANARY_ASSERTION','PRIVATE_KEY_CANARY_W22','PRIVATE_CHALLENGE_W22','PRIVATE_USER_HANDLE_W22'):
            self.assertNotIn(canary,public)
        for call in self.executor.browser_calls:
            self.assertNotIn('EXAMPLE_KC_CLIENT_SECRET',call['env'])
            if call['mode']=='a11y':self.assertNotIn('HELIX_RUNTIME_WEBAUTHN_INPUT',call['env'])
        self.assertFalse(self.runner.tmp.exists())

    def test_post_key_session_failure_stays_separate_from_initial_form_policy(self):
        self.setup_identity();self.executor.scenario={'postRolesMismatch':True};report=self.run_pipeline()
        view=execution.project_webauthn_execution(report)
        self.assertEqual((view['outcome'],view['coverage_status']),('FAIL','INCOMPLETE'))
        self.assertEqual(report['identity_forms'][0]['form_status'],'PASS')
        self.assertEqual(report['identity_assessment']['status'],'PASS')
        self.assertNotEqual(report['status'],'PASS');runtime.validate_report(report)

    def test_unknown_device_cleanup_cannot_complete(self):
        self.setup_identity();self.executor.scenario={'removeFailure':True};report=self.run_pipeline()
        view=execution.project_webauthn_execution(report)
        self.assertEqual(view['coverage_status'],'INCOMPLETE');self.assertEqual(view['counts']['completed_flows'],0)
        self.assertEqual(report['webauthn_executions'][0]['cleanup']['authenticator'],'unknown')
        self.assertNotEqual(report['status'],'PASS');runtime.validate_report(report)

    def test_truncated_final_recovers_bound_checkpoint_without_completing_measurement(self):
        self.setup_identity();self.executor.truncate_final=True;report=self.run_pipeline()
        self.assertEqual(execution.project_webauthn_execution(report)['outcome'],'PASS')
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'BLOCKED')
        self.assertNotEqual(report['status'],'PASS');runtime.validate_report(report)

    def test_foreign_attempt_cannot_replace_current_artifact(self):
        self.setup_identity();report=self.run_pipeline();suite=report['webauthn_executions'][0]
        path=self.out/'logs'/(suite['binding']['webauthn_attempt_id']+'.json');before=path.read_bytes()
        for key,value in [('webauthn_attempt_id','webauthn-'+'f'*32),('policy_attempt_id','policy-'+'f'*32),('part','other')]:
            bad=copy.deepcopy(suite);bad['binding'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.runner.record_webauthn({'path':'frontend'},bad)
            self.assertEqual(path.read_bytes(),before)

    def test_import_retains_plan_and_independent_execution_projection(self):
        self.setup_identity();report=self.run_pipeline();maturity=helix_pro.assess(self.project,'XL')
        runtime.import_evidence(maturity,self.out/'runtime-report.json',self.project)
        self.assertEqual(maturity['runtime_webauthn']['execution_status'],'NOT_RUN')
        self.assertEqual(maturity['runtime_webauthn_execution']['outcome'],'PASS')
        self.assertFalse(any(v.startswith('runtime-webauthn:') for v in maturity['blocking']))
        self.assertTrue(any(v.startswith('runtime-integrations:') for v in maturity['blocking']))


if __name__=='__main__':unittest.main()
