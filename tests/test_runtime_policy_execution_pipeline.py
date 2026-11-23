"""Real Runner and browser entrypoint, fake Playwright only; no services."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_config
import helix_runtime as runtime
import test_runtime_keycloak_login_pipeline as login_fixture
import test_runtime_identity_policy as plan_fixture


def policy_playwright_module(wrapper,scenario):
    fixture=ROOT/'tests/fixtures/runtime-policy-fake.cjs'
    return """const fs=require('fs'),Module=require('module'),load=Module._load;
Module._load=function(id,...args){if(/^(?:node:)?(?:http|https|net|tls|dns|child_process)$/.test(id))throw Error('forbidden external I/O');return load.call(this,id,...args);};
global.fetch=()=>{throw Error('forbidden network');};
const {createBrowserFixture}=require(__FIXTURE__);
const scenario=__SCENARIO__,fixture=createBrowserFixture({input:__WRAPPER__,scenario});let pages=0;
exports.chromium={launch:async options=>{
 if(options.ignoreHTTPSErrors)throw Error('global TLS disabled');
 return {newContext:async options=>{const ctx=await fixture.browser.newContext(options),newPage=ctx.newPage;
  ctx.newPage=async()=>{const page=await newPage(),close=page.close,index=++pages;page.close=async()=>{await close();if(scenario.pageCloseFailure===index)throw Error('synthetic page close failure');};return Object.assign(page,{addScriptTag:async()=>{},evaluate:async()=>({violations:[]})});};return ctx;},
  close:async()=>fs.writeFileSync(process.env.LOGIN_FIXTURE_RECORDS,JSON.stringify({events:fixture.events,counters:fixture.counters}))};
}};
""".replace('__FIXTURE__',json.dumps(str(fixture))).replace('__WRAPPER__',json.dumps(wrapper)).replace('__SCENARIO__',json.dumps(scenario))


class PolicyExecutor(login_fixture.LoginExecutor):
    def __init__(self):
        super().__init__();self.latest_policy=None;self.policy_calls=[];self.scenario={}
    def run(self,argv,cwd,env,timeout):
        if len(argv)>1 and str(argv[1]).endswith('runtime-browser.cjs'):
            if env.get('HELIX_RUNTIME_POLICY_INPUT'):
                path=Path(env['HELIX_RUNTIME_POLICY_INPUT']);self.latest_policy=json.loads(path.read_text())
                self.policy_calls.append(dict(input=copy.deepcopy(self.latest_policy),path=str(path),mode=path.stat().st_mode&0o777,parent_mode=path.parent.stat().st_mode&0o777))
            if self.latest_policy is not None:
                with patch.object(login_fixture,'fake_playwright_module',side_effect=lambda:policy_playwright_module(self.latest_policy,self.scenario)):
                    return super().run(argv,cwd,env,timeout)
        return super().run(argv,cwd,env,timeout)


class RuntimePolicyExecutionPipeline(unittest.TestCase):
    app=login_fixture.RuntimeIdentityRunnerWiring.app
    snapshot=login_fixture.RuntimeIdentityRunnerWiring.snapshot
    application=login_fixture.RuntimeIdentityRunnerWiring.application
    setup_identity=login_fixture.RuntimeIdentityRunnerWiring.setup_identity
    run_pipeline=login_fixture.RuntimeIdentityRunnerWiring.run_pipeline

    def setUp(self):
        login_fixture.RuntimeIdentityRunnerWiring.setUp(self)
        self.executor=PolicyExecutor()
        fixture=plan_fixture.RuntimeIdentityPolicy();fixture.setUp()
        self.raw=fixture.raw;self.raw['session']['assertions'][0]['pointer']='/user/username'
        cell=fixture.cell('editor','editor-denied');cell['expected']={'access':'deny','denial':{'kind':'status','codes':[403]}}
        self.raw['cells'].append(cell)

    def configure(self):
        cfg=login_fixture.RuntimeIdentityRunnerWiring.configure(self)
        cfg['runtime']['identity_policy']={'schema_version':1,'parts':{'frontend':self.raw}}
        self.config_path.write_text(json.dumps(cfg));helix_config.configure(self.project,self.config_path)
        return cfg

    def test_real_entrypoint_preserves_form_and_records_bound_selected_matrix(self):
        from helix_runtime_identity_policy_run import project_policy_execution
        self.setup_identity();before=self.snapshot();report=self.run_pipeline()
        suite,=report['identity_policy_executions'];private,=self.executor.policy_calls
        self.assertEqual(suite['binding'],private['input']['binding'])
        self.assertEqual(suite['binding']['form_attempt_id'],report['identity_forms'][0]['binding']['attempt_id'])
        self.assertTrue(all(c['result']=='PASS' for c in suite['cells']))
        self.assertTrue(all(r['session']['identity_matched'] and r['session']['roles_matched'] for r in suite['identities']))
        self.assertEqual(report['identity_forms'][0]['form_status'],'PASS')
        self.assertEqual(report['identity_forms'][0]['session_coverage'],'NOT_RUN')
        self.assertEqual(report['identity_assessment']['status'],'PASS')
        self.assertEqual(project_policy_execution(report)['coverage_status'],'RECORDED')
        self.assertNotEqual(report['status'],'PASS') # Integration readiness remains incomplete.
        self.assertEqual(report['integration_receipts'][0]['tested_routes'],[])
        self.assertEqual(before,self.snapshot());runtime.validate_report(report)
        self.assertFalse(self.runner.tmp.exists());self.assertTrue(self.executor.identity.removed)
        records=[]
        for path in self.out.glob('logs/browser-*-e2e.jsonl'):
            records.extend(json.loads(line) for line in path.read_text().splitlines())
        forms={}
        for record in records:
            if record.get('type')=='identity-form-suite':
                forms={row['identity_id']:row for row in record['identities']}
            if record.get('type')=='identity-policy-suite':
                for cell in record['cells']:
                    if cell['result']=='PASS':
                        self.assertEqual(forms[cell['identity_id']]['form_status'],'PASS')
                        self.assertEqual(forms[cell['identity_id']]['cleanup'],'closed')

    def test_private_wrapper_is_0600_deleted_and_never_published(self):
        self.setup_identity();report=self.run_pipeline();private,=self.executor.policy_calls
        self.assertEqual((private['mode'],private['parent_mode']),(0o600,0o700))
        self.assertFalse(Path(private['path']).exists())
        self.assertNotIn('client_secret',json.dumps(private['input']))
        public=json.dumps(report)+''.join(p.read_text() for p in self.out.rglob('*') if p.is_file())
        for identity in private['input']['form_input']['identities']:self.assertNotIn(identity['password'],public)
        for value in ('PRIVATE_CANARY_ASSERTION','AUTH_CODE_CANARY_POLICY','STATE_CANARY_POLICY','SESSION_CODE_CANARY_POLICY'):
            self.assertNotIn(value,public)
        for call in self.executor.browser_calls:
            self.assertNotIn('EXAMPLE_KC_CLIENT_SECRET',call['env'])
            if call['mode']=='a11y':self.assertNotIn('HELIX_RUNTIME_POLICY_INPUT',call['env'])
        self.assertFalse(any(p.name.endswith('.session') for p in self.out.rglob('*')))

    def test_session_mismatch_does_not_erase_form_pass_or_claim_route_execution(self):
        self.setup_identity();self.executor.scenario={'sessionMismatch':True};report=self.run_pipeline()
        self.assertEqual(report['identity_forms'][0]['form_status'],'PASS')
        self.assertEqual(report['identity_assessment']['outcome'],'FAIL')
        self.assertEqual(report['identity_assessment']['coverage_status'],'INCOMPLETE')
        self.assertTrue(all(c['access']['status']=='BLOCKED' for c in report['identity_policy_executions'][0]['cells']))
        self.assertNotEqual(report['status'],'PASS');runtime.validate_report(report)

    def test_cleanup_error_does_not_erase_performed_session_failure(self):
        self.setup_identity();self.executor.scenario={'sessionMismatch':True,'pageCloseFailure':4};report=self.run_pipeline()
        suite,=report['identity_policy_executions']
        self.assertTrue(any(row['session']['status']=='FAIL' for row in suite['identities']))
        self.assertEqual(report['identity_assessment']['outcome'],'FAIL')
        self.assertEqual(report['identity_assessment']['coverage_status'],'INCOMPLETE')
        self.assertNotEqual(report['status'],'PASS');runtime.validate_report(report)

    def test_partial_final_keeps_journal_policy_without_completed_measurement(self):
        self.setup_identity();self.executor.truncate_final=True;report=self.run_pipeline()
        self.assertTrue(all(c['result']=='PASS' for c in report['identity_policy_executions'][0]['cells']))
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'BLOCKED')
        self.assertNotEqual(report['status'],'PASS');runtime.validate_report(report)

    def test_failed_browser_keeps_empty_execution_and_removes_private_wrapper(self):
        self.setup_identity();self.executor.browser_failure=True;report=self.run_pipeline()
        self.assertEqual(report['identity_policy_executions'],[])
        self.assertEqual(report['identity_assessment']['coverage_status'],'INCOMPLETE')
        self.assertFalse(Path(self.executor.policy_calls[0]['path']).exists())
        self.assertTrue(self.executor.identity.removed);self.assertFalse(self.runner.tmp.exists())

    def test_changed_attempt_cannot_replace_current_policy_artifact(self):
        self.setup_identity();report=self.run_pipeline();suite=report['identity_policy_executions'][0]
        path=self.out/'logs'/(suite['binding']['policy_attempt_id']+'.json');before=path.read_bytes()
        for key,value in [('policy_attempt_id','policy-'+'f'*32),('form_attempt_id','login-'+'f'*32),('policy_hash','f'*64),('policy_plan_id','f'*64),('run_id','runtime-forged'),('part','other')]:
            forged=copy.deepcopy(suite);forged['binding'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.runner.record_identity_policy({'path':'frontend'},forged)
            self.assertEqual(path.read_bytes(),before)

    def test_current_part_policy_record_does_not_include_previous_part_form(self):
        self.setup_identity();report=self.run_pipeline()
        prior=copy.deepcopy(report['identity_forms'][0]);prior['binding']['part']='previous-app'
        self.runner.identity_forms['previous-app']=prior
        # The previous part's independently recorded suite is not part of this
        # single-part receipt validation. Its own final report validates it.
        path=self.runner.record_identity_policy({'path':'frontend'},report['identity_policy_executions'][0])
        self.assertTrue((self.out/path).is_file())
        self.assertEqual(self.runner.identity_forms['previous-app'],prior)


if __name__=='__main__':unittest.main()
