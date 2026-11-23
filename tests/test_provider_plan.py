"""Provider probing/planning is exercised with fake callers, never the network."""
import argparse
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
import helix_provider_plan as routing


def inventory(*pairs, age=0):
    checked = (datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat()
    return dict(schema_version=1, checked_at=checked, status='complete', models=[
        dict(provider=p, model=m, family=routing.family(p), status='available', method='short_call', checked_at=checked)
        for p,m in pairs])


def config():
    return dict(providers=dict(planner='codex', implementer='codex', fallback='codex',
                              reviewers=[dict(name='A',provider='codex'),dict(name='B',provider='gemini')]),
                models={'codex':['code-model'], 'gemini':['big-model','fast-model'],
                        'claude-via-agy':['reason-model'], 'grok-cli':['verify-model']},
                data_egress={'status':'approved','allowed_providers':list(routing.FAMILIES),'exclude_paths':[]},
                limits={'provider_timeout_s':30, 'max_review_rounds':2})


def load_helix():
    loader = importlib.machinery.SourceFileLoader('provider_plan_helix_test',str(ROOT/'bin/helix'))
    spec = importlib.util.spec_from_loader(loader.name,loader)
    module = importlib.util.module_from_spec(spec)
    import helix_ux, helix_consistency, helix_security_deep
    old = helix_ux.H,helix_consistency.H,helix_security_deep.H
    with patch.dict(sys.modules,{loader.name:module}): loader.exec_module(module)
    helix_ux.H,helix_consistency.H,helix_security_deep.H = old
    return module


class ProviderPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.cfg=config()
        self.ctx=SimpleNamespace(cfg=self.cfg,state_dir=self.root,repo=self.root,offline=False,explicit_cfg={})

    def test_refresh_calls_every_actual_model_and_persists_each(self):
        called=[]; path=self.root/'provider-availability.json'
        def caller(ctx,model,prompt,images,schema,write,out,timeout):
            saved=json.loads(path.read_text())
            self.assertEqual(len(saved['models']),len(called))
            self.assertFalse(write); self.assertLessEqual(timeout,30)
            called.append(model)
            (out/'raw.json').write_text('private output must be removed')
            if model=='fast-model': raise ValueError('model unavailable token=TOP_SECRET')
            return '{"ok": true}'
        callers={p:caller for p in self.cfg['models']}
        result=routing.refresh(self.ctx,callers,path,jobs=1)
        self.assertEqual(called,['code-model','big-model','fast-model','reason-model','verify-model'])
        self.assertEqual(result['status'],'complete')
        self.assertFalse(list(self.root.glob('provider-probe-*')))
        self.assertNotIn('TOP_SECRET',path.read_text())
        self.assertFalse(routing.model_available(result,'gemini','fast-model'))
        self.assertTrue(routing.model_available(result,'claude-via-agy','reason-model'))
        self.assertTrue(all(r['checked_at'] for r in result['models']))

    def test_probe_rejects_catalog_or_login_only_and_invalid_answer(self):
        avail=inventory(('codex','code-model'))
        avail['models'][0]['method']='login_status'
        self.assertFalse(routing.model_available(avail,'codex','code-model'))
        self.assertFalse(routing.model_available(inventory(('codex','code-model'),age=1900),'codex','code-model'))
        self.assertFalse(routing.model_available(inventory(('codex','code-model')),'codex','other-model'))
        self.ctx.cfg=dict(providers={},models={'codex':['code-model']})
        result=routing.refresh(self.ctx,{'codex':lambda *args:'{"ok": false}'},self.root/'probe.json')
        self.assertEqual(result['models'][0]['status'],'unavailable')
        self.assertIn('JSON',result['models'][0]['reason'])

    def test_unknown_manual_or_malformed_availability_never_becomes_ready(self):
        for provider in ('unknown-provider','grok'):
            with self.subTest(provider=provider):
                self.assertFalse(routing.model_available(inventory((provider,'model')),provider,'model'))
        for records in (None,False,42,{},'not-receipts',[None,{}]):
            with self.subTest(records=records):
                self.assertFalse(routing.model_available({'models':records},'codex','code-model'))
        for model in ([],{},False,''):
            with self.subTest(model=model):
                self.assertFalse(routing.model_available(inventory(('codex',model)),'codex',model))
        self.assertIn('claude',routing.JSON_PROVIDERS)
        self.assertIn('claude-via-agy',routing.JSON_PROVIDERS)
        self.assertNotIn('grok',routing.JSON_PROVIDERS)

    def test_ambiguous_or_future_receipts_do_not_reuse_a_positive_probe(self):
        available=inventory(('codex','code-model'))
        duplicate=dict(available['models'][0],status='unavailable')
        available['models'].append(duplicate)
        self.assertFalse(routing.model_available(available,'codex','code-model'))
        self.assertFalse(routing.model_available(inventory(('codex','code-model'),age=-60),'codex','code-model'))
        available=inventory(('codex','code-model'))
        available['models'][0]['family']='anthropic'
        self.assertFalse(routing.model_available(available,'codex','code-model'))

    def test_agy_alias_cannot_hide_another_known_model_family(self):
        self.cfg['models']['gemini']=['claude-opus-synthetic']
        self.cfg['models']['claude-via-agy']=['claude-opus-synthetic']
        explicit={'providers':{'hunter':'claude-via-agy','verifier':'gemini'},
                  'models':copy.deepcopy(self.cfg['models'])}
        before=copy.deepcopy(self.cfg)
        available=inventory(('claude-via-agy','claude-opus-synthetic'),('gemini','claude-opus-synthetic'))
        plan=routing.plan(self.cfg,available,explicit)
        self.assertEqual(plan['roles']['verifier']['provider'],'gemini')
        self.assertEqual(plan['roles']['verifier']['model'],'claude-opus-synthetic')
        self.assertEqual(plan['roles']['verifier']['status'],'model_conflict')
        self.assertEqual(plan['roles']['verifier']['family'],'anthropic')
        self.assertFalse(plan['independent_verifier']);self.assertEqual(plan['status'],'LIMITED')
        self.assertFalse(routing.model_available(available,'gemini','claude-opus-synthetic'))
        self.assertFalse(routing.compatible_model('gemini','claude-opus-synthetic'))
        self.assertEqual(self.cfg,before)
        self.assertTrue(plan['proposals'])

    def test_probe_records_json_success_separately_from_conflicting_family(self):
        self.ctx.cfg=dict(providers={},models={'gemini':['claude-opus-synthetic'],'claude-via-agy':['claude-opus-synthetic']})
        called=[]
        def caller(ctx,model,*args):called.append(model);return '{"ok":true}'
        data=routing.refresh(self.ctx,dict(gemini=caller,**{'claude-via-agy':caller}),self.root/'brand-probe.json')
        self.assertEqual(len(called),2)
        self.assertEqual([r['status'] for r in data['models']],['model_conflict','available'])
        self.assertTrue(all(r['json_response'] and r['family']=='anthropic' for r in data['models']))

    def test_agy_default_family_is_unknown_but_native_default_transport_is_known(self):
        self.ctx.cfg=dict(providers={},models={p:[None] for p in routing.JSON_PROVIDERS})
        data=routing.refresh(self.ctx,{p:lambda *args:'{"ok":true}' for p in routing.JSON_PROVIDERS},self.root/'defaults-probe.json')
        for provider in routing.JSON_PROVIDERS:
            with self.subTest(provider=provider):
                record=routing.model_record(data,provider,None)
                if provider in routing.AGY_PROVIDERS:
                    self.assertIsNone(routing.model_family(provider,None))
                    self.assertFalse(routing.compatible_model(provider,None))
                    self.assertEqual(record['status'],'unknown_family')
                    self.assertFalse(routing.model_available(data,provider,None))
                else:
                    self.assertEqual(routing.model_family(provider,None),routing.family(provider))
                    self.assertTrue(routing.model_available(data,provider,None))
        explicit={'providers':{'hunter':'codex','verifier':'gemini'}}
        planned=routing.plan(self.ctx.cfg,data,explicit)
        self.assertEqual(planned['roles']['verifier']['status'],'unknown_family')
        self.assertFalse(planned['independent_verifier'])

    def test_model_family_brand_guards_do_not_guess_opaque_identifiers(self):
        for model,family in [('claude-synthetic','anthropic'),('anthropic/claude-synthetic','anthropic'),
                             ('gemini-synthetic','google'),('grok-synthetic','xai'),('gpt-synthetic','openai')]:
            self.assertEqual(routing.model_family('gemini',model),family)
        for model in ('custom-reason-model','o99-opaque'):
            self.assertEqual(routing.model_family('gemini',model),'google')
            self.assertEqual(routing.model_family_basis('gemini',model),'provider_policy')
        planned=routing.plan(self.cfg,inventory(('codex','code-model'),('gemini','big-model')),{'providers':{'verifier':'gemini'}})
        self.assertEqual(planned['roles']['verifier']['family_basis'],'provider_policy')
        self.assertIn('ASSUMPTION',planned['roles']['verifier']['reason'])

    def test_successful_json_refreshes_only_the_exact_model_without_cache_write(self):
        initial=inventory(('codex','code-model'),('gemini','big-model'),age=1900)
        before=copy.deepcopy(initial)
        with patch.object(routing,'atomic_json') as write:
            observed=routing.record_success(initial,'codex','code-model')
        write.assert_not_called()
        self.assertEqual(initial,before)
        self.assertTrue(routing.model_available(observed,'codex','code-model'))
        self.assertFalse(routing.model_available(observed,'gemini','big-model'))
        self.assertFalse(routing.model_available(observed,'codex','different-model'))
        receipt=routing.model_record(observed,'codex','code-model')
        self.assertEqual(receipt['method'],'model_response')
        self.assertEqual(receipt['scope'],'current_run')
        conflicting=routing.record_success(observed,'gemini','claude-opus-synthetic')
        self.assertFalse(routing.model_available(conflicting,'gemini','claude-opus-synthetic'))
        unknown=routing.record_success(observed,'gemini',None)
        self.assertFalse(routing.model_available(unknown,'gemini',None))
        with self.assertRaises(ValueError):routing.record_success(observed,'unknown','model')

    def test_plan_uses_alias_families_and_prefers_available_strong_model(self):
        avail=inventory(('codex','code-model'),('gemini','big-model'),('gemini','fast-model'),('claude-via-agy','reason-model'),('grok-cli','verify-model'))
        before=copy.deepcopy(self.cfg)
        plan=routing.plan(self.cfg,avail,{})
        self.assertEqual(plan['status'],'READY')
        self.assertEqual(plan['roles']['implementer']['provider'],'codex')
        self.assertEqual(plan['roles']['planner']['provider'],'claude-via-agy')
        self.assertEqual(plan['roles']['visual_judge']['model'],'big-model')
        self.assertTrue(plan['independent_verifier']); self.assertTrue(plan['independent_review'])
        self.assertEqual(self.cfg,before)
        self.assertEqual(routing.independent_providers('claude',['claude-via-agy','gemini','grok-cli']),['gemini','grok-cli'])
        self.assertEqual(routing.family('gemini-flash'),routing.family('gemini'))
        self.assertEqual(routing.family('grok'),routing.family('grok-cli'))

    def test_two_families_allow_two_separate_review_contexts(self):
        plan=routing.plan(self.cfg,inventory(('codex','code-model'),('gemini','big-model')),{})
        self.assertEqual(plan['status'],'READY')
        self.assertEqual([r['family'] for r in plan['roles']['reviewers']],['google','google'])
        self.assertEqual(len({r['name'] for r in plan['roles']['reviewers']}),2)
        self.assertIn('świeży kontekst',plan['roles']['reviewers'][1]['reason'])

    def test_single_family_or_no_probe_is_limited(self):
        for available in ({},inventory(('gemini','big-model')),inventory(('codex','code-model'))):
            with self.subTest(available=available):
                plan=routing.plan(self.cfg,available,{})
                self.assertEqual(plan['status'],'LIMITED')
                self.assertFalse(plan['independent_verifier']); self.assertFalse(plan['independent_review'])

    def test_explicit_unavailable_provider_and_model_preserved_with_proposal(self):
        avail=inventory(('codex','code-model'),('gemini','fast-model'))
        explicit={'providers':{'implementer':'gemini'},'models':{'gemini':['big-model','fast-model']}}
        before=copy.deepcopy(explicit)
        plan=routing.plan(self.cfg,avail,explicit)
        chosen=plan['roles']['implementer']
        self.assertEqual((chosen['provider'],chosen['model'],chosen['status']),('gemini','big-model','unavailable'))
        self.assertTrue(chosen['explicit']); self.assertTrue(plan['proposals'])
        self.assertEqual(explicit,before)
        self.assertIn({'provider':'gemini','model':'fast-model','family':'google'},plan['proposals'][0]['alternatives'])

    def test_explicit_same_family_verifier_cannot_be_independent(self):
        cfg=config();cfg['models']['claude']=['native-model']
        explicit={'providers':{'hunter':'claude','verifier':'claude-via-agy'}}
        plan=routing.plan(cfg,inventory(('claude','native-model'),('claude-via-agy','reason-model')),explicit)
        self.assertEqual(plan['roles']['verifier']['provider'],'claude-via-agy')
        self.assertEqual(plan['roles']['verifier']['status'],'not_independent')
        self.assertFalse(plan['independent_verifier'])

    def test_invalid_configuration_is_reported_as_value_error(self):
        for changed in ({'models':[]},{'models':{'codex':[]}}, {'providers':{'reviewers':'gemini'}}, {'providers':{'reviewers':[None]}}, {'providers':{'implementer':42}}, {'providers':{'implementer':{'provider':'codex'}}}, {'providers':{'reviewers':[dict(provider='gemini', model=[])]}}, {'providers':{'reviewers':[dict(provider='gemini', name='../bad')]}}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                routing.plan(dict(self.cfg,**changed),{},changed)

    def test_ask_does_not_fallback_from_explicit_model(self):
        H=load_helix(); self.ctx.explicit_cfg={'providers':{'planner':'gemini'},'models':{'gemini':['big-model','fast-model']}}
        routing.atomic_json(self.root/'provider-availability.json',inventory(('gemini','big-model'),('gemini','fast-model'),('codex','code-model')))
        calls=[]
        def failing(ctx,model,*args): calls.append(model); raise H.ProviderError('quota token=TOP_SECRET')
        with patch.dict(H.CALLERS,{'gemini':failing,'codex':lambda *args:'{"ok":true}'}),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(H.ProviderError) as error:
            H.ask(self.ctx,'gemini','task',need_json=True)
        self.assertEqual(calls,['big-model'])
        self.assertIn('Jawna konfiguracja zachowana',str(error.exception))
        self.assertNotIn('TOP_SECRET',str(error.exception))

    def test_probe_does_not_probe_a_different_agy_model(self):
        H=load_helix();routing.atomic_json(self.root/'provider-availability.json',inventory(('gemini','big-model')))
        self.assertTrue(H.probe('gemini',ctx=self.ctx,model='big-model')[0])
        self.assertFalse(H.probe('claude-via-agy',ctx=self.ctx,model='reason-model')[0])
        self.assertFalse(H.probe('gemini',ctx=self.ctx,model='fast-model')[0])

    def test_providers_plan_requires_no_calls(self):
        H=load_helix(); routing.atomic_json(self.root/'provider-availability.json',inventory(('codex','code-model')))
        with patch.object(routing,'refresh') as refresh,contextlib.redirect_stdout(io.StringIO()) as output:
            H.cmd_providers(self.ctx,argparse.Namespace(refresh=False,plan=True))
        refresh.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['status'],'LIMITED')
        self.assertTrue((self.root/'role-plan.json').is_file())

    def test_review_same_author_family_is_limited_before_models(self):
        H=load_helix()
        self.ctx.cfg['providers']['reviewers']=[dict(name='A',provider='claude'),dict(name='B',provider='claude-via-agy')]
        self.ctx.cfg['providers']['implementer']='claude'
        self.ctx.ev=lambda _:self.root; self.ctx.cp=lambda _:dict(id='cp1',title='Change',goal='Change',test_cases=[])
        self.ctx.state=lambda _:dict(base='HEAD')
        with patch.object(H.helix_workflow,'check_connections',return_value=True),patch.object(H.helix_workflow,'precheck',return_value={'pass':True}),patch.object(H,'ask') as ask:
            result=H.gate_review(self.ctx,'cp1')
        ask.assert_not_called(); self.assertFalse(result['pass']); self.assertEqual(result['status'],'LIMITED')

    def test_review_fallback_to_author_family_never_passes(self):
        H=load_helix();self.ctx.cfg['providers']['implementer']='codex'
        self.ctx.cfg['providers']['reviewers']=[dict(name='A',provider='gemini'),dict(name='B',provider='gemini')]
        self.ctx.ev=lambda _:self.root; self.ctx.cp=lambda _:dict(id='cp1',title='Change',goal='Change',test_cases=[])
        self.ctx.state=lambda _:dict(base='HEAD'); self.ctx.architecture=lambda:'local'
        with patch.object(H.helix_workflow,'check_connections',return_value=True),patch.object(H.helix_workflow,'precheck',return_value={'pass':True}),patch.object(H.helix_workflow,'matching_rules',return_value=[]),patch.object(H.helix_workflow,'diff_files',return_value=[]),patch.object(H,'diff_since',return_value='synthetic diff'),patch.object(H,'ask',return_value=('{"verdict":"approve","findings":[]}',{'provider':'codex','model':'code-model'})),contextlib.redirect_stdout(io.StringIO()):
            result=H.gate_review(self.ctx,'cp1')
        self.assertFalse(result['pass']); self.assertEqual(result['status'],'LIMITED')

    def test_explicit_reviewer_model_is_probed_and_used(self):
        H=load_helix()
        choice=dict(provider='gemini',model='special-review-model')
        self.cfg['providers']['reviewers']=[choice]
        self.ctx.explicit_cfg={'providers':{'reviewers':[choice]}}
        self.assertIn(('gemini','special-review-model'),routing.configured_models(self.cfg))
        availability=inventory(('gemini','special-review-model'),('gemini','big-model'))
        role_plan=routing.plan(self.cfg,availability,self.ctx.explicit_cfg)
        effective=routing.apply_plan(self.cfg,role_plan,self.ctx.explicit_cfg)
        self.assertEqual(effective['providers']['reviewers'][0]['name'],'reviewer-1')
        self.assertNotIn('name',self.ctx.explicit_cfg['providers']['reviewers'][0])
        routing.atomic_json(self.root/'provider-availability.json',availability)
        calls=[]
        def answer(ctx,model,*args): calls.append(model); return '{"verdict":"approve","findings":[]}'
        with patch.dict(H.CALLERS,{'gemini':answer}):
            text,used=H.ask(self.ctx,'gemini','task',need_json=True,model='special-review-model')
        self.assertEqual(calls,['special-review-model'])
        self.assertEqual(used['model'],'special-review-model')

    def test_offline_review_never_uses_manual_handoff(self):
        H=load_helix();self.ctx.offline=True
        self.ctx.cfg['providers']['reviewers']=[dict(name='A',provider='grok'),dict(name='B',provider='gemini')]
        self.ctx.ev=lambda _:self.root; self.ctx.cp=lambda _:dict(id='cp1',title='Change',goal='Change',test_cases=[])
        self.ctx.state=lambda _:dict(base='HEAD')
        with patch.object(H.helix_workflow,'check_connections',return_value=True),patch.object(H.helix_workflow,'precheck',return_value={'pass':True}),patch.object(H,'call_grok') as handoff,patch.object(H,'ask') as ask:
            result=H.gate_review(self.ctx,'cp1')
        handoff.assert_not_called();ask.assert_not_called()
        self.assertEqual(result['status'],'LIMITED');self.assertFalse(result['pass'])

    def test_review_requires_valid_verdict_and_never_approves_blockers(self):
        H=load_helix();self.ctx.cfg['providers']['implementer']='codex'
        self.ctx.cfg['providers']['reviewers']=[dict(name='A',provider='gemini'),dict(name='B',provider='gemini')]
        self.ctx.ev=lambda _:self.root; self.ctx.cp=lambda _:dict(id='cp1',title='Change',goal='Change',test_cases=[])
        self.ctx.state=lambda _:dict(base='HEAD'); self.ctx.architecture=lambda:'local'
        finding=dict(severity='major',file='a.py',issue='Missing check',fix='Add check')
        examples=[({},False),([],False),({'verdict':'approve','findings':[]},False),
                  ({'verdict':'approve','findings':[finding],'summary':'Check'},False),
                  ({'verdict':'changes','findings':[],'summary':'Unresolved'},False),
                  ({'verdict':'changes','findings':[dict(finding,severity='nit')],'summary':'Style'},True),
                  ({'verdict':'approve','findings':[],'summary':'Reviewed'},True)]
        for answer,expected in examples:
            with self.subTest(answer=answer),patch.object(H.helix_workflow,'check_connections',return_value=True),patch.object(H.helix_workflow,'precheck',return_value={'pass':True}),patch.object(H.helix_workflow,'matching_rules',return_value=[]),patch.object(H.helix_workflow,'diff_files',return_value=[]),patch.object(H,'diff_since',return_value='synthetic diff'),patch.object(H,'ask',return_value=(json.dumps(answer),{'provider':'gemini','model':'big-model'})),contextlib.redirect_stdout(io.StringIO()):
                result=H.gate_review(self.ctx,'cp1')
            self.assertEqual(result['pass'],expected)


    def test_review_model_brand_cannot_fake_independence(self):
        H=load_helix()
        self.ctx.cfg['providers']['implementer']='claude'
        self.ctx.cfg['models']['claude']=['claude-author-synthetic']
        self.ctx.cfg['providers']['reviewers']=[dict(name='A',provider='gemini'),dict(name='B',provider='gemini')]
        self.ctx.ev=lambda _:self.root; self.ctx.cp=lambda _:dict(id='cp1',title='Change',goal='Change',test_cases=[])
        self.ctx.state=lambda _:dict(base='HEAD'); self.ctx.architecture=lambda:'local'
        # A substituted agy model is Anthropic even if its transport alias says Gemini.
        for model in ('claude-review-synthetic','default'):
            with self.subTest(model=model),patch.object(H.helix_workflow,'check_connections',return_value=True),patch.object(H.helix_workflow,'precheck',return_value={'pass':True}),patch.object(H.helix_workflow,'matching_rules',return_value=[]),patch.object(H.helix_workflow,'diff_files',return_value=[]),patch.object(H,'diff_since',return_value='synthetic diff'),patch.object(H,'ask',return_value=(' {"verdict":"approve","summary":"Reviewed","findings":[]}',{'provider':'gemini','model':model})),contextlib.redirect_stdout(io.StringIO()):
                result=H.gate_review(self.ctx,'cp1')
            self.assertFalse(result['pass']);self.assertEqual(result['status'],'LIMITED')
        self.ctx.cfg['models']['gemini']=['claude-review-synthetic']
        with patch.object(H.helix_workflow,'check_connections',return_value=True),patch.object(H.helix_workflow,'precheck',return_value={'pass':True}),patch.object(H,'ask') as ask:
            result=H.gate_review(self.ctx,'cp1')
        ask.assert_not_called();self.assertEqual(result['status'],'LIMITED')

    def test_actual_implementer_receipt_supersedes_the_current_plan(self):
        H=load_helix()
        self.ctx.cfg['providers']['implementer']='codex'
        self.ctx.cfg['providers']['reviewers']=[dict(name='A',provider='gemini'),dict(name='B',provider='gemini')]
        self.ctx.ev=lambda _:self.root; self.ctx.cp=lambda _:dict(id='cp1',title='Change',goal='Change',test_cases=[])
        self.ctx.state=lambda _:dict(base='HEAD',providers_used=[dict(role='implementer',provider='gemini',model='big-model')])
        with patch.object(H.helix_workflow,'check_connections',return_value=True),patch.object(H.helix_workflow,'precheck',return_value={'pass':True}),patch.object(H,'ask') as ask:
            result=H.gate_review(self.ctx,'cp1')
        ask.assert_not_called();self.assertFalse(result['pass']);self.assertEqual(result['implementer_family'],'google')

    def test_new_init_external_config_and_state_use_target_identity(self):
        import hashlib
        import helix_config, helix_new
        H=load_helix(); target=self.root/'target'; source=self.root/'outside.json'
        source.write_text('{}'); seen=[]
        with patch.object(helix_new,'dispatch',side_effect=lambda args: seen.append(args) or 0),patch.object(helix_config,'configure') as configure,patch.object(sys,'argv',['helix','new','init','--mode','greenfield','--profile','S','--risk','low','--dir',str(target),'--config',str(source),'--offline']):
            with self.assertRaises(SystemExit) as stop: H.main()
        self.assertEqual(stop.exception.code,0); configure.assert_called_once_with(str(target),str(source))
        identity=hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:16]
        self.assertEqual(seen[0].repo,str(target));self.assertEqual(Path(seen[0].state_dir),self.root/'.helix-state'/identity)
