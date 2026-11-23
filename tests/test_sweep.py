"""Behavioral regression cases for offline documentation, platform and decision gates."""
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
sys.path.insert(0, str(ROOT / 'tests'))
import helix_new as H
from helix_pro import assess, improvement_plan
from helix_platform import platform_check, decision_check, checkpoint_decision, explanation_check


class SweepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.program = H.load(ROOT / 'tests/fixtures/commerce-platform-xl.json')['program']

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def docs(self):
        values = {'README.md':'Install dependencies, then run application.','architecture.md':'Components and dependencies\n```mermaid\ngraph LR\nA --> B\n```','adr/ADR-001.md':'Alternatives, decision and consequences.','openapi.json':'{"openapi":"3.1.0","paths":{}}','data-model.md':'Entities and relations, migrations.','runbook.md':'Incident alert, on-call owner, recover and rollback.','CONTRIBUTING.md':'Setup environment, test changes, review pull request.','CHANGELOG.md':'0.4.0 Added release documentation.','user-guide.md':'User tasks and usage, support and troubleshooting.','admin-guide.md':'Admin tasks and usage, support and troubleshooting.'}
        for name, text in values.items(): self.write(name, text)
        from datetime import datetime, timezone
        self.write('docs-metadata.json', json.dumps({'documents': [dict(path=name, owner='Documentation owner', reviewed=datetime.now(timezone.utc).date().isoformat(), code=['app.py'] if (self.root/'app.py').exists() else []) for name in values]}))

    def test_documentation_complete_and_profile_targets(self):
        self.write('app.py', 'print(1)')
        self.docs()
        for profile, target in [('S',50),('M',70),('L',85),('XL',90)]:
            result = assess(self.root, profile)['areas']['documentation']
            self.assertEqual(result['score'], 100)
            self.assertEqual(result['target'], target)
            self.assertTrue(result['meets_target'])

    def test_documentation_absent_plan_has_remediation(self):
        report = assess(self.root)
        self.assertEqual(report['areas']['documentation']['score'], 0)
        plan = improvement_plan(report)
        self.assertTrue(any('docs-api' in cp['title'] for cp in plan['checkpoints']))

    def test_documentation_freshness_stale_and_no_code(self):
        self.docs()
        self.assertFalse(next(x for x in assess(self.root)['areas']['documentation']['requirements'] if x['id']=='docs-freshness')['satisfied'])
        code = self.write('app.py', 'print(1)')
        os.utime(code, ns=(10**18,10**18))
        for p in self.root.rglob('*.md'): os.utime(p, ns=(10**17,10**17))
        self.assertFalse(next(x for x in assess(self.root)['areas']['documentation']['requirements'] if x['id']=='docs-freshness')['satisfied'])

    def test_documentation_external_and_placeholder(self):
        with tempfile.TemporaryDirectory() as outside:
            p = Path(outside) / 'README.md'; p.write_text('Install and run the application.')
            result = assess(self.root, docs_paths=[outside])['areas']['documentation']['requirements']
            self.assertTrue(next(x for x in result if x['id']=='docs-quickstart')['satisfied'])
            p.write_text('TODO install and run')
            result = assess(self.root, docs_paths=[outside])['areas']['documentation']['requirements']
            self.assertFalse(next(x for x in result if x['id']=='docs-quickstart')['satisfied'])

    def test_platform_complete(self):
        self.assertEqual(platform_check(self.program), [])

    def test_platform_every_section_required(self):
        for key in self.program:
            with self.subTest(key=key):
                doc=copy.deepcopy(self.program); del doc[key]
                self.assertTrue(platform_check(doc))

    def test_platform_portfolio_capability_and_orphans(self):
        for mutate in [lambda d:d['products'].pop(),lambda d:d['capabilities'].pop(),lambda d:d['capabilities'][0].update(context='unknown'),lambda d:d['contexts'][0].update(team='unknown'),lambda d:d['teams'][0]['contexts'].append('payments')]:
            doc=copy.deepcopy(self.program); mutate(doc)
            self.assertTrue(platform_check(doc))

    def test_platform_roadmap_cycles_owners_and_contracts(self):
        for mutate in [lambda d:d['milestones'][0]['depends_on'].append(d['milestones'][1]['id']),lambda d:d['milestones'][0].update(owner=''),lambda d:d['milestones'][1].update(dependency_contracts=[]),lambda d:d['milestones'][0]['depends_on'].append('absent')]:
            doc=copy.deepcopy(self.program); mutate(doc)
            self.assertTrue(platform_check(doc))

    def test_platform_flag_and_xl_cli_init(self):
        for profile, flag in [('XL',[]),('S',['--platform'])]:
            target=self.root/profile
            result=subprocess.run([sys.executable,str(ROOT/'bin/helix'),'new','init','--dir',str(target),'--mode','greenfield','--profile',profile,'--risk','low','--write','--no-probe',*flag],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout)
            self.assertTrue((target/'platform-program.json').is_file())
            H.dump(target/'platform-program.json', self.program)
            result=subprocess.run([sys.executable,str(ROOT/'bin/helix'),'new','check','--dir',str(target)],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)  # Unapproved remainder must still fail.

    def test_xl_full_handoff_then_missing_contract_fails(self):
        from test_new import NewTests
        fixture=NewTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        fixture.ready('XL')
        self.assertEqual(H.check(fixture.project),[])
        for key in self.program:
            doc=copy.deepcopy(self.program); del doc[key]
            H.dump(fixture.project/'platform-program.json',doc); fixture.refresh()
            self.assertTrue(H.check(fixture.project),key)

    def decision(self):
        return dict(status='approved', accepted_by='Design owner', accepted_at='2026-10-25T12:00:00Z',selected='a',alternatives=[dict(id='a',approach='Modular service',benefits='Simple operations',trade_offs='Shared releases'),dict(id='b',approach='Separate services',benefits='Independent releases',trade_offs='Distributed consistency')])

    def test_decision_requires_approval_alternatives_and_tradeoffs(self):
        self.assertEqual(decision_check(self.decision()),[])
        for mutate in [lambda d:d.update(status='draft'),lambda d:d.update(accepted_by=''),lambda d:d.update(selected='unknown'),lambda d:d['alternatives'].pop(),lambda d:d['alternatives'][0].update(trade_offs='')]:
            doc=self.decision(); mutate(doc); self.assertTrue(decision_check(doc))
        self.assertTrue(checkpoint_decision(self.root,'cp1'))
        H.dump(self.root/'design-decisions/cp1.json',self.decision())
        self.assertEqual(checkpoint_decision(self.root,'cp1'),[])

    def test_checkpoint_blocks_before_git_or_implementer(self):
        loader=importlib.machinery.SourceFileLoader('sweep_helix',str(ROOT/'bin/helix'))
        spec=importlib.util.spec_from_loader(loader.name,loader); module=importlib.util.module_from_spec(spec); sys.modules[loader.name]=module; loader.exec_module(module)
        from types import SimpleNamespace
        ctx=SimpleNamespace(repo=self.root,cfg={'limits':{},'design_decision':{'required':True}},cp=lambda _: {'id':'cp1'},state=lambda _: {})
        with patch.object(module,'git') as git, patch.object(module,'ask') as ask:
            with self.assertRaises(SystemExit): module.cmd_run(ctx,SimpleNamespace(checkpoint='cp1'))
            git.assert_not_called(); ask.assert_not_called()

    def test_explanation_requires_meaningful_section(self):
        self.assertTrue(explanation_check('# Done\nTests pass'))
        self.assertTrue(explanation_check('## What changed and why\nTODO explain the changes in eight or more words'))
        self.assertEqual(explanation_check('## Co zmieniono i dlaczego\nDodano jawne kontrakty platformy aby sprawdzać kompletność zakresu przed rozpoczęciem implementacji.'),[])

    def test_brownfield_map_static_imports(self):
        self.write('src/app.py','from domain import orders\n')
        out=self.root.parent/(self.root.name+'-audit'); self.addCleanup(__import__('shutil').rmtree,out,True)
        H.audit(self.root,out,'S')
        result=H.load(out/'system-map.json')
        self.assertEqual(result['components'][0]['id'],'src/app.py')
        self.assertEqual(result['dependencies'][0]['target'],'domain')
        self.assertEqual(result['tag'],'ASSUMPTION')

    def test_top_contracts_empty_vs_populated(self):
        catalog=H.load(H.NEW/'profiles/pro-standard.json')
        for ident in ('privacy-contract','ai-eval-budget','license-inventory','observability-contract','incident-postmortem'):
            rule=next(x for x in catalog['requirements'] if x['id']==ident)
            name=rule['template'].replace('.tpl','')
            blank=H.load(H.NEW/'templates'/rule['template']); self.write(name,json.dumps(blank))
            def item(): return next(x for a in assess(self.root,'M')['areas'].values() for x in a['requirements'] if x['id']==ident)
            self.assertFalse(item()['satisfied'])
            from test_new import NewTests
            value = NewTests().fill(H.load(H.NEW/'schemas'/name))
            if ident == 'ai-eval-budget':
                value['cases'] = [dict(id=category,category=category,input='Synthetic adversarial input',expected='Scoped safe response') for category in ('injection','refusal','quality-pl','extraction')]
            self.write(name,json.dumps(value))
            self.assertTrue(item()['satisfied'])

    def test_platform_every_api_tenancy_identity_design_field_required(self):
        for section in ('api','tenancy','identity','design_system','adr'):
            for key in self.program[section]:
                with self.subTest(section=section,key=key):
                    doc=copy.deepcopy(self.program); del doc[section][key]
                    self.assertTrue(platform_check(doc))

    def test_platform_dependency_contract_must_match_edge(self):
        for mutate in (lambda d:d['milestones'][1]['dependency_contracts'][0].update(milestone='other'),lambda d:d['milestones'][1]['dependency_contracts'][0].update(status='draft')):
            doc=copy.deepcopy(self.program); mutate(doc)
            self.assertTrue(platform_check(doc))

    def test_decision_timestamp_and_distinct_approaches(self):
        for mutate in (lambda d:d.update(accepted_at='yesterday'),lambda d:d.update(accepted_at='2026-10-25T12:00:00'),lambda d:d['alternatives'][1].update(approach=d['alternatives'][0]['approach'])):
            doc=self.decision(); mutate(doc)
            self.assertTrue(decision_check(doc))

    def test_ai_evals_need_all_categories_and_numeric_budgets(self):
        from test_new import NewTests
        value=NewTests().fill(H.load(H.NEW/'schemas/ai-evals.json'))
        self.write('ai-evals.json',json.dumps(value))
        def satisfied():
            return next(x for x in assess(self.root,'M')['areas']['security']['requirements'] if x['id']=='ai-eval-budget')['satisfied']
        self.assertFalse(satisfied())
        value['cases']=[dict(id=k,category=k,input='Synthetic input',expected='Expected safe result') for k in ('injection','refusal','quality-pl','extraction')]
        value['max_tokens']='unbounded'
        self.write('ai-evals.json',json.dumps(value)); self.assertFalse(satisfied())
        value['max_tokens']=2048; value['max_retries']=0
        self.write('ai-evals.json',json.dumps(value)); self.assertTrue(satisfied())
