"""Regression coverage for all nine review blockers; offline neutral fixtures."""
import copy
from datetime import datetime, timezone
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
sys.path.insert(0, str(ROOT / 'tests'))
import helix_contracts as C
import helix_new as H
from helix_pro import assess
import test_fix12
import test_new


class ReviewRegression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, value):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value if isinstance(value, str) else json.dumps(value))
        return p

    def item(self, ident, **kwargs):
        return next(x for a in assess(self.root, **kwargs)['areas'].values() for x in a['requirements'] if x['id'] == ident)

    def metadata(self, reviewed=None, owner='Maintainer'):
        return {'documents': [dict(path='README.md', owner=owner, reviewed=reviewed or datetime.now(timezone.utc).date().isoformat(), code=['app.py'])]}

    def test_1_release_cli_templates_and_docs_agree(self):
        output = subprocess.run([sys.executable, str(ROOT/'bin/helix'), '--version'], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(output, 'helix ' + C.VERSION)
        self.assertEqual(C.VERSION, json.loads((ROOT/'helix.json').read_text())['helix_version'])
        self.assertEqual(H.load(H.NEW/'templates/helix.json.tpl')['helix_version'], C.VERSION)
        for name in ('README.md', 'README.pl.md'):
            self.assertIn('`'+C.VERSION+'`', (ROOT/name).read_text().splitlines()[4])

    def test_2_document_owner_and_date_required(self):
        self.write('app.py', 'print(1)')
        self.write('README.md', 'Install and run application.')
        self.assertFalse(self.item('docs-ownership')['satisfied'])
        for metadata in (self.metadata(owner=''), self.metadata('bad-date'), self.metadata('2999-01-01')):
            self.write('docs-metadata.json', metadata)
            self.assertFalse(self.item('docs-ownership')['satisfied'])
        self.write('docs-metadata.json', self.metadata())
        self.assertTrue(self.item('docs-ownership')['satisfied'])

    def test_2_html_does_not_hide_document_metadata_or_staleness(self):
        self.write('app.py', 'print(1)')
        self.write('README.md', 'Reviewed application guide.')
        self.write('docs-metadata.json', self.metadata())
        for content in ('Additional guide.', '<details>Additional guide.</details>',
                        '<!-- guide -->', '<https://example.test/guide>'):
            with self.subTest(content=content):
                doc = self.write('guide.md', content)
                self.assertFalse(self.item('docs-ownership')['satisfied'])
                for reviewed, owner in (('bad-date', 'Maintainer'),
                                        ('2999-01-01', 'Maintainer'),
                                        (datetime.now(timezone.utc).date().isoformat(), '')):
                    metadata = self.metadata()
                    metadata['documents'].append(dict(path='guide.md', owner=owner,
                                                     reviewed=reviewed, code=['app.py']))
                    self.write('docs-metadata.json', metadata)
                    self.assertFalse(self.item('docs-ownership')['satisfied'])
                metadata['documents'][1].update(owner='Maintainer',
                    reviewed=datetime.now(timezone.utc).date().isoformat())
                self.write('docs-metadata.json', metadata)
                self.assertTrue(self.item('docs-ownership')['satisfied'])
                self.assertTrue(self.item('docs-freshness')['satisfied'])
                os.utime(doc, ns=(10**17, 10**17))
                self.assertFalse(self.item('docs-freshness')['satisfied'])
                self.write('docs-metadata.json', self.metadata())

    def test_2_each_document_checked_new_unrelated_doc_cannot_hide_stale(self):
        code=self.write('app.py', 'print(1)')
        doc=self.write('README.md', 'Install and run application.')
        self.write('docs-metadata.json', self.metadata())
        self.assertTrue(self.item('docs-freshness')['satisfied'])
        os.utime(doc, ns=(10**17,10**17))
        self.write('unrelated.md', 'A recently reviewed note.')
        self.write('helix.json', {'docs_paths': []})
        report=assess(self.root)
        self.assertFalse(next(x for x in report['areas']['documentation']['requirements'] if x['id']=='docs-freshness')['satisfied'])
        self.assertTrue(any('stale' in x and 'README.md' in x and 'app.py' in x for x in report['warnings']))

    def test_2_external_non_markdown_cannot_count_as_fresh_doc(self):
        self.write('app.py', 'print(1)')
        with tempfile.TemporaryDirectory() as outside:
            Path(outside, 'recent.json').write_text('{"note":"recent"}')
            self.assertFalse(self.item('docs-freshness', docs_paths=[outside])['satisfied'])

    def test_2_external_metadata_and_stale_link(self):
        code=self.write('app.py','print(1)')
        with tempfile.TemporaryDirectory() as outside:
            doc=Path(outside,'README.md');doc.write_text('Install and run application.')
            metadata=self.metadata();metadata['documents'][0]['code']=[str(code)]
            Path(outside,'docs-metadata.json').write_text(json.dumps(metadata))
            self.assertTrue(self.item('docs-ownership', docs_paths=[outside])['satisfied'])
            os.utime(doc, ns=(10**17,10**17))
            result=self.item('docs-freshness', docs_paths=[outside])
            self.assertFalse(result['satisfied']);self.assertTrue(any('stale' in w for w in result['warnings']))

    def test_3_documentation_custom_gate(self):
        self.write('helix.json', {'custom_gates':[dict(name='docs-check', area='documentation', description='Review documentation', command='python check_docs.py')]})
        report=assess(self.root)
        item=next(x for x in report['areas']['documentation']['requirements'] if x['id']=='custom:docs-check')
        self.assertEqual(item['status'], 'needs-runtime')
        self.assertEqual(report['areas']['documentation']['score'],0)

    def test_4_external_populated_and_empty_contracts(self):
        for ident in ('observability-contract','incident-postmortem'):
            with self.subTest(ident=ident), tempfile.TemporaryDirectory() as outside:
                catalog=H.load(H.NEW/'profiles/pro-standard.json')
                rule=next(x for x in catalog['requirements'] if x['id']==ident)
                name=rule['template'].replace('.tpl','')
                file=Path(outside,name)
                value=test_new.NewTests().fill(H.load(H.NEW/'schemas'/name))
                file.write_text(json.dumps(value))
                self.assertTrue(self.item(ident, profile='M', docs_paths=[outside])['satisfied'])
                file.write_text(json.dumps(H.load(H.NEW/'templates'/rule['template'])))
                self.assertFalse(self.item(ident, profile='M', docs_paths=[outside])['satisfied'])

    def test_5_main_commands_reject_missing_or_wrong_pin_before_execution(self):
        for config in ({}, {'helix_version':'old'}):
            self.write('helix.json',config)
            for command in (['plan','Task'],['run','cp1'],['gate','truth','cp1'],['approve','cp1'],['truth','init','cp1']):
                result=subprocess.run([sys.executable,str(ROOT/'bin/helix'),'--repo',str(self.root),*command],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('version:',result.stderr)
            self.assertFalse((self.root/'.helix').exists())

    def test_5_new_check_pin_and_schema(self):
        fixture=test_new.NewTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.ready()
        self.assertEqual(H.check(fixture.project),[])
        p=fixture.project/'helix.json';config=H.load(p);config['helix_version']='old';H.dump(p,config);fixture.refresh()
        self.assertTrue(any('helix_version' in e or 'version:' in e for e in H.check(fixture.project)))

    def test_6_sections_cannot_pass_vacuously(self):
        fixture=test_fix12.Contracts();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.assertEqual(C.validate(fixture.root, fixture.data)['status'],'PASS')
        for section in fixture.data:
            data=copy.deepcopy(fixture.data);del data[section]
            self.assertEqual(C.validate(fixture.root,data)['status'],'FAIL',section)
        self.assertEqual(C.validate(fixture.root,{'helix_version':C.VERSION})['status'],'FAIL')

    def test_6_ui_inferred_without_optional_flag(self):
        fixture=test_fix12.Contracts();fixture.setUp();self.addCleanup(fixture.doCleanups)
        data=copy.deepcopy(fixture.data)
        for path in ('src/App.tsx:1','ui/panel.ts:8','src/style.css:1'):
            resolution=dict(conflict=path,choice='manual',reason='Retain both behaviors',reviewer='Reviewer')
            data['merge']=dict(conflicts=[path],resolutions=[resolution])
            self.assertTrue(any('UI before/after' in e for e in C.validate(fixture.root,data)['errors']))
            resolution.update(before='proof',after='proof')
            self.assertEqual(C.validate(fixture.root,data)['status'],'PASS')

    def test_6_new_domain_map_required_and_semantic_links(self):
        fixture=test_new.NewTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.ready()
        path=fixture.project/'domain-map.json'
        self.assertTrue(path.is_file())
        for kind in ('mechanisms','patterns','components','industries'):
            data=H.load(path);data[kind]={}
            H.dump(path,data);fixture.refresh()
            self.assertTrue(any('domain:' in e for e in H.check(fixture.project)))
            H.dump(path,dict(mechanisms={'M1':['P1']},patterns={'P1':['C1']},components={'C1':['I1']},industries={'I1':[]}));fixture.refresh()
        data=H.load(path);data['patterns']['P1']=['unknown'];H.dump(path,data);fixture.refresh()
        self.assertTrue(any('domain:' in e for e in H.check(fixture.project)))

    def test_7_design_gate_required_when_configuration_omitted(self):
        loader=importlib.machinery.SourceFileLoader('review_helix',str(ROOT/'bin/helix'))
        spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);sys.modules[loader.name]=module;loader.exec_module(module)
        ctx=SimpleNamespace(repo=self.root,cfg={'limits':{}},cp=lambda _: {'id':'cp1'},state=lambda _: {})
        with patch.object(module,'git') as git, patch.object(module,'ask') as ask:
            with self.assertRaises(SystemExit) as exc:module.cmd_run(ctx,SimpleNamespace(checkpoint='cp1'))
            self.assertIn('decision',str(exc.exception).lower())
            git.assert_not_called();ask.assert_not_called()
        self.assertTrue(H.load(ROOT/'helix.example.json')['design_decision']['required'])

    def test_8_fixture_is_external_and_sweep_module_importable(self):
        fixture=test_new.NewTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.assertFalse(fixture.base.is_relative_to(ROOT))
        import tests.test_sweep
        self.assertIsNotNone(tests.test_sweep.SweepTests)

    def test_9_working_artifacts_removed(self):
        for path in ('RESOLUTIONS-helix-s3.md','docs/implementation/merge-helix-s3','docs/implementation/SWEEP-tests.txt'):
            self.assertFalse((ROOT/path).exists(),path)

    def test_2_structured_api_documents_also_require_metadata(self):
        self.write('openapi.json', {'openapi':'3.1.0', 'paths':{}})
        self.assertFalse(self.item('docs-ownership')['satisfied'])
        entry = dict(path='openapi.json', owner='API owner', reviewed=datetime.now(timezone.utc).date().isoformat(), code=[])
        self.write('docs-metadata.json', {'documents':[entry]})
        self.assertTrue(self.item('docs-ownership')['satisfied'])
        self.assertFalse(self.item('docs-freshness')['satisfied'])

    def test_1_and_6_contract_regeneration_preserves_pins_map_and_gate(self):
        import shutil
        build_root=self.root/'builder'
        shutil.copytree(ROOT/'new', build_root/'new')
        (build_root/'bin').mkdir()
        shutil.copyfile(ROOT/'bin/helix_contracts.py',build_root/'bin/helix_contracts.py')
        result=subprocess.run([sys.executable,str(build_root/'new/build_contracts.py')],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        config=H.load(build_root/'new/templates/helix.json.tpl')
        self.assertEqual(config['helix_version'],C.VERSION)
        self.assertTrue(config['design_decision']['required'])
        schema=H.load(build_root/'new/schemas/config.json')
        self.assertIn('helix_version',schema['required'])
        for profile in ('S','M','L','XL'):
            self.assertEqual(H.load(build_root/f'new/profiles/{profile}.json')['artifacts']['domain-map.json'],'domain-map')
        text=(build_root/'new/templates/SKILL.md.tpl').read_text()
        self.assertIn('only exit 0 means PASS',text)
        self.assertIn('exit 2 is FAIL',text)
