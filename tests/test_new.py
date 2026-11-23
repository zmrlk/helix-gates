"""Helix New offline contracts; all fixtures stay inside the permitted workspace."""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_new as hn


class NewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.project = self.base / 'project'

    def init(self, profile='S', risk='low', mode='greenfield'):
        hn.initialize(self.project, mode, profile, risk)

    def fill(self, schema):
        if 'enum' in schema:
            return schema['enum'][0]
        kind = schema.get('type')
        if kind == 'object':
            return {k: self.fill(s) for k, s in schema.get('properties', {}).items()}
        if kind == 'array':
            return [self.fill(schema.get('items', {}))] if schema.get('minItems', 0) else []
        if kind in ('integer','number'): return 10
        if kind == 'boolean': return True
        return 'Owner-reviewed requirement'

    def refresh(self):
        m = hn.load(self.project / 'handoff-manifest.yaml')
        for entry in m['artifacts']:
            p = self.project / entry['path']
            if p.is_file(): entry['sha256'] = hn.digest(p)
        hn.dump(self.project / 'handoff-manifest.yaml', m)

    def ready(self, profile='S', risk='low', mode='greenfield'):
        self.init(profile, risk, mode)
        files = hn.required(profile, risk, mode)
        m = self.fill(hn.load(hn.NEW / 'schemas/manifest.json'))
        m.update(profile=profile, risk=risk, mode=mode, platform=False, artifacts=[], claims=[dict(tag='VERIFIED', statement='Local charter reviewed', evidence='PROJECT.md:1')])
        for name, kind in files.items():
            p = self.project / name
            if kind != 'markdown':
                value = self.fill(hn.load(hn.NEW / 'schemas' / (kind + '.json')))
                if kind == 'domain-map':
                    value = dict(mechanisms={'M1':['P1']}, patterns={'P1':['C1']}, components={'C1':['I1']}, industries={'I1':[]})
                if kind == 'platform':
                    value = hn.load(ROOT / 'tests/fixtures/commerce-platform-xl.json')['program']
                if kind == 'brand':
                    for item in [value['logo'], *value['colors'], *value['fonts']]:
                        item['source'] = dict(kind='owner', reference='Owner approved asset record 1')
                    value['logo']['value'] = 'logo.svg'
                    value['colors'][0]['value'] = '#123456'
                    value['fonts'][0]['value'] = 'Example Sans'
                hn.dump(p, value)
            elif name not in ('SKILL.md', 'AGENTS.md', 'DESIGN.md'):
                p.write_text('# Reviewed\n\nVERIFIED: owner reviewed local requirement.\n')
            m['artifacts'].append(dict(path=name, sha256=hn.digest(p), status='approved', accepted_by='Project owner'))
        (self.project / 'HANDOFF.md').write_text('# Handoff\n\nVERIFIED: reviewed locally.\n\n## What changed and why\n\nAdded the reviewed project contracts to establish explicit scope and acceptance checks.\n')
        brand = hn.load(self.project / 'brand.yaml')
        tokens = {k:[x['value'] for x in brand[k]] for k in ('colors','fonts')}
        contract = hn.load(self.project / 'design-contract.yaml')
        contract['tokens'] = tokens
        hn.dump(self.project / 'design-contract.yaml', contract)
        (self.project / 'DESIGN.md').write_text('# Design\n\nVERIFIED: approved projection.\n\n```json\n' + json.dumps(tokens) + '\n```\n')
        hn.dump(self.project / 'handoff-manifest.yaml', m)
        self.refresh()
        if profile != 'S':
            # These tests exercise handoff contracts; explicit temporary waivers
            # keep unrelated Pro requirements visible rather than faking CI.
            from helix_pro import assess
            ids = [x['id'] for a in assess(self.project, profile)['areas'].values() for x in a['requirements'] if not x['satisfied']]
            hn.dump(self.project / 'pro-exceptions.json', {'exceptions': [dict(requirement=x, reason='Contract fixture only', approved_by='Test owner', expires='2099-01-01') for x in ids]})

    def test_pro_m_check_requires_ci(self):
        self.ready('M')
        (self.project / 'pro-exceptions.json').unlink()
        self.assertTrue(any('postgres-ci' in error for error in hn.check(self.project)))

    def test_greenfield_s_pass(self):
        self.ready(); self.assertEqual(hn.check(self.project), [])

    def test_greenfield_xl_pass(self):
        self.ready('XL'); self.assertEqual(hn.check(self.project), [])

    def test_greenfield_l_pass(self):
        self.ready('L'); self.assertEqual(hn.check(self.project), [])

    def test_m_high_pass(self):
        self.ready('M','high'); self.assertEqual(hn.check(self.project), [])

    def test_brownfield_pass(self):
        self.ready(mode='brownfield'); self.assertEqual(hn.check(self.project), [])

    def test_draft_fails(self):
        self.init(); self.assertTrue(hn.check(self.project))

    def test_no_overwrite(self):
        self.init(); before = hn.digest(self.project / 'PROJECT.md')
        with self.assertRaises(ValueError): self.init()
        self.assertEqual(before, hn.digest(self.project / 'PROJECT.md'))

    def test_hash_mismatch(self):
        self.ready(); (self.project / 'PROJECT.md').write_text('VERIFIED: changed')
        self.assertTrue(any('hash mismatch' in e for e in hn.check(self.project)))

    def test_missing_skill(self):
        self.ready(); (self.project / 'SKILL.md').unlink()
        self.assertTrue(any('SKILL.md' in e for e in hn.check(self.project)))

    def test_skill_minimum(self):
        self.ready(); (self.project / 'SKILL.md').write_text('ASSUMPTION: project skill'); self.refresh()
        self.assertTrue(any('SKILL.md missing' in e for e in hn.check(self.project)))

    def test_placeholder(self):
        self.ready(); (self.project / 'PRD.md').write_text('ASSUMPTION: TODO requirement'); self.refresh()
        self.assertTrue(any('placeholder' in e for e in hn.check(self.project)))

    def test_claim_label(self):
        self.ready(); (self.project / 'PRD.md').write_text('Unlabeled requirement'); self.refresh()
        self.assertTrue(any('claim label' in e for e in hn.check(self.project)))

    def test_invalid_evidence(self):
        self.ready(); m=hn.load(self.project/'handoff-manifest.yaml'); m['claims'][0]['evidence']='PROJECT.md:999'; hn.dump(self.project/'handoff-manifest.yaml',m)
        self.assertIn('invalid claim evidence', hn.check(self.project))

    def test_missing_large_artifacts(self):
        self.ready('XL')
        for name in ('adr/tenancy.yaml','partitioning.yaml','regions-dr.yaml','capacity.yaml'):
            (self.project / name).unlink()
        self.assertGreaterEqual(len(hn.check(self.project)), 4)

    def test_large_numeric_capacity(self):
        self.ready('XL'); p=self.project/'capacity.yaml'; d=hn.load(p); d['rps']='many'; hn.dump(p,d); self.refresh()
        self.assertTrue(any('rps' in e for e in hn.check(self.project)))

    def test_large_slo(self):
        self.ready('L'); hn.dump(self.project/'slo.yaml', {'critical_paths':[]}); self.refresh()
        self.assertTrue(any('critical_paths' in e for e in hn.check(self.project)))

    def test_regulated_compliance_required(self):
        self.ready(risk='regulated'); (self.project/'compliance.yaml').unlink()
        self.assertTrue(any('compliance' in e for e in hn.check(self.project)))

    def test_small_advanced_fail(self):
        self.ready(); p=self.project/'architecture.yaml'; d=hn.load(p); d['advanced_features']=['multi-region']; hn.dump(p,d); self.refresh()
        self.assertTrue(any('numeric threshold' in e for e in hn.check(self.project)))

    def test_small_advanced_approved(self):
        self.ready(); p=self.project/'architecture.yaml'; d=hn.load(p); d.update(advanced_features=['cells'], decisions=[dict(feature='cells',status='approved',threshold=1000,metric='rps',adr='adr/ADR-001.md',accepted_by='Owner')]); hn.dump(p,d); self.refresh()
        self.assertEqual(hn.check(self.project), [])

    def test_brand_correct(self):
        self.ready(); self.assertEqual(hn.brand_check(self.project), [])

    def test_brand_no_source(self):
        self.ready(); p=self.project/'brand.yaml'; b=hn.load(p); del b['fonts'][0]['source']; hn.dump(p,b)
        self.assertTrue(hn.brand_check(self.project))

    def test_brand_no_approval(self):
        self.ready(); p=self.project/'brand.yaml'; b=hn.load(p); b['accepted_by']=''; hn.dump(p,b)
        self.assertTrue(hn.brand_check(self.project))

    def test_brand_contract_mismatch(self):
        self.ready(); p=self.project/'design-contract.yaml'; d=hn.load(p); d['tokens']['colors']=['#ffffff']; hn.dump(p,d)
        self.assertTrue(any('differ' in e for e in hn.brand_check(self.project)))

    def test_brand_design_mismatch(self):
        self.ready(); p=self.project/'DESIGN.md'; p.write_text(p.read_text().replace('#123456','#abcdef'))
        self.assertTrue(any('differ' in e for e in hn.brand_check(self.project)))

    def test_brand_missing_file_source(self):
        self.ready(); p=self.project/'brand.yaml'; b=hn.load(p); b['logo']['source']=dict(kind='file',reference='absent.svg'); hn.dump(p,b)
        self.assertTrue(hn.brand_check(self.project))

    def test_manifest_path_escape(self):
        self.ready(); p=self.project/'handoff-manifest.yaml'; m=hn.load(p); m['artifacts'][0]['path']='../outside.md'; hn.dump(p,m)
        with self.assertRaises(ValueError): hn.check(self.project)

    def test_manifest_symlink_escape(self):
        self.ready(); p=self.project/'PRD.md'; p.unlink(); p.symlink_to(self.base/'outside.md')
        with self.assertRaises(ValueError): hn.check(self.project)

    def test_audit_read_only_palette(self):
        repo=self.base/'target'; repo.mkdir()
        (repo/'style.css').write_text(':root { --accent: #123456; color: #123456; font-family: Example Sans; }\n')
        (repo/'package.json').write_text('{"dependencies":{"react":"1"}}')
        (repo/'Dockerfile').write_text('FROM scratch\n')
        (repo/'secret.json').write_text('{"private":"DO NOT COPY"}')
        before={p.name:(hn.digest(p),p.stat().st_mtime_ns) for p in repo.iterdir()}
        out=self.base/'output'; hn.audit(repo,out)
        after={p.name:(hn.digest(p),p.stat().st_mtime_ns) for p in repo.iterdir()}
        self.assertEqual(before,after)
        result=hn.load(out/'audit.json')
        self.assertEqual(result['palette']['hex']['#123456'],2)
        self.assertIn('--accent',result['palette']['variables'])
        self.assertIn('Example Sans',result['palette']['fonts'])
        self.assertNotIn('DO NOT COPY', (out/'audit.json').read_text())
        self.assertTrue(any(x['kind']=='framework-declaration' for x in result['observations']))
        self.assertTrue(any('docker' in x['categories'] for x in result['inventory']))

    def test_audit_reject_target_output(self):
        self.project.mkdir()
        with self.assertRaises(ValueError): hn.audit(self.project,self.project/'out')

    def test_cli_pass_fail_error(self):
        self.ready()
        for action, expected in [('check',0),('handoff',0)]:
            p=subprocess.run([sys.executable,str(ROOT/'bin/helix'),'new',action,'--dir',str(self.project)],capture_output=True,text=True)
            self.assertEqual(p.returncode,expected,p.stdout+p.stderr)
        (self.project/'SKILL.md').unlink()
        a=argparse.Namespace(new_action='check',dir=str(self.project))
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(hn.dispatch(a),2)
        (self.project/'handoff-manifest.yaml').write_text('{broken')
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(hn.dispatch(a),3)

    def test_json_yaml_subset_without_parser(self):
        self.init(); self.assertIsInstance(json.loads((self.project/'brand.yaml').read_text()),dict)

    def test_small_prose_advanced_requires_adr(self):
        self.ready(); (self.project/'PRD.md').write_text('ASSUMPTION: deploy multi-region cells.'); self.refresh()
        self.assertTrue(any('numeric threshold' in e for e in hn.check(self.project)))

    def test_missing_required_manifest_entry(self):
        self.ready('XL'); p=self.project/'handoff-manifest.yaml'; m=hn.load(p); m['artifacts']=[e for e in m['artifacts'] if e['path']!='capacity.yaml']; hn.dump(p,m)
        self.assertTrue(any('required manifest artifact missing: capacity.yaml' in e for e in hn.check(self.project)))

    def test_duplicate_manifest_entry(self):
        self.ready(); p=self.project/'handoff-manifest.yaml'; m=hn.load(p); m['artifacts'].append(m['artifacts'][0]); hn.dump(p,m)
        self.assertIn('duplicate manifest artifact',hn.check(self.project))

    def test_large_compliance_required_at_low_risk(self):
        self.ready('L'); (self.project/'compliance.yaml').unlink()
        self.assertTrue(any('compliance.yaml' in e for e in hn.check(self.project)))

    def test_unapproved_artifact(self):
        self.ready(); p=self.project/'handoff-manifest.yaml'; m=hn.load(p); m['artifacts'][0]['status']='draft'; hn.dump(p,m)
        self.assertTrue(hn.check(self.project))

    def test_nonfinite_capacity(self):
        self.ready('XL'); p=self.project/'capacity.yaml'; d=hn.load(p); d['rps']=float('nan'); hn.dump(p,d); self.refresh()
        self.assertTrue(any('rps' in e for e in hn.check(self.project)))

    def test_audit_tailwind_and_reconstruction(self):
        self.project.mkdir(); (self.project/'tailwind.config.js').write_text("export default { fontFamily: { sans: ['Example Sans', 'sans-serif'] }, colors: { primary: '#123456' } };\n")
        (self.project/'tokens.json').write_text('{"primary":"#123456"}')
        (self.project/'link.css').symlink_to(self.base/'absent.css')
        out=self.base/'audit'; hn.audit(self.project,out)
        r=hn.load(out/'audit.json')
        self.assertEqual(r['palette']['hex']['#123456'],2)
        self.assertIn('Example Sans',r['palette']['fonts'])
        self.assertTrue((out/'proposed'/'SKILL.md').is_file())
        self.assertTrue(hn.check(out/'proposed'))
        self.assertFalse(any(x['path']=='link.css' for x in r['inventory']))

    def test_absent_manifest_fails(self):
        self.project.mkdir(); self.assertEqual(hn.check(self.project),['handoff-manifest.yaml missing'])

    def test_malformed_design_returns_error_without_source_echo(self):
        self.ready(); (self.project/'DESIGN.md').write_text('```json\n{private-content\n```')
        a=argparse.Namespace(new_action='brand',dir=str(self.project))
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.assertEqual(hn.dispatch(a),3)
        self.assertNotIn('private-content',output.getvalue())

    def test_binary_brand_asset_hash(self):
        self.ready(); p=self.project/'logo.png'; p.write_bytes(b'\x89PNG\xff\x00')
        m=hn.load(self.project/'handoff-manifest.yaml'); m['artifacts'].append(dict(path='logo.png',sha256=hn.digest(p),status='approved',accepted_by='Owner')); hn.dump(self.project/'handoff-manifest.yaml',m)
        self.assertEqual(hn.check(self.project),[])

    def test_review_negation_only_before_feature(self):
        self.ready()
        for prose in ('multi-region bez ADR', 'multi-region without an ADR threshold',
                      'multi-region deployment is required, not optional',
                      'Use cells, no ADR yet', 'sharding jest wymagany, nie opcjonalny'):
            with self.subTest(prose=prose):
                (self.project/'PRD.md').write_text('ASSUMPTION: ' + prose)
                self.refresh()
                self.assertTrue(any('numeric threshold' in e for e in hn.check(self.project)))
        for prose in ('not multi-region', 'bez multi-region', 'avoid cells', 'no sharding'):
            with self.subTest(prose=prose):
                (self.project/'PRD.md').write_text('ASSUMPTION: ' + prose)
                self.refresh()
                self.assertEqual(hn.check(self.project), [])

    def test_review_invalid_architecture_cli_fail(self):
        self.ready()
        original = hn.load(self.project/'architecture.yaml')
        decision = dict(feature='cells', status='approved', threshold=1000,
                        metric='rps', adr='adr/ADR-001.md', accepted_by='Owner')
        cases = [[], dict(original, decisions='private-content'),
                 dict(original, decisions=['private-content'])]
        for threshold in ('1000', True, None, float('nan')):
            cases.append(dict(original, advanced_features=['cells'],
                              decisions=[dict(decision, threshold=threshold)]))
        for architecture in cases:
            with self.subTest(architecture=architecture):
                hn.dump(self.project/'architecture.yaml', architecture)
                self.refresh()
                result = subprocess.run([sys.executable, str(ROOT/'bin/helix'), 'new',
                                         'check', '--dir', str(self.project)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'], 'FAIL')
                self.assertIn('architecture.yaml', result.stdout)
                self.assertNotIn('private-content', result.stdout + result.stderr)

    def test_attribute_error_is_sanitized_error(self):
        from unittest.mock import patch
        output = io.StringIO()
        with patch.object(hn, 'check', side_effect=AttributeError('private-content')):
            with contextlib.redirect_stdout(output):
                self.assertEqual(hn.dispatch(argparse.Namespace(new_action='check', dir=str(self.project))), 3)
        self.assertEqual(json.loads(output.getvalue()), dict(status='ERROR', reason='AttributeError'))

    def test_audit_build_dependency_variants(self):
        self.project.mkdir()
        for name in ('Dockerfile.prod', 'Dockerfile.dev', 'requirements-dev.txt', 'requirements.prod.txt', 'alembic.ini'):
            (self.project/name).write_text('fixture')
        (self.project/'requirements-secret.txt').write_text('excluded')
        out = self.base/'audit'
        hn.audit(self.project, out)
        inventory = {x['path']: x['categories'] for x in hn.load(out/'audit.json')['inventory']}
        self.assertEqual(set(inventory), {'Dockerfile.prod', 'Dockerfile.dev', 'requirements-dev.txt', 'requirements.prod.txt', 'alembic.ini'})
        self.assertIn('docker', inventory['Dockerfile.prod'])
        self.assertIn('manifest', inventory['requirements-dev.txt'])

    def test_audit_alembic_migrations(self):
        version = self.project/'apps/api/alembic/versions/abc_add_table.py'
        version.parent.mkdir(parents=True)
        version.write_text('# fixture')
        (version.parent.parent/'env.py').write_text('# fixture')
        out = self.base/'audit'
        hn.audit(self.project, out)
        inventory = {x['path']: x['categories'] for x in hn.load(out/'audit.json')['inventory']}
        self.assertIn('migrations', inventory[version.relative_to(self.project).as_posix()])
        self.assertNotIn('migrations', inventory['apps/api/alembic/env.py'])

    def test_audit_palette_comments_and_references(self):
        self.project.mkdir()
        (self.project/'style.css').write_text(
            '/* --accent: #ffffff; font-family: Fake;\ncontinued */\n'
            ':root { --accent: #123456; --font-sans: "Example Sans", sans-serif; }\n'
            'body { color: var(--accent); font-family: var(--font-sans); }\n'
            '/* #123456 */\n')
        (self.project/'tailwind.config.js').write_text('// #ffffff\nexport default {color: "#123456"};')
        out = self.base/'audit'
        hn.audit(self.project, out)
        report = hn.load(out/'audit.json')
        self.assertEqual(report['palette']['hex'], {'#123456': 2})
        self.assertEqual(report['palette']['variables']['--accent'], 1)
        self.assertEqual(report['palette']['variable_references'], {'--accent': 1, '--font-sans': 1})
        self.assertIn('var(--font-sans)', report['palette']['fonts'])
        self.assertNotIn('Fake', report['palette']['fonts'])
        self.assertTrue(any(x['kind']=='variables' and x['value']=='--font-sans'
                            and x['declared_value']=='"Example Sans", sans-serif'
                            and x['evidence']=='style.css:3' for x in report['observations']))
        self.assertTrue(any(x['kind']=='fonts' and x['evidence']=='style.css:4' for x in report['observations']))
        self.assertIn('runtime not evaluated', report['scope']['palette'])

    def test_audit_brownfield_gap_scope(self):
        self.project.mkdir()
        out = self.base/'audit'
        hn.audit(self.project, out)
        report = hn.load(out/'audit.json')
        self.assertEqual({x['artifact'] for x in report['gaps']}, set(hn.required('S', 'low', 'brownfield')))
        self.assertEqual({k:report['scope'][k] for k in ('profile','risk','mode')}, dict(profile='S', risk='low', mode='brownfield'))
        self.assertIn('audit.json', {x['artifact'] for x in report['gaps']})

    def test_skill_template_exit_contract(self):
        text = (hn.NEW/'templates/SKILL.md.tpl').read_text()
        self.assertIn('only exit 0 means PASS', text)
        self.assertIn('exit 2 is FAIL', text)


if __name__ == '__main__': unittest.main()
