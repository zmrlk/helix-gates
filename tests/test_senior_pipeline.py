import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_data_leaks as leaks
import helix_senior_pipeline as pipeline
import helix_lenses as lenses

FIXTURES = Path(__file__).parent / 'fixtures/senior_pipeline'


class SeniorPipelineTests(unittest.TestCase):
    def materialize(self, root, files):
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def test_leaks_and_clean_no_values_exported(self):
        fixtures = json.loads((FIXTURES/'leaks.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.materialize(root, fixtures['leaky'])
            report = leaks.analyze(root)
            ids = {r['id'] for r in report['findings']}
            self.assertTrue({'DATA-LOG','DATA-ODBIORCA','DATA-CACHE','DATA-URL','DATA-BŁĄD',
                             'DATA-OVERFETCH','DATA-BUNDLE','DATA-SOURCEMAP','DATA-ARTIFACT'} <= ids)
            self.assertIn('identyfikatory', report['dpia']['categories'])
            self.assertNotIn('collector.invalid', json.dumps(report))
            self.assertTrue(all(r.get(k) for r in report['findings'] for k in ('file','line','severity','confidence','why','fix')))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.materialize(root, fixtures['clean'])
            self.assertEqual(leaks.analyze(root)['findings'], [])

    def test_audit_trail_stays_unknown_even_with_logger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.materialize(root, {'api.py':'def login():\n    audit_log(who, what, when)\n'})
            report = leaks.analyze(root)
            self.assertTrue(report['audit_trail']['actions'])
            self.assertEqual(report['audit_trail']['tamper_resistance'], 'unknown')
            self.assertTrue(all(r['execution']=='not-run' for r in report['audit_trail']['actions']))
            self.assertNotIn('DATA-AUDIT-GAP', {r['id'] for r in report['findings']})
            self.materialize(root, {'api.py':'def login():\n    return True\n'})
            self.assertIn('DATA-AUDIT-GAP', {r['id'] for r in leaks.analyze(root)['findings']})

    def test_nine_roles_each_part_and_na(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.materialize(root, {'apps/a/api.py':'print(1)', 'apps/b/api.go':'package main', 'README.md':'opis'})
            report = pipeline.build(root, [], {})
            self.assertEqual({r['part'] for r in report['parts']}, {'.','apps/a','apps/b'})
            for part in report['parts']:
                self.assertEqual(len(part['roles']), 9)
                for role in part['roles'].values():
                    self.assertTrue(role['checklist'])
                    self.assertTrue(role['adversarial_pass']['checks'])
                    self.assertTrue(role['tools'])
                    self.assertEqual(role['execution_score'], 0)
                self.assertIsNone(part['roles']['ui_designer']['maturity_score'])

    def test_calibration_ranges_and_missing_evidence(self):
        fixture = json.loads((FIXTURES/'calibration.json').read_text())
        scores = []
        for case in fixture.values():
            controls = [dict(status='observed' if v is not None else 'not-run', level=v,
                             evidence=['source:1'] if v is not None else []) for v in case['levels']]
            result = pipeline.calibrate(controls)
            self.assertLessEqual(case['range'][0], result['maturity_score'])
            self.assertLessEqual(result['maturity_score'], case['range'][1])
            self.assertEqual(result['execution_score'], 0)
            scores.append(result['maturity_score'])
        self.assertEqual(scores, sorted(scores))
        self.assertEqual(pipeline.calibrate([dict(status='observed',level=5,evidence=[])])['maturity_score'],0)
        self.assertEqual(pipeline.calibrate([dict(status='not-run',level=5,evidence=['x:1'])])['maturity_score'],0)

    def test_project_calibration_ranges(self):
        for name, case in json.loads((FIXTURES/'projects.json').read_text()).items():
            with self.subTest(project=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.materialize(root, case['files'])
                role = pipeline.build(root, [], {})['parts'][0]['roles']['senior_developer']
                self.assertLessEqual(case['range'][0], role['maturity_score'])
                self.assertLessEqual(role['maturity_score'], case['range'][1])
                self.assertEqual(role['execution_score'], 0)

    def test_na_gate_and_severity(self):
        controls = [dict(status='observed',level=5,evidence=['x:1']), dict(status='not-applicable',reason='profil',level=None)]
        self.assertEqual(pipeline.calibrate(controls)['maturity_score'],100)
        high = pipeline.calibrate(controls,[dict(severity='high')])
        self.assertEqual(high['gate'],'BLOCK')
        self.assertEqual(high['maturity_score'],90)
        with self.assertRaises(ValueError): pipeline.calibrate([dict(status='not-applicable')])

    def test_dedup_sources_and_severity(self):
        row = dict(id='RULE',file='a.py',line=2,lens='security',severity='medium')
        other = dict(row,lens='ops_data',severity='high')
        before = copy.deepcopy([row, other])
        result = lenses.deduplicate([row,other,row])
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['sources'],['ops_data','security'])
        self.assertEqual(result[0]['severity'],'high')
        self.assertEqual([row,other],before)

    def test_mutable_audit_and_documented_examples(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.materialize(root, {'db.sql':'DELETE FROM audit_log;\n',
                                   'docs/example.ts':'console.log(user.email)',
                                   'tests/example.py':'print(user.email)'})
            report = leaks.analyze(root)
            self.assertEqual({r['id'] for r in report['findings']}, {'DATA-AUDIT-MUTABLE'})
            self.assertTrue(report['audit_trail']['mechanism_candidates'])
            self.assertEqual(report['audit_trail']['tamper_resistance'], 'unknown')

    def test_private_paths_and_symlink_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.materialize(root, {'.env':'email=hidden', 'private/data.py':'console.log(user.email)', 'api.py':'pass'})
            (root/'alias.py').symlink_to(root/'private/data.py')
            self.assertEqual(leaks.analyze(root)['flows'],[])
