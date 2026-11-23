"""Offline maturity contracts: runtime configuration never certifies execution."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_new as H
from helix_pro import assess, improvement_plan, markdown, valid_references


class MaturityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'project'
        self.root.mkdir()

    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def test_catalog_contract(self):
        catalog = H.load(H.NEW / 'profiles/pro-standard.json')
        self.assertEqual(len(catalog['areas']), 9)
        self.assertEqual(set(catalog['area_weights']), set(catalog['areas']))
        ids = set()
        for rule in catalog['requirements']:
            self.assertNotIn(rule['id'], ids)
            ids.add(rule['id'])
            self.assertIn(rule['area'], catalog['areas'])
            self.assertGreater(rule['weight'], 0)
            self.assertTrue(rule['profiles'])
            self.assertEqual(rule['detection'], 'offline+runtime' if rule['runtime'] else 'offline')
            self.assertTrue(rule['threshold'])
            self.assertTrue(rule['source'].startswith('https://'))
            self.assertGreaterEqual(len(rule['remediation']), 3)
            self.assertTrue((H.NEW / 'templates' / rule['template']).is_file(), rule['id'])

    def test_runtime_never_earns_verified_points(self):
        self.write('helix.json', '{"ux":{"pages":["/"]},"consistency":{}}')
        report = assess(self.root, 'M')
        ux = report['areas']['UX']
        self.assertEqual(ux['score'], 0)
        self.assertGreater(ux['preparation_score'], 0)
        self.assertEqual(ux['requirements'][0]['status'], 'needs-runtime')
        self.assertIn('ux-probes', [x['id'] for x in ux['top_gaps']])
        self.assertIn('helix ux', markdown(report))

    def test_weighted_scores_and_missing_runtime(self):
        self.write('architecture.yaml', '{"summary":"modular service boundaries","owner":"platform","trigger":"latency threshold 500ms"}')
        self.write('adr/ADR-001.md', 'Approved decision: local module boundaries accepted by platform owner.')
        report = assess(self.root, 'L')
        area = report['areas']['backend/architecture']
        self.assertEqual(area['score'], round(100 * 2 / 6))
        expected = round(sum(a['score'] * report['area_weights'][k] for k, a in report['areas'].items()) / sum(report['area_weights'].values()))
        self.assertEqual(report['score'], expected)
        cwv = next(x for x in report['areas']['performance']['requirements'] if x['id'] == 'cwv')
        self.assertEqual(cwv['status'], 'needs-runtime')
        self.assertFalse(cwv['satisfied'])

    def test_runtime_k6_config_not_execution(self):
        self.write('k6.js', "import http from 'k6/http'; // slo.yaml thresholds p(95) http_req_failed")
        self.write('slo.yaml', '{"p95_ms":500,"error_rate":0.01}')
        perf = assess(self.root, 'M')['areas']['performance']
        load = next(x for x in perf['requirements'] if x['id'] == 'load')
        self.assertTrue(load['satisfied'])
        self.assertEqual(load['status'], 'needs-runtime')
        self.assertGreater(perf['preparation_score'], perf['score'])

    def test_exceptions_never_earn_points_even_when_present(self):
        self.write('threat-model.md', 'VERIFIED: assets and boundaries reviewed locally.')
        self.write('pro-exceptions.json', json.dumps({'exceptions':[dict(requirement='threat-model', reason='Review pending', approved_by='Owner', expires='2099-01-01')]}))
        self.assertEqual(assess(self.root)['areas']['security']['score'], 0)

    def refs(self):
        return dict(key_flows=['checkout'], flows=[dict(id='checkout', platform='mobile/web', references=[dict(url=f'https://example.test/pattern/{i}', pattern='confirmation', rationale='Keep recovery visible') for i in range(3)])])

    def test_references_coverage_and_bounds(self):
        doc = self.refs()
        self.assertTrue(valid_references(json.dumps(doc)))
        for mutate in (lambda x: x['key_flows'].append('login'),
                       lambda x: x['flows'][0]['references'].pop(),
                       lambda x: x['flows'][0]['references'][0].update(url='file:///private'),
                       lambda x: x['flows'][0]['references'][0].update(rationale='')):
            invalid = copy.deepcopy(doc)
            mutate(invalid)
            self.assertFalse(valid_references(json.dumps(invalid)))

    def test_reference_control_m_plus(self):
        self.write('design-references.json', json.dumps(self.refs()))
        for profile in ('S', 'M', 'L', 'XL'):
            refs = [x for x in assess(self.root, profile)['areas']['UI']['requirements'] if x['id'] == 'design-references']
            self.assertEqual(len(refs), int(profile != 'S'))
            if refs:
                self.assertTrue(refs[0]['satisfied'])

    def test_draft_templates_do_not_count_as_evidence(self):
        for name in ('threat-model.md', 'prr-checklist.md', 'cwv-budget.md', 'design-references.json'):
            self.write(name, (H.NEW / 'templates' / (name + '.tpl')).read_text())
        report = assess(self.root, 'M')
        self.assertEqual(report['score'], 0)
        self.assertTrue(all(not x['satisfied'] for a in report['areas'].values() for x in a['requirements']))

    def test_plan_schema_priority_runtime_and_determinism(self):
        report = assess(self.root, 'M')
        plan = improvement_plan(report)
        self.assertEqual(plan, improvement_plan(report))
        self.assertEqual(set(plan), {'checkpoints'})
        self.assertEqual(H.schema_check(plan, H.load(H.HOME / 'schemas/plan.json')), [])
        priorities = [0 if x['title'].split(':')[0] in ('security','data') else 1 if x['title'].startswith('ops/reliability:') else 2 for x in plan['checkpoints']]
        self.assertEqual(priorities, sorted(priorities))
        self.assertEqual([x['id'] for x in plan['checkpoints']], [f'cp{i+1}' for i in range(len(priorities))])
        self.assertTrue(any(x['visual'] for x in plan['checkpoints']))
        self.assertIn('k6', json.dumps(plan))
        self.assertIn('new/templates/', json.dumps(plan))

    def test_plan_cli_no_overwrite(self):
        out = Path(self.temp.name) / 'audit'
        H.audit(self.root, out, 'M')
        plan_path = Path(self.temp.name) / 'plan.json'
        command = [sys.executable, str(H.HOME / 'bin/helix'), 'new', 'plan', '--to', 'pro', '--audit', str(out / 'audit.json'), '--out', str(plan_path)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(json.loads(plan_path.read_text())['checkpoints'])
        before = plan_path.read_bytes()
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 3)
        self.assertEqual(plan_path.read_bytes(), before)

    def test_symlink_and_old_audit_rejected(self):
        target = Path(self.temp.name) / 'threat-model.md'
        target.write_text('VERIFIED: reviewed boundaries')
        (self.root / 'threat-model.md').symlink_to(target)
        self.assertEqual(assess(self.root)['areas']['security']['score'], 0)
        with self.assertRaises(ValueError):
            improvement_plan(dict(areas={}))
