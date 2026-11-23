import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_project_evidence as E
from helix_pro import assess, markdown


class ProjectEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sha = 'a' * 40
        self.write('tests/brand.test.ts', 'assertTokensMatchApprovedBrand();\n')
        self.write('src/Generated.tsx', 'export const Module = () => <Button />;\n')
        self.write('result.txt', '1 test passed\n')
        self.write('helix.json', json.dumps(dict(custom_gates=[dict(name='brand', area='UI', description='Approved brand tokens', file='tests/brand.test.ts', command='node tests/brand.test.ts')])))
        self.run_data = dict(status='passed', exit=0, who='fixture', where='localhost', command='test fixture', sha=self.sha,
                             log='result.txt', log_sha256=self.digest('result.txt'),
                             files={p: self.digest(p) for p in ('tests/brand.test.ts', 'src/Generated.tsx')})
        self.addCleanup(patch.stopall)
        patch('helix_git_readonly.read_ref', return_value=dict(head=self.sha, dirty=False)).start()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def digest(self, name):
        return hashlib.sha256((self.root / name).read_bytes()).hexdigest()

    def control(self, run=None):
        self.write('pro-evidence.json', json.dumps(dict(schema_version=1, controls=[dict(requirement='design-contract', gate='brand', evidence=['tests/brand.test.ts:1'], run=run)])))
        return assess(self.root)

    def item(self, report):
        return next(x for x in report['areas']['UI']['requirements'] if x['id'] == 'design-contract')

    def test_custom_evidence_without_execution_is_visible_and_zero_points(self):
        report = self.control()
        item = self.item(report)
        self.assertEqual(item['status'], 'local-unexecuted')
        self.assertEqual(item['points'], 0)
        self.assertTrue(item['satisfied'])
        self.assertEqual(report['areas']['UI']['score'], 0)
        self.assertIn('dowód lokalny, nieuruchomiony', markdown(report))

    def test_local_matching_receipt_earns_points_without_running_command(self):
        with patch('subprocess.run', side_effect=AssertionError('must not run project code')):
            self.assertTrue(E.execution(self.root, self.run_data)['points_eligible'])
        item = self.item(self.control(self.run_data))
        self.assertEqual(item['status'], 'local-executed')
        self.assertEqual(item['points'], item['weight'])

    def test_missing_failed_stale_or_forged_receipt_never_earns_points(self):
        for changes in (dict(status='not-run'), dict(status='failed', exit=1), dict(sha='b'*40), dict(log_sha256='0'*64), dict(files={}), dict(exit=False)):
            with self.subTest(changes=changes):
                self.assertEqual(self.item(self.control(dict(self.run_data, **changes)))['points'], 0)
        self.write('tests/brand.test.ts', 'changed source\n')
        self.assertEqual(self.item(self.control(self.run_data))['points'], 0)

    def test_invalid_gate_or_citation_fails_closed(self):
        self.control()
        path = self.root / 'pro-evidence.json'
        data = json.loads(path.read_text())
        for changes in (dict(gate='unknown'), dict(requirement='unknown'), dict(evidence=['../escape:1']), dict(evidence=['tests/brand.test.ts:99'])):
            value = copy.deepcopy(data)
            value['controls'][0].update(changes)
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                assess(self.root)

    def test_unexecuted_tests_are_preparation_only(self):
        result = assess(self.root)['areas']['testing/CI']
        self.assertEqual(result['score'], 0)
        self.assertGreater(result['preparation_score'], 0)
        self.assertTrue(all(x['points'] == 0 for x in result['requirements']))

    def document(self):
        return dict(catalog=['Button'], modules=[dict(id='generated-orders', path='src/Generated.tsx', components=['Button'],
                    gates={g: self.run_data for g in ('contract', 'tests', 'permissions', 'appearance', 'brand')})])

    def test_ai_module_requires_catalog_and_all_project_gates(self):
        doc = self.document()
        self.assertEqual(E.modules(self.root, doc, ['brand'])['status'], 'PASS')
        for gate in ('contract', 'tests', 'permissions', 'appearance', 'brand'):
            value = copy.deepcopy(doc)
            del value['modules'][0]['gates'][gate]
            result = E.modules(self.root, value, ['brand'])
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['modules'][0]['points'], 0)
        doc['modules'][0]['components'].append('UnapprovedWidget')
        self.assertEqual(E.modules(self.root, doc)['status'], 'FAIL')

    def test_ai_changed_source_and_missing_inventory_are_not_pass(self):
        self.write('src/Generated.tsx', 'changed module')
        self.assertEqual(E.modules(self.root, self.document())['status'], 'FAIL')
        with self.assertRaises(ValueError):
            E.modules(self.root, dict(catalog=['Button'], modules=[]))

    def test_cli_failure_reports_gate_and_no_execution(self):
        doc = self.document(); doc['modules'][0]['gates'] = {}
        self.write('ai-modules.json', json.dumps(doc))
        result = subprocess.run([sys.executable, str(ROOT/'bin/helix'), '--repo', str(self.root), '--offline', 'new', 'modules'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('brand', json.loads(result.stdout)['required_gates'])
