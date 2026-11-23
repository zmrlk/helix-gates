import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_pro import assess
import helix_new as hn


class ProTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def test_missing_and_s(self):
        self.assertEqual(assess(self.root, 'S')['blocking'], [])
        for profile in ('M', 'L', 'XL'):
            result = assess(self.root, profile)
            self.assertTrue(result['blocking'])
            self.assertEqual(len(result['areas']), 9)
            self.assertTrue(all(0 <= a['score'] <= 100 and len(a['top_gaps']) <= 3 for a in result['areas'].values()))

    def test_ci_presence_github_gitlab(self):
        for path in ('.github/workflows/test.yml', '.gitlab-ci.yml'):
            with self.subTest(path=path):
                self.write(path, 'services:\n  postgres:16\nDATABASE_URL: postgresql://localhost/test\nrun: migrate && test-integration && playwright test && k6 run k6.js\n')
                self.write('playwright.config.ts', 'export default {};')
                self.write('k6.js', "import http from 'k6/http'; // slo.yaml\nconst thresholds = {http_req_failed:'rate<0.01', duration:'p(95)<500'};")
                self.write('slo.yaml', '{"load_test":{"p95_ms":500,"error_rate":0.01}}')
                self.write('tests/integration/test_database.py', 'def test_database(): pass')
                self.write('migrations/001.sql', 'CREATE TABLE example(id integer);')
                result = assess(self.root, 'M')
                self.assertEqual(result['blocking'], [])
                self.assertEqual(result['areas']['testing/CI']['score'], 0)
                self.assertEqual(result['areas']['testing/CI']['preparation_score'], 100)
                (self.root / path).unlink()

    def test_compose_alone_does_not_prove_ci(self):
        self.write('docker-compose.test.yml', 'services:\n  postgres:\n    image: postgres:16')
        self.assertTrue(any('postgres-ci' in x for x in assess(self.root, 'M')['blocking']))

    def test_exception_expiry_and_score(self):
        for expires, waived in [('2099-01-01', True), ('2000-01-01', False), ('invalid', False)]:
            self.write('pro-exceptions.json', json.dumps({'exceptions':[dict(requirement='postgres-ci', reason='Tracked migration', approved_by='Owner', expires=expires)]}))
            result = assess(self.root, 'M')
            self.assertEqual(any(x.startswith('postgres-ci:') for x in result['blocking']), not waived)
            self.assertEqual(result['areas']['testing/CI']['score'], 0)

    def test_runtime_and_symlink(self):
        self.write('helix.json', '{"ux":{"pages":["/"]},"consistency":{}}')
        result = assess(self.root, 'M')
        self.assertEqual(result['areas']['UX']['requirements'][0]['status'], 'needs-runtime')
        (self.root / 'helix.json').unlink()
        (self.root / 'helix.json').symlink_to('/dev/null')
        self.assertEqual(assess(self.root)['areas']['UX']['score'], 0)

    def test_audit_outputs(self):
        with tempfile.TemporaryDirectory() as output:
            hn.audit(self.root, Path(output), 'M')
            report = json.loads((Path(output) / 'audit.json').read_text())
            self.assertEqual(report['maturity']['profile'], 'M')
            self.assertIn('testing/CI: 0/100', (Path(output) / 'audit.md').read_text())
