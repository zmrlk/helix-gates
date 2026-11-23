"""Offline regression contract; fixtures contain source data, never executed."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_lenses as lenses
import helix_static_security as security
import helix_authz_routes as scopes
import helix_verification as verification

FIXTURES = Path(__file__).parent / 'fixtures/authz-precision'


class ReviewPrecisionTests(unittest.TestCase):
    def write(self, root, files):
        for name, source in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)

    def scan(self, files):
        with tempfile.TemporaryDirectory() as directory:
            self.write(Path(directory), files)
            return security.analyze(directory)

    def test_pattern_fixtures(self):
        cases = json.loads((FIXTURES / 'patterns.json').read_text())
        for case in cases:
            with self.subTest(case=case['name']):
                data = self.scan(case['files'])
                hits = [r for r in data['findings'] if r['id'] == case['detector']]
                self.assertEqual(bool(hits), case['positive'])
                for row in hits:
                    self.assertGreater(row['line'], 0)
                    self.assertIn(f"{row['file']}:{row['line']}", row['evidence'])
                    self.assertTrue(row['why'])
                    self.assertTrue(row['fix'])

    def test_framework_fixtures(self):
        cases = json.loads((FIXTURES / 'frameworks.json').read_text())
        for case in cases:
            with self.subTest(case=case['name']):
                data = self.scan(case['files'])
                routes = {r['path']: r for r in data['endpoints']}
                for path, candidate in case['expected'].items():
                    self.assertIn(path, routes)
                    self.assertEqual(routes[path]['guard_candidate'], candidate)
                    self.assertIn(routes[path]['auth_status'], {'unknown', 'proven-guarded', 'unguarded'})

    def test_matcher_and_layout_boundaries(self):
        self.assertTrue(scopes.matches('/staff/:path*', '/staff'))
        self.assertTrue(scopes.matches('/staff/:path*', '/staff/a'))
        self.assertFalse(scopes.matches('/staff/:path*', '/staffing'))
        self.assertIsNone(scopes.matches('/((?!public).*)', '/staff'))
        data = self.scan({'src/routes/+layout.server.ts': 'export function load(event) { if (!event.locals.user) throw error(401); }',
                          'src/routes/api/+server.ts': 'export function GET() { return db.findMany(); }'})
        self.assertFalse(data['endpoints'][0]['guard_candidate'])

    def test_mandatory_verifier_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repo'; root.mkdir()
            self.write(root, {'routes.ts': "router.get('/a', () => db.findMany());"})
            data = lenses.report(root)
            self.assertFalse(data['owner_findings'])
            self.assertTrue(data['verification']['candidates'])
            self.assertEqual(data['verification']['status'], 'not-run')
            self.assertTrue(all(i['score'] == 0 for i in data['lenses'].values()))
            self.assertIn('## Załącznik: candidate', lenses.markdown(data))
            self.assertIn('ograniczonym zakresem', lenses.markdown(data))
            # No confidence label alone may bypass the mandatory boundary.
            row = security.finding('TEST', 'test', 'routes.ts', '', 0, 'why', 'fix', 'critical', 'confirmed')
            verification.apply([row], root, {'routes.ts':'v1'})
            self.assertEqual(row['severity'], 'medium')
            self.assertEqual(row['verification_status'], 'candidate')

    def test_import_persistence_precision_and_stale_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); repo = base/'repo'; repo.mkdir()
            state = base/'state'; verdicts = base/'verdicts.json'
            sources = {'a.ts':'v1', 'b.ts':'v1', 'c.ts':'v1'}
            def findings():
                return [security.finding('TEST', 'test', file, '', 0, 'why', 'fix', 'high', 'likely') for file in sources]
            rows = findings()
            verification.apply(rows, repo, sources)
            payload = dict(schema_version=1, hunter='hunter', verifier='independent', verdicts=[dict(finding_id=r['finding_id'], verdict=v, reason='Źródło sprawdzone.') for r,v in zip(rows, ['confirmed','rejected','unclear'])])
            verdicts.write_text(json.dumps(payload))
            result = verification.apply(findings(), repo, sources, verdicts, state, threshold=.5, minimum=3)
            self.assertAlmostEqual(result['project']['TEST']['precision'], 1/3)
            self.assertTrue(result['project']['TEST']['degraded'])
            repeated = findings()
            result = verification.apply(repeated, repo, sources, verdicts, state, threshold=.5, minimum=3)
            self.assertEqual(result['project']['TEST']['total'], 3)
            self.assertEqual(repeated[0]['severity'], 'medium')
            self.assertEqual(repeated[0]['verification_status'], 'confirmed')
            loaded = findings()
            verification.apply(loaded, repo, sources, state_dir=state)
            self.assertEqual(loaded[0]['verification_status'], 'confirmed')
            other = base/'other'; other.mkdir()
            result = verification.apply(findings(), other, sources, state_dir=state, threshold=.5, minimum=3)
            self.assertFalse(result['project'])
            self.assertTrue(result['global_precision']['TEST']['degraded'])
            sources['a.ts'] = 'v2'
            with self.assertRaises(ValueError):
                verification.apply(findings(), repo, sources, verdicts, state)
            payload['verifier'] = 'hunter'; verdicts.write_text(json.dumps(payload))
            with self.assertRaises(ValueError):
                verification.apply(findings(), repo, sources, verdicts)
            with self.assertRaises(ValueError):
                verification.apply(findings(), repo, sources, state_dir=repo/'state')

    def test_proven_local_guard_and_late_guard_unknown(self):
        data = self.scan({'routes.ts': "function check(req) { if (!req.user) throw error(403); }\nrouter.get('/a', (req) => { check(req); return db.findMany(); });\nrouter.get('/b', (req) => { db.findMany(); check(req); });"})
        # Retain the historical test ID; neither lexical nor local AST syntax
        # constitutes complete control-flow evidence in the current contract.
        self.assertEqual(data['endpoints'][0]['auth_status'], 'unknown')
        self.assertTrue(data['endpoints'][0]['guard_candidate'])
        self.assertEqual(data['endpoints'][1]['auth_status'], 'unknown')
        self.assertEqual(data['authz']['proven_protected'], 0)

    def test_conditional_guard_is_not_proof(self):
        data = self.scan({'routes.ts': "function check(req) { if (!req.user) throw error(403); }\nrouter.get('/a', (req) => { if (req.special) { check(req); } return db.findMany(); });"})
        self.assertEqual(data['endpoints'][0]['auth_status'], 'unknown')

    def test_cross_file_subaction_and_application_isolation(self):
        guard = 'function decide(user, record) { if (record.owner !== user.id) throw error(403); }\n'
        data = self.scan({
            'packages/api/src/routes/items/[id]/+server.ts': guard + 'export function GET() { decide(user, record); return db.findUnique({id: params.id}); }',
            'packages/api/src/routes/items/[id]/rotate/+server.ts': 'export function POST() { db.update({id: params.id}); }',
            'packages/other/src/routes/items/[id]/rotate/+server.ts': 'export function POST() { db.update({id: params.id}); }'})
        hits = [f for f in data['findings'] if f['id'] == 'SEC-METHOD-ASYMMETRY']
        self.assertEqual(len(hits), 1)
        self.assertIn('packages/api/', hits[0]['file'])

    def test_record_guard_single_record_and_module_only(self):
        data = self.scan({'routes.ts': "router.patch('/a', (req) => { requireCan(record, user); db.update({id: req.params.id}); });\nrouter.patch('/b', (req) => { requireCan('module'); db.update({id: req.params.id}); });\nrouter.get('/a', (req) => { requireCan(record, user); return db.findUnique({id: req.params.id}); });\nrouter.get('/b', (req) => { requireCan(record, user); return db.findUnique({id: req.params.id}); });\nfunction requireCan(record, user) { if (!record.allowed(user)) throw Error(403); }"})
        hits = [f for f in data['findings'] if f['id'] == 'SEC-METHOD-ASYMMETRY']
        self.assertEqual([f['line'] for f in hits], [2])

    def test_local_advisory_proves_match_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repo'; root.mkdir()
            self.write(root, {'requirements.txt': 'example-lib==1.0.0\n'})
            advisory = Path(directory)/'advisory.json'
            advisory.write_text(json.dumps({'advisories':[{'package':'example-lib','versions':['1.0.0'],'severity':'critical'}]}))
            data = lenses.report(root, advisories=advisory)
            finding = next(f for f in data['owner_findings'] if f['id'] == 'SEC-DEPENDENCY')
            self.assertEqual(finding['severity'], 'critical')
            self.assertIn('exploitability unknown', finding['verification_reason'])
            self.assertEqual(len(finding['source_hash']), 64)
            self.assertFalse(data['verification']['project'])

    def test_comments_do_not_establish_scope(self):
        data = self.scan({'routes.ts': "router.get('/x', (req) => { checkOwnership(record, user); return db.findUnique({id: req.params.id}); });\nrouter.patch('/x', (req) => { /* checkOwnership(record, user); */ db.update({id: req.params.id}); });\nfunction checkOwnership(record, user) { if (!record.allowed(user)) throw Error(403); }"})
        self.assertTrue(any(f['id'] == 'SEC-METHOD-ASYMMETRY' for f in data['findings']))

    def test_verified_route_map_persistent_and_source_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); root = base/'repo'; root.mkdir()
            self.write(root, {'routes.ts': "router.get('/a', () => {});"})
            data = lenses.report(root)
            route = data['endpoints'][0]
            verdicts = base/'verdicts.json'
            verdicts.write_text(json.dumps(dict(schema_version=1, hunter='model-A', verifier='model-B', verdicts=[], routes=[dict(route_id=route['route_id'], auth_status='unguarded', reason='Sprawdzony cały łańcuch middleware.') ])))
            data = lenses.report(root, verdicts=verdicts, state_dir=base/'state')
            self.assertEqual(data['authz']['unprotected'], 1)
            self.assertEqual(data['endpoints'][0]['effective_guard']['status'], 'unguarded')
            reused = lenses.report(root, state_dir=base/'state')
            self.assertEqual(reused['authz']['unprotected'], 1)
            (root/'routes.ts').write_text("router.get('/a', () => { requireAuth(); });")
            data = lenses.report(root, state_dir=base/'state')
            self.assertEqual(data['authz']['unprotected'], 0)
            with self.assertRaises(ValueError):
                lenses.report(root, verdicts=verdicts, state_dir=base/'state')


if __name__ == '__main__':
    unittest.main()
