import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_static_security as security
import helix_lenses as lenses


class AuthzInferenceTests(unittest.TestCase):
    def scan(self, files, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                p = Path(tmp) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            return security.analyze(tmp, **kwargs)

    def test_custom_wrapper_and_global_hook(self):
        data = self.scan({
            'src/security.ts': 'export function wymagajSesji(event) { if (!event.locals.user) throw error(401); }\nexport function ensureStaff(event) { wymagajSesji(event); }',
            'src/hooks.server.ts': 'export const handle = async (event) => { ensureStaff(event); return resolve(event); };',
            'src/routes/(staff)/items/+server.ts': 'export const GET = async () => { return db.findMany(); };'})
        self.assertFalse([f for f in data['findings'] if f['id'] == 'SEC-AUTH'])
        self.assertTrue(data['endpoints'][-1]['guard_evidence'])
        self.assertEqual(data['endpoints'][-1]['auth_status'], 'unknown')

    def test_express_custom_guard_and_unprotected_route(self):
        data = self.scan({'routes.ts': '''function wymagajSesji(req) { if (!req.user) return res.status(403); }
router.use('/staff', wymagajSesji);
router.get('/staff/list', () => {});
router.get('/public-data', () => db.findMany());'''})
        routes = data['endpoints']
        self.assertTrue(routes[0]['guard_candidate'])
        self.assertFalse(routes[1]['guard_candidate'])
        alarm = next(f for f in data['findings'] if f['id'] == 'SEC-AUTH')
        self.assertEqual(alarm['count'], 1)
        self.assertEqual(alarm['line'], 4)
        self.assertNotEqual(alarm['severity'], 'high')

    def test_next_matcher_is_candidate_not_proof(self):
        data = self.scan({'middleware.ts': "function ensureStaff(req) { if (!req.user) throw error(403); }\nexport function middleware(req) { ensureStaff(req); }\nexport const config = {matcher: ['/staff/:path*']};",
                          'app/staff/route.ts': 'export function GET() { return db.findMany(); }'})
        self.assertFalse([f for f in data['findings'] if f['id'] == 'SEC-AUTH'])
        self.assertEqual(data['authz']['proven_protected'], 0)
        self.assertIn('≠', lenses.markdown(dict(lenses={}, coverage={}, findings=[], endpoints=[], rbac=[], reported_findings=[], offline_audits={}, limitations=[], authz=data['authz'])))

    def test_aggregation_sanity_and_severity(self):
        data = self.scan({'routes.ts': '\n'.join(f"router.get('/r{i}', () => {{}});" for i in range(40))})
        alarms = [f for f in data['findings'] if f['id'] == 'SEC-AUTH']
        self.assertEqual(len(alarms), 1)
        self.assertEqual(alarms[0]['count'], 40)
        self.assertEqual(len(alarms[0]['examples']), 5)
        self.assertTrue(alarms[0]['detector_suspect'])
        data = self.scan({'routes.ts': "router.get('/x', () => {});"}, auth_sanity_percent=100)
        self.assertFalse(data['authz']['detector_suspect'])
        self.assertEqual(security.finding('X','x','x','',0,'why','fix')['severity'], 'medium')

    def test_token_race_and_atomic_alternative(self):
        vulnerable = 'async function redeem() { const token = await db.findUnique(id); if (token.used) throw error(403); await db.update({used:true}); }'
        safe = 'async function redeem() { const token = await db.findUnique(id); if (token.used) throw error(403); await db.query(`UPDATE tokens SET used=true WHERE used=false RETURNING id`); }'
        data = self.scan({'unsafe.ts': vulnerable, 'safe.ts': safe})
        alarms = [f for f in data['findings'] if f['id'] == 'SEC-TOKEN-TOCTOU']
        self.assertEqual([f['file'] for f in alarms], ['unsafe.ts'])
        self.assertEqual(alarms[0]['line'], 1)
        self.assertEqual(alarms[0]['confidence'], 'possible')

    def test_guard_in_another_handler_is_not_inherited(self):
        data = self.scan({'routes.ts': "function nazwany(req) { if (!req.user) throw error(401); }\nrouter.get('/a', (req) => { nazwany(req); });\nrouter.get('/b', (req) => { return db.findMany(); });"})
        self.assertTrue(data['endpoints'][0]['guard_candidate'])
        self.assertFalse(data['endpoints'][1]['guard_candidate'])

    def test_toctou_line_and_unrelated_transaction(self):
        data = self.scan({'tokens.ts': "function other() { db.transaction(() => {}); }\nasync function redeem() {\n const token = await db.findUnique(id);\n if (token.used) throw error(403);\n await db.update({used:true});\n}"})
        alarm = next(f for f in data['findings'] if f['id'] == 'SEC-TOKEN-TOCTOU')
        self.assertEqual(alarm['line'], 3)

    def test_report_forwards_sanity_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'routes.ts').write_text("router.get('/x', () => {});")
            data = lenses.report(tmp, auth_sanity_percent=100)
            self.assertFalse(data['authz']['detector_suspect'])
        with self.assertRaises(ValueError):
            self.scan({'route.ts': 'export function GET() {}'}, auth_sanity_percent=101)
