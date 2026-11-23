"""Owner reports retain runtime gaps without converting phase observations to credit."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))

import helix_owner_report as owner
import helix_pro
import helix_runtime as runtime
import helix_runtime_login as login
import test_runtime as fixture
import test_runtime_identity_projection as identity_fixture


class OwnerRuntimeProjection(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.project, self.out = self.base / 'project', self.base / 'out'
        shutil.copytree(fixture.FIX / 'sveltekit-pg', self.project)

    def run_fake(self, cookie=True):
        if cookie:
            (self.project / 'src/cookie.ts').write_text("cookies.set('synthetic', 'opaque', {secure: true});\n")
        runner = runtime.Runner(self.project, self.out, executor=fixture.FakeExecutor(),
                                tools={'tools': dict(fixture.TOOLS)}, port_factory=lambda: 31234)
        return runner.run()

    def save(self, report):
        path = self.out / 'runtime-report.json'
        path.write_text(json.dumps(report))
        return path

    def test_transport_gap_survives_owner_aggregation_with_source_location(self):
        report = self.run_fake()
        self.assertEqual(report['transport_coverage'], 'INCOMPLETE')
        result = owner.aggregate(self.project, [self.out])
        transport = result['groups'][0]['runtime_transport'][0]
        self.assertEqual(transport['status'], 'INCOMPLETE')
        self.assertTrue(any(g['kind'] == 'https_not_enabled' for p in transport['parts'] for g in p['gaps']))
        text = owner.markdown(result)
        self.assertIn('Transport runtime: **INCOMPLETE**', text)
        self.assertIn('https_not_enabled', text)
        self.assertIn('src/cookie.ts:1', text)
        self.assertTrue(any('Transport runtime: INCOMPLETE' in gap['reason'] for gap in result['gaps']))

    def test_failed_check_reaches_attention_with_and_without_controls(self):
        # G3 16.11: controls jest opcjonalne; FAIL z parts[].checks nie może zniknąć z góry raportu.
        report = self.run_fake()
        report['parts'][0]['checks']['lighthouse'].update(status='FAIL', reason='lcp_ms=2881 vs budget 2500')
        for controls in (True, False):
            with self.subTest(controls=controls):
                data = copy.deepcopy(report)
                if controls: next(c for c in data['controls'] if c['id'] == 'lighthouse').update(status='FAIL', reason='lcp_ms=2881 vs budget 2500')
                else: data.pop('controls', None)
                self.save(data)
                text = owner.evidence_markdown(owner.aggregate(self.project, [self.out]))
                attention = text.split('## Co wymaga uwagi')[1].split('## Wyniki')[0]
                self.assertIn('runtime lighthouse (lcp_ms=2881 vs budget 2500): FAIL', attention)
                self.assertNotIn('Brak zgłoszonego FAIL/ERROR', attention)

    def test_absent_keycloak_declaration_does_not_invent_missing_login(self):
        self.run_fake(cookie=False)
        result = owner.aggregate(self.project, [self.out])
        identity = result['groups'][0]['runtime_identity'][0]
        self.assertEqual(identity['status'], 'NOT_DETECTED')
        self.assertFalse(any('Fazy tożsamości runtime' in gap['reason'] for gap in result['gaps']))
        self.assertIn('Nie wykryto Keycloaka', owner.markdown(result))

    def test_legacy_missing_metadata_remains_not_recorded(self):
        report = self.run_fake(cookie=False)
        for key in ('transport_plan', 'transport_coverage', 'identity_plan', 'identity_forms', 'identity_coverage',
                    'identity_policy_plan', 'identity_policy_receipts', 'identity_policy_executions', 'identity_assessment',
                    'webauthn_plan', 'webauthn_receipts', 'webauthn_executions', 'webauthn_coverage'):
            report.pop(key, None)
        for part in report['parts']:
            part.pop('transport', None)
        self.save(report)
        result = owner.aggregate(self.project, [self.out])
        for key in ('runtime_transport', 'runtime_identity'):
            self.assertEqual(result['groups'][0][key][0]['status'], 'NOT_RECORDED')
        self.assertIn('Brak zapisu transportu', owner.markdown(result))

    def test_policy_without_its_identity_plan_is_not_treated_as_legacy(self):
        report = self.run_fake(cookie=False)
        report.pop('identity_plan')
        self.save(report)
        result = owner.aggregate(self.project, [self.out])
        self.assertEqual(result['groups'][0]['runtime_identity_policy'], [])
        self.assertTrue(any('Nieprawidłowy kontrakt runtime' in gap['reason'] for gap in result['gaps']))

    def test_contradictory_transport_artifact_is_rejected_without_partial_credit(self):
        report = self.run_fake()
        report.update(transport_coverage='RECORDED', status='PASS')
        self.save(report)
        result = owner.aggregate(self.project, [self.out])
        self.assertEqual(result['groups'][0]['runtime_transport'], [])
        self.assertEqual(result['groups'][0]['runtime_identity'], [])
        self.assertTrue(any('Nieprawidłowy kontrakt runtime' in gap['reason'] for gap in result['gaps']))

    def test_generated_private_fields_do_not_enter_owner_projection(self):
        report = self.run_fake()
        report['private_material'] = {'password': 'CANARY_PRIVATE_RUNTIME_VALUE'}
        report['parts'][0]['transport']['reason'] = 'CANARY_PRIVATE_RUNTIME_VALUE'
        self.save(report)
        result = owner.aggregate(self.project, [self.out])
        self.assertTrue(result['groups'][0]['runtime_transport'])
        self.assertNotIn('CANARY_PRIVATE_RUNTIME_VALUE', json.dumps(result))
        self.assertNotIn('CANARY_PRIVATE_RUNTIME_VALUE', owner.markdown(result))

    def test_form_phase_pass_does_not_claim_session_or_role_access(self):
        projection = login.project_identity(identity_fixture.public_fixture())
        before = copy.deepcopy(projection)
        text = '\n'.join(owner.runtime_boundary_markdown(identity=projection))
        self.assertIn('Formularz i fazy OIDC: **PASS**; pokrycie: **INCOMPLETE**', text)
        self.assertIn('Sesję oraz uprawnienia dokumentuje osobny wynik polityki', text)
        self.assertIn('no-app-role', text)
        self.assertIn('unverified-email', text)
        self.assertEqual(projection, before)
        self.assertNotIn('logowanie działa', text)

    def test_imported_transport_gap_reaches_owner_current_without_execution_points(self):
        self.run_fake()
        maturity = helix_pro.assess(self.project, 'XL')
        runtime.import_evidence(maturity, self.out / 'runtime-report.json', self.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(self.project, self.out, audit, {})
        result = json.loads((self.out / 'owner-current.json').read_text())
        self.assertEqual(result['runtime_transport']['status'], 'INCOMPLETE')
        self.assertTrue(any(gap['id'].startswith('runtime_transport:') for gap in result['gaps']))
        self.assertFalse(any(row['id'].startswith(('runtime_transport:', 'runtime_identity:')) and row.get('score')
                             for row in result['controls']))
        self.assertIn('Transport runtime: **INCOMPLETE**', (self.out / 'owner-current.md').read_text())


if __name__ == '__main__':
    unittest.main()
