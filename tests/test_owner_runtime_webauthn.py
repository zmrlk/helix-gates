"""A WebAuthn declaration or plan never grants ceremony credit to the owner."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))

import helix_owner_report as owner
import helix_pro
import helix_runtime as runtime
import helix_runtime_webauthn as webauthn
import test_owner_runtime_projection as runtime_fixture
import test_runtime_webauthn as fixture


class OwnerRuntimeWebAuthn(unittest.TestCase):
    def run_fake(self, *, dependency=True, config=None):
        case = runtime_fixture.OwnerRuntimeProjection()
        case.setUp()
        self.addCleanup(case.doCleanups)
        if dependency:
            package = case.project / 'package.json'
            data = json.loads(package.read_text())
            data.setdefault('dependencies', {})['@simplewebauthn/browser'] = '^13.3.0'
            package.write_text(json.dumps(data, indent=2))
        if config is not None:
            (case.project / 'helix.json').write_text(json.dumps(config))
        return case, case.run_fake(cookie=False)

    def imported_owner(self, case):
        maturity = helix_pro.assess(case.project, 'XL')
        runtime.import_evidence(maturity, case.out / 'runtime-report.json', case.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(case.project, case.out, audit, {})
        return json.loads((case.out / 'owner-current.json').read_text())

    def test_dependency_is_explained_with_all_locations_and_no_execution(self):
        summary = webauthn.project_webauthn_plan(fixture.fixture_report('dependency'))
        text = '\n'.join(owner.runtime_webauthn_markdown(summary))
        self.assertIn('brak opisanego przebiegu rejestracji i logowania', text)
        self.assertIn('wykonanie **NOT_RUN**', text)
        self.assertIn('Wykonane ceremonie: 0', text)
        self.assertIn('^13.3.0', text)
        for part in summary['parts']:
            for declaration in part['declarations']:
                for place in declaration['evidence']:
                    self.assertIn(place['path'] + ':' + str(place['line']), text)

    def test_disabled_remains_visible_as_unexecuted_gap(self):
        summary = webauthn.project_webauthn_plan(fixture.fixture_report('disabled'))
        text = '\n'.join(owner.runtime_webauthn_markdown(summary))
        self.assertIn('plan **DISABLED**', text)
        self.assertIn('jawnie wyłączona', text)
        self.assertIn('pokrycie **INCOMPLETE**', text)
        self.assertIn('Wykonane ceremonie: 0', text)

    def test_planned_profile_and_private_assertion_do_not_grant_ceremony_pass(self):
        args = fixture.fixture_inputs()
        args[-1]['runtime']['webauthn']['parts']['frontend']['registration']['verify']['json'][0]['equals_literal'] = 'PRIVATE_WEBAUTHN_CANARY'
        report = fixture.fixture_report()
        report['webauthn_plan'] = webauthn.webauthn_plan(*args)
        summary = webauthn.project_webauthn_plan(report)
        text = '\n'.join(owner.runtime_webauthn_markdown(summary))
        self.assertIn('plan **PLANNED**', text)
        self.assertIn('rejestracje PASS: 0; uwierzytelnienia PASS: 0', text)
        self.assertNotIn('PRIVATE_WEBAUTHN_CANARY', text)
        self.assertNotIn('PRIVATE_WEBAUTHN_CANARY', json.dumps(summary))

    def test_legacy_absence_does_not_become_known_zero(self):
        text = '\n'.join(owner.runtime_webauthn_markdown(webauthn.project_webauthn_plan({})))
        self.assertIn('NOT_RECORDED', text)
        self.assertIn('Wykonane ceremonie: nieznane', text)
        self.assertNotIn('Wykonane ceremonie: 0', text)

    def test_real_runner_and_aggregate_keep_dependency_gap(self):
        case, _ = self.run_fake()
        result = owner.aggregate(case.project, [case.out])
        summary = result['groups'][0]['runtime_webauthn'][0]
        self.assertEqual(summary['plan_status'], 'BLOCKED')
        self.assertEqual(summary['counts']['completed_flows'], 0)
        self.assertEqual(summary['counts']['registration_pass'], 0)
        self.assertEqual(summary['counts']['authentication_pass'], 0)
        self.assertTrue(any('WebAuthn: plan BLOCKED' in gap['reason'] for gap in result['gaps']))
        self.assertIn('brak opisanego przebiegu rejestracji i logowania', owner.markdown(result))

    def test_imported_plan_reaches_owner_current_without_points(self):
        case, _ = self.run_fake()
        result = self.imported_owner(case)
        self.assertEqual(result['runtime_webauthn']['execution_status'], 'NOT_RUN')
        gap = next(gap for gap in result['gaps'] if gap['id'] == 'runtime_webauthn:unexecuted')
        self.assertTrue(any(place.startswith('package.json:') for place in gap['evidence']))
        self.assertFalse(any(row['id'].startswith('runtime_webauthn:') and row.get('score') for row in result['controls']))

    def test_explicit_config_without_dependency_retains_its_evidence_pointer(self):
        case, _ = self.run_fake(dependency=False, config={'runtime': {'webauthn': {
            'schema_version': 1, 'parts': {'.': {'enabled': False}}}}})
        result = self.imported_owner(case)
        self.assertEqual(result['runtime_webauthn']['plan_status'], 'DISABLED')
        gap = next(gap for gap in result['gaps'] if gap['id'] == 'runtime_webauthn:unexecuted')
        self.assertIn('/runtime/webauthn/parts/.', gap['evidence'])

    def test_unsupported_ceremony_receipt_rejects_runtime_projection(self):
        case, report = self.run_fake()
        report['webauthn_receipts'] = [{'status': 'PASS', 'privateKey': 'PRIVATE_WEBAUTHN_CANARY'}]
        (case.out / 'runtime-report.json').write_text(json.dumps(report))
        result = owner.aggregate(case.project, [case.out])
        self.assertEqual(result['groups'][0]['runtime_webauthn'], [])
        self.assertTrue(any('Nieprawidłowy kontrakt runtime' in gap['reason'] for gap in result['gaps']))
        self.assertNotIn('PRIVATE_WEBAUTHN_CANARY', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
