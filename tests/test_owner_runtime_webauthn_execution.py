"""Owner output uses the validated flow result, not the virtual device profile."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))

import helix_owner_report as owner
import helix_pro
import helix_runtime as runtime
from helix_runtime_webauthn_run import project_webauthn_execution
from test_runtime_webauthn_run import fixture_report
import test_runtime_webauthn_execution_pipeline as pipeline_fixture


class OwnerRuntimeWebAuthnExecution(unittest.TestCase):
    def run_fake(self, scenario=None):
        fixture = pipeline_fixture.RuntimeWebAuthnExecutionPipeline()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.setup_identity()
        fixture.executor.scenario = scenario or {}
        fixture.run_pipeline()
        return fixture

    def test_complete_flow_has_scoped_result_and_preserves_locations(self):
        summary = project_webauthn_execution(fixture_report('pass'))
        before = copy.deepcopy(summary)
        text = '\n'.join(owner.runtime_webauthn_markdown(summary))
        self.assertIn('wykonanie **COMPLETE**', text)
        self.assertIn('Wynik wybranego przebiegu: **PASS**', text)
        self.assertIn('Przebiegi zakończone: 1 z 1', text)
        self.assertIn('Rejestracje PASS: 1; uwierzytelnienia PASS: 1', text)
        self.assertIn('Nie potwierdza pozostałych ról', text)
        self.assertIn('Nowa sesja: PASS', text)
        self.assertIsNone(owner.runtime_webauthn_gap(summary))
        for part in summary['parts']:
            self.assertIn(part['config_pointer'], text)
            for declaration in part['declarations']:
                for place in declaration['evidence']:
                    self.assertIn(place['path'] + ':' + str(place['line']), text)
        self.assertEqual(summary, before)

    def test_failed_observation_survives_partial_execution(self):
        summary = project_webauthn_execution(fixture_report('partial_failure'))
        text = '\n'.join(owner.runtime_webauthn_markdown(summary))
        self.assertIn('wykonanie **INCOMPLETE**', text)
        self.assertIn('Wynik wybranego przebiegu: **FAIL**', text)
        self.assertEqual(owner.runtime_webauthn_gap(summary)[0], 'failed')
        self.assertEqual(summary['counts']['completed_flows'], 0)

    def test_interrupted_cleanup_preserves_observation_without_positive_credit(self):
        summary = project_webauthn_execution(fixture_report('cleanup_unknown'))
        text = '\n'.join(owner.runtime_webauthn_markdown(summary))
        self.assertEqual(summary['counts']['completed_flows'], 0)
        self.assertEqual(summary['counts']['registration_pass'], 0)
        self.assertEqual(summary['counts']['authentication_pass'], 0)
        self.assertIn('zachowana obserwacja PASS', text)
        self.assertIn('Zamknięcie własnych zasobów:', text)
        self.assertNotIn('Wynik wybranego przebiegu: **PASS**', text)
        self.assertEqual(owner.runtime_webauthn_gap(summary)[0], 'unexecuted')

    def test_pending_plan_has_known_zero_but_legacy_is_unknown(self):
        pending = project_webauthn_execution(fixture_report('pending'))
        legacy = project_webauthn_execution({})
        self.assertIn('Przebiegi zakończone: 0 z 1', '\n'.join(owner.runtime_webauthn_markdown(pending)))
        self.assertIn('Przebiegi zakończone: nieznane z nieznane', '\n'.join(owner.runtime_webauthn_markdown(legacy)))
        self.assertEqual(legacy['execution_status'], 'NOT_RECORDED')
        self.assertEqual(owner.runtime_webauthn_gap(pending)[0], 'unexecuted')

    def test_completed_failure_is_coverage_not_success(self):
        summary = project_webauthn_execution(fixture_report('cell_failure'))
        text = '\n'.join(owner.runtime_webauthn_markdown(summary))
        self.assertIn('wykonanie **COMPLETE**', text)
        self.assertIn('pokrycie **RECORDED**', text)
        self.assertIn('Wynik wybranego przebiegu: **FAIL**', text)
        self.assertEqual(summary['counts']['failed_cells'], 1)
        self.assertEqual(owner.runtime_webauthn_gap(summary)[0], 'failed')

    def test_actual_runner_flow_reaches_aggregate_without_global_runtime_pass(self):
        fixture = self.run_fake()
        result = owner.aggregate(fixture.project, [fixture.out])
        summary = result['groups'][0]['runtime_webauthn'][0]
        self.assertEqual(summary['execution_status'], 'COMPLETE')
        self.assertEqual(summary['outcome'], 'PASS')
        self.assertEqual(summary['counts']['completed_flows'], 1)
        self.assertFalse(any(gap['reason'].startswith('WebAuthn:') for gap in result['gaps']))
        self.assertNotEqual(result['groups'][0]['runs'][0]['status'], 'PASS')
        self.assertNotIn('synthetic-private-password', json.dumps(result))
        self.assertNotIn('PRIVATE_CANARY', owner.markdown(result))

    def test_actual_runner_failed_session_remains_visible_in_partial_aggregate(self):
        fixture = self.run_fake({'postRolesMismatch': True})
        result = owner.aggregate(fixture.project, [fixture.out])
        summary = result['groups'][0]['runtime_webauthn'][0]
        self.assertEqual(summary['execution_status'], 'INCOMPLETE')
        self.assertEqual(summary['outcome'], 'FAIL')
        self.assertIn('Nowa sesja: FAIL', owner.markdown(result))
        self.assertIn('Role nowej sesji nie zgadzają się z kontraktem.', owner.markdown(result))
        self.assertTrue(any('WebAuthn:' in gap['reason'] and 'FAIL' in gap['reason'] for gap in result['gaps']))

    def test_imported_unknown_cleanup_does_not_grant_points_or_pass(self):
        fixture = self.run_fake({'removeFailure': True})
        maturity = helix_pro.assess(fixture.project, 'XL')
        runtime.import_evidence(maturity, fixture.out / 'runtime-report.json', fixture.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(fixture.project, fixture.out, audit, {})
        result = json.loads((fixture.out / 'owner-current.json').read_text())
        summary = result['runtime_webauthn']
        self.assertEqual(summary['counts']['completed_flows'], 0)
        self.assertEqual(summary['counts']['authentication_pass'], 0)
        self.assertEqual(summary['parts'][0]['authentication']['observation_status'], 'PASS')
        self.assertTrue(any(gap['id'] == 'runtime_webauthn:unexecuted' for gap in result['gaps']))
        self.assertFalse(any(row['id'].startswith('runtime_webauthn:') and row.get('score') for row in result['controls']))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
