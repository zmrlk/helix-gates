"""Owner output distinguishes matrix evidence, unresolved scope and failed cases."""
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
from helix_runtime_identity_policy_run import project_policy_execution
from test_runtime_identity_policy_run import fixture_report
import test_runtime_policy_execution_pipeline as pipeline_fixture


class OwnerRuntimePolicyExecution(unittest.TestCase):
    def run_fake(self, scenario=None):
        fixture = pipeline_fixture.RuntimePolicyExecutionPipeline()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.setup_identity()
        fixture.executor.scenario = scenario or {}
        fixture.run_pipeline()
        return fixture

    def test_completed_matrix_keeps_unconfigured_identities_visible(self):
        report = fixture_report(state='pass')
        summary = project_policy_execution(report)
        before = copy.deepcopy(summary)
        text = '\n'.join(owner.runtime_policy_markdown(summary))
        self.assertIn('wykonanie **COMPLETE**', text)
        self.assertIn('wynik wymaganej macierzy **PASS**', text)
        self.assertIn('Tożsamości bez zadeklarowanych przypadków:', text)
        self.assertEqual(owner.runtime_policy_gap(summary)[0], 'outside-scope')
        self.assertEqual(summary, before)
        self.assertNotIn('Sesja aplikacji: NOT_RUN', text)

    def test_failed_observation_does_not_disappear_inside_partial_coverage(self):
        summary = project_policy_execution(fixture_report(state='partial_failure'))
        self.assertGreater(summary['counts']['failed_cells'], 0)
        self.assertEqual(summary['execution_status'], 'INCOMPLETE')
        text = '\n'.join(owner.runtime_policy_markdown(summary))
        self.assertIn('wykonanie **INCOMPLETE**', text)
        self.assertIn('wynik wymaganej macierzy **FAIL**', text)
        self.assertIn('FAIL: ' + str(summary['counts']['failed_cells']), text)
        self.assertEqual(owner.runtime_policy_gap(summary)[0], 'failed')

    def test_pending_receipt_does_not_claim_execution_or_success(self):
        summary = project_policy_execution(fixture_report(state='pending'))
        text = '\n'.join(owner.runtime_policy_markdown(summary))
        self.assertEqual(summary['counts']['completed_cells'], 0)
        self.assertIn('wykonane: 0', text)
        self.assertNotIn('wynik wymaganej macierzy **PASS**', text)
        self.assertEqual(owner.runtime_policy_gap(summary)[0], 'unexecuted')

    def test_legacy_absence_keeps_unknown_execution_counts(self):
        summary = project_policy_execution({})
        text = '\n'.join(owner.runtime_policy_markdown(summary))
        self.assertIn('wykonane: nieznane', text)
        self.assertIn('Sesje zakończone: nieznane z nieznane', text)
        self.assertNotIn('wykonane: 0', text)
        self.assertEqual(summary['execution_status'], 'NOT_RECORDED')

    def test_actual_runner_matrix_reaches_aggregate_without_private_values_or_global_pass(self):
        fixture = self.run_fake()
        result = owner.aggregate(fixture.project, [fixture.out])
        summary = result['groups'][0]['runtime_identity_policy'][0]
        self.assertEqual(summary['execution_status'], 'COMPLETE')
        self.assertEqual(summary['outcome'], 'PASS')
        self.assertEqual(summary['counts']['completed_cells'], 2)
        self.assertTrue(any('tożsamości bez przypadków' in gap['reason'] for gap in result['gaps']))
        self.assertNotEqual(result['groups'][0]['runs'][0]['status'], 'PASS')
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', json.dumps(result))
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', owner.markdown(result))

    def test_actual_runner_session_failure_remains_visible_in_aggregate(self):
        fixture = self.run_fake({'sessionMismatch': True})
        result = owner.aggregate(fixture.project, [fixture.out])
        summary = result['groups'][0]['runtime_identity_policy'][0]
        self.assertEqual(summary['execution_status'], 'INCOMPLETE')
        self.assertEqual(summary['outcome'], 'FAIL')
        self.assertGreater(summary['counts']['failed_cells'], 0)
        text = owner.markdown(result)
        self.assertIn('wynik wymaganej macierzy **FAIL**', text)
        self.assertIn('wykonanie **INCOMPLETE**', text)

    def test_imported_execution_reaches_owner_current_and_preserves_scope_gap(self):
        fixture = self.run_fake()
        maturity = helix_pro.assess(fixture.project, 'XL')
        runtime.import_evidence(maturity, fixture.out / 'runtime-report.json', fixture.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(fixture.project, fixture.out, audit, {})
        result = json.loads((fixture.out / 'owner-current.json').read_text())
        self.assertEqual(result['runtime_identity_policy']['outcome'], 'PASS')
        self.assertTrue(any(gap['id'] == 'runtime_identity_policy:outside-scope' for gap in result['gaps']))
        self.assertFalse(any(gap['id'] == 'runtime_identity_policy:unexecuted' for gap in result['gaps']))
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
