"""Local captures do not become delivery or application-route evidence."""
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
import test_runtime_sinks_pipeline as pipeline_fixture
from helix_runtime_sinks import project_sinks
from test_runtime_sinks import fixture_report


class OwnerRuntimeSinks(unittest.TestCase):
    def test_legacy_unknown_counts_are_distinct_from_unexecuted_current_plan(self):
        legacy = project_sinks({})
        pending = project_sinks(fixture_report('pending'))
        self.assertIsNone(legacy['counts']['captured_local'])
        self.assertEqual(pending['counts']['captured_local'], 0)
        self.assertIn('lokalne przyjęcia: nieznane', '\n'.join(owner.runtime_sinks_markdown(legacy)))
        self.assertIn('lokalne przyjęcia: 0', '\n'.join(owner.runtime_sinks_markdown(pending)))
        self.assertIn('nie został wykonany', owner.runtime_sinks_gap(pending))
        self.assertEqual(legacy['external_delivery'], 'NOT_RECORDED')

    def test_local_capture_keeps_delivery_and_application_routes_unverified(self):
        summary = project_sinks(fixture_report('captured'))
        self.assertGreater(summary['counts']['captured_local'], 0)
        self.assertEqual(summary['counts']['external_deliveries_verified'], 0)
        self.assertEqual(summary['counts']['application_routes_verified'], 0)
        text = '\n'.join(owner.runtime_sinks_markdown(summary))
        self.assertIn('Doręczenie zewnętrzne: **NOT_RUN**', text)
        self.assertIn('Przyjęcie do skrzynki jest emulacją', text)
        self.assertIsNotNone(owner.runtime_sinks_gap(summary))
        self.assertNotIn('**PASS**', text)

    def test_control_response_is_not_presented_as_an_accepted_message(self):
        report = fixture_report('captured')
        report['sink_observations'][0]['observations'][0].update(operation_id='play.token', provider='play-sms')
        summary = project_sinks(report)
        text = '\n'.join(owner.runtime_sinks_markdown(summary))
        self.assertEqual(summary['counts']['captured_local'], 0)
        self.assertIn('lokalne przyjęcia: 0', text)
        self.assertIn('play.token`: odpowiedzi kontrolne 1', text)
        self.assertNotIn('play.token`: przyjęcia 1', text)

    def test_rejection_remains_visible_with_its_operation_and_http_status(self):
        summary = project_sinks(fixture_report('rejected'))
        self.assertGreater(summary['counts']['rejected_local'], 0)
        row = next(row for part in summary['parts'] for row in part['observations']
                   if row['outcome'] == 'rejected_local')
        text = '\n'.join(owner.runtime_sinks_markdown(summary))
        self.assertIn(row['operation_id'], text)
        self.assertIn('HTTP ' + str(row['http_status']), text)
        self.assertIn('odmowy', text)

    def test_partial_observation_keeps_known_counts_and_configuration_gaps(self):
        summary = project_sinks(fixture_report('partial'))
        self.assertEqual(summary['execution_status'], 'PARTIAL')
        text = '\n'.join(owner.runtime_sinks_markdown(summary))
        self.assertIn('**PARTIAL**', text)
        self.assertIn('niepełne', owner.runtime_sinks_gap(summary))
        self.assertNotIn('**PASS**', text)
        self.assertIsNotNone(summary['counts']['captured_local'])

    def test_rendering_retains_all_places_and_does_not_modify_evidence(self):
        summary = project_sinks(fixture_report('captured', sibling=True))
        before = copy.deepcopy(summary)
        text = '\n'.join(owner.runtime_sinks_markdown(summary))
        for part in summary['parts']:
            self.assertIn(part['part'], text)
            for declaration in part['providers']:
                for evidence in declaration['evidence']:
                    self.assertIn(evidence['path'] + ':' + str(evidence['line']), text)
        self.assertEqual(summary, before)


    def run_fake(self, scenario='captured'):
        fixture = pipeline_fixture.RuntimeSinksPipeline()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        report = fixture.run_pipeline(scenario)
        return fixture, report

    @unittest.skipUnless(pipeline_fixture.NODE, 'Node unavailable')
    def test_actual_runner_capture_reaches_aggregate_without_payload_or_delivery_credit(self):
        fixture, _ = self.run_fake()
        result = owner.aggregate(fixture.project, [fixture.out])
        summary = result['groups'][0]['runtime_sinks'][0]
        self.assertEqual(summary['execution_status'], 'OBSERVED')
        self.assertEqual(summary['counts']['captured_local'], 1)
        self.assertEqual(summary['counts']['external_deliveries_verified'], 0)
        text = owner.markdown(result)
        self.assertIn('src/sender.ts:1', text)
        self.assertIn('Doręczenie zewnętrzne: **NOT_RUN**', text)
        self.assertNotIn('PRIVATE_MAILBOX_CANARY', text + json.dumps(result))
        self.assertNotIn('PRIVATE_CANARY', text + json.dumps(result))
        self.assertTrue(any('nie potwierdzają jeszcze wykonania tras' in gap['reason'] for gap in result['gaps']))

    @unittest.skipUnless(pipeline_fixture.NODE, 'Node unavailable')
    def test_imported_partial_capture_reaches_owner_current_with_a_gap_and_no_route_points(self):
        fixture, _ = self.run_fake('writer_failure')
        maturity = helix_pro.assess(fixture.project, 'XL')
        runtime.import_evidence(maturity, fixture.out / 'runtime-report.json', fixture.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(fixture.project, fixture.out, audit, {})
        result = json.loads((fixture.out / 'owner-current.json').read_text())
        self.assertEqual(result['runtime_sinks']['execution_status'], 'PARTIAL')
        self.assertEqual(result['runtime_sinks']['counts']['application_routes_verified'], 0)
        gap = next(gap for gap in result['gaps'] if gap['id'] == 'runtime_sinks:partial')
        self.assertIn('src/sender.ts:1', gap['evidence'])
        self.assertFalse(any(row['id'].startswith('runtime_sinks:') and row.get('score')
                             for row in result['controls']))
        self.assertNotIn('PRIVATE_MAILBOX_CANARY', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
