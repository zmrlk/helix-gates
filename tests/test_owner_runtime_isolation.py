"""Owner output keeps admission, invocation and OS evidence separate."""
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
import test_runtime_extensions_pipeline as pipeline_fixture


def public_summary(status, records=()):
    """Use the same validated projection as a runtime import."""
    return runtime.project_network_isolation(dict(network_isolation=dict(
        schema_version=1, scope='project_processes_and_owned_database',
        status=status, records=list(records))))


class OwnerRuntimeIsolation(unittest.TestCase):
    def run_fake(self):
        fixture = pipeline_fixture.RuntimeExtensionsPipeline()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        report = fixture.run_pipeline()
        return fixture, report

    def test_historical_absence_is_unknown_and_empty_current_admission_is_not_run(self):
        historical = runtime.project_network_isolation({})
        current = public_summary('NOT_RUN')
        self.assertEqual(historical['status'], 'NOT_RECORDED')
        self.assertIsNone(historical['counts']['invoked'])
        self.assertEqual(current['counts']['invoked'], 0)
        self.assertIn('wywołane polecenia: nieznane', '\n'.join(owner.runtime_network_markdown(historical)))
        self.assertIn('wywołane polecenia: 0', '\n'.join(owner.runtime_network_markdown(current)))
        self.assertIn('Historyczny', owner.runtime_network_gap(historical))
        self.assertIn('Nie sprawdzono', owner.runtime_network_gap(current))

    def test_fake_runner_aggregate_preserves_simulation_and_each_phase_without_os_credit(self):
        fixture, report = self.run_fake()
        summary = runtime.project_network_isolation(report)
        self.assertEqual(summary['status'], 'SIMULATED')
        self.assertEqual(summary['coverage_status'], 'INCOMPLETE')
        self.assertGreater(summary['counts']['simulated'], 0)
        self.assertEqual(summary['counts']['enforced'], 0)
        self.assertNotEqual(report['status'], 'PASS')
        result = owner.aggregate(fixture.project, [fixture.current.out])
        saved = result['groups'][0]['runtime_network_isolation'][0]
        self.assertEqual(saved['counts'], summary['counts'])
        text = owner.markdown(result)
        self.assertIn('Dowód OS: 0', text)
        self.assertIn('atrapa testowa', text)
        self.assertIn('serwer bazy', text)
        self.assertTrue(any('Atrapa potwierdza test wykonawcy' in gap['reason'] for gap in result['gaps']))

    def test_blocked_server_reports_admission_reason_and_no_invocation(self):
        row = dict(phase='database_server', scope='database_server', enforcement='blocked',
                   proof_kind='none', backend='unsupported', reason_code='DATABASE_SERVER_UNSUPPORTED',
                   policy_hash=None, command_invoked=False)
        summary = public_summary('BLOCKED', [row])
        text = '\n'.join(owner.runtime_network_markdown(summary))
        self.assertIn('serwer bazy', text)
        self.assertIn('DATABASE_SERVER_UNSUPPORTED', text)
        self.assertIn('odmowy: 1; wywołane polecenia: 0', text)
        self.assertEqual(summary['counts']['enforced'], 0)
        self.assertIn('Odmowa izolacji', owner.runtime_network_gap(summary))

    def test_enforced_database_does_not_hide_blocked_application(self):
        server = dict(phase='database_server', scope='database_server', enforcement='enforced',
                      proof_kind='execution', backend='macos-seatbelt', reason_code='LOCAL_PROBE_PASSED',
                      policy_hash='a' * 64, command_invoked=True)
        app = dict(phase='application', scope='project', enforcement='blocked', proof_kind='none',
                   backend='macos-seatbelt', reason_code='PROBE_DENIED', policy_hash='b' * 64,
                   command_invoked=False)
        summary = public_summary('BLOCKED', [server, app])
        self.assertEqual(summary['coverage_status'], 'INCOMPLETE')
        self.assertEqual(summary['counts']['enforced'], 1)
        self.assertEqual(summary['counts']['blocked'], 1)
        self.assertIsNotNone(owner.runtime_network_gap(summary))
        text = '\n'.join(owner.runtime_network_markdown(summary))
        self.assertIn('System odmówił wykonania sondy', text)
        self.assertIn('aplikacja / projekt', text)
        self.assertIn('Dowód OS: 1', text)

    def test_grouped_display_retains_full_records_without_changing_projection(self):
        _, report = self.run_fake()
        summary = runtime.project_network_isolation(report)
        before = copy.deepcopy(summary)
        text = '\n'.join(owner.runtime_network_markdown(summary))
        self.assertIn('Dopuszczenie procesu nie potwierdza działania aplikacji', text)
        self.assertIn('| Faza / zakres |', text)
        self.assertEqual(summary, before)
        self.assertEqual(len(summary['records']), len(report['network_isolation']['records']))

    def test_imported_simulation_remains_owner_gap_with_no_isolation_points(self):
        fixture, _ = self.run_fake()
        maturity = helix_pro.assess(fixture.project, 'XL')
        runtime.import_evidence(maturity, fixture.current.out / 'runtime-report.json', fixture.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(fixture.project, fixture.current.out, audit, {})
        result = json.loads((fixture.current.out / 'owner-current.json').read_text())
        summary = result['runtime_network_isolation']
        self.assertEqual(summary['status'], 'SIMULATED')
        self.assertEqual(summary['counts']['enforced'], 0)
        self.assertTrue(any(gap['id'] == 'runtime_network_isolation:simulated' for gap in result['gaps']))
        self.assertFalse(any(row['id'].startswith('runtime_network_isolation:') and row.get('score')
                             for row in result['controls']))


if __name__ == '__main__':
    unittest.main()
