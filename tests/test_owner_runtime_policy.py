"""A declared policy matrix is visible to the owner, with no execution credit."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))

import helix_owner_report as owner
import helix_config
import helix_pro
import helix_runtime as runtime
from helix_runtime_identity_policy_run import project_policy_execution
import test_runtime_identity_policy as policy_fixture
import test_runtime_keycloak_pipeline as runtime_fixture


class OwnerRuntimePolicy(unittest.TestCase):
    def policy(self):
        fixture = policy_fixture.RuntimeIdentityPolicy()
        fixture.setUp()
        fixture.raw['cells'].append(fixture.cell('editor', 'editor-list'))
        return fixture

    def projection(self, fixture):
        return project_policy_execution(dict(identity_policy_plan=fixture.compile(), identity_policy_receipts=[],
                                        identity_plan=fixture.identities, parts=fixture.parts))

    def run_fake(self):
        fixture = runtime_fixture.RuntimeKeycloakPipeline()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.app()
        fixture.parts['frontend']['roles'] = ['reader', 'editor']
        config = fixture.configure()
        config['runtime']['identity_policy'] = self.policy().config['runtime']['identity_policy']
        fixture.config_path.write_text(json.dumps(config))
        helix_config.configure(fixture.project, fixture.config_path)
        report = fixture.run_pipeline()
        return fixture, report

    def test_legacy_unknown_counts_are_not_printed_as_zero(self):
        summary = project_policy_execution({})
        text = '\n'.join(owner.runtime_policy_markdown(summary))
        self.assertIn('NOT_RECORDED', text)
        self.assertIn('wykonane: nieznane', text)
        self.assertNotIn('wykonane: 0', text)

    def test_same_route_has_named_roles_and_two_unexecuted_cells_without_literal_values(self):
        fixture = self.policy()
        summary = self.projection(fixture)
        text = '\n'.join(owner.runtime_policy_markdown(summary))
        self.assertIn('reader', text)
        self.assertIn('editor', text)
        self.assertIn('wykonanie **NOT_RUN**', text)
        self.assertIn('rola/trasa: 2; wykonane: 0; niesprawdzone: 2', text)
        self.assertNotIn('wynik wymaganej macierzy **PASS**', text)
        for value in (fixture.compile(), summary, text):
            self.assertNotIn('PRIVATE_CANARY_ASSERTION', json.dumps(value))

    def test_unknown_role_is_retained_as_blocked_without_reflecting_raw_role(self):
        fixture = self.policy()
        fixture.raw['cells'].append(fixture.cell('PRIVATE_UNKNOWN_ROLE', 'unresolved-case'))
        summary = self.projection(fixture)
        text = '\n'.join(owner.runtime_policy_markdown(summary))
        self.assertEqual(summary['counts']['blocked_cells'], 1)
        self.assertIn('unresolved-case', text)
        self.assertIn('nierozpoznana rola', text)
        self.assertNotIn('PRIVATE_UNKNOWN_ROLE', text)
        self.assertNotIn('PRIVATE_UNKNOWN_ROLE', json.dumps(summary))

    def test_actual_runtime_plan_and_owner_aggregation_keep_no_execution_credit(self):
        fixture, report = self.run_fake()
        result = owner.aggregate(fixture.project, [fixture.out])
        summary = result['groups'][0]['runtime_identity_policy'][0]
        self.assertEqual(summary['plan_status'], 'PLANNED')
        self.assertEqual(summary['counts']['required_cells'], 2)
        self.assertEqual(summary['counts']['completed_cells'], 0)
        self.assertTrue(any('Polityka sesji i tras' in gap['reason'] for gap in result['gaps']))
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', json.dumps(report))
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', json.dumps(result))
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', owner.markdown(result))

    def test_imported_policy_reaches_owner_current_as_pending_with_no_points(self):
        fixture, _ = self.run_fake()
        maturity = helix_pro.assess(fixture.project, 'XL')
        runtime.import_evidence(maturity, fixture.out / 'runtime-report.json', fixture.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(fixture.project, fixture.out, audit, {})
        result = json.loads((fixture.out / 'owner-current.json').read_text())
        self.assertEqual(result['runtime_identity_policy']['execution_status'], 'NOT_RUN')
        gap = next(gap for gap in result['gaps'] if gap['id'] == 'runtime_identity_policy:unexecuted')
        self.assertIn('/runtime/identity_policy/parts/frontend', gap['evidence'])
        self.assertFalse(any(row['id'].startswith('runtime_identity_policy:') and row.get('score')
                             for row in result['controls']))
        self.assertNotIn('PRIVATE_CANARY_ASSERTION', json.dumps(result))

    def test_unsupported_execution_receipt_is_not_accepted_by_owner(self):
        fixture, report = self.run_fake()
        report['identity_policy_receipts'] = [{'status': 'PASS', 'secret': 'PRIVATE_RECEIPT_VALUE'}]
        (fixture.out / 'runtime-report.json').write_text(json.dumps(report))
        result = owner.aggregate(fixture.project, [fixture.out])
        self.assertEqual(result['groups'][0]['runtime_identity_policy'], [])
        self.assertTrue(any('Nieprawidłowy kontrakt runtime' in gap['reason'] for gap in result['gaps']))
        self.assertNotIn('PRIVATE_RECEIPT_VALUE', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
