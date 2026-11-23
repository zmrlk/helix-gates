"""Catalog readiness and missing requirements remain visible without runtime credit."""
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
from helix_runtime_extensions import COMMON_EXTENSIONS
import test_runtime_extensions_pipeline as pipeline_fixture


def observed_check(**changes):
    result = dict(scope='base', database='helix', part='frontend', candidate=None,
                  status='ready', reason_code='CATALOG_OBSERVED', requirements_status='recorded',
                  required=['pg_trgm'], declarations=[dict(name='pg_trgm', path='db/001.sql', line=7, declared_version='1.6')],
                  gaps=[], observed=[dict(name=name, available=True, default_version='1.6', installed_version=None)
                                     for name in sorted(COMMON_EXTENSIONS)],
                  missing=[], version_check='not_checked', log='logs/001.log')
    result.update(changes)
    runtime.validate_extension_checks(dict(extension_checks=[result]))
    return result


class OwnerRuntimeExtensions(unittest.TestCase):
    def run_fake(self, sql=None):
        fixture = pipeline_fixture.RuntimeExtensionsPipeline()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        report = fixture.run_pipeline(sql) if sql is not None else fixture.run_pipeline()
        return fixture, report

    def test_available_is_not_installed_or_version_verified(self):
        fidelity = dict(extension_checks=[observed_check()])
        before = copy.deepcopy(fidelity)
        summary = owner.runtime_extensions_summary(fidelity)
        text = '\n'.join(owner.runtime_extensions_markdown(summary))
        self.assertEqual(summary['status'], 'READY')
        self.assertIn('niezainstalowane w tej bazie', text)
        self.assertIn('zadeklarowana wersja 1.6 nie została zweryfikowana', text)
        self.assertIn('db/001.sql:7', text)
        self.assertIn('logs/001.log', text)
        self.assertIn('Dostępność nie potwierdza instalacji', text)
        self.assertEqual(fidelity, before)

    def test_missing_required_extension_explains_why_migration_is_blocked(self):
        check = observed_check(status='blocked', reason_code='REQUIRED_EXTENSION_UNAVAILABLE', missing=['pg_trgm'],
                               observed=[dict(name=name, available=name != 'pg_trgm', default_version=None, installed_version=None)
                                         for name in sorted(COMMON_EXTENSIONS)])
        summary = owner.runtime_extensions_summary(dict(extension_checks=[check]))
        text = '\n'.join(owner.runtime_extensions_markdown(summary))
        self.assertEqual(summary['status'], 'BLOCKED')
        self.assertIn('Brakujące: `pg_trgm`', text)
        self.assertIn('migrator nie został dopuszczony', text)
        self.assertIn('instalacja: nieustalona', text)

    def test_ready_catalog_keeps_unknown_requirements_and_distinct_database_scopes(self):
        checks = [observed_check(requirements_status='unknown', gaps=[dict(path='db/runner.py', line=1, reason_code='DYNAMIC_RUNNER_REQUIREMENTS_UNKNOWN')]),
                  observed_check(scope='trial', database='helix_trial_01234567', candidate='project-runner:db/runner.py'),
                  observed_check(scope='restore', database='helix_restore_89abcdef')]
        summary = owner.runtime_extensions_summary(dict(extension_checks=checks))
        text = '\n'.join(owner.runtime_extensions_markdown(summary))
        self.assertEqual(summary['status'], 'INCOMPLETE')
        self.assertEqual(summary['counts']['requirements_unknown'], 1)
        for name in ('helix', 'helix_trial_01234567', 'helix_restore_89abcdef'):
            self.assertIn('`' + name + '`', text)
        self.assertIn('Pełny zbiór wymagań jest nieustalony', text)
        self.assertIn('db/runner.py:1', text)

    def test_historical_absence_is_unknown_and_current_empty_list_is_not_run(self):
        missing = owner.runtime_extensions_summary({})
        empty = owner.runtime_extensions_summary(dict(extension_checks=[]))
        self.assertEqual(missing['status'], 'NOT_RECORDED')
        self.assertIsNone(missing['counts']['checks'])
        self.assertEqual(empty['status'], 'NOT_RUN')
        self.assertEqual(empty['counts']['checks'], 0)
        self.assertIn('Sprawdzenia katalogu: nieznane', '\n'.join(owner.runtime_extensions_markdown(missing)))
        self.assertIn('Sprawdzenia katalogu: 0', '\n'.join(owner.runtime_extensions_markdown(empty)))

    def test_actual_runner_catalog_reaches_aggregate_with_separate_restore_scope(self):
        fixture, _ = self.run_fake()
        result = owner.aggregate(fixture.project, [fixture.current.out])
        summary = result['groups'][0]['runtime_database_extensions'][0]
        self.assertEqual(summary['status'], 'READY')
        self.assertIn('restore', {row['scope'] for row in summary['checks']})
        self.assertIn('migrations/001.sql:1', owner.markdown(result))
        self.assertIn('niezainstalowane w tej bazie', owner.markdown(result))
        self.assertFalse(any(gap['reason'].startswith('Rozszerzenia PostgreSQL:') for gap in result['gaps']))

    def test_actual_missing_extension_is_a_gap_with_its_location(self):
        fixture, _ = self.run_fake('CREATE EXTENSION unavailable_extension; CREATE TABLE synthetic(id int);')
        result = owner.aggregate(fixture.project, [fixture.current.out])
        summary = result['groups'][0]['runtime_database_extensions'][0]
        self.assertEqual(summary['status'], 'BLOCKED')
        self.assertIn('Brakujące: `unavailable_extension`', owner.markdown(result))
        self.assertIn('migrations/001.sql:1', owner.markdown(result))
        self.assertTrue(any('Rozszerzenia PostgreSQL: BLOCKED' in gap['reason'] for gap in result['gaps']))

    def test_imported_dynamic_scope_keeps_catalog_readiness_separate_from_credit(self):
        fixture, _ = self.run_fake('CREATE EXTENSION pg_trgm; DO $$ BEGIN NULL; END $$; CREATE TABLE synthetic(id int);')
        maturity = helix_pro.assess(fixture.project, 'XL')
        runtime.import_evidence(maturity, fixture.current.out / 'runtime-report.json', fixture.project)
        audit = dict(maturity=maturity, quality={'domains': {'checks': []}, 'findings': []},
                     source_coverage={}, scope={'profile': 'XL'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}):
            owner.audit_report(fixture.project, fixture.current.out, audit, {})
        result = json.loads((fixture.current.out / 'owner-current.json').read_text())
        summary = result['runtime_database_extensions']
        self.assertEqual(summary['status'], 'INCOMPLETE')
        self.assertGreater(summary['counts']['requirements_unknown'], 0)
        gap = next(gap for gap in result['gaps'] if gap['id'] == 'runtime_database_extensions:incomplete')
        self.assertIn('migrations/001.sql:1', gap['evidence'])
        self.assertFalse(any(row['id'].startswith('runtime_database_extensions:') and row.get('score') for row in result['controls']))


if __name__ == '__main__':
    unittest.main()
