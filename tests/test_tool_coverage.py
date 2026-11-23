"""Declared tools and preparation reports never claim project coverage."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_tool_adapters as adapters
import helix_owner_report as owner


class ToolCoverage(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / 'project'; self.repo.mkdir()
        self.evidence = self.root / 'evidence'; self.evidence.mkdir()

    def report(self, name, data):
        (self.evidence / name).write_text(json.dumps(data))
        with patch.object(subprocess, 'run', side_effect=AssertionError('no process for aggregation')):
            return owner.aggregate(self.repo, [self.evidence])

    def test_registry_distinguishes_declaration_runner_and_pinned_license(self):
        ast = adapters.REGISTRY['ast-grep']
        self.assertEqual(ast['license'], 'MIT')
        self.assertTrue(ast['runner_implemented'])
        self.assertEqual(ast['runner'], 'review deep / security deep risk plan')
        self.assertIsNone(ast['parser'])
        self.assertNotIn('ast-grep', adapters.ARGS)
        self.assertEqual(adapters.REGISTRY['squawk']['license'], 'Apache-2.0 OR MIT')
        for name in ('svelte-check', 'tsc', 'eslint'):
            self.assertEqual(adapters.REGISTRY[name]['runner'], 'precheck')
        self.assertEqual(adapters.REGISTRY['mutmut']['runner'], 'runtime mutation')
        self.assertEqual(adapters.REGISTRY['semgrep']['runner'], 'tools scan')

    def test_missing_tool_is_a_coverage_gap_before_copy_or_process(self):
        with patch.object(adapters, 'locate', return_value=None), \
             patch.object(adapters, 'copy_project', side_effect=AssertionError('no copy')), \
             patch.object(adapters.subprocess, 'run', side_effect=AssertionError('no process')):
            result = adapters.scan(self.repo, 'ast-grep')
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['coverage']['status'], 'INCOMPLETE')
        self.assertEqual(result['coverage']['gaps'][0]['reason_code'], 'TOOL_NOT_FOUND')
        self.assertIn('zadeklarowane, nieuruchomione: brak narzędzia', result['reason'])

    def test_present_executable_without_adapter_is_still_a_coverage_gap(self):
        with patch.object(adapters, 'locate', return_value='/synthetic/depcheck'), \
             patch.object(adapters, 'copy_project', side_effect=AssertionError('no copy')), \
             patch.object(adapters.subprocess, 'run', side_effect=AssertionError('no process')):
            result = adapters.scan(self.repo, 'depcheck')
        self.assertEqual(result['status'], 'not-run')
        self.assertEqual(result['coverage']['gaps'][0]['reason_code'], 'RUNNER_NOT_ADMITTED')
        self.assertEqual(result['findings'], [])

    def test_owner_plan_keeps_missing_tool_and_runner_as_visible_gaps(self):
        report = self.report('tools-plan.json', dict(schema_version=1, kind='tools-plan', status='PLANNED', tools=[
            dict(name='knip', local=dict(status='MISSING'), managed=dict(managed_install_status='NOT_VERIFIED'), runner_implemented=False,
                 raw='PRIVATE_SOURCE_CANARY')]))
        tool = report['groups'][0]['tools'][0]
        self.assertEqual(tool['status'], 'NOT_RUN')
        self.assertEqual(tool['applicability'], 'NOT_ASSESSED')
        self.assertIsNone(tool['duration_seconds'])
        self.assertTrue(any('knip' in gap['reason'] for gap in report['gaps']))
        text = owner.markdown(report)
        self.assertIn('zadeklarowane, nieuruchomione: brak narzędzia', text)
        self.assertIn('Brak runnera', text)
        self.assertNotIn('PRIVATE_SOURCE_CANARY', json.dumps(report))

    def test_owner_installation_and_smoke_never_become_project_scan(self):
        report = self.report('tools-install.json', dict(schema_version=1, kind='tools-install', status='COMPLETE', tools=[
            dict(tool='knip', status='COMPLETE', proof_kind='subprocess', usable=True, smoke_status='PASS',
                 argv_prefix=['PRIVATE_COMMAND_CANARY'], receipt={'password': 'PRIVATE_RECEIPT_CANARY'})]))
        tool = report['groups'][0]['tools'][0]
        self.assertEqual(tool['status'], 'NOT_RUN')
        self.assertEqual(tool['project_execution'], 'NOT_RUN')
        self.assertEqual(tool['preparation_status'], 'COMPLETE')
        self.assertTrue(any('skan projektu nieuruchomiony' in gap['reason'] for gap in report['gaps']))
        self.assertEqual(report['groups'][0]['findings'], [])
        self.assertNotIn('PRIVATE_', json.dumps(report))

    def test_extra_finding_and_coverage_fields_cannot_escape_preparation_projection(self):
        for kind in ('plan', 'install'):
            with self.subTest(kind=kind):
                for existing in self.evidence.iterdir(): existing.unlink()
                item = dict(name='knip', runner_implemented=False) if kind == 'plan' else dict(tool='knip', status='COMPLETE')
                report = self.report('tools-' + kind + '.json', dict(schema_version=1, kind='tools-' + kind,
                    status='COMPLETE', tools=[item], findings=[dict(id='FORGED', file='src/a.ts', line=1, verdict='confirmed')],
                    verdicts=[dict(verdict='approve')], source_coverage=dict(status='COMPLETE', files_read=123),
                    coverage=dict(status='PASS', files_read=999)))
                group = report['groups'][0]
                self.assertEqual(group['findings'], [])
                self.assertEqual(group['tools'][0]['project_execution'], 'NOT_RUN')
                self.assertEqual(len(group['coverage']), 1)
                self.assertEqual(group['coverage'][0]['summary']['status'], 'NOT_RUN')
                self.assertNotIn('FORGED', json.dumps(report))
                self.assertNotIn('files_read', json.dumps(group['coverage']))

    def test_existing_run_tool_failures_are_coverage_gaps_not_only_notes(self):
        report = self.report('run.json', dict(target=str(self.repo), head='a' * 40, tools=[
            dict(tool='semgrep', status='unavailable', reason='brak programu'),
            dict(tool='knip', status='not-run', reason='brak kontraktu'),
            dict(tool='typos', status='completed', duration=.5)]))
        gaps = ' '.join(gap['reason'] for gap in report['gaps'])
        self.assertIn('semgrep', gaps)
        self.assertIn('knip', gaps)
        self.assertNotIn('typos', gaps)
        self.assertEqual(report['groups'][0]['tools'][1]['reason'], 'brak kontraktu')

    def test_refused_empty_install_retains_a_gap_and_no_execution_credit(self):
        report = self.report('tools-install.json', dict(schema_version=1, kind='tools-install', status='BLOCKED',
            reason_code='EXPLICIT_YES_REQUIRED', tools=[]))
        self.assertTrue(any('EXPLICIT_YES_REQUIRED' in gap['reason'] for gap in report['gaps']))
        self.assertEqual(report['groups'][0]['tools'], [])
        self.assertEqual(report['groups'][0]['coverage'][0]['summary']['status'], 'NOT_RUN')

    def test_malformed_preparation_does_not_get_silent_clean_coverage(self):
        report = self.report('tools-plan.json', dict(schema_version=1, kind='other', tools=[]))
        self.assertTrue(any('Nieprawidłowy kontrakt przygotowania' in gap['reason'] for gap in report['gaps']))
        self.assertEqual(report['groups'][0]['tools'], [])


if __name__ == '__main__':
    unittest.main()
