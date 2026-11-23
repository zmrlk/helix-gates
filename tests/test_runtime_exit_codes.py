"""Runtime exit codes reflect completed measurements and incomplete coverage."""
import argparse
import contextlib
import copy
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_provider_plan import load_helix
import helix_runtime as runtime
import helix_runtime_integrations as integrations


class RuntimeExitCodes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / 'target'; self.project.mkdir()
        parser = argparse.ArgumentParser(); runtime.parsers(parser.add_subparsers())
        self.args = parser.parse_args(['runtime', 'run', '--project', str(self.project), '--out', str(self.root / 'out')])

    def report(self, status='PASS', **fields):
        checks = {name: {'status': 'PASS', 'metrics': {'observed': True},
                         'log': 'logs/' + name + '.log', 'reason': 'synthetic observed result'} for name in runtime.CHECKS}
        if status != 'PASS': checks['e2e']['status'] = status
        value = dict(schema_version=1, project=str(self.project), scope='synthetic fixture', engine=None,
                     status=status, parts=[{'name': '.', 'checks': checks}],run_id='exit-test',
                     integration_receipts=[],coverage_status='RECORDED',
                     integrations=integrations.execution_inventory(integrations.inventory({'main.js':'console.log("synthetic");'},[{'path':'.'}]),[],run_id='exit-test'))
        value.update(fields)
        runtime.validate_report(value)
        return value

    def dispatch(self, report):
        before = copy.deepcopy(report)
        with patch.object(runtime, 'Runner') as runner, contextlib.redirect_stdout(io.StringIO()) as stdout:
            runner.return_value.run.return_value = report
            result = runtime.dispatch(self.args)
        runner.return_value.run.assert_called_once()
        self.assertEqual(set(runner.return_value.run.call_args.kwargs.get('cli', {})), {'config', 'state_dir'})
        self.assertEqual(report, before)
        self.assertIn('runtime-report.json', stdout.getvalue())
        self.assertEqual(list(self.project.iterdir()), [])
        return result

    def test_completed_pass_and_measured_failure_have_distinct_codes(self):
        self.assertEqual(self.dispatch(self.report()), 0)
        self.assertEqual(self.dispatch(self.report('FAIL')), 2)

    def test_schema_incomplete_statuses_return_three(self):
        for status in ('BLOCKED', 'DEGRADED', 'SKIPPED'):
            with self.subTest(status=status): self.assertEqual(self.dispatch(self.report(status)), 3)

    def test_resource_pause_and_partial_never_exit_zero(self):
        for fields in ({'run_status': 'resource_paused'}, {'partial': True}):
            with self.subTest(fields=fields): self.assertEqual(self.dispatch(self.report(**fields)), 3)

    def test_legacy_report_without_integration_coverage_is_incomplete(self):
        report=self.report()
        for key in ('integrations','integration_receipts','coverage_status','run_id'):report.pop(key)
        self.assertEqual(self.dispatch(report),3)

    def test_incomplete_control_wins_over_a_measured_failure(self):
        report = self.report('FAIL')
        report['parts'][0]['checks']['load']['status'] = 'BLOCKED'
        self.assertEqual(self.dispatch(report), 3)

    def test_declaration_commands_keep_exit_zero_without_runtime(self):
        parser = argparse.ArgumentParser(); runtime.parsers(parser.add_subparsers())
        with patch.object(runtime, 'Runner') as runner, patch.object(runtime, 'plan', return_value={'tag': 'ASSUMPTION'}), \
             patch.object(runtime, 'doctor', return_value={'tools': {}}), patch.object(runtime, 'ci_template', return_value='synthetic CI'), \
             contextlib.redirect_stdout(io.StringIO()):
            for argv in (['runtime', 'plan', '--project', str(self.project)], ['runtime', 'doctor'], ['runtime', 'ci-template']):
                with self.subTest(argv=argv): self.assertEqual(runtime.dispatch(parser.parse_args(argv)), 0)
        runner.assert_not_called()

    def test_main_cli_propagates_runtime_exit_code_before_project_context(self):
        cli = load_helix()
        argv = ['helix', '--repo', str(self.project), 'runtime', 'run', '--project', str(self.project), '--out', str(self.root / 'out')]
        for report, expected in ((self.report(), 0), (self.report('FAIL'), 2),
                                 (self.report('BLOCKED'), 3), (self.report(run_status='resource_paused'), 3)):
            with self.subTest(status=report['status'], run_status=report.get('run_status')), patch.object(sys, 'argv', argv), \
                 patch.object(runtime, 'Runner') as runner, patch.object(cli, 'Ctx') as context, \
                 contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
                runner.return_value.run.return_value = report
                cli.main()
            self.assertEqual(result.exception.code, expected)
            context.assert_not_called()
        self.assertEqual(list(self.project.iterdir()), [])
