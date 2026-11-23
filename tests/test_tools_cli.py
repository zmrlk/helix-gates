"""CLI inventory/install boundaries; no tool, process, network or target code."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
sys.path.insert(0, str(ROOT / 'tests'))
from test_provider_plan import load_helix
import helix_config
import helix_contracts
import helix_tools_cli as cli
import helix_tools_manager as manager
import helix_workflow


class ToolsCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / 'target'; self.repo.mkdir()
        self.H = load_helix()
        for target in ('subprocess.run', 'subprocess.Popen'):
            self.enterContext(patch(target, side_effect=AssertionError('no process or network')))
        self.enterContext(patch.object(manager, 'resolve_installed', return_value=None))
        self.enterContext(patch.object(cli.shutil, 'which', return_value=None))

    def invoke(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['helix', '--repo', str(self.repo), *argv]), \
             patch.object(self.H, 'Ctx', side_effect=AssertionError('no target context')), \
             patch.object(helix_config, 'configure', side_effect=AssertionError('no config read')), \
             patch.object(helix_contracts, 'check_pin', side_effect=AssertionError('no pin read')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as caught:
                self.H.main()
        return caught.exception.code, out.getvalue(), err.getvalue()

    def test_plan_works_without_config_pin_state_or_process_and_covers_all_groups(self):
        (self.repo / 'helix.json').write_text('PRIVATE_INVALID_CONFIG_CANARY')
        code, output, errors = self.invoke('--config', str(self.root / 'missing.json'),
                                          '--state-dir', str(self.root / 'state'), 'tools', 'plan', '--json')
        self.assertEqual((code, errors), (0, ''))
        report = json.loads(output)
        self.assertEqual(set(report['groups']), set(cli.adapters.GROUPS))
        self.assertEqual({row['name'] for row in report['tools']}, set(cli.adapters.REGISTRY))
        self.assertEqual(report['execution'], dict(commands=0, network=False, target_reads=0, target_writes=0))
        self.assertEqual(report['producer']['helix_version'], helix_contracts.VERSION)
        self.assertEqual(report['producer']['python'], cli.platform.python_version())
        self.assertEqual(report['coverage']['status'], 'INCOMPLETE')
        self.assertNotIn('PRIVATE_INVALID_CONFIG_CANARY', output)
        self.assertEqual((self.repo / 'helix.json').read_text(), 'PRIVATE_INVALID_CONFIG_CANARY')
        self.assertEqual(list(self.repo.iterdir()), [self.repo / 'helix.json'])
        self.assertFalse((self.root / 'state').exists())

    def test_plan_repeatable_tool_filters_and_deduplicates_without_omitting_declared_only(self):
        code, output, errors = self.invoke('tools', 'plan', '--tool', 'knip', '--tool', 'stryker', '--tool', 'knip', '--json')
        self.assertEqual((code, errors), (0, ''))
        rows = json.loads(output)['tools']
        self.assertEqual([row['name'] for row in rows], ['knip', 'stryker'])
        self.assertTrue(rows[0]['managed']['install_supported'])
        self.assertFalse(rows[1]['managed']['install_supported'])
        self.assertEqual(rows[0]['managed']['status'], 'NOT_VERIFIED')
        self.assertEqual(rows[0]['execution_status'], 'NOT_RUN')

    def test_text_explains_missing_executable_runner_and_install_not_project_coverage(self):
        code, output, errors = self.invoke('tools', 'plan', '--tool', 'ast-grep')
        self.assertEqual((code, errors), (0, ''))
        self.assertIn('zadeklarowane, nieuruchomione: brak narzędzia w sprawdzonych lokalizacjach', output)
        self.assertIn('review deep / security deep risk plan', output)
        self.assertIn('adapter UNVERIFIED', output)
        self.assertIn('Skan projektu: NOT_RUN', output)

    def test_local_presence_and_managed_receipt_remain_separate_from_execution(self):
        with patch.object(cli.shutil, 'which', return_value='/synthetic/bin/knip'), \
             patch.object(manager, 'resolve_installed', return_value=dict(usable=True, smoke_status='PASS')):
            report = cli.plan(['knip'])
        row = report['tools'][0]
        self.assertTrue(row['local_executable_present'])
        self.assertIsNone(row['local']['version'])
        self.assertEqual(row['managed']['status'], 'VERIFIED')
        self.assertEqual(row['managed']['smoke_status'], 'PASS')
        self.assertEqual(row['managed']['adapter_status'], 'UNVERIFIED')
        self.assertEqual(row['execution_status'], 'NOT_RUN')
        self.assertIn('MANAGED_ADAPTER_UNVERIFIED', row['coverage_gaps'])
        row['declaration']['perspectives'].append('MUTATED')
        self.assertNotIn('MUTATED', cli.adapters.REGISTRY['knip']['perspectives'])

    def test_missing_yes_and_offline_refuse_before_manager_resolver_output_or_config(self):
        for flags, reason in (([], 'EXPLICIT_YES_REQUIRED'), (['--yes', '--offline'], 'OFFLINE_INSTALL_NOT_ALLOWED')):
            with self.subTest(flags=flags), \
                 patch.object(manager, 'install', side_effect=AssertionError('no install')), \
                 patch.object(manager, 'plan', side_effect=AssertionError('no plan')), \
                 patch.object(manager, 'resolve_installed', side_effect=AssertionError('no resolver')):
                code, output, errors = self.invoke('tools', 'install', *flags, '--json', '--out', str(self.root / 'new' / 'report'))
            self.assertEqual((code, errors), (3, ''))
            self.assertEqual(json.loads(output)['reason_code'], reason)
            self.assertFalse((self.root / 'new').exists())
            self.assertEqual(list(self.repo.iterdir()), [])

    def test_verified_managed_install_outside_path_is_available_but_not_adapter_or_execution_credit(self):
        with patch.object(manager, 'resolve_installed', return_value=dict(usable=True, smoke_status='PASS')):
            report = cli.plan(['knip'])
        row = report['tools'][0]
        self.assertFalse(row['local_executable_present'])
        self.assertEqual(row['managed']['status'], 'VERIFIED')
        self.assertNotIn('LOCAL_EXECUTABLE_NOT_FOUND', row['coverage_gaps'])
        self.assertIn('MANAGED_ADAPTER_UNVERIFIED', row['coverage_gaps'])
        self.assertEqual(row['execution_status'], 'NOT_RUN')
        rendered = cli.text_report(report)
        self.assertIn('dostępna zweryfikowana instalacja zarządzana, poza PATH', rendered)
        self.assertNotIn('brak narzędzia w sprawdzonych lokalizacjach', rendered)
        self.assertIn('adapter UNVERIFIED', rendered)

    def test_install_only_closed_catalog_with_explicit_yes_and_no_target_options(self):
        result = dict(status='COMPLETE', tools=[dict(tool='knip', status='INSTALLED', version=manager.CATALOG['knip']['version'],
                      smoke_status='PASS', adapter_status='UNVERIFIED')], proof_kind='subprocess', target_writes=0)
        with patch.object(manager, 'install', return_value=result) as install:
            code, output, errors = self.invoke('tools', 'install', '--tool', 'knip', '--yes', '--json', '--out', str(self.root / 'install-report'))
        self.assertEqual((code, errors), (0, ''))
        install.assert_called_once_with(['knip'], yes=True, offline=False)
        report = json.loads(output)
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['producer']['helix_version'], helix_contracts.VERSION)
        self.assertEqual(json.loads((self.root / 'install-report/tools-install.json').read_text()), report)
        self.assertEqual(report['tools'], result['tools'])
        self.assertEqual(report['coverage_status'], 'NOT_RUN')
        self.assertEqual(report['project_execution'], 'NOT_RUN')
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_install_default_exactly_five_tools_and_failure_is_exit_three(self):
        with patch.object(manager, 'install', return_value=dict(status='INCOMPLETE', tools=[dict(tool='knip', status='FAILED', reason_code='SMOKE_FAILED')])) as install:
            code, output, errors = self.invoke('tools', 'install', '--yes', '--json')
        self.assertEqual((code, errors), (3, ''))
        self.assertEqual(install.call_args.args, (list(manager.CATALOG),))
        self.assertEqual(len(install.call_args.args[0]), 5)
        self.assertNotIn('stryker', install.call_args.args[0])
        self.assertEqual(json.loads(output)['tools'][0]['reason_code'], 'SMOKE_FAILED')

    def diagnostic(self, **changes):
        value = dict(schema_version=1, phase='smoke', code='SMOKE_EXPECTED_FINDING_MISSING',
                     command=['<runtime>/node', '<install>/node_modules/knip/bin/knip.js', '--reporter', 'json'],
                     returncode=0, tail=[dict(stream='stderr', line='No matching exports found. token=[REDACTED]'),
                                         dict(stream='stdout', line='{"files":[]}')],
                     omitted_lines=4, truncated=True, reason_codes=['SEMANTIC_RESULT_MISSING'],
                     hints=['Sprawdź kontrakt formatu JSON przypiętej wersji.'])
        value.update(changes)
        return value

    def test_install_text_displays_only_prepared_diagnostic_with_command_phase_exit_and_hint(self):
        diagnostic = self.diagnostic()
        result = dict(status='INCOMPLETE', tools=[dict(tool='knip', status='FAILED', reason_code=diagnostic['code'],
                      diagnostic=diagnostic, stdout='RAW_STDOUT_CANARY', stderr='RAW_STDERR_CANARY')])
        with patch.object(manager, 'install', return_value=result):
            code, output, errors = self.invoke('tools', 'install', '--tool', 'knip', '--yes')
        self.assertEqual((code, errors), (3, ''))
        self.assertIn('Etap: smoke; przyczyna: SMOKE_EXPECTED_FINDING_MISSING; kod wyjścia: 0', output)
        self.assertIn('Polecenie:', output)
        self.assertIn('node_modules/knip/bin/knip.js', output)
        self.assertIn('No matching exports found. token=[REDACTED]', output)
        self.assertIn('stdout: {"files":[]}', output)
        self.assertIn('SEMANTIC_RESULT_MISSING', output)
        self.assertIn('Sprawdź kontrakt formatu JSON przypiętej wersji.', output)
        self.assertIn('pominięte linie 4; skrócono tak', output)
        self.assertNotIn('CANARY', output)
        self.assertEqual(diagnostic, self.diagnostic())

    def test_json_and_saved_report_preserve_helper_diagnostic_without_second_redaction(self):
        diagnostic = self.diagnostic(returncode=1, phase='package_install', code='COMMAND_FAILED')
        result = dict(status='INCOMPLETE', stdout='TOP_RAW_CANARY', exception='EXCEPTION_CANARY',
                      tools=[dict(tool='knip', status='FAILED', diagnostic=diagnostic,
                                  stdout='RAW_STDOUT_CANARY', stderr='RAW_STDERR_CANARY')])
        out = self.root / 'diagnostic'
        with patch.object(manager, 'install', return_value=result):
            code, output, errors = self.invoke('tools', 'install', '--tool', 'knip', '--yes', '--json', '--out', str(out))
        self.assertEqual((code, errors), (3, ''))
        report = json.loads(output)
        self.assertEqual(report['tools'][0]['diagnostic'], diagnostic)
        self.assertEqual(json.loads((out / 'tools-install.json').read_text())['tools'][0]['diagnostic'], diagnostic)
        self.assertNotIn('CANARY', output)
        self.assertNotIn('CANARY', (out / 'tools-install.json').read_text())
        self.assertEqual(report['project_execution'], 'NOT_RUN')

    def test_top_level_setup_diagnostic_with_unknown_exit_is_not_reported_as_zero(self):
        diagnostic = self.diagnostic(phase='runtime_discovery', code='RUNTIME_UNAVAILABLE', returncode=None,
                                     command=[], tail=[], omitted_lines=0, truncated=False,
                                     reason_codes=[], hints=['Brak zgodnego środowiska uruchomieniowego.'])
        with patch.object(manager, 'install', return_value=dict(status='BLOCKED', reason_code='RUNTIME_UNAVAILABLE', tools=[], diagnostic=diagnostic)):
            code, output, errors = self.invoke('tools', 'install', '--yes')
        self.assertEqual((code, errors), (3, ''))
        self.assertIn('Etap: runtime_discovery; przyczyna: RUNTIME_UNAVAILABLE; kod wyjścia: nieznany', output)
        self.assertIn('Brak zgodnego środowiska uruchomieniowego.', output)
        self.assertNotIn('Polecenie:', output)

    def test_real_diagnostic_helper_reaches_text_without_raw_process_output(self):
        from helix_tool_diagnostics import build_diagnostic
        diagnostic = build_diagnostic(phase='package_install', code='PACKAGE_INSTALL_FAILED',
            argv=['npm', 'ci', '--ignore-scripts'], returncode=1,
            stderr="npm: double-loading config /synthetic/private as 'global', previously loaded as 'user'\nPRIVATE_RAW_CANARY")
        with patch.object(manager, 'install', return_value=dict(status='INCOMPLETE', tools=[
                dict(tool='knip', status='FAILED', diagnostic=diagnostic)])):
            code, output, errors = self.invoke('tools', 'install', '--tool', 'knip', '--yes')
        self.assertEqual((code, errors), (3, ''))
        self.assertIn('package_install', output)
        self.assertIn('kod wyjścia: 1', output)
        self.assertIn('NPM_CONFIG_COLLISION', output)
        self.assertIn('double-loading config as global, previously loaded as user', output)
        self.assertNotIn('PRIVATE_RAW_CANARY', output)
        self.assertNotIn('/synthetic/private', output)

    def test_unknown_or_unmanaged_install_tool_cannot_reach_installer(self):
        for name in ('stryker', 'semgrep', '../../secret-canary'):
            with self.subTest(name=name), patch.object(manager, 'install', side_effect=AssertionError('no install')):
                code, output, errors = self.invoke('tools', 'install', '--tool', name, '--yes', '--json')
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(errors)['reason_code'], 'UNKNOWN_OR_UNSUPPORTED_TOOL')
            self.assertNotIn('secret-canary', output + errors)

    def test_output_is_external_exclusive_regular_json_with_private_mode(self):
        out = self.root / 'artifacts' / 'tools'
        code, output, errors = self.invoke('tools', 'plan', '--tool', 'knip', '--out', str(out), '--json')
        self.assertEqual((code, errors), (0, ''))
        dest = out / 'tools-plan.json'
        self.assertEqual(json.loads(dest.read_text()), json.loads(output))
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
        old = dest.read_bytes()
        with patch.object(manager, 'plan', side_effect=AssertionError('preflight before managed reads')):
            code, output, errors = self.invoke('tools', 'plan', '--out', str(out), '--json')
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(errors)['reason_code'], 'OUTPUT_ALREADY_EXISTS')
        self.assertEqual(dest.read_bytes(), old)

    def test_output_parent_symlink_leaf_symlink_and_target_overlap_refuse_before_install(self):
        external = self.root / 'external'; external.mkdir()
        link = self.root / 'link'; link.symlink_to(external, target_is_directory=True)
        leaf = self.root / 'leaf'; leaf.mkdir()
        (leaf / 'tools-install.json').symlink_to(self.repo / 'canary')
        for out in (self.repo / 'report', self.root, link / 'report', leaf):
            with self.subTest(out=out), patch.object(manager, 'install', side_effect=AssertionError('no install')):
                code, output, errors = self.invoke('tools', 'install', '--yes', '--out', str(out), '--json')
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(errors)['status'], 'ERROR')
        self.assertFalse((self.repo / 'canary').exists())
        self.assertEqual(list(external.iterdir()), [])

    def test_install_root_cannot_overlap_target(self):
        with patch.object(Path, 'home', return_value=self.repo), \
             patch.object(manager, 'install', side_effect=AssertionError('no target installation')):
            code, output, errors = self.invoke('tools', 'install', '--yes', '--json')
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(errors)['reason_code'], 'INSTALL_ROOT_OVERLAPS_TARGET')
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_install_failure_keeps_fixed_error_without_raw_exception_values(self):
        with patch.object(manager, 'install', side_effect=OSError('PRIVATE_TOKEN_CANARY')):
            code, output, errors = self.invoke('tools', 'install', '--yes', '--json')
        self.assertEqual(code, 3)
        self.assertNotIn('PRIVATE_TOKEN_CANARY', output + errors)
        self.assertEqual(json.loads(errors)['reason_code'], 'TOOLS_IO_OR_RECEIPT_ERROR')

    def test_output_write_stays_on_opened_directory_after_parent_swap(self):
        out, retained = self.root / 'output', self.root / 'retained'
        out.mkdir()
        target_file = self.repo / 'tools-plan.json'; target_file.write_text('TARGET_CANARY')
        original_open = os.open
        swapped = []
        def replace_parent(name, flags, *args, **kwargs):
            if name == 'tools-plan.json' and kwargs.get('dir_fd') is not None and not swapped:
                out.rename(retained)
                out.symlink_to(self.repo, target_is_directory=True)
                swapped.append(True)
            return original_open(name, flags, *args, **kwargs)
        with patch.object(cli.os, 'open', side_effect=replace_parent) as mocked_open, \
             patch.object(cli.os, 'supports_dir_fd', os.supports_dir_fd | {mocked_open}):
            code, output, errors = self.invoke('tools', 'plan', '--tool', 'knip', '--out', str(out), '--json')
        self.assertEqual((code, errors), (0, ''))
        self.assertEqual(swapped, [True])
        self.assertEqual(target_file.read_text(), 'TARGET_CANARY')
        self.assertEqual(json.loads((retained / 'tools-plan.json').read_text()), json.loads(output))

    def test_no_public_install_root_or_executor_override_and_no_positional_name(self):
        for extra in (['--tools-dir', str(self.root)], ['--executor', 'fake']):
            code, output, errors = self.invoke('tools', 'install', '--yes', *extra)
            self.assertEqual(code, 2)
        code, output, errors = self.invoke('tools', 'install', 'knip', '--yes', '--json')
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(errors)['reason_code'], 'USE_REPEATABLE_TOOL_OPTION')

    def test_existing_tools_actions_keep_their_parser_contract(self):
        parser = argparse.ArgumentParser()
        helix_workflow.parsers(parser.add_subparsers(dest='cmd'))
        for action in ('discover', 'schema', 'call', 'adapters', 'scan'):
            parsed = parser.parse_args(['tools', action, 'synthetic', '--input', '{"x":1}', '--fields', 'x'])
            self.assertEqual((parsed.action, parsed.name, parsed.input, parsed.fields), (action, 'synthetic', '{"x":1}', 'x'))


if __name__ == '__main__':
    unittest.main()
