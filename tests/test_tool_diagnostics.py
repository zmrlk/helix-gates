"""Pure diagnostic contracts, never starting package managers or reading HOME."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_tool_diagnostics as D


class ToolDiagnosticsTests(unittest.TestCase):
    def diagnostic(self, **kwargs):
        values = dict(phase='dependency_resolution', code='WHEEL_RESOLUTION_FAILED',
                      argv=['python3', '-I', '-m', 'pip', 'download', 'mutmut==3.8.0'], returncode=1)
        values.update(kwargs)
        return D.build_diagnostic(**values)

    def test_missing_distribution_retains_dependency_cause(self):
        result = self.diagnostic(stderr='ERROR: Could not find a version that satisfies the requirement libcst>=1.1 (from versions: none)\nERROR: No matching distribution found for libcst>=1.1\n')
        self.assertEqual(result['reason_codes'], ['NO_DISTRIBUTION'])
        self.assertIn('No matching distribution found for libcst>=1.1', result['tail'][-1]['line'])
        self.assertIn('bez przejścia na build', result['hints'][0])
        self.assertEqual(result['returncode'], 1)

    def test_env_node_missing_retains_program_and_reason(self):
        result = self.diagnostic(phase='runtime_probe', code='RUNTIME_PROBE_FAILED', stderr='env: node: No such file or directory\n')
        self.assertEqual(result['tail'], [{'stream': 'stderr', 'line': 'env: node: No such file or directory'}])
        self.assertEqual(result['reason_codes'], ['EXECUTABLE_NOT_FOUND'])

    def test_npm_codes_are_useful_without_arbitrary_raw_suffix(self):
        result = self.diagnostic(stderr='npm ERR! code ERESOLVE\nnpm ERR! secret-canary\nnpm ERR! EACCES denied contact private@example.invalid\n')
        self.assertEqual(set(result['reason_codes']), {'DEPENDENCY_CONFLICT', 'PERMISSION_DENIED'})
        public = json.dumps(result)
        self.assertNotIn('secret-canary', public)
        self.assertNotIn('private@example.invalid', public)

    def test_npm_config_collision_is_not_generic_redaction(self):
        text = 'Exit prior to config file resolving\ncause\ndouble-loading config "/dev/null" as "global", previously loaded as "user"\n'
        result = self.diagnostic(phase='runtime_probe', stderr=text)
        self.assertEqual(result['reason_codes'], ['NPM_CONFIG_COLLISION'])
        self.assertIn('double-loading config as global, previously loaded as user', result['tail'][-1]['line'])
        self.assertEqual(result['tail'][0]['line'], 'Exit prior to config file resolving')

    def test_unclassified_stdout_and_json_never_echo_canaries(self):
        result = self.diagnostic(stdout='secret-canary\n{"token":"OTHER_CANARY"}\n["INTERNAL_PAYLOAD"]\n', stderr='UNLABELED_SENSITIVE_VALUE')
        self.assertEqual(result['tail'], [])
        self.assertEqual(result['omitted_lines'], 4)
        self.assertEqual(result['reason_codes'], [])
        for value in ('secret-canary', 'OTHER_CANARY', 'INTERNAL_PAYLOAD', 'UNLABELED_SENSITIVE_VALUE'):
            self.assertNotIn(value, json.dumps(result))

    def test_credentials_pii_urls_ansi_and_controls_are_not_public(self):
        text = '\x1b[31mERROR: No matching distribution found for libcst\x1b[0m\n'
        text += 'npm ERR! ECONNRESET https://USER_CANARY:PASS_CANARY@registry.invalid/path?token=QUERY_CANARY\n'
        text += 'npm ERR! EACCES email=PERSON_CANARY@example.invalid phone=+48123456789\n'
        text += 'Bearer AUTH_CANARY\npassword=PASSWORD_CANARY\n\x1b]0;TITLE_CANARY\x07\x00'
        result = self.diagnostic(stderr=text)
        public = json.dumps(result, ensure_ascii=False)
        for value in ('USER_CANARY', 'PASS_CANARY', 'QUERY_CANARY', 'PERSON_CANARY', '48123456789', 'AUTH_CANARY', 'PASSWORD_CANARY', 'TITLE_CANARY', '\\u001b', '\\u0000'):
            self.assertNotIn(value, public)
        self.assertIn('NO_DISTRIBUTION', result['reason_codes'])
        self.assertIn('NETWORK_ERROR', result['reason_codes'])

    def test_install_and_home_paths_have_explicit_safe_aliases(self):
        result = self.diagnostic(home='/Users/owner', install_dir='/Users/owner/tools/stage',
            argv=['/Users/owner/tools/stage/venv/bin/python', '-I', '-m', 'pip', '--config', '/Users/owner/config/pip.ini'],
            stderr='  File "/Users/owner/tools/stage/venv/lib/module.py", line 17, in private_function\n')
        self.assertEqual(result['command'][0], '<install>/venv/bin/python')
        self.assertEqual(result['command'][-1], '~/config/pip.ini')
        self.assertEqual(result['tail'][0]['line'], 'File "<install>/venv/lib/module.py", line 17')
        self.assertNotIn('/Users/owner', json.dumps(result))
        self.assertNotIn('private_function', json.dumps(result))

    def test_trace_preserves_exception_type_without_source_or_message(self):
        result = self.diagnostic(stderr='Traceback (most recent call last):\n  File "/foreign/SECRET_CANARY.py", line 12\n    print("SOURCE_CANARY")\nValueError: MESSAGE_CANARY\n')
        self.assertEqual(len(result['tail']), 3)
        self.assertEqual(result['tail'][-1]['line'], 'ValueError: details omitted')
        for value in ('SECRET_CANARY', 'SOURCE_CANARY', 'MESSAGE_CANARY'):
            self.assertNotIn(value, json.dumps(result))

    def test_argv_preserves_fixed_command_but_not_user_values(self):
        result = self.diagnostic(argv=['/usr/local/bin/node', '/usr/local/bin/npm', 'install', '--ignore-scripts',
            '--registry=https://user:URL_CANARY@registry.invalid/?token=Q_CANARY', '--password', 'VALUE_CANARY',
            'knip@6.43.0', 'contact@example.invalid', 'NODE_OPTIONS=LOADER_CANARY'])
        self.assertEqual(result['command'][:4], ['node', 'npm', 'install', '--ignore-scripts'])
        self.assertIn('knip@6.43.0', result['command'])
        for value in ('URL_CANARY', 'Q_CANARY', 'VALUE_CANARY', 'contact@example.invalid', 'LOADER_CANARY'):
            self.assertNotIn(value, json.dumps(result))

    def test_twenty_tail_lines_and_serialized_byte_limit(self):
        result = self.diagnostic(stdout='\n'.join('ERROR: No matching distribution found for package'+str(i) for i in range(5000)))
        self.assertLessEqual(len(result['tail']), D.MAX_LINES)
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode()), D.MAX_BYTES)
        self.assertIn('package4999', result['tail'][-1]['line'])
        self.assertGreater(result['omitted_lines'], 4900)
        self.assertTrue(result['truncated'])

    def test_arbitrary_metadata_and_boolean_returncode_are_not_echoed(self):
        self.assertEqual(self.diagnostic(code='INSTALL_FAILED')['code'], 'INSTALL_FAILED')
        result = self.diagnostic(phase='PHASE_CANARY', code='CODE_CANARY', argv=[{'unsafe': 'ARG_CANARY'}], returncode=True)
        self.assertEqual(result['phase'], 'unknown')
        self.assertEqual(result['code'], 'COMMAND_FAILED')
        self.assertIsNone(result['returncode'])
        self.assertEqual(result['command'], ['<redacted>'])
        for value in ('PHASE_CANARY', 'CODE_CANARY', 'ARG_CANARY'):
            self.assertNotIn(value, json.dumps(result))

    def test_bytes_and_invalid_utf8_have_safe_reconstructed_output(self):
        result = self.diagnostic(stderr=b'\xff\xfe\nERROR: No matching distribution found for libcst\n')
        self.assertEqual(result['tail'][-1]['line'], 'No matching distribution found for libcst')
        self.assertNotIn('\ufffd', json.dumps(result, ensure_ascii=False))

    def test_input_is_not_mutated_and_output_is_deterministic(self):
        args = dict(argv=['python3', '-m', 'pip'], stderr='env: node: No such file or directory')
        before = copy.deepcopy(args)
        self.assertEqual(self.diagnostic(**args), self.diagnostic(**args))
        self.assertEqual(args, before)

    def test_helper_has_no_filesystem_process_clock_or_environment_probes(self):
        with patch('builtins.open', side_effect=AssertionError('no I/O')), patch('subprocess.Popen', side_effect=AssertionError('no process')), patch.object(Path, 'home', side_effect=AssertionError('no HOME')), patch('time.time', side_effect=AssertionError('no clock')):
            self.assertEqual(self.diagnostic(stderr='env: node: not found')['reason_codes'], ['EXECUTABLE_NOT_FOUND'])

    def test_tls_integrity_and_module_errors_keep_distinct_causes(self):
        result = self.diagnostic(stderr='SSLError CERTIFICATE_VERIFY_FAILED\nnpm error EINTEGRITY\nModuleNotFoundError: No module named \'libcst\'\n')
        self.assertEqual(set(result['reason_codes']), {'TLS_ERROR', 'INTEGRITY_ERROR', 'MODULE_MISSING'})
        self.assertIn('Required module not found: libcst', [row['line'] for row in result['tail']])

    def test_known_squawk_rule_name_survives_without_sql_or_message(self):
        raw = json.dumps([{'rule_name': 'require-primary-key', 'message': 'MESSAGE_CANARY',
                           'source': 'SQL_CANARY', 'path': '/private/USER_CANARY/file.sql'},
                          {'rule_name': 'UNKNOWN_RULE_CANARY', 'message': 'OTHER_CANARY'}])
        result = self.diagnostic(phase='smoke', code='SMOKE_NEGATIVE_FAILED', stdout=raw, returncode=0)
        self.assertEqual(result['tail'], [{'stream': 'stdout', 'line': 'Squawk rule_name: require-primary-key'}])
        self.assertEqual(result['code'], 'SMOKE_NEGATIVE_FAILED')
        self.assertEqual(result['returncode'], 0)
        self.assertNotIn('CANARY', json.dumps(result))

    def test_semantic_smoke_observation_keeps_only_count_and_known_rules(self):
        result = self.diagnostic(phase='smoke', code='SMOKE_NEGATIVE_FAILED', returncode=0,
            smoke_observation={'diagnostics_count': 2, 'rule_names': ['require-primary-key', 'SECRET_CANARY']})
        self.assertIn('liczba diagnostyk 2', result['hints'][0])
        self.assertIn('require-primary-key', result['hints'][0])
        self.assertIn('UNRECOGNIZED_RULE', result['hints'][0])
        self.assertNotIn('SECRET_CANARY', json.dumps(result))
        for observation in ({'diagnostics_count': True, 'rule_names': []},
                            {'diagnostics_count': 2, 'rule_names': [], 'source': 'SOURCE_CANARY'}):
            with self.subTest(observation=observation):
                self.assertEqual(self.diagnostic(phase='smoke', code='SMOKE_NEGATIVE_FAILED', smoke_observation=observation)['hints'], [])

    def test_knip_closed_smoke_counts_preserve_format_without_source(self):
        observation = dict(tool='knip', schema='v6', control='positive', issue_groups=0,
                           unused_files=0, expected_file_found=False)
        result = self.diagnostic(phase='smoke', code='SMOKE_EXPECTED_FINDING_MISSING',
            smoke_observation=observation, stdout='{"source":"SOURCE_CANARY"}')
        self.assertIn('format v6', result['hints'][0])
        self.assertIn('grupy 0', result['hints'][0])
        self.assertIn('nieobecny', result['hints'][0])
        self.assertEqual(result['reason_codes'], ['SMOKE_CONTRACT_OBSERVED'])
        self.assertNotIn('SOURCE_CANARY', json.dumps(result))
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode()), D.MAX_BYTES)

    def test_mutmut_closed_stats_and_help_preserve_specific_smoke_stage(self):
        stats = dict(total=2, killed=1, survived=0, no_tests=1, skipped=0,
                     suspicious=0, timeout=0, check_was_interrupted_by_user=0, segfault=0)
        result = self.diagnostic(phase='smoke', code='SMOKE_MUTATION_INCOMPLETE',
            smoke_observation=dict(tool='mutmut', stage='mutation_stats', stats=stats))
        self.assertIn('no_tests=1', result['hints'][0])
        self.assertIn('total=2', result['hints'][0])
        help_result = self.diagnostic(phase='smoke', code='SMOKE_EXPECTED_FINDING_MISSING',
            smoke_observation=dict(tool='mutmut', stage='help', stats=None))
        self.assertIn('help', help_result['hints'][0])

    def test_unknown_smoke_fields_types_and_large_counts_are_not_echoed(self):
        knip = dict(tool='knip', schema='v6', control='negative', issue_groups=0, unused_files=0, expected_file_found=False)
        cases = [dict(knip, source='SOURCE_CANARY'), dict(knip, schema='SCHEMA_CANARY'),
                 dict(knip, control='CONTROL_CANARY'), dict(knip, issue_groups=True),
                 dict(knip, unused_files=100001), dict(tool='mutmut', stage='STAGE_CANARY', stats=None),
                 dict(tool='mutmut', stage='help', stats={'source': 'SOURCE_CANARY'}),
                 dict(tool='mutmut', stage='help', stats=None, source='SOURCE_CANARY')]
        for observation in cases:
            with self.subTest(observation=observation):
                result = self.diagnostic(phase='smoke', code='SMOKE_NEGATIVE_FAILED', smoke_observation=observation)
                self.assertEqual(result['hints'], [])
                self.assertNotIn('CANARY', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
