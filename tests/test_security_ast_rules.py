"""Replay real ast-grep facts from own synthetic sources, with no host tools."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_security_ast_rules as Rules

FIXTURES = Path(__file__).parent / 'fixtures/security-ast'


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


class SecurityASTRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = json.loads((FIXTURES / 'recorded-cases.json').read_text())
        cls.cases = {row['name']: row for row in cls.bundle['cases']}

    def setUp(self):
        # Replay must work when no managed installation or host tool exists.
        for target in ('subprocess.Popen', 'socket.socket', 'shutil.which',
                       'helix_static_ast.analyze_snapshot', 'helix_tools_manager.resolve_installed'):
            guard = patch(target, side_effect=AssertionError('recorded replay must not run tools or use network'))
            guard.start()
            self.addCleanup(guard.stop)

    def analyze(self, case):
        row = self.cases[case]
        record = copy.deepcopy(row['record'])
        result = Rules.analyze_file(row['path'], row['source'], record, record_guards={'requireCan'}, identity_guards={'requireAuth'})
        self.assertEqual(record, row['record'], 'analysis must not mutate evidence')
        self.assertEqual(result['status'], 'ANALYZED')
        for signal in result['signals']:
            self.assertEqual(signal['evidence_kind'], 'ast_local_relation')
            self.assertEqual(signal['confidence'], 'possible')
            self.assertGreaterEqual(signal['offset'], 0)
            self.assertLess(signal['offset'], len(row['source']))
        return result

    def assert_signals(self, case, expected):
        result = self.analyze(case)
        self.assertEqual(sorted({row['id'] for row in result['signals']}), sorted(expected), case)
        return result

    def test_recorded_facts_are_hash_bound_to_synthetic_source_and_capture(self):
        raw = (FIXTURES / 'recorded-cases.json').read_bytes()
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest['sha256'])
        self.assertEqual(len(raw), manifest['bytes'])
        self.assertEqual(len(self.cases), 32)
        self.assertEqual(len(self.cases), len(self.bundle['cases']))
        capture = self.bundle['capture']
        self.assertEqual(capture['case_count'], 32)
        self.assertEqual(capture['engine_version'], '0.51.0')
        self.assertEqual(capture['proof_kind'], 'subprocess')
        self.assertEqual(capture['rules_sha256'], hashlib.sha256((ROOT / 'config/static-ast/facts.json').read_bytes()).hexdigest())
        for name, row in self.cases.items():
            with self.subTest(case=name):
                source, record = row['source'], row['record']
                self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), record['source_sha256'])
                self.assertEqual(digest(record), row['record_sha256'])
                self.assertEqual(record['status'], 'PARSED')
                self.assertEqual(record['parser_completeness'], 'PARTIAL')
                self.assertIn({'code': 'MISSING_NODES_NOT_EXPOSED'}, record['gaps'])
                for node in record['facts']:
                    self.assertEqual(source[node['start']:node['end']], node['text'])
                    for field in node['captures'].values():
                        self.assertEqual(source[field['start']:field['end']], field['text'])

    def test_same_row_awaited_guard_precedes_exposure(self):
        result = self.assert_signals('idor-right-row', [])
        self.assertTrue(any(row['rule'] == 'SEC-IDOR' and row['reason'] == 'same_row_guard_before_exposure'
                            for row in result['omissions']))

    def test_third_argument_is_not_the_fourth_permission_context(self):
        # Preserve the original capture: its third argument is the module slot,
        # not requireCan's fourth permission context. A same-row-looking object
        # there cannot suppress the signal under the explicit terminal contract.
        result = self.assert_signals('review-01_same_row_await', ['SEC-IDOR'])
        self.assertFalse(any(row['rule'] == 'SEC-IDOR' for row in result['omissions']))

    def test_other_row_unawaited_boolean_and_nested_helpers_do_not_protect(self):
        for case in ('idor-unprotected', 'idor-other-row', 'idor-nested', 'idor-bool-ignored',
                     'idor-no-await', 'review-02_other_row', 'review-03_unawaited_row'):
            with self.subTest(case=case):
                result = self.assert_signals(case, ['SEC-IDOR'])
                self.assertFalse(any(row['rule'] == 'SEC-IDOR' for row in result['omissions']))

    def test_second_read_requires_its_own_guard(self):
        result = self.assert_signals('idor-read-second', ['SEC-IDOR'])
        row = self.cases['idor-read-second']
        expected_offset = row['source'].rindex('db.findUnique')
        self.assertEqual([r['offset'] for r in result['signals']], [expected_offset])
        self.assertEqual(len(result['omissions']), 1)
        self.assertLess(result['omissions'][0]['offset'], expected_offset)

    def test_tagged_sql_preserves_request_alias(self):
        self.assert_signals('idor-sql-alias', ['SEC-IDOR'])

    def test_owner_assignment_in_write_payload_is_not_scope_filter(self):
        result = self.assert_signals('review-09_assignment_not_scope', ['SEC-IDOR'])
        self.assertEqual(result['omissions'], [])

    def test_json_and_string_literals_do_not_become_calls_or_otp_codes(self):
        for case in ('mass-text', 'mass-literal-arg', 'otp-icon', 'review-07_json_string'):
            with self.subTest(case=case):
                self.assert_signals(case, [])

    def test_real_mass_write_and_reassigned_hash_keep_signal(self):
        for case in ('mass-real', 'mass-reassigned', 'review-08_shadowed_hash'):
            with self.subTest(case=case):
                self.assert_signals(case, ['SEC-MASS'])

    def test_unchanged_hash_construction_is_a_local_candidate(self):
        self.assert_signals('mass-hash', [])

    def test_upload_controls_require_same_file_and_enforcing_sequence(self):
        for case in ('upload-other', 'upload-safe', 'review-04_boolean_upload',
                     'review-05_nested_upload', 'review-06_unawaited_sniff'):
            with self.subTest(case=case):
                result = self.assert_signals(case, ['SEC-UPLOAD'])
                self.assertFalse(any(row['rule'] == 'SEC-UPLOAD' for row in result['omissions']))

    def test_awaited_sniff_and_size_rejection_are_same_file_candidates(self):
        result = self.assert_signals('upload-awaited', [])
        self.assertEqual(len(result['omissions']), 1)
        self.assertEqual(result['omissions'][0]['reason'], 'same_file_size_and_type_rejection_candidate')

    def test_form_fields_without_file_are_not_an_upload(self):
        self.assert_signals('upload-fields', [])

    def test_weak_otp_and_unawaited_limits_keep_signal(self):
        for case in ('otp-real', 'review-10_unawaited_otp_limits'):
            with self.subTest(case=case):
                self.assert_signals(case, ['SEC-OTP'])

    def test_auth_candidate_is_only_from_outer_route_scope(self):
        for case, expected in (('auth-straight', True), ('auth-nested', False), ('auth-comment', False)):
            with self.subTest(case=case):
                result = self.assert_signals(case, ['SEC-IDOR'])
                routes = [scope for scope in result['scopes'] if scope.function is not None
                          and scope.function['owner_function'] is None]
                self.assertEqual(len(routes), 1)
                candidate = Rules.auth_candidate(routes[0])
                self.assertEqual(candidate is not None, expected)
                if candidate:
                    self.assertEqual(candidate['reason'], 'configured_permission_helper_candidate')

    def test_partial_and_unsupported_records_do_not_claim_analysis(self):
        row = self.cases['mass-real']
        for status in ('PARTIAL', 'ERROR', 'UNAVAILABLE', 'UNSUPPORTED'):
            with self.subTest(status=status):
                record = dict(row['record'], status=status)
                result = Rules.analyze_file(row['path'], row['source'], record)
                self.assertEqual(result, {'signals': [], 'omissions': [], 'scopes': [], 'status': 'UNSUPPORTED'})


if __name__ == '__main__':
    unittest.main()
