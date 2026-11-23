"""Offline integration replay of AST facts captured from synthetic code."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_static_ast as AST
import helix_static_security as Security

FIXTURE = Path(__file__).parent / 'fixtures/security-ast/integration.json'
FIXTURE_SHA256 = '7a23524fee55bc0682fa56973e210f9bbad332876b019463fb3dd47375543f2a'


class SecurityASTIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = json.loads(FIXTURE.read_text())
        cls.cases = {row['path']: row for row in cls.bundle['cases']}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for target in ('subprocess.Popen', 'socket.socket', 'shutil.which',
                       'helix_tools_manager.resolve_installed'):
            guard = patch(target, side_effect=AssertionError('recorded replay must not execute tools'))
            guard.start()
            self.addCleanup(guard.stop)

    def analyze(self, *names, unavailable=False):
        cases = [self.cases[name] for name in names]
        snapshot = [(row['path'], row['source']) for row in cases]
        replay = {'files': {row['path']: copy.deepcopy(row['record']) for row in cases},
                  'public': copy.deepcopy(self.bundle['capture'])}
        if unavailable:
            replay = {'files': {}, 'public': {
                'engine': {'name': 'ast-grep', 'used': False},
                'coverage': {'status': 'INCOMPLETE', 'reason': 'TOOL_UNAVAILABLE'},
                'usage': {'calls': 0, 'input_bytes': 0}}}
        with patch.object(AST, 'analyze_snapshot', return_value=replay) as capture:
            result = Security.analyze(self.root, source_snapshot=snapshot, engine='auto')
        capture.assert_called_once_with(snapshot)
        return result

    def findings(self, result, code, file):
        return [row for row in result['findings'] if row['id'] == code and row['file'] == file]

    def test_fixture_is_real_ast_capture_bound_to_exact_synthetic_source(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(len(self.cases), 8)
        engine = self.bundle['capture']['engine']
        self.assertEqual(engine['name'], 'ast-grep')
        self.assertEqual(engine['version'], '0.51.0')
        self.assertEqual(engine['proof_kind'], 'subprocess')
        for row in self.cases.values():
            with self.subTest(file=row['path']):
                raw, record = row['source'], row['record']
                self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), row['source_sha256'])
                self.assertEqual(record['source_sha256'], row['source_sha256'])
                for node in record['facts']:
                    self.assertEqual(raw[node['start']:node['end']], node['text'])
                    for field in node['captures'].values():
                        self.assertEqual(raw[field['start']:field['end']], field['text'])

    def test_type_cast_transaction_alias_does_not_erase_idor(self):
        file = 'src/routes/cast/+server.ts'
        rows = self.findings(self.analyze(file), 'SEC-IDOR', file)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['evidence_kind'], 'ast_local_relation')

    def test_member_pin_comparison_does_not_erase_otp(self):
        file = 'src/routes/pin/+server.ts'
        rows = self.findings(self.analyze(file), 'SEC-OTP', file)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['evidence_kind'], 'ast_local_relation')

    def test_array_buffer_alias_written_without_limits_keeps_upload(self):
        file = 'src/routes/upload/+server.ts'
        rows = self.findings(self.analyze(file), 'SEC-UPLOAD', file)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['evidence_kind'], 'ast_local_relation')

    def test_svelte_markup_outside_parsed_scripts_retains_lexical_signal(self):
        file = 'src/lib/Widget.svelte'
        record = self.cases[file]['record']
        self.assertEqual(record['status'], 'PARSED')
        self.assertIn({'code': 'SVELTE_MARKUP_NOT_ANALYZED'}, record['gaps'])
        rows = self.findings(self.analyze(file), 'SEC-MASS', file)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['line'], 2)
        self.assertEqual(rows[0]['evidence_kind'], 'lexical_fallback')

    def test_nested_where_in_payload_is_not_operation_scope(self):
        file = 'src/routes/nested-where/+server.ts'
        result = self.analyze(file)
        self.assertEqual(len(self.findings(result, 'SEC-IDOR', file)), 1)
        self.assertFalse(any(row.get('rule') == 'SEC-IDOR'
                             for row in result['static_engine']['local_candidates']))

    def test_endpoint_text_inside_string_is_not_a_route(self):
        file = 'src/lib/example.ts'
        result = self.analyze(file)
        self.assertEqual(result['endpoints'], [])
        self.assertFalse(self.findings(result, 'SEC-AUTH', file))

    def test_partial_ast_record_keeps_lexical_idor_and_auth_unknown(self):
        file = 'src/routes/partial/+server.ts'
        self.assertEqual(self.cases[file]['record']['status'], 'PARTIAL')
        result = self.analyze(file)
        rows = self.findings(result, 'SEC-IDOR', file)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['evidence_kind'], 'lexical_fallback')
        self.assertFalse(result['endpoints'][0]['guard_candidate'])

    def test_inline_comment_guard_does_not_protect_actual_endpoint(self):
        file = 'src/routes/comment/+server.ts'
        result = self.analyze(file)
        self.assertFalse(result['endpoints'][0]['guard_candidate'])
        self.assertEqual(result['endpoints'][0]['evidence_kind'], 'ast_local_relation')
        self.assertEqual(len(self.findings(result, 'SEC-IDOR', file)), 1)
        self.assertEqual(len(self.findings(result, 'SEC-AUTH', file)), 1)

    def test_unavailable_ast_preserves_signals_with_explicit_fallback(self):
        files = ['src/routes/cast/+server.ts', 'src/routes/pin/+server.ts',
                 'src/routes/upload/+server.ts', 'src/lib/Widget.svelte']
        result = self.analyze(*files, unavailable=True)
        for file, code in zip(files, ('SEC-IDOR', 'SEC-OTP', 'SEC-UPLOAD', 'SEC-MASS')):
            with self.subTest(file=file):
                rows = self.findings(result, code, file)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['evidence_kind'], 'lexical_fallback')
        self.assertEqual(result['static_engine']['coverage']['status'], 'INCOMPLETE')
        self.assertFalse(result['static_engine']['engine']['used'])

    def test_internal_default_stays_lexical_without_tool_resolution(self):
        file = 'src/routes/cast/+server.ts'
        snapshot = [(file, self.cases[file]['source'])]
        with patch.object(AST, 'analyze_snapshot', side_effect=AssertionError('lexical default must not call AST')):
            result = Security.analyze(self.root, source_snapshot=snapshot)
        self.assertEqual(len(self.findings(result, 'SEC-IDOR', file)), 1)
        self.assertEqual(result['static_engine']['engine']['name'], 'lexical')


if __name__ == '__main__':
    unittest.main()
