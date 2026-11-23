"""Offline boundaries for a pure source-preparation helper, never delivery."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
from helix_data_egress import (DEFAULT_EXCLUDE_PATHS, DataEgressError,
    normalize_policy, policy_sha256, prepare_sources, redact_text)

OBSERVED = '2026-10-26T12:00:00+00:00'


def approved(**changes):
    result = dict(status='approved', allowed_providers=['codex'], exclude_paths=[])
    result.update(changes)
    return result


def coverage(sources, **changes):
    result = dict(status='COMPLETE', files_total=len(sources), files_read=len(sources),
        files=[dict(file=name, status='read', sha256=hashlib.sha256(text.encode()).hexdigest())
               for name, text in sources.items()])
    result.update(changes)
    return result


def prepare(sources=None, **changes):
    sources = {'src/main.py': 'print("hello")\n'} if sources is None else sources
    options = dict(coverage=coverage(sources), policy=approved(), provider='codex', observed_at=OBSERVED)
    options.update(changes)
    return prepare_sources(sources, **options)


class DataEgress(unittest.TestCase):
    def test_missing_pending_legacy_or_unknown_policy_is_fixed_error_before_source_use(self):
        for policy, code in ((None, 'POLICY_REQUIRED'),
                ({'status': 'pending_owner', 'allowed_providers': [], 'exclude_paths': []}, 'POLICY_NOT_APPROVED'),
                ({'status': 'approved', 'allowlist': ['secret-user@example.invalid']}, 'INVALID_POLICY'),
                (approved(unknown='PRIVATE_CANARY'), 'INVALID_POLICY')):
            with self.subTest(code=code), patch('helix_data_egress.redact_text', side_effect=AssertionError('source examined')):
                with self.assertRaises(DataEgressError) as caught:
                    prepare_sources(None, None, policy, 'codex', OBSERVED)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(str(caught.exception), 'data_egress: ' + code)
                self.assertEqual(caught.exception.status, 'ERROR')

    def test_provider_ids_are_exact_no_wildcard_family_alias_or_fallback(self):
        for provider in ('claude', 'claude-via-agy', 'gemini', 'gemini-flash', 'grok', 'grok-cli'):
            with self.subTest(provider=provider), self.assertRaises(DataEgressError) as caught:
                prepare(provider=provider)
            self.assertEqual(caught.exception.code, 'PROVIDER_NOT_ALLOWED')
        for provider in ('openai', 'google', '*', 'CODEX', None, ['codex']):
            with self.subTest(provider=provider), self.assertRaises(DataEgressError) as caught:
                prepare(provider=provider)
            self.assertEqual(caught.exception.code, 'INVALID_PROVIDER')
        with self.assertRaises(DataEgressError) as caught:
            prepare(policy=approved(allowed_providers=[]))
        self.assertEqual(caught.exception.code, 'PROVIDER_NOT_ALLOWED')
        self.assertEqual(prepare(policy=approved(allowed_providers=['gemini']), provider='gemini')[1]['provider'], 'gemini')

    def test_schema_types_unknown_keys_and_ambiguous_legacy_not_reinterpreted(self):
        variants = [approved(schema_version=True), approved(schema_version=2), approved(allowed_providers='codex'),
            approved(allowed_providers=['codex', 'codex']), approved(allowed_providers=['openai']),
            approved(exclude_paths=None), approved(exclude_paths=['../client']),
            approved(exclude_paths=['/outside/**']), approved(exclude_paths=['**/[a-z].py']),
            approved(exclude_paths=['!secrets/**']), approved(exclude_paths=['regex:^src']),
            approved(approved_by='CANARY\nvalue'), approved(approved_at='2026-10-26')]
        for policy in variants:
            with self.subTest(policy=policy), self.assertRaises(DataEgressError) as caught:
                normalize_policy(policy)
            self.assertEqual(caught.exception.code, 'INVALID_POLICY')

    def test_policy_defaults_are_mandatory_idempotent_and_hashes_canonical(self):
        original = approved(allowed_providers=['claude', 'codex'], exclude_paths=['src/excluded/**'],
            approved_by='owner@example.invalid', approved_at='2026-10-26T14:00:00+02:00')
        before = copy.deepcopy(original)
        normalized = normalize_policy(original)
        self.assertEqual(original, before)
        self.assertTrue(set(DEFAULT_EXCLUDE_PATHS).issubset(normalized['exclude_paths']))
        self.assertEqual(normalized, normalize_policy(normalized))
        self.assertEqual(policy_sha256(original), policy_sha256(normalized))
        reversed_order = copy.deepcopy(original); reversed_order['allowed_providers'].reverse()
        self.assertEqual(policy_sha256(original), policy_sha256(reversed_order))
        self.assertNotEqual(policy_sha256(original), policy_sha256(approved()))
        _, manifest = prepare(policy=original)
        self.assertNotIn('owner@example.invalid', json.dumps(manifest))
        self.assertEqual(manifest['approval_basis'], 'owner_declaration_not_independently_verified')

    def test_prepared_is_not_sent_or_reviewed_and_no_io_clock_process_network(self):
        sources = {'src/main.py': 'answer = 42\n'}
        with patch('builtins.open', side_effect=AssertionError('open')), \
                patch('os.open', side_effect=AssertionError('os.open')), \
                patch('subprocess.run', side_effect=AssertionError('subprocess')), \
                patch('socket.socket', side_effect=AssertionError('socket')), \
                patch('time.time', side_effect=AssertionError('clock')):
            outbound, manifest = prepare(sources)
        self.assertEqual(outbound, sources)
        self.assertEqual(manifest['status'], 'PREPARED')
        self.assertEqual(manifest['delivery'], 'NOT_SENT')
        self.assertEqual(manifest['review_status'], 'NOT_RUN')
        self.assertEqual(manifest['execution'], dict(files_opened=0, commands=0, models=0, network=0))
        self.assertEqual(manifest['gaps'], [])
        self.assertIn('NOT_SENT', ' '.join(manifest['limitations']))

    def test_default_exclusions_apply_at_root_and_nested_case_insensitively(self):
        names = ('.env', '.env.example', 'app/.env.production', 'Secrets/config.json', 'credentials.yaml',
            'fixtures/customer.json', 'app/test-fixtures/one.json', 'db/seeds/001.sql', 'seed.ts',
            'archive/dump.sql.gz', 'backups/data.sql', 'data.backup', 'records.sqlite3',
            '.aws/config', '.git/config', '.ssh/config', 'app/.npmrc', 'private/data.json', 'server.key')
        sources = {name: 'EXCLUDED_CONTENT_CANARY' for name in names}
        sources['src/main.py'] = 'answer = 42\n'
        with patch('helix_data_egress.redact_text', wraps=redact_text) as redactor:
            outbound, manifest = prepare(sources)
        self.assertEqual(outbound, {'src/main.py': 'answer = 42\n'})
        self.assertEqual(redactor.call_count, 1)
        self.assertEqual(len(manifest['exclusions']), len(names))
        self.assertEqual(manifest['status'], 'INCOMPLETE')
        self.assertNotIn('EXCLUDED_CONTENT_CANARY', json.dumps(manifest))
        self.assertTrue(all(r['outbound_sha256'] is None for r in manifest['files'] if r['status'] == 'excluded'))

    def test_custom_globs_extend_defaults_and_keep_exclusion_gaps(self):
        sources = {'src/internal/a.py': 'x=1', 'src/a.py': 'x=2', 'src/main.py': 'x=3', '.env': 'secret'}
        outbound, manifest = prepare(sources, policy=approved(exclude_paths=['src/internal/**', 'src/?.py']))
        self.assertEqual(outbound, {'src/main.py': 'x=3'})
        self.assertEqual({r['path'] for r in manifest['exclusions']}, set(sources)-set(outbound))
        self.assertEqual({r['code'] for r in manifest['exclusions']}, {'POLICY_PATH_EXCLUDED', 'DEFAULT_PATH_EXCLUDED'})

    def test_dynamic_route_filenames_are_literal_and_parent_glob_can_exclude(self):
        names = ('frontend/src/routes/(account)/items/[id]/+page.server.ts',
                 'app/[...slug]/page.tsx', 'pages/{draft}/[name].tsx')
        sources = {name: 'export const value = 42;\n' for name in names}
        outbound, manifest = prepare(sources)
        self.assertEqual(outbound, sources)
        self.assertEqual(manifest['status'], 'PREPARED')
        outbound, manifest = prepare(sources, policy=approved(exclude_paths=['frontend/src/routes/(account)/items/**']))
        self.assertNotIn(names[0], outbound)
        self.assertEqual(manifest['exclusions'], [{'path': names[0], 'code': 'POLICY_PATH_EXCLUDED'}])

    def test_unsafe_or_pii_paths_never_appear_in_errors_or_metadata(self):
        for name in ('../client.py', '/absolute.py', 'src/../x.py', './x.py', 'src//x.py',
                     'C:\\client.py', 'https://example.invalid/file.py', 'src/%2e%2e/x.py',
                     'src/line\nCANARY.py', 'src/customer@example.invalid.json'):
            with self.subTest(name=name), self.assertRaises(DataEgressError) as caught:
                prepare({name: 'PATH_PAYLOAD_CANARY'})
            self.assertEqual(str(caught.exception), 'data_egress: UNSAFE_SOURCE_PATH')

    def test_credentials_email_phone_and_pii_fields_are_removed_without_raw_diagnostics(self):
        values = [
            'const API_KEY = "api-canary-value";',
            'const config = {"password": "password-canary"};',
            '# reach person@example.invalid',
            '# telephone +48 600 700 800',
            'fullName: "Synthetic Person"',
            'street = "Example road 123"',
            'const payment = "sk_test_ABCxyz123456789";',
            'const authorization = "Bearer synthetic-token-value";',
            'const uri = "postgres://private-user:private-pass@localhost/db";',
            'const opaque = "AKIA1234567890ABCDEF";',
            'const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl";',
        ]
        for value in values:
            with self.subTest(value=value):
                outbound, metadata = redact_text(value+'\n')
                self.assertEqual(metadata['redacted_lines'], 1)
                self.assertNotIn(value, outbound)
                self.assertNotIn(value, json.dumps(metadata))
                self.assertEqual(outbound.count('\n'), 1)
                self.assertNotEqual(metadata['original_sha256'], metadata['outbound_sha256'])

    def test_pem_multiline_credentials_and_split_values_fail_closed_preserving_lines(self):
        cases = [
            ('safe\n-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE_CANARY\n-----END OPENSSH PRIVATE KEY-----\nafter\n', 3),
            ('password = """\nMULTILINE_CANARY\n"""\nsafe = True\n', 4),
            ('{"client_secret":\n "SPLIT_CANARY"}\nsafe=1\n', 3),
            ('const token = `prefix\nTEMPLATE_CANARY\n`;\n', 3),
            ('credentials = {\n "opaque": "OBJECT_CANARY"\n}\n', 3),
            ('FRAGMENT_CANARY\n-----END PRIVATE KEY-----\n', 2),
        ]
        for value, expected in cases:
            with self.subTest(expected=expected):
                outbound, metadata = redact_text(value)
                self.assertNotIn('CANARY', outbound)
                self.assertNotIn('CANARY', json.dumps(metadata))
                self.assertEqual(metadata['redacted_lines'], expected)
                self.assertEqual(outbound.count('\n'), value.count('\n'))

    def test_simple_code_references_and_types_survive_but_fallback_literals_do_not(self):
        cases = {
            'src/auth.ts': 'password: string;\ntoken: process.env.TOKEN,\nconst password = requestData.password;\n',
            'src/auth.py': 'password: str\npassword = request_data.password\ntoken = os.environ["TOKEN"]\n',
        }
        outbound, manifest = prepare(cases)
        self.assertEqual(outbound, cases)
        self.assertEqual(manifest['status'], 'PREPARED')
        for line in ('const token = process.env.TOKEN || "FALLBACK_CANARY";',
                     'token = os.environ["TOKEN"] or "FALLBACK_CANARY"',
                     'const password = obj.password; const other = "OTHER_CANARY";',
                     'password: str = "TYPE_CANARY"'):
            with self.subTest(line=line):
                value, meta = redact_text(line, source_path='src/auth.ts')
                self.assertNotIn('CANARY', value)
                self.assertEqual(meta['redacted_lines'], 1)

    def test_unknown_language_yaml_diff_and_ambiguous_literals_do_not_get_reference_exception(self):
        for path in (None, 'settings.yaml', 'notes.md', 'component.tsx'):
            with self.subTest(path=path):
                safe, meta = redact_text('token: values.owner\n', source_path=path)
                self.assertNotIn('values.owner', safe)
                self.assertEqual(meta['redacted_lines'], 1)
        for text, name in (('const doc = `\ntoken: values.owner\n`;\n', 'src/a.ts'),
                           ('doc = """\ntoken: values.owner\n"""\n', 'src/a.py'),
                           ('/*\ntoken: values.owner\n*/\n', 'src/a.js'),
                           ('<div>\ntoken: values.owner\n</div>\n', 'src/a.js')):
            with self.subTest(name=name):
                safe, meta = redact_text(text, source_path=name)
                self.assertNotIn('values.owner', safe)
                self.assertGreater(meta['redacted_lines'], 0)

    def test_deleted_diff_lines_are_redacted_and_crlf_line_numbers_survive(self):
        source = '@@ -1,2 +1,2 @@\r\n-const password="DELETED_CANARY";\r\n+const answer=42;\r\n'
        outbound, meta = redact_text(source)
        self.assertNotIn('DELETED_CANARY', outbound)
        self.assertIn('-[HELIX_REDACTED]\r\n', outbound)
        self.assertEqual(outbound.count('\r\n'), 3)
        self.assertEqual(meta['redactions'][0]['line'], 2)
        self.assertEqual(meta['redactions'][0]['end_line'], 2)

    def test_known_source_hash_and_missing_source_are_never_silently_rebound(self):
        sources = {'src/one.py': 'x=1\n', 'src/two.py': 'x=2\n'}
        read = coverage({**sources, 'src/missing.py': 'x=3\n'})
        read['files'][0]['sha256'] = '0'*64
        outbound, manifest = prepare(sources, coverage=read)
        self.assertEqual(outbound, {'src/two.py': 'x=2\n'})
        self.assertEqual(manifest['status'], 'INCOMPLETE')
        self.assertEqual({r['code'] for r in manifest['gaps']}, {'SOURCE_HASH_MISMATCH', 'SOURCE_NOT_SUPPLIED'})
        self.assertTrue(all(r['outbound_sha256'] is None for r in manifest['files'] if r['path'] not in outbound))

    def test_coverage_unknown_partial_contradictory_or_empty_is_not_prepared(self):
        source = {'src/one.py': 'x=1\n'}
        variants = [None, coverage(source, status='INCOMPLETE'), coverage(source, files_read=True),
                    coverage(source, files_total=4), coverage(source, files=[])]
        for read in variants:
            with self.subTest(read=read):
                _, manifest = prepare(source, coverage=read)
                self.assertEqual(manifest['status'], 'INCOMPLETE')
                self.assertTrue(manifest['gaps'])
                if read is None: self.assertIsNone(manifest['counts']['declared_files'])
        self.assertEqual(prepare({})[1]['status'], 'INCOMPLETE')

    def test_skipped_supplied_source_is_unavailable_and_raw_coverage_reason_not_projected(self):
        sources = {'src/main.py': 'x=1\n'}
        read = coverage(sources)
        read['files'][0].update(status='skipped', reason='COVERAGE_SECRET_CANARY')
        outbound, manifest = prepare(sources, coverage=read)
        self.assertEqual(outbound, {})
        self.assertEqual(manifest['counts']['unavailable_files'], 1)
        self.assertNotIn('COVERAGE_SECRET_CANARY', json.dumps(manifest))

    def test_declared_partial_line_coverage_cannot_claim_prepared_even_with_matching_hash(self):
        sources = {'src/main.py': 'x=1\n'}
        for field, value in (('lines_total', 2), ('lines_read', 0), ('lines_total', None)):
            read = coverage(sources)
            read['files'][0][field] = value
            with self.subTest(field=field, value=value):
                outbound, manifest = prepare(sources, coverage=read)
                self.assertEqual(outbound, {})
                self.assertEqual(manifest['status'], 'INCOMPLETE')
                self.assertIn('SOURCE_LINE_COVERAGE_MISMATCH', [g['code'] for g in manifest['gaps']])
        read = coverage(sources, unknown_line_totals=1)
        self.assertEqual(prepare(sources, coverage=read)[1]['status'], 'INCOMPLETE')
        read = coverage(sources, lines_total=9, lines_read=1)
        read['files'][0].update(lines_total=1, lines_read=1)
        self.assertEqual(prepare(sources, coverage=read)[1]['status'], 'INCOMPLETE')

    def test_malformed_or_duplicate_coverage_fails_without_echo(self):
        sources = {'src/main.py': 'x=1\n'}
        good = coverage(sources)
        variants = [{}, [], dict(status='COMPLETE', files=[{'file': '../PRIVATE_CANARY'}]),
            dict(status='COMPLETE', files=good['files']*2),
            dict(status='COMPLETE', files=[dict(file='src/main.py', status='read', sha256='PRIVATE_CANARY')])]
        for read in variants:
            with self.subTest(read=read), self.assertRaises(DataEgressError) as caught:
                prepare(sources, coverage=read)
            self.assertEqual(str(caught.exception), 'data_egress: INVALID_COVERAGE')

    def test_binary_and_invalid_unicode_cannot_be_outbound(self):
        outbound, manifest = prepare({'src/main.py': 'binary\x00PRIVATE_CANARY'})
        self.assertEqual(outbound, {})
        self.assertNotIn('PRIVATE_CANARY', json.dumps(manifest))
        self.assertIn('BINARY_SOURCE_NOT_SUPPORTED', [g['code'] for g in manifest['gaps']])
        for value in (b'bytes', '\ud800'):
            with self.subTest(value=type(value).__name__), self.assertRaises(DataEgressError):
                prepare_sources({'src/a.py': value}, None, approved(), 'codex', OBSERVED)

    def test_observation_requires_explicit_timezone_no_clock_or_future_guess(self):
        for value in (None, '2026-10-26', 'now', 3, '2026-10-26T12:00:00'):
            with self.subTest(value=value), self.assertRaises(DataEgressError) as caught:
                prepare(observed_at=value)
            self.assertEqual(caught.exception.code, 'INVALID_OBSERVED_AT')
        self.assertEqual(prepare(observed_at='2026-10-26T14:00:00+02:00')[1]['observed_at'], OBSERVED)

    def test_order_hashes_redaction_gaps_and_input_immutability(self):
        sources = {'src/z.py': 'answer=42\n', 'src/a.py': 'email="person@example.invalid"\n'}
        read, policy = coverage(sources), approved()
        before = copy.deepcopy((sources, read, policy))
        outbound, first = prepare(sources, coverage=read, policy=policy)
        _, second = prepare(dict(reversed(list(sources.items()))), coverage=coverage(dict(reversed(list(sources.items())))), policy=policy)
        self.assertEqual(first, second)
        self.assertEqual((sources, read, policy), before)
        self.assertEqual(first['status'], 'INCOMPLETE')
        self.assertEqual(first['counts']['redacted_lines'], 1)
        self.assertIn('CONTENT_REDACTED', [g['code'] for g in first['gaps']])
        for row in first['files']:
            self.assertEqual(row['original_sha256'], hashlib.sha256(sources[row['path']].encode()).hexdigest())
            self.assertEqual(row['outbound_sha256'], hashlib.sha256(outbound[row['path']].encode()).hexdigest())

    def test_large_inputs_are_fully_processed_with_bounded_runtime_not_truncated(self):
        # Isolated timeout catches accidental regex backtracking without hanging
        # the complete test gate. No subprocess accesses a network or repository.
        script = '''import sys
sys.path.insert(0, sys.argv[1])
from helix_data_egress import redact_text
samples = ['a'*1000000+'!', ('word=value; '*80000)+'end', ('token=1; '*20000)+'end']
for value in samples:
    result, meta = redact_text(value)
    assert meta['lines_total'] == 1
    assert meta['original_sha256']
result, meta = redact_text(' '*300000 + 'token=1; '*10000, source_path='src/a.ts')
assert meta['redacted_lines'] == 1
value = ('value = 42\\n'*100000) + 'email="LAST_CANARY@example.invalid"\\n'
result, meta = redact_text(value)
assert 'LAST_CANARY' not in result
assert meta['redactions'][-1]['line'] == 100001
assert result.count('\\n') == 100001
print('ok')
'''
        result = subprocess.run([sys.executable, '-c', script, str(ROOT/'bin')],
            capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'ok')


if __name__ == '__main__': unittest.main()
