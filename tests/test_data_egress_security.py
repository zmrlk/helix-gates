"""Independent, synthetic boundaries for unsent source preparation."""
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
import helix_data_egress as E

NOW = '2026-10-26T06:00:00+00:00'


def approved(**changes):
    result = {'status': 'approved', 'allowed_providers': ['claude'], 'exclude_paths': []}
    result.update(changes)
    return result


def covered(sources):
    return {'status': 'COMPLETE', 'files_total': len(sources), 'files_read': len(sources),
            'files': [{'file': p, 'status': 'read', 'sha256': hashlib.sha256(t.encode()).hexdigest()}
                      for p, t in sources.items()]}


def prepared(sources, **changes):
    args = {'coverage': covered(sources), 'policy': approved(), 'provider': 'claude',
            'observed_at': NOW}
    args.update(changes)
    return E.prepare_sources(sources, **args)


class DataEgressSecurity(unittest.TestCase):
    def test_approval_and_provider_boundary_precedes_any_source_redaction(self):
        for policy, provider, code in (
                (None, 'claude', 'POLICY_REQUIRED'),
                (approved(status='pending_owner'), 'claude', 'POLICY_NOT_APPROVED'),
                (approved(), 'claude-via-agy', 'PROVIDER_NOT_ALLOWED'),
                (approved(), 'anthropic', 'INVALID_PROVIDER'),
                (approved(allowed_providers=[]), 'claude', 'PROVIDER_NOT_ALLOWED')):
            with self.subTest(code=code, provider=provider), \
                    patch.object(E, 'redact_text', side_effect=AssertionError('read before approval')):
                with self.assertRaises(E.DataEgressError) as caught:
                    E.prepare_sources(None, None, policy, provider, NOW)
                self.assertEqual(str(caught.exception), 'data_egress: '+code)

    def test_scope_is_literal_for_routes_but_rejects_traversal_without_echo(self):
        route = 'frontend/src/routes/(group)/[id]/[...rest]/+page.server.ts'
        outbound, meta = prepared({route: 'export const answer = 42;\n'})
        self.assertEqual(set(outbound), {route})
        self.assertEqual(meta['delivery'], 'NOT_SENT')
        for path in ('src/../../CANARY', 'src/%2E%2E/CANARY', 'src\\..\\CANARY',
                     '//server/CANARY', 'src/\x00CANARY', 'src/\ud800CANARY'):
            with self.subTest(path=repr(path)), self.assertRaises(E.DataEgressError) as caught:
                prepared({path: 'PATH_SECRET_CANARY'})
            self.assertNotIn('CANARY', str(caught.exception))

    def test_default_directory_itself_and_descendants_remain_excluded(self):
        sources = {p: 'EXCLUDED_PAYLOAD_CANARY' for p in
                   ('.git', '.git/config', 'nested/.git', '.AWS', '.AWS/config', 'private',
                    'nested/private', 'nested/private/file.py', 'nested/FIXTURES/a.json',
                    '.ENV', 'src/internal/[id]/data.ts')}
        sources['src/public.ts'] = 'export const answer = 42;\n'
        outbound, meta = prepared(sources, policy=approved(exclude_paths=['src/internal/**']))
        self.assertEqual(outbound, {'src/public.ts': sources['src/public.ts']})
        self.assertEqual(meta['status'], 'INCOMPLETE')
        self.assertEqual(meta['counts']['excluded_files'], len(sources)-1)
        self.assertNotIn('EXCLUDED_PAYLOAD_CANARY', json.dumps(meta))

    def test_yaml_block_scalars_are_not_mistaken_for_complete_single_line_values(self):
        for marker in ('|', '|-', '|+', '>', '>-', '>+2'):
            for sign in ('', '-'):
                source = f'{sign}password: {marker}\r\n{sign}  BLOCK_SECRET_CANARY\r\n{sign}safe: 42\r\n'
                with self.subTest(marker=marker, diff=bool(sign)):
                    outbound, meta = E.redact_text(source, source_path='settings.yaml')
                    self.assertNotIn('BLOCK_SECRET_CANARY', outbound)
                    self.assertNotIn('BLOCK_SECRET_CANARY', json.dumps(meta))
                    self.assertEqual(outbound.count('\r\n'), 3)
                    self.assertEqual(meta['redacted_lines'], 3)
                    if sign:
                        self.assertTrue(all(line.startswith('-') for line in outbound.splitlines()))

    def test_deleted_pem_and_pii_are_masked_across_crlf_without_raw_ranges(self):
        source = ('@@ -1,6 +1,1 @@\r\n'
                  '------BEGIN PRIVATE KEY-----\r\n-OPAQUE_PEM_CANARY\r\n'
                  '------END PRIVATE KEY-----\r\n'
                  '-# Person mail.person@example.invalid tel +48 501 234 567\r\n'
                  '+export const answer = 42;\r\n')
        result, meta = E.redact_text(source, source_path='src/main.ts')
        self.assertNotIn('CANARY', result)
        self.assertNotIn('mail.person', result)
        self.assertNotIn('501', result)
        self.assertNotIn('PRIVATE KEY', json.dumps(meta))
        self.assertEqual(meta['redacted_lines'], 4)
        self.assertEqual(result.count('\r\n'), 6)
        self.assertTrue(all(set(row) == {'line', 'end_line', 'codes'} for row in meta['redactions']))

    def test_deleted_assignment_at_column_zero_cannot_escape_redaction(self):
        for assignment in ('password="REMOVED_SECRET_CANARY"',
                           'api_key: REMOVED_SECRET_CANARY',
                           'email: removed.person@example.invalid'):
            text = '@@ -1 +1 @@\n-'+assignment+'\n+answer=42\n'
            with self.subTest(assignment=assignment):
                result, meta = E.redact_text(text, source_path='src/main.py')
                self.assertNotIn('REMOVED_SECRET_CANARY', result)
                self.assertNotIn('removed.person', result)
                self.assertIn('-[HELIX_REDACTED]\n', result)
                self.assertEqual(meta['redactions'][0]['line'], 2)

    def test_code_reference_exception_cannot_hide_fallback_or_embedded_literal(self):
        for suffix in (' || "LITERAL_CANARY";', ' ?? "LITERAL_CANARY";',
                       '; const other="LITERAL_CANARY";', ' + "LITERAL_CANARY";'):
            with self.subTest(suffix=suffix):
                result, meta = E.redact_text('const password = process.env.PASSWORD'+suffix+'\n',
                                             source_path='src/auth.ts')
                self.assertNotIn('LITERAL_CANARY', result)
                self.assertEqual(meta['redacted_lines'], 1)
        for path, text in (
                ('settings.yaml', 'password: process.env.PASSWORD\n'),
                ('src/auth.ts', 'const text = `\npassword = process.env.PASSWORD\n`;\n'),
                ('src/auth.ts', '-const password = process.env.PASSWORD\n'),
                ('src/auth.py', 'text = """\npassword = source.value\n"""\n')):
            with self.subTest(path=path, text=text):
                result, meta = E.redact_text(text, source_path=path)
                self.assertGreater(meta['redacted_lines'], 0)
                self.assertNotIn('password = ', result)
                self.assertNotIn('password: ', result)

    def test_full_manifest_does_not_echo_policy_or_coverage_values(self):
        sources = {'src/one.py': 'email="payload.person@example.invalid"\n'}
        coverage = covered(sources)
        coverage['files'][0]['reason'] = 'COVERAGE_PRIVATE_CANARY'
        coverage['private_note'] = 'COVERAGE_PRIVATE_CANARY'
        policy = approved(approved_by='approval.person@example.invalid')
        outbound, meta = prepared(sources, coverage=coverage, policy=policy)
        encoded = json.dumps({'sources': outbound, 'metadata': meta})
        for canary in ('payload.person', 'approval.person', 'COVERAGE_PRIVATE_CANARY'):
            self.assertNotIn(canary, encoded)
        self.assertEqual(meta['delivery'], 'NOT_SENT')
        self.assertEqual(meta['review_status'], 'NOT_RUN')
        self.assertTrue(all(v == 0 for v in meta['execution'].values()))
        self.assertEqual(meta['status'], 'INCOMPLETE')

    def test_coverage_conflicts_missing_hash_and_skipped_sources_preserve_gaps(self):
        sources = {'src/one.ts': 'const answer=42;\n', 'src/two.ts': 'const answer=43;\n'}
        for mutation in ('wrong_hash', 'missing_hash', 'skipped', 'missing_row', 'count_bool'):
            coverage = covered(sources)
            if mutation == 'wrong_hash': coverage['files'][0]['sha256'] = '0'*64
            if mutation == 'missing_hash': coverage['files'][0].pop('sha256')
            if mutation == 'skipped': coverage['files'][0]['status'] = 'skipped'
            if mutation == 'missing_row': coverage['files'].pop(0)
            if mutation == 'count_bool': coverage['files_total'] = True
            with self.subTest(mutation=mutation):
                outbound, meta = prepared(sources, coverage=coverage)
                self.assertEqual(meta['status'], 'INCOMPLETE')
                self.assertTrue(meta['gaps'])
                if mutation in ('wrong_hash', 'skipped'):
                    self.assertNotIn('src/one.ts', outbound)
        malformed = covered(sources)
        malformed['files'][0]['sha256'] = 'HASH_PRIVATE_CANARY'
        with self.assertRaises(E.DataEgressError) as caught:
            prepared(sources, coverage=malformed)
        self.assertEqual(str(caught.exception), 'data_egress: INVALID_COVERAGE')

    def test_inputs_and_prior_results_do_not_change_when_returned_objects_are_mutated(self):
        sources = {'src/one.ts': 'export const answer = 42;\n'}
        coverage, policy = covered(sources), approved()
        before = copy.deepcopy((sources, coverage, policy))
        outbound, meta = prepared(sources, coverage=coverage, policy=policy)
        expected = copy.deepcopy((outbound, meta))
        outbound.clear()
        meta['files'][0]['path'] = 'MUTATED'
        meta['limitations'].clear()
        normalized = E.normalize_policy(policy)
        normalized['allowed_providers'].append('codex')
        normalized['exclude_paths'].clear()
        self.assertEqual((sources, coverage, policy), before)
        self.assertEqual(prepared(sources, coverage=coverage, policy=policy), expected)

    def test_large_invalid_email_and_literal_after_long_line_are_processed_without_truncation(self):
        script = '''import sys
sys.path.insert(0,sys.argv[1])
from helix_data_egress import redact_text
for text in ('a'*200000+'@', 'A1 '*70000, 'word='+'a'*200000):
    result, meta=redact_text(text)
    assert meta['lines_total']==1
text='x'*200000+'\\npassword: |-\\n  LAST_PRIVATE_CANARY\\n'
result,meta=redact_text(text,source_path='settings.yaml')
assert 'LAST_PRIVATE_CANARY' not in result
assert meta['redacted_lines']==3
print('ok')
'''
        result = subprocess.run([sys.executable, '-c', script, str(ROOT/'bin')],
                                capture_output=True, text=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'ok')


if __name__ == '__main__':
    unittest.main()
