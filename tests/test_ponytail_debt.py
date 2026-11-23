"""Pure debt contracts, locations, coverage and explicitly supplied line age."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))

from helix_ponytail_debt import debt, project_debt, with_line_ages

OBSERVED = '2026-10-26T12:00:00+00:00'
COMMENT = '# ponytail: ceiling: 50 rows; upgrade: indexed cache\n'


def coverage(sources):
    return dict(status='COMPLETE', files_total=len(sources), files_read=len(sources),
        files=[dict(file=file, status='read', sha256=hashlib.sha256(text.encode()).hexdigest())
               for file, text in sources.items()])


def snapshot(sources=None):
    sources = {'src/cache.py': COMMENT} if sources is None else sources
    return debt(sources, coverage(sources), observed_at=OBSERVED)


def age_record(report, **changes):
    row = report['rows'][0]
    result = dict(file=row['file'], line=row['line'], source_sha256=row['source_sha256'],
        head='a'*40, status='known', changed_at='2026-10-20T12:00:00+00:00', reason='HEAD_LINE_CHANGED')
    result.update(changes)
    return result


class PonytailDebt(unittest.TestCase):
    def test_upstream_and_explicit_forms_do_not_guess_missing_information(self):
        source = '\n'.join((
            '# ponytail: 50 rows, indexed cache, then measure',
            '# ponytail: ceiling: one process; upgrade: shared queue',
            '# ponytail: arbitrary explanation without a trigger',
            '# ponytail: upgrade: reusable worker',
            '# ponytail: ceiling: first; ceiling: second; upgrade: later')) + '\n'
        result = snapshot({'src/cache.py': source})
        self.assertEqual([(row['ceiling'], row['upgrade_path']) for row in result['rows']], [
            ('50 rows', 'indexed cache, then measure'), ('one process', 'shared queue'),
            ('arbitrary explanation without a trigger', None), (None, 'reusable worker'), (None, None)])
        self.assertEqual(result['counts']['no_trigger'], 2)
        self.assertEqual(result['counts']['no_ceiling'], 2)
        self.assertEqual(result['execution'], {'models': 0, 'application': False, 'credit': 0})

    def test_multiline_block_and_repeated_marker_keep_all_locations_and_hashes(self):
        source = '/*\n * ponytail: ceiling: 10 rows;\n * upgrade: indexed cache\n * ponytail: one queue, split later\n */\n'
        result = snapshot({'src/cache.ts': source})
        self.assertEqual([(row['line'], row['end_line']) for row in result['rows']], [(2, 4), (4, 4)])
        self.assertEqual(result['rows'][0]['upgrade_path'], 'indexed cache')
        self.assertEqual(len({row['id'] for row in result['rows']}), 2)
        self.assertEqual(len({row['comment_sha256'] for row in result['rows']}), 2)
        self.assertTrue(all(row['source_sha256'] == hashlib.sha256(source.encode()).hexdigest() for row in result['rows']))

    def test_code_areas_and_noncomment_documents_are_explicit(self):
        sources = {name: COMMENT for name in ('src/cache.py', 'legacy/cache.py', 'tests/cache.py', 'docs/cache.py')}
        sources.update({'README.md': '# ponytail: example, later', 'package-lock.json': '{"note":"ponytail: example"}'})
        result = snapshot(sources)
        self.assertEqual(result['counts']['by_area'], {'active': 1, 'docs': 1, 'legacy': 1, 'tests/examples': 1, 'unknown': 0})
        self.assertEqual(result['status'], 'COMPLETE')
        excluded = [row['file'] for row in result['coverage']['files'] if row['status'] == 'EXCLUDED']
        self.assertEqual(excluded, ['README.md', 'package-lock.json'])
        self.assertEqual(result['coverage']['gaps'], [])

    def test_css_url_literal_is_not_a_comment_and_unknown_language_is_incomplete(self):
        source = '.x { background: url(data:/*ponytail:phantom,never*/); }\n/* ponytail: one theme, split later */'
        result = snapshot({'src/theme.css': source, 'src/cache.rb': '# ponytail: one queue, split later'})
        self.assertEqual([(row['file'], row['line']) for row in result['rows']], [('src/theme.css', 2)])
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['coverage']['read_status'], 'COMPLETE')
        self.assertEqual(result['coverage']['comment_status'], 'INCOMPLETE')
        self.assertIn('UNSUPPORTED_FILE_TYPE', [gap['code'] for gap in result['coverage']['gaps']])

    def test_missing_or_partial_read_coverage_never_means_no_debt(self):
        sources = {'src/cache.py': COMMENT}
        missing = debt(sources, None, observed_at=OBSERVED)
        self.assertEqual(missing['status'], 'INCOMPLETE')
        self.assertEqual(missing['counts']['markers'], 1)
        declared = coverage({**sources, 'src/omitted.py': COMMENT})
        partial = debt(sources, declared, observed_at=OBSERVED)
        self.assertEqual(partial['status'], 'INCOMPLETE')
        self.assertIn({'file': 'src/omitted.py', 'line': 1, 'code': 'SOURCE_NOT_SUPPLIED'}, partial['coverage']['gaps'])
        self.assertEqual(snapshot({})['status'], 'INCOMPLETE')

    def test_marker_free_large_source_keeps_complete_whole_source_identity(self):
        source = 'const item = 1; // filler\n' * 50000
        result = snapshot({'src/large.ts': source})
        self.assertEqual(result['rows'], [])
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertEqual(result['coverage']['files'][0]['source_sha256'], hashlib.sha256(source.encode()).hexdigest())
        self.assertNotEqual(result['source_digest'], snapshot({'src/large.ts': source + 'const end = 2;'})['source_digest'])

    def test_long_relative_path_is_preserved_but_unsafe_path_is_a_gap(self):
        long_path = ('nested/' * 90) + 'cache.py'
        result = snapshot({long_path: COMMENT, '/outside/client-secret.py': COMMENT, 'x'*8200+'.py': COMMENT})
        self.assertEqual([row['file'] for row in result['rows']], [long_path])
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIn('UNSUPPORTED_SOURCE_PATH', [gap['code'] for gap in result['coverage']['gaps']])
        self.assertNotIn('/outside/', json.dumps(result))

    def test_known_line_age_is_bound_to_source_and_does_not_mutate_input(self):
        original = snapshot(); before = copy.deepcopy(original)
        records = [age_record(original)]
        result = with_line_ages(original, records, observed_at=OBSERVED)
        self.assertEqual(original, before)
        self.assertEqual(result['rows'][0]['age_days'], 6)
        self.assertEqual(result['rows'][0]['age_basis'], 'last_changed_line_at_HEAD')
        self.assertEqual(result['counts']['age_known'], 1)
        self.assertEqual(result, with_line_ages(result, records, observed_at=OBSERVED))

    def test_missing_future_unbound_or_unavailable_line_history_remains_unknown(self):
        original = snapshot()
        cases = [({}, 'NOT_PROVIDED'),
                 ({'changed_at': '2026-10-27T00:00:00Z'}, 'FUTURE_TIMESTAMP'),
                 ({'source_sha256': 'b'*64}, 'BLOB_MISMATCH'),
                 ({'changed_at': 'not a date'}, 'HISTORY_UNAVAILABLE'),
                 ({'status': 'unknown', 'reason': 'SOURCE_DIRTY'}, 'SOURCE_DIRTY')]
        for changes, reason in cases:
            with self.subTest(reason=reason):
                records = [age_record(original, **changes)] if changes else []
                row = with_line_ages(original, records, observed_at=OBSERVED)['rows'][0]
                self.assertEqual(row['age_status'], 'unknown')
                self.assertEqual(row['age_reason'], reason)
                self.assertIsNone(row['age_days'])
                self.assertIsNone(row['age_head'])

    def test_duplicate_age_rows_are_rejected_and_age_changes_require_new_observed_at(self):
        original = snapshot(); record = age_record(original)
        with self.assertRaises(ValueError):with_line_ages(original, [record, record], observed_at=OBSERVED)
        result = with_line_ages(original, [record], observed_at='2026-10-27T12:00:00+00:00')
        self.assertEqual(result['rows'][0]['age_days'], 7)
        result['rows'][0]['age_days'] = 6
        with self.assertRaises(ValueError):project_debt(result)

    def test_legacy_unknown_is_distinct_from_known_zero_and_projection_is_idempotent(self):
        legacy = project_debt(None)
        self.assertEqual(legacy, project_debt(legacy))
        self.assertEqual(legacy['status'], 'NOT_RECORDED')
        self.assertTrue(all(value is None for value in legacy['counts'].values()))
        zero = snapshot({'src/empty.py': '# no marker\n'})
        self.assertEqual(zero['counts']['markers'], 0)
        self.assertEqual(zero['status'], 'COMPLETE')
        self.assertEqual(zero, project_debt(zero))

    def test_projection_rejects_tampered_counts_fields_types_and_secret_literals(self):
        original = snapshot()
        mutations = [lambda value: value['counts'].update(markers=9),
                     lambda value: value.update(schema_version=True),
                     lambda value: value.update(raw_comment='must not be public'),
                     lambda value: value['rows'][0].update(upgrade_path='secret=CANARY_VALUE'),
                     lambda value: value['rows'][0].update(source_sha256='c'*64)]
        for mutate in mutations:
            value = copy.deepcopy(original); mutate(value)
            with self.subTest(mutation=mutate):
                with self.assertRaisesRegex(ValueError, '^ponytail debt: invalid or unbound report$'):project_debt(value)


if __name__ == '__main__':
    unittest.main()
