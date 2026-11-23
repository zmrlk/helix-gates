"""Pure evaluator fixtures contain only synthetic metadata, never target code."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

MODULE = Path(__file__).resolve().parents[1] / 'bin/helix_bench.py'
SPEC = importlib.util.spec_from_file_location('staged_helix_bench', MODULE)
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)

TARGET = dict(path='/synthetic/project', commit='a' * 40, dirty=False)


def label(line, verdict='confirmed', detector='SEC-EXAMPLE', file='src/[id]/+server.ts', **kwargs):
    return dict(detector=detector, file=file, line=line, verdict=verdict, **kwargs)


def labels(rows=None):
    return dict(schema_version=1, repo=dict(path=TARGET['path'], commit=TARGET['commit']),
                location_matching='exact_detector_file_line', labels=rows if rows is not None else [
                    label(1), label(2), label(3, 'rejected'), label(4, 'rejected'), label(5, 'needs_validation')])


def finding(line, detector='SEC-EXAMPLE', file='src/[id]/+server.ts', **kwargs):
    return dict(id=detector, file=file, line=line, **kwargs)


def evaluate(rows=None, **kwargs):
    options = dict(target=TARGET, source_revision='MATCHED', scan_status='COMPLETE')
    options.update(kwargs)
    return B.evaluate(labels(), rows if rows is not None else [finding(1), finding(3), finding(5), finding(99)], **options)


class Bench(unittest.TestCase):
    def test_precision_recall_on_reviewed_locations_with_unlabelled_and_excluded_separate(self):
        report = evaluate()
        metrics = report['summary']['metrics']
        self.assertEqual([metrics[k] for k in ('tp', 'fp', 'fn', 'tn')], [1, 1, 1, 1])
        self.assertEqual((metrics['precision'], metrics['recall']), (.5, .5))
        self.assertEqual(report['summary']['excluded'], 1)
        self.assertEqual(report['summary']['unlabelled_findings'], 1)
        self.assertEqual(report['unlabelled_findings'][0]['line'], 99)
        self.assertEqual([row['outcome'] for row in report['labelled']], ['TP', 'FN', 'FP', 'TN', 'EXCLUDED'])
        self.assertEqual(report['per_detector'][0]['metrics'], metrics)

    def test_no_confirmed_labels_never_invent_zero_recall_and_no_hits_precision_unknown(self):
        for found, expected_precision in (([], None), ([finding(3)], 0.0)):
            result = B.evaluate(labels([label(3, 'rejected')]), found, target=TARGET, source_revision='MATCHED', scan_status='COMPLETE')
            self.assertIsNone(result['summary']['metrics']['recall'])
            self.assertEqual(result['summary']['metrics']['recall_reason'], 'NO_CONFIRMED_LABELS')
            self.assertEqual(result['summary']['metrics']['precision'], expected_precision)

    def test_no_detection_of_confirmed_labels_is_real_fn_only_with_complete_evidence(self):
        result = evaluate([])
        self.assertEqual(result['summary']['metrics']['fn'], 2)
        self.assertEqual(result['summary']['metrics']['recall'], 0)
        self.assertIsNone(result['summary']['metrics']['precision'])
        for status in ('INCOMPLETE', 'UNKNOWN', 'ERROR'):
            incomplete = evaluate([], scan_status=status)
            self.assertIsNone(incomplete['summary']['metrics']['fn'])
            self.assertIsNone(incomplete['summary']['metrics']['recall'])
            self.assertEqual(incomplete['per_detector'][0]['observations']['confirmed_absent'], 2)

    def test_dirty_untracked_does_not_override_positive_label_content_evidence(self):
        result = evaluate(target=dict(TARGET, dirty=True))
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertTrue(result['target']['dirty'])
        self.assertEqual(result['summary']['metrics']['precision'], .5)

    def test_sha_or_clean_flag_without_content_evidence_never_establishes_metrics(self):
        for source in ('UNKNOWN', 'MISMATCH'):
            report = evaluate(source_revision=source)
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertTrue(all(report['summary']['metrics'][k] is None for k in ('tp', 'fp', 'fn', 'tn', 'precision', 'recall')))
            self.assertEqual(report['labelled'][0]['outcome'], 'UNSCORED')
            self.assertIn('SOURCE_REVISION_' + source, report['gaps'])

    def test_unknown_commit_and_other_target_refuse_score_even_with_claimed_match(self):
        for target, reason in ((dict(TARGET, commit=None), 'SOURCE_COMMIT_UNKNOWN'),
                               (dict(TARGET, path='/synthetic/other'), 'TARGET_PATH_MISMATCH')):
            report = evaluate(target=target)
            self.assertIn(reason, report['gaps'])
            self.assertEqual(report['status'], 'INCOMPLETE')

    def test_same_content_at_different_current_commit_requires_explicit_evidence(self):
        target = dict(TARGET, commit='b' * 40)
        self.assertEqual(evaluate(target=target, source_revision='UNKNOWN')['status'], 'INCOMPLETE')
        matched = evaluate(target=target)
        self.assertEqual(matched['status'], 'COMPLETE')
        self.assertEqual(matched['source_revision']['label_commit'], 'a' * 40)
        self.assertEqual(matched['source_revision']['target_commit'], 'b' * 40)

    def test_labels_and_findings_deduplicate_exact_key_without_counting_verdicts_twice(self):
        ref = dict(file='review.json', row=0, sha256='c' * 64)
        data = labels([label(1, sources=[ref]), label(1, sources=[ref])])
        result = B.evaluate(data, [finding(1), finding(1), finding(1, locations=['src/[id]/+server.ts:1'])],
                            target=TARGET, source_revision='MATCHED', scan_status='COMPLETE')
        self.assertEqual(result['summary']['metrics']['tp'], 1)
        self.assertEqual(result['summary']['unique_findings'], 1)
        self.assertEqual(result['labels']['input_rows'], 2)
        self.assertEqual(len(result['labels']['labels'][0]['sources']), 1)
        self.assertEqual(result['labels']['sha256'], B.normalize_labels(result['labels'])['sha256'])

    def test_conflicting_label_verdict_or_group_is_error_before_scanner(self):
        for rows, code in (([label(1), label(1, 'rejected')], 'CONFLICTING_LABEL_VERDICTS'),
                            ([label(1, issue_group='first'), label(1, issue_group='second')], 'CONFLICTING_LABEL_GROUPS')):
            scanner = Mock(side_effect=AssertionError('no scan'))
            with self.assertRaises(B.BenchError) as caught:
                B.run_benchmark(labels(rows), TARGET['path'], scanner=scanner, target=TARGET)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.status, 'ERROR')
            scanner.assert_not_called()

    def test_conflicting_finding_verdicts_error_and_detector_cannot_self_label(self):
        with self.assertRaises(B.BenchError) as caught:
            B.normalize_findings([finding(1, verdict='confirmed'), finding(1, verdict='rejected')])
        self.assertEqual(caught.exception.code, 'CONFLICTING_FINDING_VERDICTS')
        report = evaluate([finding(1, verdict='rejected'), finding(3, verification_status='confirmed')])
        self.assertEqual(report['summary']['metrics']['tp'], 1)
        self.assertEqual(report['summary']['metrics']['fp'], 1)

    def test_exact_matching_keeps_other_line_file_and_detector_unlabelled(self):
        report = B.evaluate(labels([label(1)]), [finding(2), finding(1, file='other.ts'), finding(1, detector='OTHER')],
                            target=TARGET, source_revision='MATCHED', scan_status='COMPLETE')
        self.assertEqual(report['summary']['metrics']['fn'], 1)
        self.assertEqual(report['summary']['unlabelled_findings'], 3)
        other = next(row for row in report['per_detector'] if row['detector'] == 'OTHER')
        self.assertIsNone(other['metrics']['recall'])
        self.assertIsNone(other['metrics']['precision'])

    def test_aggregate_locations_preserve_all_exact_places(self):
        result = B.normalize_findings([dict(id='SEC-EXAMPLE', locations=[dict(path='src/a.ts', line=7), 'src/b.ts:9'])])
        self.assertEqual([(r['file'], r['line']) for r in result], [('src/a.ts', 7), ('src/b.ts', 9)])

    def test_group_partial_detection_does_not_claim_all_members_found(self):
        data = labels([label(1, issue_group='synthetic-group'), label(2, issue_group='synthetic-group')])
        result = B.evaluate(data, [finding(1)], target=TARGET, source_revision='MATCHED', scan_status='COMPLETE')
        self.assertEqual(result['confirmed_groups'], [dict(issue_group='synthetic-group', labelled_locations=2,
                                                          observed_hits=1, status='PARTIALLY_FOUND')])

    def test_public_output_contains_only_metadata_and_does_not_mutate_inputs(self):
        data = labels(); found = [finding(1, title='SOURCE_CANARY', why='PRIVATE_CANARY', payload={'token': 'TOKEN_CANARY'})]
        data.update(raw='FULL_SOURCE_CANARY'); data['labels'][0].update(why='LABEL_CANARY')
        original = copy.deepcopy((data, found, TARGET))
        with patch('builtins.open', side_effect=AssertionError('pure evaluator')), \
             patch('subprocess.run', side_effect=AssertionError('no process')):
            report = B.evaluate(data, found, target=TARGET, source_revision='MATCHED', scan_status='COMPLETE')
        self.assertEqual((data, found, TARGET), original)
        self.assertNotIn('CANARY', json.dumps(report))

    def test_invalid_schema_paths_lines_or_verdicts_are_fixed_errors_without_echo(self):
        bad = [dict(schema_version=True), dict(repo=dict(path='/synthetic/project', commit='PRIVATE_CANARY')),
               dict(labels=[label(True)]), dict(labels=[label(0)]), dict(labels=[label(1, file='../PRIVATE_CANARY')]),
               dict(labels=[label(1, file='/PRIVATE_CANARY')]), dict(labels=[label(1, file='src//x.ts')]),
               dict(labels=[label(1, verdict={'PRIVATE_CANARY': 1})]), dict(labels=[])]
        for change in bad:
            with self.subTest(change=change), self.assertRaises(B.BenchError) as caught:
                B.normalize_labels(dict(labels(), **change))
            self.assertNotIn('PRIVATE_CANARY', str(caught.exception))

    def test_comparison_recomputes_previous_and_gives_same_groundtruth_deltas(self):
        previous = evaluate([finding(1), finding(3)])
        current = evaluate([finding(1), finding(2)], previous=previous, target=dict(TARGET, dirty=True))
        self.assertEqual(current['comparison']['status'], 'COMPARABLE')
        delta = current['comparison']['delta']['summary']
        self.assertEqual(delta, dict(tp=1, fp=-1, fn=-1, tn=1, precision=.5, recall=.5))

    def test_comparison_rejects_label_target_version_and_unverified_differences(self):
        previous = evaluate()
        cases = []
        changed = copy.deepcopy(previous); changed['labels']['sha256'] = 'b' * 64; cases.append((changed, 'LABEL_SET_MISMATCH'))
        changed = copy.deepcopy(previous); changed['target']['commit'] = 'b' * 40; cases.append((changed, 'TARGET_IDENTITY_MISMATCH'))
        changed = copy.deepcopy(previous); changed['scoring_version'] = 'future'; cases.append((changed, 'SCORING_VERSION_MISMATCH'))
        cases.append((evaluate(source_revision='UNKNOWN'), 'SOURCE_OR_SCAN_NOT_COMPARABLE'))
        for old, reason in cases:
            with self.subTest(reason=reason):
                result = evaluate(previous=old)['comparison']
                self.assertEqual(result['status'], 'NOT_COMPARABLE')
                self.assertEqual(result['reason_code'], reason)
                self.assertIsNone(result['delta'])

    def test_comparison_rejects_forged_numeric_summary_or_hash(self):
        for key, value in (('tp', 99), ('tp', True), ('precision', 1)):
            previous = evaluate(); previous['summary']['metrics'][key] = value
            self.assertEqual(evaluate(previous=previous)['comparison']['reason_code'], 'INVALID_PREVIOUS_REPORT')
        previous = evaluate(); previous['labels']['labels'][0]['verdict'] = 'rejected'
        self.assertEqual(evaluate(previous=previous)['comparison']['reason_code'], 'INVALID_PREVIOUS_REPORT')

    def test_runner_calls_static_scanner_once_and_uses_labelled_read_scope(self):
        scanner = Mock(return_value=dict(findings=[finding(1)], source_coverage=dict(status='INCOMPLETE', files=[
            dict(file='src/[id]/+server.ts', status='read', lines_total=200, lines_read=200),
            dict(file='unrelated.bin', status='skipped', lines_total=None, lines_read=0)])))
        report = B.run_benchmark(labels(), TARGET['path'], scanner=scanner, target=dict(TARGET, dirty=True), source_revision='MATCHED')
        scanner.assert_called_once_with(TARGET['path'])
        self.assertEqual(report['status'], 'COMPLETE')
        self.assertEqual(report['scanner_source_coverage_status'], 'INCOMPLETE')
        self.assertEqual(report['read_coverage_scope'], 'labelled_files_only')
        self.assertEqual(report['execution'], dict(static_scans=1, models=0, target_writes=0))

    def test_runner_zero_missing_or_partial_read_cannot_create_false_negatives(self):
        for coverage in (None, dict(status='COMPLETE', files=[]),
                         dict(status=['invalid'], files=[]),
                         dict(status='COMPLETE', files=[dict(file='src/[id]/+server.ts', status='read', lines_total=200, lines_read=4)]),
                         dict(status='COMPLETE', files=[dict(file='src/[id]/+server.ts', status='read', lines_total=5, lines_read=5)] * 2)):
            scanner = Mock(return_value=dict(findings=[], source_coverage=coverage))
            report = B.run_benchmark(labels(), TARGET['path'], scanner=scanner, target=TARGET, source_revision='MATCHED')
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertIsNone(report['summary']['metrics']['fn'])
            scanner.assert_called_once()

    def test_runner_rejects_invalid_findings_or_target_binding(self):
        scanner = Mock(return_value={})
        with self.assertRaises(B.BenchError) as caught:
            B.run_benchmark(labels(), '/synthetic/other', scanner=scanner, target=TARGET)
        self.assertEqual(caught.exception.code, 'SCANNER_TARGET_MISMATCH')
        scanner.assert_not_called()
        with self.assertRaises(B.BenchError) as caught:
            B.run_benchmark(labels(), TARGET['path'], scanner=scanner, target=TARGET)
        self.assertEqual(caught.exception.code, 'INVALID_SCANNER_REPORT')


if __name__ == '__main__':
    unittest.main()
