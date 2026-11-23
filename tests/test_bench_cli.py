"""Synthetic local Git fixtures; no target code, tools, models or network."""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

# Staging can be tested before publication; the repository copy uses its bin.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
SPEC = importlib.util.spec_from_file_location('bench_cli_subject', ROOT / 'bin/helix_bench.py')
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
from helix_git_readonly import git as real_git


class BenchCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / 'project'
        self.repo.mkdir()
        self.file = 'src/[id]/handler.ts'
        self.text = '// SOURCE_CANARY_DO_NOT_EXPORT\nconst item = 1;\n// third\n// fourth\n'
        path = self.repo / self.file
        path.parent.mkdir(parents=True)
        path.write_text(self.text)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_NAME='Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
        self.command('init', '-q')
        self.command('add', '.')
        self.command('commit', '-qm', 'synthetic fixture')
        self.sha = self.command('rev-parse', 'HEAD').stdout.strip()
        self.labels = dict(schema_version=1, repo=dict(path=str(self.repo), commit=self.sha),
                           location_matching='exact_detector_file_line', labels=[
                               dict(detector='SEC-EXAMPLE', file=self.file, line=1, verdict='confirmed', issue_group='synthetic-group'),
                               dict(detector='SEC-EXAMPLE', file=self.file, line=2, verdict='rejected'),
                               dict(detector='SEC-EXAMPLE', file=self.file, line=3, verdict='needs_validation'),
                               dict(detector='raw-element', file=self.file, line=4, verdict='rejected')])
        self.label_path = self.root / 'labels.json'
        self.label_path.write_text(json.dumps(self.labels))

    def command(self, *args):
        return subprocess.run(['git', '-c', 'core.hooksPath=' + os.devnull, *args], cwd=self.repo,
                              env=self.env, capture_output=True, text=True, check=True)

    def scan(self, repo, *, engine):
        text = (repo / self.file).read_text()
        lines = len(text.splitlines())
        return dict(findings=[dict(id='SEC-EXAMPLE', file=self.file, line=1, why='SOURCE_CANARY_DO_NOT_EXPORT')],
                    source_coverage=dict(status='COMPLETE', files=[dict(file=self.file, status='read',
                        sha256=hashlib.sha256(text.encode()).hexdigest(), lines_total=lines, lines_read=lines)]),
                    engine=dict(requested=engine, actual='synthetic'))

    def args(self, **changes):
        values = dict(repo=str(self.repo), labels=str(self.label_path), previous=None,
                      scope='security', engine='auto', out=None, json=True)
        values.update(changes)
        return SimpleNamespace(**values)

    def dispatch(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), patch.object(B, 'static_scan', side_effect=self.scan) as scanner:
            status = B.dispatch(args)
        return status, stdout.getvalue(), stderr.getvalue(), scanner

    def test_local_raw_blob_match_dirty_untracked_and_scoped_labels(self):
        (self.repo / 'untracked.txt').write_text('unrelated')
        scanner = Mock(side_effect=self.scan)
        with patch('helix_git_readonly.git', wraps=real_git) as calls:
            report = B.benchmark_repository(self.labels, self.repo, scanner=scanner, engine='lexical')
        scanner.assert_called_once_with(self.repo, engine='lexical')
        batch = [call for call in calls.call_args_list if 'cat-file' in call.args]
        self.assertEqual(len(batch), 1)
        self.assertTrue(batch[0].kwargs['local_objects_only'])
        self.assertEqual(report['status'], 'COMPLETE')
        self.assertTrue(report['target']['dirty'])
        self.assertEqual(report['summary']['metrics']['tp'], 1)
        self.assertEqual(report['summary']['metrics']['tn'], 1)
        self.assertEqual(report['scope']['excluded_label_count'], 1)
        self.assertEqual(report['scope']['excluded_detector_scope'], [dict(detector='raw-element', labels=1)])
        self.assertNotIn('raw-element', [row['detector'] for row in report['per_detector']])
        self.assertNotIn('SOURCE_CANARY_DO_NOT_EXPORT', json.dumps(report))
        self.assertEqual(report['execution'], dict(static_scans=1, models=0, target_writes=0, network=False))

    def test_different_commit_with_same_labelled_file_is_scored(self):
        (self.repo / 'unrelated.txt').write_text('unrelated')
        self.command('add', '.')
        self.command('commit', '-qm', 'other metadata')
        report = B.benchmark_repository(self.labels, self.repo, scanner=self.scan)
        self.assertNotEqual(report['target']['commit'], self.sha)
        self.assertEqual(report['source_proof']['status'], 'MATCHED')
        self.assertEqual(report['status'], 'COMPLETE')

    def test_changed_labelled_content_and_missing_local_commit_are_unscored(self):
        (self.repo / self.file).write_text(self.text.replace('item', 'other'))
        report = B.benchmark_repository(self.labels, self.repo, scanner=self.scan)
        self.assertEqual(report['source_revision']['status'], 'MISMATCH')
        self.assertIsNone(report['summary']['metrics']['tp'])
        unknown = copy.deepcopy(self.labels)
        unknown['repo']['commit'] = 'f' * 40
        report = B.benchmark_repository(unknown, self.repo, scanner=self.scan)
        self.assertEqual(report['source_revision']['status'], 'UNKNOWN')
        self.assertIsNone(report['summary']['metrics']['recall'])
        self.assertEqual(report['source_proof']['files'][0]['reason_code'], 'LOCAL_LABEL_BLOB_UNAVAILABLE')

    def test_changed_during_scan_and_unreadable_after_scan_preserve_unknown_counts(self):
        for mode in ('changed', 'symlink'):
            with self.subTest(mode=mode):
                path = self.repo / self.file
                if path.is_symlink(): path.unlink()
                path.write_text(self.text)
                canary = self.root / 'private-canary.txt'
                canary.write_text('DO_NOT_READ_OR_EXPORT')
                def changed(repo, *, engine):
                    result = self.scan(repo, engine=engine)
                    if mode == 'changed':
                        path.write_text(self.text + '// change\n')
                    else:
                        path.unlink()
                        path.symlink_to(canary)
                    return result
                report = B.benchmark_repository(self.labels, self.repo, scanner=changed)
                self.assertEqual(report['status'], 'INCOMPLETE')
                self.assertIsNone(report['summary']['metrics']['fn'])
                self.assertNotIn('DO_NOT_READ_OR_EXPORT', json.dumps(report))

    def test_excluded_or_unread_file_is_not_opened_by_source_proof(self):
        labels = copy.deepcopy(self.labels)
        labels['labels'][0]['file'] = '.env'
        with patch('helix_audit_context.safe_read', side_effect=AssertionError('not read')), patch('helix_git_readonly.git') as git:
            proof = B.source_proof(labels, dict(files=[]), self.repo)
        git.assert_not_called()
        self.assertEqual(proof['status'], 'UNKNOWN')

    def test_git_filter_and_fsmonitor_are_not_executed(self):
        marker = self.root / 'executed'
        # Configured commands would create the marker if a dirty check ran them.
        command = 'touch ' + str(marker)
        self.command('config', 'filter.fixture.clean', command)
        self.command('config', 'core.fsmonitor', command)
        (self.repo / '.gitattributes').write_text('*.ts filter=fixture\n')
        report = B.benchmark_repository(self.labels, self.repo, scanner=self.scan)
        self.assertFalse(marker.exists())
        self.assertIsNone(report['target']['dirty'])
        self.assertEqual(report['status'], 'COMPLETE')
        self.assertEqual(report['source_proof']['status'], 'MATCHED')

    def test_parser_preserves_global_repo_and_accepts_nested_repo(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--repo', default='global-default')
        B.parsers(parser.add_subparsers(dest='cmd', required=True))
        first = parser.parse_args(['--repo', '/selected', 'bench', '--labels', 'labels.json'])
        second = parser.parse_args(['bench', '--labels', 'labels.json', '--repo', '/nested', '--engine', 'lexical'])
        self.assertEqual(first.repo, '/selected')
        self.assertEqual(second.repo, '/nested')
        self.assertEqual(second.engine, 'lexical')

    def test_dispatch_publishes_external_metadata_json_and_markdown_without_target_change(self):
        out = self.root / 'results'
        before = self.command('status', '--porcelain=v1', '-z').stdout
        status, stdout, stderr, scanner = self.dispatch(self.args(out=str(out)))
        self.assertEqual(status, 0, stderr)
        self.assertFalse(stderr)
        result = json.loads(stdout)
        self.assertEqual(result, json.loads((out / 'benchmark.json').read_text()))
        self.assertIn('COMPLETE nie oznacza braku usterek', (out / 'BENCHMARK.md').read_text())
        self.assertEqual(result['labels_artifact_sha256'], hashlib.sha256(self.label_path.read_bytes()).hexdigest())
        self.assertIn('head', result['producer']['source_ref'])
        self.assertIn('dirty', result['producer']['source_ref'])
        self.assertEqual(before, self.command('status', '--porcelain=v1', '-z').stdout)
        scanner.assert_called_once()

    def test_existing_output_target_output_and_symlinks_refuse_before_scan(self):
        existing = self.root / 'existing'
        existing.mkdir()
        (existing / 'benchmark.json').write_text('preserved')
        link = self.root / 'link'
        link.symlink_to(existing, target_is_directory=True)
        for out in (existing, self.repo / 'results', link):
            with self.subTest(out=out):
                status, stdout, stderr, scanner = self.dispatch(self.args(out=str(out)))
                self.assertEqual(status, 3)
                scanner.assert_not_called()
                self.assertEqual(json.loads(stderr)['status'], 'ERROR')
        self.assertEqual((existing / 'benchmark.json').read_text(), 'preserved')
        self.assertFalse((self.repo / 'results').exists())

    def test_label_symlink_and_conflict_refuse_before_scan_and_output(self):
        link = self.root / 'labels-link.json'
        link.symlink_to(self.label_path)
        out = self.root / 'result'
        status, _, stderr, scanner = self.dispatch(self.args(labels=str(link), out=str(out)))
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(stderr)['reason_code'], 'INPUT_JSON_UNREADABLE')
        scanner.assert_not_called()
        self.assertFalse(out.exists())
        labels = copy.deepcopy(self.labels)
        labels['labels'].append(dict(labels['labels'][0], verdict='rejected'))
        self.label_path.write_text(json.dumps(labels))
        status, _, stderr, scanner = self.dispatch(self.args(out=str(out)))
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(stderr)['reason_code'], 'CONFLICTING_LABEL_VERDICTS')
        scanner.assert_not_called()
        self.assertFalse(out.exists())

    def test_partial_scan_and_zero_file_read_never_exit_zero(self):
        with patch.object(B, 'static_scan', return_value=dict(findings=[], source_coverage=dict(status='COMPLETE', files=[]))):
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                status = B.dispatch(self.args())
        self.assertEqual(status, 3)
        result = json.loads(stdout.getvalue())
        self.assertIsNone(result['summary']['metrics']['recall'])
        self.assertEqual(result['status'], 'INCOMPLETE')

    def test_comparison_input_revalidated_and_json_errors_do_not_echo_values(self):
        previous = B.benchmark_repository(self.labels, self.repo, scanner=self.scan)
        old = self.root / 'previous.json'
        old.write_text(json.dumps(previous))
        status, stdout, stderr, _ = self.dispatch(self.args(previous=str(old)))
        self.assertEqual(status, 0, stderr)
        self.assertEqual(json.loads(stdout)['comparison']['status'], 'COMPARABLE')
        old.write_text('{ DO_NOT_EXPORT_BROKEN_JSON')
        status, _, stderr, scanner = self.dispatch(self.args(previous=str(old)))
        self.assertEqual(status, 3)
        scanner.assert_not_called()
        self.assertNotIn('DO_NOT_EXPORT', stderr)

    def test_duplicate_json_fields_and_nonfinite_values_are_rejected_before_scan(self):
        for content in ('{"schema_version":1,"schema_version":2}', '{"schema_version":NaN}'):
            self.label_path.write_text(content)
            status, _, stderr, scanner = self.dispatch(self.args())
            self.assertEqual(status, 3)
            self.assertEqual(json.loads(stderr)['reason_code'], 'INPUT_JSON_UNREADABLE')
            scanner.assert_not_called()

    def test_static_scan_uses_same_snapshot_once_without_monkeypatching_module(self):
        source = [(self.file, self.text)]
        metadata = dict(requested='lexical', actual='synthetic', coverage=dict(status='INCOMPLETE', gaps=['SYNTHETIC_GAP']), usage=dict(calls=0))
        fake = SimpleNamespace(sources=Mock(return_value=iter(source)), analyze=Mock(return_value=dict(findings=[], static_engine=metadata)))
        with patch.dict(sys.modules, helix_static_security=fake):
            result = B.static_scan(self.repo, engine='lexical')
        fake.sources.assert_called_once_with(self.repo)
        fake.analyze.assert_called_once_with(self.repo, source_snapshot=source, engine='lexical')
        self.assertEqual(result['source_coverage']['files'][0]['sha256'], hashlib.sha256(self.text.encode()).hexdigest())
        self.assertEqual(result['engine'], metadata)
        self.assertNotIn(self.text, json.dumps(result))


if __name__ == '__main__':
    unittest.main()
