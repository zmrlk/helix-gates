"""Filesystem aliases must have the same identity on Linux and macOS."""
import argparse
import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_paths as paths
import helix_packs as packs
import helix_runs as runs
import helix_security_deep as deep


class Paths(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'real'
        self.repo.mkdir()
        self.alias = self.root / 'alias'
        self.alias.symlink_to(self.repo, target_is_directory=True)
        (self.repo / 'src').mkdir()
        (self.repo / 'src/app.py').write_text('password = "test"\n')
        (self.repo / 'linked').symlink_to(self.repo / 'src', target_is_directory=True)

    def test_scanner_paths_have_identical_baseline_identity(self):
        variants = [self.repo / 'src/app.py', self.alias / 'src/app.py', self.alias / 'linked/app.py', Path('linked/app.py')]
        for path in variants:
            self.assertEqual(packs.relative(self.alias, path), 'src/app.py')
        self.assertEqual(paths.relative(self.alias / 'linked/app.py', self.repo).as_posix(), 'src/app.py')
        with self.assertRaises(ValueError):
            packs.relative(self.repo, self.root / 'outside.py')

    def test_source_context_through_repo_and_directory_alias(self):
        for repo in (self.repo, self.alias):
            text, omitted = deep.source_context(repo, ['.'], 'quick', names=['linked/app.py'])
            self.assertIn('password =', text)
            self.assertEqual(omitted, [])

    def test_outside_path_is_in_coverage_ledger(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'file.py').write_text('sensitive = 1')
        (self.repo / 'external').symlink_to(outside, target_is_directory=True)
        with patch.object(packs, 'git', return_value='external/file.py\0'):
            batches, ledger = deep.context_plan(self.alias, ['.'], 'quick')
        self.assertEqual(batches, [])
        self.assertEqual(ledger[0]['unit'], 'external/file.py')
        self.assertEqual(ledger[0]['status'], 'uncovered')

    def test_prior_runs_share_repository_identity(self):
        import json
        audit = self.root / 'audits'
        run = audit / 'run-1'
        run.mkdir(parents=True)
        (run / 'run-metadata.json').write_text(json.dumps({'target': str(self.alias)}))
        self.assertEqual(deep.prior_runs(self.repo, audit), [run])
        self.assertEqual(deep.run_root(self.alias), deep.run_root(self.repo))

    def test_cache_excludes_output_through_alias(self):
        (self.repo / 'reports').mkdir()
        (self.repo / 'reports/data').write_text('generated')
        response = subprocess.CompletedProcess([], 0, b'src/app.py\0reports/data\0', b'')
        with patch.object(runs.subprocess, 'run', return_value=response):
            a = runs.snapshot(self.alias, self.repo / 'reports', self.repo / '.helix')
            b = runs.snapshot(self.repo, self.alias / 'reports', self.alias / '.helix')
        self.assertEqual(a, b)
        self.assertEqual(list(a), ['src/app.py'])

    def test_node_relative_uses_real_filesystem_identity(self):
        helper = Path(__file__).resolve().parents[1] / 'bin/paths.cjs'
        code = "const assert = require('node:assert/strict'); const p = require(process.argv[1]); assert.equal(p.relative(process.argv[2], process.argv[3]), 'src/app.py');"
        result = subprocess.run(['node', '-e', code, str(helper), str(self.alias), str(self.repo / 'src/app.py')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_integrity_records_symlink_skips(self):
        (self.repo / 'file-link.py').symlink_to(self.repo / 'src/app.py')
        runner = argparse.Namespace(records=[])
        with patch.object(packs, 'git', return_value='file-link.py'):
            findings, metrics = packs.integrity(self.alias, {}, 'HEAD', runner)
        self.assertEqual(findings, [])
        self.assertEqual(metrics['coverage'][0]['unit'], 'file-link.py')
        self.assertEqual(metrics['coverage'][0]['status'], 'skipped')


class CommitValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        loader = importlib.machinery.SourceFileLoader('helix_path_tests', str(Path(__file__).resolve().parents[1] / 'bin/helix'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cls.helix = importlib.util.module_from_spec(spec)
        sys.modules[loader.name] = cls.helix
        loader.exec_module(cls.helix)

    def test_commit_limit_before_staging(self):
        prefix = 'helix(cp1): '
        for title in ('x' * (121 - len(prefix)), 'line\nbreak'):
            with patch.object(self.helix, 'git') as git:
                with self.assertRaises(ValueError):
                    self.helix.commit(None, dict(id='cp1', title=title), {})
                git.assert_not_called()
        with patch.object(self.helix, 'git', return_value='abc') as git:
            self.helix.commit(None, dict(id='cp1', title='x' * (120 - len(prefix))), {})
            message = git.call_args_list[1].args[-1]
            self.assertEqual(len(message.splitlines()[0]), 120)

    def test_zero_runner_counts(self):
        for output in ('# tests 0\n# pass 0\n# fail 0', 'ℹ tests 0\nℹ pass 0\nℹ fail 0', 'no tests ran in 0.1s'):
            self.assertEqual(self.helix.parse_counts(output), (0, 0))
