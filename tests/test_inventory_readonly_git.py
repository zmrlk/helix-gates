"""All offline filename inventories keep target identity without Git callbacks."""
import hashlib
import os
import unittest
from unittest.mock import patch

import test_git_readonly as fixture
import helix_source_coverage as coverage
import helix_repo_hygiene as hygiene
import helix_runs as runs


class InventoryReadOnlyGit(unittest.TestCase):
    setUp, command = fixture.GitReadonlyTests.setUp, fixture.GitReadonlyTests.command

    def test_inventories_ignore_inherited_git_directory_and_fsmonitor(self):
        foreign = self.base / 'foreign'; foreign.mkdir()
        self.command('init', '-q', repo=foreign)
        (foreign / 'unrelated.txt').write_text('foreign source')
        self.command('add', '.', repo=foreign)
        self.command('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'foreign', repo=foreign)
        self.command('config', 'core.fsmonitor', self.fake_command)
        source = '<<<<<<< ours\nconflict fixture\n=======\nother\n>>>>>>> theirs\n'
        (self.repo / 'app.txt').write_text(source)
        with patch.dict(os.environ, {'GIT_DIR': str(foreign / '.git'), 'GIT_WORK_TREE': str(foreign),
                                     'GIT_INDEX_FILE': str(foreign / '.git/index')}):
            files, summary = coverage.scan(self.repo)
            hashes = runs.snapshot(self.repo, self.base / 'out', self.base / 'state')
            result = hygiene.report(self.repo)
        self.assertFalse(self.marker.exists())
        self.assertEqual(summary['status'], 'COMPLETE')
        self.assertEqual(files['app.txt'], source)
        self.assertNotIn('unrelated.txt', files)
        self.assertEqual(hashes['app.txt'], hashlib.sha256(source.encode()).hexdigest())
        self.assertNotIn('unrelated.txt', hashes)
        self.assertTrue(any(f['file'] == 'app.txt' and 'CONFLICT' in f['id'] for f in result['findings']))
