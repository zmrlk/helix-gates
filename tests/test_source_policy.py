"""Agent state cannot become application evidence, even when tracked by Git."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_environment as environment
import helix_source_coverage as coverage
from helix_source_policy import AGENT_STATE_DIRECTORIES


class SourcePolicyTests(unittest.TestCase):
    def test_git_and_filesystem_inventory_exclude_agent_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'app.py').write_text('print("application")\n')
            names = ['app.py']
            for directory in AGENT_STATE_DIRECTORIES:
                name = directory + '/worktrees/copy/app.py'
                path = root / name
                path.parent.mkdir(parents=True)
                path.write_text('DO_NOT_OPEN')
                names.append(name)
            original = coverage.safe_read
            def read(path, **kwargs):
                self.assertFalse(set(path.relative_to(root).parts) & AGENT_STATE_DIRECTORIES)
                return original(path, **kwargs)
            with patch.object(coverage, 'safe_read', side_effect=read):
                for method in ('git', 'filesystem (git unavailable; ignored scope unknown)'):
                    with self.subTest(method=method), patch.object(coverage, 'paths', return_value=(names, method)):
                        sources, evidence = coverage.scan(root)
                        self.assertEqual(set(sources), {'app.py'})
                        self.assertTrue(all(row['reason'] for row in evidence['files'] if row['status'] == 'skipped'))
                with patch('helix_git_readonly.git', side_effect=OSError('offline fixture')):
                    sources, evidence = coverage.scan(root)
                    self.assertEqual(set(sources), {'app.py'})

    def test_environment_keeps_active_pin_without_copied_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / '.node-version').write_text('22.1.0')
            for directory in AGENT_STATE_DIRECTORIES:
                path = root / directory / 'worktrees/copy/.node-version'
                path.parent.mkdir(parents=True)
                path.write_text('10.0.0')
            with patch('helix_runtime.database_target', return_value={'evidence': []}):
                report = environment.report(root, probe=False)
            node = next(row for row in report['components'] if row['name'] == 'node')
            self.assertEqual([row['version'] for row in node['declarations']], ['22.1.0'])
            self.assertFalse(node['conflicts'])
            self.assertEqual({row['path'] for row in report['coverage']['excluded']}, AGENT_STATE_DIRECTORIES)


if __name__ == '__main__':
    unittest.main()
