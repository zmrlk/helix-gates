import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_release as release
import helix_repo_hygiene as hygiene
from helix_contracts import VERSION


class ReleaseHygieneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        subprocess.run(['git', '-C', str(self.root), 'add', '--', name], check=True)

    def test_conflict_line_and_no_credit(self):
        self.write('src/main.py', 'pass\n<<<<<<< branch\n')
        row = next(r for r in hygiene.report(self.root)['findings'] if r['id'] == 'HYGIENE-CONFLICT')
        self.assertEqual(row['line'], 2)
        self.assertEqual(row['evidence'], ['src/main.py:2'])
        self.assertEqual(row['severity'], 'high')
        self.assertEqual(row['execution_credit'], 0)

    def test_monorepo_lock_drift_and_exact_profile(self):
        self.write('apps/web/package.json', json.dumps({'dependencies': {'library': '^1.0.0'}}))
        self.write('apps/web/package-lock.json', json.dumps({'packages': {'': {'dependencies': {'library': '2.0.0'}}}}))
        ids = {r['id'] for r in hygiene.report(self.root, True)['findings']}
        self.assertIn('HYGIENE-LOCK-DRIFT', ids)
        self.assertIn('HYGIENE-PIN', ids)
        self.assertNotIn('HYGIENE-PIN', {r['id'] for r in hygiene.report(self.root)['findings']})

    def test_migrations_and_ids(self):
        for name in ('001_a.sql', '001_b.sql', '003_c.sql'):
            self.write('db/migrations/' + name, '-- migration')
        self.write('requirements/ledger.json', json.dumps({'requirements': [{'id': 'REQ-X-01'}, {'id': 'REQ-X-01'}]}))
        ids = {r['id'] for r in hygiene.report(self.root)['findings']}
        self.assertTrue({'HYGIENE-MIGRATION-DUP', 'HYGIENE-MIGRATION-GAP', 'HYGIENE-ID-DUP'} <= ids)

    def test_symlink_not_read(self):
        external = self.root.parent / (self.root.name + '-outside')
        external.write_text('<<<<<<< private')
        self.addCleanup(external.unlink)
        (self.root / 'link').symlink_to(external)
        subprocess.run(['git', '-C', str(self.root), 'add', 'link'], check=True)
        report = hygiene.report(self.root)
        self.assertFalse(any(r['file'] == 'link' for r in report['findings']))
        self.assertTrue(any('symlink' in x for x in report['limitations']))

    def test_missing_remote_fails_closed(self):
        with self.assertRaises(ValueError): release.inventory(self.root)

    def test_duplicate_history_exception_exact(self):
        self.write('bin/helix_contracts.py', "VERSION = '1.0.0'\n")
        self.write('CHANGELOG.md', '# 1.0.0 — today\n')
        with patch.object(release, 'inventory', return_value={'0.1.0': {'a', 'b'}}), patch.object(release, 'git', return_value=''):
            self.assertIn('powtórzona wersja', ' '.join(release.check(self.root)))
            self.write('requirements/release-history.json', json.dumps({'0.1.0': {'commits': ['a', 'b'], 'reason': 'history'}}))
            self.assertEqual(release.check(self.root), [])
            with patch.object(release, 'inventory', return_value={'0.1.0': {'a', 'b', 'c'}}):
                self.assertTrue(release.check(self.root))

    def test_bump_without_claim_fails(self):
        self.write('bin/helix_contracts.py', "VERSION = '1.0.1'\n")
        self.write('CHANGELOG.md', '# 1.0.1 — today\n')
        with patch.object(release, 'inventory', return_value={}), patch.object(release, 'git', return_value="+VERSION = '1.0.1'"):
            self.assertIn('claim', ' '.join(release.check(self.root)))

    def test_offline_dry_run_no_mutations_or_fetch(self):
        self.write('bin/helix_contracts.py', "VERSION = '1.0.0'\n")
        before = (self.root / 'bin/helix_contracts.py').read_bytes()
        with patch.object(release, 'inventory', return_value={}), patch.object(release, 'check', return_value=[]), patch.object(release, 'git', return_value='') as git:
            result = release.release(self.root, dry_run=True, offline=True)
            self.assertEqual(result['version'], '1.0.1')
            self.assertFalse(any('fetch' in c.args for c in git.call_args_list))
        self.assertEqual(before, (self.root / 'bin/helix_contracts.py').read_bytes())
        self.assertFalse((self.root / '.helix').exists())

    def test_single_executable_version_source(self):
        import re
        root = Path(__file__).resolve().parents[1]
        declarations = []
        for path in (root / 'bin').glob('*.py'):
            for line in path.read_text().splitlines():
                if re.search(r"(?:VERSION\s*=|version\s*=)\s*['\"]\d+\.\d+\.\d+-beta", line):
                    declarations.append(path.name)
        self.assertEqual(declarations, ['helix_contracts.py'])
        import helix_new
        self.assertEqual(helix_new.load(root / 'new/templates/helix.json.tpl')['helix_version'], VERSION)
        self.assertEqual(helix_new.load(root / 'new/schemas/config.json')['properties']['helix_version']['enum'], [VERSION])

    def test_release_claim_excludes_second_agent(self):
        from helix_continuity import Continuity
        continuity = Continuity(self.root)
        lease = continuity.claim_take('release', 'first', ttl=60)
        with self.assertRaises(ValueError):
            continuity.claim_take('release', 'second', ttl=60)
        continuity.claim_release('release', 'first', lease['lease_id'])
        self.assertEqual(continuity.claim_take('release', 'second', ttl=60)['agent'], 'second')

    def test_potential_secret_content_is_not_read(self):
        self.write('.env', '<<<<<<< synthetic-marker\n')
        result = hygiene.report(self.root)
        self.assertTrue(any(r['id'] == 'HYGIENE-SECRET-PATH' for r in result['findings']))
        self.assertFalse(any(r['id'] == 'HYGIENE-CONFLICT' for r in result['findings']))

    def test_committed_bump_requires_claim_receipt(self):
        self.write('bin/helix_contracts.py', "VERSION = '1.0.0'\n")
        self.write('CHANGELOG.md', '# 1.0.0 — today\n')
        self.write('requirements/release-history.json', json.dumps({'_enforcement_base': 'base'}))
        def fake_git(root, *args):
            if args[0] == 'rev-list': return 'commit-sha'
            if args[:2] == ('show', '--format='): return "+VERSION = '1.0.0'"
            if args[0] == 'show' and ':requirements/releases/' in args[1]: raise ValueError('missing')
            return ''
        with patch.object(release, 'inventory', return_value={}), patch.object(release, 'git', side_effect=fake_git):
            self.assertIn('commit-sha', ' '.join(release.check(self.root)))

    def test_historical_receipt_exception_is_exact_and_reasoned(self):
        self.write('bin/helix_contracts.py', "VERSION = '1.0.0'\n")
        self.write('CHANGELOG.md', '# 1.0.0 — today\n')
        def fake_git(root, *args):
            if args[0] == 'rev-list': return 'historical'
            if args[:2] == ('show', '--format='): return "+VERSION = '1.0.0'"
            if args[0] == 'show' and ':requirements/releases/' in args[1]: raise ValueError('missing')
            return ''
        for commits, reason, accepted in [(['historical'], 'pre-enforcement runtime', True),
                                          (['other'], 'pre-enforcement runtime', False),
                                          (['historical'], '', False)]:
            self.write('requirements/release-history.json', json.dumps({
                '_enforcement_base': 'base',
                '1.0.0': {'commits': commits, 'reason': reason}}))
            with patch.object(release, 'inventory', return_value={}), patch.object(release, 'git', side_effect=fake_git):
                self.assertEqual(not release.check(self.root), accepted)

    def test_release_source_symlink_refused(self):
        self.write('outside.py', "VERSION = '1.0.0'\n")
        (self.root / 'bin').mkdir()
        (self.root / 'bin/helix_contracts.py').symlink_to(self.root / 'outside.py')
        with self.assertRaises(ValueError): release.source_version(self.root)

    def test_reused_report_engines_include_version(self):
        import helix_static_security
        import helix_ui_deep
        import helix_security_deep
        for report in (helix_static_security.analyze(self.root), helix_ui_deep.report(self.root)):
            self.assertEqual(report['helix_version'], VERSION)
            self.assertIsInstance(report['schema_version'], int)
        helix_security_deep.reports(self.root, [], [], False)
        self.assertIn('Helix: ' + VERSION + '; schemat raportu: 1', (self.root / 'REPORT.md').read_text())

    def test_report_metadata(self):
        self.assertEqual(hygiene.report(self.root)['helix_version'], VERSION)
        self.assertEqual(hygiene.report(self.root)['schema_version'], 1)


if __name__ == '__main__': unittest.main()
