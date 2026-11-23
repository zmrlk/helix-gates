"""Portable, offline checks of the four pinned Ponytail instruction files."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RELATIVE = Path('vendor/ponytail/4.9.0')
# Independently pinned to the reviewed local 4.9.0 source inventory. These are
# file hashes, not a claim that an upstream Git revision/tag was verified.
PINNED = {
    'review.md': ('skills/ponytail-review/SKILL.md', 2383,
                  '40df33b58fc6ef889b93585733feb9566b76e9586efa7f376785c1e995197ac0'),
    'audit.md': ('skills/ponytail-audit/SKILL.md', 1652,
                 '5560b8e383dbe2ddfddc873a1e2bf2e586e23e0cd7d995537482b2315331f6d1'),
    'debt.md': ('skills/ponytail-debt/SKILL.md', 1703,
                'c84fba75f0ca12bfe83f9a78ea02fd125c5dd3f1fbb18124105a489937f284e6'),
    'LICENSE': ('LICENSE', 1071,
                'fb1bc6909ac3ef82d5c22106e32ef682b0cff66788fa915fb9b53b15c9d2f3ab'),
}


class VendoredPonytailTests(unittest.TestCase):
    def manifest(self, root=ROOT):
        return json.loads((root / RELATIVE / 'VENDORED.json').read_text(encoding='utf-8'))

    def assert_sources(self, root=ROOT):
        manifest = self.manifest(root)
        self.assertEqual(len(manifest['files']), 4)
        self.assertEqual({row['path'] for row in manifest['files']}, set(PINNED))
        by_path = {row['path']: row for row in manifest['files']}
        for name, (original, size, digest) in PINNED.items():
            with self.subTest(file=name):
                raw = (root / RELATIVE / name).read_bytes()
                self.assertEqual(len(raw), size)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                self.assertEqual(by_path[name], dict(path=name, original_path=original,
                                                      bytes=size, sha256=digest))
                self.assertIs(type(by_path[name]['bytes']), int)
        self.assertEqual(sum(row['bytes'] for row in manifest['files']), 6809)

    def test_four_source_files_match_independent_byte_pins(self):
        self.assert_sources()

    def test_only_pinned_texts_license_and_manifest_are_vendored(self):
        base = ROOT / RELATIVE
        self.assertEqual({p.name for p in base.parent.iterdir()}, {'4.9.0'})
        self.assertFalse(base.is_symlink())
        self.assertEqual({p.name for p in base.iterdir()}, set(PINNED) | {'VENDORED.json'})
        for path in base.iterdir():
            with self.subTest(file=path.name):
                mode = path.lstat().st_mode
                self.assertTrue(stat.S_ISREG(mode), 'No links, hooks, or directories in this text-only vendor')
                self.assertEqual(mode & 0o111, 0, 'No executable plugin code is imported')

    def test_manifest_records_declared_version_and_unknown_upstream_revision(self):
        manifest = self.manifest()
        self.assertEqual(set(manifest), {'schema_version', 'component', 'version_declared',
            'source_kind', 'upstream_url', 'upstream_commit', 'upstream_tag_verified',
            'imported_at', 'license', 'version_sources', 'files'})
        self.assertIs(type(manifest['schema_version']), int)
        self.assertEqual(manifest['schema_version'], 1)
        self.assertEqual(manifest['component'], 'ponytail')
        self.assertEqual(manifest['version_declared'], '4.9.0')
        self.assertEqual(manifest['source_kind'], 'local_plugin_cache')
        self.assertEqual(manifest['upstream_url'], 'https://github.com/DietrichGebert/ponytail')
        self.assertIsNone(manifest['upstream_commit'])
        self.assertIs(manifest['upstream_tag_verified'], False)
        self.assertEqual(manifest['license'], 'MIT')
        self.assertEqual(manifest['version_sources'], ['.claude-plugin/plugin.json', 'package.json'])
        imported = datetime.fromisoformat(manifest['imported_at'].replace('Z', '+00:00'))
        self.assertIsNotNone(imported.tzinfo)
        self.assertEqual(imported.utcoffset(), timezone.utc.utcoffset(imported))

    def test_complete_license_and_component_scoped_attribution_are_preserved(self):
        license_text = (ROOT / RELATIVE / 'LICENSE').read_text(encoding='utf-8')
        self.assertTrue(license_text.startswith('MIT License\n'))
        self.assertIn('Copyright (c) 2026 DietrichGebert', license_text)
        self.assertIn('The above copyright notice and this permission notice shall be included', license_text)
        self.assertIn('THE SOFTWARE IS PROVIDED "AS IS"', license_text)
        notice = (ROOT / 'THIRD_PARTY_NOTICES.md').read_text(encoding='utf-8')
        section = notice.split('## Ponytail 4.9.0\n', 1)[1].split('\n## ', 1)[0]
        for text in ('DietrichGebert', 'MIT License', 'ponytail-review', 'ponytail-audit',
                     'ponytail-debt', 'vendor/ponytail/4.9.0/LICENSE',
                     'vendor/ponytail/4.9.0/VENDORED.json', 'upstream commit is unknown',
                     'no remote tag or commit was verified', 'component only'):
            self.assertIn(text, section)
        self.assertIn("does not change Helix's license", section)
        self.assertIn('## Cloudflare security-audit-skill', notice)
        self.assertIn('## Keycloak 26.8.1', notice)

    def test_public_bundle_has_no_user_cache_paths(self):
        texts = [(ROOT / RELATIVE / name).read_text(encoding='utf-8')
                 for name in (*PINNED, 'VENDORED.json')]
        texts.append((ROOT / 'THIRD_PARTY_NOTICES.md').read_text(encoding='utf-8'))
        for text in texts:
            for private in ('/Users/', '/home/', '/private/var/', '\\Users\\',
                            '.claude/plugins/cache/', '.codex/plugins/cache/'):
                self.assertNotIn(private, text)

    def test_relocated_vendor_needs_no_home_cache_process_or_network(self):
        # This miniature checkout contains only the public vendor. Access to the
        # original machine's cache cannot be necessary for validation.
        with tempfile.TemporaryDirectory() as temporary:
            relocated = Path(temporary).resolve()
            shutil.copytree(ROOT / RELATIVE, relocated / RELATIVE)
            original_open = Path.open
            def within_copy(path, *args, **kwargs):
                self.assertTrue(path.resolve().is_relative_to(relocated))
                return original_open(path, *args, **kwargs)
            with patch.object(Path, 'open', within_copy), \
                    patch.object(Path, 'home', side_effect=AssertionError('No private cache')), \
                    patch('subprocess.Popen', side_effect=AssertionError('No tools')), \
                    patch('socket.socket', side_effect=AssertionError('No network')):
                self.assert_sources(relocated)


if __name__ == '__main__':
    unittest.main()
