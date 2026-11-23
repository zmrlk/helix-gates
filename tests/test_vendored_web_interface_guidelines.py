"""Przypięte wytyczne interfejsu Vercela: skróty plików, licencja i zgodność reguł z promptem recenzenta UI (offline)."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'vendor/web-interface-guidelines/4ecfb9f'
PINNED = {'command.md': (8055, 'd246b026f4f29b5823a9cc857f9edf3d2507002e055e32040cadeaf3b38e0234'),
          'LICENSE': (1068, '6cd1609c9c12233507cdd2ce0d32e9a721e3c27494951be06b90090deeeb7af2')}


class VendoredGuidelines(unittest.TestCase):
    def test_files_match_independent_pins_and_manifest(self):
        manifest = json.loads((VENDOR / 'VENDORED.json').read_text())
        self.assertEqual(manifest['license'], 'MIT')
        self.assertEqual(manifest['upstream_commit'], '4ecfb9fb8d1d3b7009674869b3aaee2f904042e1')
        self.assertEqual({row['path'] for row in manifest['files']}, set(PINNED))
        for row in manifest['files']:
            raw = (VENDOR / row['path']).read_bytes(); size, digest = PINNED[row['path']]
            with self.subTest(file=row['path']):
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
                self.assertEqual((row['bytes'], row['sha256']), (size, digest))
        self.assertIn('MIT License', (VENDOR / 'LICENSE').read_text())
        self.assertIn('vendor/web-interface-guidelines/4ecfb9f/LICENSE', (ROOT / 'THIRD_PARTY_NOTICES.md').read_text())

    def test_reviewer_prompt_carries_the_rules_verbatim_and_the_engine_contract(self):
        source = (VENDOR / 'command.md').read_text()
        rules = source[source.index('## Rules'):source.index('## Output Format')].rstrip()
        prompt = (ROOT / 'prompts/review_ui.md').read_text()
        self.assertIn(rules, prompt)
        self.assertGreater(rules.count('\n- '), 90)
        for placeholder in ('{round}', '{max_rounds}', '{cp_id}', '{title}', '{goal}', '{test_cases}', '{architecture}', '{previous}', '{diff}'):
            self.assertEqual(prompt.count(placeholder), 1, placeholder)
        self.assertIn('only "blocker" or "major" findings justify verdict "changes"', prompt)
        self.assertNotIn('$ARGUMENTS', prompt)


if __name__ == '__main__':
    unittest.main()
