"""Public AST metadata and aggregate evidence remain useful without source text."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_lenses as lenses


class ASTReportTests(unittest.TestCase):
    def test_merge_keeps_all_locations_and_both_evidence_kinds_idempotently(self):
        first = dict(id='SEC-AUTH', lens='security', severity='medium', confidence='possible',
                     file='route.ts', line=1, evidence_kind='ast_local_relation',
                     locations=[{'file': 'route.ts', 'line': 1}, {'file': 'other.ts', 'line': 4}])
        second = dict(first, evidence_kind='lexical_fallback', locations=[{'file': 'third.ts', 'line': 8}])
        original = copy.deepcopy([first, second])
        merged = lenses.deduplicate([first, second])
        self.assertEqual([first, second], original)
        self.assertEqual(len(merged), 1)
        self.assertEqual({(r['file'], r['line']) for r in merged[0]['locations']},
                         {('route.ts', 1), ('other.ts', 4), ('third.ts', 8)})
        self.assertEqual(merged[0]['evidence_kinds'], ['ast_local_relation', 'lexical_fallback'])
        self.assertEqual(merged[0]['confidence'], 'possible')
        self.assertEqual(merged, lenses.deduplicate(merged * 2))

    def test_schema_declares_public_ast_metadata_without_private_facts(self):
        schema = json.loads((ROOT / 'schemas/review_deep.json').read_text())
        contract = schema['properties']['static_engine']
        self.assertFalse(contract['additionalProperties'])
        self.assertTrue({'engine', 'coverage', 'usage', 'local_candidates'} <= set(contract['properties']))
        self.assertFalse({'facts', 'captures', 'source', 'stdout'} & set(contract['properties']))
        properties = schema['$defs']['finding']['properties']
        self.assertTrue({'source_offset', 'evidence_kind', 'evidence_kinds', 'locations'} <= set(properties))


if __name__ == '__main__':
    unittest.main()
