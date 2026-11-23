"""Source evidence counts, scope separation and local focus alternatives."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_ui_deep as ui
import helix_lenses as lenses


class ReportQuality(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path, value):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)
        return p

    def focus(self, value):
        self.write('style.css', value)
        return ui.report(self.root)

    def test_same_keyboard_focus_block_with_alternative_is_deferred(self):
        for declaration in ('background:var(--selected)', 'background-color:#aabbee',
                            'border:2px solid blue', 'box-shadow:0 0 0 2px blue'):
            with self.subTest(declaration=declaration):
                data = self.focus('.control:focus-visible {outline:none; ' + declaration + ';}')
                self.assertNotIn('UX-FOCUS', {f['id'] for f in data['findings']})
                self.assertEqual(data['adversarial']['focus_replacements_needing_runtime'], 1)
                self.assertEqual(data['summary']['runtime'], 'not_checked')
        data = self.focus('.control:hover, .control:focus-visible {background:var(--selected);outline:none;}')
        self.assertNotIn('UX-FOCUS', {f['id'] for f in data['findings']})

    def test_hover_other_selector_and_none_do_not_hide_outline_loss(self):
        for css in ('.control:focus-visible {outline:none;box-shadow:none;background:transparent;border:0;}',
                    '.control:focus-visible {outline:none;} .other:focus-visible {box-shadow:0 0 0 2px blue;}',
                    '.control:focus-visible:hover {outline:none;background:blue;}',
                    '.control:hover {outline:none; background:blue;}',
                    '.other:hover, .control:focus-visible {outline:none;background:blue;}',
                    '.control:not(:focus-visible) {outline:none;background:blue;}'):
            with self.subTest(css=css):
                data = self.focus(css)
                self.assertIn('UX-FOCUS', {f['id'] for f in data['findings']})
                self.assertEqual(data['adversarial']['focus_replacements_needing_runtime'], 0)

    def test_ui_report_keeps_docs_legacy_and_explicit_test_exclusions(self):
        for name in ('src/A.svelte', 'docs/demo/A.svelte', 'legacy/A.svelte', 'tests/A.svelte'):
            self.write(name, '<img>')
        data = ui.report(self.root)
        self.assertEqual(data['summary']['by_area'], {'docs': 1, 'legacy': 1, 'active': 1})
        self.assertEqual(data['scanned_files'], 3)
        self.assertTrue(any(row['path'] == 'tests' for row in data['source_coverage']['excluded_subtrees']))
        text = ui.markdown(data)
        for heading in ('Aktywny kod', 'Dokumentacja', 'Starsze warianty'): self.assertIn(heading, text)
        self.assertNotRegex(text, r'\d+/100')
        self.assertEqual(data['summary']['confirmed_by_verifier'], 0)
        self.assertEqual(data['summary']['source_pattern_confirmed'], 3)

    def test_large_source_tail_is_read_and_reported_without_false_size_limit(self):
        self.write('src/Large.svelte', '<!--' + 'x' * 1_050_000 + '-->\n<img>')
        data = ui.report(self.root)
        self.assertTrue(any(f['id'] == 'UX-ALT' and f['line'] == 2 for f in data['findings']))
        self.assertEqual(data['source_coverage']['files_read'], 1)
        self.assertNotIn('Pliki >1 MB', ' '.join(data['limitations']))

    def test_review_markdown_counts_candidates_without_displaying_zero_score(self):
        for path in ('src/task.py', 'docs/demo.py', 'legacy/task.py', 'tests/test_task.py'):
            self.write(path, 'def work():\n    try:\n        do_work()\n    except Exception:\n        pass\n    time.sleep(1)\n')
        data = lenses.report(self.root)
        self.assertIn('active', data['summary']['by_area'])
        self.assertIn('docs', data['summary']['by_area'])
        self.assertIn('legacy', data['summary']['by_area'])
        self.assertIn('tests/examples', data['summary']['by_area'])
        self.assertGreater(data['summary']['candidates'], 0)
        self.assertEqual(data['summary']['confirmed_by_verifier'], 0)
        self.assertTrue(all(item['score'] == 0 for item in data['lenses'].values()))
        text = lenses.markdown(data)
        self.assertNotRegex(text, r'\d+/100')
        self.assertIn('kandydaci:', text)
        self.assertIn('## Załącznik: candidate', text)
        self.assertIn('Zakres: Starsze warianty', text)
        for item in data['lenses'].values():
            self.assertEqual(item['summary']['signals'], len(item['findings']))
        schema = json.loads((ROOT / 'schemas/review_deep.json').read_text())
        self.assertTrue(set(data) <= set(schema['properties']), set(data) - set(schema['properties']))
        self.assertEqual(set(data['lenses']), set(schema['properties']['lenses']['properties']))
        for finding in data['findings']:
            self.assertTrue(set(finding) <= set(schema['$defs']['finding']['properties']))

    def test_upstream_pipeline_and_data_flow_remain_in_the_merged_contract(self):
        self.write('apps/api/log.ts', 'console.log(request.body.email);\n')
        data = lenses.report(self.root)
        schema = json.loads((ROOT / 'schemas/review_deep.json').read_text())
        self.assertTrue(set(data) <= set(schema['properties']))
        self.assertTrue({'senior_pipeline', 'data_leak_audit'} <= set(schema['required']))
        self.assertTrue(data['data_leak_audit']['flows'])
        self.assertEqual(data['data_leak_audit']['audit_trail']['execution'], 'not-run')
        self.assertTrue(data['senior_pipeline']['parts'])
        rows = [f for f in data['findings'] if f['id'].startswith('DATA-')]
        self.assertTrue(rows)
        self.assertTrue(any('data-flow' in row['sources'] for row in rows))
        for finding in rows:
            self.assertTrue(set(finding) <= set(schema['$defs']['finding']['properties']))
            self.assertEqual(finding['claim'], 'ASSUMPTION')
            self.assertEqual(finding['source_area'], 'active')
            self.assertNotEqual(finding['verification_status'], 'confirmed')
        text = lenses.markdown(data)
        self.assertNotRegex(text, r'\d+/100')
        self.assertIn('## Dziewięć perspektyw per część', text)
        self.assertIn('## Przepływ danych i DPIA', text)


if __name__ == '__main__':
    unittest.main()
