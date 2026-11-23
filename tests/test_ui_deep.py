"""Synthetic oracle plus adversarial source-only cases; never run target code."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_ui_deep as ui

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/ui-deep'


class UIDeepTests(unittest.TestCase):
    def test_precision_recall_oracle(self):
        manifest = json.loads((FIXTURES / 'expected.json').read_text())
        tp = fp = fn = 0
        for case, rows in manifest.items():
            expected = {tuple(x) for x in rows}
            actual = {(f['file'], f['line'], f['id']) for f in ui.run(FIXTURES / case)}
            tp += len(expected & actual)
            fp += len(actual - expected)
            fn += len(expected - actual)
            self.assertEqual(actual, expected, case)
        self.assertEqual((tp, fp, fn), (23, 0, 0))

    def test_contract_order_and_evidence(self):
        rows = ui.run(FIXTURES / 'bad')
        required = {'lens', 'id', 'title', 'severity', 'confidence', 'file', 'line', 'why', 'fix', 'evidence', 'source_area'}
        for f in rows:
            self.assertEqual(set(f), required)
            self.assertIn(f['lens'], ui.LENSES)
            self.assertIn(f['confidence'], {'confirmed', 'likely', 'possible'})
            self.assertGreater(f['line'], 0)
            self.assertTrue(f['evidence'])
        self.assertEqual([ui.RANK[f['severity']] for f in rows], sorted(ui.RANK[f['severity']] for f in rows))
        data = ui.report(FIXTURES / 'bad')
        for lens in ui.LENSES:
            self.assertTrue(data['lenses'][lens]['adversarial_pass']['checks'])
        self.assertEqual(ui.score([]), 0)
        self.assertEqual(ui.score([{'severity': 'critical', 'evidence': []}]), 0)

    def scan(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            for name, value in files.items():
                path = Path(tmp) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
            return ui.report(tmp)

    def test_adversarial_ambiguous_and_cyclic_tokens(self):
        data = self.scan({'theme.css': ':root {--fg:#888;--bg:#fff;--cycle:var(--cycle);}'
                         '.dark{--fg:#fff;} p{color:var(--fg);background:var(--bg);}'
                         'a{color:var(--cycle);background:#fff;} b{color:rgba(1,2,3,.5);background:#fff;}'})
        self.assertNotIn('UI-CONTRAST', {f['id'] for f in data['findings']})

    def test_adversarial_alias_contrast_and_wcag_math(self):
        self.assertAlmostEqual(ui._ratio((0, 0, 0), (1, 1, 1)), 21)
        data = self.scan({'theme.css': ':root{--a:#888;--b:var(--a);} p{color:var(--b);background:#fff;}'})
        self.assertEqual(sum(f['id'] == 'UI-CONTRAST' for f in data['findings']), 1)

    def test_adversarial_dynamic_attributes_and_comments(self):
        data = self.scan({'Form.tsx': '<!-- <img><input> --><input {...props}/><img {...props}/>'
                         '<input aria-label={name}/><img alt={name}/>'
                         '<script>const example="<img>";</script>',
                         'Page.vue': '<input :aria-label="name"><img v-bind:alt="description">'})
        self.assertEqual(data['findings'], [])

    def test_adversarial_negative_tabindex_and_hidden_focus(self):
        data = self.scan({'A.tsx': '<div role="button" tabIndex={-1} onKeyDown={key} onClick={save}>Save</div>',
                          'a.css': 'button:focus { outline: none; }'})
        self.assertEqual({f['id'] for f in data['findings']}, {'UX-CLICK', 'UX-FOCUS'})

    def test_tailwind_arbitrary_values_and_discovery(self):
        data = self.scan({'tailwind.config.ts': "throw new Error('must never execute');",
                         'ui/BaseButton.tsx': '<button className="bg-[#123456] p-[13px] rounded-[7px] text-[13px]">Save</button>'})
        self.assertEqual(data['design_system']['tailwind']['count'], 1)
        self.assertEqual(data['components']['ui/BaseButton.tsx']['hardcoded'],
                         {'color': 1, 'spacing': 1, 'radius': 1, 'font_size': 1})
        self.assertIn('UI-TOKENS', {f['id'] for f in data['findings']})

    def test_safety_no_symlinks_hidden_or_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as external:
            root = Path(tmp)
            (Path(external) / 'secret.html').write_text('<img>')
            (root / 'link.html').symlink_to(Path(external) / 'secret.html')
            (root / 'outside').symlink_to(external, target_is_directory=True)
            for directory in ('.aws', '.codex', 'node_modules', 'tests'):
                (root / directory).mkdir()
                (root / directory / 'secret.html').write_text('<img>')
            (root / 'credentials.json').write_text('not to be read')
            self.assertEqual(ui.report(root)['scanned_files'], 0)

    def test_adversarial_similar_controls_and_schema(self):
        data = self.scan({'A.jsx': '<button className="px-4 py-2 rounded font-bold bg-red">Save</button>',
                          'B.jsx': '<button className="px-4 py-2 rounded font-bold bg-blue">Save</button>'})
        # Four shared classes out of six is below the threshold.
        self.assertNotIn('UI-REUSE', {f['id'] for f in data['findings']})
        data = self.scan({'A.js': '<button className="p-2 m-2 rounded border shadow font-bold bg-red">Save</button>',
                          'B.jsx': '<button className="p-2 m-2 rounded border shadow font-bold bg-blue">Save</button>'})
        self.assertEqual(sum(f['id'] == 'UI-REUSE' for f in data['findings']), 1)
        schema = json.loads((ROOT / 'schemas/ui_deep.json').read_text())
        self.assertEqual(set(data), set(schema['required']))
        for finding in data['findings']:
            self.assertEqual(set(finding), set(schema['$defs']['finding']['required']))

    def test_cli_read_only_and_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'target'
            out = Path(tmp) / 'output'
            target.mkdir()
            (target / 'Page.html').write_text('<img>')
            before = list(target.iterdir())
            out.mkdir()
            (out / 'ui-deep.json').symlink_to(target / 'Page.html')
            proc = subprocess.run([str(ROOT / 'bin/helix'), 'ui', 'deep', str(target), '--out', str(out)],
                                  text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['findings'][0]['id'], 'UX-ALT')
            self.assertEqual(list(target.iterdir()), before)
            self.assertEqual((target / 'Page.html').read_text(), '<img>')
            self.assertFalse((out / 'ui-deep.json').is_symlink())
            self.assertTrue((out / 'ui-deep.md').exists())
            self.assertEqual(json.loads((out / 'ui-deep.json').read_text()), json.loads(proc.stdout))
            proc = subprocess.run([str(ROOT / 'bin/helix'), 'ui', 'deep', str(target), '--out', str(target / 'out')], capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertFalse((target / 'out').exists())


if __name__ == '__main__':
    unittest.main()
