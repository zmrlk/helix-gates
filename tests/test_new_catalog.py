"""Public audit recognizes source families without executing their projects."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_new import audit


class NewCatalogTests(unittest.TestCase):
    def test_dotnet_module_and_template_sources_are_catalogued_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            repo = base / 'repo'; repo.mkdir()
            sources = {'App.cs': 'class App {}', 'Job.fs': 'printfn "sample"',
                       'Script.fsx': 'printfn "sample"', 'Logic.vb': 'Class Logic\nEnd Class'}
            sources.update({'view' + suffix: 'export const view = 1;' for suffix in ('.mjs', '.cjs', '.mts', '.cts')})
            sources.update({'view' + suffix: '<h1>Example</h1>' for suffix in ('.svelte', '.vue', '.html')})
            sources['style.css'] = 'body { color: #123456; }'
            manifests = {'App' + suffix: '<Project><TargetFramework>net8.0</TargetFramework></Project>' for suffix in ('.csproj', '.fsproj', '.vbproj')}
            files = dict(sources, **manifests)
            for name, text in files.items():
                (repo / name).write_text(text)
            audit(repo, base / 'audit', state_dir=base / 'state', offline=True, probe=False)
            result = json.loads((base / 'audit/audit.json').read_text())
            categories = {row['path']: row['categories'] for row in result['inventory']}
            for name in sources:
                self.assertIn('language:' + Path(name).suffix, categories[name])
            for name in manifests:
                self.assertIn('manifest', categories[name])
            self.assertEqual(result['execution']['models'], 0)
            self.assertFalse(result['execution']['application'])
            self.assertFalse(result['execution']['database_started'])
            self.assertEqual({p.name: p.read_text() for p in repo.iterdir()}, files)


if __name__ == '__main__':
    unittest.main()
