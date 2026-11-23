import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_function_stubs as F


class FunctionStubs(unittest.TestCase):
    # Projekt B: 20 ze 128 ekranów z błędem funkcji serwerowej (fetch_orders, fetch_metrics…), bo funkcje nie działały lokalnie.
    def project(self, d):
        root = Path(d)
        (root / 'src' / 'hooks').mkdir(parents=True)
        (root / 'src' / 'hooks' / 'useOrders.ts').write_text("const { data } = await supabase.functions.invoke('fetch_orders', { body });\nreturn data.items;")
        (root / 'src' / 'Metrics.tsx').write_text("fetch(`${url}/functions/v1/fetch_metrics`)")
        (root / 'supabase' / 'functions' / 'fetch_orders').mkdir(parents=True)
        (root / 'supabase' / 'functions' / 'fetch_orders' / 'index.ts').write_text("return new Response(JSON.stringify({ items: rows }))")
        (root / 'supabase' / 'functions' / 'internal').mkdir(parents=True)
        (root / 'supabase' / 'functions' / 'internal' / 'index.ts').write_text("functions.invoke('only_server_side')")
        return root

    def test_frontend_calls_become_cached_synthetic_responses(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.project(d)
            self.assertEqual(sorted(F.callers(root)), ['fetch_metrics', 'fetch_orders'])   # wywołania z kodu funkcji się nie liczą
            asked = []
            def ask(text):
                asked.append(text)
                return 'proszę: ' + json.dumps({'functions': {'fetch_orders': {'items': [{'kwota': 120}]}, 'fetch_metrics': [{'cel': 'A'}]}})
            stubs, report = F.generate(root, ask, root / 'cache')
            self.assertEqual(stubs['fetch_orders'], {'items': [{'kwota': 120}]})
            self.assertIn('return new Response', asked[0]); self.assertIn('src/hooks/useOrders.ts:1', asked[0])
            self.assertEqual((report['functions'], report['stubbed'], report['model_calls']), (2, 2, 1))
            again, report = F.generate(root, lambda text: self.fail('cache miss'), root / 'cache')
            self.assertEqual((again, report['cached'], report['model_calls']), (stubs, 1, 0))

    def test_bad_model_answer_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.project(d)
            stubs, report = F.generate(root, lambda text: 'nie wiem', root / 'cache')
            self.assertEqual(stubs, {})
            self.assertEqual(len(report['errors']), 1)


    def test_symlinks_and_files_outside_the_project_never_reach_the_model(self):
        # Przegląd bezpieczeństwa 16.11: projekt bywa cudzy; dowiązanie (np. do ~/.ssh) nie może trafić do polecenia.
        import os
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            root = self.project(d)
            secret = Path(outside, 'id_rsa.ts'); secret.write_text("functions.invoke('steal')\nPRIVATE_HOST_SECRET")
            os.symlink(secret, root / 'src' / 'link.ts')
            os.symlink(outside, root / 'src' / 'linked_dir')
            (root / 'supabase' / 'functions' / 'fetch_metrics').symlink_to(outside, target_is_directory=True)
            Path(outside, 'index.ts').write_text('PRIVATE_HOST_SECRET')
            self.assertNotIn('steal', F.callers(root))
            self.assertEqual(F.source(root, 'fetch_metrics'), '')
            self.assertEqual(F.source(root, '../../etc'), '')
            asked = []
            F.generate(root, lambda text: asked.append(text) or '{"functions": {}}', root / 'cache')
            self.assertTrue(asked and all('PRIVATE_HOST_SECRET' not in text for text in asked))

if __name__ == '__main__':
    unittest.main()
