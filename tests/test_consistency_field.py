"""Offline regressions for source coverage and evidence in consistency reports."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'bin'))
if 'helix_main' not in sys.modules:
    loader = importlib.machinery.SourceFileLoader('helix_main', str(ROOT / 'bin/helix'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    main = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = main
    loader.exec_module(main)
import helix_consistency as C
from helix_contracts import VERSION


class SourceCoverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / 'repo'
        self.repo.mkdir()

    def write(self, path, text='<button>Save</button>'):
        dest = self.repo / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
        return dest

    def test_discovers_nested_monorepo_sources_without_dependencies(self):
        for path in ('frontend/src/Form.svelte', 'services/console/client/src/Form.tsx',
                     'apps/site/app/page.tsx', 'packages/ui/src/Badge.vue'):
            self.write(path)
        self.write('node_modules/vendor/src/Ignore.tsx')
        self.write('frontend/node_modules/vendor/src/Ignore.tsx')
        self.write('frontend/src/tests/Ignore.tsx')
        st = C.static_scan(self.repo, C.DEFAULT_CS['static'])
        self.assertEqual(st['files'], 4)
        self.assertEqual(st['status'], 'COMPLETE')
        self.assertIn('frontend/src', st['paths'])

    def test_explicit_scope_does_not_silently_expand(self):
        self.write('frontend/src/Form.svelte')
        self.write('apps/other/src/Other.tsx')
        st = C.static_scan(self.repo, C.DEFAULT_CS['static'] | {'paths': ['frontend/src']})
        self.assertEqual(st['files'], 1)
        self.assertEqual(st['paths'], ['frontend/src'])

    def test_missing_or_empty_scope_is_incomplete(self):
        for paths in (None, ['missing'], []):
            with self.subTest(paths=paths):
                st = C.static_scan(self.repo, C.DEFAULT_CS['static'] | {'paths': paths})
                self.assertEqual(st['status'], 'INCOMPLETE')
                self.assertTrue(st['problems'])

    def test_external_symlink_is_not_read(self):
        external = Path(self.tmp.name) / 'private.tsx'
        external.write_text('<button>Private</button>')
        source = self.repo / 'frontend/src'
        source.mkdir(parents=True)
        (source / 'Linked.tsx').symlink_to(external)
        st = C.static_scan(self.repo, C.DEFAULT_CS['static'])
        self.assertEqual(st['files'], 0)
        self.assertEqual(st['status'], 'INCOMPLETE')

    def test_empty_cli_writes_incomplete_report_and_fails(self):
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True, capture_output=True)
        self.write('helix.json', json.dumps({'helix_version': VERSION}))
        out = Path(self.tmp.name) / 'report'
        state = Path(self.tmp.name) / 'state'
        result = subprocess.run([sys.executable, str(ROOT / 'bin/helix'), '--repo', str(self.repo),
                                 '--state-dir', str(state), 'consistency', 'code', '--out', str(out)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        report = json.loads((out / 'report.json').read_text())
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIn('INCOMPLETE', (out / 'consistency-report.md').read_text())

    def test_empty_static_gate_does_not_pass_or_claim_fixed(self):
        st = C.static_scan(self.repo, C.DEFAULT_CS['static'])
        base = {'keys': {'old': {'layer': 'static', 'severity': 'medium'}}}
        result = C.compare_baseline([], base, ['medium'], C.measurement_coverage(None, st))
        self.assertFalse(result['pass'])
        self.assertEqual(result['fixed'], [])
        self.assertTrue(result['incomplete'])


class EvidenceAndConfidence(unittest.TestCase):
    def setUp(self):
        C.ADOPTION.clear()
        self.addCleanup(C.ADOPTION.clear)
        self.st = {'files': 2, 'shared': {'input': ['src/components/ui/Input.svelte']},
                   'raw': {'input': [('src/A.svelte', n) for n in range(1, 42)] + [('src/B.svelte', 9)]},
                   'impl': {}, 'hardcoded': {}, 'dups': [], 'backend_en': []}

    def test_aggregate_keeps_every_location_and_source_key(self):
        per_file = C.analyze_static(self.st, None)
        aggregate = C.aggregate_static(per_file)[0]
        self.assertEqual(aggregate['where'], [f'src/A.svelte:{n}' for n in range(1, 42)] + ['src/B.svelte:9'])
        self.assertEqual(aggregate['count'], 42)
        self.assertEqual(aggregate['source_keys'], [f['key'] for f in per_file])

    def test_component_presence_is_advisory_without_approved_contract(self):
        for contract in (None, {'status': 'proposal', 'components': {'input': {'component': 'Input', 'require': True}}}):
            with self.subTest(contract=contract):
                findings = C.analyze_static(self.st, contract)
                aggregate = C.aggregate_static(findings)[0]
                self.assertEqual(aggregate['confidence'], 'ASSUMPTION')
                self.assertNotEqual(aggregate['severity'], 'high')
                self.assertTrue(C.compare_baseline(findings, None, ['high', 'medium'])['pass'])

    def test_approved_explicit_requirement_still_blocks_regression(self):
        contract = {'status': 'approved', 'components': {'input': {'component': 'Input', 'require': True}}}
        findings = C.analyze_static(self.st, contract)
        self.assertTrue(all(f['confidence'] == 'VERIFIED' for f in findings))
        self.assertFalse(C.compare_baseline(findings, None, ['high', 'medium'])['pass'])

    def test_exception_status_survives_aggregation(self):
        findings = C.analyze_static(self.st, None)
        findings[0]['status'] = 'exception'
        aggregate = C.aggregate_static(findings)
        self.assertEqual(sum(f['count'] for f in aggregate if f['status'] == 'open'), 1)
        self.assertEqual(sum(f['count'] for f in aggregate if f['status'] == 'exception'), 41)


if __name__ == '__main__':
    unittest.main()
