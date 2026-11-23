"""Neutral, offline regressions for field audit fixes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_new as H
from helix_pro import assess, improvement_plan

class FieldAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'project'
        self.root.mkdir()
    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    def cfg(self, **kw): self.write('helix.json', json.dumps(kw))
    def test_external_documents_read_only(self):
        doc = self.base / 'architecture.yaml'
        doc.write_text('summary: service boundaries\nVERIFIED local documentation\n')
        before = doc.read_bytes()
        adr = self.base / 'adr' / 'decision.md'
        adr.parent.mkdir()
        adr.write_text('Decision: service boundaries')
        self.cfg(docs_paths=[str(self.base)])
        report = assess(self.root, 'M')
        document = next(d for d in report['documents'] if str(doc) in d['path'])
        self.assertEqual(document['lines'], 2)
        self.assertIn(str(doc) + ':', json.dumps(report['areas']))
        self.assertEqual(doc.read_bytes(), before)
        self.assertEqual(report['documents'], assess(self.root, 'M', [str(self.base)])['documents'])
    def test_custom_gate_preparation_not_execution(self):
        self.cfg(custom_gates=[dict(name='rules', area='UI', command='npm run gate:visual', description='Visual assertions')])
        self.write('package.json', '{"scripts":{"gate:visual":"node rules.mjs"}}')
        self.write('Makefile', 'gate-visual:\n\ttrue\n')
        self.write('playwright.config.ts', 'export default {projects: []}')
        result = assess(self.root, 'M')
        self.assertGreater(result['areas']['UI']['preparation_score'], 0)
        self.assertEqual(result['areas']['UI']['score'], 0)
        self.assertEqual(result['areas']['UI']['preparation_score'], 33)
        custom = next(x for x in result['areas']['UI']['requirements'] if x['id'] == 'custom:rules')
        self.assertEqual(custom['execution_status'], 'needs-runtime')
        self.assertGreaterEqual(len(result['custom_gates']), 4)
        self.assertIn('custom:rules', json.dumps(improvement_plan(result)))
    def test_profile_warning_override_strict(self):
        self.write('compose.yaml', 'replicas: 3\nqueue: rabbitmq\n')
        messages = H.audit(self.root, self.base / 'inferred')
        self.assertIn('WARNING', messages[0])
        self.assertIn('profile L', messages[0])
        with self.assertRaises(ValueError): H.audit(self.root, self.base / 'strict', strict_profile=True)
        H.audit(self.root, self.base / 'explicit', 'S', strict_profile=True)
        self.assertEqual(H.load(self.base / 'explicit/audit.json')['maturity']['profile'], 'S')
    def test_concise_and_verbose(self):
        for i in range(100): self.write(f'tests/test_{i}.py', 'assert True')
        short = H.audit(self.root, self.base / 'short', 'M')
        full = H.audit(self.root, self.base / 'full', 'M', verbose=True)
        self.assertLessEqual(len('\n'.join(short).splitlines()), 40)
        self.assertGreater(len('\n'.join(full)), len('\n'.join(short)))
        self.assertEqual(len(H.load(self.base / 'short/audit.json')['inventory']), 100)
    def test_complete_gap_plan(self):
        H.audit(self.root, self.base / 'audit', 'L')
        report = H.load(self.base / 'audit/audit.json')['maturity']
        plan = improvement_plan(report)
        gaps = [x for area in report['areas'].values() for x in area['requirements'] if not x['satisfied'] or x['runtime'] or x['exception']]
        self.assertEqual(len(plan['checkpoints']), len(gaps))
        text = (self.base / 'audit/gap-plan.md').read_text()
        for gap in gaps:
            self.assertIn(gap['id'], text)
            self.assertIn(gap['threshold'], text)
        self.assertTrue(all('Priority P' in cp['goal'] for cp in plan['checkpoints']))
    def test_parts_aggregate_legacy_excluded(self):
        self.write('frontend/package.json', '{}')
        self.write('api/pyproject.toml', '')
        self.assertEqual(len(assess(self.root)['parts']), 2)
        self.cfg(parts=[dict(path='frontend', status='legacy'), dict(path='api', excluded=True)])
        r = assess(self.root)
        self.assertEqual(r['score'], r['parts'][0]['maturity']['score'])
        self.assertNotIn('maturity', r['parts'][1])
        self.assertIn('frontend/', json.dumps(improvement_plan(r)))
    def test_sharded_ci_contract(self):
        text = (H.NEW / 'templates/ci/e2e.yml').read_text()
        for token in ('fail-fast: false', 'matrix:', '--shard=', 'if: always()', 'merge-reports', 'github.run_attempt', 'rerun failed'):
            self.assertIn(token.lower(), text.lower())

    def test_external_unrelated_text_does_not_satisfy_controls(self):
        doc = self.base / 'notes.txt'
        doc.write_text('unrelated nonempty notes')
        report = assess(self.root, 'L', [str(doc)])
        for area in ('backend/architecture', 'data', 'ops/reliability'):
            self.assertFalse(any(x['satisfied'] for x in report['areas'][area]['requirements']))

    def test_external_yml_sql_and_mixed_evidence(self):
        docs = self.base / 'docs'
        docs.mkdir()
        (docs / 'observability.yml').write_text('structured redacted logs, metrics, traces, actionable alerts, owner: operations')
        (docs / '001.sql').write_text('-- migration preserves invariant\nCREATE TABLE sample (id int PRIMARY KEY, parent int REFERENCES parents(id), CHECK (id > 0));')
        self.write('data-model.yaml', 'entities: sample')
        report = assess(self.root, 'L', [str(docs)])
        self.assertEqual(len(report['documents']), 2)
        for area, control in [('data', 'data-model'), ('ops/reliability', 'observability')]:
            item = next(x for x in report['areas'][area]['requirements'] if x['id'] == control)
            self.assertTrue(item['satisfied'])
            self.assertTrue(any('(outside repo)' in e for e in item['evidence']))

    def test_invalid_custom_gates_are_errors(self):
        base = dict(name='checks', area='UI', description='Project checks')
        for extra in ({}, {'file': 'absent.ts'}, {'area': 'unknown', 'command': 'true'},
                      {'file': 'absent.ts', 'command': 'true'}, {'command': ''}):
            with self.subTest(extra=extra):
                self.cfg(custom_gates=[dict(base, **extra)])
                with self.assertRaises(ValueError):
                    assess(self.root)

    def test_playwright_detection_requires_projects_declaration(self):
        for text, expected in [('export default {}', False),
                               ('// projects: []\nexport default {}', False),
                               ('export default {projects: [{name: "desktop"}]}', True)]:
            self.write('playwright.config.ts', text)
            detected = assess(self.root)['custom_gates']
            self.assertEqual(any('projects' in g['name'] for g in detected), expected)

    def test_part_priorities_and_visual_match_root(self):
        self.write('frontend/package.json', '{}')
        report = assess(self.root, 'L')
        checkpoints = improvement_plan(report)['checkpoints']
        for area, control, priority, visual in [('security', 'threat-model', 0, False),
                ('data', 'data-model', 0, False), ('ops/reliability', 'ops-slo', 1, False),
                ('UX', 'ux-probes', 2, True), ('UI', 'consistency', 2, True)]:
            root = next(cp for cp in checkpoints if cp['title'] == f'{area}: {control}')
            part = next(cp for cp in checkpoints if cp['title'] == f'frontend/{area}: {control}')
            self.assertEqual(part['goal'], root['goal'])
            self.assertIn(f'Priority P{priority}', part['goal'])
            self.assertEqual(part['visual'], visual)

    def test_artifact_gaps_follow_selected_profile(self):
        for profile in ('S', 'M', 'L', 'XL'):
            out = self.base / profile
            H.audit(self.root, out, profile)
            report = H.load(out / 'audit.json')
            self.assertEqual({g['artifact'] for g in report['gaps']},
                             set(H.required(profile, 'low', 'brownfield')))
