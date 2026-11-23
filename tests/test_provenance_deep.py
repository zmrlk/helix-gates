"""Execution provenance in static reports and model checkpoints, without network."""
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_deep_budget as fixture
from test_security_deep import D, H
import helix_consistency as consistency
import helix_environment as environment
import helix_lenses as lenses
import helix_ui_deep as ui
import helix_ux as ux


class DeepProvenance(unittest.TestCase):
    args, covered = fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def setUp(self):
        fixture.DeepBudget.setUp(self)
        self.cfg['models'] = {'codex': ['hunter-model'], 'grok-cli': ['verifier-model'], 'gemini': ['fallback-model']}
        self.ctx.availability = fixture.availability(self.cfg)
        self.ctx.evidence_root = self.root / 'state/evidence'
        patch.object(consistency, 'H', H).start()
        patch.object(ux, 'H', H).start()

    def test_plan_has_source_identity_but_no_executed_models_or_node(self):
        _, meta = D.run(self.ctx, self.args(plan_only=True))
        self.assertEqual(meta['provenance']['target_head'], meta['source_ref']['head'])
        self.assertFalse(meta['provenance']['target_dirty'])
        self.assertEqual(meta['provenance']['models'], [])
        self.assertFalse(meta['provenance']['tools']['node']['used'])
        self.assertTrue(meta['provenance']['tools']['python']['used'])
        self.assertIsNotNone(meta['provenance']['tools']['python']['version'])
        cost = self.load('cost-plan.json')
        self.assertEqual(cost['provenance']['models'], [])
        self.assertEqual({row['status'] for row in cost['planned_models']}, {'planned'})
        self.assertEqual(self.load('progress.json')['provenance'], meta['provenance'])
        self.assertIn('provenance w run-metadata.json', (self.out / 'REPORT.md').read_text())
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_failed_attempts_and_planned_models_do_not_become_actual_receipts(self):
        with patch.object(H, 'call_grok_cli', side_effect=H.ProviderError('synthetic failure')), \
             patch.object(environment, 'provenance', wraps=environment.provenance) as snapshot:
            _, meta = D.run(self.ctx, self.args())
        snapshot.assert_called_once()
        observed = {(row['provider'], row['model']) for row in meta['provenance']['models']}
        self.assertEqual(observed, {('codex', 'hunter-model')})
        self.assertEqual(meta['usage']['calls'], 2)
        self.assertTrue(meta['provenance']['tools']['node']['used'])
        self.assertTrue(meta['provenance']['tools']['python']['used'])
        self.assertIsNone(meta['provenance']['tools']['node']['version'])
        for artifact in ('run-metadata.json', 'progress.json'):
            self.assertEqual(self.load(artifact)['provenance'], meta['provenance'])
        self.assertEqual(self.load('checkpoint.json')['meta']['provenance'], meta['provenance'])
        self.assertEqual(self.load('cost-plan.json')['provenance']['models'], [])

    def test_cache_reuse_does_not_invent_a_current_hunter_call(self):
        D.run(self.ctx, self.args())
        _, cached = D.run(self.ctx, self.args(out=str(self.root / 'cached')))
        self.assertEqual(cached['progress']['cache_hits'], 1)
        self.assertEqual({row['provider'] for row in cached['provenance']['models']}, {'grok-cli'})
        self.assertEqual(cached['usage']['calls'], 1)
        self.assertTrue(cached['provenance']['tools']['node']['used'])

    def test_static_ui_and_lenses_have_dirty_identity_and_no_model_probes(self):
        source = self.repo / 'frontend/src/Page.svelte'
        source.parent.mkdir(parents=True)
        source.write_text('<button>Save</button>\n')
        with patch.object(environment, 'local_tool', side_effect=AssertionError('metadata must not probe tools')):
            reports = [(ui.report(self.repo), 'ui_deep.json'), (lenses.report(self.repo), 'review_deep.json')]
        for report, schema_name in reports:
            with self.subTest(report=schema_name):
                self.assertTrue(report['provenance']['target_dirty'])
                self.assertEqual(report['provenance']['models'], [])
                self.assertFalse(report['provenance']['tools']['node']['used'])
                schema = json.loads((Path(__file__).resolve().parents[1] / 'schemas' / schema_name).read_text())
                self.assertIn('provenance', schema['required'])
                self.assertIn('provenance', schema['properties'])
        self.assertIn('provenance w ui-deep.json', ui.markdown(reports[0][0]))
        self.assertIn('provenance w review-deep.json', lenses.markdown(reports[1][0]))
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_consistency_static_scan_report_and_gate_share_execution_metadata(self):
        source = self.repo / 'frontend/src/Page.svelte'
        source.parent.mkdir(parents=True)
        source.write_text('<button>Save</button>\n')
        with patch.object(environment, 'local_tool', side_effect=AssertionError('no tool probe')):
            gate = consistency.gate_consistency(self.ctx, a=SimpleNamespace(static_only=True))
        report_path = Path(gate['report']).parent / 'report.json'
        report = json.loads(report_path.read_text())
        static = json.loads((report_path.parent / 'static.json').read_text())
        self.assertEqual(gate['provenance'], report['provenance'])
        self.assertEqual(report['input_provenance']['static'], static['provenance'])
        self.assertEqual(report['provenance']['target_head'], static['provenance']['target_head'])
        self.assertEqual(gate['provenance']['models'], [])
        self.assertFalse(gate['provenance']['tools']['playwright']['used'])

    def test_consistency_runtime_records_invoked_tools_without_inventing_versions(self):
        out = self.root / 'runtime'; out.mkdir()
        configuration = consistency.cfg(self.ctx)
        configuration.update(base_url='http://127.0.0.1:12345', pages=[])
        original = subprocess.run
        commands = []
        def process(command, **kwargs):
            commands.append(command)
            if command[0] == 'node':
                self.assertEqual(command[1], str(consistency.CS_JS))
                (out / 'raw.json').write_text(json.dumps({'results': [], 'targets': []}))
                return subprocess.CompletedProcess(command, 0, '', '')
            self.assertEqual(command[0], 'git')
            return original(command, **kwargs)
        with patch.object(consistency.subprocess, 'run', side_effect=process), \
             patch.object(environment, 'local_tool', side_effect=AssertionError('no version probe')):
            raw = consistency.run_runtime(self.ctx, configuration, out)
        self.assertEqual(json.loads((out / 'raw.json').read_text())['provenance'], raw['provenance'])
        for name in ('node', 'playwright'):
            self.assertTrue(raw['provenance']['tools'][name]['used'])
            self.assertIsNone(raw['provenance']['tools'][name]['version'])
        self.assertEqual(raw['provenance']['models'], [])
        self.assertFalse(any('--version' in command for command in commands))

    def ux_fixture(self):
        self.out.mkdir(); self.ctx.state_dir.mkdir()
        self.ctx.ev = lambda cp: self.ctx.state_dir
        self.cfg['ux'] = {'enabled': True, 'base_url': 'http://127.0.0.1:12345'}
        target = {'id': 'fixture/chromium', 'engine': 'chromium', 'kind': 'desktop', 'label': 'Fixture'}
        row = {'target': target['id'], 'engine': 'chromium', 'page': 'home', 'variant': 'base',
               'status': 'pass', 'findings': []}
        return ux.cfg(self.ctx), [target], row

    def test_ux_report_preserves_actual_runner_versions_and_model_receipts(self):
        config, targets, row = self.ux_fixture()
        initial = environment.provenance(self.repo)
        tools = [{'tool': name, 'version': version, 'used': True} for name, version in
                 [('node', '22.1.0'), ('playwright', '1.50.0'), ('chromium', '130.0.1.2')]]
        (self.out / 'scan.json').write_text(json.dumps({'results': [row], 'tools': tools, 'provenance': initial}))
        # Old flow metadata cannot erase known scan versions.
        (self.out / 'flows.json').write_text(json.dumps({'results': [dict(flow='f', target=targets[0]['id'],
            engine='chromium', status='pass', steps=[], ok=True, friction=[])]}))
        (self.out / 'judge.json').write_text(json.dumps({targets[0]['id']:
            {'_used': {'provider': 'gemini', 'model': 'actual-vision'}, 'issues': []},
            'failed': {'error': 'synthetic unavailable'}, '_provenance': initial}))
        with patch.object(ux, 'engines', side_effect=AssertionError('no browser probe')), \
             patch.object(environment, 'local_tool', side_effect=AssertionError('no tool probe')), \
             patch.object(ux, 'thumbs'), patch.object(ux, 'render_md', return_value='metadata fixture'), \
             patch.object(ux, 'render_html', return_value='metadata fixture'):
            report = ux.build_report(self.ctx, config, self.out, targets)
        actual = report['provenance']
        for receipt in tools:
            self.assertEqual(actual['tools'][receipt['tool']]['version'], receipt['version'])
            self.assertTrue(actual['tools'][receipt['tool']]['used'])
        self.assertEqual([(m['provider'], m['model'], m['role']) for m in actual['models']],
                         [('gemini', 'actual-vision', 'ux_judge')])
        self.assertEqual(report['input_provenance']['scan'], initial)
        self.assertNotIn('_provenance', report['judge'])
        with patch.object(ux, 'cmd_ux', return_value=report):
            gate = ux.gate_ux(self.ctx, 'cp1')
        self.assertEqual(gate['provenance'], actual)
        self.assertEqual(json.loads((self.ctx.state_dir / 'ux.json').read_text())['provenance'], actual)

    def test_ux_legacy_runner_has_unknown_versions_and_disabled_gate_used_false(self):
        config, targets, row = self.ux_fixture()
        (self.out / 'scan.json').write_text(json.dumps({'results': [row]}))
        with patch.object(ux, 'thumbs'), patch.object(environment, 'local_tool', side_effect=AssertionError('no probe')):
            report = ux.build_report(self.ctx, config, self.out, targets)
        for name in ('node', 'playwright', 'chromium'):
            self.assertTrue(report['provenance']['tools'][name]['used'])
            self.assertIsNone(report['provenance']['tools'][name]['version'])
        self.assertEqual(report['provenance']['models'], [])
        self.assertIn('provenance w ux-report.json', (self.out / 'ux-report.md').read_text())
        self.assertIn('provenance JSON', (self.out / 'ux-report.html').read_text())
        self.cfg['ux']['enabled'] = False
        gate = ux.gate_ux(self.ctx, 'cp1')
        self.assertFalse(gate['provenance']['tools']['node']['used'])
        self.assertEqual(gate['provenance']['models'], [])

    def test_ux_job_records_source_before_the_runner(self):
        config, targets, _ = self.ux_fixture()
        with patch.object(environment, 'local_tool', side_effect=AssertionError('no probe')):
            job = json.loads(ux.job_for(self.ctx, config, self.out, targets).read_text())
        self.assertFalse(job['provenance']['target_dirty'])
        self.assertEqual(job['provenance']['models'], [])
        self.assertFalse(job['provenance']['tools']['node']['used'])

    def test_ux_explorer_keeps_actual_model_and_runner_receipts(self):
        config, targets, _ = self.ux_fixture()
        config['explore']['devices'] = [targets[0]['id']]
        tools = [{'tool': name, 'version': version, 'used': True} for name, version in
                 [('node', '22.1.0'), ('playwright', '1.50.0'), ('chromium', '130.0.1.2')]]
        replies = [{'ok': True, 'tools': tools}, {'ok': True, 'elements': [], 'text': 'Done'},
                   {'ok': True}, {'ok': True}]
        runner = SimpleNamespace(stdin=io.StringIO(), stdout=io.StringIO('\n'.join(json.dumps(r) for r in replies)),
                                 wait=lambda **kw: 0)
        with patch.object(ux.subprocess, 'Popen', return_value=runner), \
             patch.object(H, 'ask', return_value=(json.dumps({'action': 'done', 'success': True}),
                 {'provider': 'gemini', 'model': 'actual-explorer'})), patch.object(H, 'fill', return_value='fixture'), \
             patch.object(environment, '_git_ref', return_value={'head': 'a' * 40, 'dirty': False, 'status': 'recorded'}):
            ux.explore(self.ctx, config, self.out, targets, [{'id': 'one', 'goal': 'Finish'}], {})
        report = json.loads((self.out / 'explore.json').read_text())
        self.assertEqual(report['provenance']['models'][0]['model'], 'actual-explorer')
        self.assertEqual(report['provenance']['models'][0]['role'], 'ux_explorer')
        self.assertEqual(report['provenance']['tools']['node']['version'], '22.1.0')
        self.assertTrue(report['provenance']['tools']['python']['used'])

    def test_ux_node_metadata_only_reads_loaded_library_and_existing_browsers(self):
        package = self.root / 'playwright'; package.mkdir()
        (package / 'package.json').write_text(json.dumps({'version': '1.50.0'}))
        (package / 'index.js').write_text('module.exports = {};')
        script = r'''
const Module = require('module'), real = Module._load;
Module._load = function(name, parent, main) {
  if (name === './dependencies.cjs') return n => {
    if (n === 'playwright') return process.env.FIXTURE_PLAYWRIGHT;
    throw Error('no other dependency');
  };
  if (name === 'child_process') throw Error('metadata may not spawn tools');
  return real.apply(this, arguments);
};
const ux = require(process.env.FIXTURE_UX);
(async () => {
  const tools = await ux.executionTools({chromium: Promise.resolve({version: () => '130.0.1.2'})});
  const empty = await ux.executionTools({});
  const provenance = ux.executionProvenance({provenance: {target_head: 'fixture', models: [], tools: {}}}, tools);
  console.log(JSON.stringify({tools, empty, provenance, node: process.versions.node}));
})().catch(e => { console.error(e); process.exitCode = 1; });
'''
        process = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=10,
            env=dict(os.environ, FIXTURE_PLAYWRIGHT=str(package / 'index.js'), FIXTURE_UX=str(ux.UX_JS)))
        self.assertEqual(process.returncode, 0, process.stderr)
        observed = json.loads(process.stdout)
        versions = {row['tool']: row['version'] for row in observed['tools']}
        self.assertEqual(versions, {'node': observed['node'], 'playwright': '1.50.0', 'chromium': '130.0.1.2'})
        self.assertEqual({row['tool'] for row in observed['empty']}, {'node', 'playwright'})
        self.assertEqual(observed['provenance']['target_head'], 'fixture')
        self.assertEqual(observed['provenance']['models'], [])


if __name__ == '__main__': unittest.main()
