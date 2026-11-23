"""UX admission uses fake measurements and fake browsers/models, without network."""
import json
import io
import os
from pathlib import Path
import subprocess
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_deep_budget as fixture
from test_security_deep import H
import helix_ux as U
from helix_resources import Governor, ResourcePaused


class UXResources(unittest.TestCase):
    hunter, verifier = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier
    covered = fixture.DeepBudget.covered

    def setUp(self):
        fixture.DeepBudget.setUp(self)
        patch.object(U, 'H', H).start()
        self.ctx.state_dir.mkdir()
        self.cfg['ux'] = {'enabled': True, 'base_url': 'http://127.0.0.1:12345', 'devices': ['desktop'],
                         'desktop_engines': ['chromium'], 'variants': [], 'judge': {'enabled': False}}
        self.args = SimpleNamespace(action='all', base_url=None, no_start=True, matrix=None, devices=None,
            no_variants=False, no_judge=False, explore=False, refresh=False, out=str(self.out))

    def governor(self, levels):
        clock = [0.0]; levels = iter(levels); last = ['normal']
        def sample():
            last[0] = next(levels, last[0]); return {'memory_pressure': last[0]}
        governor = Governor(snapshot_fn=sample, policy={'max_pause_s': 2, 'poll_s': 1, 'sample_s': 0.001}, requested_jobs=3, out=self.out)
        governor._clock = lambda: clock[0]
        governor._sleep = lambda n: clock.__setitem__(0, clock[0] + n)
        self.ctx.resource_governor = governor
        return governor, clock

    def test_critical_before_start_saves_incomplete_report_without_browser_or_model(self):
        self.governor(['critical'])
        with patch.object(U, 'engines') as engines, patch.object(U, 'Server') as server, \
             patch.object(U, 'run_node') as runner, patch.object(H, 'ask') as model:
            report = U.cmd_ux(self.ctx, self.args)
        for tool in (engines, server, runner, model): tool.assert_not_called()
        self.assertFalse(report['pass'])
        self.assertEqual(report['run_status'], 'resource_paused')
        self.assertEqual(set(report['not_checked']['stages']), {'scan', 'report'})
        self.assertFalse(report['provenance']['tools']['node']['used'])
        self.assertEqual(report['ran_checks'], [])
        self.assertEqual(report['resources']['max_pause_s'], 2)
        self.assertIn('RESOURCE_PAUSED', (self.out / 'ux-report.md').read_text())

    def test_critical_recovers_and_job_uses_live_monitor_without_changing_parallel(self):
        _, clock = self.governor(['critical', 'normal'])
        def run(mode, path):
            job = json.loads(Path(path).read_text())
            self.assertEqual(job['parallel'], 3)
            current = json.loads(Path(job['resources']['path']).read_text())
            self.assertGreater(current['effective_jobs'], 0)
            (self.out / 'scan.json').write_text(json.dumps({'run_status': 'complete', 'not_checked': [],
                'results': [{'target': 'desktop/chromium', 'engine': 'chromium', 'page': 'home', 'variant': 'base',
                             'status': 'pass', 'findings': []}]}))
        with patch.object(U, 'engines', return_value={'chromium': 'fixture'}), patch.object(U, 'Server', return_value=U._Null()), \
             patch.object(U, 'run_node', side_effect=run), patch.object(H, 'ask') as model:
            report = U.cmd_ux(self.ctx, self.args)
        model.assert_not_called()
        self.assertTrue(report['pass'])
        self.assertGreaterEqual(clock[0], 1)
        self.assertEqual(report['resources']['requested_jobs'], 3)
        self.assertEqual({r['state'] for r in report['resources']['decisions']}, {'critical', 'normal'})

    def test_partial_node_results_are_retained_and_make_gate_incomplete(self):
        self.governor(['normal'])
        def run(mode, path):
            (self.out / 'scan.json').write_text(json.dumps({'run_status': 'resource_paused',
                'not_checked': [{'target': 'desktop/chromium', 'page': 'home', 'variant': 'base'}], 'results': []}))
            raise ResourcePaused('synthetic pause')
        with patch.object(U, 'engines', return_value={'chromium': 'fixture'}), patch.object(U, 'Server', return_value=U._Null()), \
             patch.object(U, 'run_node', side_effect=run):
            report = U.cmd_ux(self.ctx, self.args)
        self.ctx.ev = lambda cp: self.ctx.state_dir
        with patch.object(U, 'cmd_ux', return_value=report): gate = U.gate_ux(self.ctx, 'cp1')
        self.assertFalse(gate['pass'])
        self.assertEqual(gate['run_status'], 'resource_paused')
        self.assertEqual(len(gate['not_checked']['scan']), 1)
        self.assertTrue((self.out / 'scan.json').exists())

    def previous_artifacts(self):
        self.out.mkdir(exist_ok=True)
        previous = dict(at='previous-attempt', run_status='complete', **{'pass': True}, provenance={'target_head': 'a' * 40})
        (self.out / 'ux-report.json').write_text(json.dumps(previous))
        (self.out / 'scan.json').write_text(json.dumps({'run_status': 'complete', 'tools': [
            {'tool': 'chromium', 'version': '123.4', 'used': True}], 'results': [
            {'target': 'desktop/chromium', 'engine': 'chromium', 'page': 'home', 'variant': 'base', 'status': 'pass', 'findings': []}]}))
        (self.out / 'judge.json').write_text(json.dumps({'desktop/chromium':
            {'_used': {'provider': 'gemini', 'model': 'stale-model'}, 'issues': []}}))

    def assert_no_previous_execution(self, report):
        self.assertEqual(report['stale_inputs'], ['scan.json', 'judge.json'])
        self.assertEqual(report['provenance']['models'], [])
        self.assertFalse(report['provenance']['tools']['chromium']['used'])
        self.assertEqual(report['ran_checks'], [])
        self.assertEqual(report['counts'], {'pass': 0, 'warn': 0, 'fail': 0})
        self.assertIsNone(report['input_provenance']['scan'])
        self.assertEqual(report['historical_sources']['judge.json']['artifact'], 'judge.json')
        latest = json.loads((self.ctx.state_dir / 'ux-latest.json').read_text())
        self.assertFalse(latest['pass'])
        self.assertEqual(latest['ran_checks'], [])
        self.assertEqual(latest['provenance']['models'], [])

    def test_failed_retry_replaces_previous_pass_and_labels_stale_inputs(self):
        self.governor(['normal'])
        self.previous_artifacts()
        with patch.object(U, 'engines', return_value={'chromium': 'fixture'}), patch.object(U, 'Server', return_value=U._Null()), \
             patch.object(U, 'run_node', side_effect=RuntimeError('ux.cjs scan failed (exit 1): token=SECRET')):
            report = U.cmd_ux(self.ctx, self.args)
        self.assertEqual(report['run_status'], 'partial')
        self.assertFalse(report['pass'])
        self.assertEqual(report['previous_attempt']['at'], 'previous-attempt')
        self.assertTrue(report['previous_attempt']['stale'])
        self.assert_no_previous_execution(report)
        self.assertIn('code=1', report['reason'])
        self.assertNotIn('SECRET', json.dumps(report))
        for name in ('ux-report.json', 'ux-progress.json'):
            current = json.loads((self.out / name).read_text())
            self.assertNotEqual(current['run_status'], 'complete')
        self.assertFalse(json.loads((self.ctx.state_dir / 'ux-latest.json').read_text())['pass'])
        self.assertIn('Nie potwierdzają bieżącego przebiegu', (self.out / 'ux-report.md').read_text())

    def test_resource_pause_before_retry_excludes_previous_models_and_browser_checks(self):
        self.governor(['critical'])
        self.previous_artifacts()
        with patch.object(U, 'engines') as engines, patch.object(U, 'run_node') as runner, patch.object(H, 'ask') as model:
            report = U.cmd_ux(self.ctx, self.args)
        for tool in (engines, runner, model): tool.assert_not_called()
        self.assertEqual(report['run_status'], 'resource_paused')
        self.assert_no_previous_execution(report)

    def test_interruption_preserves_non_pass_breadcrumb_before_any_runner_starts(self):
        self.governor(['normal'])
        self.previous_artifacts()
        def interrupted():
            report = json.loads((self.out / 'ux-report.json').read_text())
            self.assertEqual(report['run_status'], 'partial')
            self.assertFalse(report['pass'])
            self.assert_no_previous_execution(report)
            raise KeyboardInterrupt()
        with patch.object(U, 'engines', side_effect=interrupted), patch.object(U, 'run_node') as runner, \
             self.assertRaises(KeyboardInterrupt):
            U.cmd_ux(self.ctx, self.args)
        runner.assert_not_called()
        report = json.loads((self.out / 'ux-report.json').read_text())
        self.assertFalse(report['pass'])
        self.assert_no_previous_execution(report)
        self.assertIn('PARTIAL', (self.out / 'ux-report.md').read_text())

    def test_process_timeout_and_launch_error_replace_old_pass_without_leaking_arguments(self):
        errors = [subprocess.TimeoutExpired(['node', 'SECRET-ARGV'], 10, output='SECRET-STDOUT', stderr='SECRET-STDERR'),
                  FileNotFoundError(2, 'SECRET-ERROR', 'SECRET-PATH')]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                self.governor(['normal'])
                self.previous_artifacts()
                with patch.object(U, 'engines', return_value={'chromium': 'fixture'}), patch.object(U, 'Server', return_value=U._Null()), \
                     patch.object(U, 'run_node', side_effect=error):
                    report = U.cmd_ux(self.ctx, self.args)
                self.assertEqual(report['run_status'], 'partial')
                self.assertIn(type(error).__name__, report['reason'])
                self.assertNotIn('SECRET', json.dumps(report))
                self.assert_no_previous_execution(report)
                self.assertFalse(json.loads((self.out / 'ux-report.json').read_text())['pass'])

    def test_retry_partial_scan_keeps_new_results_but_excludes_previous_judge(self):
        self.governor(['normal'])
        self.previous_artifacts()
        def run(mode, path):
            (self.out / 'scan.json').write_text(json.dumps({'run_status': 'error', 'results': [
                {'target': 'desktop/chromium', 'engine': 'chromium', 'page': 'home', 'variant': 'base', 'status': 'pass', 'findings': []}]}))
            raise RuntimeError('ux.cjs scan failed (exit 1)')
        with patch.object(U, 'engines', return_value={'chromium': 'fixture'}), patch.object(U, 'Server', return_value=U._Null()), \
             patch.object(U, 'run_node', side_effect=run):
            report = U.cmd_ux(self.ctx, self.args)
        self.assertEqual(report['stale_inputs'], ['judge.json'])
        self.assertEqual(report['counts']['pass'], 1)
        self.assertEqual(report['provenance']['models'], [])
        self.assertTrue(report['provenance']['tools']['chromium']['used'])
        self.assertIsNone(report['provenance']['tools']['chromium']['version'])
        self.assertIn('overflow', report['ran_checks'])
        self.assertNotIn('judge', report['ran_checks'])
        self.assertFalse(report['pass'])

    def test_successful_scan_does_not_attribute_an_old_disabled_judge_to_current_run(self):
        self.governor(['normal'])
        self.previous_artifacts()
        def run(mode, path):
            (self.out / 'scan.json').write_text(json.dumps({'run_status': 'complete', 'results': [
                {'target': 'desktop/chromium', 'engine': 'chromium', 'page': 'home', 'variant': 'base', 'status': 'pass', 'findings': []}]}))
        with patch.object(U, 'engines', return_value={'chromium': 'fixture'}), patch.object(U, 'Server', return_value=U._Null()), \
             patch.object(U, 'run_node', side_effect=run):
            report = U.cmd_ux(self.ctx, self.args)
        self.assertTrue(report['pass'])
        self.assertEqual(report['run_status'], 'complete')
        self.assertEqual(report['stale_inputs'], ['judge.json'])
        self.assertEqual(report['provenance']['models'], [])
        self.assertNotIn('judge', report['ran_checks'])
        self.assertEqual(report['evidence_scope'], 'current_attempt')

    def test_report_only_aggregates_historical_evidence_without_current_model_or_browser_calls(self):
        self.governor(['normal'])
        self.previous_artifacts()
        self.args.action = 'report'
        with patch.object(U, 'engines', return_value={'chromium': 'fixture'}), patch.object(U, 'run_node') as runner, \
             patch.object(H, 'ask') as model:
            report = U.cmd_ux(self.ctx, self.args)
        runner.assert_not_called(); model.assert_not_called()
        self.assertTrue(report['pass'])
        self.assertEqual(report['counts']['pass'], 1)
        self.assertEqual(report['evidence_scope'], 'historical_artifact_aggregation')
        self.assertEqual(report['provenance']['models'], [])
        self.assertFalse(report['provenance']['tools']['chromium']['used'])
        self.assertTrue(report['historical_sources']['judge.json']['stale'])

    def test_high_pressure_limits_judge_concurrency_and_keeps_receipts(self):
        governor, _ = self.governor(['high'])
        self.out.mkdir(exist_ok=True); self.ctx._ux_governor = governor
        config = U.cfg(self.ctx); config['judge'].update(enabled=True, targets='all', parallel=3)
        targets = [{'id': 'device' + str(i), 'engine': 'chromium', 'viewport': [800, 600]} for i in range(4)]
        scan = {'results': [{'target': t['id'], 'page': 'home', 'variant': 'base', 'shot': 'fixture.png', 'findings': []} for t in targets]}
        (self.out / 'fixture.png').write_bytes(b'png')   # strona bez pliku zrzutu nie jest oceniana
        active = 0; maximum = 0; lock = threading.Lock()
        def model(*args, **kwargs):
            nonlocal active, maximum
            with lock: active += 1; maximum = max(maximum, active)
            time.sleep(0.005)
            with lock: active -= 1
            return '{"issues": []}', {'provider': 'gemini', 'model': 'fixture'}
        with patch.object(U, 'contact_sheet', return_value=self.out / 'sheet.jpg'), patch.object(H, 'ask', side_effect=model):
            results = U.judge(self.ctx, config, self.out, scan, targets)
        self.assertEqual(len(results), 4); self.assertEqual(maximum, 1)
        artifact = json.loads((self.out / 'judge.json').read_text())
        self.assertEqual(artifact['_resources']['not_checked'], [])
        self.assertEqual(artifact['_provenance']['models'][0]['model'], 'fixture')

    def test_critical_between_judgments_keeps_completed_result_and_pending_targets(self):
        governor, clock = self.governor(['high', 'critical'])
        self.out.mkdir(exist_ok=True); self.ctx._ux_governor = governor
        config = U.cfg(self.ctx); config['judge'].update(enabled=True, targets='all', parallel=3)
        targets = [{'id': 'device' + str(i), 'engine': 'chromium', 'viewport': [800, 600]} for i in range(3)]
        scan = {'results': [{'target': t['id'], 'page': 'home', 'variant': 'base', 'shot': 'x.png', 'findings': []} for t in targets]}
        (self.out / 'x.png').write_bytes(b'png')
        def model(*args, **kwargs):
            clock[0] += 1
            return '{"issues": []}', {'provider': 'gemini', 'model': 'fixture'}
        with patch.object(U, 'contact_sheet', return_value=self.out / 'sheet.jpg'), patch.object(H, 'ask', side_effect=model) as caller:
            with self.assertRaises(ResourcePaused): U.judge(self.ctx, config, self.out, scan, targets)
        caller.assert_called_once()
        artifact = json.loads((self.out / 'judge.json').read_text())
        self.assertIn('device0', artifact)
        self.assertEqual(artifact['_resources']['not_checked'], ['device1', 'device2'])
        self.assertEqual(artifact['_resources']['run_status'], 'resource_paused')

    def test_critical_explorer_closes_active_browser_and_saves_partial_result(self):
        governor, clock = self.governor(['normal', 'critical'])
        self.out.mkdir(exist_ok=True); self.ctx._ux_governor = governor
        config = U.cfg(self.ctx); config['explore']['devices'] = ['desktop/chromium']
        config['explore']['enabled'] = True
        target = {'id': 'desktop/chromium', 'engine': 'chromium'}
        replies = iter([{'ok': True}, {'ok': True}, {'ok': True}])
        def response():
            clock[0] += 1
            return json.dumps(next(replies)) + '\n'
        runner = SimpleNamespace(stdin=io.StringIO(), stdout=SimpleNamespace(readline=response), wait=lambda **kw: 0)
        with patch.object(U.subprocess, 'Popen', return_value=runner), patch.object(H, 'ask') as model, \
             patch('helix_environment._git_ref', return_value={'head': 'a' * 40, 'dirty': False, 'status': 'recorded'}):
            with self.assertRaises(ResourcePaused):
                U.explore(self.ctx, config, self.out, [target], [{'goal': 'Finish', 'id': 'one'}], {})
        model.assert_not_called()
        commands = [json.loads(line)['cmd'] for line in runner.stdin.getvalue().splitlines()]
        self.assertEqual(commands, ['open', 'close', 'quit'])
        artifact = json.loads((self.out / 'explore.json').read_text())
        self.assertEqual(artifact['results'][0]['status'], 'not_checked')
        self.assertEqual(artifact['provenance']['models'], [])

    def test_explorer_without_model_is_not_checked_not_failed(self):
        # Projekt B: limit Gemini skończony, 6 zadań eksploratora bez żadnego kroku raport pokazał jako „fail”.
        self.out.mkdir(exist_ok=True)
        config = U.cfg(self.ctx); config['explore'].update(devices=['desktop/chromium'], enabled=True)
        target = {'id': 'desktop/chromium', 'engine': 'chromium'}
        replies = iter([{'ok': True}, {'ok': True, 'text': '', 'elements': []}, {'ok': True}, {'ok': True}])
        runner = SimpleNamespace(stdin=io.StringIO(), stdout=SimpleNamespace(readline=lambda: json.dumps(next(replies)) + '\n'), wait=lambda **kw: 0)
        with patch.object(U.subprocess, 'Popen', return_value=runner), patch.object(H, 'ask', side_effect=H.ProviderError('limit')), \
             patch('helix_environment._git_ref', return_value={'head': 'a' * 40, 'dirty': False, 'status': 'recorded'}):
            U.explore(self.ctx, config, self.out, [target], [{'goal': 'Finish', 'id': 'one'}], {})
        artifact = json.loads((self.out / 'explore.json').read_text())
        self.assertEqual((artifact['results'][0]['status'], artifact['run_status']), ('not_checked', 'partial'))

    def javascript(self, body):
        package = self.root / 'playwright'; package.mkdir()
        (package / 'index.js').write_text('module.exports = {};')
        script = r'''
const Module = require('module'), real = Module._load;
Module._load = function(name) {
  if (name === './dependencies.cjs') return n => {
    if (n === 'playwright') return process.env.FIXTURE_PLAYWRIGHT;
    throw Error('no dependency probes');
  };
  if (name === 'child_process') throw Error('no subprocess');
  return real.apply(this, arguments);
};
const ux = require(process.env.FIXTURE_UX);
const {createGate, ResourcePaused} = require(process.env.FIXTURE_GATE);
''' + '\n(async()=>{\n' + body + '\n})().catch(e=>{console.error(e);process.exitCode=1;});'
        process = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=10,
            env=dict(os.environ, FIXTURE_PLAYWRIGHT=str(package / 'index.js'), FIXTURE_UX=str(U.UX_JS),
                     FIXTURE_GATE=str(U.BIN / 'resources.cjs')))
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_js_high_limit_waits_for_busy_slots_without_spurious_resource_pause(self):
        result = self.javascript(r'''
let active=0,max=0;
const gate=createGate({requestedJobs:3,pollMs:1,maxPauseMs:2,
  readDecision:()=>({state:'high',effective_jobs:1,updated_at:new Date().toISOString()})});
const result=await ux.pool([1,2,3],3,async item=>{
  active++;max=Math.max(max,active);await new Promise(resolve=>setTimeout(resolve,5));active--;return {item};
},gate);
console.log(JSON.stringify({max,result}));
''')
        self.assertEqual(result['max'], 1)
        self.assertIsNone(result['result']['paused'])
        self.assertEqual(result['result']['not_checked'], [])

    def test_js_pause_drains_and_checkpoints_active_unit_before_return(self):
        result = self.javascript(r'''
let admissions=0,finished=false;const checkpoints=[];
const gate={acquire:async()=>{if(admissions++>0)throw new ResourcePaused('fixture');},release:()=>{}};
const result=await ux.pool([1,2,3],3,async item=>{
  await new Promise(resolve=>setTimeout(resolve,5));finished=true;return {item};
},gate,async rows=>checkpoints.push(rows.filter(Boolean).length));
console.log(JSON.stringify({finished,result,checkpoints}));
''')
        self.assertTrue(result['finished'])
        self.assertEqual(result['result']['results'], [{'item': 1}])
        self.assertEqual(result['result']['not_checked'], [1, 2])
        self.assertEqual(result['checkpoints'][-1], 1)

    def test_js_critical_recovers_without_starting_units_until_ready(self):
        result = self.javascript(r'''
let clock=0,reads=0,last='critical';
const gate=createGate({requestedJobs:2,pollMs:1,maxPauseMs:10,now:()=>clock,sleep:async ms=>{clock+=ms;},
 readDecision:()=>{last=++reads<3?'critical':'normal';return {state:last,effective_jobs:last==='normal'?2:0,updated_at:new Date(clock).toISOString()};}});
const states=[];const result=await ux.pool([1,2],2,async item=>{states.push(last);return {item};},gate);
console.log(JSON.stringify({states,result,clock}));
''')
        self.assertEqual(result['states'], ['normal', 'normal'])
        self.assertEqual(result['result']['not_checked'], [])
        self.assertGreaterEqual(result['clock'], 1)

    def test_js_runner_errors_close_only_owned_browsers_and_preserve_partial_artifacts(self):
        observed = self.javascript(r'''
const fs=require('fs'),path=require('path'),pw=require(process.env.FIXTURE_PLAYWRIGHT);
const root=path.dirname(path.dirname(process.env.FIXTURE_PLAYWRIGHT));const observed=[];
for (const scenario of ['scan-error','launch-error','checkpoint-error']) {
  const out=path.join(root,scenario);fs.mkdirSync(out);
  const resourcePath=path.join(out,'resource-current.json');
  fs.writeFileSync(resourcePath,JSON.stringify({state:'normal',effective_jobs:2,updated_at:new Date().toISOString()}));
  let ownedClosed=0,foreignClosed=0,contextClosed=0,renames=0;
  const foreign={close:async()=>{foreignClosed++;}}; // Not created by this runner.
  const owned={version:()=> '130.0.0.1',close:async()=>{ownedClosed++;},newContext:async()=>{
    if(scenario==='scan-error')throw Error('SCAN');
    return {newPage:async()=>({on:()=>{}}),close:async()=>{contextClosed++;}};
  }};
  pw.chromium={launch:async()=>owned};pw.webkit={launch:async()=>{throw Error('LAUNCH');}};
  const targets=[{id:'owned',engine:'chromium',viewport:[800,600]}];
  if(scenario==='launch-error')targets.push({id:'failed',engine:'webkit',viewport:[800,600]});
  const job={out,targets,parallel:2,base_url:'http://127.0.0.1:12345',block_external:false,
    pages:[{name:'home',path:'/'}],variants:[],flows:[{id:'fixture',steps:[]}],checks:{},thresholds:{},
    resources:{path:resourcePath,max_pause_s:1,poll_s:0.001}};
  const rename=fs.renameSync;
  if(scenario==='checkpoint-error')fs.renameSync=function(from,to){
    if(to.endsWith('flows.json')&&++renames===2)throw Error('CHECKPOINT');
    return rename.apply(this,arguments);
  };
  let error;
  try { await (scenario==='scan-error'?ux.cmdScan(job):ux.cmdFlows(job)); }
  catch(e){error=e.message;}
  finally{fs.renameSync=rename;}
  const artifact=JSON.parse(fs.readFileSync(path.join(out,scenario==='scan-error'?'scan.json':'flows.json'),'utf8'));
  observed.push({scenario,error,ownedClosed,foreignClosed,contextClosed,artifact});
}
console.log(JSON.stringify(observed));
''')
        self.assertEqual([item['error'] for item in observed], ['SCAN', 'LAUNCH', 'CHECKPOINT'])
        for item in observed:
            with self.subTest(scenario=item['scenario']):
                self.assertEqual(item['ownedClosed'], 1)
                self.assertEqual(item['foreignClosed'], 0)
                self.assertEqual(item['artifact']['run_status'], 'error')
        self.assertEqual(len(observed[0]['artifact']['not_checked']), 1)
        self.assertEqual(len(observed[1]['artifact']['results']), 1)
        self.assertEqual(len(observed[1]['artifact']['not_checked']), 1)
        self.assertEqual(len(observed[2]['artifact']['results']), 1)


if __name__ == '__main__': unittest.main()
