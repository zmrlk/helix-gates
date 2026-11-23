"""Execution receipts, safe Git snapshots and runtime versions without network."""
import copy
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_runtime import FakeExecutor, TOOLS, FIX
import helix_environment as environment
import helix_runtime as runtime
import helix_pro
import helix_git_readonly as readonly


class ProvenanceRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve()

    def runner(self,executor=None):
        return runtime.Runner(FIX/'sveltekit-pg',self.base/'out',executor=executor or FakeExecutor(),
                              tools={'tools':dict(TOOLS)},port_factory=lambda:31234)

    def test_snapshot_only_reads_git_and_identifies_dirty_source_and_target(self):
        calls=[]
        def snapshot(repo):
            calls.append(repo)
            return dict(head='a'*40 if repo==self.base else 'b'*40, dirty=True,
                        status='recorded', dirty_reason='git_status_without_filters', reason='local Git')
        with patch.object(readonly,'read_ref',side_effect=snapshot), \
             patch.object(environment,'_run',side_effect=AssertionError('unexpected version probe')):
            record=environment.provenance(self.base)
        self.assertEqual(record['target_head'],'a'*40)
        self.assertEqual(record['helix_head'],'b'*40)
        self.assertTrue(record['target_dirty']);self.assertTrue(record['helix_dirty'])
        self.assertEqual(record['python'],platform.python_version())
        self.assertEqual(record['models'],[])
        self.assertEqual(calls,[Path(environment.__file__).resolve().parents[1],self.base])
        for name in environment.STANDARD_TOOLS:
            self.assertEqual(record['tools'][name]['used'],name=='python')
            if name!='python':self.assertEqual(record['tools'][name]['status'],'not_used')
        self.assertNotIn('changed.txt',json.dumps(record))

    def test_git_failure_is_unknown_and_probe_environment_does_not_inherit_credentials(self):
        with patch.object(readonly,'git',side_effect=OSError('secret host unavailable')):
            record=environment.provenance(self.base)
        self.assertIsNone(record['target_head']);self.assertIsNone(record['target_dirty'])
        self.assertEqual(record['target_ref']['status'],'unknown')
        self.assertNotIn('secret host',json.dumps(record))
        with patch.dict(os.environ,{'API_TOKEN':'DO_NOT_RETAIN','HOME':'/private/credentials'}), \
             patch.object(environment.subprocess,'run') as execute:
            environment._run(['git','--no-optional-locks','status'])
        child=execute.call_args.kwargs['env']
        self.assertEqual(child['GIT_OPTIONAL_LOCKS'],'0')
        self.assertNotIn('API_TOKEN',child);self.assertNotIn('HOME',child)

    def test_tool_receipts_are_idempotent_and_drop_private_payloads_and_plans(self):
        raw={'gitleaks':{'version':'gitleaks 8.22.0','status':'PASS','argv':['SECRET'],
                         'stderr':'PRIVATE','env':{'TOKEN':'PRIVATE'}},
             'semgrep':{'status':'failed','used':True,'version':None},
             'trivy':{'status':'planned','version':'9.99.0'},
             'python':{'version':'3.10.2','status':'recorded','used':True}}
        records=environment.normalize_tools(raw)
        self.assertEqual(records['gitleaks']['version'],'8.22.0')
        self.assertEqual(records['semgrep']['status'],'unknown')
        self.assertTrue(records['semgrep']['used'])
        self.assertEqual(records['trivy']['status'],'not_used')
        self.assertIsNone(records['trivy']['version'])
        self.assertEqual(records['python']['version'],'3.10.2')
        self.assertEqual(environment.normalize_tools(records),records)
        self.assertNotIn('PRIVATE',json.dumps(records));self.assertNotIn('SECRET',json.dumps(records))
        self.assertEqual(environment.normalize_tools([dict(tool='node',status='PASS',version='v22.13.1')])['node']['version'],'22.13.1')

    def test_model_receipts_exclude_plans_and_keep_unknown_manual_model_explicit(self):
        raw=[dict(provider='gemini',model='gemini-observed',role='verifier',status='ok',prompt='PRIVATE'),
             dict(provider='codex',model='configured-model',status='planned'),
             dict(provider='claude',requested_model='requested-only'),
             dict(provider='claude',model='available-only',status='available'),
             dict(provider='grok',model='orchestrator',status='completed'),
             dict(provider='fallback',model='default',status='failed')]
        records=environment.normalize_models(raw)
        self.assertEqual({r['provider'] for r in records},{'gemini','grok','fallback'})
        self.assertEqual(records[0]['model'],'gemini-observed')
        self.assertTrue(all(r['model'] is None and r['status']=='unknown' for r in records[1:]))
        self.assertEqual(environment.normalize_models(records),records)
        self.assertNotIn('PRIVATE',json.dumps(records))
        self.assertEqual(environment.normalize_models({'gemini':{'model':'observed'}})[0]['model'],'observed')

    def test_runtime_collects_used_tool_versions_once_and_records_database_server(self):
        runner=self.runner();report=runner.run();runtime.validate_report(report)
        tools=report['provenance']['tools']
        for name in ('node','npm','podman','k6','lighthouse'):
            self.assertTrue(tools[name]['used']);self.assertEqual(tools[name]['version'],'1.2.3')
            calls=[c for c in runner.executor.calls if c[0]==[TOOLS[name],'--version']]
            self.assertEqual(len(calls),1,name)
            self.assertEqual(calls[0][1],runner.out)
            self.assertEqual(calls[0][2]['COREPACK_ENABLE_NETWORK'],'0')
            self.assertNotIn('DATABASE_URL',calls[0][2])
        for name in ('gitleaks','semgrep','trivy'):
            self.assertFalse(tools[name]['used']);self.assertEqual(tools[name]['status'],'not_used')
        self.assertEqual(tools['postgres-server']['version'],'16.4')
        self.assertEqual(tools['postgres-server']['scope'],'observed_running_server')
        self.assertEqual(report['provenance']['models'],[])
        count=len(runner.executor.calls);runner.collect_tool_versions()
        self.assertEqual(len(runner.executor.calls),count)
        self.assertEqual(json.loads((runner.out/'runtime-report.json').read_text())['provenance'],report['provenance'])

    def test_failed_metadata_probe_keeps_runtime_results_and_cleanup(self):
        runner=self.runner(FakeExecutor(fail=lambda argv:'--version' in argv));report=runner.run()
        self.assertTrue(all(c['status']=='PASS' for c in report['parts'][0]['checks'].values()))
        self.assertEqual(report['provenance']['tools']['node']['status'],'unknown')
        self.assertIsNone(report['provenance']['tools']['node']['version'])
        self.assertEqual(runner.executor.started,runner.executor.stopped)
        self.assertFalse(runner.tmp.exists())

    def test_exhausted_budget_does_not_probe_metadata_or_invent_versions(self):
        runner=self.runner();runner.note_tool([TOOLS['node'],'server.cjs'])
        runner.budget=runtime.Budget(1,clock=lambda:2)
        with patch.object(runner.budget,'remaining',side_effect=runtime.Blocked('budget exhausted')):
            runner.collect_tool_versions()
        self.assertEqual(runner.executor.calls,[])
        self.assertEqual(runner.execution_tools['node']['evidence_kind'],'version_not_probed_budget')
        self.assertIsNone(runner.execution_tools['node']['version'])

    def test_browser_package_metadata_and_missing_browser_version_are_separate(self):
        runner=self.runner();modules=self.base/'modules';(modules/'playwright').mkdir(parents=True)
        (modules/'playwright/package.json').write_text(json.dumps({'version':'1.50.2','private':'DO_NOT_RETAIN'}))
        runner.browser_module_dir=str(modules)
        runner.browser_metadata({'routes':[{'status':'PASS'}]})
        tools=environment.normalize_tools(runner.execution_tools)
        self.assertEqual(tools['playwright']['version'],'1.50.2')
        self.assertTrue(tools['chromium']['used']);self.assertIsNone(tools['chromium']['version'])
        self.assertEqual(tools['chromium']['status'],'unknown')
        self.assertEqual(runner.executor.calls,[])
        self.assertNotIn('DO_NOT_RETAIN',json.dumps(tools))

    def test_import_preserves_source_metadata_and_legacy_runtime_remains_accepted(self):
        runner=self.runner();report=runner.run()
        report['provenance']['python']='3.10.2'
        report['provenance']['tools']['python']['version']='3.10.2'
        path=runner.out/'runtime-report.json';path.write_text(json.dumps(report))
        maturity=helix_pro.assess(FIX/'sveltekit-pg','XL')
        imported=runtime.import_evidence(maturity,path,FIX/'sveltekit-pg')
        self.assertEqual(imported,report['provenance'])
        self.assertEqual(environment.normalize_tools(imported['tools'])['python']['version'],'3.10.2')
        legacy=copy.deepcopy(report);legacy.pop('provenance');runtime.validate_report(legacy)
        bad=copy.deepcopy(report);bad['provenance'].pop('tools')
        with self.assertRaises(ValueError):runtime.validate_report(bad)


if __name__=='__main__':unittest.main()
