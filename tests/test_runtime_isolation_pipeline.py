import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime as rt
from helix_runtime_isolation import SeatbeltBackend
from test_runtime import FakeExecutor, SyntheticNetworkGuard, TOOLS, FIX


class ScopeDeniedGuard(SyntheticNetworkGuard):
    def __init__(self,scope='project'):
        super().__init__();self.denied_scope=scope
    def admit(self,policy,remaining):
        grant=super().admit(policy,remaining)
        if policy['scope']==self.denied_scope:
            grant.update(enforcement='blocked',proof_kind='none',backend='macos-seatbelt',reason_code='PROBE_DENIED')
        return grant


class RuntimeIsolationPipeline(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.executor=FakeExecutor()
    def runner(self,guard=None,**kwargs):
        self.current=rt.Runner(FIX/'sveltekit-pg',self.base/'out',executor=self.executor,tools={'tools':TOOLS},port_factory=lambda:31234,network_guard=guard,**kwargs)
        return self.current
    def run_pipeline(self,guard=None,**kwargs):return self.runner(guard,**kwargs).run()
    def prepare(self,guard=None):
        runner=self.runner(guard);runner.tmp=self.base/'private';runner.tmp.mkdir()
        runner.work=runner.tmp/'project';runner.work.mkdir()
        (runner.out/'logs').mkdir(parents=True);runner.env={'PATH':'/bin','HOME':str(runner.project_temporary()/'home')}
        return runner

    def test_all_project_phases_are_admitted_but_synthetic_proof_is_not_os_evidence(self):
        report=self.run_pipeline();projection=rt.project_network_isolation(report)
        self.assertEqual({r['phase'] for r in projection['records'] if r['command_invoked']},set(rt.ISOLATION_PHASES))
        self.assertEqual(projection['status'],'SIMULATED');self.assertEqual(projection['counts']['enforced'],0)
        self.assertEqual(report['status'],'INCOMPLETE')
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'PASS')
        self.assertEqual(report['parts'][0]['checks']['backup']['status'],'PASS')
        self.assertEqual(projection['coverage_status'],'INCOMPLETE')
        self.assertNotIn('profile_path',json.dumps(report['network_isolation']))
        rt.validate_report(report)

    def test_refused_project_scope_prevents_migrations_install_and_start(self):
        report=self.run_pipeline(ScopeDeniedGuard())
        projection=rt.project_network_isolation(report)
        self.assertEqual(projection['status'],'BLOCKED')
        self.assertGreater(projection['counts']['blocked'],0)
        self.assertGreater(projection['counts']['simulated'],0) # Owned synthetic server was started.
        self.assertEqual(self.executor.started,[])
        self.assertFalse(any('-f' in argv and 'migrations' in str(argv[-1]) for argv,*_ in self.executor.calls))
        self.assertFalse(any(argv[0].endswith('npm') and argv[1:]!=['--version'] for argv,*_ in self.executor.calls))
        self.assertNotEqual(report['status'],'PASS')

    def test_real_backend_does_not_attest_daemon_or_existing_service_server(self):
        class NoDaemonGuard(SyntheticNetworkGuard):synthetic_test=False
        for engine in ('docker','service'):
            with self.subTest(engine=engine):
                runner=self.prepare(NoDaemonGuard());runner.engine=engine
                with self.assertRaisesRegex(rt.Blocked,'unsupported'):runner.database()
                self.assertEqual(self.executor.calls,[])
                projection=rt.project_network_isolation({'network_isolation':rt.network_isolation_record(runner.network_records)})
                self.assertEqual(projection['status'],'BLOCKED');self.assertEqual(projection['counts']['invoked'],0)
                self.assertEqual(projection['records'][0]['reason_code'],'DATABASE_SERVER_UNSUPPORTED')
                shutil.rmtree(self.base/'private');shutil.rmtree(self.base/'out')

    def test_generated_policy_normalizes_without_network_or_broad_private_writes(self):
        runner=self.prepare();runner.database_network=dict(port=31234,data=runner.tmp/'pgdata',socket=runner.tmp/'pg-socket/.s.PGSQL.31234',log=runner.out/'logs/postgres.log')
        runner.database_network['data'].mkdir();runner.database_network['socket'].parent.mkdir()
        backend=SeatbeltBackend(runner.tmp/'network-control');backend._control()
        for phase in rt.ISOLATION_PHASES:
            with self.subTest(phase=phase):
                policy=runner.isolation_policy(phase)
                normalized=backend._normalize(policy)
                text=backend._compile(normalized)
                self.assertNotIn(str(runner.tmp),policy['writable_roots'])
                self.assertNotIn(str(runner.out),policy['writable_roots'])
                self.assertIn('(deny file-write* (subpath '+json.dumps(str(rt.HOME))+'))',text)
                self.assertNotIn('(deny file-read* file-write* (subpath '+json.dumps(str(rt.HOME))+'))',text)
                if phase=='database_server':
                    self.assertEqual(policy['connect_tcp'],[])
                    self.assertIn(str(runner.tmp/'pg-socket'),policy['writable_roots'])
                elif phase=='measurement':
                    self.assertIn(str(runner.out/'visual'),policy['writable_roots'])
                    self.assertEqual(policy['writable_files'],[str(runner.out/'logs/load-requests.jsonl')])

    def test_trusted_and_project_commands_drop_target_loaders_and_host_relays(self):
        runner=self.prepare();runner.env.update(NODE_OPTIONS='--require /malicious',PYTHONPATH='/malicious',BASH_ENV='/malicious',DYLD_INSERT_LIBRARIES='/malicious',LD_PRELOAD='/malicious',HTTP_PROXY='http://remote.invalid',SSH_AUTH_SOCK='/host/socket')
        before=dict(runner.env)
        runner.command(['/trusted','--version'],cleanup=True)
        runner.project_command(['/synthetic','build'],phase='build')
        for _,_,environment,_ in self.executor.calls:
            self.assertFalse(set(environment)&{'NODE_OPTIONS','PYTHONPATH','BASH_ENV','DYLD_INSERT_LIBRARIES','LD_PRELOAD','HTTP_PROXY','SSH_AUTH_SOCK'})
        self.assertEqual(runner.env,before)
        runner.owned_node_options='--require '+str(rt.HOME/'bin/runtime-fetch.cjs')
        runner.env['NODE_OPTIONS']=runner.owned_node_options
        runner.project_command(['/synthetic','build'],phase='build')
        self.assertEqual(self.executor.calls[-1][2]['NODE_OPTIONS'],runner.owned_node_options)

    def test_admission_only_does_not_claim_execution_and_mixed_refusal_stays_visible(self):
        runner=self.prepare();runner.admit_process('build',15)
        source={'network_isolation':rt.network_isolation_record(runner.network_records)};before=copy.deepcopy(source)
        result=rt.project_network_isolation(source)
        self.assertEqual(result['status'],'NOT_RUN');self.assertEqual(result['counts']['invoked'],0);self.assertEqual(source,before)
        row=dict(runner.network_records[0],enforcement='enforced',proof_kind='execution',backend='macos-seatbelt',reason_code='LOCAL_PROBE_PASSED',command_invoked=True)
        denied=dict(row,enforcement='blocked',proof_kind='none',reason_code='PROBE_DENIED',command_invoked=False)
        mixed={'network_isolation':rt.network_isolation_record([row,denied])}
        result=rt.project_network_isolation(mixed)
        self.assertEqual(result['status'],'BLOCKED');self.assertEqual(result['counts']['enforced'],1)
        self.assertEqual(result['coverage_status'],'INCOMPLETE')
        forged=copy.deepcopy(mixed);forged['network_isolation']['status']='ENFORCED'
        with self.assertRaises(ValueError):rt.project_network_isolation(forged)

    def test_spawn_checkpoint_failure_closes_only_its_own_process(self):
        runner=self.prepare()
        with patch.object(runner,'save_network_isolation',side_effect=[None,OSError('synthetic write failure')]):
            with self.assertRaises(OSError):runner.project_spawn(['/synthetic','start'],runner.work,runner.env,runner.out/'logs/app.log',phase='application')
        self.assertEqual(len(self.executor.started),1);self.assertEqual(self.executor.stopped,self.executor.started)

if __name__=='__main__':unittest.main()
