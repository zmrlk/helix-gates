"""Synthetic host pressure and queue admission. No network, models or load generation."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_resources as R


def normal():
    return dict(platform='Linux',logical_cpus=8,load1=2,load_ratio=.25,
                memory_available_ratio=.5,memory_pressure='normal',confidence='recorded')


class Resources(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()

    def test_thresholds_requested_cap_and_unknown(self):
        cases=[({},'unknown',1),(normal(),'normal',8),
               (dict(normal(),load_ratio=1.5),'high',4),(dict(normal(),load_ratio=3),'critical',0),
               (dict(normal(),memory_available_ratio=.1),'high',4),
               (dict(normal(),memory_available_ratio=.049),'critical',0),
               (dict(normal(),psi_memory_full_avg10=10),'critical',0),
               (dict(normal(),memory_pressure='critical'),'critical',0)]
        for sample,state,jobs in cases:
            with self.subTest(state=state,sample=sample):
                decision=R.decide(sample,8)
                self.assertEqual((decision['state'],decision['effective_jobs']),(state,jobs))
                self.assertEqual(decision['requested_jobs'],8)
                self.assertEqual(decision['thresholds']['max_pause_s'],300)
        self.assertEqual(R.decide(dict(normal(),load_ratio=2),1)['effective_jobs'],1)
        self.assertEqual(R.decide(dict(normal(),load_ratio=2),8,{'high_load_ratio':2.5})['state'],'normal')

    def test_invalid_thresholds_or_jobs_fail_before_sampling(self):
        for policy in ({'unknown':1},{'max_pause_s':0},{'poll_s':float('nan')},{'high_load_ratio':4},
                       {'critical_memory_available_ratio':.3},{'critical_psi_full_avg10':101}):
            with self.subTest(policy=policy),self.assertRaises(ValueError):R.Governor(snapshot_fn=lambda:self.fail('sampled'),policy=policy)
        for jobs in (0,-1,True,1.5):
            with self.subTest(jobs=jobs),self.assertRaises(ValueError):R.decide(normal(),jobs)

    def test_linux_memavailable_psi_and_cgroup_limit_not_swap(self):
        files={'/proc/meminfo':'MemTotal: 10000 kB\nMemAvailable: 8000 kB\nSwapFree: 9999999 kB\n',
               '/proc/pressure/memory':'some avg10=1.25 avg60=0.0 total=1\nfull avg10=10.00 avg60=0.0 total=1\n',
               '/proc/self/cgroup':'0::/fixture\n','/sys/fs/cgroup/fixture/memory.max':'2048000',
               '/sys/fs/cgroup/fixture/memory.current':'2000000'}
        with patch.object(R.os,'cpu_count',return_value=8),patch.object(R.os,'getloadavg',return_value=(2,1,1)):
            sample=R.snapshot(platform_name='Linux',read_text=lambda p:files[p])
        self.assertEqual(sample['memory_total_bytes'],2048000)
        self.assertEqual(sample['memory_available_bytes'],48000)
        self.assertEqual(sample['psi_memory_full_avg10'],10)
        self.assertEqual(R.decide(sample,3)['state'],'critical')
        self.assertNotIn('SwapFree',json.dumps(sample))

    def test_linux_unavailable_memory_does_not_invent_zero(self):
        def missing(path):raise OSError('SECRET path unavailable')
        with patch.object(R.os,'cpu_count',return_value=4),patch.object(R.os,'getloadavg',side_effect=OSError('hidden')):
            sample=R.snapshot(platform_name='Linux',read_text=missing)
        for key in ('memory_available_bytes','memory_total_bytes','memory_available_ratio','load_ratio'):
            self.assertIsNone(sample[key])
        self.assertEqual(sample['confidence'],'unknown');self.assertEqual(R.decide(sample,4)['state'],'unknown')
        self.assertNotIn('SECRET',json.dumps(sample))

    def test_darwin_page_size_and_denied_sysctl_are_partial_not_fake_pressure(self):
        commands=[]
        for page_size in (4096,16384):
            def run(argv):
                commands.append(argv)
                return subprocess.CompletedProcess(argv,0,f'Mach Virtual Memory Statistics: (page size of {page_size} bytes)\nPages free: 1.\nPages inactive: 100.\n') if argv==['/usr/bin/vm_stat'] else subprocess.CompletedProcess(argv,1,'','EPERM SECRET')
            with patch.object(R.os,'cpu_count',return_value=10),patch.object(R.os,'getloadavg',return_value=(5,4,3)):
                sample=R.snapshot(platform_name='Darwin',run=run)
            self.assertEqual(sample['vm_stat']['free_bytes'],page_size)
            self.assertIsNone(sample['memory_available_ratio']);self.assertEqual(sample['memory_pressure'],'unknown')
            self.assertEqual(sample['confidence'],'partial');self.assertEqual(R.decide(sample,3)['state'],'normal')
        self.assertTrue(all(argv[0] in ('/usr/bin/vm_stat','/usr/sbin/sysctl') for argv in commands))
        self.assertNotIn('SECRET',json.dumps(sample))

    def test_darwin_system_pressure_is_used_when_available(self):
        def run(argv):
            value='4' if argv[-1]=='kern.memorystatus_vm_pressure_level' else '17179869184' if argv[-1]=='hw.memsize' else 'malformed'
            return subprocess.CompletedProcess(argv,0,value,'')
        with patch.object(R.os,'getloadavg',return_value=(0,0,0)):
            sample=R.snapshot(platform_name='Darwin',run=run)
        self.assertEqual(sample['memory_pressure'],'critical');self.assertEqual(R.decide(sample,3)['effective_jobs'],0)

    def test_probes_use_fixed_argv_and_do_not_inherit_credentials(self):
        with patch.object(R.subprocess,'run') as command:
            R._run(['/usr/bin/vm_stat'])
        self.assertEqual(command.call_args.kwargs['timeout'],1)
        self.assertEqual(set(command.call_args.kwargs['env']),{'PATH','LC_ALL'})

    def governor(self,sampler,**kwargs):
        gate=R.Governor(snapshot_fn=sampler,out=self.root,**kwargs)
        clock=[0.0];gate._clock=lambda:clock[0];gate._sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds)
        return gate,clock

    def test_pause_resumes_same_command_and_checks_budget_each_poll(self):
        samples=iter([dict(normal(),load_ratio=3),dict(normal(),load_ratio=3),normal()])
        gate,clock=self.governor(lambda:next(samples));checked=[]
        with contextlib.redirect_stderr(io.StringIO()):
            result=gate.wait(stop=lambda:checked.append(clock[0]))
        self.assertEqual(result['state'],'normal');self.assertEqual(checked,[0,5,10])
        self.assertEqual([d['state'] for d in gate.history],['critical','normal'])
        saved=json.loads(gate.current_path.read_text());self.assertEqual(saved['max_pause_s'],300)
        self.assertEqual(saved['state'],'normal')

    def test_pause_limit_preserves_evidence_and_budget_exception_is_not_swallowed(self):
        gate,clock=self.governor(lambda:dict(normal(),load_ratio=4),policy={'max_pause_s':10})
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(R.ResourcePaused) as caught:gate.wait()
        self.assertEqual(clock[0],10);self.assertEqual(caught.exception.decision['effective_jobs'],0)
        self.assertTrue((self.root/'resource-decisions.jsonl').is_file())
        class Exhausted(Exception):pass
        def stop():raise Exhausted()
        with self.assertRaises(Exhausted):gate.wait(stop=stop)
        with self.assertRaises(R.ResourcePaused):gate.wait(stop=lambda:-1)

    def test_history_and_messages_are_bounded_by_change_or_thirty_seconds_and_private_fields_drop(self):
        sample=dict(normal(),env={'TOKEN':'SECRET'},prompt='SECRET')
        gate,clock=self.governor(lambda:sample)
        with contextlib.redirect_stderr(io.StringIO()) as output:
            for tick in (0,1,5,29,30):clock[0]=tick;gate.decision()
        self.assertEqual(len(gate.history),2);self.assertEqual(len(output.getvalue().splitlines()),2)
        self.assertNotIn('SECRET',(self.root/'resource-decisions.jsonl').read_text())
        saved=gate.history;saved.clear();self.assertEqual(len(gate.history),2)

    def test_monitor_owns_only_its_thread_and_stops_on_exception(self):
        gate=R.Governor(snapshot_fn=normal,out=self.root,policy={'poll_s':.01,'sample_s':.01})
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(RuntimeError):
            with gate.monitor() as path:
                self.assertEqual(json.loads(path.read_text())['state'],'normal')
                raise RuntimeError('synthetic failure')
        import threading
        self.assertFalse(any(t.name=='helix-resource-monitor' for t in threading.enumerate()))

    def test_current_file_publication_is_not_repeated_for_fast_scheduler_polls(self):
        gate,clock=self.governor(normal)
        with patch.object(R,'_atomic',wraps=R._atomic) as publish,contextlib.redirect_stderr(io.StringIO()):
            for tick in (0,.1,.2,4.9,5):clock[0]=tick;gate.decision()
        self.assertEqual(publish.call_count,2)

    def test_output_parents_and_leaves_never_follow_links(self):
        target=self.root/'target';target.mkdir();(target/'keep').write_text('original')
        alias=self.root/'alias';alias.symlink_to(target,target_is_directory=True)
        for out in (alias,alias/'nested'):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises((OSError,ValueError)):
                R.Governor(snapshot_fn=normal,out=out).decision()
        out=self.root/'out';out.mkdir();(out/'resource-decisions.jsonl').symlink_to(target/'keep')
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises((OSError,ValueError)):
            R.Governor(snapshot_fn=normal,out=out).decision()
        self.assertEqual((target/'keep').read_text(),'original')
        self.assertEqual(list(target.iterdir()),[target/'keep'])

    def test_fifo_history_is_rejected_without_waiting_for_reader(self):
        import os
        if not hasattr(os,'mkfifo'):self.skipTest('FIFO unavailable')
        os.mkfifo(self.root/'resource-decisions.jsonl')
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises((OSError,ValueError)):
            R.Governor(snapshot_fn=normal,out=self.root).decision()

    @unittest.skipUnless(shutil.which('node'),'Node unavailable')
    def test_javascript_gate_critical_stale_and_healthy_queue(self):
        code='''
const assert=require('assert'),{createGate,ResourcePaused}=require(process.argv[1]);
const normal=(now,state='normal',jobs=2)=>({updated_at:new Date(now).toISOString(),state,effective_jobs:jobs,max_pause_s:.02,poll_s:.001,stale_after_s:.02});
(async()=>{
 let now=0, reads=0;
 const gate=createGate({requestedJobs:2,now:()=>now,sleep:async n=>{now+=n},readDecision:()=>normal(now,++reads<3?'critical':'normal',reads<3?0:2)});
 let ran=0;await gate.run(async()=>ran++);assert.equal(ran,1);assert(now>=2);
 now=0;const critical=createGate({now:()=>now,sleep:async n=>{now+=n},readDecision:()=>normal(now,'critical',0)});
 await assert.rejects(critical.run(async()=>assert.fail('must not start')),ResourcePaused);
 now=100;const stale=createGate({now:()=>now,sleep:async n=>{now+=n},readDecision:()=>normal(0),staleAfterMs:5,pollMs:1});
 await assert.rejects(stale.acquire(),ResourcePaused);
 now=0;let alternate=0;
 const unstable=createGate({now:()=>now,maxPauseMs:5,pollMs:1,sleep:async n=>{now+=n},readDecision:()=>++alternate%2?normal(now,'critical',0):null});
 await assert.rejects(unstable.acquire(),ResourcePaused);assert(now<=5);
 const privateGate=createGate({now:()=>now,readDecision:()=>({...normal(now),prompt:'SECRET',sample:{env:{token:'SECRET'}}})});
 assert(!JSON.stringify(privateGate.decision()).includes('SECRET'));
 now=0;let waits=0;
 const queue=createGate({requestedJobs:2,now:()=>now,maxPauseMs:2,pollMs:1,readDecision:()=>normal(now,'high',1),sleep:async n=>{now+=n;if(++waits===5)queue.release()}});
 await queue.acquire();await queue.acquire();assert(waits===5);assert.equal(queue.active,1);queue.release();assert.equal(queue.active,0);
 console.log('OK');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result=subprocess.run(['node','-e',code,str(ROOT/'bin/resources.cjs')],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'OK')


if __name__=='__main__':unittest.main()
