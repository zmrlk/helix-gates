"""Provider-independent plans and strategy behavior, no external API or service pull."""
import copy
import json
import os
import runpy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_runtime as runtime
from helix_runtime_registry import load_registry,manifest_signals
from helix_runtime_integrations import inventory,execution_inventory
from helix_runtime_generic import compile_rules,Engine,start_containers


class GenericTests(unittest.TestCase):
    def project(self,files,config=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,text in files.items():
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
            return runtime.plan(root,config or {})

    def test_two_non_project_a_projects_detect_providers_and_strategies(self):
        django=self.project({'requirements.txt':'Django==5.1\ncelery==5.4\ndjango-celery-beat\nstripe\nboto3\n',
                             'manage.py':'from django.core.management import execute_from_command_line\n',
                             'jobs.py':'beat_schedule = {}\n'})
        node=self.project({'package.json':json.dumps({'scripts':{'start':'node server.js'},'dependencies':{'express':'1','paynow':'1','backblaze-b2':'1','bullmq':'1'}}),
                           'server.js':"require('express'); fetch('https://api.paynow.pl/v1/payments');"})
        for plan,expected in ((django,{'stripe':'http-sink','s3':'container','celery-beat':'disable'}),
                              (node,{'paynow':'http-sink','b2':'http-sink','bullmq-repeat':'disable','redis':'container'})):
            self.assertTrue(plan['parts'])
            rows={r['provider']:r for r in plan['integrations']['integrations']}
            for provider,strategy in expected.items():
                self.assertIn(provider,rows);self.assertEqual(rows[provider]['strategy']['selected'],strategy)
                self.assertEqual(rows[provider]['execution']['status'],'not_run')
                rules=compile_rules(plan['integrations'],rows[provider]['parts'][0],{})
                self.assertEqual(next(r for r in rules if r['provider']==provider)['strategy'],strategy)

    def test_registry_ecosystems_and_scheduler_files(self):
        registry=load_registry()
        for path,text in [('go.mod','require github.com/stripe/stripe-go/v81 v81.0.0'),('composer.json','{"require":{"stripe/stripe-php":"*"}}'),('Gemfile',"gem 'stripe'"),('pyproject.toml','dependencies = ["stripe>=1"]'),('package.json','{"dependencies":{"stripe":"1"}}')]:
            with self.subTest(path=path):self.assertIn('stripe',{r[0] for r in manifest_signals(path,text,registry)})
        plan=inventory({'crontab':'* * * * * command','job.timer':'[Timer]\nOnCalendar=daily','batch.yml':'kind: CronJob\n','tasks.py':'beat_schedule = {}'},[{'path':'.'}])
        self.assertTrue({'crontab','systemd-timer','k8s-cronjob','celery-beat'} <= {r['provider'] for r in plan['integrations']})
        for preset in registry['containers'].values():self.assertRegex(preset['image'],r'@sha256:[a-f0-9]{64}$')

    def test_custom_registry_isolated_and_unaccepted_proposal_stays_unknown(self):
        custom={'provider':'acme-api','family':'payments','packages':{'pypi':['acme-sdk']},'hosts':['api.acme.invalid'],'env_patterns':['^ACME_'],'default_strategy':'http-sink'}
        cfg={'runtime':{'integrations':{'custom':[custom]}}}
        sources={'requirements.txt':'acme-sdk','app.py':"import requests\nrequests.post('https://api.acme.invalid/pay')"}
        plan=inventory(sources,[{'path':'.','package_manager':'pip'}],cfg)
        self.assertEqual({r['provider'] for r in plan['integrations']},{'acme-api'})
        self.assertNotIn('acme-api',{r['provider'] for r in load_registry()['providers']})
        custom['accepted']=False
        unaccepted=inventory(sources,[{'path':'.'}],cfg)
        self.assertEqual({r['provider'] for r in unaccepted['integrations']},{'unknown-http'})
        self.assertNotEqual(plan['plan_id'],unaccepted['plan_id'])
        custom['accepted']=True;custom['provider']='stripe'
        with self.assertRaises(ValueError):load_registry(cfg)

    def test_blind_configured_replay_disabled_and_learning_share_engine(self):
        base={'provider':'acme','hosts':['api.acme.invalid'],'strategy':'http-sink'}
        req={'url':'https://api.acme.invalid/private/123?secret=VALUE','method':'POST','headers':{'authorization':'SECRET'},'body':{'amount':123,'token':'PRIVATE'}}
        engine=Engine([base]);self.assertEqual(engine.handle(req),{'status':200,'body':{}})
        self.assertEqual(engine.snapshot()['observations'][0]['outcome'],'zaślepione')
        base['response']={'status':201,'body':{'id':'synthetic'}};self.assertEqual(engine.handle(req)['status'],201)
        base['strategy']='record-replay';base['recordings']=[{'request':{k:req[k] for k in ('url','method','body')},'response':{'status':200,'body':{'ok':True}}}]
        self.assertEqual(engine.handle(req)['body'],{'ok':True})
        self.assertEqual(engine.handle(dict(req,body={}))['status'],502)
        base['strategy']='disable';self.assertEqual(engine.handle(req)['status'],503)
        unknown=Engine([],learning=True);self.assertEqual(unknown.handle(req)['status'],503)
        receipt=unknown.snapshot();raw=json.dumps(receipt)
        for value in ('VALUE','SECRET','PRIVATE','123','private'):self.assertNotIn(value,raw)
        row=receipt['observations'][0];self.assertFalse(row['proposal']['accepted'])
        self.assertEqual(row['shape']['path'],'/{segment}/{segment}')
        self.assertEqual(row['shape']['body_fields'],['amount','token'])
        self.assertEqual(receipt['coverage'],'not_checked')

    def test_response_and_replay_configuration_bind_plan(self):
        sources={'app.js':"fetch('https://api.stripe.com/v1/charges')"};parts=[{'path':'.','package_manager':'npm'}]
        cfg={'runtime':{'integrations':{'stripe':{'strategy':'http-sink','response':{'status':200,'body':{'secret':'PRIVATE'}}}}}}
        first=inventory(sources,parts,cfg)
        cfg['runtime']['integrations']['stripe']['response']['status']=201
        second=inventory(sources,parts,cfg)
        self.assertNotEqual(first['plan_id'],second['plan_id']);self.assertNotIn('PRIVATE',json.dumps(first))

    def test_configured_sink_does_not_gain_tested_coverage(self):
        plan=inventory({'app.js':"fetch('https://api.stripe.com/v1/charges')"},[{'path':'.','package_manager':'npm'}])
        report=execution_inventory(plan,[],run_id='unit')
        self.assertEqual(report['integrations'][0]['coverage']['status'],'not_checked')
        self.assertIn('nietestowane',' '.join(report['integrations'][0]['coverage']['untested_because']))

    def test_container_presets_use_cached_pinned_image_and_internal_network(self):
        calls=[];cleanups=[]
        def command(argv,**kwargs):
            calls.append(argv)
            return 'true' if '--format' in argv else ''
        runner=SimpleNamespace(tools={'docker':'docker'},command=command,port_factory=lambda:32123,network_connect_ports=set(),env={},cleanup_actions=cleanups)
        rules=[{'provider':name,'strategy':'container','container':spec} for name,spec in load_registry()['containers'].items()]
        results=start_containers(runner,rules)
        self.assertEqual([r['status'] for r in results],['RUNNING']*3)
        for argv in calls:
            if 'run' in argv:
                self.assertIn('--pull=never',argv);self.assertIn('--read-only',argv);self.assertIn('--cap-drop=ALL',argv)
            if 'create' in argv:self.assertIn('--internal',argv)
        self.assertEqual(len(cleanups),3)
        for action in cleanups:action()
        self.assertEqual(sum('rm' in a for a in calls),6)
        runner.tools={};self.assertTrue(all(r['status']=='BLOCKED' for r in start_containers(runner,rules)))

    def test_python_worker_path_is_not_named_worker(self):
        spec=self.project({'jobs/requirements.txt':'requests','jobs/main.py':'import requests'})
        self.assertEqual(spec['parts'][0]['path'],'jobs')
        self.assertEqual(spec['parts'][0]['framework'],'python-worker')

    def test_python_requests_hook_and_disabled_import_without_network(self):
        calls=[]
        class Session:
            headers={'Accept':'application/json'}
            def request(self,method,url,**kwargs):
                calls.append((method,url,kwargs));return 'captured'
        class Request:
            def __init__(self,method,url,params=None):self.url=url
            def prepare(self):return self
        fake=SimpleNamespace(Session=Session,Request=Request,sessions=SimpleNamespace(Session=Session))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json';path.write_text(json.dumps({'origin':'http://127.0.0.1:32123','token':'synthetic','own_origins':[],'disabled_modules':['fixture_disabled']}));path.chmod(0o600)
            before=list(sys.meta_path)
            try:
                with patch.dict(os.environ,{'HELIX_GENERIC_INPUT':str(path)}),patch.dict(sys.modules,{'requests':fake}):
                    runpy.run_path(str(ROOT/'bin/runtime-python/sitecustomize.py'))
                    self.assertEqual(Session().request('POST','https://api.acme.invalid/send',json={'amount':1}),'captured')
                    self.assertEqual(calls[0][1],'http://127.0.0.1:32123/capture')
                    self.assertEqual(json.loads(calls[0][2]['data'])['body'],{'amount':1})
                    self.assertFalse(calls[0][2]['allow_redirects'])
                    with self.assertRaisesRegex(ImportError,'DISABLED'):__import__('fixture_disabled')
            finally:sys.meta_path[:]=before

    @unittest.skipUnless(shutil.which('node'),'Node unavailable')
    def test_node_fetch_and_http_capture_share_endpoint_without_outbound_transport(self):
        program=r"""
const assert=require('node:assert/strict');const {install}=require(process.argv[1]);const calls=[];
const target={fetch:async(url,options)=>{assert.equal(url,'http://127.0.0.1:32123/capture');calls.push(JSON.parse(options.body));return new Response('{"ok":true}',{status:201});}};
const http={request:()=>{throw Error('outbound')},get:()=>{}};const https={...http};const module={_load:()=>{}};
const undo=install({origin:'http://127.0.0.1:32123',token:'test',own_origins:[],disabled_packages:['acme-sdk']},{target,http,https,module});
(async()=>{assert.equal((await target.fetch('https://api.acme.invalid/send',{method:'POST',body:JSON.stringify({x:1})})).status,201);
await new Promise((resolve,reject)=>{const req=https.request('https://api.acme.invalid/send',{method:'POST'},res=>{assert.equal(res.statusCode,201);res.on('data',()=>{});res.on('end',resolve)});req.on('error',reject);req.end('{"x":2}');});
assert.equal(calls.length,2);assert.deepEqual(calls.map(r=>r.body),[{x:1},{x:2}]);assert.throws(()=>module._load('acme-sdk/sub'),/DISABLED/);undo();})().catch(e=>{console.error(e);process.exitCode=1});
"""
        result=subprocess.run(['node','-e',program,str(ROOT/'bin/runtime-generic.cjs')],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()
