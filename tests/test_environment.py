"""Offline environment declarations, safe reads and fake local version probes."""
from datetime import datetime, timezone
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_environment as env


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.root=self.base/'app';self.root.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(env,'_run',return_value=subprocess.CompletedProcess([],1,'','')).start()
    def put(self,path,text):
        target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text);return target
    def report(self,**kw):return env.report(self.root,probe=False,**kw)
    def component(self,data,name):return next(c for c in data['components'] if c['name']==name)

    def test_all_declaration_sources_and_locations(self):
        self.put('frontend/package.json',json.dumps({'engines':{'node':'>= 22 <23'},'packageManager':'pnpm@9.12.0','devDependencies':{'@playwright/test':'1.48.2'}}))
        self.put('.nvmrc','22.11.0\n');self.put('.node-version','22.11.0\n');self.put('.python-version','3.12\n')
        self.put('.tool-versions','nodejs 22.11.0\npython 3.12.8\nnginx 1.26.2\n')
        self.put('mise.toml','[tools]\nnode = "22.11.0"\n')
        self.put('worker/pyproject.toml','[project]\nrequires-python = ">=3.12,<3.13"\n')
        self.put('Dockerfile','FROM node:22.11.0-alpine\nFROM nginx:1.26.2\n')
        self.put('compose.yaml','services:\n  db:\n    image: postgres:16.4\n')
        self.put('package-lock.json','{"lockfileVersion":3}')
        self.put('pnpm-lock.yaml',"lockfileVersion: '9.0'\n")
        self.put('yarn.lock','# yarn lockfile v1\n')
        data=self.report();names={c['name'] for c in data['components']}
        self.assertTrue({'node','python','pnpm','postgres','postgres-client','pg_ctl','nginx','playwright','chromium','package-lock-format','pnpm-lock-format','yarn-lock-format'}<=names)
        node=self.component(data,'node');self.assertGreaterEqual(len(node['declarations']),5)
        self.assertTrue(all(e['line']>0 and e['path'] for e in node['declarations']))
        self.assertEqual(self.component(data,'postgres')['production']['status'],'unknown')
        self.assertEqual(data['coverage']['status'],'COMPLETE')

    def test_conflicts_ranges_and_unsupported_selectors_are_explicit(self):
        self.put('.nvmrc','18.20.0');self.put('package.json','{"engines":{"node":">=22"}}')
        data=self.report();self.assertEqual(data['status'],'WARN')
        self.assertTrue(self.component(data,'node')['conflicts'])
        for constraint,local,incompatible in [('>=22.20.0','22.1.0',True),('1.50.0','1.51.0',True),('^0.2.3','0.9.0',True),('>=3.12.8','3.12.1',True),('>=18 <23','22.5.0',False)]:
            first=env._bounds(constraint,'node');actual=env._bounds(local,'node')
            self.assertIsNotNone(first)
            self.assertEqual(actual[0]<first[0] or actual[1]>first[1],incompatible)
        self.assertIsNone(env._bounds('22.0.0-rc.1','node'))
        self.put('.nvmrc','lts/*');self.put('package.json','{}')
        self.assertTrue(self.component(self.report(),'node')['unresolved'])

    def test_ci_multiline_include_matrix_and_separate_jobs(self):
        self.put('.nvmrc','20')
        self.put('.github/workflows/check.yml','''jobs:
  javascript:
    strategy:
      matrix:
        node:
          - '18'
          - '20'
        include:
          - node: '22'
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
  python:
    strategy:
      matrix:
        py: ['3.11', '3.12']
    services:
      db:
        image: postgres:16
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.py }}
''')
        data=self.report();node=self.component(data,'node')
        self.assertEqual({d['version'] for d in node['declarations'] if d['kind']=='ci_matrix'},{'18','20','22'})
        self.assertFalse(node['conflicts'])
        self.assertEqual({d['version'] for d in self.component(data,'python')['declarations']},{'3.11','3.12'})
        self.assertEqual(self.component(data,'postgres')['declarations'][0]['version'],'16')

    def test_environment_names_aliases_without_comments_or_values(self):
        self.put('.env','REAL_SECRET=DO_NOT_READ')
        self.put('.env.local','OTHER=DO_NOT_READ')
        self.put('.env.example','APP_TOKEN=SECRET_SAMPLE\nPUBLIC_URL=https://private.invalid\n')
        self.put('src/config.ts','''// process.env.COMMENTED
const message = "process.env.STRING_FALSE";
const templ = `process.env.TEMPLATE_FALSE ${process.env.ACTUAL_TEMPLATE}`;
import { APP_TOKEN as localToken, PUBLIC_URL } from '$env/static/private';
import { env as settings } from '$env/dynamic/private';
settings.DYNAMIC_TOKEN; settings['BRACKET_TOKEN'];
process.env.NODE_ENV; process.env['STATIC_TOKEN']; import.meta.env.VITE_URL;
const { SOURCE_KEY: renamed, SECOND_KEY = 'fallback' } = process.env;
''')
        self.put('worker/task.py','''# os.environ['PY_COMMENT']
from os import environ as configuration
import os as system
configuration['WORKER_TOKEN']
system.getenv('PY_URL')
os.environ.get('PY_KEY')
''')
        self.put('compose.yml','services:\n  app:\n    environment:\n      APP_TOKEN: PRIVATE_VALUE\n      - SECOND_KEY=OTHER_VALUE\n')
        original=env.safe_read;opened=[]
        def read(path,*args,**kw):
            opened.append(Path(path).name)
            self.assertNotIn(Path(path).name,('.env','.env.local'))
            return original(path,*args,**kw)
        with patch.object(env,'safe_read',side_effect=read):data=self.report()
        used=set(data['env_names']['used'])
        self.assertEqual(used,{'APP_TOKEN','PUBLIC_URL','DYNAMIC_TOKEN','BRACKET_TOKEN','NODE_ENV','STATIC_TOKEN','VITE_URL','SOURCE_KEY','SECOND_KEY','WORKER_TOKEN','PY_URL','PY_KEY','ACTUAL_TEMPLATE'})
        self.assertNotIn('APP_TOKEN',data['env_names']['missing_from_examples'])
        serialized=json.dumps(data)
        for secret in ('DO_NOT_READ','SECRET_SAMPLE','private.invalid','PRIVATE_VALUE','OTHER_VALUE','renamed','localToken'):self.assertNotIn(secret,serialized)
        self.assertFalse(data['env_names']['values_parsed']);self.assertFalse(data['env_names']['values_retained'])

    def test_full_read_large_file_and_explicit_symlink_gap(self):
        self.put('src/big.ts','// filler\n'*220000+'process.env.LAST_NAME;\n')
        external=self.base/'outside.ts';external.write_text('process.env.OUTSIDE_SECRET;')
        (self.root/'linked.ts').symlink_to(external)
        data=self.report()
        self.assertIn('LAST_NAME',data['env_names']['used']);self.assertNotIn('OUTSIDE_SECRET',data['env_names']['used'])
        self.assertGreater(data['coverage']['bytes_read'],2_000_000)
        self.assertEqual(data['status'],'INCOMPLETE')
        self.assertTrue(any(r['gap'] for r in data['coverage']['excluded']))
        alias=self.base/'alias';alias.symlink_to(self.root)
        with self.assertRaises(ValueError):env.report(alias,probe=False)

    def test_unreadable_and_empty_are_incomplete(self):
        self.assertEqual(self.report()['status'],'INCOMPLETE')
        self.put('package.json','{bad SECRET_LITERAL')
        data=self.report();self.assertEqual(data['status'],'INCOMPLETE');self.assertNotIn('SECRET_LITERAL',json.dumps(data))
        with patch.object(env,'safe_read',side_effect=OSError('sensitive detail')):
            data=self.report()
        self.assertEqual(data['status'],'INCOMPLETE');self.assertNotIn('sensitive detail',json.dumps(data))

    def test_local_tools_are_versions_not_running_service_claims(self):
        def run(command,cwd=None):
            versions={'postgres':'postgres (PostgreSQL) 16.4','psql':'psql (PostgreSQL) 14.12','pg_ctl':'pg_ctl (PostgreSQL) 16.4','nginx':'nginx version: nginx/1.26.2','playwright':'Version 1.48.2','chromium':'Chromium 130.0.6723.58'}
            return subprocess.CompletedProcess(command,0,versions[Path(command[0]).name],'')
        with patch.object(env.shutil,'which',side_effect=lambda name:'/fake/'+name),patch.object(env,'_run',side_effect=run):
            self.assertEqual(env.local_tool('postgres')['scope'],'server_binary_not_running_server')
            self.assertEqual(env.local_tool('postgres-client')['scope'],'client')
            self.assertEqual(env.local_tool('pg_ctl')['version'],'16.4')
            self.assertEqual(env.local_tool('chromium')['version'],'130.0.6723.58')
            self.assertEqual(env.local_tool('nginx')['version'],'1.26.2')
            self.assertEqual(env.local_tool('playwright')['version'],'1.48.2')

    def test_probe_process_environment_does_not_install_or_inherit_credentials(self):
        patch.stopall()
        with patch.dict(os.environ,{'PRIVATE_TOKEN':'do-not-copy'}),patch.object(env.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'v22.0.0','')) as run:
            env._run(['node','--version'])
        options=run.call_args.kwargs
        self.assertEqual(options['env']['COREPACK_ENABLE_NETWORK'],'0')
        self.assertEqual(options['env']['npm_config_offline'],'true')
        self.assertNotIn('PRIVATE_TOKEN',options['env']);self.assertNotIn('HOME',options['env'])
        self.assertNotIn('npx',str(run.call_args))

    def test_prod_requires_explicit_dated_exact_version_and_supports_g0(self):
        self.put('.nvmrc','22');proof=self.base/'proof.json';now=datetime.now(timezone.utc).isoformat()
        proof.write_text(json.dumps({'components':{'node':{'version':'20.11.0','checked_at':now,'evidence':'owner: verified log PRIVATE_VALUE'}}}))
        data=self.report(prod_evidence=proof);prod=self.component(data,'node')['production']
        self.assertEqual(prod['scope'],'owner provided; no remote readback');self.assertEqual(prod['checked_at'],now)
        self.assertTrue(any(c['kind']=='production_mismatch' for c in self.component(data,'node')['conflicts']))
        self.assertNotIn('PRIVATE_VALUE',json.dumps(data))
        for version,date in [('latest',now),('>=16',now),('22',''),('22','2026-01-01')]:
            proof.write_text(json.dumps({'components':{'node':{'version':version,'checked_at':date,'evidence':'owner'}}}))
            with self.subTest(version=version,date=date),self.assertRaises(ValueError):self.report(prod_evidence=proof)
        claim=dict(component='node',version='22.11.0',retrieved_at=now,evidence=['owner: local record'],tag='VERIFIED',source_status='FOUND')
        proof.write_text(json.dumps({'claims':[claim]}));self.assertEqual(self.component(self.report(prod_evidence=proof),'node')['production']['version'],'22.11.0')
        del claim['source_status'];proof.write_text(json.dumps({'claims':[claim]}))
        with self.assertRaises(ValueError):self.report(prod_evidence=proof)

    def test_migration_minimum_does_not_invent_default_database(self):
        self.put('migrations/001.sql','CREATE TABLE samples(id int);')
        self.put('package.json','{}')
        self.assertNotIn('postgres',{c['name'] for c in self.report()['components']})
        self.put('migrations/002.sql','MERGE INTO samples USING other ON true WHEN MATCHED THEN DO NOTHING;')
        declarations=self.component(self.report(),'postgres')['declarations']
        self.assertEqual(declarations[0]['version'],'>=15');self.assertEqual(declarations[0]['kind'],'migration_minimum')

    def test_existing_output_is_refused_before_creating_other_artifact(self):
        self.put('.nvmrc','22');out=self.base/'out';out.mkdir()
        (out/'environment.md').write_text('retain')
        args=argparse.Namespace(repo=str(self.root),out=str(out),json=True,no_probe=True,prod_evidence=None)
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(env.dispatch(args),3)
        self.assertEqual((out/'environment.md').read_text(),'retain');self.assertFalse((out/'environment.json').exists())

    def test_malformed_version_cannot_hold_up_audit(self):
        command=[sys.executable,'-B','-c',"import sys;sys.path.insert(0,sys.argv[1]);import helix_environment as e;assert e._version('1'*24+'!') is None",str(ROOT/'bin')]
        subprocess.run(command,check=True,timeout=2,capture_output=True,text=True)
        self.put('package.json',json.dumps({'engines':{'node':'1'*24+'!'}}))
        data=self.report();self.assertEqual(data['status'],'INCOMPLETE')
        self.assertNotIn('1'*24,json.dumps(data))

    def test_sibling_app_versions_are_not_false_global_conflicts(self):
        self.put('apps/one/package.json','{"engines":{"node":"18"}}')
        self.put('apps/two/package.json','{"engines":{"node":"22"}}')
        self.assertFalse(self.component(self.report(),'node')['conflicts'])

    def test_quoted_and_inline_compose_ci_names_do_not_parse_values(self):
        self.put('compose.yaml',"""services:
  first:
    environment: {FIRST_KEY: 'not,a,new_key:value', "SECOND_KEY": 'top-secret'}
  second:
    environment:
      - 'THIRD_KEY=hidden'
      - FOURTH_KEY
      "FIFTH_KEY": hidden
""")
        self.put('.github/workflows/ci.yml','env: ["SIXTH_KEY=secret", SEVENTH_KEY]\n')
        data=self.report()
        self.assertEqual(set(data['env_names']['declared']),{'FIRST_KEY','SECOND_KEY','THIRD_KEY','FOURTH_KEY','FIFTH_KEY','SIXTH_KEY','SEVENTH_KEY'})
        for value in ('top-secret','hidden','new_key'):self.assertNotIn(value,json.dumps(data))

    def test_report_marks_local_postgres_client_server_difference(self):
        self.put('compose.yml','services:\n  db:\n    image: postgres:16.4\n')
        def local(name):return dict(status='available',version='14.12' if name=='postgres-client' else '16.4',scope='client' if name=='postgres-client' else 'server_binary_not_running_server')
        with patch.object(env,'local_tool',side_effect=local):data=env.report(self.root,probe=True)
        client=self.component(data,'postgres-client')
        self.assertEqual(client['conflicts'][0]['kind'],'client_server_major_difference')
        self.assertEqual(data['status'],'WARN')

    def test_cached_chromium_is_probed_without_package_execution(self):
        cache=self.base/'Library/Caches/ms-playwright/chromium-999/chrome-mac/Chromium.app/Contents/MacOS'
        cache.mkdir(parents=True);(cache/'Chromium').write_text('fake executable')
        with patch.object(env.shutil,'which',return_value=None),patch.object(env.Path,'home',return_value=self.base),patch.object(env,'_run',return_value=subprocess.CompletedProcess([],0,'Chromium 130.0.6723.58','')) as run:
            observed=env.local_tool('chromium')
        self.assertEqual(observed['version'],'130.0.6723.58')
        self.assertEqual(run.call_args.args[0],[str(cache/'Chromium'),'--version'])
