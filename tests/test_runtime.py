import copy
import hashlib
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
import helix_runtime as rt
import helix_new
import helix_pro
import yaml

FIX=ROOT/'tests/fixtures/runtime'
TOOLS={name:'/fake/'+name for name in ('podman','docker','initdb','pg_ctl','pg_dump','pg_restore','psql','pg_isready','node','npm','pnpm','yarn','k6','lighthouse')}

class SyntheticNetworkGuard:
    """Trusted fixture injection, explicitly not an OS isolation attestation."""
    synthetic_test=True
    def __init__(self,control_dir=None):self.policies=[];self.grants=[];self.wrapped=[]
    def admit(self,policy,remaining):
        self.policies.append(copy.deepcopy(policy))
        grant=dict(enforcement='simulated',proof_kind='synthetic_test',backend='synthetic-test',reason_code='SYNTHETIC_TEST',
                   policy_hash=hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest(),scope=policy['scope'])
        self.grants.append(grant);return grant
    def wrap(self,argv,grant):
        if not any(grant is item for item in self.grants):raise ValueError('unknown synthetic grant')
        self.wrapped.append(list(argv));return list(argv)

class FakeExecutor:
    @staticmethod
    def network_guard(control_dir):return SyntheticNetworkGuard(control_dir)
    @staticmethod
    def docker_endpoint(home):
        return dict(host='unix:///synthetic/docker.sock',kind='unix',source='test_fixture')
    @staticmethod
    def resource_snapshot():
        return dict(platform='Linux',logical_cpus=8,load1=1,load_ratio=.125,memory_pressure='normal',memory_available_ratio=.5,confidence='recorded')
    def __init__(self,fail=None,health_error=False):
        self.calls=[];self.started=[];self.stopped=[];self.fail=fail;self.health_error=health_error
    def run(self,argv,cwd,env,timeout):
        self.calls.append((argv,Path(cwd),dict(env),timeout))
        if self.fail and self.fail(argv):return 1,'synthetic command error'
        if argv[-1]=='SHOW server_version':return 0,'16.4\n'
        from helix_runtime_extensions import AVAILABLE_EXTENSIONS_SQL, COMMON_EXTENSIONS
        if argv[-1]==AVAILABLE_EXTENSIONS_SQL:return 0,json.dumps([dict(name=name,default_version='1.0',installed_version=None) for name in (*COMMON_EXTENSIONS,'vector','postgis')])
        if argv[-1]=='--version' and str(argv[0]).endswith('postgres'):return 0,'postgres (PostgreSQL) 16.4\n'
        if argv[-1]=='--version':return 0,Path(argv[0]).name+' 1.2.3\n'
        if '-f' in argv and str(argv[-1]).endswith('counts.sql'):
            return 0,json.dumps(dict(table='public.runtime_items',rows=1,checksum='a'*32))+'\n'
        if str(argv[0]).endswith('psql'):return 0,'public.runtime_items|1\n'
        if len(argv)>2 and argv[1]=='cp' and ':/' in argv[2]: Path(argv[3]).write_text('synthetic container dump')
        if str(argv[0]).endswith('pg_dump'):Path(argv[argv.index('--file')+1]).write_text('synthetic dump')
        if str(argv[0]).endswith('node') and any(str(x).endswith('runtime-browser.cjs') for x in argv):
            routes=[dict(type='route',route=route,status='PASS',reachable=True,errors=[],violations=[]) for route in json.loads(argv[5])]
            Path(argv[3]).write_text(json.dumps(dict(routes=routes,requests=[])))
            Path(str(argv[3])+'.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in routes))
        if str(argv[0]).endswith('lighthouse'):
            output=next(x.split('=',1)[1] for x in argv if x.startswith('--output-path='))
            Path(output).write_text(json.dumps({'audits':{name:{'numericValue':value} for name,value in [('largest-contentful-paint',1000),('cumulative-layout-shift',.01),('total-blocking-time',20)]},'categories':{'performance':{'score':.99}}}))
        if str(argv[0]).endswith('k6'):
            Path(argv[argv.index('--summary-export')+1]).write_text(json.dumps({'metrics':{'http_req_duration':{'p(95)':20},'http_req_failed':{'rate':0}}}))
        return 0,'synthetic command complete'
    def spawn(self,argv,cwd,env,log):
        oidc=(Path(cwd)/'server.cjs').is_file() and 'OIDC_ISSUER discovery' in (Path(cwd)/'server.cjs').read_text()
        log.write_text('OIDC_ISSUER discovery connection failed: ECONNREFUSED\n' if oidc else 'synthetic application started\n')
        self.oidc=oidc; obj=object();self.started.append(obj);return obj
    def stop(self,p):self.stopped.append(p)
    def health(self,url,timeout):
        if self.health_error or getattr(self,'oidc',False):raise rt.Blocked('HTTP healthcheck timeout')
        self.last_health=dict(state='http',status=200)

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def runner(self,fixture='sveltekit-pg',**kwargs):
        return rt.Runner(FIX/fixture,self.base/'out',executor=kwargs.pop('executor',FakeExecutor()),tools={'tools':TOOLS},port_factory=lambda:31234,**kwargs)
    def test_stop_kills_descendants_after_launcher_exits(self):
        from unittest.mock import Mock, call
        process=Mock(pid=12345)
        with patch.object(rt.os,'killpg') as kill:
            rt.Executor().stop(process)
        self.assertEqual(kill.call_args_list,[call(12345,rt.signal.SIGTERM),call(12345,rt.signal.SIGKILL)])

    def test_container_backup_uses_server_tools(self):
        runner=self.runner();report=runner.run()
        self.assertEqual(report['parts'][0]['checks']['backup']['status'],'PASS')
        self.assertGreater(report['parts'][0]['checks']['backup']['metrics']['dump_bytes'],0)
        commands=[c[0] for c in runner.executor.calls]
        dump=next(c for c in commands if 'pg_dump' in c)
        restore=next(c for c in commands if 'pg_restore' in c)
        self.assertEqual(dump[:3],restore[:3])
        self.assertEqual(dump[1],'exec')
        self.assertFalse(any(c[0].endswith('/pg_dump') or c[0].endswith('/pg_restore') for c in commands))

    def test_k6_summary_rate_formats(self):
        for failed in ({'value':0},{'values':{'rate':0}},{'value':.5},{'values':{'rate':.5}}):
            with self.subTest(failed=failed):
                executor=FakeExecutor();original=executor.run
                def run(argv,cwd,env,timeout):
                    result=original(argv,cwd,env,timeout)
                    if argv[0].endswith('k6') and '--version' not in argv:
                        Path(argv[argv.index('--summary-export')+1]).write_text(json.dumps({'metrics':{'http_req_duration':{'p(95)':20},'http_req_failed':failed}}))
                    return result
                executor.run=run
                runner=self.runner(executor=executor)
                report=runner.run()
                self.assertEqual(report['parts'][0]['checks']['load']['status'],'FAIL' if '0.5' in str(failed) else 'PASS')
                import shutil
                shutil.rmtree(self.base/'out')

    def test_report_controls_match_all_parts(self):
        report=self.runner().run()
        self.assertEqual({c['id'] for c in report['controls']},set(rt.CHECKS)|{'timezone-utc'})
        for control in report['controls']:
            self.assertEqual(control,dict(report['parts'][0]['checks'][control['id']],id=control['id'],part='.'))
        report['controls'][0]['status']='BLOCKED'
        with self.assertRaises(ValueError): rt.validate_report(report)

    def test_svelte_plan(self):
        plan=rt.plan(FIX/'sveltekit-pg');part=plan['parts'][0]
        self.assertEqual(part['framework'],'sveltekit');self.assertEqual(part['start'],['npm','run','start'])
        self.assertIn('/items',part['routes']);self.assertEqual(plan['migrations'][0]['kind'],'sql')
        self.assertEqual({e['name'] for e in plan['env']},{'DATABASE_URL','SESSION_SECRET'})
    def test_next_monorepo(self):
        plan=rt.plan(FIX/'next-pg');p=plan['parts'][0]
        self.assertEqual(p['path'],'apps/web');self.assertEqual(p['package_manager'],'pnpm');self.assertEqual(p['workspace'],'.')
        self.assertEqual(plan['migrations'][0]['path'],'packages/db/migrations/001_init.sql')
        self.assertIn('/items',p['routes'])
    def test_layouts_and_frameworks(self):
        for index,(dependency,framework) in enumerate(rt.FRAMEWORKS):
            with self.subTest(framework=framework):
                root=self.base/str(index);app=root/('frontend' if index%2 else 'apps/client');app.mkdir(parents=True)
                (app/'package.json').write_text(json.dumps({'dependencies':{dependency:'1'},'scripts':{'build':'builder','start':'server'}}))
                p=rt.plan(root)['parts'][0];self.assertEqual(p['framework'],framework);self.assertEqual(p['build'],['npm','run','build'])
    def test_python_detection(self):
        (self.base/'requirements.txt').write_text('fastapi\nuvicorn\n')
        (self.base/'main.py').write_text('from fastapi import FastAPI\napp=FastAPI()\nx=os.environ["DATABASE_URL"]')
        p=rt.plan(self.base);self.assertEqual(p['parts'][0]['start'][3],'main:app')
        self.assertIn('DATABASE_URL',[x['name'] for x in p['env']])
    def test_env_syntax(self):
        text='process.env.AAA; process.env["BBB"]; import.meta.env.CCC; import { DDD } from "$env/static/private"; env.EEE; os.environ["FFF"]; os.getenv("GGG"); os.environ.get("HHH")'
        self.assertEqual(rt.env_names(text),set('AAA BBB CCC DDD EEE FFF GGG HHH'.split()))
    def test_dummy_environment_no_secrets(self):
        (self.base/'.env').write_text('REAL_SECRET=private-real-value')
        (self.base/'.env.example').write_text('SESSION_SECRET=example-value\nAPI_URL=https://example.invalid\n')
        spec=rt.plan(self.base)
        with patch.dict(os.environ,{'PRIVATE_TOKEN':'private-real-value'}):env=rt.dummy_env(spec,'postgresql://helix@127.0.0.1:1234/helix',3000)
        self.assertNotIn('private-real-value',str(env));self.assertNotIn('example-value',str(env));self.assertNotIn('PRIVATE_TOKEN',env)
        self.assertTrue(env['API_URL'].startswith('http://127.0.0.1:'));self.assertGreaterEqual(len(env['SESSION_SECRET']),32)
    def test_oidc_blocked_by_runtime_startup(self):
        runner=self.runner('needs-oidc');report=runner.run()
        self.assertTrue(all(c['status']=='BLOCKED' and 'OIDC_ISSUER discovery connection failed' in c['reason'] for k,c in report['parts'][0]['checks'].items() if k not in ('backup','schema-apply')))
        self.assertTrue(runner.executor.calls); self.assertTrue(runner.executor.started)
        self.assertEqual(report['parts'][0]['checks']['backup']['status'],'PASS')
    def test_copy_exclusions(self):
        root=self.base/'src';root.mkdir()
        for name in ('.env','.env.local','.npmrc','credential.key'):(root/name).write_text('private')
        (root/'public.txt').write_text('public');(root/'.env.example').write_text('KEY=')
        (root/'node_modules').mkdir();(root/'node_modules/a').write_text('dependency')
        (root/'link').symlink_to(root/'public.txt')
        rt.copy_project(root,self.base/'copy')
        self.assertEqual({p.name for p in (self.base/'copy').iterdir()},{'public.txt','.env.example'})
    def test_full_fake_run_and_original_readonly(self):
        before={p.relative_to(FIX/'sveltekit-pg'):p.read_bytes() for p in rt.files(FIX/'sveltekit-pg')}
        runner=self.runner();report=runner.run()
        self.assertEqual([v['status'] for v in report['parts'][0]['checks'].values()],['PASS']*(len(rt.CHECKS)+1))
        self.assertFalse(runner.tmp.exists());self.assertEqual(runner.executor.started,runner.executor.stopped)
        self.assertEqual(before,{p.relative_to(FIX/'sveltekit-pg'):p.read_bytes() for p in rt.files(FIX/'sveltekit-pg')})
        for argv,cwd,environment,_ in runner.executor.calls:
            if cwd==runner.out:
                self.assertEqual(argv[1:],['--version'])
                self.assertNotIn('DATABASE_URL',environment)
                self.assertEqual(environment['COREPACK_ENABLE_NETWORK'],'0')
            else:self.assertTrue(cwd.is_relative_to(runner.tmp))
        self.assertTrue(any('rm' in call[0] for call in runner.executor.calls))
        migration=next(c for c in runner.executor.calls if '-f' in c[0] and c[0][-1].endswith('.sql') and 'migrations' in c[0][-1])
        self.assertIn(':31234/',migration[2]['DATABASE_URL'])
    def test_engine_fallback(self):
        runner=self.runner(executor=FakeExecutor(fail=lambda a:a[0].endswith('podman') and 'run' in a))
        report=runner.run();self.assertEqual(report['engine'],'docker')
        self.assertTrue(any(a[0][0].endswith('podman') and 'rm' in a[0] for a in runner.executor.calls))
    def test_native_engine(self):
        runner=self.runner(engine='native');self.assertEqual(runner.run()['engine'],'native')
        commands=[c[0] for c in runner.executor.calls]
        self.assertTrue(any(c[0].endswith('initdb') for c in commands));self.assertTrue(any('stop' in c for c in commands))
    def test_health_exception_cleanup(self):
        runner=self.runner(executor=FakeExecutor(health_error=True));report=runner.run()
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'BLOCKED')
        self.assertEqual(runner.executor.started,runner.executor.stopped);self.assertFalse(runner.tmp.exists())
    def test_unexpected_exception_cleanup(self):
        runner=self.runner()
        with patch.object(runner,'measure',side_effect=RuntimeError('unexpected')):
            with self.assertRaises(RuntimeError):runner.run()
        self.assertFalse(runner.tmp.exists());self.assertEqual(runner.executor.started,runner.executor.stopped)
    def test_keep(self):
        runner=self.runner(keep=True);report=runner.run()
        self.assertTrue(Path(report['kept_directory']).exists());self.assertEqual(runner.executor.stopped,[])
        import shutil;shutil.rmtree(runner.tmp)
    def test_budget(self):
        now=[0];budget=rt.Budget(10,clock=lambda:now[0]);self.assertEqual(budget.remaining(100),10)
        now[0]=8;self.assertEqual(budget.remaining(5),2)
        now[0]=11
        with self.assertRaises(rt.Blocked):budget.remaining(1)
    def test_step_timeouts_and_skip(self):
        runner=self.runner(skip=['load']);report=runner.run()
        self.assertEqual(report['parts'][0]['checks']['load']['status'],'SKIPPED')
        self.assertTrue(all(0<c[3]<=300 for c in runner.executor.calls))
    def test_route_review_can_be_skipped_explicitly(self):
        # Dokończenie pakietu UX projektu B bez ponownego 3-godzinnego przeglądu 128 tras.
        report=self.runner(skip=['route-review']).run();rt.validate_report(report)
        self.assertEqual((report['parts'][0]['legacy_audits']['status'],report['parts'][0]['legacy_audits']['reason']),('SKIPPED','explicit --skip'))
        with self.assertRaises(ValueError):self.runner(skip=['route-revue'])
    def test_schema_validation(self):
        report=self.runner().run();rt.validate_report(report)
        for mutate in (lambda r:r.update(schema_version=2),lambda r:r['parts'][0]['checks']['e2e'].update(status='UNKNOWN'),lambda r:r['parts'][0]['checks']['e2e'].update(log='../escape'),lambda r:r['parts'][0]['checks']['e2e'].update(metrics={})):
            bad=copy.deepcopy(report);mutate(bad)
            with self.assertRaises(ValueError):rt.validate_report(bad)
    def test_audit_mapping(self):
        runner=self.runner();runner.run();maturity=helix_pro.assess(FIX/'sveltekit-pg','XL')
        rt.import_evidence(maturity,self.base/'out/runtime-report.json',FIX/'sveltekit-pg')
        requirements={i['id']:i for a in maturity['areas'].values() for i in a['requirements']}
        for key in ('load','cwv','a11y','restore','ux-probes'):
            self.assertEqual(requirements[key]['status'],'PASS');self.assertTrue(requirements[key]['metrics'])
        self.assertEqual(requirements['consistency']['status'],'needs-runtime')
    def test_audit_rejects_wrong_project(self):
        self.runner().run()
        with self.assertRaises(ValueError):rt.import_evidence(helix_pro.assess(FIX/'sveltekit-pg'),self.base/'out/runtime-report.json',self.base)
    def test_ci_yaml(self):
        data=yaml.safe_load(rt.ci_template());self.assertIn('postgres',data['jobs']['runtime']['services'])
        self.assertTrue(any('--engine service' in step.get('run','') for step in data['jobs']['runtime']['steps']))
    def test_cli_without_project_pin(self):
        for args in (['runtime','plan','--project',str(FIX/'next-pg'),'--json'],['runtime','ci-template']):
            p=subprocess.run([str(ROOT/'bin/helix'),*args],cwd=self.base,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
    def test_300_migrations_bounded_markdown(self):
        root=self.base/'project';root.mkdir();directory=root/'db/migrations';directory.mkdir(parents=True)
        for i in range(300):(directory/f'{i:03d}.sql').write_text('CREATE TABLE synthetic (id int);\n')
        out=self.base/'audit';helix_new.audit(root,out,profile='S')
        report=json.loads((out/'audit.json').read_text());text=(out/'audit.md').read_text()
        requirements=[i for a in report['maturity']['areas'].values() for i in a['requirements']]
        evidence=next(i['evidence'] for i in requirements if len(i['evidence'])>=300)
        self.assertGreaterEqual(len(evidence),300);self.assertIn('300 paths:',text);self.assertIn('full list: audit.json/evidence',text)
        self.assertLessEqual(text.count('.sql:'),5)
    def test_profile_budgets(self):
        b=rt.profile_budgets({'profile':'XL','runtime':{'budgets':{'p95_ms':123}}})
        self.assertEqual(b['p95_ms'],123);self.assertEqual(b['vus'],8)

    def test_both_containers_fail_fallback_native(self):
        runner=self.runner(executor=FakeExecutor(fail=lambda a:a[0].endswith(('podman','docker')) and 'run' in a))
        self.assertEqual(runner.run()['engine'],'native')
        self.assertEqual(sum('rm' in c[0] for c in runner.executor.calls),2)
    def test_install_fallback(self):
        root=self.base/'project';root.mkdir()
        (root/'package.json').write_text(json.dumps({'scripts':{'start':'node server.js'}}))
        (root/'package-lock.json').write_text('{}')
        executor=FakeExecutor(fail=lambda a:'ci' in a)
        runner=rt.Runner(root,self.base/'out',executor=executor,tools={'tools':TOOLS},port_factory=lambda:31234)
        runner.run()
        self.assertTrue(any('ci' in c[0] for c in executor.calls));self.assertTrue(any('install' in c[0] for c in executor.calls))
    def test_load_threshold_failure_is_fail(self):
        executor=FakeExecutor();original=executor.run
        def fail_load(argv,cwd,env,timeout):
            result=original(argv,cwd,env,timeout)
            if argv[0].endswith('k6') and '--version' not in argv:
                Path(argv[argv.index('--summary-export')+1]).write_text(json.dumps({'metrics':{'http_req_duration':{'p(95)':9000},'http_req_failed':{'rate':.5}}}))
                return 99,'thresholds failed'
            return result
        executor.run=fail_load
        report=self.runner(executor=executor).run()
        self.assertEqual(report['parts'][0]['checks']['load']['status'],'FAIL')
        self.assertEqual(report['status'],'FAIL')
    def test_browser_assertions_failure_is_fail(self):
        executor=FakeExecutor();original=executor.run
        def bad_browser(argv,cwd,env,timeout):
            result=original(argv,cwd,env,timeout)
            if argv[0].endswith('node') and 'runtime-browser.cjs' in argv[1]:
                rows=[dict(type='route',route=route,status='FAIL',reachable=False,errors=['HTTP 500'],violations=[]) for route in json.loads(argv[5])]
                Path(argv[3]).write_text(json.dumps(dict(routes=rows,requests=[])))
                Path(str(argv[3])+'.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return result
        executor.run=bad_browser
        report=self.runner(executor=executor).run()
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'FAIL')
        self.assertEqual(report['parts'][0]['checks']['a11y']['status'],'FAIL')
    def test_expired_runner_budget_never_runs_command(self):
        runner=self.runner();runner.budget.end=0
        report=runner.run()
        self.assertEqual(report['parts'][0]['checks']['load']['status'],'BLOCKED');self.assertEqual(runner.executor.calls,[])
        self.assertFalse(runner.tmp.exists())
    def test_missing_evidence_log_rejected(self):
        runner=self.runner();report=runner.run();(self.base/'out'/report['parts'][0]['checks']['e2e']['log']).unlink()
        with self.assertRaises(ValueError):rt.import_evidence(helix_pro.assess(FIX/'sveltekit-pg','XL'),self.base/'out/runtime-report.json',FIX/'sveltekit-pg')
    def test_part_specific_external_requirement(self):
        root=self.base/'project'
        for name in ('apps/public','apps/identity'):
            app=root/name;app.mkdir(parents=True);(app/'package.json').write_text(json.dumps({'dependencies':{'express':'1'},'scripts':{'start':'node app.js'}}))
        (root/'apps/identity/app.js').write_text('const issuer=process.env.OIDC_ISSUER;')
        runner=rt.Runner(root,self.base/'out',part='apps/public',executor=FakeExecutor(),tools={'tools':TOOLS},port_factory=lambda:31234)
        report=runner.run();self.assertEqual(len(report['parts']),1);self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'PASS')
    def test_seeds_never_copied_from_real_env(self):
        (self.base/'seed.sql').write_text("INSERT INTO users VALUES ('synthetic');")
        spec=rt.plan(self.base);self.assertEqual(spec['seeds'][0]['status'],'SYNTHETIC')
        self.assertEqual(spec['migrations'],[])
    def test_report_json_schema_matches_generated_output(self):
        report=self.runner().run()
        try: import jsonschema
        except ImportError:
            rt.validate_report(report)
        else: jsonschema.validate(report,json.loads((ROOT/'schemas/runtime-report.json').read_text()))
    def test_safe_database_aliases(self):
        names=['DB_HOST','DB_PORT','DB_USER','DB_PASSWORD','DB_NAME','POSTGRES_USER','POSTGRES_DB']
        env=rt.dummy_env({'env':[dict(name=n,classification=rt.classification(n)) for n in names]},'postgresql://helix@127.0.0.1:5555/helix',3333)
        self.assertEqual(env['DB_HOST'],'127.0.0.1');self.assertEqual(env['DB_PORT'],'5555');self.assertEqual(env['POSTGRES_USER'],'helix')

    def test_service_database_has_unique_owned_name(self):
        runner=self.runner(engine='service');report=runner.run()
        self.assertEqual(report['engine'],'service')
        calls=[a for a,_,_,_ in runner.executor.calls]
        create=next(a[-1] for a in calls if a[-1].startswith('CREATE DATABASE helix_rt_'))
        name=create.split()[-1]
        self.assertTrue(any(a[-1]=='DROP DATABASE '+name+' WITH (FORCE)' for a in calls))
        self.assertFalse(any(a[-1]=='DROP DATABASE helix WITH (FORCE)' for a in calls))
    def test_failed_service_create_never_drops_existing_database(self):
        runner=self.runner(engine='service',executor=FakeExecutor(fail=lambda a:a[-1].startswith('CREATE DATABASE')))
        report=runner.run()
        self.assertEqual(report['status'],'BLOCKED')
        self.assertFalse(any('DROP DATABASE' in a[-1] for a,_,_,_ in runner.executor.calls))

    def test_sql_migration_external_connection_is_blocked(self):
        root=self.base/'project';root.mkdir();(root/'package.json').write_text(json.dumps({'scripts':{'start':'node server.cjs'}}))
        migrations=root/'db/migrations';migrations.mkdir(parents=True)
        (migrations/'001.sql').write_text('\\connect postgresql://outside.invalid/database\n')
        executor=FakeExecutor();runner=rt.Runner(root,self.base/'out',executor=executor,tools={'tools':TOOLS},port_factory=lambda:31234)
        report=runner.run()
        self.assertEqual(report['status'],'FAIL')
        self.assertIn('external connection',report['parts'][0]['checks']['schema-apply']['reason'])
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'PASS')
        self.assertFalse(any('-f' in a and a[-1].endswith('001.sql') for a,_,_,_ in executor.calls))


    def test_split_db_dummy_integrations_pass(self):
        spec=rt.plan(FIX/'monorepo-split-db'); part=spec['parts'][0]
        self.assertEqual(part['path'],'frontend')
        self.assertEqual(part['migrations'][0]['path'],'database/migrations/001_init.sql')
        runner=self.runner('monorepo-split-db'); report=runner.run()
        self.assertTrue(all(c['status']=='PASS' for c in report['parts'][0]['checks'].values()))
        migration=next(c for c in runner.executor.calls if '-f' in c[0] and 'database/migrations' in c[0][-1])
        self.assertEqual(migration[2]['SMTP_HOST'],'127.0.0.1')
        self.assertEqual(migration[2]['S3_ENDPOINT'],'http://127.0.0.1:1')
        self.assertNotIn('external-required',str(spec))

    def test_sdk_env_is_advisory(self):
        names='AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY S3_ENDPOINT GCS_ENDPOINT AZURE_STORAGE_CONNECTION_STRING SMTP_HOST SMTP_PORT STRIPE_SECRET_KEY SENTRY_DSN ANALYTICS_URL OAUTH_CLIENT_ID OAUTH_CLIENT_SECRET WEBHOOK_URL API_KEY OIDC_ISSUER'.split()
        spec={'env':[dict(name=n,classification=rt.classification(n)) for n in names]}
        env=rt.dummy_env(spec,'postgresql://helix@127.0.0.1:5432/helix',3000)
        self.assertEqual(env['OIDC_ISSUER'],'http://127.0.0.1:1')
        self.assertEqual(env['SENTRY_DSN'],'http://dummy@127.0.0.1:1/1')
        self.assertEqual(env['SMTP_PORT'],'1')
        self.assertEqual(env['AWS_EC2_METADATA_DISABLED'],'true')
        self.assertTrue(all(env[n] for n in names))

    def test_backup_survives_build_and_install_failures(self):
        for failed in ('install','build'):
            with self.subTest(failed=failed):
                runner=self.runner(executor=FakeExecutor(fail=lambda a:failed in a))
                report=runner.run();checks=report['parts'][0]['checks']
                self.assertEqual(checks['backup']['status'],'PASS')
                self.assertEqual(checks['e2e']['status'],'BLOCKED')
                import shutil;shutil.rmtree(self.base/'out')

    def test_sql_failure_rolls_back_and_continues(self):
        root=self.base/'project'; app=root/'frontend';app.mkdir(parents=True)
        (app/'package.json').write_text(json.dumps({'scripts':{'start':'node server.cjs'}}))
        migrations=root/'database/migrations';migrations.mkdir(parents=True)
        (migrations/'001.sql').write_text('CREATE TABLE fails (id invalid_synthetic_type);')
        (migrations/'002.sql').write_text('CREATE TABLE synthetic (id int);')
        executor=FakeExecutor();original=executor.run
        def run(argv,cwd,env,timeout):
            if '-f' in argv and argv[-1].endswith('001.sql'):
                executor.calls.append((argv,Path(cwd),dict(env),timeout))
                return 1,'ERROR: type "invalid_synthetic_type" does not exist'
            return original(argv,cwd,env,timeout)
        executor.run=run
        runner=rt.Runner(root,self.base/'out',executor=executor,tools={'tools':TOOLS},port_factory=lambda:31234)
        report=runner.run();part=report['parts'][0]
        self.assertEqual(part['checks']['backup']['status'],'PASS')
        self.assertEqual(len(part['database']['limitations']),1)
        self.assertTrue(any('-f' in a and a[-1].endswith('002.sql') for a,_,_,_ in executor.calls))
        self.assertTrue(all('--single-transaction' in a for a,_,_,_ in executor.calls if '-f' in a and 'migrations' in a[-1]))
        self.assertIn('Migracja pominięta', (self.base/'out/runtime.md').read_text())

    def test_seed_safety_and_execution(self):
        root=self.base/'project';root.mkdir()
        (root/'package.json').write_text(json.dumps({'scripts':{'start':'node server.cjs'}}))
        (root/'seed.sql').write_text("INSERT INTO users VALUES ('fixture@example.test');")
        runner=rt.Runner(root,self.base/'out',executor=FakeExecutor(),tools={'tools':TOOLS},port_factory=lambda:31234)
        runner.run()
        self.assertTrue(any('-f' in a and a[-1].endswith('seed.sql') for a,_,_,_ in runner.executor.calls))
        for text in ("INSERT INTO users VALUES ('person@real.example');", "INSERT INTO users VALUES ('+48 123 456 789');", "INSERT INTO users VALUES ('12345678901');", "INSERT INTO users VALUES ('1234567890');", 'x'*100001, "INSERT INTO users SELECT pg_read_file('/secret');"):
            with self.subTest(text=text[:60]): self.assertFalse(rt.synthetic_sql(text))
        self.assertTrue(rt.synthetic_sql("INSERT INTO users VALUES ('fixture@example.test');"))

    def test_db_association_excludes_other_app(self):
        for name in ('apps/a','apps/b'):
            app=self.base/name; (app/'db/migrations').mkdir(parents=True)
            (app/'package.json').write_text(json.dumps({'scripts':{'start':'node server.cjs'}}))
            (app/'db/migrations/001.sql').write_text('CREATE TABLE synthetic(id int);')
        (self.base/'database').mkdir();(self.base/'database/schema.sql').write_text('CREATE TABLE shared(id int);')
        spec=rt.plan(self.base)
        for part in spec['parts']:
            self.assertTrue(all(not m['path'].startswith('apps/b' if part['path']=='apps/a' else 'apps/a') for m in part['migrations']))


    def test_public_login_health_fallback(self):
        runner=self.runner();spec=rt.plan(runner.project);spec['parts'][0]['routes']=['/','/login']
        attempts=[]
        def health(url,timeout):
            attempts.append(url)
            if url.endswith('/login'): return url
            raise rt.Blocked('external identity redirect')
        runner.executor.health=health
        with patch.object(rt,'plan',return_value=spec): report=runner.run()
        self.assertTrue(report['parts'][0]['startup']['url'].endswith('/login'))
        self.assertEqual(report['parts'][0]['checks']['e2e']['status'],'PASS')
        self.assertIn('not covered',report['parts'][0]['coverage'])

    def test_migration_natural_order(self):
        self.assertEqual(sorted(['db/10.sql','db/2.sql','db/1.sql'],key=rt.migration_order),['db/1.sql','db/2.sql','db/10.sql'])

    def test_root_app_does_not_borrow_nested_app_database(self):
        for directory in (self.base,self.base/'apps/other'):
            directory.mkdir(parents=True,exist_ok=True)
            (directory/'package.json').write_text(json.dumps({'scripts':{'start':'node app.js'}}))
        db=self.base/'apps/other/db/migrations';db.mkdir(parents=True)
        (db/'001.sql').write_text('CREATE TABLE synthetic(id int);')
        root=next(p for p in rt.plan(self.base)['parts'] if p['path']=='.')
        self.assertEqual(root['migrations'],[])


    def test_schema_fallback_is_local_to_database_source(self):
        for name in ('migrations','packages/db/migrations'):
            directory=self.base/name;directory.mkdir(parents=True)
            (directory/'001.sql').write_text('CREATE TABLE synthetic(id int);')
            (directory.parent/'schema.sql').write_text('CREATE TABLE synthetic(id int);')
        migrations=rt.plan(self.base)['migrations']
        self.assertEqual(len(migrations),2)
        self.assertTrue(all(m['path'].endswith('001.sql') for m in migrations))

    def test_runtime_migration_limitations_are_bounded_in_markdown(self):
        runner=self.runner();original=runner.migrate
        def migrate(spec,seed=True,**kwargs):
            original(spec,seed=seed,**kwargs)
            if not runner.migration_notes:
                runner.migration_notes.extend(dict(path=f'database/migrations/{i}.sql',reason='unavailable extension',log='logs/001.log') for i in range(300))
        runner.migrate=migrate;report=runner.run()
        text=(self.base/'out/runtime.md').read_text()
        self.assertEqual(len(report['parts'][0]['database']['limitations']),300)
        self.assertEqual(text.count('Migracja pominięta:'),5)
        self.assertIn('Ograniczenia migracji: 300',text)

    def test_transaction_wrappers_cannot_commit_partial_files(self):
        sql="-- wrapper\nBEGIN;\nCREATE TABLE synthetic(id int);\nCOMMIT;\nSELECT 'BEGIN; COMMIT;';\nDO $$ BEGIN RAISE NOTICE 'COMMIT;'; END $$;"
        normalized=rt.transactional_sql(sql)
        self.assertNotIn('-- wrapper',normalized)
        self.assertIn("SELECT 'BEGIN; COMMIT;';",normalized)
        self.assertIn("DO $$ BEGIN RAISE NOTICE 'COMMIT;'; END $$;",normalized)
        self.assertEqual(normalized.count('COMMIT;'),2)
        self.assertIn('CREATE TABLE synthetic',normalized)

    def test_audit_cli_error_contains_validation_message(self):
        out=self.base/'audit';out.mkdir();(out/'audit.json').write_text('{}')
        result=subprocess.run([sys.executable,str(ROOT/'bin/helix'),'new','audit','--repo',str(FIX/'sveltekit-pg'),'--out',str(out)],capture_output=True,text=True)
        self.assertEqual(result.returncode,3)
        error=json.loads(result.stdout)
        self.assertEqual(error['error'],'ValueError')
        self.assertIn('existing artifacts: audit.json',error['reason'])

    def test_partial_schema_continues_and_archive_is_excluded(self):
        executor=FakeExecutor(fail=lambda a: '-f' in a and a[-1].endswith('002_failure.sql'))
        runner=self.runner('monorepo-split-db',executor=executor)
        report=runner.run(); part=report['parts'][0]
        check=part['checks']['schema-apply']
        self.assertEqual(check['status'],'FAIL')
        self.assertEqual({k:check['metrics'][k] for k in ('applied','failed','selected')},dict(applied=2,failed=1,selected=3))
        self.assertIn('synthetic command error',check['reason'])
        self.assertEqual(part['checks']['e2e']['status'],'PASS')
        self.assertTrue(executor.started)
        files=[a[-1] for a,_,_,_ in executor.calls if '-f' in a]
        self.assertTrue(any(x.endswith('010_after.sql') for x in files))
        self.assertFalse(any('/archive/' in x for x in files))
        self.assertEqual(len(part['database']['migrations']),3)
        self.assertEqual(part['database']['selection']['count'],3)

    def test_backup_command_failure_is_fail(self):
        executor=FakeExecutor(fail=lambda a: 'pg_dump' in a)
        check=self.runner(executor=executor).run()['parts'][0]['checks']['backup']
        self.assertEqual(check['status'],'FAIL')
        self.assertFalse(check['metrics']['verification_completed'])

    def test_old_v1_report_without_schema_control_remains_readable(self):
        report=self.runner().run()
        for part in report['parts']: del part['checks']['schema-apply']
        report['controls']=[c for c in report['controls'] if c['id']!='schema-apply']
        rt.validate_report(report)

    def test_empty_backup_fails_with_schema_context(self):
        executor=FakeExecutor(); original=executor.run
        def run(argv,cwd,env,timeout):
            if '-f' in argv and argv[-1].endswith('counts.sql'): return 0,''
            return original(argv,cwd,env,timeout)
        executor.run=run
        part=self.runner(executor=executor).run()['parts'][0]
        self.assertEqual(part['checks']['backup']['status'],'FAIL')
        self.assertEqual(part['checks']['backup']['metrics']['tables'],0)
        self.assertIn('schema-apply',part['checks']['backup']['metrics']['cause'])

    def test_incremental_chain_uses_baseline_and_excludes_obsolete_dirs(self):
        root=self.base/'project'; (root/'database/schema').mkdir(parents=True)
        (root/'database/migrations').mkdir()
        (root/'database/schema/001.sql').write_text('CREATE TABLE synthetic(id int);')
        (root/'database/migrations/1.sql').write_text('SELECT 1; -- superseded by baseline')
        (root/'database/migrations/2.sql').write_text('ALTER TABLE synthetic ADD COLUMN label text;')
        (root/'database/migrations/10.sql').write_text('SELECT 1;')
        for name in ('archive','archived','old','legacy','deprecated','backup','_unused','examples'):
            path=root/'database'/name;path.mkdir();(path/'migration.sql').write_text('BROKEN;')
        self.assertEqual([m['path'] for m in rt.plan(root)['migrations']],['database/schema/001.sql','database/migrations/1.sql','database/migrations/2.sql','database/migrations/10.sql'])

    def test_audit_can_share_output_with_runtime_and_state(self):
        out=self.base/'audit';(out/'rt').mkdir(parents=True);(out/'state').mkdir()
        runner=rt.Runner(FIX/'sveltekit-pg',out/'rt/result',executor=FakeExecutor(),tools={'tools':TOOLS},port_factory=lambda:31234)
        runner.run()
        marker=out/'rt/keep.txt';marker.write_text('preserve')
        result=subprocess.run([sys.executable,str(ROOT/'bin/helix'),'--state-dir',str(out/'state'),'new','audit','--repo',str(FIX/'sveltekit-pg'),'--out',str(out),'--runtime-report',str(out/'rt/result/runtime-report.json')],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertTrue((out/'audit.json').is_file())
        self.assertEqual(marker.read_text(),'preserve')
        with self.assertRaisesRegex(ValueError,'existing artifacts:'):
            helix_new.audit(FIX/'sveltekit-pg',out)

class RoundFourTests(unittest.TestCase):
    setUp=RuntimeTests.setUp
    tearDown=RuntimeTests.tearDown
    runner=RuntimeTests.runner
    def test_baseline_dependencies_seed_names_and_no_cutoff(self):
        root=self.base/'project'
        for directory in ('schema','migrations'): (root/'db'/directory).mkdir(parents=True)
        contents={
            'schema/012_initial.sql':'CREATE TABLE accounts(id int primary key);',
            'schema/008_seed_roles.sql':"INSERT INTO roles VALUES (1);",
            'migrations/002.sql':'ALTER TABLE accounts ADD COLUMN label text; CREATE TABLE sessions(id int, account_id int REFERENCES accounts(id));',
            'migrations/003_seed.sql':'ALTER TABLE sessions ADD COLUMN active boolean;',
        }
        for name,sql in contents.items(): (root/'db'/name).write_text(sql)
        spec=rt.plan(root)
        self.assertEqual(len(spec['migrations']),4)
        self.assertEqual(spec['seeds'],[])
        self.assertTrue(spec['migrations'][0]['path'].startswith('db/schema/'))
        self.assertFalse(rt.initial_sql(contents['migrations/002.sql']))
        self.assertTrue(rt.initial_sql('CREATE TABLE accounts(id int); CREATE TABLE sessions(id int REFERENCES accounts(id));'))

    def test_later_dependency_requires_baseline_despite_initial_create(self):
        root=self.base/'project'
        for directory in ('schema','migrations'): (root/'db'/directory).mkdir(parents=True)
        (root/'db/schema/020.sql').write_text('CREATE TABLE "public"."accounts"(id int);')
        (root/'db/migrations/001.sql').write_text('CREATE TABLE sessions(id int);')
        (root/'db/migrations/002.sql').write_text('ALTER TABLE "accounts" ADD COLUMN active boolean;')
        self.assertEqual([m['path'] for m in rt.plan(root)['migrations']],['db/schema/020.sql','db/migrations/001.sql','db/migrations/002.sql'])

    def test_seed_named_ddl_outside_chain_is_schema(self):
        (self.base/'seed_structure.sql').write_text('CREATE TABLE roles(id int);')
        spec=rt.plan(self.base)
        self.assertEqual(spec['seeds'],[])
        self.assertEqual(spec['migrations'],[dict(kind='sql',path='seed_structure.sql',extensions=dict(declarations=[],gaps=[],requirements_status='recorded'))])

    def test_comment_lexer_and_quoted_dependencies(self):
        self.assertEqual(rt.sql_without_comments("/* don't close early /* nested */ x */ SELECT '/* literal */'; -- tail" ).strip(), "SELECT '/* literal */';")
        self.assertFalse(rt.initial_sql('CREATE TABLE child(id int REFERENCES "public"."parent"(id));'))
        self.assertFalse(rt.initial_sql("SELECT 'CREATE TABLE imaginary(id int)';"))

    def test_duplicate_file_is_attempted_and_reported(self):
        executor=FakeExecutor(); original=executor.run
        def run(argv,cwd,env,timeout):
            if '-f' in argv and argv[-1].endswith('001_init.sql'):
                executor.calls.append((argv,Path(cwd),dict(env),timeout))
                return 1,'ERROR: relation already exists'
            return original(argv,cwd,env,timeout)
        executor.run=run
        report=self.runner(executor=executor).run()
        self.assertTrue(report['parts'][0]['database']['limitations'][0]['duplicate'])
        self.assertEqual(report['parts'][0]['checks']['schema-apply']['status'],'FAIL')

    def test_email_policy_comments_domains_and_service_account(self):
        for sql in ("-- person@private.example\nSELECT 1", "/* person@private.example */ SELECT 1", "SELECT 'admin@internal.example'", "SELECT 'a@example.edu', 'b@host.local', 'c@host.localhost', 'd@host.test', 'e@host.invalid'"):
            self.assertFalse(rt.personal_emails(sql),sql)
        self.assertTrue(rt.personal_emails("SELECT 'person@private.example'"))
        self.assertTrue(rt.personal_emails("SELECT 'admin@internal.example','person@private.example'"))
        self.assertTrue(rt.personal_emails("SELECT '-- person@private.example'"))

    def test_failed_schema_reduces_data_audit_and_marks_backup_partial(self):
        runner=self.runner('monorepo-split-db',executor=FakeExecutor(fail=lambda a: '-f' in a and a[-1].endswith('002_failure.sql')))
        report=runner.run(); backup=report['parts'][0]['checks']['backup']
        self.assertEqual(backup['status'],'PASS');self.assertTrue(backup['metrics']['partial'])
        # Also protect import of older reports with a successful partial backup.
        report['parts'][0]['checks']['backup']['status']='PASS'
        report['controls']=[dict(c,id=k,part=p['name']) for p in report['parts'] for k,c in p['checks'].items()]
        path=self.base/'out/runtime-report.json';path.write_text(json.dumps(report))
        maturity=helix_pro.assess(FIX/'monorepo-split-db')
        rt.import_evidence(maturity,path,FIX/'monorepo-split-db')
        self.assertLess(maturity['areas']['data']['score'],100)

    def test_dependency_failure_retried_and_duplicate_reported(self):
        counts={}
        def fail(a):
            if '-f' not in a:return False
            name=Path(a[-1]).name;counts[name]=counts.get(name,0)+1
            return name=='001_init.sql' and counts[name]==1
        runner=self.runner(executor=FakeExecutor(fail=fail));report=runner.run()
        self.assertEqual(counts['001_init.sql'],3)  # trial failure + retry, then selected plan on main DB
        self.assertEqual(report['parts'][0]['checks']['schema-apply']['status'],'PASS')

    def test_readiness_retries_both_probes_before_migration(self):
        calls=[]
        def fail(a):
            calls.append(a)
            return a[-1]=='SELECT 1' and sum(x[-1]=='SELECT 1' for x in calls)==1
        with patch.object(rt.time,'sleep'):
            report=self.runner(executor=FakeExecutor(fail=fail)).run()
        self.assertEqual(report['parts'][0]['checks']['schema-apply']['status'],'PASS')
        first_file=next(i for i,a in enumerate(calls) if '-f' in a)
        probes=calls[:first_file]
        self.assertEqual(sum('pg_isready' in a for a in probes),2)
        self.assertEqual(sum(a[-1]=='SELECT 1' for a in probes),2)

if __name__=='__main__':unittest.main()
