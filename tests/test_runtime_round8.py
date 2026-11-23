"""Offline bootstrap, typed environment, startup diagnostics and release fixtures."""
import importlib.util
import json
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_runtime import FakeExecutor, TOOLS, FIX, ROOT
import helix_runtime as rt

spec=importlib.util.spec_from_file_location('release',ROOT/'scripts/check_release_version.py')
release=importlib.util.module_from_spec(spec); spec.loader.exec_module(release)


class BootstrapExecutor(FakeExecutor):
    def run(self,argv,cwd,env,timeout):
        if argv[0]=='bash':
            self.calls.append((argv,Path(cwd),dict(env),timeout))
            p=subprocess.run(argv,cwd=cwd,env=env,capture_output=True,text=True,timeout=2)
            return p.returncode,p.stdout+p.stderr
        return super().run(argv,cwd,env,timeout)


class RoundEightTests(unittest.TestCase):
    def run_fixture(self,executor):
        directory=tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        runner=rt.Runner(FIX/'bootstrap-runner',Path(directory.name)/'out',executor=executor,tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
        return runner.run()['parts'][0],runner

    def test_bootstrap_guard_order_isolation_and_report(self):
        part,runner=self.run_fixture(BootstrapExecutor())
        group=part['database']['strategies'][0]
        self.assertIn(':fresh',group['strategy'])
        results=group['results']
        self.assertEqual([r['status'] for r in results],['failed','applied'])
        self.assertIn('empty migration ledger',results[0]['first_error'])
        self.assertEqual(results[0]['category'],'fresh-database-guard')
        self.assertEqual(results[1]['commands'][0]['env'],{'APP_FORCE_FRESH':'1'})
        self.assertTrue(results[1]['commands'][0]['evidence']['line'])
        calls=[c for c in runner.executor.calls if c[0][0]=='bash']
        self.assertNotIn('APP_FORCE_FRESH',calls[0][2])
        self.assertNotEqual(calls[0][2]['PGDATABASE'],calls[1][2]['PGDATABASE'])
        self.assertEqual(calls[-1][2]['APP_FORCE_FRESH'],'1')
        self.assertTrue(all(r['seconds']>=0 for r in results))

    def test_flags_require_documented_fresh_context(self):
        runners=rt.project_runners({'migrate.sh':'echo up','README.md':'For first run / fresh database:\nbash migrate.sh --fresh\nbash migrate.sh --baseline=0'})
        self.assertEqual(len(runners),3)
        self.assertEqual(runners[1]['argv'][-1],'--fresh')
        self.assertEqual(runners[2]['argv'][-1],'--baseline=0')

    def test_typed_values_and_adapter_defaults(self):
        names=['BODY_SIZE_LIMIT','ORIGIN','PROTOCOL_HEADER','HOST_HEADER','XFF_DEPTH','SHUTDOWN_TIMEOUT','IDLE_TIMEOUT','NODE_ENV','REQUEST_SIZE_LIMIT','ENABLE_CACHE','USE_TLS','API_TIMEOUT','MAX_COUNT','CONTACT_EMAIL','APP_URL','APP_HOST','TOKEN_TTL']
        env=rt.dummy_env({'env':[dict(name=n,classification=rt.classification(n)) for n in names]},'postgresql://helix@127.0.0.1/db',31234)
        for name in names[:8]:
            if name!='ORIGIN': self.assertNotIn(name,env)
        self.assertEqual(env['ORIGIN'],'http://127.0.0.1:31234')
        self.assertEqual(env['REQUEST_SIZE_LIMIT'],'1')
        self.assertEqual(env['USE_TLS'],'false')
        self.assertEqual(env['CONTACT_EMAIL'],'x@example.invalid')
        self.assertEqual(env['PORT'],'31234')
        self.assertEqual(env['TOKEN_TTL'],'1')
        self.assertEqual(env['APP_HOST'],'127.0.0.1')
        self.assertTrue(env['APP_URL'].startswith('http://127.0.0.1'))
        part=rt.plan(FIX/'bootstrap-runner')['parts'][0]
        generated=rt.dummy_env(part,'postgresql://helix@127.0.0.1/db',31234)
        self.assertEqual(generated['REQUEST_SIZE_LIMIT'],'1024')
        self.assertEqual(generated['FEATURE_ENABLED'],'false')

    def test_crashed_and_dependents_blocked(self):
        class Crashed(BootstrapExecutor):
            def spawn(self,argv,cwd,env,log):
                log.write_text('Error: Cannot find module synthetic-package\n')
                class Process:
                    def poll(self): return 3
                return Process()
            def health(self,*args): raise rt.Blocked('no-listener')
        part,_=self.run_fixture(Crashed())
        self.assertEqual(part['startup']['status'],'CRASHED')
        attempt=part['startup']['attempts'][0]
        self.assertEqual(attempt['exit_code'],3)
        self.assertEqual(attempt['category'],'dependency')
        for name in ('e2e','a11y','lighthouse','load'):
            self.assertEqual(part['checks'][name]['status'],'BLOCKED')
            self.assertIn('Cannot find module',part['checks'][name]['reason'])

    def test_env_crash_repaired_exactly_once(self):
        class EnvCrash(BootstrapExecutor):
            def spawn(self,argv,cwd,env,log):
                self.valid=env['REQUEST_SIZE_LIMIT']=='1'
                log.write_text('started\n' if self.valid else "Invalid REQUEST_SIZE_LIMIT: 'bad'. Please provide a numeric value.\n")
                class Process:
                    def poll(inner): return None if self.valid else 2
                return Process()
            def health(self,*args):
                if not self.valid: raise rt.Blocked('no-listener')
        original=rt.dummy_env
        def bad(*args):
            env=original(*args); env['REQUEST_SIZE_LIMIT']='bad'; return env
        with patch.object(rt,'dummy_env',side_effect=bad): part,_=self.run_fixture(EnvCrash())
        self.assertEqual([a['status'] for a in part['startup']['attempts']],['CRASHED','RUNNING'])
        self.assertEqual(part['startup']['attempts'][0]['category'],'env')

    def test_fresh_guard_threshold_is_not_a_switch(self):
        runners=rt.project_runners({'migrate.sh':'if [ "${DB_FORCE_FRESH:-0}" != "1" ] && [ "$total" -gt "$FRESH_GUARD" ]; then\n exit 2\nfi'})
        self.assertEqual(len(runners),2)
        self.assertEqual(runners[1]['env'],{'DB_FORCE_FRESH':'1'})

    def test_required_database_guard_is_not_bootstrap(self):
        runners=rt.project_runners({'migrate.sh':'if [ -z "$DATABASE_URL" ]; then\n exit 2\nfi'})
        self.assertEqual(len(runners),1)

    def test_empty_guard_without_fresh_name(self):
        sources={'migrate.sh':'if [ -z "$ALLOW_BOOTSTRAP" ]; then\n echo "fresh database"\n exit 2\nfi', 'README.md':'first run: ALLOW_BOOTSTRAP=1 bash migrate.sh'}
        runners=rt.project_runners(sources)
        self.assertEqual(len(runners),2)
        self.assertEqual(runners[1]['env'],{'ALLOW_BOOTSTRAP':'1'})
        env=rt.dummy_env({'env':[dict(name='ALLOW_BOOTSTRAP',classification='dummy')],'bootstrap_variables':['ALLOW_BOOTSTRAP']},'postgresql://helix@127.0.0.1/db',3000)
        self.assertNotIn('ALLOW_BOOTSTRAP',env)

    def test_runner_failures_fall_back_to_sql(self):
        with tempfile.TemporaryDirectory() as directory:
            project=Path(directory)/'project'; shutil.copytree(FIX/'bootstrap-runner',project)
            (project/'migrations').mkdir()
            (project/'migrations/001.sql').write_text('CREATE TABLE example_items (id integer);')
            (project/'schema.sql').write_text('CREATE TABLE example_items (id integer);')
            class DuplicateTableExecutor(FakeExecutor):
                def __init__(self):
                    super().__init__(fail=lambda argv:argv[0]=='bash'); self.created=set()
                def run(self,argv,*args):
                    if '-f' in argv and argv[-1].endswith(('schema.sql','001.sql')):
                        database=argv[1]
                        if database in self.created: return 1,'ERROR: relation example_items already exists'
                        self.created.add(database)
                    return super().run(argv,*args)
            executor=DuplicateTableExecutor()
            runner=rt.Runner(project,Path(directory)/'out',executor=executor,tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
            part=runner.run()['parts'][0]; group=part['database']['strategies'][0]
            self.assertEqual(group['strategy'],'migrations')
            self.assertEqual([r['failed'] for r in group['results'][:2]],[1,1])
            self.assertEqual([r['strategy'] for r in group['results'][2:]],['migrations','baseline+migrations','snapshot'])
            for result in group['results']:
                for key in ('status','commands','category','first_error','seconds'): self.assertIn(key,result)
                self.assertTrue(all(c['argv'] for c in result['commands']))
            self.assertEqual(part['checks']['schema-apply']['status'],'PASS')
            chosen=next(r for r in group['results'] if r['strategy']==group['strategy'])
            duplicate=next(r for r in group['results'] if r['strategy']=='baseline+migrations')
            self.assertEqual(chosen['applied'],1)
            self.assertEqual(duplicate['failed'],1)
            self.assertIn('maximum catalog objects',group['selection_reason'])

    def test_numeric_dummy_runs_actual_synthetic_app(self):
        with tempfile.TemporaryDirectory() as directory:
            app=Path(directory)/'app.py'
            app.write_text('import os\nassert int(os.environ["REQUEST_SIZE_LIMIT"]) > 0\n')
            env=rt.dummy_env({'env':[dict(name='REQUEST_SIZE_LIMIT',classification='dummy')]},'postgresql://helix@127.0.0.1/db',3000)
            process=subprocess.run([sys.executable,str(app)],env=env,text=True,capture_output=True,timeout=2)
            self.assertEqual(process.returncode,0,process.stderr)

    def test_repair_stops_after_second_env_failure(self):
        class AlwaysCrash(BootstrapExecutor):
            def spawn(self,argv,cwd,env,log):
                log.write_text("Invalid REQUEST_SIZE_LIMIT: numeric value required\n")
                class Process:
                    def poll(self): return 2
                return Process()
            def health(self,*args): raise rt.Blocked('no-listener')
        original=rt.dummy_env
        def bad(*args):
            env=original(*args);env['REQUEST_SIZE_LIMIT']='bad';return env
        with patch.object(rt,'dummy_env',side_effect=bad): part,_=self.run_fixture(AlwaysCrash())
        self.assertEqual(len(part['startup']['attempts']),2)
        self.assertEqual(part['startup']['status'],'CRASHED')
        self.assertEqual(part['checks']['e2e']['status'],'BLOCKED')


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        (self.root/'bin').mkdir()
        (self.root/'bin/helix_contracts.py').write_text("VERSION = '0.7.2-beta'\n")
        (self.root/'CHANGELOG.md').write_text('# 0.7.2-beta — 2026-10-25\n')
        self.git('init','-q'); self.git('config','user.email','x@example.invalid'); self.git('config','user.name','Fixture')
        self.commit('Helix 0.7.1-beta')
        self.git('update-ref','refs/remotes/origin/master','HEAD')
    def git(self,*args): return release.git(self.root,*args).strip()
    def commit(self,subject):
        self.git('add','.'); self.git('commit','--allow-empty','-qm',subject)
    def test_new_version(self): self.assertEqual(release.check(self.root),[])
    def test_reused_version(self):
        self.commit('Helix 0.7.2-beta'); self.git('update-ref','refs/remotes/origin/master','HEAD'); self.commit('later change')
        self.assertTrue(any('already released' in e for e in release.check(self.root)))
    def test_current_range_allowed(self):
        base=self.git('rev-parse','HEAD'); self.commit('Helix 0.7.2-beta'); self.git('update-ref','refs/remotes/origin/master','HEAD'); self.commit('release followup')
        self.assertEqual(release.check(self.root,since=base),[])
    def test_duplicate_and_mismatch(self):
        (self.root/'CHANGELOG.md').write_text('# 0.7.1-beta — date\n# 0.7.1-beta — date\n')
        self.assertEqual(len(release.check(self.root)),2)
    def test_higher_later_heading_blocks(self):
        (self.root/'CHANGELOG.md').write_text('# 0.7.2-beta — date\n# 0.8.0-beta — date\n')
        self.assertTrue(release.check(self.root))
    def test_cli_fails_for_reused_release(self):
        self.commit('Helix 0.7.2-beta'); self.git('update-ref','refs/remotes/origin/master','HEAD'); self.commit('followup')
        result=subprocess.run([sys.executable,str(ROOT/'scripts/check_release_version.py'),'--repo',str(self.root)],capture_output=True,text=True,timeout=2)
        self.assertEqual(result.returncode,1)
        self.assertIn('already released',result.stdout)
    def test_missing_history_blocks(self): self.assertTrue(release.check(self.root,ref='missing'))
