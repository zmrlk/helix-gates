"""Offline regressions: executor doubles never install tools or access a network."""
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_runtime import FakeExecutor, TOOLS, FIX
import helix_runtime as rt

class RoundSixTests(unittest.TestCase):
    def run_fixture(self, fixture, executor=None):
        with tempfile.TemporaryDirectory() as directory:
            runner=rt.Runner(FIX/fixture,Path(directory)/'out',executor=executor or FakeExecutor(),tools={'tools':TOOLS},port_factory=lambda:31234)
            return runner.run()['parts'][0],runner

    def test_project_runner_first_and_database_env_isolated(self):
        part,runner=self.run_fixture('project-runner')
        group=part['database']['strategies'][0]
        self.assertEqual(group['strategy'],'project-runner:migrate.sh')
        self.assertEqual(group['results'][0]['applied'],1)
        self.assertTrue(group['candidates'][0]['migrations'][0]['documentation'])
        calls=[c for c in runner.executor.calls if c[0][0]=='bash']
        self.assertEqual(len(calls),2)
        self.assertIn('helix_trial_',calls[0][2]['PGDATABASE'])
        self.assertEqual(calls[0][2]['DATABASE_URL'].split('/')[-1],calls[0][2]['PGDATABASE'])
        self.assertNotIn('helix_trial_',calls[1][2]['PGDATABASE'])
        self.assertEqual(part['database']['selection']['count'],1)
        self.assertEqual(len(part['database']['selection']['selected']),1)

    def test_runner_failure_falls_back_and_retains_diagnostic(self):
        executor=FakeExecutor(fail=lambda argv: argv[0]=='bash')
        part,_=self.run_fixture('project-runner',executor)
        group=part['database']['strategies'][0]
        self.assertEqual(group['strategy'],'migrations')
        self.assertEqual(group['results'][0]['failed'],1)
        self.assertTrue(group['results'][0]['errors'])
        self.assertEqual(part['checks']['schema-apply']['status'],'PASS')

    def test_convention_and_script_detection(self):
        sources={'Makefile':'db-migrate:\n\techo migrate\n', 'package.json':json.dumps({'scripts':{'db:migrate':'dbmate up'}}), 'supabase/config.toml':''}
        runners=rt.project_runners(sources)
        self.assertEqual([r['argv'][:2] for r in runners],[['make','db-migrate'],['npm','run'],['supabase','db']])
        self.assertIn('{database}',runners[2]['argv'])

    def test_dynamic_private_issuer_and_no_bypass(self):
        with patch.object(rt,'locate',return_value='/fake/openssl'):
            part,runner=self.run_fixture('oidc-dynamic-private')
        self.assertIn('IDENTITY_ISSUER_URL',part['startup']['oidc']['variables'])
        self.assertTrue(runner.env['IDENTITY_ISSUER_URL'].startswith('https://'))
        env=rt.dummy_env({'env':[{'name':'APP_AUTH_BYPASS','classification':'dummy'}]},'postgresql://helix@127.0.0.1/db',3000)
        self.assertNotIn('APP_AUTH_BYPASS',env)

    def test_config_and_source_issuer_names(self):
        text='''import { ISSUER_URL } from '$env/static/private';
import { env as privateEnv } from '$env/dynamic/private';
privateEnv.REALM_ENDPOINT; env['OIDC_URL']; import.meta.env.AUTH_URL;
process.env.OKTA_ISSUER; os.environ['COGNITO_ISSUER'];
KEYCLOAK_URL: synthetic
'''
        self.assertTrue({'ISSUER_URL','REALM_ENDPOINT','OIDC_URL','AUTH_URL','OKTA_ISSUER','COGNITO_ISSUER','KEYCLOAK_URL'} <= rt.env_names(text))

    def test_http_503_fails_lighthouse_without_invoking_tool(self):
        executor=FakeExecutor()
        def health(url,timeout):
            executor.last_health={'state':'http','status':503};return url
        executor.health=health
        part,runner=self.run_fixture('project-runner',executor)
        self.assertEqual(part['checks']['lighthouse']['status'],'FAIL')
        self.assertIn('503',part['checks']['lighthouse']['reason'])
        self.assertFalse(any(c[0][0].endswith('lighthouse') for c in executor.calls))

    def test_a11y_and_budget_failures_have_specific_reasons(self):
        executor=FakeExecutor(); original=executor.run
        def run(argv,cwd,env,timeout):
            result=original(argv,cwd,env,timeout)
            if str(argv[0]).endswith('node') and any(str(x).endswith('runtime-browser.cjs') for x in argv):
                rows=[dict(type='route',route=route,status='FAIL',reachable=True,errors=[],violations=[{'id':'document-title'}]) for route in json.loads(argv[5])]
                Path(argv[3]).write_text(json.dumps(dict(routes=rows,requests=[])))
                Path(str(argv[3])+'.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
            if str(argv[0]).endswith('lighthouse') and '--version' not in argv:
                output=next(a.split('=',1)[1] for a in argv if a.startswith('--output-path='))
                data=json.loads(Path(output).read_text());data['audits']['largest-contentful-paint']['numericValue']=99999;Path(output).write_text(json.dumps(data))
            return result
        executor.run=run
        part,_=self.run_fixture('project-runner',executor)
        self.assertIn('document-title',part['checks']['a11y']['reason'])
        self.assertIn('lcp_ms=99999 vs budget',part['checks']['lighthouse']['reason'])

    def test_lighthouse_runtime_error_is_app_failure(self):
        executor=FakeExecutor(); original=executor.run
        def run(argv,cwd,env,timeout):
            if str(argv[0]).endswith('lighthouse') and '--version' not in argv:
                output=next(a.split('=',1)[1] for a in argv if a.startswith('--output-path='))
                Path(output).write_text(json.dumps({'runtimeError':{'code':'NOT_HTML','message':'Page is not HTML: text/plain'}}))
                return 1,'Runtime error: Page is not HTML: text/plain'
            return original(argv,cwd,env,timeout)
        executor.run=run
        part,_=self.run_fixture('project-runner',executor)
        self.assertEqual(part['checks']['lighthouse']['status'],'FAIL')
        self.assertIn('text/plain',part['checks']['lighthouse']['reason'])

    def test_shell_fixture_executes_psql_loop_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'calls'
            env={'PATH':os.defpath,'DATABASE_URL':'postgresql://helix@127.0.0.1:1/trial','CALLS':str(output)}
            command='psql() { printf "%s\\n" "$*" >> "$CALLS"; }; export -f psql; bash migrate.sh'
            result=subprocess.run(['bash','-c',command],cwd=FIX/'project-runner',env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(env['DATABASE_URL'],output.read_text())
            self.assertIn('db/migrations/001.sql',output.read_text())
            result=subprocess.run(['bash','-c','psql() { return 42; }; export -f psql; bash migrate.sh'],cwd=FIX/'project-runner',env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,42)

    def test_deployment_env_declarations(self):
        self.assertTrue({'OIDC_URL','AUTH_BYPASS','REALM_URL'} <= rt.env_names('environment:\n  - OIDC_URL=https://invalid\n  AUTH_BYPASS: false\nenv:\n  - name: REALM_URL\n    value: synthetic'))

    def test_shared_helm_issuer_reaches_nested_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'frontend').mkdir(); (root/'helm').mkdir()
            (root/'frontend/package.json').write_text(json.dumps({'scripts':{'start':'node app.cjs'}}))
            (root/'helm/values.yaml').write_text('env:\n  - name: KEYCLOAK_ISSUER\n    value: synthetic\n')
            names={e['name'] for e in rt.plan(root)['parts'][0]['env']}
            self.assertIn('KEYCLOAK_ISSUER',names)

    def test_runner_cannot_hide_psql_error_with_exit_zero(self):
        executor=FakeExecutor(); original=executor.run
        def run(argv,cwd,env,timeout):
            if argv[0]=='bash': return 0,'psql:db/2.sql:3: ERROR: relation missing does not exist'
            return original(argv,cwd,env,timeout)
        executor.run=run
        part,_=self.run_fixture('project-runner',executor)
        self.assertEqual(part['database']['strategies'][0]['results'][0]['failed'],1)
        self.assertEqual(part['database']['strategies'][0]['strategy'],'migrations')

    def test_fallback_plan_keeps_independent_schema_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'db/migrations').mkdir(parents=True); (root/'catalog/schema').mkdir(parents=True)
            (root/'package.json').write_text(json.dumps({'scripts':{'start':'node app.cjs','migrate':'dbmate up','db:migrate':'dbmate up'}}))
            (root/'db/migrations/001.sql').write_text('CREATE TABLE items(id int);')
            (root/'catalog/schema/001.sql').write_text('CREATE TABLE catalog(id int);')
            group=rt.plan(root)['parts'][0]['schema_strategies'][0]
            ids=[c['strategy'] for c in group['candidates']]
            self.assertEqual(len(ids),len(set(ids)))
            fallback=next(c for c in group['candidates'] if c['strategy']=='migrations')
            self.assertEqual({m['path'] for m in fallback['migrations']},{'db/migrations/001.sql','catalog/schema/001.sql'})
