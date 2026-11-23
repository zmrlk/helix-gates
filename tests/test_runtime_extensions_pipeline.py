import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime as rt
from helix_runtime_extensions import AVAILABLE_EXTENSIONS_SQL, COMMON_EXTENSIONS
from test_runtime import FakeExecutor, TOOLS


class RuntimeExtensionsPipeline(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.project=self.base/'project';self.project.mkdir()
        (self.project/'package.json').write_text(json.dumps({'scripts':{'start':'node app.cjs'}}))
        (self.project/'app.cjs').write_text('// synthetic entrypoint, never executed by this fixture')
        self.migrations=self.project/'migrations';self.migrations.mkdir()
        self.executor=FakeExecutor()
    def runner(self):
        return rt.Runner(self.project,self.base/'out',executor=self.executor,tools={'tools':TOOLS},port_factory=lambda:31234)
    def run_pipeline(self,sql='CREATE EXTENSION pg_trgm; CREATE TABLE synthetic(id int);'):
        (self.migrations/'001.sql').write_text(sql)
        self.current=self.runner()
        return self.current.run()
    def prepare(self):
        runner=self.runner();runner.work=self.project;runner.tmp=self.base/'private';runner.tmp.mkdir()
        (runner.out/'logs').mkdir(parents=True)
        runner.db='postgresql://helix@127.0.0.1:32123/helix';runner.active_part='.'
        return runner

    def test_catalog_before_each_migration_and_restore_without_activation(self):
        report=self.run_pipeline()
        rt.validate_report(report)
        calls=[call[0] for call in self.executor.calls]
        catalog=[i for i,argv in enumerate(calls) if argv[-1]==AVAILABLE_EXTENSIONS_SQL]
        major=next(i for i,argv in enumerate(calls) if argv[-1]=='SHOW server_version')
        self.assertLess(major,catalog[0])
        migration=next(i for i,argv in enumerate(calls) if '-f' in argv and str(argv[-1]).endswith('001.sql'))
        self.assertLess(catalog[0],migration)
        restore=next(i for i,argv in enumerate(calls) if 'pg_restore' in argv)
        checks=report['database_fidelity']['extension_checks']
        self.assertIn('restore',{row['scope'] for row in checks})
        self.assertTrue(any(i<restore and 'helix_restore_' in ' '.join(calls[i]) for i in catalog))
        self.assertFalse(any('-c' in a and a[-1].upper().startswith('CREATE EXTENSION') for a in calls))
        row=next(row for row in checks if row['scope']=='restore')
        self.assertEqual(row['required'],['pg_trgm']);self.assertEqual(row['status'],'ready')
        self.assertEqual(row['declarations'][0]['path'],'migrations/001.sql')
        self.assertIsNone(next(o for o in row['observed'] if o['name']=='pg_trgm')['installed_version'])
        self.assertEqual(row['version_check'],'not_checked')

    def test_missing_requirement_blocks_before_project_runner(self):
        (self.migrations/'001.sql').write_text('CREATE EXTENSION absent_extension;')
        runner=self.prepare()
        spec={'migrations':[{'kind':'runner','path':'migrate.sh','cwd':'.','argv':['bash','migrate.sh'],'extensions':rt.extension_requirements([dict(kind='sql',path='migrations/001.sql',extensions={'declarations':[dict(name='absent_extension',path='migrations/001.sql',line=1,declared_version=None)],'gaps':[]})])}]}
        with self.assertRaisesRegex(rt.Blocked,'absent_extension'):runner.migrate(spec,seed=False)
        self.assertFalse(any('bash' in argv for argv,*_ in self.executor.calls))
        row=json.loads((runner.out/'database-fidelity.json').read_text())['extension_checks'][-1]
        self.assertEqual(row['status'],'blocked');self.assertEqual(row['missing'],['absent_extension'])
        self.assertEqual(row['requirements_status'],'unknown')
        rt.validate_extension_checks(runner.fidelity)

    def test_unrequired_common_absence_is_observation_not_block(self):
        original=self.executor.run
        def run(argv,cwd,env,timeout):
            result=original(argv,cwd,env,timeout)
            return (0,'[]') if argv[-1]==AVAILABLE_EXTENSIONS_SQL else result
        self.executor.run=run
        runner=self.prepare();row=runner.extension_preflight()
        self.assertEqual(row['status'],'ready');self.assertEqual(row['required'],[])
        self.assertEqual({o['name'] for o in row['observed']},set(COMMON_EXTENSIONS))
        self.assertTrue(all(not o['available'] for o in row['observed']))

    def test_special_profiles_do_not_conflict_with_common_extensions(self):
        for name,image in [('vector','pgvector/pgvector:pg16'),('postgis','postgis/postgis:16-3.5'),('pgcrypto','postgres:16-alpine')]:
            with self.subTest(name=name):
                (self.migrations/'001.sql').write_text('CREATE EXTENSION '+name+'; CREATE EXTENSION pg_trgm;')
                target=rt.database_target(self.project)
                self.assertEqual(target['image'],image);self.assertFalse(target['extension_profile_conflict'])
        (self.migrations/'001.sql').write_text('CREATE EXTENSION vector; CREATE EXTENSION postgis;')
        runner=self.prepare()
        with self.assertRaises(rt.Blocked):runner.database()
        self.assertEqual(self.executor.calls,[])

    def test_plan_keeps_versions_and_monorepo_locations(self):
        (self.project/'package.json').unlink()
        for app,name in [('one','pg_trgm'),('two','pgcrypto')]:
            directory=self.project/app;directory.mkdir()
            (directory/'package.json').write_text(json.dumps({'scripts':{'start':'node app.cjs'}}))
            (directory/'schema.sql').write_text('\nCREATE EXTENSION '+name+" VERSION '1.0';\nCREATE TABLE synthetic(id int);")
        plan=rt.plan(self.project)
        for part in plan['parts']:
            declarations=rt.extension_requirements(part['migrations'])['declarations']
            self.assertEqual(len(declarations),1)
            self.assertEqual(declarations[0]['path'],part['path']+'/schema.sql')
            self.assertEqual(declarations[0]['line'],2)
            self.assertEqual(declarations[0]['declared_version'],'1.0')

    def test_import_rejects_forged_ready_and_legacy_absence_is_allowed(self):
        report=self.run_pipeline();row=report['database_fidelity']['extension_checks'][-1]
        row['missing']=['pg_trgm']
        with self.assertRaises(ValueError):rt.validate_report(report)
        del report['database_fidelity']['extension_checks']
        rt.validate_report(report)

    def test_known_common_plus_dynamic_sql_keeps_unknown_scope(self):
        report=self.run_pipeline("CREATE EXTENSION pg_trgm; DO $$ BEGIN NULL; END $$; CREATE TABLE synthetic(id int);")
        rows=[r for r in report['database_fidelity']['extension_checks'] if r['required']]
        self.assertTrue(rows)
        self.assertTrue(all(r['requirements_status']=='unknown' for r in rows))
        self.assertTrue(all(any(g['reason_code']=='dynamic_sql_requirements_unresolved' for g in r['gaps']) for r in rows))
        rt.validate_report(report)

    def test_sqitch_deploy_requirements_block_before_runner_without_duplicate_sql(self):
        (self.project/'sqitch.plan').write_text('%syntax-version=1.0.0\n001 2026-01-01T00:00:00Z Synthetic <fixture@example.invalid> # init\n')
        for folder,name in [('deploy','pgcrypto'),('revert','revert_only'),('verify','verify_only')]:
            directory=self.project/folder;directory.mkdir()
            (directory/'001.sql').write_text('\nCREATE EXTENSION '+name+';')
        spec=rt.plan(self.project)['parts'][0]
        self.assertEqual([(m['kind'],m['path']) for m in spec['migrations']],[('sqitch','sqitch.plan')])
        declarations=rt.extension_requirements(spec['migrations'])['declarations']
        self.assertEqual(declarations,[dict(name='pgcrypto',path='deploy/001.sql',line=2,declared_version=None)])
        original=self.executor.run
        def run(argv,cwd,env,timeout):
            result=original(argv,cwd,env,timeout)
            if argv[-1]==AVAILABLE_EXTENSIONS_SQL:
                return 0,json.dumps([row for row in json.loads(result[1]) if row['name']!='pgcrypto'])
            return result
        self.executor.run=run
        runner=self.prepare()
        with self.assertRaisesRegex(rt.Blocked,'pgcrypto'):runner.migrate(spec,seed=False)
        self.assertFalse(any(argv[0]=='sqitch' for argv,*_ in self.executor.calls))
        self.assertEqual(runner.fidelity['extension_checks'][-1]['missing'],['pgcrypto'])
        rt.validate_extension_checks(runner.fidelity)

if __name__=='__main__':unittest.main()
