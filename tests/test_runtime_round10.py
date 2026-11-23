"""Round ten: offline runtime regressions; no services or installations."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from test_runtime import FIX, TOOLS, FakeExecutor, ROOT
import helix_runtime as rt


def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class RefusalExecutor(FakeExecutor):
    def __init__(self, always_fail=False):
        super().__init__(); self.always_fail=always_fail
    def run(self,argv,cwd,env,timeout):
        if argv[0]=='bash':
            self.calls.append((argv,Path(cwd),dict(env),timeout))
            if self.always_fail or env.get('PSQL_FORCE_FRESH')!='1':
                return 2,'empty migration ledger; fresh database: PSQL_FORCE_FRESH=1 migrate.sh up\n'
            return 0,'created application tables'
        return super().run(argv,cwd,env,timeout)


class RoundTenTests(unittest.TestCase):
    def fixture(self, always_fail=False):
        directory=tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        project=Path(directory.name)/'project'; shutil.copytree(FIX/'bootstrap-runner',project)
        # No hints in source: only the executor refusal reveals the env variant.
        (project/'migrate.sh').write_text('#!/bin/sh\nexit 2\n')
        (project/'README.md').write_text('Migration runner\n')
        (project/'schema.sql').write_text('CREATE TABLE runtime_items(id integer);')
        runner=rt.Runner(project,Path(directory.name)/'out',executor=RefusalExecutor(always_fail),tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
        return runner.run()['parts'][0],runner

    def test_run_refusal_then_env_success(self):
        part,runner=self.fixture()
        group=part['database']['strategies'][0]
        results=group['results']
        self.assertEqual(results[0]['status'],'failed')
        env_result=next(r for r in results if r['commands'][0]['env'].get('PSQL_FORCE_FRESH')=='1')
        self.assertEqual(env_result['status'],'applied')
        self.assertEqual(group['strategy'],env_result['strategy'])
        self.assertEqual(part['checks']['schema-apply']['status'],'PASS')
        calls=[c for c in runner.executor.calls if c[0][0]=='bash']
        self.assertNotEqual(calls[0][2]['PGDATABASE'],calls[1][2]['PGDATABASE'])
        for candidate in group['candidates']:
            self.assertTrue({'status','applied','failed','first_error'} <= candidate.keys())

    def test_run_all_runners_fail_then_sql(self):
        part,_=self.fixture(True)
        group=part['database']['strategies'][0]
        self.assertFalse(group['strategy'].startswith('project-runner:'))
        self.assertEqual(part['checks']['schema-apply']['status'],'PASS')
        self.assertTrue(all(r['status']=='failed' for r in group['results'] if r['strategy'].startswith('project-runner:')))

    def test_failed_variants_tie_keeps_project_recommendation(self):
        part,runner=self.fixture(True)
        spec=rt.plan(runner.project)['parts'][0]
        runner.tmp=Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree,runner.tmp)
        runner.work=runner.project; runner.db='postgresql://helix@127.0.0.1/db'
        runner.applied=set(); runner.migration_notes=[]; runner.env={}
        runner.budget=rt.Budget(60)
        runner.executor=RefusalExecutor(True)
        runner.executor.fail=lambda argv: '-f' in argv
        runner.select_schema(spec)
        group=spec['schema_strategies'][0]
        self.assertEqual(group['strategy'],group['candidates'][0]['strategy'])
        self.assertTrue(all(r['applied']==0 and r.get('objects',0)==0 for r in group['results'] if r['status']!='skipped'))
        self.assertTrue(next(r for r in group['results'] if r['strategy']==group['strategy'])['failed'])

    def test_lighthouse_spki_argument(self):
        _,runner=self.fixture()
        runner.tmp=Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree,runner.tmp)
        runner.work=runner.project; runner.env={'HELIX_RUNTIME_OIDC_SPKI':'syntheticHash='}
        runner.budget=rt.Budget(60)
        runner.measure('lighthouse',{'path':'.'},'http://127.0.0.1:31234/',{'lcp_ms':2500,'cls':.1,'tbt_ms':200,'performance':.9})
        argv=runner.executor.calls[-1][0]
        flags=next(a for a in argv if a.startswith('--chrome-flags='))
        self.assertIn('--ignore-certificate-errors-spki-list=syntheticHash=',flags)
        self.assertNotIn('--ignore-certificate-errors ',flags)

    def test_oidc_prefixed_authorization_paths(self):
        oidc=module('runtime_oidc',ROOT/'bin/runtime-oidc.py')
        for prefix in ('','/tenant/arbitrary','/realms/synthetic'):
            for suffix in ('/authorize','/login','/protocol/openid-connect/auth'):
                self.assertEqual(oidc.authorization_prefix(prefix+suffix),prefix)
        self.assertIsNone(oidc.authorization_prefix('/missing'))

    def test_pre_push_rejects_remote_version_without_release_subject(self):
        release=module('release_round10',ROOT/'scripts/check_release_version.py')
        from unittest.mock import patch
        def git(root,*args):
            if args[0]=='show': return (ROOT/args[1].split(':',1)[1]).read_text()
            if args[0]=='rev-parse': return 'abc'
            return ''
        with patch.object(release,'git',git):
            self.assertTrue(any('already present' in e for e in release.check(ROOT,pre_push=True)))


if __name__=='__main__': unittest.main()
