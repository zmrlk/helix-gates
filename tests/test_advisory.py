import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_advisory as A
import helix_tool_adapters as T
import helix_mutation_advisory as M
import helix_simplicity as S
import helix_owner_report as O


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.repo=self.root/'repo';self.repo.mkdir()
        self.receipt=self.root/'receipt.json';self.receipt.write_text('{}')
        self.pin=dict(usable=True,version='synthetic',proof_kind='synthetic_test',argv_prefix=['synthetic'],receipt=str(self.receipt))
        (self.repo/'main.ts').write_text('export const value = 1;\n')
        (self.repo/'unused.ts').write_text('export const unused = 2;\n')
        (self.repo/'migrations').mkdir();(self.repo/'migrations/001.sql').write_text('SELECT 1;')
        (self.repo/'.env').write_text('SECRET_CANARY=never')

    def run_tool(self,name,execute,since=None):
        from helix_source_coverage import scan
        snapshot=scan(self.repo)
        with patch('helix_source_coverage.scan',return_value=snapshot),patch.object(A,'resolve_installed',return_value=self.pin),patch.object(A,'changed_files',return_value=['unused.ts','migrations/001.sql']),patch.object(A.subprocess,'run',side_effect=execute):
            return A.scan(self.repo,name,since=since)

    def test_knip_sanitized_snapshot_and_v6_parser(self):
        def execute(argv,**kwargs):
            target=kwargs['cwd'];self.assertFalse((target/'.env').exists());self.assertNotEqual(target,self.repo)
            self.assertEqual(json.loads((target/'package.json').read_text())['name'],'helix-snapshot')
            self.assertNotIn('SECRET_CANARY',json.dumps(kwargs['env']))
            return subprocess.CompletedProcess(argv,1,json.dumps({'issues':[{'file':'unused.ts','files':[{'name':'unused.ts'}],'exports':[]}]}),'')
        value=self.run_tool('knip',execute)
        self.assertEqual(value['status'],'completed');self.assertEqual(value['findings'][0]['file'],'unused.ts');self.assertEqual(value['score'],0)
        self.assertEqual((self.repo/'unused.ts').read_text(),'export const unused = 2;\n')

    def test_duplicate_keeps_both_locations_and_changed_second_side(self):
        def execute(argv,**kwargs):
            out=Path(argv[argv.index('--output')+1]);out.mkdir()
            data=dict(statistics={'total':{'sources':2}},duplicates=[dict(firstFile={'name':'main.ts','startLoc':{'line':1}},secondFile={'name':'unused.ts','startLoc':{'line':1}})])
            (out/'jscpd-report.json').write_text(json.dumps(data));return subprocess.CompletedProcess(argv,0,'','')
        value=self.run_tool('jscpd',execute,since='HEAD')
        self.assertEqual(value['status'],'completed');self.assertEqual(len(value['findings']),1)
        self.assertEqual(value['findings'][0]['related_locations'],[dict(file='unused.ts',line=1)])

    def test_squawk_requires_ref_and_limits_files(self):
        with patch.object(A,'resolve_installed',side_effect=AssertionError('must not execute')):
            self.assertEqual(A.scan(self.repo,'squawk')['status'],'not-run')
        def execute(argv,**kwargs):
            self.assertEqual(sorted(str(p.relative_to(kwargs['cwd'])) for p in kwargs['cwd'].rglob('*') if p.is_file()),['migrations/001.sql'])
            return subprocess.CompletedProcess(argv,1,json.dumps([dict(file='migrations/001.sql',line=0,rule_name='prefer-text-field')]),'')
        value=self.run_tool('squawk',execute,since='HEAD');self.assertEqual(value['status'],'completed');self.assertEqual(value['findings'][0]['line'],1)

    def test_three_duplicate_copies_preserve_all_related_locations(self):
        (self.repo/'third.ts').write_text('export const x=1;\n')
        rows=T.parse('jscpd',json.dumps({'duplicates':[dict(firstFile={'name':'main.ts','startLoc':{'line':1}},secondFile={'name':p,'startLoc':{'line':1}}) for p in ('unused.ts','third.ts')]}),self.repo)
        self.assertEqual(len(rows),1)
        self.assertEqual({p['file'] for p in rows[0]['related_locations']},{'unused.ts','third.ts'})

    def test_missing_empty_and_error_never_complete(self):
        with patch.object(A,'resolve_installed',return_value=None):self.assertEqual(A.scan(self.repo,'knip')['status'],'unavailable')
        for raw in ('{}','null','{"issues":{}}'):
            with self.subTest(raw=raw):self.assertEqual(self.run_tool('knip',lambda *a,**k:subprocess.CompletedProcess(a,0,raw,''))['status'],'error')
        def timeout(*a,**k):raise subprocess.TimeoutExpired(a,1)
        self.assertEqual(self.run_tool('knip',timeout)['status'],'timeout')

    def test_changed_files_includes_untracked_and_ref_failure(self):
        def git(repo,*args,**kwargs):
            if args[0]=='rev-parse':return SimpleNamespace(returncode=0,stdout='a'*40+'\n')
            return SimpleNamespace(returncode=0,stdout='src/change.py\0' if args[0]=='diff' else 'migrations/new.sql\0')
        with patch.object(A,'git',side_effect=git):self.assertEqual(A.changed_files(self.repo,'HEAD~1'),['migrations/new.sql','src/change.py'])
        with self.assertRaises(ValueError):A.changed_files(self.repo,'--all')
        with patch.object(A,'git',return_value=SimpleNamespace(returncode=1,stdout='')):
            with self.assertRaises(ValueError):A.changed_files(self.repo,'unknown')

    def test_publish_and_owner_preserve_advisory_status(self):
        value=A.result('knip');value.update(status='not-run',reason='not executed')
        with self.assertRaises(ValueError):A.publish(self.repo,self.repo/'out',value)
        out=self.root/'out';A.publish(self.repo,out,value)
        owner=O.aggregate(self.repo,[out]);self.assertEqual(owner['groups'][0]['tools'][0]['status'],'not-run')
        self.assertEqual(json.loads((out/'advisory-tools.json').read_text())['execution_credit'],0)
        with self.assertRaises(FileExistsError):A.publish(self.repo,out,value)


class MutationAdvisoryTests(unittest.TestCase):
    def test_requires_since_and_sandbox_without_execution(self):
        self.assertEqual(M.run('/unused','mutmut')['status'],'not-run')
        with patch.object(M,'changed_files',return_value=['src/a.py']),patch.object(M,'resolve_installed',return_value=None),patch.object(M,'locate',return_value=None),patch.object(M,'command',side_effect=AssertionError('not executed')):
            self.assertEqual(M.run('/unused','mutmut',since='HEAD')['status'],'not-run')

    def test_mutmut_uses_only_changed_sources_in_disposable_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);(repo/'src').mkdir();(repo/'src/a.py').write_text('a=1\n');(repo/'src/b.py').write_text('b=2\n')
            original='[tool.pytest.ini_options]\naddopts="-q"\n[tool.mutmut]\nsource_paths=["src/"]\n';(repo/'pyproject.toml').write_text(original)
            def command(argv,cwd,env,seconds):
                if 'run' in argv:
                    import tomllib
                    data=tomllib.loads((cwd/'pyproject.toml').read_text());self.assertEqual(data['tool']['mutmut']['source_paths'],['src/a.py']);self.assertEqual(data['tool']['pytest']['ini_options']['addopts'],'-q')
                if 'export-cicd-stats' in argv:
                    out=cwd/'mutants';out.mkdir();stats=dict(total=1,killed=1,survived=0,no_tests=0,skipped=0,suspicious=0,timeout=0,check_was_interrupted_by_user=0,segfault=0);(out/'mutmut-cicd-stats.json').write_text(json.dumps(stats))
                return ''
            with patch.object(M,'changed_files',return_value=['src/a.py']),patch.object(M,'resolve_installed',return_value=dict(usable=True,argv_prefix=['mutmut'])),patch.object(M,'locate',return_value='unshare'),patch.object(M,'command',side_effect=command):
                value=M.run(repo,'mutmut',since='HEAD')
            self.assertEqual(value['status'],'completed');self.assertEqual(value['mutation_score'],100);self.assertEqual(value['score'],0);self.assertEqual((repo/'pyproject.toml').read_text(),original)

    def test_stryker_keeps_literal_route_path_and_rejects_report_outside_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);p=repo/'src/[id]/route.ts';p.parent.mkdir(parents=True);p.write_text('export const x=1;\n')
            def command(argv,cwd,env,seconds):
                if 'run' in argv:
                    self.assertIn(r'src/\[id\]/route.ts',argv)
                    out=cwd/'reports/mutation';out.mkdir(parents=True)
                    (out/'mutation.json').write_text(json.dumps({'files':{'outside.ts':{'mutants':[{'status':'Killed'}]}}}))
                return ''
            with patch.object(M,'changed_files',return_value=['src/[id]/route.ts']),patch.object(M,'locate',side_effect=lambda name:name),patch.object(M,'command',side_effect=command):
                value=M.run(repo,'stryker',since='HEAD')
            self.assertEqual(value['status'],'error');self.assertEqual(value['score'],0)


class SimplicityTests(unittest.TestCase):
    def setUp(self):
        self.role=dict(provider='codex',model='exact-model',family='openai',status='available',prompt='review_architecture')
        self.ctx=SimpleNamespace(repo=Path('/synthetic'),role_plan={'roles':{'reviewers':[self.role]}},cfg={},offline=False)
    def run_review(self,execute=False,caller=None):
        with patch.object(S,'changed_files',return_value=['a.py']),patch.object(S,'scan',return_value=({'a.py':'x=1\n'},{'status':'COMPLETE'})):
            return S.review(self.ctx,since='HEAD',execute=execute,caller=caller)
    def test_plan_and_admission_do_not_call_model(self):
        caller=Mock(side_effect=AssertionError('must not call'));value=self.run_review(caller=caller)
        self.assertEqual(value['role'],self.role);self.assertEqual(value['usage']['calls'],0)
        # Jawne ograniczenie właściciela (inny dostawca) zatrzymuje wywołanie; domyślnie model jest dopuszczony (decyzja 15.11.2026).
        self.ctx.cfg={'data_egress':dict(schema_version=1,status='approved',allowed_providers=['gemini'],exclude_paths=[])}
        value=self.run_review(True,caller);self.assertEqual(value['status'],'not-run');caller.assert_not_called()
    def test_exact_role_result_remains_advisory(self):
        caller=Mock(return_value=(json.dumps({'findings':[dict(file='a.py',line=1,tag='shrink',why='reason',fix='proposal')]}),dict(provider='codex',model='exact-model')))
        before=copy.deepcopy(self.ctx.role_plan)
        with patch.object(S,'source_input_admission',return_value=None):value=self.run_review(True,caller)
        self.assertEqual(value['status'],'completed');self.assertEqual(value['score'],0);self.assertEqual(self.ctx.role_plan,before);self.assertEqual(caller.call_args.kwargs['model'],'exact-model')
        self.assertIsNone(value['usage']['cost'])

if __name__=='__main__':unittest.main()
