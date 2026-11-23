"""Local Git fixtures; no transports or target processes are used."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_ponytail_age as age
import helix_git_readonly as gitread

OBSERVED='2026-10-26T12:00:00+00:00'

class PonytailAge(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.repo=self.root/'repo';self.repo.mkdir()
        self.environment={'PATH':os.environ['PATH'],'HOME':str(self.root),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
            'GIT_AUTHOR_NAME':'Synthetic','GIT_AUTHOR_EMAIL':'test@example.invalid','GIT_COMMITTER_NAME':'Synthetic','GIT_COMMITTER_EMAIL':'test@example.invalid',
            'GIT_AUTHOR_DATE':'2026-10-20T12:00:00+00:00','GIT_COMMITTER_DATE':'2026-10-20T12:00:00+00:00'}
        self.git('init','-q');self.sources={'source.py':'# ponytail: one queue, upgrade after 100 jobs\nvalue=1\n# ponytail: no cache, upgrade after profiling\n'}
        (self.repo/'source.py').write_text(self.sources['source.py']);self.git('add','source.py');self.git('commit','-qm','synthetic history')
        self.head=self.git('rev-parse','HEAD').strip();self.ref={'head':self.head,'dirty':False}
    def git(self,*args):
        result=subprocess.run(['git','-c','core.hooksPath='+os.devnull,*args],cwd=self.repo,env=self.environment,capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr);return result.stdout
    def report(self):return {'rows':[{'file':'source.py','line':1},{'file':'source.py','line':3}]}
    def test_one_blame_and_batch_for_multiple_markers(self):
        with patch.object(age,'read_git',wraps=age.read_git) as calls:
            result=age.collect_line_ages(self.repo,self.report(),self.sources,self.ref,observed_at=OBSERVED)
        self.assertEqual([row['status'] for row in result],['known','known'])
        self.assertEqual({row['changed_at'] for row in result},{'2026-10-20T12:00:00+00:00'})
        self.assertEqual(sum(call.args[1]=='blame' for call in calls.call_args_list),1)
        self.assertEqual(sum(call.args[1]=='cat-file' for call in calls.call_args_list),1)
        self.assertTrue(all(call.kwargs['local_objects_only'] for call in calls.call_args_list))
        self.assertFalse(any(call.args[1]=='status' for call in calls.call_args_list))
        self.assertNotIn('example.invalid',json.dumps(result));self.assertNotIn('Synthetic',json.dumps(result))
    def test_empty_scope_and_exhausted_budget_do_not_call_git(self):
        with patch.object(age,'read_git',side_effect=AssertionError('no Git')):
            self.assertEqual(age.collect_line_ages(self.repo,{'rows':[]},{},self.ref,observed_at=OBSERVED),[])
            result=age.collect_line_ages(self.repo,self.report(),self.sources,self.ref,observed_at=OBSERVED,budget_s=0)
        self.assertEqual({row['reason'] for row in result},{'BUDGET_EXHAUSTED'})
    def test_head_changes_during_collection_invalidate_all_ages(self):
        original=age.read_git;head_reads=0
        def changing(repo,*args,**kwargs):
            nonlocal head_reads
            result=original(repo,*args,**kwargs)
            if args==('rev-parse','--verify','HEAD^{commit}'):
                head_reads+=1
                if head_reads==2:result.stdout='f'*40+'\n'
            return result
        with patch.object(age,'read_git',side_effect=changing):
            result=age.collect_line_ages(self.repo,self.report(),self.sources,self.ref,observed_at=OBSERVED)
        self.assertEqual({row['reason'] for row in result},{'HEAD_CHANGED'});self.assertTrue(all(row['changed_at'] is None for row in result))
    def test_malformed_batch_never_becomes_known_age(self):
        original=age.read_git
        def malformed(repo,*args,**kwargs):
            result=original(repo,*args,**kwargs)
            if args==('cat-file','--batch'):result.stdout=b'bad batch\n'
            return result
        with patch.object(age,'read_git',side_effect=malformed):
            result=age.collect_line_ages(self.repo,self.report(),self.sources,self.ref,observed_at=OBSERVED)
        self.assertTrue(all(row['status']=='unknown' for row in result))
    def test_local_objects_environment_strips_overlays_and_denies_transports(self):
        hostile={'GIT_DIR':'/hostile','GIT_WORK_TREE':'/hostile','GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'protocol.allow','GIT_CONFIG_VALUE_0':'always','SECRET_CANARY':'private'}
        with patch.dict(os.environ,hostile),patch.object(gitread.subprocess,'run') as run:
            gitread.git(self.repo,'cat-file','--batch',text=False,input_data=b'a\n',local_objects_only=True)
        kwargs=run.call_args.kwargs;argv=run.call_args.args[0]
        self.assertEqual(kwargs['env']['GIT_NO_LAZY_FETCH'],'1');self.assertEqual(kwargs['env']['GIT_NO_REPLACE_OBJECTS'],'1')
        self.assertEqual(kwargs['env']['GIT_ALLOW_PROTOCOL'],'');self.assertIn('protocol.allow=never',argv)
        self.assertIn('--no-replace-objects',argv);self.assertIn('--literal-pathspecs',argv)
        for key in hostile:self.assertNotIn(key,kwargs['env'])
        self.assertEqual(kwargs['input'],b'a\n')

if __name__=='__main__':unittest.main()
