"""Existing quality/new/status wiring, with no models, application or network."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_new
import helix_quality
import helix_source_coverage
import helix_ponytail_age as age
import helix_security_status as status

class PonytailPipeline(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.repo=self.base/'repo';self.repo.mkdir();self.out=self.base/'out';self.state=self.base/'state'
        self.env={'PATH':os.environ['PATH'],'HOME':str(self.base),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
                  'GIT_AUTHOR_NAME':'Fixture','GIT_AUTHOR_EMAIL':'test@example.invalid','GIT_COMMITTER_NAME':'Fixture','GIT_COMMITTER_EMAIL':'test@example.invalid',
                  'GIT_AUTHOR_DATE':'2026-10-20T12:00:00+00:00','GIT_COMMITTER_DATE':'2026-10-20T12:00:00+00:00'}
        self.git('init','-q')
        self.text='# ponytail: one worker, upgrade after measurement\nvalue = 1\n'
        (self.repo/'app.py').write_text(self.text)
        self.git('add','app.py');self.git('commit','-qm','synthetic debt')
        self.head=self.git('rev-parse','HEAD').strip()
    def git(self,*args):
        result=subprocess.run(['git','-c','core.hooksPath='+os.devnull,*args],cwd=self.repo,env=self.env,text=True,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr);return result.stdout
    def quality(self,complete=True):
        sources,coverage=helix_source_coverage.scan(self.repo)
        if not complete:coverage['status']='INCOMPLETE'
        value=helix_quality.analyze(self.repo,sources=sources,coverage=coverage,observed_at='2026-10-26T12:00:00+00:00')
        value.update(target=str(self.repo),provenance={'target_head':self.head,'target_dirty':False})
        self.out.mkdir(exist_ok=True);path=self.out/'quality.json';path.write_text(json.dumps(value));return value,path
    def test_quality_reuses_sources_and_leaves_model_packet_not_run(self):
        sources,coverage=helix_source_coverage.scan(self.repo)
        with patch.object(helix_quality,'scan',side_effect=AssertionError('second source scan')):
            result=helix_quality.analyze(self.repo,sources=sources,coverage=coverage,observed_at='2026-10-26T12:00:00+00:00')
        self.assertEqual(result['ponytail_debt']['counts']['markers'],1)
        self.assertEqual(result['execution_credit'],0);self.assertEqual(result['model']['status'],'not-run')
        self.assertEqual(helix_quality.model_packet(sources)['status'],'not-run')
    def test_new_audit_saves_same_debt_identity_and_external_summary(self):
        with patch.object(socket,'socket',side_effect=AssertionError('no network')),patch.object(helix_quality,'scan',side_effect=AssertionError('no debt rescan')):
            lines=helix_new.audit(self.repo,self.out,profile='S',state_dir=self.state,offline=True)
        quality=json.loads((self.out/'quality.json').read_text());audit=json.loads((self.out/'audit.json').read_text())
        self.assertEqual(quality['ponytail_debt'],audit['quality']['ponytail_debt'])
        self.assertEqual(quality['ponytail_debt']['observed_at'],audit['provenance']['generated_at'])
        self.assertEqual(quality['ponytail_debt']['counts']['age_known'],1)
        self.assertTrue(any('Ponytail debt:' in line for line in lines))
        view=age.read_debt_summary(self.repo,self.state,{'head':self.head,'dirty':False})
        self.assertEqual(view['status'],'CURRENT');self.assertEqual(view['counts']['markers'],1)
        self.assertEqual(self.git('status','--porcelain'),'')
        self.assertFalse((self.repo/'helix.json').exists())
    def test_status_only_reads_exact_summary_and_never_scans_or_blames(self):
        value,path=self.quality();age.write_debt_summary(self.repo,self.state,path)
        with patch.object(status,'read_ref',return_value={'head':self.head,'dirty':False,'dirty_reason':'fixture','status':'recorded'}),patch.object(age,'read_git',side_effect=AssertionError('no age Git')),patch.object(helix_source_coverage,'scan',side_effect=AssertionError('no scan')):
            data=status.report(self.repo,self.state)
        self.assertEqual(data['status'],'NO_BASELINE')
        self.assertEqual(data['ponytail_debt']['status'],'CURRENT')
        text=status.text_report(data);self.assertIn('app.py:1',text);self.assertIn('wiek przy odczycie',text);self.assertIn('CURRENT',text)
        historical=copy.deepcopy(data);historical['ponytail_debt'].update(status='STALE',counts=None)
        text=status.text_report(historical);self.assertIn('HISTORY (STALE) app.py:1',text);self.assertIn('wiek przy odczycie',text)
        self.assertIn('2026-10-26T12:00:00+00:00',text)
        self.assertEqual(status.text_report(data,reminder_only=True).count('\n'),1)
    def test_incomplete_tampered_and_wrong_revision_never_current(self):
        _,path=self.quality(False);age.write_debt_summary(self.repo,self.state,path)
        self.assertEqual(age.read_debt_summary(self.repo,self.state,{'head':self.head,'dirty':False})['status'],'INCOMPLETE')
        value,path=self.quality();age.write_debt_summary(self.repo,self.state,path)
        stale=age.read_debt_summary(self.repo,self.state,{'head':'a'*40,'dirty':False})
        self.assertEqual(stale['status'],'STALE');self.assertIsNone(stale['counts'])
        value['ponytail_debt']['counts']['markers']=999;path.write_text(json.dumps(value))
        unknown=age.read_debt_summary(self.repo,self.state,{'head':self.head,'dirty':False})
        self.assertEqual(unknown['status'],'UNKNOWN');self.assertIsNone(unknown['last_observation'])
    def test_malformed_artifact_types_remain_unknown_even_with_matching_hash(self):
        value,path=self.quality();age.write_debt_summary(self.repo,self.state,path)
        pointer=age.debt_summary_path(self.repo,self.state);summary=json.loads(pointer.read_text())
        bad_provenance=copy.deepcopy(value);bad_provenance['provenance']=[]
        for malformed in ([],bad_provenance):
            with self.subTest(kind=type(malformed).__name__):
                raw=json.dumps(malformed);path.write_text(raw)
                summary['artifact_sha256']=hashlib.sha256(raw.encode()).hexdigest();pointer.write_text(json.dumps(summary))
                result=age.read_debt_summary(self.repo,self.state,{'head':self.head,'dirty':False})
                self.assertEqual(result['status'],'UNKNOWN');self.assertIsNone(result['last_observation'])
                with self.assertRaises(ValueError):age.write_debt_summary(self.repo,self.state,path)
    def test_no_implicit_home_state_and_missing_counts_are_unknown(self):
        _,path=self.quality()
        self.assertIsNone(age.write_debt_summary(self.repo,None,path))
        result=age.read_debt_summary(self.repo,None,{'head':self.head,'dirty':False})
        self.assertEqual(result['status'],'NOT_RUN');self.assertIsNone(result['counts'])
        self.assertFalse(self.state.exists())
    def test_symlink_receipt_is_not_followed_or_rewritten(self):
        _,path=self.quality();age.write_debt_summary(self.repo,self.state,path)
        pointer=age.debt_summary_path(self.repo,self.state);original=pointer.read_bytes();pointer.unlink();outside=self.base/'outside';outside.write_bytes(original);pointer.symlink_to(outside)
        self.assertEqual(age.read_debt_summary(self.repo,self.state,{'head':self.head,'dirty':False})['status'],'UNKNOWN')
        with self.assertRaises(ValueError):age.write_debt_summary(self.repo,self.state,path)
        self.assertEqual(outside.read_bytes(),original)

if __name__=='__main__':unittest.main()
