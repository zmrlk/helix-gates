"""Offline version fidelity fixtures; no installations or live services."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_runtime import FakeExecutor, TOOLS, FIX
import helix_runtime as rt

class RoundSevenTests(unittest.TestCase):
    def target(self, files):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,content in files.items():
                path=root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(content)
            return rt.database_target(root)

    def test_repository_fixtures(self):
        for name,text,major in [('compose.yml','services:\n  db:\n    image: postgres:15-alpine',15),('infra/main.tf','resource "aws_db_instance" "db" {\n engine = "postgres"\n engine_version = "14.9"\n}',14),('.github/workflows/test.yml','services:\n  postgres:\n    image: postgres:16',16)]:
            with self.subTest(name=name):
                target=self.target({name:text})
                self.assertEqual(target['major'],major)
                self.assertEqual(target['tag'],'VERIFIED')
                self.assertTrue(target['evidence'][0]['line'])

    def test_conflict_and_absent_evidence(self):
        self.assertTrue(self.target({'compose.yml':'image: postgres:15','.github/workflows/ci.yml':'image: postgres:16'})['conflict'])
        target=self.target({})
        self.assertEqual(target['major'],16)
        self.assertEqual(target['tag'],'ASSUMPTION')
        self.assertTrue(target['assumption'])

    def test_extensions_and_minimum(self):
        target=self.target({'schema.sql':'CREATE EXTENSION vector;\nMERGE INTO items USING other ON false;','compose.yml':'image: postgres:16'})
        self.assertEqual(target['image'],'pgvector/pgvector:pg16')
        self.assertTrue(self.target({'schema.sql':'NULLS NOT DISTINCT','compose.yml':'image: postgres:14'})['conflict'])

    def test_darwin_instruction(self):
        self.assertIn('uruchom Docker Desktop',rt.backend_instruction({},16,'darwin'))
        self.assertIn('podman machine start',rt.backend_instruction({'podman':'podman'},16,'darwin'))

    def test_actual_mismatch_degrades_and_warns(self):
        class VersionExecutor(FakeExecutor):
            def run(self,argv,*args):
                if argv[-1]=='SHOW server_version': return 0,'14.12\n'
                return super().run(argv,*args)
        with tempfile.TemporaryDirectory() as directory:
            runner=rt.Runner(FIX/'project-runner',Path(directory)/'out',engine='native',executor=VersionExecutor(),tools={'tools':dict(TOOLS)},port_factory=lambda:31234,allow_version_mismatch=True)
            report=runner.run()
            self.assertFalse(report['database_fidelity']['compatible'])
            self.assertEqual(report['parts'][0]['checks']['schema-apply']['status'],'DEGRADED')
            self.assertIn('WARN:',(runner.out/'runtime.md').read_text().split('Część:')[0])
            rt.validate_report(report)

    def test_audit_degraded_no_credit(self):
        import helix_pro
        with tempfile.TemporaryDirectory() as directory:
            runner=rt.Runner(FIX/'sveltekit-pg',Path(directory)/'out',executor=FakeExecutor(),tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
            runner.run()
            path=runner.out/'runtime-report.json'
            report=json.loads(path.read_text())
            report.pop('controls')
            for part in report['parts']:
                for check in ('schema-apply','load','backup'):
                    part['checks'][check]['status']='DEGRADED'
            report['database_fidelity']['compatible']=False
            path.write_text(json.dumps(report))
            maturity=helix_pro.assess(FIX/'sveltekit-pg','XL')
            rt.import_evidence(maturity,path,FIX/'sveltekit-pg')
            items={i['id']:i for a in maturity['areas'].values() for i in a['requirements']}
            for key in ('load','restore','backup-policy'):
                self.assertEqual(items[key]['status'],'DEGRADED')
                self.assertFalse(items[key]['satisfied'])
            self.assertFalse(maturity['database_fidelity']['compatible'])
