"""Explicit runner only: python3 tests/integration/test_runtime_it.py (no __init__.py)."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]

class RuntimeIntegration(unittest.TestCase):
    def test_fixtures(self):
        self.assertEqual(os.environ.get('HELIX_RUNTIME_IT'),'1','Use scripts/run_runtime_it.sh explicitly')
        for fixture in ('sveltekit-pg','next-pg','monorepo-split-db','needs-oidc','flyway-style','dbmate-style','snapshot+migrations-duplicate','oidc-https-app','project-runner','oidc-dynamic-private'):
            with self.subTest(fixture=fixture), tempfile.TemporaryDirectory() as directory:
                output=Path(directory)/'report'
                result=subprocess.run([str(ROOT/'bin/helix'),'runtime','run','--project',str(ROOT/'tests/fixtures/runtime'/fixture),'--out',str(output)]+(['--no-oidc-stub'] if fixture=='needs-oidc' else []),capture_output=True,text=True,timeout=1900)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                report=json.loads((output/'runtime-report.json').read_text())
                self.assertTrue(report['parts'])
                self.assertEqual(report['controls'],[dict(check,id=name,part=part['name']) for part in report['parts'] for name,check in part['checks'].items()])
                for part in report['parts']:
                    self.assertEqual(part['checks']['backup']['status'],'PASS',part['checks']['backup'])
                    if fixture=='monorepo-split-db':
                        self.assertEqual(part['checks']['schema-apply']['status'],'FAIL')
                        self.assertEqual(part['checks']['schema-apply']['metrics']['failed'],1)
                        self.assertEqual(part['checks']['schema-apply']['metrics']['applied'],2)
                    if fixture in ('flyway-style','dbmate-style','snapshot+migrations-duplicate','oidc-https-app','project-runner','oidc-dynamic-private'):
                        self.assertEqual(part['checks']['schema-apply']['status'],'PASS',part['checks']['schema-apply'])
                        self.assertEqual(part['checks']['e2e']['status'],'PASS',part['checks']['e2e'])
                    if fixture=='needs-oidc':
                        self.assertEqual(part['checks']['e2e']['status'],'BLOCKED')
                        self.assertIn('OIDC_ISSUER discovery',part['checks']['e2e']['reason'])
                    for check in part['checks'].values():
                        self.assertIn(check['status'],('PASS','FAIL','BLOCKED') if fixture=='needs-oidc' else ('PASS','FAIL'),check)
                        self.assertTrue((output/check['log']).is_file())

if __name__=='__main__': unittest.main()
