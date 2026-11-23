"""Large documentation ledgers must not scan all paths for unrelated IDs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BIN = Path(__file__).resolve().parents[1] / 'bin'
sys.path.insert(0, str(BIN))
from helix_static_security import analyze


class ClaimCostTests(unittest.TestCase):
    def test_classified_and_unknown_claims_keep_distinct_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = [('app.ts', 'const value = 1;'), ('audit.md', 'FINDING-1 SEC-SSRF app.ts\nFINDING-2 unrelated app.ts\n')]
            report = analyze(Path(tmp), source_snapshot=files)
            self.assertEqual([r['status'] for r in report['reported_findings']], ['likely-fixed', 'unknown'])

    def test_unrelated_ids_finish_without_repository_wide_reconciliation(self):
        code = '''import sys,json,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from helix_static_security import analyze
files=[('src/file'+str(i)+'.ts','const value = 1;') for i in range(4000)]
files.append(('ledger.md','\\n'.join('NOTE-'+str(i)+' unclassified reference src/file0.ts' for i in range(500))))
with tempfile.TemporaryDirectory() as tmp:
 report=analyze(Path(tmp),source_snapshot=files)
 print(json.dumps([len(report['reported_findings']),sorted({r['status'] for r in report['reported_findings']})]))
'''
        result = subprocess.run([sys.executable, '-c', code, str(BIN)], capture_output=True,
                                text=True, timeout=10, check=True)
        self.assertEqual(json.loads(result.stdout), [500, ['unknown']])


if __name__ == '__main__':
    unittest.main()
