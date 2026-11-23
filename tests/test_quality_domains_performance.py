"""Linear evidence locations preserve full line coverage in large sources."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

BIN = Path(__file__).resolve().parents[1] / 'bin'
sys.path.insert(0, str(BIN))
from helix_quality_domains import analyze, located_matches


class DomainLocationsTests(unittest.TestCase):
    def test_multiline_locations_and_same_line_evidence_are_unique(self):
        text = 'unit unit\r\nżółć\nunit\n'
        self.assertEqual([line for _, line in located_matches('unit', text)], [1, 1, 3])
        data = analyze({'sample.txt': text})
        check = next(row for row in data['checks'] if row['id'] == 'test-pyramid')
        self.assertEqual(check['evidence'], ['sample.txt:1', 'sample.txt:3'])
        self.assertEqual(check['score'], 0)
        self.assertEqual(check['status'], 'not-run')

    def test_repeated_signals_retain_last_line_without_prefix_rescans(self):
        code = '''import sys,json
sys.path.insert(0,sys.argv[1])
from helix_quality_domains import analyze
data=analyze({'sample.txt':'unit unit integration e2e\\n'*50000})
row=next(r for r in data['checks'] if r['id']=='test-pyramid')
print(json.dumps([len(row['evidence']),row['evidence'][0],row['evidence'][-1],row['score']]))
'''
        result = subprocess.run([sys.executable, '-c', code, str(BIN)],
                                capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(json.loads(result.stdout), [50000, 'sample.txt:1', 'sample.txt:50000', 0])


if __name__ == '__main__':
    unittest.main()
