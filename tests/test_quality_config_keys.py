"""Repeated configuration records retain typo signals without quadratic work."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

BIN = Path(__file__).resolve().parents[1] / 'bin'
sys.path.insert(0, str(BIN))
from helix_quality import config_checks


class ConfigKeysTests(unittest.TestCase):
    def test_similar_spelling_after_repetitions_and_negative_control(self):
        text = '{"billingAddress":1,"billingAddress":2,"billingAdress":3,"billingAddress":4,"billingAddress":5,"status":6}'
        rows = []
        config_checks({'settings.json': text}, rows)
        self.assertEqual([row['id'] for row in rows], ['PREC-KEY', 'PREC-KEY'])
        self.assertEqual(len({row['source_offset'] for row in rows}), 2)
        clean = []
        config_checks({'settings.json': '{"status":1,"quantity":2,"status":3}'}, clean)
        self.assertEqual(clean, [])

    def test_large_repeated_records_finish_with_bounded_findings(self):
        code = '''import sys,json
sys.path.insert(0,sys.argv[1])
from helix_quality import config_checks
text = '{"rows":[' + ','.join(['{"alphaValue":1,"quantity":2,"status":3}'] * 10000) + '],"alphaValu":1,"alphaValue":1}'
rows=[]
config_checks({'records.json':text},rows)
print(json.dumps([r['id'] for r in rows]))
'''
        result = subprocess.run([sys.executable, '-c', code, str(BIN)],
                                capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(json.loads(result.stdout), ['PREC-KEY', 'PREC-KEY'])


if __name__ == '__main__':
    unittest.main()
