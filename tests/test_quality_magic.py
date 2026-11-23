"""READ-MAGIC: jeden wpis na plik produktu; dane testów i SQL nie są stałymi do nazwania."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_quality as quality


class Magic(unittest.TestCase):
    def rows(self, sources):
        with tempfile.TemporaryDirectory() as repo:
            report = quality.analyze(repo, sources=sources)
        return [row for row in report['findings'] if row['id'] == 'READ-MAGIC']

    def test_one_low_finding_per_product_file_with_line_count(self):
        code = 'export function limit(x) {\n  if (x > 2500) return 3600;\n  return x * 86400;\n}\n'
        rows = self.rows({'src/limit.ts': code})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['severity'], 'low')
        self.assertEqual(rows[0]['line'], 2)
        self.assertIn('w pliku: 2', rows[0]['why'])

    def test_tests_fixtures_and_sql_are_not_reported(self):
        code = 'const kwota = 12345;\n'
        rows = self.rows({'src/a.test.ts': code, 'tests/helper.ts': code, 'app/test_money.py': 'KWOTA_X = 1\nx = 12345\n',
                          'database/migrations/001_init.sql': 'INSERT INTO t VALUES (12345);\n', 'src/fixtures/dane.ts': code})
        self.assertEqual(rows, [])

    def test_named_constant_stays_silent(self):
        self.assertEqual(self.rows({'src/c.ts': 'const SECONDS_PER_DAY = 86400;\n'}), [])


if __name__ == '__main__':
    unittest.main()
