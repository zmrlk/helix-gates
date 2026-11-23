"""Synthetic stack fixtures; no network, providers or target execution."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_quality as quality
import helix_source_coverage as coverage


class QualityStage2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)

    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def test_large_file_tail_and_chunks(self):
        self.write('large.ts', '// filler\n' * 600000 + 'const amount = parseFloat("12,34");\n')
        data = quality.analyze(self.root)
        self.assertEqual(data['coverage']['files_read'], 1)
        self.assertEqual(data['coverage']['lines_read'], 600001)
        findings = [f for f in data['findings'] if f['id'] == 'PREC-DECIMAL']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['line'], 600001)
        self.assertEqual(data['model']['status'], 'not-run')

    def test_stacks_precision_and_negative_controls(self):
        vulnerable = {
            'src/routes/+page.svelte': '<script>const amount = parseFloat("12,34");</script>',
            'pages/index.tsx': 'const price = Number("12,34");',
            'app.py': 'from datetime import datetime\namount = float("12,34")\nnow = datetime.now()\n',
        }
        for name, text in vulnerable.items(): self.write(name, text)
        self.write('safe.ts', 'const amountCents = 1234;\nconst date = new Date("2026-01-01T12:00:00Z");\n')
        data = quality.analyze(self.root)
        actual = {f['file'] for f in data['findings'] if f['id'] == 'PREC-DECIMAL'}
        self.assertEqual(actual, set(vulnerable))  # detection 3/3; false positives 0/1
        self.assertFalse(any(f['file'] == 'safe.ts' and f['id'].startswith('PREC-') for f in data['findings']))
        for f in data['findings']:
            self.assertTrue(f['why'] and f['fix'] and f['severity'] and f['confidence'])

    def test_inventory_ignored_untracked_private_binary_generated(self):
        self.write('.gitignore', 'ignored.txt\n')
        self.write('ignored.txt', 'ignored')
        self.write('untracked.unknown', 'all text\n')
        self.write('generated.js', '// @generated\nconst n = 1;\n')
        self.write('.env', 'REDACTED_FIXTURE')
        (self.root/'image.bin').write_bytes(b'\0image')
        sources, data = coverage.scan(self.root)
        self.assertIn('untracked.unknown', sources)
        self.assertNotIn('ignored.txt', sources)
        self.assertNotIn('.env', sources)
        self.assertEqual(data['status'], 'INCOMPLETE')
        rows = {r['file']:r for r in data['files']}
        self.assertEqual(rows['generated.js']['category'], 'generated')
        self.assertEqual(rows['image.bin']['category'], 'binary')
        self.assertTrue(all(r['reason'] for r in rows.values() if r['status'] == 'skipped'))

    def test_units_ranges_timezone_and_money(self):
        self.write('app.py', 'timeout_ms = timeout_seconds\nif index <= count: pass\nnow = datetime.now()\namount = float(value)\n')
        self.write('migration.sql', 'CREATE TABLE bill (price DOUBLE PRECISION);')
        ids = {f['id'] for f in quality.analyze(self.root)['findings']}
        self.assertTrue({'PREC-UNIT','PREC-RANGE','PREC-TZ','PREC-MONEY','PREC-SQL-MONEY'} <= ids)

    def test_i18n_and_near_keys(self):
        self.write('locales/en.json', json.dumps({'title':'Hello {name}.','billingAddress':'a','billingAdress':'b'}))
        self.write('locales/pl.json', json.dumps({'title':'Witaj {user} ','billingAddress':'a'}))
        ids = {f['id'] for f in quality.analyze(self.root)['findings']}
        self.assertTrue({'PREC-KEY','PREC-I18N-KEY','PREC-I18N-COPY'} <= ids)

    def test_readability_thresholds_and_packet(self):
        self.write('app.py', 'def x(v):\n' + ''.join('    if v == '+str(i)+': return v\n' for i in range(20)))
        sources, cov = coverage.scan(self.root)
        data = quality.analyze(self.root, sources=sources, coverage=cov)
        self.assertIn('READ-CYCLOMATIC', {f['id'] for f in data['findings']})
        packet = quality.model_packet(sources)
        self.assertEqual(packet['execution_credit'], 0)
        self.assertIn('output_contract', packet)

    def test_migration_columns_and_safe_query(self):
        self.write('migrations/001.sql', 'CREATE TABLE invoices (id INTEGER, amount NUMERIC);')
        self.write('bad.py', 'query = "SELECT ammount FROM invoices"')
        self.write('safe.py', 'query = "SELECT amount FROM invoices"')
        findings = [f for f in quality.analyze(self.root)['findings'] if f['id'] == 'PREC-COLUMN']
        self.assertEqual([f['file'] for f in findings], ['bad.py'])

    def test_shared_readers_keep_large_tail_and_multiline(self):
        from helix_audit_context import safe_read
        from helix_runtime import read
        from helix_security_deep import source_context, context_plan
        self.write('large.ts', '// filler\n' * 230000 + 'const amount = parseFloat(\n"12,34");\n')
        raw = safe_read(self.root/'large.ts')
        self.assertTrue(read(self.root/'large.ts').endswith('"12,34");\n'))
        source, omitted = source_context(self.root, ['.'], 'quick')
        self.assertFalse(omitted)
        self.assertIn('"12,34"', source)
        batches, ledger = context_plan(self.root, ['.'], 'quick')
        self.assertGreater(len(batches), 1)
        self.assertTrue(any('"12,34"' in window for window, _ in batches))
        self.assertTrue(all(row['status'] == 'planned' for row in ledger))
        found = quality.analyze(self.root)['findings']
        self.assertEqual(len([f for f in found if f['id'] == 'PREC-DECIMAL']), 1)

    def test_profile_override_is_used_and_validated(self):
        self.write('app.py', 'def work(v):\n    if v: return 1\n    return 0\n')
        self.write('helix.json', json.dumps({'quality_profiles': {'S': {'cyclomatic': 1}}}))
        self.assertIn('READ-CYCLOMATIC', {f['id'] for f in quality.analyze(self.root)['findings']})
        self.write('helix.json', json.dumps({'quality_profiles': {'S': {'cyclomatic': 50}}}))
        self.assertNotIn('READ-CYCLOMATIC', {f['id'] for f in quality.analyze(self.root)['findings']})
        self.write('helix.json', json.dumps({'quality_profiles': {'S': {'cyclomatic': 0}}}))
        with self.assertRaises(ValueError): quality.analyze(self.root)

    def test_budget_is_incomplete_and_not_na(self):
        self.write('app.ts', 'const value = 1;')
        sources, cov = coverage.scan(self.root, time_budget_seconds=0)
        self.assertEqual(sources, {})
        self.assertEqual(cov['status'], 'INCOMPLETE')
        self.assertIn('time budget', cov['files'][0]['reason'])

    def test_audit_exports_coverage_and_quality(self):
        import helix_new
        self.write('app.py', 'amount = float("12,34")')
        with tempfile.TemporaryDirectory() as output:
            out = Path(output)/'audit'
            helix_new.audit(self.root, out, profile='S')
            cov = json.loads((out/'coverage.json').read_text())
            report = json.loads((out/'quality.json').read_text())
            self.assertEqual(cov['files_read'], 1)
            self.assertIn('PREC-DECIMAL', {f['id'] for f in report['findings']})
            self.assertIn('Pokrycie odczytu', (out/'audit.md').read_text())
            self.assertEqual(json.loads((out/'readability-model-tasks.json').read_text())['status'], 'not-run')
            self.assertEqual((self.root/'app.py').read_text(), 'amount = float("12,34")')

    def test_overlap_and_symlink(self):
        self.write('plain.txt', 'read me')
        (self.root/'link.txt').symlink_to(self.root/'plain.txt')
        _, data = coverage.scan(self.root)
        self.assertEqual(data['status'], 'INCOMPLETE')
        windows = list(coverage.chunks('a'*100, 20, 5))
        self.assertEqual(windows[1][0], 15)


if __name__ == '__main__': unittest.main()
