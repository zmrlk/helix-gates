"""Kalibracja lokalnych narzędzi i kontraktów parserów bez sieci."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_tool_adapters as a


class ToolAdapters(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'sample.sh').write_text('#!/bin/sh\necho "$HOME"\n')

    def test_registry_and_unavailable(self):
        self.assertGreaterEqual(len(a.REGISTRY), 45)
        with patch.object(a, 'locate', return_value=None):
            self.assertEqual(a.scan(self.root, 'semgrep')['status'], 'unavailable')
        for spec in a.REGISTRY.values():
            for key in ('license', 'perspectives', 'area', 'catches', 'offline', 'parser', 'timeout'):
                self.assertIn(key, spec)

    def test_parser_samples(self):
        samples = {
            'shellcheck': [{'file':'sample.sh','line':2,'code':2086,'level':'info'}],
            'hadolint': [{'file':'sample.sh','line':2,'code':'DL3006','level':'warning'}],
            'bandit': {'results':[{'filename':'sample.sh','line_number':2,'test_id':'B602','issue_severity':'HIGH'}]},
        }
        for name, sample in samples.items():
            with self.subTest(name=name):
                rows = a.parse(name, json.dumps(sample), self.root)
                self.assertEqual(rows[0]['line'], 2)
                self.assertEqual(rows[0]['confidence'], 'possible')
                self.assertTrue(rows[0]['why']); self.assertTrue(rows[0]['fix_hint'])
        for name in ('actionlint', 'typos'):
            raw = json.dumps({'path':'sample.sh','line_num':2,'location':{'path':'sample.sh','line':2},'secret':'sensitive-output'})
            self.assertNotIn('sensitive-output', json.dumps(a.parse(name, '[' + raw + ']' if name == 'actionlint' else raw, self.root)))
        self.assertEqual(a.parse('codespell', 'sample.sh:2: spelling\n', self.root)[0]['line'], 2)

    def test_recorded_output_samples(self):
        samples = json.loads((Path(__file__).parent / 'fixtures/tool-adapters/output-samples.json').read_text())
        self.assertEqual(set(samples), set(a.ARGS))
        for name, raw in samples.items():
            with self.subTest(name=name):
                result = a.parse(name, raw, self.root)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]['file'], 'sample.sh')
                self.assertEqual(result[0]['line'], 2)

    def test_same_rule_at_distinct_lines_is_preserved(self):
        raw = json.dumps([{'file': 'sample.sh', 'line': line, 'code': 2086} for line in (1, 2)])
        self.assertEqual([r['line'] for r in a.parse('shellcheck', raw, self.root)], [1, 2])

    def test_partial_scan_never_completes(self):
        for name, value in [('bandit', {'results': [], 'errors': ['incomplete']}), ('semgrep', {'results': [], 'errors': ['incomplete']}), ('radon', {'sample.sh': {'error': 'parse'}}), ('stylelint', [{'warnings': [], 'parseErrors': ['parse']}])]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.parse(name, json.dumps(value), self.root)

    def test_invalid_and_outside_output(self):
        for raw in ('{}', 'invalid', '[{}]', '[{"file":"../outside","line":1}]'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, KeyError)):
                a.parse('shellcheck', raw, self.root)

    def test_copy_timeout_and_no_credentials(self):
        def execute(argv, **kw):
            self.assertNotEqual(kw['cwd'], self.root)
            self.assertNotIn('PRIVATE_CREDENTIAL', kw['env'])
            self.assertFalse((kw['cwd'] / '.env').exists())
            (kw['cwd'] / 'sample.sh').write_text('changed')
            raise subprocess.TimeoutExpired(argv, 1)
        (self.root / '.env').write_text('private-placeholder')
        with patch.object(a, 'locate', return_value='/bin/false'), patch.object(a.subprocess, 'run', side_effect=execute):
            self.assertEqual(a.scan(self.root, 'shellcheck', 1)['status'], 'timeout')
        self.assertIn('echo', (self.root / 'sample.sh').read_text())

    def test_skip_is_not_na(self):
        with patch.object(a, 'locate', return_value='/bin/false'):
            self.assertEqual(a.scan(self.root, 'grype')['status'], 'not-run')
            (self.root / 'sample.sh').unlink()
            self.assertEqual(a.scan(self.root, 'shellcheck')['status'], 'not-applicable')

    @unittest.skipUnless(os.environ.get('HELIX_TOOL_INTEGRATION') == '1', 'kalibracja programów zewnętrznych wymaga HELIX_TOOL_INTEGRATION=1')
    def test_jscpd_and_radon_calibration(self):
        for name in ('jscpd', 'radon'):
            with self.subTest(name=name):
                if not a.locate(name): self.skipTest('brak programu ' + name)
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    if name == 'jscpd':
                        code = 'function calculate(value) {\n' + ''.join(f'  const value{i} = value + {i};\n' for i in range(15)) + '  return value14;\n}\n'
                        p = root / 'first.js'; p.write_text(code)
                        second = root / 'second.js'; second.write_text(code)
                    else:
                        p = root / 'sample.py'
                        p.write_text('def calculate(value):\n' + ''.join(f'    if value == {i}: return {i}\n' for i in range(12)) + '    return 0\n')
                    result = a.scan(root, name)
                    self.assertEqual(result['status'], 'completed', result)
                    self.assertTrue(result['findings'], result)
                    if name == 'jscpd': second.write_text('export const title = "example";\n')
                    else: p.write_text('def calculate(value):\n    return value + 1\n')
                    result = a.scan(root, name)
                    self.assertEqual(result['status'], 'completed', result)
                    self.assertEqual(result['findings'], [], result)

    @unittest.skipUnless(os.environ.get('HELIX_TOOL_INTEGRATION') == '1', 'kalibracja programów zewnętrznych wymaga HELIX_TOOL_INTEGRATION=1')
    def test_gitleaks_synthetic_marker(self):
        if not a.locate('gitleaks'): self.skipTest('brak programu gitleaks')
        (self.root / '.gitleaks.toml').write_text('title = "Calibration"\n[[rules]]\nid = "synthetic-marker"\ndescription = "Synthetic non-credential marker"\nregex = "HELIX_CALIBRATION_[M]ARKER"\n')
        p = self.root / 'fixture.txt'; p.write_text('HELIX_CALIBRATION_MARKER\n')
        argv = list(a.ARGS['gitleaks'])
        argv[argv.index('--config') + 1] = str(self.root / '.gitleaks.toml')
        with patch.dict(a.ARGS, {'gitleaks': argv}):
            result = a.scan(self.root, 'gitleaks')
        self.assertEqual(result['status'], 'completed', result)
        self.assertTrue(result['findings'])
        self.assertNotIn('HELIX_CALIBRATION_MARKER', json.dumps(result))
        p.write_text('ordinary text\n')
        argv = list(a.ARGS['gitleaks'])
        argv[argv.index('--config') + 1] = str(self.root / '.gitleaks.toml')
        with patch.dict(a.ARGS, {'gitleaks': argv}):
            result = a.scan(self.root, 'gitleaks')
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result['findings'], [])

    @unittest.skipUnless(os.environ.get('HELIX_TOOL_INTEGRATION') == '1', 'kalibracja programów zewnętrznych wymaga HELIX_TOOL_INTEGRATION=1')
    def test_calibration_installed_tools(self):
        cases = {
            'checkov': ('main.tf', 'resource "aws_s3_bucket" "test" {\n  bucket = "example-bucket"\n}\n', 'locals {\n  example = 1\n}\n'),
            'squawk': ('sample.sql', 'DROP TABLE users;\n', 'SELECT 1;\n'),
            'sqlfluff': ('sample.sql', 'select  a  from t;\n', 'SELECT a FROM t;\n'),
            'stylelint': ('sample.css', 'a { color: #xyz; }\n', 'a { color: #fff; }\n'),
            'zizmor': ('.github/workflows/test.yml', 'name: test\non: pull_request_target\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n', 'name: test\non: push\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n'),
            'semgrep': ('sample.py', 'eval(input())\n', 'print(1)\n'),
            'bandit': ('sample.py', 'eval(input())\n', 'print(1)\n'),
            'shellcheck': ('sample.sh', '#!/bin/sh\necho $1\n', '#!/bin/sh\necho "$1"\n'),
            'hadolint': ('Dockerfile', 'FROM ubuntu\nRUN cd /tmp\n', 'FROM alpine:3.20\nWORKDIR /app\n'),
            'codespell': ('text.txt', 'This is teh example.\n', 'This is the example.\n'),
            'typos': ('text.txt', 'This is teh example.\n', 'This is the example.\n'),
            'actionlint': ('.github/workflows/test.yml', 'name: test\non: push\njobs:\n  test:\n    runs-on: imaginary-runner\n    steps:\n      - run: echo ok\n', 'name: test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n'),
        }
        for name, (file, bad, clean) in cases.items():
            with self.subTest(name=name):
                if not a.locate(name):
                    # Each missing executable is explicitly reported as a subtest skip.
                    self.skipTest('brak programu ' + name)
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp); p = root / file; p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(bad)
                    result = a.scan(root, name)
                    self.assertEqual(result['status'], 'completed', result)
                    self.assertTrue(result['findings'], result)
                    p.write_text(clean)
                    result = a.scan(root, name)
                    self.assertEqual(result['status'], 'completed', result)
                    self.assertEqual(result['findings'], [], result)
