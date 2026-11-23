"""Dependency hints separate modules, symbols, prose and unsupported syntax."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_import_hints import modules
from helix_platform import system_map


class ImportHintsTests(unittest.TestCase):
    def test_python_imports_are_modules_not_symbols_or_docstrings(self):
        source = '"""import imaginary\nfrom phantom import Name"""\nfrom pydantic import BaseModel\nfrom .helpers import value\nimport json as codec, os.path\n# import prose\n'
        names, reason = modules('app.py', source)
        self.assertEqual(names, {'pydantic', '.helpers', 'json', 'os.path'})
        self.assertIsNone(reason)
        self.assertTrue(modules('broken.py', 'def invalid(')[1])

    def test_js_comments_and_strings_do_not_create_modules(self):
        source = '''// import the library
const guide = "from fiction import something";
/* import {Book} from 'comment'; */
import {Thing as Local} from '@vendor/library';
import 'side-effect';
export {Item} from './shared';
const loaded = require('node:fs');
const lazy = import('./lazy');
'''
        names, reason = modules('main.ts', source)
        self.assertEqual(names, {'@vendor/library', 'side-effect', './shared', 'node:fs', './lazy'})
        self.assertTrue(reason)

    def test_system_map_retains_unknown_syntax_as_explicit_gap(self):
        sources = {'app.py': 'from library import Symbol', 'app.cs': 'using Framework;'}
        inventory = [dict(path=p, evidence=p + ':1', categories=['language:' + Path(p).suffix]) for p in sources]
        report = system_map(inventory, sources)
        self.assertEqual([row['target'] for row in report['dependencies']], ['library'])
        self.assertEqual(report['unresolved'][0]['file'], 'app.cs')
        self.assertEqual(report['tag'], 'ASSUMPTION')


if __name__ == '__main__':
    unittest.main()
