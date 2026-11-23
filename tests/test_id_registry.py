from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_id_registry as R


class IdentifierRegistry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'registry.json'

    def take(self, owner, **kwargs):
        return R.reserve(self.path, kwargs.get('prefix', 'RULE'), kwargs.get('kind', 'rule'), owner, 'validation', kwargs.get('ident'))

    def test_concurrent_authors_get_unique_sequential_reservations(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(lambda n: self.take('worker-'+str(n)), range(16)))
        self.assertEqual(len({r['id'] for r in rows}), 16)
        self.assertEqual({r['id'] for r in rows}, {f'RULE-{n:04d}' for n in range(1,17)})
        self.assertEqual(len(R.read(self.path)['entries']), 16)

    def test_collision_prefix_conflict_and_invalid_owner_do_not_modify_registry(self):
        self.take('alice')
        before = self.path.read_bytes()
        for options in (dict(ident='RULE-0001'), dict(kind='component'), dict(ident='WRONG-0002')):
            with self.assertRaises(ValueError):
                self.take('bob', **options)
            self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(ValueError):
            self.take('')
        self.assertEqual(self.path.read_bytes(), before)

    def test_merge_collision_and_symlink_are_rejected(self):
        self.take('alice')
        data = R.read(self.path)
        data['entries'].append(copy.deepcopy(data['entries'][0]))
        self.path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'duplicate ID'):
            R.read(self.path)
        link = self.root / 'link.json'; link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            R.reserve(link, 'RULE', 'rule', 'bob', 'test')

    def test_cli_reservation_is_persistent_and_check_is_read_only(self):
        command = [sys.executable, str(ROOT/'bin/helix'), '--repo', str(self.root), '--offline', 'new', 'ids']
        result = subprocess.run([*command, 'reserve', '--prefix', 'CMP', '--type', 'component', '--owner', 'test', '--purpose', 'orders'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['result']['id'], 'CMP-0001')
        path = self.root/'helix-id-registry.json'; before = path.read_bytes()
        self.assertEqual(subprocess.run([*command, 'check'], capture_output=True).returncode, 0)
        self.assertEqual(path.read_bytes(), before)
