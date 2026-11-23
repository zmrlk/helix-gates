"""Regresje offline dla kontraktów z bookmarks-scan."""
import argparse
import contextlib
import datetime as dt
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BIN = Path(__file__).resolve().parents[1] / 'bin'
sys.path.insert(0, str(BIN))
from helix_contracts import VERSION
import helix_workflow as w
import helix_packs as packs


class Workflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name); self.state_dir = self.repo / '.helix'; self.state_dir.mkdir()
        self.evidence_root = self.repo / 'helix-evidence'; self.evidence_root.mkdir(); self.cfg = {}
        self.states = {}

    def ev(self, cp):
        p = self.evidence_root / cp; p.mkdir(exist_ok=True); return p

    def state(self, cp): return self.states.get(cp, {'id': cp})
    def save_state(self, st): self.states[st['id']] = st

    def args(self, **kw):
        return argparse.Namespace(**dict(dict(action='new', goal='Napraw filtr', owner='Tester', type='zadanie', recommendation=None, cost=None, impact=None, evidence=None, pr=None, checkpoint=None, human=None, id=None), **kw))

    def quiet(self, fn, a):
        with contextlib.redirect_stdout(io.StringIO()) as out: fn(self, a)
        return out.getvalue()

    def test_tasks_evidence_wip_and_human(self):
        for _ in range(5): self.quiet(w.task, self.args())
        with self.assertRaises(ValueError): w.task(self, self.args())
        t = w.tasks(self)[0][1]
        with self.assertRaises(ValueError): w.task(self, self.args(action='close', id=t['id']))
        outside = self.repo / 'proof'; outside.write_text('ok')
        with self.assertRaises(ValueError): w.task(self, self.args(action='close', id=t['id'], evidence=str(outside)))
        proof = self.evidence_root / 'proof'; proof.write_text('test OK')
        self.quiet(w.task, self.args(action='close', id=t['id'], evidence=str(proof)))
        with self.assertRaises(ValueError): w.task(self, self.args(goal='Migracja bazy'))
        self.quiet(w.task, self.args(goal='Migracja bazy', recommendation='testowa', cost='0', impact='nowy schemat'))
        t = next(t for _, t in w.tasks(self) if t['type'] == 'decyzja')
        with self.assertRaises(ValueError): w.task(self, self.args(action='close', id=t['id'], evidence=str(proof)))
        self.quiet(w.task, self.args(action='close', id=t['id'], evidence=str(proof), human='Owner'))

    @unittest.skipUnless(shutil.which('git'), 'Wymaga lokalnego Git')
    def test_cli_dispatch_and_review_precheck_precedes_model(self):
        subprocess.run(['git', 'init', '-q'], cwd=self.repo, check=True, capture_output=True)
        (self.repo / 'helix.json').write_text(json.dumps({'helix_version': VERSION}))
        for command in (['task', 'new', '--goal', 'Filtr', '--owner', 'Tester'], ['task', 'list'], ['board'], ['tools', 'discover']):
            p = subprocess.run([sys.executable, str(BIN / 'helix'), '--repo', str(self.repo), *command], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        loader = importlib.machinery.SourceFileLoader('helix_bookmarks_test', str(BIN / 'helix'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        import helix_ux, helix_consistency, helix_security_deep
        old_ux, old_consistency, old_deep = helix_ux.H, helix_consistency.H, helix_security_deep.H
        with patch.dict(sys.modules, {loader.name: module}): loader.exec_module(module)
        helix_ux.H, helix_consistency.H, helix_security_deep.H = old_ux, old_consistency, old_deep
        self.cp = lambda cp: {'id': cp}
        self.cfg = {'precheck': {'commands': [[sys.executable, '-c', 'raise SystemExit(1)']]}}
        with patch.object(module, 'ask') as model:
            result = module.gate_review(self, 'cp1')
            self.assertFalse(result['pass']); model.assert_not_called()
        self.assertIn('precheck', result['error'])
        self.cfg = {'limits': {}, 'worker': {'allow_hosts': []}}
        # Satisfy the design prerequisite so this case reaches the network guard.
        w.save(self.repo / 'design-decisions/cp1.json', {
            'status': 'approved', 'accepted_by': 'Test fixture owner',
            'accepted_at': '2026-10-25T12:00:00+00:00', 'selected': 'local',
            'alternatives': [
                {'id': 'local', 'approach': 'Run checks locally',
                 'benefits': 'No external dependency', 'trade_offs': 'Local resources needed'},
                {'id': 'remote', 'approach': 'Run checks on a remote worker',
                 'benefits': 'Independent resources', 'trade_offs': 'Network access needed'},
            ],
        })
        w.save(self.ev('cp1') / 'worker-network-error.json', {'status': 'ERROR'})
        with patch.object(module, 'ask') as model:
            with self.assertRaises(SystemExit) as error:
                module.cmd_run(self, argparse.Namespace(checkpoint='cp1'))
            self.assertEqual(error.exception.code, 3)
            model.assert_not_called()
        self.assertEqual(self.state('cp1')['status'], 'ERROR')

    def test_board(self):
        self.quiet(w.task, self.args(checkpoint='cp1', pr='PR42'))
        w.save(self.state_dir / 'cp1.state.json', {'gates': {'behavior': True}})
        self.quiet(w.board, None)
        text = (self.state_dir / 'BOARD.md').read_text()
        for value in ('Tester', 'PR42', 'behavior', 'Napraw filtr'): self.assertIn(value, text)

    def test_tools_disabled_schema_projection_and_redaction(self):
        w.save(self.repo / 'schema.json', {'required': ['x']})
        entry = dict(name='echo', owner='Tester', schema='schema.json', command=[sys.executable, '-c', 'import json; print(json.dumps({"answer":42,"token":"secret"}))'])
        w.save(self.state_dir / 'tools.json', {'tools': [entry]})
        a = argparse.Namespace(action='call', name='echo', input='{"x":1}', fields='answer')
        with self.assertRaises(ValueError): w.tools(self, a)
        entry['enabled'] = True; w.save(self.state_dir / 'tools.json', {'tools': [entry]})
        text = self.quiet(w.tools, a); self.assertIn('42', text); self.assertNotIn('secret', text)
        result = json.loads(Path(text.splitlines()[0]).read_text()); self.assertEqual(result['token'], '[REDACTED]')
        a.input = '{}'
        with self.assertRaises(ValueError): w.tools(self, a)

    def test_rules_and_precheck(self):
        rules = self.state_dir / 'rules'; rules.mkdir()
        (rules / 'a.md').write_text('---\npaths: ["src/**/*.py", "src/*.py"]\n---\nA')
        (rules / 'b.md').write_text('---\npaths:\n  - "web/**"\n---\nB')
        self.assertTrue(w.glob_matches('src/a.py', 'src/**/*.py'))
        self.assertFalse(w.glob_matches('src/deep/a.py', 'src/*.py'))
        self.assertEqual([p.name for p, _ in w.matching_rules(self, ['src/a.py'])], ['a.md'])
        self.cfg = {'precheck': {'commands': [[sys.executable, '-c', 'raise SystemExit(1)']]}}
        self.assertFalse(w.precheck(self)['pass'])
        self.cfg = {}; self.assertTrue(w.precheck(self)['pass'])

    def test_source_status_and_ttl(self):
        c = dict(tag='VERIFIED', affects_prod=True, source_status='FOUND', retrieved_at=dt.datetime.now(dt.timezone.utc).isoformat(), ttl=60)
        self.assertIsNone(w.source_error(c))
        for status in ('NOT_FOUND', 'AMBIGUOUS', 'OUT_OF_SCOPE', None):
            self.assertIsNotNone(w.source_error(dict(c, source_status=status)))
        self.assertIsNotNone(w.source_error(dict(c, ttl=-1)))
        self.assertIsNotNone(w.source_error(dict(c, retrieved_at='2000-01-01T00:00:00+00:00')))

    def test_audit_dedupe_proposal_budget_and_stop(self):
        rows = [dict(session_id=str(i), error='Ten sam błąd', status='stopped', cost=1) for i in range(15)]
        rows[0]['cost'] = 100
        (self.state_dir / 'workers.jsonl').write_text('\n'.join(json.dumps(x) for x in rows + rows))
        self.quiet(w.audit, None)
        text = (self.evidence_root / 'audit-sessions.md').read_text()
        for value in ('Liczba sesji: 15', '15: Ten sam błąd', '>25%: 0', 'Bez odpowiedzi: 0'): self.assertIn(value, text)
        self.assertEqual(len(list((self.state_dir / 'rules').glob('proposal-*'))), 1)

    def test_worker_denial_is_sticky_and_never_connects(self):
        self.cfg = {'worker': {'allow_hosts': ['allowed.test']}}
        a = argparse.Namespace(checkpoint='cp1', url='https://evil.test/path')
        with patch.object(w.urllib.request, 'build_opener') as network:
            with self.assertRaises(ValueError): w.worker_connect(self, a)
            network.assert_not_called()
        self.assertEqual(self.state('cp1')['status'], 'ERROR')
        (self.ev('cp1') / 'worker-connections.jsonl').unlink()
        self.assertFalse(w.check_connections(self, 'cp1'))

    def test_security_examples_and_web_dump(self):
        (self.repo / 'config.example').write_text('{"password": "admin"}\n')
        (self.repo / 'public').mkdir(); (self.repo / 'public/backup.sql').write_text('CREATE TABLE t;')
        findings = packs.local_security(self.repo)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f['severity'] == 'high' and f['verdict'] == 'needs_validation' for f in findings))

    @unittest.skipUnless(shutil.which('git'), 'Wymaga lokalnego Git')
    def test_integrity_migration_deletion_and_evidence(self):
        for cmd in (['init', '-q'],): subprocess.run(['git', *cmd], cwd=self.repo, check=True, capture_output=True)
        (self.repo / 'src').mkdir(); (self.repo / 'src/a.py').write_text('def a():\n    return 1\n')
        (self.repo / 'migrations').mkdir(); (self.repo / 'migrations/1.sql').write_text('CREATE TABLE t;')
        subprocess.run(['git', 'add', 'src', 'migrations'], cwd=self.repo, check=True)
        subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base'], cwd=self.repo, check=True)
        (self.repo / 'src/a.py').unlink(); (self.repo / 'migrations/1.sql').write_text('CREATE TABLE x;')
        runner = packs.Runner(self.repo)
        fs, _ = packs.integrity(self.repo, {}, 'HEAD', runner)
        self.assertIn('migration-database', [f['id'] for f in fs])
        self.assertEqual(next(f for f in fs if f['id'] == 'production-deletion')['verdict'], 'needs_validation')
        (self.ev('cp1') / 'operator.md').write_text('database: test_db\ntelemetry: "brak wywołań przez 90 dni"\n')
        fs, _ = packs.integrity(self.repo, {}, 'HEAD', runner)
        self.assertNotIn('migration-database', [f['id'] for f in fs])
        self.assertEqual(next(f for f in fs if f['id'] == 'production-deletion')['severity'], 'high')

    @unittest.skipUnless(shutil.which('node'), 'Wymaga lokalnego Node; bez przeglądarki i sieci')
    def test_webkit_findings_offline(self):
        script = '''const u = require(process.argv[1]); const r={engine:'webkit',mobile:true,layout:{meta_viewport:'width=device-width',theme_color:null,safari_edges:{top:{color:'red',element:'header'},bottom:{color:'blue',element:'footer'}},overflow_px:0,clipped:[],overlaps:[],covered:[],small_targets:[],tiny_targets:[],small_text:[],fixed:[],broken_images:[],text_chars:100}}; const f=u.findingsFor(r,{},'base'); console.log(JSON.stringify(f));'''
        p = subprocess.run(['node', '-e', script, str(BIN / 'ux.cjs')], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for check in ('safari-viewport-cover', 'safari-theme-color', 'safari-chrome-tint'): self.assertIn(check, p.stdout)


if __name__ == '__main__': unittest.main()
