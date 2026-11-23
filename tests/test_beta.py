"""Private beta contracts: fail closed, isolated prechecks and documented CLI."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
from helix_contracts import VERSION
import helix_packs as P
import helix_runs as R
import helix_workflow as W
import helix_security_deep as D


class Beta(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'example-app'; self.repo.mkdir()
        self.state = self.root / 'state'; self.state.mkdir()
        self.evidence = self.state / 'evidence'; self.evidence.mkdir()
        self.ctx = SimpleNamespace(repo=self.repo, state_dir=self.state, evidence_root=self.evidence, external_state=True, cfg={})
        self.ctx.ev = lambda cp: self.evidence / cp
        self.ctx.ev('cp1').mkdir()
        self.status = {}
        self.ctx.state = lambda cp: self.status
        self.ctx.save_state = lambda value: self.status.update(value)
        self.git('init', '-q')
        (self.repo / 'app.py').write_text('def example():\n    return 42\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'fixture')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True, text=True)

    def test_incomplete_never_returns_success(self):
        for mode in ('blocking', 'advisory'):
            result = P.evaluate('security', [], dict(mode=mode, fail_on=['high']), [dict(status='skipped')], False)
            self.assertEqual(result['exit_code'], 3)
            self.assertFalse(result['pass'])

    def test_incomplete_baseline_is_not_written(self):
        (self.repo / 'helix.json').write_text(json.dumps({'packs': {'security': {'tools': ['gitleaks']}}}))
        args = argparse.Namespace(cmd='security', action='baseline', out=str(self.evidence / 'baseline'), trusted_base=False)
        with patch.object(P.shutil, 'which', return_value=None), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
            P.cmd_pack(self.ctx, args)
        self.assertEqual(error.exception.code, 3)
        self.assertFalse((self.repo / '.helix/baselines/security.json').exists())

    def test_missing_deep_validator_returns_error(self):
        with patch.object(D.shutil, 'which', return_value=None), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
            D.cmd_deep(self.ctx, argparse.Namespace(out=str(self.evidence / 'deep')))
        self.assertEqual(error.exception.code, 3)

    def test_untrusted_package_and_config_do_not_execute(self):
        marker = self.repo / 'executed'
        command = [sys.executable, '-c', f'from pathlib import Path; Path({str(marker)!r}).touch()']
        self.ctx.cfg = {'precheck': {'commands': [command]}}
        self.assertFalse(W.precheck(self.ctx)['pass'])
        self.assertFalse(marker.exists())
        self.ctx.cfg = {}
        (self.repo / 'package.json').write_text(json.dumps({'scripts': {'lint': 'touch executed'}}))
        self.assertFalse(W.precheck(self.ctx)['pass'])
        self.assertFalse(marker.exists())

    def test_explicit_precheck_strips_credentials(self):
        self.ctx.trust_repo = True
        self.ctx.cfg = {'precheck': {'commands': [[sys.executable, '-c', 'import os; assert "BETA_TEST_TOKEN" not in os.environ']]}}
        with patch.dict(os.environ, BETA_TEST_TOKEN='synthetic-private-value'):
            self.assertTrue(W.precheck(self.ctx)['pass'])

    def test_worker_log_without_configuration_denies_host(self):
        W.save(self.ctx.ev('cp1') / 'unused.json', {})
        (self.ctx.ev('cp1') / 'worker-connections.jsonl').write_text(json.dumps({'host': 'outside.example.test'}) + '\n')
        self.assertFalse(W.check_connections(self.ctx, 'cp1'))
        self.assertEqual(self.status['status'], 'ERROR')

    def test_changed_nul_file_prevents_integrity_pass(self):
        (self.repo / 'test_example.py').write_text('def test_example():\n    assert True\n')
        self.git('add', '.'); self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'test')
        (self.repo / 'test_example.py').write_bytes(b'def test_example():\n    pass\n\0')
        runner = P.Runner(self.repo)
        findings, metrics = P.integrity(self.repo, {}, 'HEAD', runner)
        result = P.evaluate('integrity', findings, dict(mode='blocking', fail_on=['high']), runner.records, False)
        self.assertEqual(result['exit_code'], 3)
        self.assertEqual(metrics['coverage'][0]['status'], 'skipped')

    def test_external_deletion_citation_remains_uncertain_and_blocking(self):
        (self.repo / 'app.py').write_text('')
        (self.evidence / 'deletion.md').write_text('telemetry: observed on staging\n')
        runner = P.Runner(self.repo)
        findings, _ = P.integrity(self.repo, {}, 'HEAD', runner, self.evidence)
        deletion = next(f for f in findings if f['id'] == 'production-deletion')
        self.assertIn('observed on staging', deletion['evidence'])
        self.assertEqual((deletion['verdict'], deletion['tag'], deletion['severity']), ('needs_validation', 'ASSUMPTION', 'high'))
        self.assertNotIn('return 42', json.dumps(findings))
        self.assertEqual(P.evaluate('integrity', findings, dict(mode='blocking', fail_on=['high']), runner.records, False)['exit_code'], 2)

    def test_symlink_target_changes_cannot_reuse_cached_scan(self):
        target = self.root / 'outside'; target.write_text('one')
        (self.repo / 'linked.py').symlink_to(target)
        args = argparse.Namespace(no_cache=False)
        runner = P.Runner(self.repo)
        calls = []
        def operation():
            calls.append(1)
            return [], {}
        R.Session(self.ctx, 'security', args, self.evidence, {}).execute('internal', operation, runner)
        target.write_text('two')
        R.Session(self.ctx, 'security', args, self.evidence, {}).execute('internal', operation, runner)
        self.assertEqual(len(calls), 2)

    def test_session_costs_and_unanswered_events_accumulate(self):
        events = [dict(session_id='expensive', cost=20, budget=100, status='stopped'),
                  dict(session_id='expensive', cost=10, budget=100, status='done', response='ok'),
                  dict(session_id='cheap', cost=1, budget=100, status='done', response='ok')]
        log = self.state / 'sessions.jsonl'; log.write_text('\n'.join(map(json.dumps, events)) + '\n')
        with contextlib.redirect_stdout(io.StringIO()):
            W.audit(self.ctx, argparse.Namespace(logs=[str(log)], budget=100))
        text = (self.evidence / 'audit-sessions.md').read_text()
        self.assertIn('- >25%: expensive\n', text)
        self.assertIn('- Bez odpowiedzi: expensive\n', text)
        self.assertNotIn('- >25%: cheap', text)

    def test_deep_gate_uses_external_index_and_finalizes_final_verdict(self):
        (self.repo / 'helix.json').write_text(json.dumps({'packs': {'security': {'tools': [], 'deep_required': True}}}))
        out = self.state / 'security-audit' / 'run-1'; out.mkdir(parents=True)
        metadata = dict(target=str(self.repo.resolve()), run_status='partial', errors=[], uncovered_units=['api'])
        P.write_json(out / 'run-metadata.json', metadata)
        P.write_json(out / 'helix-findings.json', [])
        args = argparse.Namespace(which='security', checkpoint=None, trusted_base=False, out=str(self.evidence / 'gate'))
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
            P.gate_pack(self.ctx, args)
        self.assertEqual(error.exception.code, 3)
        data = R.latest(self.ctx)
        self.assertEqual(data['status'], 'blocked')
        self.assertIn(',blocked,', (self.evidence / 'gate/run-log.csv').read_text())
        metadata.update(run_status='complete', uncovered_units=[])
        P.write_json(out / 'run-metadata.json', metadata)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
            P.gate_pack(self.ctx, args)
        self.assertEqual(error.exception.code, 0)
        self.assertEqual(Path(P.read_json(self.evidence / 'gate/gate.json')['deep_run']).resolve(), out.resolve())

    def test_secret_never_persists_in_unit_or_cache(self):
        (self.repo / 'secret.txt').write_text('credential=synthetic-sensitive-value\n')
        self.ctx.cfg = {'packs': {'security': {'tools': ['gitleaks']}}}
        (self.repo / 'helix.json').write_text(json.dumps(self.ctx.cfg))
        def fake_run(runner, tool, command, *args, **kwargs):
            runner.records.append(dict(tool=tool, status='ok', version='fixture', command=[], exit_code=1, duration=0, error=None))
            return [dict(RuleID='test-key', File='secret.txt', Secret='synthetic-sensitive-value', Match='credential=synthetic-sensitive-value', StartLine=1)]
        with patch.object(P.Runner, 'run', fake_run):
            P.scan(self.ctx, 'security', argparse.Namespace(out=str(self.evidence / 'scan'), trusted_base=False))
        for path in [*self.state.rglob('*.json'), *self.evidence.rglob('*.md')]:
            self.assertNotIn('synthetic-sensitive-value', path.read_text(), str(path))


class Documentation(unittest.TestCase):
    def test_readme_commands_have_help(self):
        for name in ('README.md', 'README.pl.md'):
            text = (ROOT / name).read_text()
            commands = set(re.findall(r'^\s*(helix[^\n]*)$', text, re.M))
            commands.update(re.findall(r'`(helix [^`\n]+)`', text))
            self.assertGreaterEqual(len(commands), 7)
            for command in commands:
                with self.subTest(readme=name, command=command):
                    argv = shlex.split(command)
                    p = subprocess.run([sys.executable, str(ROOT / 'bin/helix'), *argv[1:], '--help'], cwd=ROOT, capture_output=True, text=True, timeout=10)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertTrue('usage:' in p.stdout or VERSION in p.stdout)

    def test_version_and_vendor_attribution(self):
        p = subprocess.run([sys.executable, str(ROOT / 'bin/helix'), '--version'], capture_output=True, text=True, check=True)
        self.assertEqual(p.stdout.strip(), 'helix ' + VERSION)
        self.assertTrue((ROOT / 'LICENSE').read_text().startswith('MIT License'))
        self.assertIn('Cloudflare', (ROOT / 'THIRD_PARTY_NOTICES.md').read_text())
