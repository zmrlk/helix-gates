"""Offline contracts, including deliberately rejected/blocked operations."""
import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runs as R
import helix_packs as P


class Runs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / 'a.py').write_text('one')
        (self.repo / 'b.py').write_text('two')
        self.out = self.repo / 'helix-evidence' / 'test'; self.out.mkdir(parents=True)
        self.ctx = argparse.Namespace(repo=self.repo, state_dir=self.repo / '.helix')
        self.args = argparse.Namespace(cmd='security', action='scan', no_cache=False, out=str(self.out))
        self.runner = P.Runner(self.repo)

    def session(self, config=None):
        return R.Session(self.ctx, 'security', self.args, self.out, config or {})

    def test_cache_dates_content_config_and_bypass(self):
        def operation(): return [dict(file='a.py', verdict='needs_validation')], {}
        one = self.session(); a, _ = one.execute('internal', operation, self.runner)
        two = self.session(); b, _ = two.execute('internal', lambda: self.fail('cache miss'), self.runner)
        self.assertEqual(a[0]['verified_at'], b[0]['verified_at']); self.assertEqual(two.hits, 1)
        (self.repo / 'a.py').write_text('changed')
        self.assertEqual(self.session().execute('internal', lambda: ([], {'changed': True}), self.runner)[1], {'changed': True})
        self.assertEqual(self.session({'new': 1}).execute('internal', lambda: ([], {'config': True}), self.runner)[1], {'config': True})
        self.args.no_cache = True
        self.assertEqual(self.session().execute('internal', lambda: ([], {'bypass': True}), self.runner)[1], {'bypass': True})

    def test_incremental_retains_original_dates_and_removes_deleted(self):
        with patch('helix_runs.shutil.which', return_value=None):
            one = self.session()
            original, _ = one.execute('semgrep', lambda: ([dict(file='a.py'), dict(file='b.py')], {}), self.runner)
            (self.repo / 'a.py').write_text('changed')
            def changed():
                root = Path(self.args._scan_root)
                self.assertTrue((root / 'a.py').exists()); self.assertFalse((root / 'b.py').exists())
                return [dict(file='a.py')], {}
            two = self.session(); results, _ = two.execute('semgrep', changed, self.runner)
            self.assertEqual(results[0]['file'], 'b.py')
            self.assertEqual(results[0]['verified_at'], original[1]['verified_at'])
            (self.repo / 'b.py').unlink()
            three = self.session(); results, _ = three.execute('semgrep', lambda: self.fail('deletion needs no scan'), self.runner)
            self.assertEqual([f['file'] for f in results], ['a.py'])

    def test_two_failures_block_but_other_unit_runs_and_resume_skips(self):
        calls = []
        def fail(): calls.append(1); raise ValueError('exact failure')
        session = self.session(); session.execute('bad', fail, self.runner)
        session.execute('good', lambda: ([], {}), self.runner)
        self.assertEqual(len(calls), 2)
        unit = session.data['units']['bad']
        self.assertEqual(unit['status'], 'blocked'); self.assertIn('exact failure', unit['error']); self.assertTrue(unit['next_step'])
        self.args.resume_id = session.data['run_id']
        resumed = self.session()
        resumed.execute('bad', lambda: self.fail('blocked retried'), self.runner)
        resumed.execute('good', lambda: self.fail('completed repeated'), self.runner)
        resumed.execute('unfinished', lambda: ([], {'done': True}), self.runner)
        self.assertEqual(resumed.data['units']['unfinished']['status'], 'completed')

    def test_running_attempt_budget_survives_interrupt(self):
        session = self.session()
        def interrupt(): raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): session.execute('interrupt', interrupt, self.runner)
        self.args.resume_id = session.data['run_id']
        resumed = self.session()
        with self.assertRaises(KeyboardInterrupt): resumed.execute('interrupt', interrupt, self.runner)
        resumed = self.session(); resumed.execute('interrupt', lambda: self.fail('third attempt'), self.runner)
        self.assertEqual(resumed.data['units']['interrupt']['status'], 'blocked')

    def test_log_and_handoff(self):
        session = self.session(); session.execute('unit', lambda: ([], {}), self.runner)
        result = dict(status='PASS', would_fail=False)
        session.finish(result, []); session.finish(result, [])
        with (self.out / 'run-log.csv').open() as stream: rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['usage'], 'unknown'); self.assertEqual(rows[0]['status'], 'accepted')
        path = R.handoff(self.ctx, argparse.Namespace(out=None, run_id=None))
        text = path.read_text(); self.assertLess(len(text.split()), 400)
        for label in ('Cel:', 'Decyzje:', 'Ścieżki:', 'Otwarte pytania:', 'Następny krok:'): self.assertIn(label, text)

    def test_gitleaks_calibration_rejects_unverified_confirmation(self):
        for file in ('tests/test.py', 'fixtures/key', 'examples/demo', 'prod/key'):
            self.assertEqual(P.finding('security', 'gitleaks', 'secret', 'high', 'secret', file=file)['verdict'], 'needs_validation')
        with self.assertRaises(ValueError): P.finding('security', 'gitleaks', 'secret', 'high', 'secret', verdict='confirmed')
        self.assertEqual(P.finding('security', 'gitleaks', 'secret', 'high', 'secret', verdict='confirmed', verification_evidence='rotation provider record')['verdict'], 'confirmed')

    def test_tool_version_invalidates_cache(self):
        one, two, three = self.session(), self.session(), self.session()
        with patch('helix_runs.shutil.which', return_value='/fixture/tool'), patch('helix_runs.subprocess.run') as run:
            run.return_value = argparse.Namespace(returncode=0, stdout='version-1', stderr='')
            one.execute('tool', lambda: ([], {}), self.runner)
            two.execute('tool', lambda: self.fail('version-1 cache missed'), self.runner)
            run.return_value.stdout = 'version-2'
            _, metrics = three.execute('tool', lambda: ([], {'new_version': True}), self.runner)
            self.assertTrue(metrics['new_version'])

    def test_blocked_csv_and_handoff_include_failure(self):
        session = self.session()
        def fail(): raise ValueError('cannot parse fixture')
        session.execute('parser', fail, self.runner)
        session.finish(dict(status='ERROR', would_fail=False), [])
        with (self.out / 'run-log.csv').open() as stream: row = next(csv.DictReader(stream))
        self.assertEqual(row['status'], 'blocked'); self.assertEqual(row['retries'], '1')
        path = R.handoff(self.ctx, argparse.Namespace(out=None, run_id=None))
        self.assertIn('parser', path.read_text())

    def test_scan_and_resume_integration(self):
        self.ctx.cfg = {}
        self.args.accept_secret = []
        config = {'mode': 'blocking', 'fail_on': ['high'], 'tools': ['fixture']}
        calls = []
        def operation(repo, cfg, out, runner, args):
            calls.append(1)
            return [P.finding('security', 'fixture', 'rule', 'low', 'fixture', file='a.py', verdict='needs_validation')], {}
        with patch.object(P, 'policy', return_value=({}, config, 'HEAD', {}, {}, False)), patch.object(P, 'security', side_effect=operation):
            first = P.scan(self.ctx, 'security', self.args)
            second = P.scan(self.ctx, 'security', self.args)
            self.assertEqual(len(calls), 1)
            self.assertEqual(first[1][0]['verified_at'], second[1][0]['verified_at'])
            R.resume(self.ctx, argparse.Namespace(run_id=None, no_cache=False))
            self.assertEqual(len(calls), 1)
            self.assertEqual(json.loads((self.out / 'findings.json').read_text())[0]['verified_at'], first[1][0]['verified_at'])

    def test_missing_run_fails(self):
        with self.assertRaises(SystemExit): R.latest(self.ctx)


if __name__ == '__main__': unittest.main()
