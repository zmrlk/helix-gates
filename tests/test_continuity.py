"""Continuity regression tests: isolated repositories, no network or user git config."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_continuity import Continuity, VERSION, load, validate, write

CLI = Path(__file__).resolve().parents[1] / 'bin/helix'
FIXTURE = Path(__file__).parent / 'fixtures/continuity/agent-policy.json'


@unittest.skipUnless(shutil.which('git'), 'git unavailable')
class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test Agent')
        self.git('config', 'user.email', 'agent@example.test')
        self.git('config', 'commit.gpgsign', 'false')
        (self.root / 'source.txt').write_text('baseline\n')
        self.commit('baseline')
        self.c = Continuity(self.root)
        self.policy = json.loads(FIXTURE.read_text())
        self.policy['helix_version'] = VERSION
        self.save_policy()

    def git(self, *args):
        p = subprocess.run(['git', '-C', str(self.root), *args], text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.strip()

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD')

    def save_policy(self):
        write(self.root / '.helix/agent-policy.json', self.policy)

    def handoff(self):
        return self.c.handoff_write(dict(agent='agent-a', env='box', done='Implemented module',
                                        evidence='tests/test_module.py', next='Review changes', risks='Pending review'))

    def test_agents_generate_check(self):
        self.c.generate()
        self.assertEqual(self.c.agents_check(), [])
        texts = [(self.root / n).read_text() for n in ('AGENTS.md', 'CLAUDE.md', 'GEMINI.md')]
        self.assertEqual(len(set(texts)), 1)
        self.assertIn('source-sha256', texts[0])

    def test_manual_claude_edit(self):
        self.c.generate()
        (self.root / 'CLAUDE.md').write_text('edited')
        self.assertIn('dryf instrukcji: CLAUDE.md', self.c.agents_check())

    def test_missing_adapter(self):
        self.c.generate()
        (self.root / 'GEMINI.md').unlink()
        self.assertTrue(self.c.agents_check())

    def test_changed_policy_hash(self):
        self.c.generate()
        self.policy['conventions'].append('New convention')
        self.save_policy()
        self.assertEqual(len(self.c.agents_check()), 3)

    def test_version_pin(self):
        self.c.generate()
        self.policy['helix_version'] = 'different'
        self.save_policy()
        self.assertIn('wersja Helixa różni się od pina polityki', self.c.agents_check())
        with self.assertRaises(ValueError):
            self.c.generate()

    def test_ambiguous_policy(self):
        write(self.root / '.helix/agent-policy.yaml', self.policy)
        with self.assertRaises(ValueError):
            self.c.generate()

    def test_json_in_yaml(self):
        (self.root / '.helix/agent-policy.json').rename(self.root / '.helix/agent-policy.yaml')
        self.c.generate()
        self.assertFalse(self.c.agents_check())

    def test_handoff_ack(self):
        self.handoff()
        self.assertTrue(self.c.handoff_check())
        read = self.c.handoff_read('agent-b', 'mac')
        self.assertEqual(read['handoff']['agent'], 'agent-a')
        self.assertEqual(self.c.handoff_check(), [])

    def test_new_handoff_invalidates_ack(self):
        self.handoff()
        self.c.handoff_read('agent-b', 'mac')
        self.handoff()
        self.assertTrue(self.c.handoff_check())

    def test_session_without_handoff(self):
        self.handoff()
        self.c.handoff_read('agent-b', 'mac')
        self.commit('store state')
        # policy was also committed, so write fresh handoff after setup.
        self.handoff()
        self.c.handoff_read('agent-b', 'mac')
        (self.root / 'source.txt').write_text('change\n')
        self.commit('work without handoff')
        self.assertTrue(any('commit bez nowego' in e for e in self.c.handoff_check()))
        self.handoff()
        self.c.handoff_read('agent-b', 'mac')
        self.assertFalse(self.c.handoff_check())

    def test_handoff_commit_only_allowed(self):
        self.commit('policy')
        self.handoff()
        self.c.handoff_read('agent-b', 'mac')
        self.commit('handoff and receipt')
        self.assertFalse(self.c.handoff_check())

    def test_secret_handoff_rejected(self):
        with self.assertRaises(ValueError):
            self.c.handoff_write(dict(agent='agent-a', env='box', done='password=example-invalid-value',
                                      evidence='tests', next='review', risks='none'))
        self.assertFalse(self.c.path('handoffs').exists())

    def test_provider_secret_rejected(self):
        with self.assertRaises(ValueError):
            self.c.handoff_write(dict(agent='agent-a', env='box', done='sk-' + 'aB1cD2' * 8,
                                      evidence='tests', next='review', risks='none'))

    def test_handoff_missing_required(self):
        with self.assertRaises(ValueError):
            self.c.handoff_write(dict(agent='agent-a'))

    def test_claim_two_agents(self):
        self.c.claim_take('task-1', 'agent-a')
        with self.assertRaises(ValueError):
            self.c.claim_take('task-1', 'agent-b')

    def test_claim_release_owner_and_lease(self):
        claim = self.c.claim_take('task-1', 'agent-a')
        with self.assertRaises(ValueError):
            self.c.claim_release('task-1', 'agent-b', claim['lease_id'])
        with self.assertRaises(ValueError):
            self.c.claim_release('task-1', 'agent-a', 'outdated')
        self.c.claim_release('task-1', 'agent-a', claim['lease_id'])
        second = self.c.claim_take('task-1', 'agent-b')
        self.assertNotEqual(claim['lease_id'], second['lease_id'])

    def test_claim_expiry(self):
        claim = self.c.claim_take('task-1', 'agent-a')
        claim['expires_at'] = '2000-01-01T00:00:00+00:00'
        write(self.c.path('claims/task-1.json'), claim)
        self.assertEqual(self.c.claim_take('task-1', 'agent-b')['agent'], 'agent-b')

    def test_claim_invalid_ttl(self):
        with self.assertRaises(ValueError):
            self.c.claim_take('task-1', 'agent-a', -1)

    def test_claim_path_traversal(self):
        with self.assertRaises(ValueError):
            self.c.claim_take('../escape', 'agent-a')

    def test_duplicate_claim_files(self):
        claim = self.c.claim_take('task-1', 'agent-a')
        claim['agent'] = 'agent-b'
        write(self.c.path('claims/task-1-copy.json'), claim)
        self.assertTrue(self.c.claims_check())

    def test_claim_commit_only_explicit(self):
        before = self.git('rev-parse', 'HEAD')
        self.c.claim_take('task-1', 'agent-a')
        self.assertEqual(self.git('rev-parse', 'HEAD'), before)
        self.c.claim_take('task-2', 'agent-b', commit=True)
        self.assertNotEqual(self.git('rev-parse', 'HEAD'), before)
        self.assertEqual(self.git('show', '--format=', '--name-only', 'HEAD'), '.helix/claims/task-2.json')

    def test_claim_commit_respects_gitignore(self):
        for pattern in ('.helix/', '.helix/claims/*.json'):
            with self.subTest(pattern=pattern):
                (self.root / '.gitignore').write_text(pattern + '\n')
                before = self.git('rev-parse', 'HEAD')
                with self.assertRaisesRegex(ValueError, r'ignorowany.*gitignore.*bez --commit'):
                    self.c.claim_take('ignored-task', 'agent-a', commit=True)
                self.assertEqual(self.git('rev-parse', 'HEAD'), before)
                self.assertEqual(self.git('diff', '--cached', '--name-only'), '')
                self.assertFalse(self.c.path('claims/ignored-task.json').exists())
                self.assertFalse(self.c.path('claims/.lock').exists())
        self.c.claim_take('local-task', 'agent-a')
        self.assertTrue(self.c.path('claims/local-task.json').exists())

    def test_merge_collision_chosen_side(self):
        base = self.git('rev-parse', 'HEAD')
        branch = self.git('branch', '--show-current')
        self.c.claim_take('task-1', 'agent-a', commit=True)
        left = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-qb', 'other', base)
        self.c.claim_take('task-1', 'agent-b', commit=True)
        right = self.git('rev-parse', 'HEAD')
        self.git('checkout', branch)
        # A synthetic merge selecting one tree models conflict resolution hiding a lease.
        tree = self.git('rev-parse', left + '^{tree}')
        merge = self.git('commit-tree', tree, '-p', left, '-p', right, '-m', 'resolve collision')
        self.git('reset', '--hard', merge)
        self.assertTrue(any('kolizja' in e for e in self.c.claims_check()))

    def test_decision_supersedes(self):
        a = self.c.decisions_add('agent-a', 'Use files', 'Portable storage')
        b = self.c.decisions_add('agent-b', 'Use structured files', 'Schema validation', a['id'])
        self.assertEqual(b['id'], 'DEC-0002')
        self.assertFalse(self.c.decisions_check())

    def test_decision_invalid_supersedes(self):
        with self.assertRaises(ValueError):
            self.c.decisions_add('agent-a', 'Use files', 'Portable storage', 'DEC-9999')

    def test_decision_edit_detected(self):
        self.c.decisions_add('agent-a', 'Use files', 'Portable storage')
        self.commit('decision')
        p = self.c.path('decisions/DEC-0001.json')
        data = load(p); data['decision'] = 'Use service'; write(p, data)
        self.assertTrue(self.c.decisions_check())

    def test_decision_delete_detected(self):
        self.c.decisions_add('agent-a', 'Use files', 'Portable storage')
        self.commit('decision')
        self.c.path('decisions/DEC-0001.json').unlink()
        self.commit('remove decision')
        self.assertTrue(self.c.decisions_check())

    def test_decision_revert_history_detected(self):
        self.c.decisions_add('agent-a', 'Use files', 'Portable storage')
        self.commit('decision')
        p = self.c.path('decisions/DEC-0001.json'); original = p.read_text()
        data = load(p); data['decision'] = 'Use service'; write(p, data)
        self.commit('alter decision')
        p.write_text(original); self.commit('revert alteration')
        self.assertTrue(self.c.decisions_check())

    def test_policy_diff_author(self):
        self.policy['rules'] = [dict(id='DEC-0001', kind='forbidden_pattern', glob='*.txt', pattern='unsafe')]
        self.save_policy()
        base = self.commit('policy')
        (self.root / 'source.txt').write_text('unsafe\n')
        self.commit('violation')
        errors = self.c.decisions_check(base)
        self.assertEqual(len(errors), 1)
        self.assertIn('autor=Test Agent', errors[0])
        self.assertIn('DEC-0001', errors[0])

    def test_required_convention_and_forbidden_file(self):
        self.policy['rules'] = [dict(id='RULE-1', kind='required_pattern', glob='*.txt', pattern='baseline'),
                                dict(id='RULE-2', kind='forbidden_file', glob='blocked.txt')]
        self.save_policy(); base = self.commit('policy')
        (self.root / 'blocked.txt').write_text('bad')
        self.commit('bad file')
        self.assertEqual(len(self.c.policy_diff(base)), 2)

    def test_uncommitted_convention_reversal(self):
        self.policy['rules'] = [dict(id='RULE-1', kind='required_pattern', glob='*.txt', pattern='baseline')]
        self.save_policy(); base = self.commit('policy')
        (self.root / 'source.txt').write_text('reversal')
        self.assertIn('autor=WORKTREE', self.c.policy_diff(base)[0])

    def test_symlink_state_rejected(self):
        shutil.rmtree(self.root / '.helix')
        (self.root / '.helix').symlink_to(self.root / 'other', target_is_directory=True)
        with self.assertRaises(ValueError):
            Continuity(self.root)

    def test_symlink_adapter_rejected(self):
        (self.root / 'CLAUDE.md').symlink_to(self.root / 'source.txt')
        with self.assertRaises(ValueError):
            self.c.generate()
        self.assertEqual((self.root / 'source.txt').read_text(), 'baseline\n')

    def test_custom_directory(self):
        (self.root / 'helix.json').write_text(json.dumps({'continuity': {'directory': 'project-state'}}))
        c = Continuity(self.root)
        write(c.path('agent-policy.json'), self.policy)
        c.generate()
        self.assertFalse(c.agents_check())

    def test_directory_escape_rejected(self):
        (self.root / 'helix.json').write_text(json.dumps({'continuity': {'directory': '../outside'}}))
        with self.assertRaises(ValueError):
            Continuity(self.root)

    def test_report_fails_missing_state(self):
        report = self.c.report()
        self.assertEqual(report['title'], 'Dryf i ciągłość')
        self.assertEqual(report['status'], 'FAIL')

    def test_report_complete(self):
        self.c.generate(); self.handoff(); self.c.handoff_read('agent-b', 'mac')
        self.assertEqual(self.c.report()['status'], 'PASS')

    def test_cli_without_helix_config(self):
        p = subprocess.run([sys.executable, str(CLI), '--repo', str(self.root), 'agents', 'generate'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_cli_rejects_secret_without_echo(self):
        marker = 'password=invalid-example-value'
        p = subprocess.run([sys.executable, str(CLI), '--repo', str(self.root), 'handoff', 'write',
                            '--agent', 'agent-a', '--done', marker], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(marker, p.stdout + p.stderr)

    def test_invalid_schema_unknown_fields(self):
        with self.assertRaises(ValueError):
            validate('agent-policy', dict(self.policy, unknown=True))

    def test_decision_delete_then_restore_history(self):
        self.c.decisions_add('agent-a', 'Use files', 'Portable storage')
        self.commit('decision')
        p = self.c.path('decisions/DEC-0001.json'); original = p.read_text()
        p.unlink(); self.commit('delete')
        p.write_text(original); self.commit('restore')
        self.assertTrue(self.c.decisions_check())

    def test_whitespace_source_change_updates_hash(self):
        self.c.generate()
        p = self.c.path('agent-policy.json')
        p.write_text(p.read_text() + '\n')
        self.assertTrue(self.c.agents_check())

    def test_timestamp_without_zone_rejected(self):
        claim = self.c.claim_take('task-1', 'agent-a')
        claim['expires_at'] = '2099-01-01T00:00:00'
        with self.assertRaises(ValueError):
            validate('claim', claim)

    def test_report_detects_policy_violation_without_base_argument(self):
        self.policy['rules'] = [dict(id='DEC-0001', kind='forbidden_pattern', glob='*.txt', pattern='unsafe')]
        self.save_policy(); self.commit('policy')
        (self.root / 'source.txt').write_text('unsafe')
        self.commit('violation')
        self.assertTrue(self.c.report()['decision_violations'])

    def test_fresh_clone_handoff_and_decisions(self):
        self.c.generate()
        self.c.decisions_add('agent-a', 'Use files', 'Portable storage')
        self.commit('initial state')
        self.handoff(); self.commit('handoff')
        with tempfile.TemporaryDirectory() as dest:
            subprocess.run(['git', 'clone', '-q', str(self.root), dest], check=True, capture_output=True)
            c = Continuity(dest)
            read = c.handoff_read('agent-b', 'mac')
            self.assertEqual(read['decisions'][0]['id'], 'DEC-0001')
            self.assertEqual(read['handoff']['next'], 'Review changes')
            self.assertEqual(c.report()['status'], 'PASS')

    def test_git_push_arbitrates_separate_clones(self):
        self.commit('policy')
        with tempfile.TemporaryDirectory() as dest:
            remote = Path(dest) / 'remote.git'
            subprocess.run(['git', 'clone', '-q', '--bare', str(self.root), str(remote)], check=True, capture_output=True)
            clones = []
            for agent in ('agent-a', 'agent-b'):
                path = Path(dest) / agent
                subprocess.run(['git', 'clone', '-q', str(remote), str(path)], check=True, capture_output=True)
                for key, value in [('user.name', agent), ('user.email', agent + '@example.test'), ('commit.gpgsign', 'false')]:
                    subprocess.run(['git', '-C', str(path), 'config', key, value], check=True)
                Continuity(path).claim_take('task-1', agent, commit=True)
                clones.append(path)
            first = subprocess.run(['git', '-C', str(clones[0]), 'push', 'origin', 'HEAD'], capture_output=True)
            second = subprocess.run(['git', '-C', str(clones[1]), 'push', 'origin', 'HEAD'], capture_output=True)
            self.assertEqual(first.returncode, 0)
            self.assertNotEqual(second.returncode, 0)

    def test_invalid_regex_rejected(self):
        self.policy['rules'] = [dict(id='RULE-1', kind='forbidden_pattern', pattern='[')]
        with self.assertRaises(Exception):
            validate('agent-policy', self.policy)

    def test_claim_after_handoff_requires_reader_ack(self):
        self.handoff()
        with self.assertRaises(ValueError):
            self.c.claim_take('task-1', 'agent-b')
        self.c.handoff_read('agent-a', 'box')
        with self.assertRaises(ValueError):
            self.c.claim_take('task-1', 'agent-b')
        self.c.handoff_read('agent-b', 'mac')
        self.assertEqual(self.c.claim_take('task-1', 'agent-b')['agent'], 'agent-b')

    def test_read_reports_ack_after_writing_it(self):
        self.c.generate(); self.handoff()
        result = self.c.handoff_read('agent-b', 'mac')
        self.assertFalse(result['drift']['missing_handoffs'])
