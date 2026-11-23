"""Real transport wrappers run by default and refuse only the owner's restriction or offline; neutral probes use explicit leases."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_provider_plan import load_helix, config
import helix_provider_plan as routing
from helix_model_admission import authorized_probe, FIXED_PROBE_PROMPT


def restricted(*providers):
    return dict(schema_version=1, status='approved', allowed_providers=list(providers), exclude_paths=[])


class ModelCallAdmission(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / 'target'; self.repo.mkdir()
        self.out = self.root / 'out'; self.out.mkdir()
        self.H = load_helix()
        self.ctx = SimpleNamespace(repo=self.repo, state_dir=self.out, out_dir=self.out,
                                   cfg=config(), explicit_cfg={}, offline=False)

    def test_every_real_source_caller_refuses_owner_restriction_before_process_or_export(self):
        # Decyzja właściciela 15.11.2026: domyślnie wszyscy dostawcy; odmawia tylko jawne ograniczenie właściciela.
        with patch.object(self.H, 'sh', side_effect=AssertionError('model process must not start')):
            for provider, caller in self.H.CALLERS.items():
                other = 'gemini' if provider not in ('gemini',) else 'codex'
                self.ctx.cfg['data_egress'] = restricted(other)
                with self.subTest(provider=provider), self.assertRaises(self.H.ProviderError) as caught:
                    caller(self.ctx, 'synthetic-model', 'PRIVATE_SOURCE_CANARY', None, None, False, self.out, 1)
                self.assertEqual(caught.exception.admission_code, 'PROVIDER_NOT_ALLOWED')
                self.assertNotIn('PRIVATE_SOURCE_CANARY', str(caught.exception))
        self.assertEqual(list(self.out.iterdir()), [])
    def test_default_and_approved_policy_run_every_automatic_caller(self):
        def answer(argv, cwd, **kwargs):
            if argv[0] == 'codex': Path(argv[argv.index('-o') + 1]).write_text('{"ok": true}'); return 0, '', ''
            if argv[0] == 'agy': return 0, json.dumps({'status': 'SUCCESS', 'structured_output': {'ok': True}}), ''
            if argv[0] == 'grok': return 0, json.dumps({'structuredOutput': {'ok': True}}), ''
            return 0, '{"ok": true}', ''
        for policy in (None, config()['data_egress']):
            if policy is None: self.ctx.cfg.pop('data_egress', None)
            else: self.ctx.cfg['data_egress'] = policy
            with patch.object(self.H, 'sh', side_effect=answer) as process:
                for provider in routing.JSON_PROVIDERS:
                    with self.subTest(policy=bool(policy), provider=provider):
                        self.H.CALLERS[provider](self.ctx, 'synthetic-model', 'PRIVATE_SOURCE_CANARY', None, None, False, self.out, 1)
                self.assertEqual(process.call_count, len(routing.JSON_PROVIDERS))
    def test_every_model_cli_runs_with_the_browser_login_blocker(self):
        # A CLI without a login (agy) opened a browser OAuth tab on every probe refresh.
        blocker = str(Path(__file__).resolve().parents[1] / 'bin/no-browser')
        envs = {}
        def answer(argv, cwd, **kwargs):
            envs[argv[0]] = kwargs.get('env') or {}
            if argv[0] == 'codex': Path(argv[argv.index('-o') + 1]).write_text('{"ok": true}'); return 0, '', ''
            if argv[0] == 'agy': return 0, json.dumps({'status': 'SUCCESS', 'structured_output': {'ok': True}}), ''
            if argv[0] == 'grok': return 0, json.dumps({'structuredOutput': {'ok': True}}), ''
            return 0, '{"ok": true}', ''
        self.ctx.cfg.pop('data_egress', None)
        with patch.object(self.H, 'sh', side_effect=answer):
            for provider, caller in self.H.CALLERS.items():
                if provider == 'grok': continue   # manual handoff file, no process
                with self.subTest(provider=provider):
                    caller(self.ctx, 'synthetic-model', 'prompt', None, None, False, self.out, 1)
        self.assertEqual(set(envs), {'codex', 'agy', 'grok', 'claude'})
        for program, env in envs.items():
            self.assertEqual(env.get('PATH', '').split(os.pathsep)[0], blocker, program)

    def test_browser_login_attempt_is_refused_without_signalling_any_process(self):
        cli = self.root / 'fake-cli'
        # The CLI decides what a refused browser means; the blocker only refuses and signals nobody,
        # even when a CLI replaces itself with `exec open` and the caller becomes its parent.
        cli.write_text('#!/bin/sh\nopen "https://login.example.invalid/oauth" || { echo "login unavailable" >&2; exit 3; }\n')
        cli.chmod(0o755)
        done = subprocess.run([str(cli)], capture_output=True, text=True, timeout=20, env=self.H.model_cli_env())
        self.assertEqual(done.returncode, 3)
        self.assertIn('open blocked', done.stderr)
        replaced = self.root / 'exec-cli'
        replaced.write_text('#!/bin/sh\nexec xdg-open "https://login.example.invalid/oauth"\n'); replaced.chmod(0o755)
        done = subprocess.run([str(replaced)], capture_output=True, text=True, timeout=20, env=self.H.model_cli_env())
        self.assertEqual(done.returncode, 1)
        self.assertIn('xdg-open blocked', done.stderr)

    def test_read_only_grok_runs_outside_the_checked_project(self):
        # Haki sesji (memsearch) piszą w katalogu roboczym: Grok w projekcie B zmienił źródła przeglądu.
        seen = []
        def answer(argv, cwd, **kwargs):
            seen.append((argv[argv.index('--cwd') + 1], Path(cwd)))
            self.assertEqual(argv[argv.index('--max-turns') + 1], '8')   # 16.11: 4 tury kończyły się „max turns reached”
            return 0, json.dumps({'structuredOutput': {'ok': True}}), ''
        with patch.object(self.H, 'sh', side_effect=answer):
            self.H.call_grok_cli(self.ctx, 'grok-4.7', 'zadanie', None, None, False, self.out, 1)
        self.assertEqual(seen, [(str(self.out), self.out)])

    def test_configured_probe_flags_and_constant_text_do_not_create_a_lease(self):
        self.ctx.cfg['data_egress'] = restricted('gemini')
        self.ctx.cfg.update(availability_probe=True, probe=True)
        self.ctx.availability_probe = True
        with patch.object(self.H, 'sh', side_effect=AssertionError('forged probe')):
            with self.assertRaises(self.H.ProviderError) as caught:
                self.H.call_codex(self.ctx, None, FIXED_PROBE_PROMPT, None, None, False, self.out, 1)
        self.assertEqual(caught.exception.admission_code, 'PROVIDER_NOT_ALLOWED')
        self.assertEqual(list(self.out.iterdir()), [])
    def fake_cli(self, commands):
        def invoke(argv, cwd, **kwargs):
            commands.append((argv, cwd, kwargs))
            self.assertNotIn(str(self.repo), json.dumps([argv, str(cwd), kwargs], default=str))
            self.assertNotIn('PRIVATE_CONTEXT_CANARY', json.dumps([argv, str(cwd), kwargs], default=str))
            if argv[0] == 'codex':
                Path(argv[argv.index('-o') + 1]).write_text('{"ok": true}')
                return 0, '', ''
            if argv[0] == 'agy':
                return 0, json.dumps({'status': 'SUCCESS', 'structured_output': {'ok': True}}), ''
            if argv[0] == 'grok':
                return 0, json.dumps({'structuredOutput': {'ok': True}}), ''
            if argv[0] == 'claude': return 0, '{"ok": true}', ''
            self.fail('unexpected CLI')
        return invoke

    def test_real_wrappers_accept_only_the_live_fixed_neutral_probe(self):
        self.ctx.cfg.pop('data_egress')
        self.ctx.cfg['private_context'] = 'PRIVATE_CONTEXT_CANARY'
        models = {'codex': None, 'gemini': 'gemini-pro', 'gemini-flash': 'gemini-flash',
                  'claude-via-agy': 'claude-opus', 'claude': 'claude-opus', 'grok-cli': 'grok-4.7'}
        commands, paths = [], []
        with patch.object(self.H, 'sh', side_effect=self.fake_cli(commands)):
            for provider, model in models.items():
                with authorized_probe(self.ctx, provider, model) as (ctx, prompt, out):
                    paths.append(out)
                    result = self.H.CALLERS[provider](ctx, model, prompt, None, None, False, out, 1)
                    self.assertEqual(json.loads(result), {'ok': True})
                    with self.assertRaises(self.H.ProviderError):
                        self.H.CALLERS[provider](ctx, model, prompt, None, None, False, out, 1)
        self.assertEqual(len(commands), 6)
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_refresh_uses_leases_without_source_approval_and_retains_neutral_cleanup(self):
        self.ctx.cfg = {'providers': {}, 'models': {'codex': [None], 'gemini': ['gemini-pro'],
                                                 'claude': ['claude-opus'], 'grok-cli': ['grok-4.7']}}
        commands = []
        with patch.object(self.H, 'sh', side_effect=self.fake_cli(commands)):
            report = routing.refresh(self.ctx, self.H.CALLERS, self.out / 'availability.json', jobs=2)
        self.assertEqual(len(commands), 4)
        self.assertTrue(all(row['json_response'] for row in report['models']))
        self.assertTrue(all(not Path(cwd).exists() for _, cwd, _ in commands))
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_ask_refuses_policy_before_probe_or_mocked_caller(self):
        self.ctx.cfg['data_egress'] = restricted('gemini')
        with patch.object(self.H, 'probe', side_effect=AssertionError('no probe needed')), \
             patch.dict(self.H.CALLERS, {'codex': lambda *args: self.fail('source caller invoked')}):
            with self.assertRaises(self.H.ProviderError) as caught:
                self.H.ask(self.ctx, 'codex', 'PRIVATE_SOURCE_CANARY')
        self.assertEqual(caught.exception.admission_code, 'PROVIDER_NOT_ALLOWED')

    def test_admission_failure_does_not_attempt_a_silent_provider_fallback(self):
        self.ctx.cfg['providers']['fallback'] = 'gemini'
        self.ctx.cfg['data_egress'] = restricted('gemini')
        with patch.object(self.H, 'probe', return_value=(True, 'synthetic availability')) as probe, \
             patch.object(self.H, 'sh', side_effect=AssertionError('unadmitted model process')):
            with self.assertRaises(self.H.ProviderError) as caught:
                self.H.ask(self.ctx, 'codex', 'PRIVATE_SOURCE_CANARY')
        self.assertEqual(caught.exception.admission_code, 'PROVIDER_NOT_ALLOWED')
        # Odmowa zapada przed sondą i przed zapasowym dostawcą (gemini jest dopuszczony, ale nie wchodzi po cichu).
        self.assertEqual(probe.call_count, 0)

    def test_substitute_moves_to_next_available_provider_when_configured_one_is_limited(self):
        # Właściciel: Gemini na limicie, a sędzia UX i eksplorator stały zamiast przejść na Codexa, Claude albo Groka.
        self.ctx.cfg['models'] = {'gemini-flash': ['flash-high', 'flash-low'], 'codex': ['astra'], 'grok-cli': [None]}
        self.ctx.explicit_cfg = {'providers': {'visual_judge': 'gemini-flash'}}
        probed = []
        def probe(provider, ctx=None, model=None):
            probed.append((provider, model)); return provider == 'codex', 'synthetic availability'
        with patch.object(self.H, 'probe', side_effect=probe), \
             patch.dict(self.H.CALLERS, {'codex': lambda *args: '{"ok": true}'}):
            with self.assertRaises(self.H.ProviderError):   # bez zastępstwa jawny wybór zostaje i zadanie staje
                self.H.ask(self.ctx, 'gemini-flash', 'synthetic', need_json=True)
            text, used = self.H.ask(self.ctx, 'gemini-flash', 'synthetic', need_json=True, substitute=True)
        self.assertEqual((used['provider'], used['model'], used['fallback_used']), ('codex', 'astra', True))
        self.assertEqual(probed[-3:], [('gemini-flash', 'flash-high'), ('gemini-flash', 'flash-low'), ('codex', 'astra')])

    def test_review_invalid_policy_reports_error_before_diff_or_reviewers(self):
        self.ctx.cfg['data_egress'] = {'status': 'approved', 'allowlist': ['x']}
        self.ctx.ev = lambda cp: self.out
        self.ctx.cp = lambda cp: {'id': cp, 'title': 'synthetic'}
        self.ctx.state = lambda cp: {'base': 'a' * 40}
        with patch.object(self.H.helix_workflow, 'check_connections', return_value=True), \
             patch.object(self.H.helix_workflow, 'precheck', return_value={'pass': True}), \
             patch.object(self.H, 'diff_since', side_effect=AssertionError('no source diff needed')), \
             patch.object(self.H, 'ask', side_effect=AssertionError('no reviewer needed')):
            result = self.H.gate_review(self.ctx, 'cp1')
        self.assertEqual(result['status'], 'ERROR')
        self.assertFalse(result['pass'])
        self.assertEqual(result['verdicts'], [])
        self.assertFalse((self.out / 'diff.patch').exists())
        self.assertEqual(json.loads((self.out / 'review.json').read_text())['status'], 'ERROR')

    def test_restricted_review_records_native_admission_error_without_model_execution(self):
        self.ctx.cfg['providers']['implementer'] = 'codex'
        self.ctx.cfg['data_egress'] = restricted('codex')
        self.ctx.cfg['providers']['reviewers'] = [dict(name='A', provider='gemini'), dict(name='B', provider='claude')]
        self.ctx.ev = lambda cp: self.out
        self.ctx.cp = lambda cp: dict(id=cp, title='synthetic', goal='synthetic', test_cases=[])
        self.ctx.state = lambda cp: {'base': 'a' * 40}
        self.ctx.architecture = lambda: 'synthetic architecture'
        with patch.object(self.H.helix_workflow, 'check_connections', return_value=True), \
             patch.object(self.H.helix_workflow, 'precheck', return_value={'pass': True}), \
             patch.object(self.H.helix_workflow, 'matching_rules', return_value=[]), \
             patch.object(self.H.helix_workflow, 'diff_files', return_value=[]), \
             patch.object(self.H, 'diff_since', return_value='synthetic diff'), \
             patch.object(self.H, 'probe', return_value=(True, 'synthetic availability')), \
             patch.object(self.H, 'sh', side_effect=AssertionError('no model process')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.H.gate_review(self.ctx, 'cp1')
        self.assertEqual(result['status'], 'ERROR')
        self.assertFalse(result['pass'])
        self.assertEqual(result['model_admission'], [dict(reviewer=name, code='PROVIDER_NOT_ALLOWED') for name in ('A', 'B')])
        self.assertTrue(all(row['used'] is None for row in result['verdicts']))
        self.assertIn('gate review: ERROR', output.getvalue())
        self.assertEqual(json.loads((self.out / 'review.json').read_text())['status'], 'ERROR')

    def test_visual_identical_pixels_cannot_turn_admission_refusal_into_pass(self):
        (self.out / 'screenshots').mkdir()
        (self.repo / 'reference.png').write_bytes(b'synthetic reference')
        self.ctx.cfg['visual'] = dict(enabled=True, url='http://localhost', reference_image='reference.png')
        self.ctx.cfg['providers']['visual_judge'] = 'codex'
        self.ctx.ev = lambda cp: self.out
        self.ctx.cp = lambda cp: dict(id=cp, visual=True)
        def fake_shot(ctx, url, destination):
            destination.write_bytes(b'synthetic screenshot')
            return []
        for policy, code in ((restricted('gemini'), 'PROVIDER_NOT_ALLOWED'), ({'status': 'approved', 'allowlist': ['x']}, 'INVALID_POLICY')):
            self.ctx.cfg['data_egress'] = policy
            with self.subTest(code=code), \
                 patch.object(self.H, 'Server', return_value=contextlib.nullcontext()), \
                 patch.object(self.H, 'screenshot', side_effect=fake_shot), \
                 patch.object(self.H, 'pixel_diff', return_value=dict(changed_pixels_ratio=0, bbox=None)), \
                 patch.object(self.H, 'probe', return_value=(True, 'synthetic availability')), \
                 patch.object(self.H, 'sh', side_effect=AssertionError('no model process')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                result = self.H.gate_visual(self.ctx, 'cp1')
            self.assertFalse(result['pass'])
            self.assertEqual(result['status'], 'ERROR')
            self.assertEqual(result['model_admission']['code'], code)
            self.assertIsNone(result['judge'])
            self.assertIn('gate visual: ERROR', output.getvalue())
            self.assertFalse(json.loads((self.out / 'visual.json').read_text())['pass'])

    def test_gate_error_reaches_the_shell_as_exit_three(self):
        self.ctx.state = lambda cp: {'base': 'a' * 40}
        args = SimpleNamespace(which='review', checkpoint='cp1', round=1)
        with patch.object(self.H, 'gate_review', return_value={'gate': 'review', 'pass': False, 'status': 'ERROR'}), \
             contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            self.H.cmd_gate(self.ctx, args)
        self.assertEqual(caught.exception.code, 3)
        self.assertEqual(json.loads(output.getvalue())['status'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
