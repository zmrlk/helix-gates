"""Source orchestration authorization (default: all providers; refusal: owner restriction, offline) and manual exports, all synthetic."""
import copy
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_deep_budget as fixture
from test_security_deep import D, H, availability
from helix_data_egress import DataEgressError, policy_sha256
from helix_model_admission import effective_policy
import helix_manual_review as manual


def approval(providers=('codex', 'grok-cli'), **values):
    return dict(status='approved', allowed_providers=list(providers), exclude_paths=[], **values)


def refuse_at_call(original):
    """Granica odmawia w chwili wywołania (tu: tryb offline), choć polityka na starcie przebiegu dopuszczała dostawcę."""
    def call(ctx, *args, **kwargs):
        refused = copy.copy(ctx); refused.offline = True
        return original(refused, *args, **kwargs)
    return call


class DeniedCache(dict):
    def __contains__(self, key):
        raise AssertionError('cache examined before approval')


class DeniedBudget:
    @property
    def lock(self):
        raise AssertionError('budget touched before approval')


class DeepModelEgress(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def test_invalid_policy_and_owner_restriction_refuse_before_sources_budget_or_cache(self):
        # Brak polityki i propozycja czekająca na właściciela dopuszczają wszystkich (decyzja 15.11.2026); odmawia jawne ograniczenie.
        policies = [(dict(status='approved', allowlist=['x']), 'INVALID_POLICY'),
                    (approval(('claude',)), 'PROVIDER_NOT_ALLOWED')]
        for policy, expected in policies:
            self.cfg['data_egress'] = policy
            with self.subTest(expected=expected), \
                    patch.object(D, 'context_plan', side_effect=AssertionError('sources')), \
                    patch.object(D, 'parse_budget', side_effect=AssertionError('budget')), \
                    patch.object(D, 'load_batch_cache', side_effect=AssertionError('cache')):
                with self.assertRaises(DataEgressError) as caught:
                    D.run(self.ctx, self.args())
                self.assertEqual(caught.exception.code, expected)
            with self.subTest(ask=expected), self.assertRaises(DataEgressError) as caught:
                D.ask(self.ctx, dict(provider='codex', model='fixture'), 'SOURCE_CANARY', self.out,
                      'hunter', budget=DeniedBudget(), cache=DeniedCache())
            self.assertEqual(caught.exception.code, expected)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_source_batches_sent_to_models_have_secrets_masked(self):
        import base64, subprocess
        part = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        token = part(dict(alg='HS256')) + '.' + part(dict(role='service_role', ref='abc')) + '.' + part('podpis-testowy-nie-jest-kluczem')
        (self.repo / 'src').mkdir(exist_ok=True)
        (self.repo / 'src' / 'plain_name.sql').write_text("select 1;\nselect net.http_post(headers:='Bearer " + token + "');\nselect 2;\n")
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True, capture_output=True)
        batches, _ = D.context_plan(self.repo, ['.'], 'standard')
        text = '\n'.join(batch for batch, _ in batches)
        self.assertIn('FILE src/plain_name.sql', text)
        self.assertNotIn(token, text); self.assertNotIn('eyJ', text)
        self.assertIn('1: select 1;', text); self.assertIn('3: select 2;', text)

    def test_secret_masking_keeps_ordinary_code_visible(self):
        from helix_data_egress import mask_secrets
        form = ('<Input type="password" name="password" placeholder="Hasło" value={password} />\n'
                'const token = session?.access_token;\nif (!email.includes("@")) setError("Niepoprawny e-mail");\n'
                'const { data } = await supabase.auth.signInWithPassword({ email, password });\n')
        self.assertEqual(mask_secrets(form), (form, 0))
        value = 'a1b2c3d4e5' + 'f6g7h8i9j0kk'   # wartość składana w teście: w repozytorium nie ma napisu wyglądającego na klucz
        secret = 'const API_KEY = "' + value + '";\nconst password = \'Tajne1234\';\n'
        masked, count = mask_secrets(secret)
        self.assertEqual(count, 2); self.assertNotIn('a1b2c3', masked); self.assertNotIn('Tajne1234', masked)
        self.assertEqual(masked, 'const API_KEY = "[HELIX_SECRET]";\nconst password = \'[HELIX_SECRET]\';\n')
        # Przypadki z recenzji G3: spacje w wartości, odwrotne apostrofy, cudzysłów wewnątrz literału; składnia zostaje poprawna.
        for line, expected in (('password = "two words 123";', 'password = "[HELIX_SECRET]";'),
                               ('const apiKey = `abc def`;', 'const apiKey = `[HELIX_SECRET]`;'),
                               ('secret: "a\\"b c";', 'secret: "[HELIX_SECRET]";')):
            self.assertEqual(mask_secrets(line), (expected, 1))

    def test_verifier_approval_is_checked_before_hunter_execution(self):
        self.cfg['data_egress'] = approval(('codex',))
        with self.assertRaises(DataEgressError) as caught:
            D.run(self.ctx, self.args())
        self.assertEqual(caught.exception.code, 'PROVIDER_NOT_ALLOWED')
        self.assertFalse(self.hunter_calls + self.verifier_calls)
        self.assertFalse(self.out.exists())

    def test_invalid_policy_refuses_before_reading_resume_checkpoint(self):
        self.cfg['data_egress'] = dict(status='approved', allowlist=['x'])
        with patch.object(D, '_checkpoint', side_effect=AssertionError('cached responses read')):
            with self.assertRaises(DataEgressError) as caught:
                D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertEqual(caught.exception.code, 'INVALID_POLICY')

    def test_plan_and_offline_plan_remain_available_without_source_approval(self):
        self.cfg.pop('data_egress')
        self.ctx.offline = True
        _, meta = D.run(self.ctx, self.args(plan_only=True))
        self.assertEqual(meta['run_status'], 'planned')
        self.assertEqual(meta['data_egress_policy_sha256'], policy_sha256(effective_policy(None)))
        self.assertEqual(meta['providers'], [])
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_preview_plan_accepts_missing_and_pending_policy_without_authorization(self):
        for name, policy in (('missing', None), ('pending', dict(status='pending_owner', allowed_providers=[], exclude_paths=[]))):
            self.cfg['data_egress'] = policy
            with self.subTest(name=name), patch.object(D, 'authorize_provider', side_effect=AssertionError('source execution admission')):
                _, meta = D.preview_plan(self.repo, self.cfg, self.ctx.state_dir, self.root/name,
                                         availability=self.ctx.availability)
            self.assertEqual(meta['run_status'], 'planned')
            self.assertEqual(meta['providers'], [])
            self.assertEqual(meta['usage']['calls'], 0)
            self.assertEqual(meta['data_egress_policy_sha256'], policy_sha256(effective_policy(policy)))
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_response_cache_and_receipt_bind_the_canonical_policy_hash(self):
        self.cfg['data_egress'] = approval()
        work = self.root/'response'; work.mkdir()
        cache = {}
        assignment = dict(provider='codex', model='fixture')
        _, first = D.ask(self.ctx, assignment, 'synthetic source', work, 'hunter', cache=cache)
        self.assertEqual(first['data_egress_policy_sha256'], policy_sha256(self.cfg['data_egress']))
        for entry in cache.values():
            self.assertEqual(entry['data_egress_policy_sha256'], first['data_egress_policy_sha256'])
        D.ask(self.ctx, assignment, 'synthetic source', work, 'hunter', cache=cache)
        self.assertEqual(len(self.hunter_calls), 1)
        self.cfg['data_egress']['approved_by'] = 'synthetic second approval'
        _, second = D.ask(self.ctx, assignment, 'synthetic source', work, 'hunter', cache=cache)
        self.assertEqual(len(self.hunter_calls), 2)
        self.assertNotEqual(first['data_egress_policy_sha256'], second['data_egress_policy_sha256'])
        self.cfg['data_egress'] = approval(('claude',))
        with self.assertRaises(DataEgressError):
            D.ask(self.ctx, assignment, 'synthetic source', work, 'hunter', cache=cache)
        self.assertEqual(len(self.hunter_calls), 2)
        # Bez polityki obowiązuje domyślna (wszyscy dostawcy) z własnym skrótem: odpowiedź z pamięci podręcznej nie jest dzielona.
        self.cfg.pop('data_egress')
        _, third = D.ask(self.ctx, assignment, 'synthetic source', work, 'hunter', cache=cache)
        self.assertEqual(third['data_egress_policy_sha256'], policy_sha256(effective_policy(None)))
        self.assertEqual(len(self.hunter_calls), 3)

    def test_legacy_and_unbound_response_entries_are_cache_misses(self):
        self.cfg['data_egress'] = approval()
        work = self.root/'response'; work.mkdir()
        assignment, prompt = dict(provider='codex', model='fixture'), 'synthetic'
        legacy = dict(data={'legacy': True}, used={'provider': 'codex', 'model': 'fixture'})
        cache = {D.digest([assignment, 'hunter', prompt, D.VERSION]): copy.deepcopy(legacy)}
        result, _ = D.ask(self.ctx, assignment, prompt, work, 'hunter', cache=cache)
        self.assertNotIn('legacy', result)
        key = D.digest([assignment, 'hunter', prompt, D.VERSION, policy_sha256(self.cfg['data_egress'])])
        cache[key] = legacy
        result, _ = D.ask(self.ctx, assignment, prompt, work, 'hunter', cache=cache)
        self.assertNotIn('legacy', result)
        self.assertEqual(len(self.hunter_calls), 2)
        cache[key]['used']['model'] = 'different-model'
        D.ask(self.ctx, assignment, prompt, work, 'hunter', cache=cache)
        self.assertEqual(len(self.hunter_calls), 3)

    def test_batch_cache_and_provider_attempts_preserve_policy_binding(self):
        self.cfg['data_egress'] = approval()
        _, meta = D.run(self.ctx, self.args())
        expected = policy_sha256(self.cfg['data_egress'])
        self.assertEqual(meta['data_egress_policy_sha256'], expected)
        self.assertTrue(all(r['data_egress_policy_sha256'] == expected for r in meta['provider_attempts']))
        self.assertTrue(all(r['data_egress_policy_sha256'] == expected for r in meta['providers']))
        state = self.load('checkpoint.json')
        cached = next(Path(state['cache_root']).glob('*.json'))
        content = json.loads(cached.read_text())
        self.assertEqual(content.pop('data_egress_policy_sha256'), expected)
        self.assertEqual(content['result']['used']['provider'], 'codex')
        self.assertEqual(content['result']['used']['model'], 'fixture')
        self.assertEqual(content['result']['used']['data_egress_policy_sha256'], expected)
        cached.write_text(json.dumps(content))
        _, fresh = D.run(self.ctx, self.args(out=str(self.root/'fresh')))
        self.assertEqual(fresh['progress']['cache_hits'], 0)
        self.assertEqual(len(self.hunter_calls), 2)
        # A current filename/key and outer hash do not upgrade an old cache
        # without its actual exact-model/policy receipt.
        content = json.loads(cached.read_text())
        content['result'].pop('used')
        cached.write_text(json.dumps(content))
        _, unbound = D.run(self.ctx, self.args(out=str(self.root/'unbound')))
        self.assertEqual(unbound['progress']['cache_hits'], 0)
        self.assertEqual(len(self.hunter_calls), 3)
        self.cfg['data_egress']['approved_by'] = 'new declaration'
        _, changed = D.run(self.ctx, self.args(out=str(self.root/'changed')))
        self.assertEqual(changed['progress']['cache_hits'], 0)
        self.assertEqual(len(self.hunter_calls), 4)

    def test_resume_cannot_rebind_old_results_to_changed_approval(self):
        self.cfg['data_egress'] = approval()
        D.run(self.ctx, self.args(budget='calls=1'))
        before = (self.out/'checkpoint.json').read_bytes()
        self.cfg['data_egress']['approved_by'] = 'different approval'
        with self.assertRaisesRegex(ValueError, 'resume'):
            D.run(self.ctx, self.args(resume=str(self.out), budget='calls=2'))
        self.assertEqual((self.out/'checkpoint.json').read_bytes(), before)
        self.assertEqual(len(self.hunter_calls), 1)
        self.assertFalse(self.verifier_calls)

    def test_agy_receives_exact_provider_keyword_instead_of_guessing_from_model(self):
        self.cfg['data_egress'] = approval(('gemini-flash',))
        self.cfg['models']['gemini-flash'] = ['gemini-flash-synthetic']
        self.ctx.availability = availability(self.cfg)
        with patch.object(H, 'call_agy', return_value='{}') as invoke:
            D.ask(self.ctx, dict(provider='gemini-flash', model='gemini-flash-synthetic'),
                  'synthetic', self.out, 'hunter')
        self.assertEqual(invoke.call_args.kwargs, {'provider': 'gemini-flash'})

    def test_real_native_transport_refusal_is_error_without_model_call_or_fallback(self):
        from test_provider_plan import load_helix
        native = load_helix()
        self.cfg['data_egress'] = approval()
        with patch.object(D, 'H', native), \
                patch.object(native, 'sh', side_effect=AssertionError('native process')), \
                patch.object(native, 'probe', side_effect=AssertionError('availability probe')), \
                patch.object(native, 'call_codex', side_effect=refuse_at_call(native.call_codex)) as caller, \
                patch.object(native, 'call_grok_cli', side_effect=AssertionError('verifier or fallback')), \
                patch.object(native, 'call_agy', side_effect=AssertionError('fallback')):
            _, meta = D.run(self.ctx, self.args(jobs=1, budget='calls=1'))
        self.assertEqual(caller.call_count, 1)
        self.assertEqual(meta['run_status'], 'error')
        self.assertEqual(meta['error_code'], 'OFFLINE')
        self.assertEqual(meta['stop_reason'], 'data_egress: OFFLINE')
        self.assertEqual(meta['usage']['calls'], 0)
        self.assertEqual(meta['usage']['prompt_bytes'], 0)
        self.assertEqual(meta['providers'], [])
        self.assertEqual(meta['provenance']['models'], [])
        self.assertEqual(len(meta['provider_attempts']), 1)
        attempt = meta['provider_attempts'][0]
        self.assertEqual(attempt['status'], 'not_invoked')
        self.assertFalse(attempt['call_invoked'])
        self.assertEqual(attempt['error_code'], 'OFFLINE')
        self.assertEqual(self.load('provider-errors.json')[0]['error_code'], 'OFFLINE')
        self.assertFalse(list(self.out.rglob('*prompt*.md')))
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_native_refusal_is_not_hidden_by_parallel_budget_reservation(self):
        from test_provider_plan import load_helix
        native = load_helix()
        self.cfg['data_egress'] = approval()
        release = threading.Event()
        original_begin = D.Budget.begin
        def reserve(budget, *args, **kwargs):
            try:
                return original_begin(budget, *args, **kwargs)
            except D.BudgetExceeded:
                release.set()
                raise
        def denied(ctx, *args, **kwargs):
            self.assertTrue(release.wait(3), 'second reservation must reach budget before denial')
            refused = copy.copy(ctx); refused.offline = True   # odmowa na granicy w chwili wywołania
            return native.call_codex(refused, *args, **kwargs)
        callers = SimpleNamespace(**{name: getattr(native, name) for name in
            ('call_claude', 'call_grok_cli', 'call_agy', 'ProviderError')}, call_codex=denied)
        batches = [('FILE src/app.py\nvalue=1', ['src/app.py']),
                   ('FILE src/app.py\nvalue=2', ['src/app.py'])]
        with patch.object(D, 'H', callers), patch.object(D.Budget, 'begin', new=reserve), \
                patch.object(native, 'sh', side_effect=AssertionError('native process')), \
                patch.object(D, 'context_plan', return_value=(batches, [dict(unit='src/app.py', status='planned', reason=None)])):
            _, meta = D.run(self.ctx, self.args(jobs=3, budget='calls=1'))
        self.assertTrue(release.is_set())
        self.assertEqual(meta['run_status'], 'error')
        self.assertEqual(meta['error_code'], 'OFFLINE')
        self.assertEqual(meta['usage']['calls'], 0)
        self.assertEqual(len(meta['provider_attempts']), 1)
        self.assertFalse(meta['provider_attempts'][0]['call_invoked'])


class ManualModelEgress(unittest.TestCase):
    def test_public_prepare_and_handoff_refuse_before_protocol_clock_or_source_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            args = dict(checkpoint='cp1', reviewer='synthetic', round_no=1,
                        prompt='SOURCE_PROMPT_CANARY', diff='-SOURCE_DIFF_CANARY')
            policies = [(dict(status='approved', allowlist=['x']), 'INVALID_POLICY'),
                        (approval(('grok-cli',)), 'PROVIDER_NOT_ALLOWED')]
            for entrypoint in (manual.prepare, manual.handoff):
                for policy, expected in policies:
                    with self.subTest(entrypoint=entrypoint.__name__, expected=expected), \
                            patch.object(manual, '_prepare_local_protocol', side_effect=AssertionError('export')), \
                            patch.object(manual, 'read_response', side_effect=AssertionError('cached answer')), \
                            patch.object(manual.time, 'monotonic', side_effect=AssertionError('wait')):
                        with self.assertRaises(DataEgressError) as caught:
                            entrypoint(out, policy=policy, **args)
                        self.assertEqual(caught.exception.code, expected)
                        self.assertNotIn('CANARY', str(caught.exception))
            self.assertEqual(list(out.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
