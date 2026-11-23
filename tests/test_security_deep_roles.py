"""Exact source-review model assignments use synthetic fresh proofs, never network."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_deep_budget as fixture
from test_security_deep import D, H, availability
import helix_provider_plan as RP


class DeepRoles(unittest.TestCase):
    setUp, args, covered = fixture.DeepBudget.setUp, fixture.DeepBudget.args, fixture.DeepBudget.covered
    hunter, verifier, load = fixture.DeepBudget.hunter, fixture.DeepBudget.verifier, fixture.DeepBudget.load

    def configure(self, hunter='codex', verifier='grok-cli', explicit=True):
        self.cfg['models'] = {p: [p + '-exact'] for p in RP.JSON_PROVIDERS}
        self.cfg['providers'].update(hunter=hunter, verifier=verifier)
        self.ctx.explicit_cfg = {'providers': {'hunter': hunter, 'verifier': verifier}} if explicit else {}
        self.ctx.availability = availability(self.cfg)

    def test_every_json_provider_can_hunt_with_a_different_family(self):
        for provider in RP.JSON_PROVIDERS:
            with self.subTest(provider=provider):
                other = 'claude' if provider == 'codex' else 'codex'
                self.configure(provider, other)
                calls = []
                def invoke(ctx, model, *args, **kwargs):
                    role = 'hunter' if hasattr(ctx, '_deep_batch_index') else 'verifier'
                    calls.append((role, model))
                    return (self.hunter if role == 'hunter' else self.verifier)(ctx, model, *args, **kwargs)
                with patch.object(H, 'call_codex', side_effect=invoke), patch.object(H, 'call_claude', side_effect=invoke), \
                     patch.object(H, 'call_agy', side_effect=invoke), patch.object(H, 'call_grok_cli', side_effect=invoke):
                    out, meta = D.run(self.ctx, self.args(out=str(self.root / provider)))
                self.assertEqual(meta['run_status'], 'complete')
                self.assertEqual(calls, [('hunter', provider + '-exact'), ('verifier', other + '-exact')])
                self.assertTrue(meta['role_plan']['independent_verifier'])
                self.assertEqual(meta['plan']['role_plan'], meta['role_plan'])
                checkpoint = json.loads((out / 'checkpoint.json').read_text())
                self.assertEqual(checkpoint['settings']['role_assignments']['hunter']['provider'], provider)
                cache = next(p for p in Path(checkpoint['cache_root']).glob('*.json')
                             if json.loads(p.read_text()).get('role_assignments', {}).get('hunter', {}).get('provider') == provider)
                self.assertEqual(json.loads(cache.read_text())['role_plan'], meta['role_plan'])

    def test_aliases_in_same_family_remain_limited_without_calls(self):
        for hunter, verifier in [('claude', 'claude-via-agy'), ('gemini', 'gemini-flash'), ('codex', 'codex')]:
            with self.subTest(hunter=hunter):
                self.configure(hunter, verifier)
                _, meta = D.run(self.ctx, self.args(out=str(self.root / hunter)))
                self.assertEqual(meta['run_status'], 'limited')
                self.assertEqual(meta['role_plan']['deep_status'], 'LIMITED')
                self.assertEqual(meta['role_plan']['roles']['verifier']['provider'], verifier)
                self.assertFalse(meta['provider_attempts'])
                self.assertEqual(meta['progress']['batches_not_checked'], 1)
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_agy_alias_cannot_hide_another_model_family(self):
        self.configure('claude', 'gemini')
        self.cfg['models']['gemini'] = ['claude-opus-fixture']
        self.ctx.availability = availability(self.cfg)
        _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'limited')
        role = meta['role_plan']['roles']['verifier']
        self.assertEqual(role['model'], 'claude-opus-fixture')
        self.assertEqual(role['family'], 'anthropic')
        self.assertEqual(role['status'], 'model_conflict')
        self.assertFalse(meta['provider_attempts'])

    def test_stale_or_missing_proof_never_calls_models_or_uses_cache(self):
        self.configure()
        D.run(self.ctx, self.args())
        before = len(self.hunter_calls + self.verifier_calls)
        for receipt in self.ctx.availability['models']:
            receipt['checked_at'] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        out, meta = D.run(self.ctx, self.args(out=str(self.root / 'stale')))
        self.assertEqual(meta['run_status'], 'limited')
        self.assertEqual(len(self.hunter_calls + self.verifier_calls), before)
        self.assertEqual(meta['progress']['cache_hits'], 0)
        self.assertIn('LIMITED', (out / 'REPORT.md').read_text())
        self.ctx.availability = {}
        _, meta = D.run(self.ctx, self.args(out=str(self.root / 'missing')))
        self.assertEqual(meta['run_status'], 'limited')
        self.assertEqual(meta['providers'], [])

    def test_explicit_unavailable_model_preserved_and_alternative_only_proposed(self):
        self.configure()
        self.cfg['models']['codex'] = ['requested-unavailable', 'available-second']
        self.ctx.explicit_cfg['models'] = {'codex': self.cfg['models']['codex'][:]}
        self.ctx.availability = availability(self.cfg)
        self.ctx.availability['models'] = [r for r in self.ctx.availability['models'] if r['model'] != 'requested-unavailable']
        original = copy.deepcopy(self.cfg)
        _, meta = D.run(self.ctx, self.args())
        role = meta['role_plan']['roles']['hunter']
        self.assertEqual(role['model'], 'requested-unavailable')
        self.assertTrue(role['explicit'])
        self.assertEqual(meta['run_status'], 'limited')
        self.assertTrue(meta['role_plan']['proposals'])
        self.assertEqual(self.cfg, original)
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_cli_provider_overrides_config_but_retains_exact_model(self):
        self.configure('claude', 'gemini')
        _, meta = D.run(self.ctx, self.args(hunter='codex', verifier='grok-cli'))
        self.assertEqual([(r['provider'], r['model']) for r in meta['providers']],
                         [('codex', 'codex-exact'), ('grok-cli', 'grok-cli-exact')])
        self.assertEqual(self.cfg['providers']['hunter'], 'claude')
        self.assertTrue(meta['role_plan']['roles']['hunter']['explicit'])

    def test_auto_plan_can_select_an_available_secondary_model_but_never_runtime_fallback(self):
        self.configure(explicit=False)
        self.cfg['models']['codex'] = ['missing', 'fresh']
        self.ctx.availability = availability(self.cfg)
        self.ctx.availability['models'] = [r for r in self.ctx.availability['models'] if r['model'] != 'missing']
        with patch.object(H, 'call_codex', side_effect=H.ProviderError('synthetic failure')):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['role_plan']['roles']['hunter']['model'], 'fresh')
        self.assertEqual(meta['usage']['calls'], 1)
        self.assertEqual(meta['provider_attempts'][0]['model'], 'fresh')
        self.assertEqual(meta['run_status'], 'error')
        self.assertFalse(self.verifier_calls)

    def test_resume_rechecks_freshness_without_changing_the_saved_auto_assignment(self):
        self.configure(explicit=False)
        D.run(self.ctx, self.args(budget='calls=1'))
        saved = copy.deepcopy(self.ctx.availability)
        self.ctx.availability['models'] = [r for r in saved['models'] if r['provider'] != 'grok-cli']
        # Ctx may apply a fresh automatic suggestion to its effective config.
        self.cfg['providers']['verifier'] = 'gemini'
        _, limited = D.run(self.ctx, self.args(resume=str(self.out), budget='calls=2'))
        self.assertEqual(limited['run_status'], 'limited')
        self.assertEqual(limited['role_plan']['roles']['verifier']['provider'], 'grok-cli')
        self.assertEqual(limited['usage']['calls'], 1)
        self.ctx.availability = saved
        _, complete = D.run(self.ctx, self.args(resume=str(self.out), budget='calls=2'))
        self.assertEqual(complete['run_status'], 'complete')
        self.assertEqual(len(self.hunter_calls), 1)
        self.assertEqual(len(self.verifier_calls), 1)
        with self.assertRaisesRegex(ValueError, 'resume'):
            D.run(self.ctx, self.args(resume=str(self.out), verifier='gemini'))

    def test_removed_proof_during_a_run_preserves_not_checked_candidates_without_calls(self):
        self.configure()
        original = self.hunter
        def hunt(*args):
            result = original(*args)
            args[0].availability['models'] = []
            return result
        with patch.object(H, 'call_codex', side_effect=hunt):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'limited')
        self.assertEqual(meta['usage']['calls'], 1)
        self.assertEqual(meta['progress']['candidates_not_checked'], 1)
        self.assertFalse(self.verifier_calls)

    def test_long_run_can_use_admitted_exact_verifier_and_refresh_only_its_receipt(self):
        self.configure()
        self.ctx.availability['models'][0].update(stdout='SECRET-PROBE-OUTPUT', prompt='SECRET-PROMPT', env={'token': 'SECRET-TOKEN'})
        initial = copy.deepcopy(self.ctx.availability)
        original = self.hunter
        def hunt(*args):
            result = original(*args)
            for receipt in args[0].availability['models']:
                if receipt['provider'] == 'grok-cli':
                    receipt['checked_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            return result
        with patch.object(H, 'call_codex', side_effect=hunt):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'complete')
        self.assertEqual(meta['usage']['calls'], 2)
        self.assertEqual(meta['admission_proofs'], [D.admission_receipt(RP.model_record(initial, p, p + '-exact')) for p in ('codex', 'grok-cli')])
        self.assertNotIn('SECRET-', (self.out / 'run-metadata.json').read_text())
        self.assertNotIn('SECRET-', (self.out / 'checkpoint.json').read_text())
        self.assertEqual({r['method'] for r in meta['availability_receipts']}, {'model_response'})
        self.assertEqual(self.ctx.availability, initial)

    def test_failed_expired_admitted_model_is_limited_without_fallback(self):
        self.configure()
        original = self.hunter
        def hunt(*args):
            result = original(*args)
            for receipt in args[0].availability['models']:
                if receipt['provider'] == 'grok-cli':
                    receipt['checked_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            return result
        with patch.object(H, 'call_codex', side_effect=hunt), patch.object(H, 'call_grok_cli', side_effect=H.ProviderError('offline')):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'limited')
        self.assertEqual(meta['usage']['calls'], 2)
        self.assertEqual(meta['role_plan']['deep_status'], 'LIMITED')
        self.assertEqual(meta['role_plan']['proposals'][-1]['current']['provider'], 'grok-cli')
        self.assertEqual(meta['progress']['candidates_not_checked'], 1)
        self.assertEqual([r['provider'] for r in meta['availability_receipts']], ['codex'])
        self.assertFalse(self.verifier_calls)

    def test_provider_plan_preview_works_offline_and_can_resolve_missing_roles_on_resume(self):
        self.ctx.availability = {}
        out, preview = D.preview_plan(self.repo, self.cfg, self.ctx.state_dir, self.out,
                                      availability={}, explicit_cfg={})
        self.assertEqual(preview['run_status'], 'planned')
        self.assertEqual(preview['role_plan']['deep_status'], 'LIMITED')
        self.assertFalse(preview['provider_attempts'])
        self.ctx.availability = availability(self.cfg)
        _, meta = D.run(self.ctx, self.args(resume=str(out)))
        self.assertEqual(meta['run_status'], 'complete')
        self.assertEqual(meta['role_plan']['deep_status'], 'READY')

    def test_response_cache_and_batch_cache_pin_prompt_and_exact_model(self):
        self.configure()
        state = {'base_prompt': 'instructions', 'settings': {'role_assignments':
            D.role_assignments(D.role_plan(self.ctx, self.args()))},
            'contract': {'vendor_digest': 'vendor', 'auth_context_digest': 'guards'}}
        batch = {'source_sha256': 'source'}
        key = D.batch_cache_key(state, batch, self.ctx)
        state['settings']['role_assignments']['hunter']['model'] = 'changed'
        self.assertNotEqual(D.batch_cache_key(state, batch, self.ctx), key)
        state['settings']['role_assignments']['hunter']['model'] = 'codex-exact'
        state['base_prompt'] = 'changed instructions'
        self.assertNotEqual(D.batch_cache_key(state, batch, self.ctx), key)
        work = self.root / 'responses'; work.mkdir()
        cache = {}; assignment = {'provider': 'codex', 'model': 'codex-exact'}
        D.ask(self.ctx, assignment, 'prompt', work, 'hunter', cache=cache)
        self.cfg['models']['codex'].append('second-exact'); self.ctx.availability = availability(self.cfg)
        D.ask(self.ctx, dict(assignment, model='second-exact'), 'prompt', work, 'hunter', cache=cache)
        self.assertEqual(len(self.hunter_calls), 2)
        D.ask(self.ctx, assignment, 'prompt', work, 'hunter', cache=cache)
        self.assertEqual(len(self.hunter_calls), 2)

    def test_unknown_default_model_does_not_reuse_cached_hunter(self):
        self.configure()
        self.cfg['models']['codex'] = [None]
        self.ctx.availability = availability(self.cfg)
        D.run(self.ctx, self.args())
        _, meta = D.run(self.ctx, self.args(out=str(self.root / 'second')))
        self.assertEqual(len(self.hunter_calls), 2)
        self.assertEqual(meta['progress']['cache_hits'], 0)
        self.assertIsNone(meta['provenance']['models'][0]['model'])


if __name__ == '__main__': unittest.main()
