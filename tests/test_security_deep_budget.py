"""Budget, progress and resume contracts use synthetic source and fake providers."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_security_deep import D, H, ledger, record, availability, NormalResources


@unittest.skipUnless(shutil.which('node'), 'Local Node validator unavailable')
class DeepBudget(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.repo = self.root / 'repo'; self.repo.mkdir()
        (self.repo / 'src').mkdir(); (self.repo / 'src/app.py').write_text('def update():\n    pass\n')
        for argv in (['git', 'init', '-q'], ['git', 'add', '.'], ['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture']):
            subprocess.run(argv, cwd=self.repo, check=True, capture_output=True)
        self.cfg = copy.deepcopy(H.DEFAULT_CFG)
        self.cfg['data_egress'] = dict(status='approved', allowed_providers=list(__import__('helix_provider_plan').JSON_PROVIDERS), exclude_paths=[])
        self.cfg['models'] = {'codex': ['fixture'], 'grok-cli': ['fixture'], 'gemini': ['fixture']}
        self.ctx = SimpleNamespace(repo=self.repo, cfg=self.cfg, state_dir=self.root / 'state', external_state=True, availability=availability(self.cfg), resource_governor=NormalResources())
        self.out = self.root / 'audit'
        self.hunter_calls = []; self.verifier_calls = []
        self.addCleanup(patch.stopall)
        patch.object(D, 'H', H).start()
        patch.object(H, 'call_codex', side_effect=self.hunter).start()
        patch.object(H, 'call_grok_cli', side_effect=self.verifier).start()
        patch.object(H, 'call_agy', side_effect=self.verifier).start()

    def args(self, **overrides):
        return SimpleNamespace(**(dict(hunter=None, verifier=None, profile=None, scope=None, max_candidates=None,
                                       out=str(self.out), budget=None, resume=None, plan_only=False) | overrides))

    def covered(self):
        rows = ledger()
        rows[0].update(status='covered', agent_id='fixture', reviewed_paths=['src/app.py'],
                       local_checks=[dict(agent_id='fixture', reviewed_paths=['src/app.py'], invariant='Ownership', method='source', result='Reviewed fixture', artifact=None)])
        return rows

    def hunter(self, ctx, model, prompt, images, schema, write, out, timeout, **kwargs):
        self.hunter_calls.append((prompt, timeout))
        return json.dumps(dict(architecture_md='# Fixture', coverage_ledger=self.covered(), candidates=[record()]))

    def verifier(self, ctx, model, prompt, images, schema, write, out, timeout, **kwargs):
        self.verifier_calls.append((prompt, timeout)); return json.dumps(record())

    def load(self, name='run-metadata.json'):
        return json.loads((self.out / name).read_text())

    def test_budget_parser_rejects_ambiguous_or_unbounded_values(self):
        self.assertEqual(D.parse_budget('time=1.5m,calls=3'), {'seconds': 90.0, 'calls': 3})
        for value in ('', '0', 'calls=0', 'calls=1.5', 'calls=2s', 'time=-1', 'time=nan', 'calls=1,calls=2'):
            with self.subTest(value=value), self.assertRaises(ValueError): D.parse_budget(value)

    def test_plan_cost_is_saved_before_any_provider_call(self):
        _, meta = D.run(self.ctx, self.args(plan_only=True, profile='standard'))
        self.assertEqual(meta['run_status'], 'planned'); self.assertFalse(self.hunter_calls + self.verifier_calls)
        batches, _ = D.context_plan(self.repo, ['.'], 'standard')
        self.assertEqual(meta['plan']['source_bytes'], sum(len(text.encode()) for text, _ in batches))
        self.assertEqual(meta['plan']['batches'], 1); self.assertEqual(meta['plan']['calls_min'], 1)
        self.assertEqual(meta['progress']['units']['not_checked'], 1)
        self.assertEqual(self.load('cost-plan.json'), meta['plan'])
        self.assertIsNone(meta['usage']['cost_usd'])

    def test_wrapped_verifier_record_is_accepted_in_one_call(self):
        # Grok 15.11 zwracał {"decision", "record"}: ta sama treść, a walidator odrzucał całość i szło drugie wywołanie.
        def wrapped(ctx, model, prompt, *args, **kwargs):
            self.verifier_calls.append(prompt); return json.dumps(dict(decision='confirmed', record=record()))
        with patch.object(H, 'call_grok_cli', side_effect=wrapped):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(len(self.verifier_calls), 1)
        checkpoint = self.load('checkpoint.json')
        self.assertEqual([(v['status'], v['error'], v['record']['verdict']) for v in checkpoint['verification']], [('complete', None, record()['verdict'])])

    def test_egress_refusal_in_parallel_verification_stops_the_queue_with_its_code(self):
        # G3 16.11: DataEgressError dziedziczy po ValueError i wcześniej stawał się zwykłym blocked bez kodu.
        def hunter(ctx, model, prompt, *args, **kwargs):
            self.hunter_calls.append(prompt)
            return json.dumps(dict(architecture_md='# Fixture', coverage_ledger=self.covered(),
                                   candidates=[record(fp='a-' + str(i)) for i in range(4)]))
        def refused(ctx, model, prompt, *args, **kwargs):
            self.verifier_calls.append(prompt); raise D.DataEgressError('PROVIDER_NOT_ALLOWED')
        with patch.object(H, 'call_codex', side_effect=hunter), patch.object(H, 'call_grok_cli', side_effect=refused):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual((meta['run_status'], meta.get('error_code')), ('error', 'PROVIDER_NOT_ALLOWED'))
        jobs = self.load('checkpoint.json')['settings']['jobs']
        self.assertLess(jobs, 4)
        self.assertLessEqual(len(self.verifier_calls), jobs)   # po odmowie żadne nowe podejrzenie nie startuje
        items = self.load('checkpoint.json')['verification']
        self.assertTrue(any(v.get('error_code') == 'PROVIDER_NOT_ALLOWED' for v in items))
        self.assertEqual(sum(v['status'] == 'complete' for v in items), 0)

    def test_calls_budget_stops_before_verifier_and_resume_does_not_rehunt(self):
        _, meta = D.run(self.ctx, self.args(profile='standard', budget='calls=1'))
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(meta['usage']['calls'], 1); self.assertEqual(len(meta['providers']), 1)
        self.assertEqual(meta['progress']['candidates_not_checked'], 1)
        _, meta = D.run(self.ctx, self.args(resume=str(self.out), budget='calls=2'))
        self.assertEqual(meta['run_status'], 'complete')
        self.assertEqual(len(self.hunter_calls), 1); self.assertEqual(len(self.verifier_calls), 1)
        self.assertEqual(meta['usage']['calls'], 2)

    def test_resume_without_larger_budget_makes_no_extra_call(self):
        D.run(self.ctx, self.args(budget='calls=1'))
        _, meta = D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(len(self.hunter_calls), 1); self.assertFalse(self.verifier_calls)

    def test_failed_exact_model_calls_consume_the_same_resume_budget(self):
        with patch.object(H, 'call_grok_cli', side_effect=H.ProviderError('token=do-not-retain network')):
            _, meta = D.run(self.ctx, self.args(budget='calls=2'))
        self.assertEqual(meta['run_status'], 'error')
        self.assertEqual([a['status'] for a in meta['provider_attempts']], ['complete', 'error'])
        self.assertFalse(self.verifier_calls)
        self.assertNotIn('do-not-retain', (self.out / 'checkpoint.json').read_text())
        _, meta = D.run(self.ctx, self.args(resume=str(self.out), budget='calls=3'))
        self.assertEqual(meta['usage']['calls'], 3)
        self.assertEqual([p['provider'] for p in meta['providers']], ['codex', 'grok-cli'])

    def test_timeout_cannot_exceed_remaining_active_budget(self):
        clock = SimpleNamespace(monotonic=lambda: now[0]); now = [0.0]
        original = self.hunter
        def timed(*args):
            self.assertLessEqual(args[-1], 3.0)
            result = original(*args); now[0] += 4.0; return result
        with patch.object(D, 'time', clock), patch.object(H, 'call_codex', side_effect=timed):
            _, meta = D.run(self.ctx, self.args(budget='time=3s'))
        self.assertEqual(meta['run_status'], 'budget_exhausted')
        self.assertEqual(meta['usage']['calls'], 1); self.assertFalse(self.verifier_calls)
        self.assertFalse(hasattr(self.ctx, '_deep_deadline'))

    def test_progress_and_providers_are_durable_before_the_next_batch(self):
        batches = [('FILE src/app.py\n1: def a(): pass', ['src/app.py']), ('FILE src/app.py\n2: def b(): pass', ['src/app.py'])]
        units = [dict(unit='src/app.py', status='planned', reason=None)]
        original = self.hunter
        def inspect(*args):
            if self.hunter_calls:
                meta = self.load()
                self.assertEqual(meta['progress']['batches_complete'], 1)
                self.assertEqual(meta['progress']['units']['not_checked'], 1)
                self.assertEqual(len(meta['providers']), 1)
                self.assertEqual(meta['usage']['calls'], 2)  # next attempt reserved before execution
            return original(*args)
        with patch.object(D, 'context_plan', side_effect=lambda *a: (copy.deepcopy(batches), copy.deepcopy(units))), patch.object(H, 'call_codex', side_effect=inspect):
            _, meta = D.run(self.ctx, self.args(budget='calls=2', jobs=1))
        self.assertEqual(meta['progress']['batches_complete'], 2)
        self.assertEqual(meta['progress']['units']['covered'], 1)

    def test_blocked_and_not_checked_remain_distinct(self):
        with patch.object(H, 'call_codex', side_effect=H.ProviderError('offline')):
            _, meta = D.run(self.ctx, self.args())
        self.assertEqual(meta['run_status'], 'error')
        self.assertEqual(meta['progress']['batches_blocked'], 1)
        self.assertEqual(meta['progress']['units']['blocked'], 1)
        self.assertEqual(meta['progress']['batches_not_checked'], 0)
        self.assertIn('no automatic fallback', ' '.join(meta['errors']))

    def test_interrupt_keeps_completed_hunter_and_charges_interrupted_verifier(self):
        with patch.object(H, 'call_grok_cli', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            D.run(self.ctx, self.args(profile='standard'))
        meta = self.load()
        self.assertEqual(meta['run_status'], 'interrupted'); self.assertEqual(meta['usage']['calls'], 2)
        self.assertFalse((self.out / '.deep.lock').exists())
        _, meta = D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertEqual(len(self.hunter_calls), 1); self.assertEqual(meta['usage']['calls'], 3)
        self.assertEqual(meta['run_status'], 'complete')

    def test_source_and_configuration_changes_refuse_resume_before_call(self):
        D.run(self.ctx, self.args(plan_only=True))
        path = self.repo / 'src/app.py'; original = path.read_text(); path.write_text(original + '# changed\n')
        with self.assertRaisesRegex(ValueError, 'źródła'): D.run(self.ctx, self.args(resume=str(self.out)))
        path.write_text(original); self.cfg['models']['codex'] = ['other-model']
        with self.assertRaisesRegex(ValueError, 'konfiguracja'): D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_completed_run_resume_has_no_additional_provider_calls(self):
        D.run(self.ctx, self.args(profile='standard'))
        _, meta = D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertEqual(meta['run_status'], 'complete'); self.assertEqual(meta['usage']['calls'], 2)
        self.assertEqual(len(self.hunter_calls), 1); self.assertEqual(len(self.verifier_calls), 1)

    def test_plan_can_resume_using_saved_profile_and_scope(self):
        D.run(self.ctx, self.args(plan_only=True, profile='standard', scope=['src']))
        _, meta = D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertEqual(meta['profile'], 'standard'); self.assertEqual(meta['scope_paths'], ['src'])
        self.assertEqual(len(self.hunter_calls), 1)

    def test_cached_response_survives_interruption_during_validation(self):
        with patch.object(D, 'validate', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            D.run(self.ctx, self.args(profile='standard'))
        self.assertEqual(len(self.hunter_calls), 1)
        _, meta = D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertEqual(len(self.hunter_calls), 1); self.assertEqual(meta['usage']['calls'], 2)
        self.assertEqual(meta['run_status'], 'complete')

    def test_live_lock_and_symlink_checkpoint_are_rejected(self):
        D.run(self.ctx, self.args(plan_only=True))
        lock = self.out / '.deep.lock'; lock.write_text(str(__import__('os').getpid()))
        with self.assertRaisesRegex(ValueError, 'właściciela'): D.run(self.ctx, self.args(resume=str(self.out)))
        lock.unlink()
        checkpoint = self.out / 'checkpoint.json'; saved = self.out / 'saved.json'; checkpoint.rename(saved); checkpoint.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, 'dowiązaniem'): D.run(self.ctx, self.args(resume=str(self.out)))
        self.assertFalse(self.hunter_calls + self.verifier_calls)

    def test_plan_scans_source_once_for_many_files(self):
        import helix_source_coverage
        for i in range(20): (self.repo / 'src' / f'part{i}.py').write_text(f'value = {i}\n')
        with patch.object(helix_source_coverage, 'scan', wraps=helix_source_coverage.scan) as scan:
            batches, units = D.context_plan(self.repo, ['.'], 'standard')
        self.assertEqual(scan.call_count, 1); self.assertEqual(len(units), 21)


if __name__ == '__main__': unittest.main()
