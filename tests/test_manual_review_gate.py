"""Gate orchestration of a local protocol fixture, never an admitted export."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_provider_plan import config, load_helix


class ManualReviewGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.out = self.root / 'evidence'; self.out.mkdir()
        self.H = load_helix()
        self.cfg = config()
        self.cfg['data_egress'] = dict(status='approved', allowed_providers=['grok', 'gemini'], exclude_paths=[])
        self.cfg['providers']['reviewers'] = [dict(name=name, provider='grok') for name in ('first', 'second')]
        self.cfg['models']['grok'] = ['grok-synthetic']
        self.cfg['limits']['grok_wait_s'] = 0
        self.ctx = SimpleNamespace(cfg=self.cfg, repo=self.root, state_dir=self.root, offline=False,
            ev=lambda cp: self.out,
            cp=lambda cp: dict(id=cp, title='Synthetic change', goal='Review this fixture', test_cases=[]),
            state=lambda cp: dict(base='synthetic-base'), architecture=lambda: 'Synthetic architecture')
        self.diff = '-before\n+after\n'
        self.patch(self.H.helix_workflow, 'check_connections', return_value=True)
        self.patch(self.H.helix_workflow, 'precheck', return_value={'pass': True})
        self.patch(self.H.helix_workflow, 'matching_rules', return_value=[])
        self.patch(self.H.helix_workflow, 'diff_files', return_value=[])
        self.patch(self.H, 'diff_since', side_effect=lambda *args: self.diff)
        self.patch(self.H, 'log')
        self.ask = self.patch(self.H, 'ask', side_effect=AssertionError('no actual model calls'))
        self.legacy = self.patch(self.H, 'call_grok', side_effect=AssertionError('no legacy shared handoff'))
        # The public handoff refuses unprepared source input in checkpoint 30.
        # Keep protocol/receipt assertions through a visibly local test adapter.
        import helix_manual_review as manual
        def local_protocol_handoff(out, *, policy=None, wait_seconds=0, **kwargs):
            binding = manual._prepare_local_protocol(out, **kwargs)
            return manual.wait_response(out, binding, wait_seconds=wait_seconds)
        self.patch(manual, 'handoff', side_effect=local_protocol_handoff)

    def patch(self, target, name, **kwargs):
        patcher = patch.object(target, name, **kwargs)
        value = patcher.start(); self.addCleanup(patcher.stop)
        return value

    def bindings(self, *, round_no=1, checkpoint='cp1'):
        digest = hashlib.sha256(self.diff.encode()).hexdigest()
        rows = [json.loads(path.read_text()) for path in self.out.glob('manual-request-*.json')]
        return {row['reviewer']: row for row in rows
                if row['round'] == round_no and row['checkpoint'] == checkpoint and row['diff_sha256'] == digest}

    def test_manual_prompt_contains_the_entire_bound_diff(self):
        self.diff = 'x' * 61000 + '\n+ UNIQUE_TAIL_TO_REVIEW\n'
        result = self.H.gate_review(self.ctx, 'cp1')
        self.assertFalse(result['pass'])
        bindings = self.bindings()
        self.assertEqual(len(bindings), 2)
        for binding in bindings.values():
            prompt = (self.out / binding['prompt']).read_text()
            self.assertIn(self.diff, prompt)
            self.assertIn('UNIQUE_TAIL_TO_REVIEW', prompt)
            self.assertEqual(binding['diff_sha256'], hashlib.sha256(self.diff.encode()).hexdigest())

    def respond(self, binding):
        raw = json.dumps(dict(verdict='approve', findings=[], summary='Synthetic manual review')).encode()
        (self.out / binding['verdict']).write_bytes(raw)
        (self.out / binding['receipt']).write_text(json.dumps(dict(request_id=binding['request_id'],
            verdict_sha256=hashlib.sha256(raw).hexdigest(), provider='grok', model='grok-synthetic')))
        return raw

    def test_two_requests_with_one_response_remain_pending_for_the_other_reviewer(self):
        first = self.H.gate_review(self.ctx, 'cp1')
        self.assertFalse(first['pass'])
        self.assertEqual(first['pending'], ['first', 'second'])
        bindings = self.bindings()
        self.assertEqual(set(bindings), {'first', 'second'})
        self.assertNotEqual(bindings['first']['request_id'], bindings['second']['request_id'])
        self.respond(bindings['first'])
        result = self.H.gate_review(self.ctx, 'cp1')
        self.assertFalse(result['pass'])
        self.assertEqual(result['pending'], ['second'])
        self.assertEqual([item['reviewer'] for item in result['verdicts']], ['first'])
        self.ask.assert_not_called(); self.legacy.assert_not_called()

    def test_two_valid_independent_receipts_pass_without_modifying_raw_named_grok(self):
        self.cfg['providers']['reviewers'][0]['name'] = 'grok'
        self.H.gate_review(self.ctx, 'cp1')
        bindings = self.bindings()
        originals = {name: self.respond(binding) for name, binding in bindings.items()}
        result = self.H.gate_review(self.ctx, 'cp1')
        self.assertTrue(result['pass'])
        self.assertEqual(result['pending'], [])
        self.assertEqual(len(result['verdicts']), 2)
        self.assertEqual(len({v['used']['request_id'] for v in result['verdicts']}), 2)
        for name, binding in bindings.items():
            self.assertEqual((self.out / binding['verdict']).read_bytes(), originals[name])
            self.assertNotEqual(binding['verdict'], 'review-' + name + '-r1.json')
        for verdict in result['verdicts']:
            self.assertEqual(verdict['used']['method'], 'manual_handoff')
            self.assertEqual(verdict['used']['model'], 'grok-synthetic')
            self.assertEqual(verdict['used']['family'], 'xai')
        self.assertEqual(len(result['provenance']['models']), 2)
        self.assertEqual({row['request_id'] for row in result['provenance']['models']},
                         {row['used']['request_id'] for row in result['verdicts']})
        for receipt in result['provenance']['models']:
            self.assertEqual(receipt['method'], 'manual_handoff')
            self.assertEqual(receipt['status'], 'declared')
            self.assertEqual(receipt['evidence_kind'], 'manual_receipt')
            self.assertFalse(receipt['call_invoked'])
        self.ask.assert_not_called(); self.legacy.assert_not_called()

    def test_legacy_raw_and_invalid_history_survive_new_result_and_summary(self):
        self.cfg['providers']['reviewers'][0]['name'] = 'grok'
        self.ctx.state = lambda cp: dict(base='synthetic-base', status='pending_review')
        legacy = self.out / 'review-grok-r1.json'
        legacy.write_text('{"verdict":"approve","summary":"LEGACY_RAW","findings":[]}')
        invalid = self.out / 'review-broken-r1.json'
        invalid.write_text('INVALID_OLD_JSON')
        unrelated = self.out / 'review-unrelated-r1.json'
        unrelated.write_text('{"used":{"provider":"fake","model":"NOT_A_WRAPPER"}}')
        originals = {path: path.read_bytes() for path in (legacy, invalid, unrelated)}
        self.H.gate_review(self.ctx, 'cp1')
        bindings = self.bindings()
        for binding in bindings.values(): self.respond(binding)
        result = self.H.gate_review(self.ctx, 'cp1')
        self.assertTrue(result['pass'])
        self.H.build_evidence(self.ctx, 'cp1')
        for path, original in originals.items(): self.assertEqual(path.read_bytes(), original)
        for binding in bindings.values():
            path = self.out / ('review-manual-' + binding['request_id'] + '-r1.json')
            wrapper = json.loads(path.read_text())
            self.assertEqual(wrapper['used']['request_id'], binding['request_id'])
        summary = (self.out / 'summary.md').read_text()
        self.assertIn('reviewer grok r1: grok/grok-synthetic', summary)
        self.assertIn('manual_handoff: declared receipt, no CLI call', summary)
        self.assertNotIn('LEGACY_RAW', summary)
        self.assertNotIn('NOT_A_WRAPPER', summary)

    def test_duplicate_names_fail_before_creating_requests_or_calling_providers(self):
        self.cfg['providers']['reviewers'][1]['name'] = 'first'
        with patch.object(self.H, 'diff_since', side_effect=AssertionError('duplicate names fail before review preparation')):
            result = self.H.gate_review(self.ctx, 'cp1')
        self.assertFalse(result['pass'])
        self.assertEqual(result['status'], 'ERROR')
        self.assertEqual(result['verdicts'], [])
        self.assertFalse(list(self.out.glob('manual-*')))
        self.ask.assert_not_called(); self.legacy.assert_not_called()

    def test_summary_rejects_fifo_and_malformed_unicode_without_blocking_read(self):
        import helix_audit_context
        self.ctx.state = lambda cp: dict(base='synthetic-base', status='pending_review')
        fifo = self.out / 'review-pipe-r1.json'; os.mkfifo(fifo)
        (self.out / 'review-unicode-r1.json').write_bytes(b'\xff')
        original = Path.read_text
        def text(path, *args, **kwargs):
            if path == fifo:
                raise AssertionError('FIFO must use bounded nonblocking descriptor read')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', new=text), \
             patch.object(helix_audit_context, 'safe_read', wraps=helix_audit_context.safe_read) as reader:
            self.H.build_evidence(self.ctx, 'cp1')
        reader.assert_any_call(fifo, errors='strict')
        self.assertTrue((self.out / 'summary.md').is_file())

    def test_manual_request_contains_full_diff_and_binds_the_entire_prompt(self):
        self.diff = 'synthetic ' * 8000 + '\nUNIQUE_TAIL_AFTER_60K\n'
        result = self.H.gate_review(self.ctx, 'cp1')
        self.assertEqual(result['pending'], ['first', 'second'])
        for binding in self.bindings().values():
            markdown = (self.out / binding['prompt']).read_text()
            self.assertIn('UNIQUE_TAIL_AFTER_60K', markdown)
            self.assertIn(self.diff, markdown)
            prompt = markdown.rsplit('\n\n## Ręczna odpowiedź\n\n', 1)[0]
            self.assertEqual(hashlib.sha256(prompt.encode()).hexdigest(), binding['prompt_sha256'])
            self.assertEqual(hashlib.sha256(self.diff.encode()).hexdigest(), binding['diff_sha256'])

    def test_both_fake_cli_reviewers_receive_the_entire_diff_before_approval(self):
        self.cfg['providers']['reviewers'] = [dict(name=name, provider='gemini') for name in ('first', 'second')]
        self.diff = 'synthetic ' * 8000 + '\nUNIQUE_CLI_TAIL_AFTER_60K\n'
        prompts = []
        def answer(ctx, provider, prompt, **kwargs):
            prompts.append(prompt)
            self.assertEqual(provider, 'gemini')
            self.assertIn(self.diff, prompt)
            self.assertIn('UNIQUE_CLI_TAIL_AFTER_60K', prompt)
            return json.dumps(dict(verdict='approve', summary='Synthetic complete diff', findings=[])), \
                dict(provider='gemini', model='big-model')
        with patch.object(self.H, 'ask', side_effect=answer) as fake:
            result = self.H.gate_review(self.ctx, 'cp1')
        self.assertTrue(result['pass'])
        self.assertEqual(fake.call_count, 2)
        self.assertEqual(len(prompts), 2)
        self.assertFalse(list(self.out.glob('manual-request-*')))
        self.legacy.assert_not_called()

    def test_full_diff_change_and_different_checkpoint_cannot_reuse_old_answers(self):
        prefix = 'synthetic ' * 8000
        self.diff = prefix + 'before'
        self.H.gate_review(self.ctx, 'cp1')
        old_bindings = self.bindings()
        for binding in old_bindings.values(): self.respond(binding)
        self.assertTrue(self.H.gate_review(self.ctx, 'cp1')['pass'])
        # The change lies beyond the existing 60000-character prompt excerpt.
        self.diff = prefix + 'after'
        result = self.H.gate_review(self.ctx, 'cp1')
        self.assertFalse(result['pass'])
        self.assertEqual(result['pending'], ['first', 'second'])
        for name, binding in self.bindings().items():
            self.assertNotEqual(binding['request_id'], old_bindings[name]['request_id'])
        result = self.H.gate_review(self.ctx, 'cp2')
        self.assertFalse(result['pass'])
        self.assertEqual(result['pending'], ['first', 'second'])
        self.assertEqual(len(self.bindings(checkpoint='cp2')), 2)

    def test_next_round_requires_new_separate_responses(self):
        self.H.gate_review(self.ctx, 'cp1')
        first = self.bindings()
        for binding in first.values(): self.respond(binding)
        self.assertTrue(self.H.gate_review(self.ctx, 'cp1')['pass'])
        result = self.H.gate_review(self.ctx, 'cp1', round_no=2)
        self.assertFalse(result['pass'])
        self.assertEqual(result['pending'], ['first', 'second'])
        second = self.bindings(round_no=2)
        for name, binding in second.items():
            self.assertNotEqual(binding['request_id'], first[name]['request_id'])
        self.assertEqual(len(second), 2)

    def test_offline_never_creates_request_or_calls_legacy_handoff(self):
        self.ctx.offline = True
        result = self.H.gate_review(self.ctx, 'cp1')
        self.assertFalse(result['pass'])
        self.assertEqual(result['status'], 'LIMITED')
        self.assertFalse(list(self.out.glob('manual-*')))
        self.ask.assert_not_called(); self.legacy.assert_not_called()


if __name__ == '__main__': unittest.main()
