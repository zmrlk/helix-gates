"""Manual review identity and receipts using only small local synthetic files."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_manual_review as manual


class ManualReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name).resolve()
        self.args = dict(checkpoint='cp1', reviewer='first', round_no=1, prompt='Review the synthetic change.',
                         diff='-before\n+after\n', base='synthetic-base')

    def prepare(self, **changes):
        return manual._prepare_local_protocol(self.out, **(self.args | changes))

    def respond(self, binding, *, model='grok-synthetic', provider='grok', **changes):
        raw = json.dumps(dict(verdict='approve', summary='Synthetic review', findings=[])).encode()
        (self.out / binding['verdict']).write_bytes(raw)
        receipt = dict(request_id=binding['request_id'], verdict_sha256=hashlib.sha256(raw).hexdigest(),
                       provider=provider, model=model) | changes
        (self.out / binding['receipt']).write_text(json.dumps(receipt))
        return raw

    def test_one_raw_response_never_satisfies_two_reviewer_requests(self):
        first, second = self.prepare(), self.prepare(reviewer='second')
        self.assertNotEqual(first['request_id'], second['request_id'])
        self.assertNotEqual(first['verdict'], second['verdict'])
        self.respond(first)
        _, used = manual.read_response(self.out, first)
        self.assertEqual(used['reviewer'], 'first')
        with self.assertRaises(manual.PendingReview): manual.read_response(self.out, second)
        # Even copying both response files does not transfer the request binding.
        for key in ('verdict', 'receipt'):
            (self.out / second[key]).write_bytes((self.out / first[key]).read_bytes())
        with self.assertRaisesRegex(manual.PendingReview, 'tego requestu'):
            manual.read_response(self.out, second)

    def test_two_valid_receipts_preserve_exact_manual_provenance_and_raw_bytes(self):
        seen = set()
        for reviewer in ('grok', 'second'):
            binding = self.prepare(reviewer=reviewer)
            raw = self.respond(binding)
            text, used = manual.read_response(self.out, binding)
            self.assertEqual(text.encode(), raw)
            self.assertEqual(used['method'], 'manual_handoff')
            self.assertEqual(used['family_basis'], 'manual_model_declaration')
            self.assertEqual(used['family'], 'xai')
            self.assertEqual(used['model'], 'grok-synthetic')
            self.assertNotEqual(binding['verdict'], f'review-{reviewer}-r1.json')
            (self.out / f'review-{reviewer}-r1.json').write_text(json.dumps(dict(raw=json.loads(text), used=used)))
            self.assertEqual((self.out / binding['verdict']).read_bytes(), raw)
            seen.add(used['request_id'])
        self.assertEqual(len(seen), 2)

    def test_round_checkpoint_prompt_and_full_untruncated_diff_bind_request(self):
        common = 'x' * 60000
        original = self.prepare(diff=common + 'original')
        self.respond(original)
        changed = [dict(round_no=2), dict(checkpoint='cp2'), dict(prompt='Different prompt'),
                   dict(diff=common + 'changed'), dict(base='another-base')]
        for change in changed:
            with self.subTest(change=list(change)):
                current = self.prepare(**(dict(diff=common + 'original') | change))
                self.assertNotEqual(original['request_id'], current['request_id'])
                with self.assertRaises(manual.PendingReview): manual.read_response(self.out, current)

    def test_names_with_same_slug_stay_distinct_and_duplicate_names_fail_early(self):
        first, second = self.prepare(reviewer='a b'), self.prepare(reviewer='a-b')
        self.assertTrue(first['request'].startswith('manual-request-a-b-r1-'))
        self.assertTrue(second['request'].startswith('manual-request-a-b-r1-'))
        self.assertNotEqual(first['request'], second['request'])
        with self.assertRaisesRegex(ValueError, 'unikalne'):
            manual.validate_reviewers([dict(name='same'), dict(name='same')])
        manual.validate_reviewers([dict(name='same'), dict(name='same', enabled=False)])
        for name in ('', '../escape', 'back\\slash', 'bad\nname'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.prepare(reviewer=name)

    def test_old_unbound_verdict_is_preserved_but_not_consumed(self):
        legacy = self.out / 'review-grok-r1.json'
        legacy.write_text('{"verdict":"approve","summary":"Legacy","findings":[]}')
        old = legacy.read_bytes()
        with self.assertRaises(manual.PendingReview): manual.read_response(self.out, self.prepare())
        self.assertEqual(legacy.read_bytes(), old)
        self.assertFalse(list(self.out.glob('manual-verdict-*')))

    def test_receipt_must_match_bytes_request_model_and_family_without_echoing_values(self):
        binding = self.prepare(requested_model='grok-synthetic')
        invalid = [dict(request_id='SECRET'), dict(verdict_sha256='SECRET'), dict(model=None),
                   dict(model='orchestrator'), dict(model='default'), dict(model='opaque-model'),
                   dict(model='claude-synthetic', family='xai'), dict(model='grok-other'), dict(provider='claude')]
        for change in invalid:
            with self.subTest(change=change):
                self.respond(binding, **change)
                with self.assertRaises(manual.PendingReview) as failure:
                    manual.read_response(self.out, binding)
                self.assertNotIn('SECRET', str(failure.exception))
        self.respond(binding)
        (self.out / binding['verdict']).write_text('{"changed":"SECRET"}')
        with self.assertRaises(manual.PendingReview): manual.read_response(self.out, binding)

    def test_missing_receipt_or_malformed_json_is_pending(self):
        binding = self.prepare()
        self.respond(binding)
        (self.out / binding['receipt']).unlink()
        with self.assertRaises(manual.PendingReview): manual.read_response(self.out, binding)
        self.respond(binding)
        (self.out / binding['verdict']).write_text('SECRET invalid JSON')
        with self.assertRaises(manual.PendingReview) as failure: manual.read_response(self.out, binding)
        self.assertNotIn('SECRET', str(failure.exception))

    def test_requests_are_deterministic_immutable_and_never_overwrite_existing_proof(self):
        binding = self.prepare()
        metadata = (self.out / binding['request']).read_bytes()
        original = copy.deepcopy(self.args)
        self.assertEqual(self.prepare(), binding)
        self.assertEqual(self.args, original)
        self.assertEqual((self.out / binding['request']).read_bytes(), metadata)
        (self.out / binding['request']).write_text('modified')
        with self.assertRaisesRegex(ValueError, 'nie nadpisano'):
            self.prepare()
        self.assertEqual((self.out / binding['request']).read_text(), 'modified')
        self.assertFalse(list(self.out.glob('.manual-*.tmp')))

    def test_symlink_response_parent_and_path_escape_are_not_read(self):
        binding = self.prepare()
        self.respond(binding)
        target = self.out / 'unrelated.txt'
        target.write_text('SECRET')
        for key in ('verdict', 'receipt'):
            self.respond(binding)
            path = self.out / binding[key]
            path.unlink(); path.symlink_to(target)
            with self.assertRaises(manual.PendingReview): manual.read_response(self.out, binding)
            path.unlink()
        alias = self.out / 'alias'; alias.symlink_to(self.out, target_is_directory=True)
        with self.assertRaises(OSError): manual._prepare_local_protocol(alias, **self.args)
        with self.assertRaises(manual.PendingReview):
            manual.read_response(self.out, binding | {'verdict': '../unrelated.txt'})
        self.assertEqual(target.read_text(), 'SECRET')

    def test_offline_refuses_before_any_request_write(self):
        with patch.object(manual, '_directory', side_effect=AssertionError('no files')), \
             self.assertRaisesRegex(ValueError, 'offline'):
            manual.handoff(self.out, **self.args, offline=True)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_wait_has_a_bounded_clock_and_never_calls_a_provider(self):
        binding = self.prepare()
        clock = [0.0]
        def pause(seconds): clock[0] += seconds
        with patch.object(manual.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(manual.time, 'sleep', side_effect=pause):
            with self.assertRaises(manual.PendingReview):
                manual.wait_response(self.out, binding, wait_seconds=0.25)
        self.assertEqual(clock[0], 0.25)
        for seconds in (-1, float('nan'), True):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                manual.wait_response(self.out, binding, wait_seconds=seconds)


if __name__ == '__main__': unittest.main()
