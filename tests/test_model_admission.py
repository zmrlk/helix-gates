"""Offline authorization and exact one-use neutral-probe leases, without CLIs."""
from concurrent.futures import ThreadPoolExecutor
import copy
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
from helix_data_egress import DataEgressError, policy_sha256
from helix_model_admission import (AdmissionError, FIXED_PROBE_PROMPT,
    authorize_provider, authorized_probe, native_call_admission,
    probe_provider, source_input_admission)


def approved(*providers):
    return dict(schema_version=1, status='approved', allowed_providers=list(providers), exclude_paths=[])


def admit(ctx, original_prompt, out, **changes):
    arguments = dict(provider='codex', model='test-model', prompt=original_prompt, images=None,
                     schema=None, write=False, out_dir=out)
    arguments.update(changes)
    return native_call_admission(ctx, **arguments)


class ModelAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='helix-admission-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root/'project'; self.repo.mkdir()
        self.ctx = SimpleNamespace(repo=self.repo, state_dir=self.root/'state', out_dir=self.root/'out',
            cfg={'data_egress': approved('codex'), 'limits': {'provider_timeout_s': 12}}, offline=False)

    def test_authorization_reuses_canonical_policy_and_is_pure_without_context_guessing(self):
        original = copy.deepcopy(self.ctx.cfg)
        with patch('builtins.open', side_effect=AssertionError('file')), \
                patch('subprocess.run', side_effect=AssertionError('process')), \
                patch('socket.socket', side_effect=AssertionError('network')):
            self.assertEqual(authorize_provider(self.ctx, 'codex'), policy_sha256(original['data_egress']))
            self.assertEqual(authorize_provider(original['data_egress'], 'codex'), policy_sha256(original['data_egress']))
            with self.assertRaises(DataEgressError) as caught:
                authorize_provider(original, 'codex')
        self.assertEqual(caught.exception.code, 'INVALID_POLICY')
        self.assertEqual(self.ctx.cfg, original)

    def test_missing_pending_invalid_and_disallowed_actual_provider_precede_transport(self):
        # Decyzja właściciela 15.11.2026: brak polityki albo propozycja czekająca na właściciela = wszyscy dostawcy.
        for policy in (None, {'status': 'pending_owner'}):
            self.ctx.cfg['data_egress'] = policy
            with self.subTest(policy=policy), patch('os.open', side_effect=AssertionError('file inspected')):
                receipt = native_call_admission(self.ctx, 'claude', 'test-model', 'PRIVATE_SOURCE_CANARY',
                                                None, None, False, self.ctx.out_dir)
                self.assertEqual((receipt['status'], receipt['kind'], receipt['provider']), ('ADMITTED', 'model_call', 'claude'))
        # Niepoprawna deklaracja, jawne ograniczenie właściciela i nieznany dostawca odmawiają przed transportem.
        for policy, provider, expected in (({'status': 'approved', 'allowlist': ['PRIVATE_CANARY']}, 'codex', 'INVALID_POLICY'),
                (approved('codex'), 'claude', 'PROVIDER_NOT_ALLOWED'),
                (approved('codex'), 'openai', 'INVALID_PROVIDER')):
            self.ctx.cfg['data_egress'] = policy
            with self.subTest(expected=expected), patch('os.open', side_effect=AssertionError('file inspected')):
                with self.assertRaises(DataEgressError) as caught:
                    native_call_admission(self.ctx, provider, 'test-model', 'PRIVATE_SOURCE_CANARY',
                                          None, None, False, self.ctx.out_dir)
            self.assertEqual(caught.exception.code, expected)
            self.assertNotIn('CANARY', str(caught.exception))

    def test_approved_source_is_admitted_restriction_and_offline_refuse(self):
        receipt = admit(self.ctx, 'SOURCE_CANARY', self.ctx.out_dir)
        self.assertEqual((receipt['status'], receipt['policy_sha256']), ('ADMITTED', policy_sha256(self.ctx.cfg['data_egress'])))
        self.assertNotIn('SOURCE_CANARY', str(receipt))
        self.assertEqual(source_input_admission(self.ctx, 'codex')['status'], 'ADMITTED')
        with self.assertRaises(DataEgressError) as caught:
            source_input_admission(self.ctx, 'grok')
        self.assertEqual(caught.exception.code, 'PROVIDER_NOT_ALLOWED')
        self.ctx.offline = True
        for call in (lambda: admit(self.ctx, 'SOURCE_CANARY', self.ctx.out_dir), lambda: source_input_admission(self.ctx, 'codex')):
            with self.assertRaises(AdmissionError) as caught: call()
            self.assertEqual(caught.exception.code, 'OFFLINE')

    def test_fixed_prompt_and_fake_json_flags_do_not_grant_permission(self):
        self.ctx.cfg.update(availability_probe=True, probe_admitted=True, _helix_model_probe_token='approved')
        self.assertIsNone(probe_provider(self.ctx))
        # Flagi w konfiguracji nie tworzą dzierżawy sondy: to zwykłe wywołanie według polityki.
        self.assertEqual(admit(self.ctx, FIXED_PROBE_PROMPT, self.ctx.out_dir)['kind'], 'model_call')
        self.ctx._helix_model_probe_token = {'provider': 'codex', 'status': 'ADMITTED', 'kind': 'availability_probe'}
        with self.assertRaises(AdmissionError) as caught:
            admit(self.ctx, FIXED_PROBE_PROMPT, self.ctx.out_dir)
        self.assertEqual(caught.exception.code, 'INPUT_NOT_ADMITTED')
        self.assertIsNone(probe_provider(self.ctx))

    def test_probe_has_owned_disjoint_cwd_fixed_prompt_copied_config_and_no_source_credit(self):
        self.ctx.cfg.pop('data_egress')
        (self.repo/'private-source.txt').write_text('PRIVATE_SOURCE_CANARY')
        original = copy.deepcopy(vars(self.ctx))
        with patch('pathlib.Path.read_text', side_effect=AssertionError('source read')), \
                patch('pathlib.Path.read_bytes', side_effect=AssertionError('source read')), \
                patch('subprocess.run', side_effect=AssertionError('process')), \
                patch('socket.socket', side_effect=AssertionError('network')):
            with authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
                self.assertEqual(prompt, FIXED_PROBE_PROMPT)
                self.assertFalse(out.is_relative_to(self.repo))
                self.assertFalse(self.repo.is_relative_to(out))
                self.assertEqual((probe.repo, probe.state_dir, probe.out_dir), (out, out, out))
                self.assertEqual(probe_provider(probe), 'codex')
                probe.cfg['limits']['provider_timeout_s'] = 1
                probe._deep_deadline = 123.0
                result = admit(probe, prompt, out)
                self.assertEqual(result['kind'], 'availability_probe')
                self.assertEqual(result['source_review_calls'], 0)
                self.assertEqual(result['source_paths'], [])
                self.assertEqual(result['delivery'], 'NOT_SENT')
                self.assertIsNone(result['policy_sha256'])
                self.assertIsNone(probe_provider(probe))
        self.assertFalse(out.exists())
        self.assertEqual(vars(self.ctx), original)

    def test_probe_lease_consumed_once_and_expires_without_a_json_reusable_grant(self):
        with authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
            metadata = admit(probe, prompt, out)
            self.assertEqual((metadata['status'], metadata['kind']), ('ADMITTED', 'availability_probe'))
            with self.assertRaises(AdmissionError) as caught:
                admit(probe, prompt, out)
            self.assertEqual(caught.exception.code, 'INPUT_NOT_ADMITTED')
        self.assertIsNone(probe_provider(probe))
        self.assertFalse(hasattr(probe, '_helix_model_probe_token'))
        self.assertFalse(out.exists())
        # Po wygaśnięciu dzierżawy kontekst sondy nie jest już sondą: kolejne wywołanie to zwykłe wywołanie według polityki.
        self.assertEqual(admit(probe, prompt, out)['kind'], 'model_call')
        forged = copy.copy(self.ctx); forged._helix_model_probe_token = metadata
        with self.assertRaises(AdmissionError): admit(forged, prompt, out)

    def test_mutated_provider_model_prompt_images_schema_or_write_never_admitted(self):
        variants = [dict(provider='gemini'), dict(provider='claude-via-agy'), dict(model='other-model'),
            dict(model=True), dict(model=None), dict(prompt=FIXED_PROBE_PROMPT+' SOURCE_CANARY'),
            dict(images=[]), dict(images=['PRIVATE_CANARY.png']), dict(schema='PRIVATE_CANARY.json'),
            dict(write=True), dict(write=0)]
        for changes in variants:
            with self.subTest(changes=changes), authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
                with self.assertRaises(AdmissionError) as caught:
                    admit(probe, prompt, out, **changes)
                self.assertEqual(str(caught.exception), 'data_egress: INPUT_NOT_ADMITTED')

    def test_changed_context_paths_or_outside_out_are_denied(self):
        for field in ('repo', 'state_dir', 'out_dir', 'argument_out'):
            with self.subTest(field=field), authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
                if field != 'argument_out': setattr(probe, field, self.repo)
                with self.assertRaises(AdmissionError) as caught:
                    admit(probe, prompt, self.repo if field == 'argument_out' else out)
                self.assertEqual(caught.exception.code, 'INPUT_NOT_ADMITTED')
        with authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
            with self.assertRaises(AdmissionError): admit(probe, prompt, out/'..'/out.name)

    def test_copied_context_cannot_reuse_or_steal_the_opaque_lease(self):
        with authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
            for copier in (copy.copy, copy.deepcopy):
                forged = copier(probe)
                self.assertIsNone(probe_provider(forged))
                with self.assertRaises(AdmissionError): admit(forged, prompt, out)
            self.assertEqual(admit(probe, prompt, out)['status'], 'ADMITTED')

    def test_directory_replacement_and_symlink_do_not_keep_path_only_authority(self):
        for replacement in ('directory', 'symlink'):
            with self.subTest(replacement=replacement), authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
                saved = out.with_name(out.name+'-saved')
                out.rename(saved)
                try:
                    if replacement == 'directory': out.mkdir()
                    else: out.symlink_to(self.repo, target_is_directory=True)
                    with self.assertRaises(AdmissionError) as caught:
                        admit(probe, prompt, out)
                    self.assertEqual(caught.exception.code, 'INPUT_NOT_ADMITTED')
                finally:
                    if out.is_symlink(): out.unlink()
                    else: out.rmdir()
                    saved.rename(out)

    def test_caller_exception_and_interrupt_revoke_lease_and_remove_owned_cwd(self):
        for error in (RuntimeError('synthetic'), ValueError('synthetic'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)) as caught:
                    with authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
                        self.assertEqual(probe_provider(probe), 'codex')
                        raise error
                self.assertIs(caught.exception, error)
                self.assertIsNone(probe_provider(probe))
                self.assertFalse(out.exists())
                self.assertFalse(hasattr(probe, '_helix_model_probe_token'))

    def test_offline_and_invalid_probe_are_refused_before_temp_or_process(self):
        self.ctx.offline = True
        with patch('tempfile.TemporaryDirectory', side_effect=AssertionError('created')):
            with self.assertRaises(AdmissionError) as caught:
                with authorized_probe(self.ctx, 'codex', 'test-model'): pass
            self.assertEqual(caught.exception.code, 'OFFLINE')
        self.ctx.offline = False
        for provider, model in (('grok', 'test-model'), ('openai', 'test-model'), ('codex', True),
                                ('codex', ''), ('codex', 'NAME\nCANARY')):
            with self.subTest(provider=provider, model=model), patch('tempfile.TemporaryDirectory', side_effect=AssertionError('created')):
                with self.assertRaises(AdmissionError):
                    with authorized_probe(self.ctx, provider, model): pass

    def test_temporary_base_inside_target_is_refused_before_creation(self):
        self.ctx.repo = Path(tempfile.gettempdir()).resolve()
        with patch('tempfile.TemporaryDirectory', side_effect=AssertionError('created')):
            with self.assertRaises(AdmissionError) as caught:
                with authorized_probe(self.ctx, 'codex', 'test-model'): pass
        self.assertEqual(caught.exception.code, 'INPUT_NOT_ADMITTED')

    def test_parallel_consumers_cannot_start_two_calls_with_one_lease(self):
        with authorized_probe(self.ctx, 'codex', 'test-model') as (probe, prompt, out):
            barrier = threading.Barrier(2)
            def consume():
                barrier.wait(timeout=3)
                try: return admit(probe, prompt, out)['status']
                except AdmissionError as error: return error.code
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: consume(), range(2)))
        self.assertEqual(sorted(results), ['ADMITTED', 'INPUT_NOT_ADMITTED'])

    def test_concurrent_distinct_probes_bind_exact_alias_model_and_keep_source_context(self):
        original = copy.deepcopy(vars(self.ctx))
        def run(pair):
            provider, model = pair
            with authorized_probe(self.ctx, provider, model) as (probe, prompt, out):
                self.assertEqual(probe_provider(probe), provider)
                result = native_call_admission(probe, provider, model, prompt, None, None, False, out)
                return result, out
        pairs = [('gemini', None), ('gemini-flash', 'opaque-model'), ('claude-via-agy', 'claude-synthetic')]
        with ThreadPoolExecutor(max_workers=3) as pool: results = list(pool.map(run, pairs))
        self.assertEqual([(r['provider'], r['model']) for r, _ in results], pairs)
        self.assertEqual(len({str(path) for _, path in results}), 3)
        self.assertTrue(all(not path.exists() for _, path in results))
        self.assertEqual(vars(self.ctx), original)


if __name__ == '__main__': unittest.main()
