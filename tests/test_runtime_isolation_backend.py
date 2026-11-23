"""Synthetic Seatbelt contract tests. No OS sandbox, socket or process starts."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_isolation as isolation
import helix_runtime_isolation_probe as probe


class RuntimeIsolationBackend(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        for name in ('work', 'scratch', 'source', 'trusted'):
            (self.base / name).mkdir()
        self.backend = isolation.SeatbeltBackend(self.base / 'control')
        self.policy = dict(scope='project', connect_tcp=[34561], listen_tcp=[34562],
                           unix_sockets=[], writable_roots=[str(self.base / 'work'), str(self.base / 'scratch')],
                           writable_files=[], readonly_roots=[str(self.base / 'trusted')],
                           protected_roots=[str(self.base / 'source'), str(self.base / 'trusted')])
        self.cap = patch.object(self.backend, 'capability', return_value=dict(
            backend=isolation.BACKEND, status='present_not_probed', reason_code='SANDBOX_EXEC_PRESENT'))
        self.cap.start()
        self.addCleanup(self.cap.stop)

    def proof(self, policy, path, remaining):
        # A mocked receipt tests Python routing only, never an executed OS proof.
        return dict(status='passed', checks={key: True for key in isolation.required_probe_checks(policy)},
                    child_checks={key: True for key in isolation.required_probe_checks(policy)}, cleanup=True,
                    policy_hash=hashlib.sha256(path.read_bytes()).hexdigest(), probe_policy_hash='a' * 64)

    def admitted(self, policy=None):
        with patch.object(self.backend, '_probe', side_effect=self.proof) as called:
            grant = self.backend.admit(policy or self.policy, 10)
        return grant, called

    def test_unsupported_platform_does_not_probe_or_create_control(self):
        backend = isolation.SeatbeltBackend(self.base / 'other-control')
        with patch.object(isolation.sys, 'platform', 'linux'), patch.object(backend, '_probe') as called:
            grant = backend.admit(self.policy, 10)
        self.assertEqual(grant['reason_code'], 'UNSUPPORTED_PLATFORM')
        self.assertEqual(grant['enforcement'], 'blocked')
        self.assertFalse((self.base / 'other-control').exists())
        called.assert_not_called()

    def test_presence_is_not_enforcement_and_missing_binary_blocks(self):
        backend = isolation.SeatbeltBackend(self.base / 'other-control')
        with patch.object(isolation.sys, 'platform', 'darwin'), patch.object(isolation, 'SANDBOX_EXEC', '/nonexistent-neutral-sandbox'):
            self.assertEqual(backend.capability()['status'], 'unavailable')
            self.assertEqual(backend.admit(self.policy, 10)['proof_kind'], 'none')

    def test_exact_remote_filters_and_no_relays_or_imports(self):
        grant, called = self.admitted()
        self.assertEqual(grant['reason_code'], 'LOCAL_PROBE_PASSED')
        called.assert_called_once()
        text = Path(grant['profile_path']).read_text()
        self.assertIn('(remote tcp "localhost:34561")', text)
        self.assertIn('(local tcp "localhost:34562")', text)
        self.assertNotIn('network-outbound (local', text)
        for forbidden in ('localhost:*', '(import ', 'remote udp', 'mach-lookup', 'with no-sandbox', 'AF_UNIX'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(Path(grant['profile_path']).stat().st_mode & 0o777, 0o400)

    def test_protected_code_keeps_explicit_trusted_reads(self):
        grant, _ = self.admitted()
        profile = Path(grant['profile_path']).read_text()
        trusted = str(self.base / 'trusted')
        self.assertIn('(allow file-read* file-map-executable (subpath "' + trusted + '"))', profile)
        self.assertIn('(deny file-write* (subpath "' + trusted + '"))', profile)
        self.assertNotIn('(deny file-read*', profile)

    def test_readonly_file_is_one_exact_read_rule_and_never_a_directory_or_link(self):
        state = self.base / 'state.json'; state.write_text('{}')
        grant, _ = self.admitted(dict(self.policy, readonly_files=[str(state)]))
        profile = Path(grant['profile_path']).read_text()
        self.assertIn('(allow file-read* (literal "' + str(state) + '"))', profile)
        self.assertNotIn('file-write* (literal "' + str(state), profile)
        self.assertEqual(self.admitted(dict(self.policy, readonly_files=[]))[0]['policy_hash'], self.admitted()[0]['policy_hash'])
        link = self.base / 'link.json'; link.symlink_to(state)
        for bad in ([str(self.base / 'work')], [str(self.base / 'missing.json')], [str(link)], 'x'):
            with patch.object(self.backend, '_probe') as called:
                self.assertEqual(self.backend.admit(dict(self.policy, readonly_files=bad), 10)['reason_code'], 'INVALID_POLICY')
            called.assert_not_called()

    def test_empty_network_lists_do_not_emit_unconditional_allow(self):
        grant, _ = self.admitted(dict(self.policy, connect_tcp=[], listen_tcp=[]))
        profile = Path(grant['profile_path']).read_text()
        self.assertNotIn('(allow network-', profile)
        self.assertIn('(deny default)', profile)

    def test_exact_owned_unix_socket_without_directory_wildcard(self):
        socket = str(self.base / 'scratch/pg.sock')
        grant, _ = self.admitted(dict(self.policy, unix_sockets=[socket]))
        profile = Path(grant['profile_path']).read_text()
        self.assertIn('(remote unix-socket (path-literal "' + socket + '"))', profile)
        self.assertNotIn('path-regex', profile)

    def test_unix_policy_requires_positive_control_and_probe_retains_narrow_rule(self):
        policy = dict(self.policy, scope='database_server', unix_sockets=[str(self.base / 'scratch/pg.sock')])
        self.assertIn('unix_allowed', isolation.required_probe_checks(policy))
        self.assertNotIn('unix_allowed', isolation.required_probe_checks(self.policy))
        payload = dict(allowed4=34561, allowed6=34562, listen_allowed4=34563,
                       listen_allowed6=34564, unix_allowed=str(self.base / 'scratch/owned.sock'))
        candidate = probe._probe_policy(policy, payload, self.base, self.base / 'scratch')
        text = self.backend._compile(candidate)
        self.assertIn('(socket-domain AF_UNIX)', text)
        self.assertIn('(remote unix-socket (path-literal "' + payload['unix_allowed'] + '"))', text)
        self.assertNotIn('pg.sock', text)
        def missing_unix(policy, path, remaining):
            result = self.proof(policy, path, remaining)
            result['child_checks'].pop('unix_allowed')
            return result
        with patch.object(self.backend, '_probe', side_effect=missing_unix):
            self.assertEqual(self.backend.admit(policy, 10)['reason_code'], 'PROBE_INCOMPLETE')

    def test_no_probe_on_invalid_ports_fields_or_unowned_sockets(self):
        bad = [dict(self.policy, connect_tcp=[True]), dict(self.policy, connect_tcp=[0]),
               dict(self.policy, listen_tcp=[65536]), dict(self.policy, connect_tcp=['*:443']),
               dict(self.policy, extra='PRIVATE_CANARY'),
               dict(self.policy, unix_sockets=[str(self.base / 'foreign.sock')])]
        for policy in bad:
            with self.subTest(policy=policy), patch.object(self.backend, '_probe') as called:
                result = self.backend.admit(policy, 10)
                self.assertEqual(result['reason_code'], 'INVALID_POLICY')
                self.assertNotIn('PRIVATE_CANARY', str(result))
                called.assert_not_called()

    def test_source_control_and_ancestor_writes_are_rejected(self):
        for writable in (self.base / 'source', self.base, self.base / 'control', Path('/')):
            with self.subTest(writable=writable), patch.object(self.backend, '_probe') as called:
                result = self.backend.admit(dict(self.policy, writable_roots=[str(writable)]), 10)
                self.assertEqual(result['enforcement'], 'blocked')
                called.assert_not_called()

    def test_symlink_write_and_control_roots_are_rejected(self):
        (self.base / 'alias').symlink_to(self.base / 'work', target_is_directory=True)
        self.assertEqual(self.backend.admit(dict(self.policy, writable_roots=[str(self.base / 'alias')]), 10)['enforcement'], 'blocked')
        (self.base / 'linked-control').symlink_to(self.base / 'trusted', target_is_directory=True)
        backend = isolation.SeatbeltBackend(self.base / 'linked-control')
        with patch.object(backend, 'capability', return_value=self.backend.capability()):
            self.assertEqual(backend.admit(self.policy, 10)['reason_code'], 'CONTROL_PATH_UNSAFE')

    def test_incomplete_or_false_controls_do_not_grant(self):
        variants = [None, {}, dict(status='blocked', reason_code='PROBE_DENIED')]
        for result in variants:
            with patch.object(self.backend, '_probe', return_value=result):
                self.assertEqual(self.backend.admit(self.policy, 10)['enforcement'], 'blocked')
        for field in ('checks', 'child_checks', 'cleanup', 'policy_hash'):
            def incomplete(policy, path, remaining):
                result = self.proof(policy, path, remaining)
                result[field] = False if field == 'cleanup' else {} if field.endswith('checks') else '0' * 64
                return result
            with self.subTest(field=field), patch.object(self.backend, '_probe', side_effect=incomplete):
                self.assertEqual(self.backend.admit(self.policy, 10)['reason_code'], 'PROBE_INCOMPLETE')

    def test_probe_exception_is_redacted_and_budget_is_checked_first(self):
        with patch.object(self.backend, '_probe', side_effect=OSError('PRIVATE_CANARY')):
            result = self.backend.admit(self.policy, 10)
        self.assertEqual(result['reason_code'], 'PROBE_FAILED')
        self.assertNotIn('PRIVATE_CANARY', str(result))
        for remaining in (0, -1, True, float('nan'), float('inf')):
            with patch.object(self.backend, '_probe') as called:
                self.assertEqual(self.backend.admit(self.policy, remaining)['reason_code'], 'BUDGET_EXHAUSTED')
                called.assert_not_called()

    def test_wrap_is_argv_only_and_grants_are_one_use(self):
        grant, _ = self.admitted()
        argv = ['/usr/bin/python3', '-c', 'literal; $(not-a-shell)']
        wrapped = self.backend.wrap(argv, grant)
        self.assertEqual(wrapped, [isolation.SANDBOX_EXEC, '-f', grant['profile_path'], *argv])
        with self.assertRaisesRegex(ValueError, '^invalid isolation grant$'):
            self.backend.wrap(argv, grant)

    def test_other_backend_forged_mutated_and_simulated_grants_are_rejected(self):
        grant, _ = self.admitted()
        other = isolation.SeatbeltBackend(self.base / 'other-control')
        with self.assertRaises(ValueError):
            other.wrap(['/usr/bin/true'], grant)
        for change in ({'_token': object()}, {'scope': 'database_server'}, {'enforcement': 'simulated'}, {'profile_path': '/PRIVATE_CANARY'}):
            grant, _ = self.admitted()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^invalid isolation grant$'):
                self.backend.wrap(['/usr/bin/true'], dict(grant, **change))

    def test_changed_or_replaced_profile_cannot_be_used(self):
        grant, _ = self.admitted()
        path = Path(grant['profile_path'])
        path.chmod(0o600)
        path.write_text('(allow default)')
        path.chmod(0o400)
        with self.assertRaises(ValueError):
            self.backend.wrap(['/usr/bin/true'], grant)
        self.backend._proofs.clear()
        grant, _ = self.admitted()
        path = Path(grant['profile_path'])
        path.unlink()
        path.symlink_to(self.base / 'source')
        with self.assertRaises(ValueError):
            self.backend.wrap(['/usr/bin/true'], grant)

    def test_current_instance_cache_keeps_new_tokens_and_exact_policy_hash(self):
        with patch.object(self.backend, '_probe', side_effect=self.proof) as called:
            first = self.backend.admit(self.policy, 10)
            second = self.backend.admit(self.policy, 10)
            different = self.backend.admit(dict(self.policy, connect_tcp=[34563]), 10)
        self.assertEqual(called.call_count, 2)
        self.assertIsNot(first['_token'], second['_token'])
        self.assertEqual(first['policy_hash'], second['policy_hash'])
        self.assertNotEqual(first['policy_hash'], different['policy_hash'])

    def test_neutral_launcher_closes_descriptors_and_discards_environment(self):
        class Process:
            returncode = 0
            pid = 97531
            def communicate(self, **kwargs): return b'neutral', None
            def poll(self): return 0
        env = {'HOME': str(self.base), 'PATH': '/usr/bin:/bin'}
        with patch.object(probe.subprocess, 'Popen', return_value=Process()) as launch, patch.object(probe.os, 'killpg') as stop:
            result = probe._command(['/usr/bin/true'], env, probe.time.monotonic() + 5)
        self.assertEqual(result, (0, b'neutral'))
        args = launch.call_args.kwargs
        self.assertIs(args['close_fds'], True)
        self.assertEqual(args['pass_fds'], ())
        self.assertEqual(args['stdin'], probe.subprocess.DEVNULL)
        self.assertEqual(args['env'], env)
        self.assertTrue(args['start_new_session'])
        stop.assert_called_once_with(97531, probe.signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
