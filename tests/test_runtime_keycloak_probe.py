"""Próba TLS z Node do lokalnego Keycloaka: dopuszczenie portu w straży skrzynek i jego cofnięcie (atrapy, bez procesów)."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_keycloak as keycloak


class Runner:
    def __init__(self, ports=(), refresh_error_at=None):
        self.env = {'KEEP': '1', 'NODE_TLS_REJECT_UNAUTHORIZED': '0'}; self.original = self.env
        self.network_connect_ports = set(ports); self.refreshes = []; self.refresh_error_at = refresh_error_at
    def refresh_sink_input(self):
        self.refreshes.append((sorted(self.network_connect_ports), dict(self.env)))
        if self.refresh_error_at == len(self.refreshes): raise OSError('synthetic refresh failure')


class Handle:
    def __init__(self, issuer='https://127.0.0.1:45001/realms/helix-synthetic', fail=False):
        self.issuer = issuer; self.fail = fail; self.calls = []
        self.environment = {'HELIX_RUNTIME_OIDC_ISSUER': issuer, 'NODE_EXTRA_CA_CERTS': '/synthetic/cert.pem'}
    def command(self, argv, maximum=None):
        self.calls.append(argv)
        if self.fail: raise keycloak.KeycloakBlocked('synthetic probe failure')
        return ''


class NodeTlsProbe(unittest.TestCase):
    def test_success_keeps_the_port_admitted_and_restores_environment(self):
        runner = Runner(); handle = Handle()
        keycloak._node_tls_probe(runner, handle, '/synthetic/node')
        self.assertEqual(runner.network_connect_ports, {45001})
        self.assertIs(runner.env, runner.original)
        self.assertEqual(len(runner.refreshes), 1)
        ports, env = runner.refreshes[0]
        self.assertEqual(ports, [45001]); self.assertEqual(env['HELIX_RUNTIME_OIDC_ISSUER'], handle.issuer)
        self.assertNotIn('NODE_TLS_REJECT_UNAUTHORIZED', env)
        self.assertEqual(handle.calls[0][-2:], [handle.issuer + '/.well-known/openid-configuration', handle.issuer])

    def test_failed_probe_withdraws_the_port_and_refreshes_again(self):
        runner = Runner(); handle = Handle(fail=True)
        with self.assertRaises(keycloak.KeycloakBlocked): keycloak._node_tls_probe(runner, handle, '/synthetic/node')
        self.assertEqual(runner.network_connect_ports, set())
        self.assertIs(runner.env, runner.original)
        self.assertEqual([ports for ports, _ in runner.refreshes], [[45001], []])
        self.assertNotIn('HELIX_RUNTIME_OIDC_ISSUER', runner.refreshes[1][1])

    def test_refresh_failure_restores_environment_and_withdraws_the_port(self):
        runner = Runner(refresh_error_at=1); handle = Handle()
        with self.assertRaises(OSError): keycloak._node_tls_probe(runner, handle, '/synthetic/node')
        self.assertEqual(runner.network_connect_ports, set())
        self.assertIs(runner.env, runner.original)
        self.assertEqual(handle.calls, [])

    def test_port_admitted_earlier_by_the_run_is_not_withdrawn(self):
        runner = Runner(ports=[45001]); handle = Handle(fail=True)
        with self.assertRaises(keycloak.KeycloakBlocked): keycloak._node_tls_probe(runner, handle, '/synthetic/node')
        self.assertEqual(runner.network_connect_ports, {45001})

    def test_non_local_issuer_is_refused_before_any_admission(self):
        for issuer in ('https://idp.example.invalid:8443/realms/x', 'https://10.0.0.5:8443/realms/x', 'https://127.0.0.1/realms/x'):
            with self.subTest(issuer=issuer):
                runner = Runner(); handle = Handle(issuer=issuer)
                with self.assertRaises(keycloak.KeycloakBlocked): keycloak._node_tls_probe(runner, handle, '/synthetic/node')
                self.assertEqual(runner.network_connect_ports, set()); self.assertEqual(runner.refreshes, []); self.assertEqual(handle.calls, [])
                self.assertIs(runner.env, runner.original)


class RealGuardBoundary(unittest.TestCase):
    """Granica na prawdziwych elementach: preload straży w Node i Runner.refresh_sink_input, bez atrap granicy."""
    @unittest.skipUnless(__import__('shutil').which('node'), 'wymaga Node')
    def test_real_preload_refuses_the_idp_until_its_origin_is_admitted(self):
        import json, shutil, subprocess
        from test_runtime_sinks import fixture_input
        root = Path(__file__).resolve().parents[1]
        source = r"""
const assert=require('node:assert/strict');
const {createAdapter}=require('./bin/runtime-sinks-preload.cjs');
const input=JSON.parse(process.argv[1]);const idp=process.argv[2];
const seen=[];const native=async(request)=>{seen.push(request.url);return new Response('{}')};
(async()=>{
  const closed=createAdapter(input,{fetch:native});
  await assert.rejects(closed.fetch(idp+'/realms/x/.well-known/openid-configuration'),{code:'HELIX_SINK_UNSUPPORTED'});
  assert.equal(seen.length,0);
  const open=createAdapter(Object.assign({},input,{own_origins:[...input.own_origins,idp]}),{fetch:native});
  await open.fetch(idp+'/realms/x/.well-known/openid-configuration');
  assert.deepEqual(seen,[idp+'/realms/x/.well-known/openid-configuration']);
  await assert.rejects(open.fetch('https://idp.example.invalid:8443/realms/x'),{code:'HELIX_SINK_UNSUPPORTED'});
  await assert.rejects(open.fetch('https://127.0.0.1:45999/realms/x'),{code:'HELIX_SINK_UNSUPPORTED'});
  assert.equal(seen.length,1);
})().catch(error=>{console.error(error);process.exit(1)});
"""
        done = subprocess.run([shutil.which('node'), '-e', source, json.dumps(fixture_input()[1]), 'https://127.0.0.1:45001'],
                              cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr[-800:])

    def test_real_refresh_admits_only_a_loopback_issuer_on_a_port_owned_by_the_run(self):
        import json, tempfile
        import helix_runtime as runtime
        from unittest.mock import patch
        from test_runtime import FakeExecutor, TOOLS, FIX
        from test_runtime_sinks import fixture_input
        cases = [('https://127.0.0.1:45001/realms/x', {45001}, True), ('https://127.0.0.1:45001/realms/x', set(), False),
                 ('https://idp.example.invalid:45001/realms/x', {45001}, False), ('https://10.0.0.5:45001/realms/x', {45001}, False)]
        for issuer, ports, admitted in cases:
            with self.subTest(issuer=issuer, ports=ports), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                runner = runtime.Runner(FIX/'project-runner', base/'out', executor=FakeExecutor(), tools={'tools': dict(TOOLS)}, port_factory=lambda: 31234)
                value = fixture_input()[1]; before = list(value['own_origins']); written = []
                runner.active_sink = dict(input=value, config=base/'sink.json'); runner.network_connect_ports = set(ports)
                runner.env = {'HELIX_RUNTIME_OIDC_ISSUER': issuer}
                with patch('helix_runtime_generic.refresh_generic'), patch.object(runner, 'add_owned_preload'), \
                        patch.object(runner, 'write_sink_input', side_effect=lambda data, path: written.append(json.loads(json.dumps(data)))):
                    runner.refresh_sink_input()
                expected = sorted(set(before) | ({'https://127.0.0.1:45001'} if admitted else set()))
                self.assertEqual(written[-1]['own_origins'], expected)


if __name__ == '__main__':
    unittest.main()
