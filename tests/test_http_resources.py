"""Readiness probes close responses without requiring local sockets."""
import importlib.machinery
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
loader = importlib.machinery.SourceFileLoader('helix_http_test', str(ROOT / 'bin/helix'))
spec = importlib.util.spec_from_loader(loader.name, loader)
H = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = H
loader.exec_module(H)
import helix_ux as U


class Responses(unittest.TestCase):
    def test_probe_closes_success_and_retried_response(self):
        for module, key, url in ((H, 'visual', 'url'), (U, 'ux', 'base_url')):
            for retry in (False, True):
                for body_error in (False, True):
                    with self.subTest(module=module.__name__, retry=retry, body_error=body_error):
                        response = MagicMock()
                        cfg = {'start_cmd': 'fixture', url: 'http://fixture', 'ready_timeout_s': 10}
                        ctx = SimpleNamespace(cfg={key: cfg}, repo=ROOT)
                        effects = ([OSError('not ready')] if retry else []) + [response]
                        with patch('urllib.request.urlopen', side_effect=effects), patch.object(module.subprocess, 'Popen'), patch.object(module.time, 'sleep'), patch.object(module.os, 'killpg'):
                            server = module.Server(ctx) if module is H else module.Server(ctx, cfg)
                            try:
                                with server:
                                    if body_error: raise RuntimeError('caller failed')
                            except RuntimeError:
                                if not body_error: raise
                        response.__exit__.assert_called_once()

    def test_http_error_response_closed_before_retry(self):
        for module, key, url in ((H, 'visual', 'url'), (U, 'ux', 'base_url')):
            with self.subTest(module=module.__name__):
                body = io.BytesIO(b'unavailable')
                error = urllib.error.HTTPError('http://fixture', 503, 'Unavailable', {}, body)
                cfg = {'start_cmd': 'fixture', url: 'http://fixture'}
                ctx = SimpleNamespace(cfg={key: cfg}, repo=ROOT)
                response = MagicMock()
                with patch('urllib.request.urlopen', side_effect=[error, response]), patch.object(module.subprocess, 'Popen'), patch.object(module.time, 'sleep'), patch.object(module.os, 'killpg'):
                    server = module.Server(ctx) if module is H else module.Server(ctx, cfg)
                    server.__exit__()
                self.assertTrue(body.closed)
                response.__exit__.assert_called_once()


class FixtureServers(unittest.TestCase):
    def test_consistency_closes_server_on_success_and_setup_error(self):
        import test_consistency as C
        for fails in (False, True):
            with self.subTest(setup_error=fails):
                class Fixture(C.Runtime):
                    pass
                server = MagicMock()
                repo = MagicMock()
                (repo / 'out' / 'findings.json').read_text.return_value = '[]'
                with patch.object(C, 'free_port', return_value=12345), patch.object(C.http.server, 'ThreadingHTTPServer', return_value=server), patch.object(C.threading, 'Thread') as thread, patch.object(C, 'make_repo', side_effect=RuntimeError('setup failed') if fails else None, return_value=repo), patch.object(C, 'sh', return_value=SimpleNamespace(returncode=0)):
                    try:
                        if fails:
                            with self.assertRaises(RuntimeError): Fixture.setUpClass()
                        else:
                            Fixture.setUpClass()
                    finally:
                        Fixture.doClassCleanups()
                    server.shutdown.assert_called_once()
                    server.server_close.assert_called_once()
                    thread.return_value.join.assert_called_once()
