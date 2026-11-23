"""Trusted local-only Seatbelt canaries. Importing this file does not probe."""
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time


def _command(argv, env, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired('neutral probe', 0)
    process = subprocess.Popen(argv, env=env, cwd=env['HOME'], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               close_fds=True, pass_fds=(), start_new_session=True)
    try:
        output, _ = process.communicate(timeout=remaining)
        return process.returncode, output
    finally:
        # The launcher may exit before a leaf. Its process group still belongs
        # to this probe and must be stopped even when poll() reports completion.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.wait(timeout=1)


def _probe_policy(policy, payload, root, scratch):
    return dict(policy, connect_tcp=[payload['allowed4'], payload['allowed6']],
                listen_tcp=[payload['listen_allowed4'], payload['listen_allowed6']],
                unix_sockets=[payload['unix_allowed']] if policy['unix_sockets'] else [],
                writable_roots=[str(scratch)], writable_files=[],
                readonly_roots=[*policy['readonly_roots'], str(root)])


def run_probe(backend, policy, profile_path, remaining):
    """Check profile admission and a neutral profile from the same compiler.

    All listeners belong to this probe. There are no DNS lookups or remote
    addresses, and no project interpreter, configuration, script or service.
    """
    from helix_runtime_isolation import SANDBOX_EXEC
    deadline = time.monotonic() + remaining
    try:
        with tempfile.TemporaryDirectory(prefix='helix-probe-', dir=backend.control_dir.parent) as name:
            root = Path(name).resolve()
            scratch = root / 'scratch'
            scratch.mkdir(mode=0o700)
            env = {'HOME': str(root), 'TMPDIR': str(scratch), 'PATH': '/usr/bin:/bin',
                   'LANG': 'C', 'LC_ALL': 'C'}
            code, _ = _command([SANDBOX_EXEC, '-f', str(profile_path), '/usr/bin/true'], env, deadline)
            if code != 0:
                return dict(status='blocked', reason_code='PROBE_DENIED')
            script = root / 'neutral.py'
            script.write_bytes(Path(__file__).read_bytes())
            script.chmod(0o400)
            forbidden = root / 'forbidden.txt'
            forbidden.write_text('neutral canary')
            (scratch / 'escape').symlink_to(forbidden)
            nonce = secrets.token_hex(16)
            payload = dict(nonce=nonce, scratch=str(scratch), forbidden=str(forbidden))
            with contextlib.ExitStack() as stack:
                def endpoint(family, kind=socket.SOCK_STREAM):
                    sock = stack.enter_context(socket.socket(family, kind))
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
                    if kind == socket.SOCK_STREAM:
                        sock.listen(16)
                    return sock.getsockname()[1]

                for suffix, family in (('4', socket.AF_INET), ('6', socket.AF_INET6)):
                    payload['allowed' + suffix] = endpoint(family)
                    payload['denied' + suffix] = endpoint(family)
                    payload['udp' + suffix] = endpoint(family, socket.SOCK_DGRAM)
                    # These ports are used only by bind/listen tests, after the
                    # parent's positive availability check releases them.
                    for key in ('listen_allowed', 'listen_denied'):
                        with socket.socket(family, socket.SOCK_STREAM) as reserve:
                            reserve.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
                            payload[key + suffix] = reserve.getsockname()[1]
                unix = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                unix_path = root / 'denied.sock'
                unix.bind(str(unix_path))
                unix.listen(4)
                payload['unix'] = str(unix_path)
                payload['unix_required'] = bool(policy['unix_sockets'])
                if payload['unix_required']:
                    allowed_unix = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                    allowed_path = scratch / 'owned.sock'
                    allowed_unix.bind(str(allowed_path))
                    allowed_unix.listen(4)
                    payload['unix_allowed'] = str(allowed_path)
                input_path = root / 'input.json'
                input_path.write_text(json.dumps(payload))
                input_path.chmod(0o400)
                probe_policy = _probe_policy(policy, payload, root, scratch)
                probe_text = backend._compile(probe_policy)
                probe_path = backend._publish(probe_text, label='neutral')
                try:
                    code, output = _command([SANDBOX_EXEC, '-f', str(probe_path),
                                             sys.executable, '-I', '-S', str(script), '--parent', str(input_path)], env, deadline)
                    if code != 0:
                        return dict(status='blocked', reason_code='PROBE_DENIED')
                    if len(output) > 16384:
                        return dict(status='blocked', reason_code='PROBE_INCOMPLETE')
                    result = json.loads(output)
                    if not isinstance(result, dict) or set(result) != {'nonce', 'checks', 'child_checks'} or result['nonce'] != nonce:
                        return dict(status='blocked', reason_code='PROBE_INCOMPLETE')
                    return dict(status='passed', checks=result['checks'], child_checks=result['child_checks'],
                                cleanup=True, policy_hash=hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                                probe_policy_hash=hashlib.sha256(probe_text.encode()).hexdigest())
                finally:
                    probe_path.unlink(missing_ok=True)
    except subprocess.TimeoutExpired:
        return dict(status='blocked', reason_code='BUDGET_EXHAUSTED')
    except (OSError, ValueError, RuntimeError):
        return dict(status='blocked', reason_code='PROBE_FAILED')


def _checks(data):
    def expect(operation, allowed):
        try:
            operation()
            return allowed
        except OSError as error:
            return not allowed and error.errno in (errno.EPERM, errno.EACCES)

    def connect(family, address, port, *, udp=False):
        with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
            sock.settimeout(.4)
            if udp:
                sock.sendto(b'neutral', (address, port))
            else:
                sock.connect((address, port))

    def listen(family, address, port):
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((address, port))
            sock.listen(1)

    def unix(path):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(.4)
            sock.connect(path)

    def write(path):
        with open(path, 'a') as stream:
            stream.write('neutral')

    result = {}
    for suffix, family, address in (('4', socket.AF_INET, '127.0.0.1'), ('6', socket.AF_INET6, '::1')):
        result['tcp' + suffix + '_allowed'] = expect(lambda: connect(family, address, data['allowed' + suffix]), True)
        result['tcp' + suffix + '_denied'] = expect(lambda: connect(family, address, data['denied' + suffix]), False)
        result['udp' + suffix + '_denied'] = expect(lambda: connect(family, address, data['udp' + suffix], udp=True), False)
        result['listen' + suffix + '_allowed'] = expect(lambda: listen(family, address, data['listen_allowed' + suffix]), True)
        result['listen' + suffix + '_denied'] = expect(lambda: listen(family, address, data['listen_denied' + suffix]), False)
    result['unix_denied'] = expect(lambda: unix(data['unix']), False)
    if data['unix_required']:
        result['unix_allowed'] = expect(lambda: unix(data['unix_allowed']), True)
    result['write_allowed'] = expect(lambda: write(str(Path(data['scratch']) / ('ok-' + str(os.getpid())))), True)
    result['write_denied'] = expect(lambda: write(data['forbidden']), False)
    result['symlink_write_denied'] = expect(lambda: write(str(Path(data['scratch']) / 'escape')), False)
    return result


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ('--parent', '--leaf'):
            raise ValueError('invalid neutral probe invocation')
        data = json.loads(Path(sys.argv[2]).read_text())
        checks = _checks(data)
        if sys.argv[1] == '--leaf':
            print(json.dumps(dict(nonce=data['nonce'], checks=checks)))
        else:
            child = subprocess.run([sys.executable, '-I', '-S', __file__, '--leaf', sys.argv[2]],
                                   check=True, timeout=3, capture_output=True, stdin=subprocess.DEVNULL,
                                   close_fds=True, pass_fds=())
            leaf = json.loads(child.stdout)
            if set(leaf) != {'nonce', 'checks'} or leaf['nonce'] != data['nonce']:
                raise ValueError('invalid neutral child proof')
            print(json.dumps(dict(nonce=data['nonce'], checks=checks, child_checks=leaf['checks'])))
    except Exception:
        sys.exit(2)
