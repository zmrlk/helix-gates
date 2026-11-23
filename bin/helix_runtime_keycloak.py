"""Owned disposable Keycloak lifecycle. No image pull, stub fallback or login claim.

Runner supplies its executor, global budget, resource governor, private temp root
and shared TLS material. Tests inject Executor.keycloak_json; the default probe
only contacts exact loopback HTTPS URLs, verifies the supplied CA and rejects
redirects. Private realm import data never enters argv or the public receipt.
"""
import base64
import copy
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import stat
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from helix_runtime_identity import IMAGE, synthetic_realm
from helix_resources import ResourcePaused
from helix_runtime_container import local_docker_endpoint, engine_environment

OWNER_LABEL = 'io.helix.runtime.owner'
IMAGE_FORMAT = '{"id":{{json .Id}},"digests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}'
OWNER_FORMAT = '{{json (index .Config.Labels "' + OWNER_LABEL + '")}}'
LIMIT = 1024 * 1024


class KeycloakBlocked(RuntimeError):
    def __init__(self, reason, receipt=None):
        super().__init__(reason)
        self.receipt = receipt or {}


def private_material(plan, app_origin):
    """Fresh synthetic-only secrets; caller must keep this dictionary private."""
    material = dict(realm='helix-' + secrets.token_hex(16), app_origin=app_origin,
                    user_passwords={row['id']: secrets.token_urlsafe(32) for row in plan.get('identities', [])})
    if plan.get('client', {}).get('client_type') == 'confidential': material['client_secret'] = secrets.token_urlsafe(40)
    synthetic_realm(plan, material)  # Validate before any caller publishes files.
    return material


def _loopback(url):
    try:
        value = urlsplit(url)
        return (value.scheme == 'https' and value.hostname == '127.0.0.1' and value.port is not None and
                1 <= value.port <= 65535 and not value.username and not value.password and
                not value.query and not value.fragment and not re.search(r'[\s\\\x00-\x1f\x7f]', url))
    except (ValueError, TypeError): return False


def local_json(url, cert, timeout):
    """One bounded request, no proxy, redirects, remote hostname or insecure TLS."""
    if not _loopback(url): raise KeycloakBlocked('invalid local Keycloak probe URL')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    context = ssl.create_default_context(cafile=str(cert))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    try: response = opener.open(url, timeout=timeout)
    except urllib.error.HTTPError as error: response = error
    with response:
        raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT: raise KeycloakBlocked('Keycloak probe response exceeds size limit')
        try: data = json.loads(raw)
        except (ValueError, UnicodeError): data = None
        return dict(status=response.code, data=data)


def _private_read(root, candidate):
    """Read only a regular TLS file below Runner's private root, no symlinks."""
    try: relative = Path(candidate).relative_to(root)
    except (TypeError, ValueError): raise KeycloakBlocked('TLS material must be inside runtime private directory') from None
    if not relative.parts or '..' in relative.parts: raise KeycloakBlocked('invalid private TLS path')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT: raise KeycloakBlocked('TLS material must be a bounded regular file')
            with os.fdopen(fd, 'rb', closefd=False) as stream: data = stream.read(LIMIT + 1)
            if not data or len(data) > LIMIT: raise KeycloakBlocked('empty or oversized TLS material')
            return data
        finally: os.close(fd)
    finally: os.close(directory)


def _write_private(path, data):
    # UID 1000 in the image must read each bind-mounted file. The host parent is
    # 0700; no directory, project tree, HOME or writable secret mount is exposed.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream: stream.write(data); stream.flush(); os.fsync(fd)
        os.fchmod(fd, 0o444)
    finally: os.close(fd)


def _image_record(raw):
    try: value = json.loads(raw)
    except (ValueError, TypeError): raise KeycloakBlocked('invalid local image metadata') from None
    if not isinstance(value, dict): raise KeycloakBlocked('invalid local image metadata')
    image_id = value.get('id', '')
    if isinstance(image_id, str) and re.fullmatch(r'[a-f0-9]{64}', image_id): image_id = 'sha256:' + image_id
    if not isinstance(image_id, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id): raise KeycloakBlocked('local image ID missing')
    if value.get('os') != 'linux': raise KeycloakBlocked('Keycloak image must target Linux')
    arch = value.get('architecture')
    digests = value.get('digests')
    return dict(requested=IMAGE, id=image_id, digests=[d for d in digests if isinstance(d, str) and
                re.fullmatch(r'[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}', d)] if isinstance(digests, list) else [],
                os='linux', architecture=arch if isinstance(arch, str) and re.fullmatch(r'[a-z0-9_]+', arch) else None)


class IdentityHandle:
    """Internal handle: serialize receipt(), never its private attributes."""
    def __init__(self, runner, plan, binding):
        self.runner = runner; self.plan = plan
        self.host_home = getattr(runner, 'host_home', None) or Path.home(); self.engine_endpoint = None
        self.endpoint_record = None
        self.token = secrets.token_hex(16); self.name = 'helix-keycloak-' + self.token
        self.directory = Path(runner.tmp) / self.name
        self.artifact = Path(runner.out) / (self.name + '-status.json')
        self.engine = None; self.executable = None; self.container_id = None; self.issuer = None
        self.cert = None; self.key = None; self.closed = False; self.creation_attempted = False
        self.environment = {}
        self.state = dict(schema_version=1, **binding, identity_plan_id=plan['plan_id'], provider='keycloak',
                          strategy='container', status='starting', readiness='not_checked', actual_version=None,
                          logs=[], tested_routes=[], coverage='not_checked', image=None, phases=[],
                          cleanup=dict(status='not_needed'), profile='synthetic dev-file/cache-local',
                          limitations=['no_login_performed', 'no_route_coverage', 'egress_isolation_not_proven',
                                       'app_tls_secure_cookie_coverage_not_proven'])

    def receipt(self): return copy.deepcopy(self.state)

    def save(self):
        fd, name = tempfile.mkstemp(prefix='.' + self.name + '-', dir=self.runner.out)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(self.state, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.artifact)
        finally:
            if os.path.exists(name): os.unlink(name)

    def command(self, argv, maximum=120, cleanup=False):
        previous_env = self.runner.env
        if argv and str(argv[0]) == str(self.executable):
            # App credentials may have been installed after readiness. Engine
            # commands, including final cleanup, never inherit those values.
            self.runner.env = engine_environment(previous_env, engine=self.engine, endpoint=self.endpoint_record)
        try:
            output = self.runner.command(argv, cwd=self.runner.tmp, maximum=maximum, cleanup=cleanup)
            if not cleanup: self.runner.budget.remaining(.001)
            return output
        finally:
            self.runner.env = previous_env
            log = getattr(self.runner, 'last_log', None)
            if isinstance(log, str) and re.fullmatch(r'logs/[A-Za-z0-9_.-]+', log) and log not in self.state['logs']:
                self.state['logs'].append(log)

    def close(self):
        if self.closed: return
        if self.creation_attempted and self.executable:
            target = self.container_id or self.name
            try:
                owner = json.loads(self.command([self.executable, 'container', 'inspect', '--format', OWNER_FORMAT, target], cleanup=True))
                if owner != self.token:
                    self.state['cleanup'] = dict(status='refused', reason='container ownership label does not match')
                    self.save(); return
                self.command([self.executable, 'rm', '-f', target], cleanup=True)
                self.state['cleanup'] = dict(status='removed', ownership_label_verified=True)
            except Exception as error:
                self.state['cleanup'] = dict(status='unknown', reason='cleanup failed', error_type=type(error).__name__)
                self.save(); return
        else: self.state['cleanup'] = dict(status='not_needed')
        if self.directory.exists(): shutil.rmtree(self.directory)
        self.closed = True
        self.save()


def _wait_json(handle, url, phase, accept, maximum=120):
    runner = handle.runner
    clock = getattr(runner.budget, 'clock', time.monotonic)
    sleep = getattr(runner.executor, 'sleep', time.sleep)
    probe = getattr(runner.executor, 'keycloak_json', local_json)
    end = clock() + runner.budget.remaining(maximum)
    while True:
        runner.resource_wait()
        if clock() >= end: raise KeycloakBlocked('Keycloak ' + phase + ' timed out')
        timeout = runner.budget.remaining(min(2, end - clock()))
        try: response = probe(url, handle.cert, timeout)
        except (OSError, ValueError, urllib.error.URLError): response = None
        runner.budget.remaining(.001)
        if isinstance(response, dict) and response.get('status') == 200:
            value = accept(response.get('data'))
            if value is not None: return value
        elif isinstance(response, dict) and 300 <= response.get('status', 0) < 400:
            raise KeycloakBlocked('Keycloak redirect refused during ' + phase)
        delay = runner.budget.remaining(min(.2, max(.001, end - clock())))
        sleep(delay)


def _discovery(data, issuer):
    if not isinstance(data, dict): return None
    if data.get('issuer') != issuer: raise KeycloakBlocked('Keycloak discovery issuer mismatch')
    endpoints = {'authorization_endpoint': 'auth', 'token_endpoint': 'token', 'jwks_uri': 'certs'}
    for key, suffix in endpoints.items():
        if data.get(key) != issuer + '/protocol/openid-connect/' + suffix:
            raise KeycloakBlocked('Keycloak discovery endpoint mismatch')
    return {'issuer': issuer, 'endpoints_local': True}


def _jwks(data):
    if not isinstance(data, dict) or not isinstance(data.get('keys'), list) or not data['keys']:
        raise KeycloakBlocked('Keycloak JWKS has no public signing key')
    for key in data['keys']:
        if not isinstance(key, dict) or set(key) & {'d', 'p', 'q', 'dp', 'dq', 'qi', 'k'}:
            raise KeycloakBlocked('Keycloak JWKS contains unsupported key material')
        if key.get('kty') == 'RSA': fields = [('n', 128), ('e', 2)]
        elif key.get('kty') == 'EC' and key.get('crv') in ('P-256', 'P-384', 'P-521'): fields = [('x', 40), ('y', 40)]
        else: raise KeycloakBlocked('Keycloak JWKS key type unsupported')
        if any(not isinstance(key.get(field), str) or not re.fullmatch(r'[A-Za-z0-9_-]{' + str(minimum) + ',}', key[field]) for field, minimum in fields):
            raise KeycloakBlocked('Keycloak JWKS public key malformed')
    return dict(public_key_count=len(data['keys']), signature_verification_performed=False)


def _node_tls_probe(runner, handle, node):
    """Próba fetch z Node do własnego IdP przez straż skrzynek; każdy błąd przywraca środowisko i cofa dopuszczenie portu."""
    # Przyczyna trafia do logu kroku: sam kod wyjścia 1 nie mówił, czy zawiódł certyfikat, sieć czy treść odpowiedzi.
    probe = ("fetch(process.argv[1],{redirect:'error'}).then(async r=>{if(!r.ok){console.error('status '+r.status);process.exit(1)}"
             "if((await r.json()).issuer!==process.argv[2]){console.error('issuer mismatch');process.exit(1)}})"
             ".catch(e=>{console.error(String((e&&e.cause&&(e.cause.code||e.cause.message))||e));process.exit(1)})")
    parsed = urlsplit(handle.issuer)
    if parsed.hostname not in ('127.0.0.1', 'localhost', '::1') or not parsed.port: raise KeycloakBlocked('Keycloak issuer is not a local run address')
    ports = getattr(runner, 'network_connect_ports', None); refresh = getattr(runner, 'refresh_sink_input', None)
    previous_env = runner.env; admitted_here = False; passed = False
    try:
        runner.env = dict(previous_env, **handle.environment)
        runner.env.pop('NODE_TLS_REJECT_UNAUTHORIZED', None)
        # Straż skrzynek (preload Node) przepuszcza tylko własne adresy przebiegu; lokalny Keycloak jest jednym z nich.
        if isinstance(ports, set) and parsed.port not in ports:
            ports.add(parsed.port); admitted_here = True
        if callable(refresh): refresh()
        handle.command([node, '-e', probe, handle.issuer + '/.well-known/openid-configuration', handle.issuer], maximum=10)
        passed = True
    finally:
        runner.env = previous_env
        if not passed and admitted_here:
            ports.discard(parsed.port)
            if callable(refresh):
                try: refresh()
                except Exception: pass  # pierwotny błąd próby jest ważniejszy niż błąd sprzątania


def start_keycloak(runner, part_plan, material, tls, *, binding, engine=None):
    """Start exact local image, register cleanup first, return readiness receipt.

    binding is the inventory integration_id/plan_id and current runtime run_id.
    TLS is already generated by Runner: cert_path, key_path, spki_sha256.
    No private credentials are set in argv, container environment or receipts.
    """
    patterns = dict(integration_id=r'keycloak:[0-9a-f]{12}', plan_id=r'[0-9a-f]{64}', run_id=r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}')
    if not isinstance(binding, dict) or set(binding) != set(patterns) or any(
            not isinstance(binding[key], str) or not re.fullmatch(pattern, binding[key]) for key, pattern in patterns.items()):
        raise KeycloakBlocked('Keycloak requires exact inventory and run binding')
    realm = synthetic_realm(part_plan, material)
    if part_plan['image'] != IMAGE: raise KeycloakBlocked('unsupported Keycloak image; no fallback')
    handle = IdentityHandle(runner, part_plan, binding)
    runner.cleanup_actions.append(handle.close)
    ready = False; phase = 'configuration'; failure = None
    try:
        handle.save()
        selected = engine or (runner.engine if runner.engine in ('docker', 'podman') else None)
        selected = selected or next((name for name in ('podman', 'docker') if runner.tools.get(name)), None)
        if selected not in ('docker', 'podman') or not runner.tools.get(selected): raise KeycloakBlocked('local container engine missing; no fallback')
        handle.engine = selected; handle.executable = runner.tools[selected]; handle.state['engine'] = selected
        if selected == 'docker':
            endpoint = runner.docker_endpoint(local_docker_endpoint) if hasattr(runner, 'docker_endpoint') else local_docker_endpoint(handle.host_home)
            handle.state['endpoint'] = ({key: endpoint[key] for key in ('kind', 'source')} if endpoint else
                                        dict(kind='unavailable', source='known_local_paths'))
            if endpoint is None: raise KeycloakBlocked('known local Docker Unix socket missing; no context fallback')
            handle.endpoint_record = endpoint
            handle.engine_endpoint = endpoint['host']
        if not isinstance(tls, dict) or set(tls) != {'cert_path', 'key_path', 'spki_sha256'}: raise KeycloakBlocked('shared runtime TLS material missing')
        try: spki = base64.b64decode(tls['spki_sha256'], validate=True)
        except (ValueError, TypeError): raise KeycloakBlocked('invalid shared TLS SPKI') from None
        if len(spki) != 32: raise KeycloakBlocked('invalid shared TLS SPKI')
        if any(Path(tls[key]).is_relative_to(runner.work) for key in ('cert_path', 'key_path')):
            raise KeycloakBlocked('TLS material cannot come from project copy')
        root = Path(runner.tmp)
        cert = _private_read(root, tls['cert_path']); key = _private_read(root, tls['key_path'])
        phase = 'image_inspect'
        handle.state['image'] = _image_record(handle.command([handle.executable, 'image', 'inspect', '--format', IMAGE_FORMAT, IMAGE], maximum=15))
        handle.state['phases'].append(dict(name=phase, status='recorded')); handle.save()
        handle.directory.mkdir(mode=0o700)
        realm_file = handle.directory / (realm['realm'] + '-realm.json')
        handle.cert = handle.directory / 'cert.pem'; handle.key = handle.directory / 'key.pem'
        _write_private(realm_file, json.dumps(realm, sort_keys=True).encode())
        _write_private(handle.cert, cert); _write_private(handle.key, key)
        port, health_port = runner.port_factory(), runner.port_factory()
        app_port = urlsplit(material['app_origin']).port
        if any(type(p) is not int or not 1 <= p <= 65535 for p in (port, health_port)) or len({port, health_port, app_port}) != 3:
            raise KeycloakBlocked('Keycloak ports must be distinct from each other and the application')
        origin = 'https://127.0.0.1:' + str(port); handle.issuer = origin + '/realms/' + realm['realm']
        handle.state['issuer'] = handle.issuer
        argv = [handle.executable, 'run', '--detach', '--rm', '--pull=never', '--name', handle.name,
                '--label', OWNER_LABEL + '=' + handle.token, '-p', f'127.0.0.1:{port}:8443', '-p', f'127.0.0.1:{health_port}:9000']
        for source, target in [(realm_file, '/opt/keycloak/data/import/' + realm_file.name), (handle.cert, '/helix/cert.pem'), (handle.key, '/helix/key.pem')]:
            if ',' in str(source): raise KeycloakBlocked('unsupported comma in private mount path')
            argv += ['--mount', 'type=bind,src=' + str(source) + ',dst=' + target + ',readonly']
        # Launch the inspected immutable image ID, avoiding a concurrent tag move.
        argv += [handle.state['image']['id'], 'start', '--import-realm', '--db=dev-file', '--cache=local', '--health-enabled=true',
                 '--metrics-enabled=true', '--hostname=' + origin, '--http-enabled=false', '--http-host=0.0.0.0',
                 '--https-certificate-file=/helix/cert.pem', '--https-certificate-key-file=/helix/key.pem',
                 '--http-management-scheme=inherited', '--http-management-relative-path=/']
        phase = 'container_start'; handle.creation_attempted = True
        output = handle.command(argv, maximum=120)
        candidate = output.strip().splitlines()[-1] if output.strip() else ''
        if not re.fullmatch(r'[a-f0-9]{64}', candidate): raise KeycloakBlocked('container ID missing after start')
        handle.container_id = candidate
        handle.state['container_id'] = candidate; handle.state['phases'].append(dict(name=phase, status='started')); handle.save()
        phase = 'server_version'
        output = handle.command([handle.executable, 'exec', candidate, '/opt/keycloak/bin/kc.sh', '--version'], maximum=30)
        match = re.search(r'\bKeycloak\s+(\d+\.\d+\.\d+)(?![\w.-])', output)
        handle.state['actual_version'] = match[1] if match else None
        if handle.state['actual_version'] != '26.8.1': raise KeycloakBlocked('actual Keycloak server version mismatch')
        handle.state['phases'].append(dict(name=phase, status='recorded')); handle.save()
        phase = 'health'
        health = _wait_json(handle, f'https://127.0.0.1:{health_port}/health/ready', phase,
                           lambda data: dict(checks_count=len(data.get('checks', []))) if isinstance(data, dict) and data.get('status') == 'UP' and isinstance(data.get('checks', []), list) else None)
        handle.state['phases'].append(dict(name=phase, status='ready', **health)); handle.save()
        phase = 'discovery'
        discovery = _wait_json(handle, handle.issuer + '/.well-known/openid-configuration', phase, lambda data: _discovery(data, handle.issuer))
        handle.state['phases'].append(dict(name=phase, status='ready', **discovery)); handle.save()
        phase = 'jwks'
        keys = _wait_json(handle, handle.issuer + '/protocol/openid-connect/certs', phase, _jwks)
        handle.state['phases'].append(dict(name=phase, status='ready', **keys)); handle.save()
        phase = 'node_tls'
        node = runner.tools.get('node')
        if not node: raise KeycloakBlocked('Node TLS probe unavailable')
        handle.environment = dict(NODE_EXTRA_CA_CERTS=str(handle.cert), SSL_CERT_FILE=str(handle.cert), REQUESTS_CA_BUNDLE=str(handle.cert),
                                  HELIX_RUNTIME_OIDC_SPKI=tls['spki_sha256'], HELIX_RUNTIME_OIDC_ISSUER=handle.issuer)
        _node_tls_probe(runner, handle, node)
        handle.state['phases'].append(dict(name=phase, status='ready', scope='native Node fetch with per-process CA'))
        handle.state.update(status='ready', readiness='ready'); handle.save(); ready = True
        return handle
    except ResourcePaused as error:
        handle.state.update(status='resource_paused', reason='resource admission paused', failed_phase=phase)
        failure = error
        raise
    except Exception as error:
        reason = str(error) if isinstance(error, KeycloakBlocked) else 'Keycloak ' + phase + ' failed (' + type(error).__name__ + ')'
        handle.state.update(status='blocked', reason=reason, failed_phase=phase)
        failure = KeycloakBlocked(reason)
        raise failure from None
    finally:
        if not ready:
            if handle.state['status'] == 'starting': handle.state.update(status='interrupted', failed_phase=phase)
            handle.close()
            if failure is not None:
                failure.receipt = handle.receipt()
                failure.artifact = handle.artifact
