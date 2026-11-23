"""Small fail-closed macOS process boundary. No project-configured profiles."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys


SANDBOX_EXEC = '/usr/bin/sandbox-exec'
BACKEND = 'macos-seatbelt'
KEYS = {'scope', 'connect_tcp', 'listen_tcp', 'unix_sockets', 'writable_roots',
        'writable_files', 'readonly_roots', 'protected_roots'}
SCOPES = ('project', 'database_server', 'measurement')
PUBLIC = {'enforcement', 'proof_kind', 'backend', 'reason_code', 'policy_hash', 'scope'}
PROBE_CHECKS = {'tcp4_allowed', 'tcp6_allowed', 'tcp4_denied', 'tcp6_denied',
                'udp4_denied', 'udp6_denied', 'unix_denied', 'write_allowed',
                'write_denied', 'symlink_write_denied', 'listen4_allowed',
                'listen6_allowed', 'listen4_denied', 'listen6_denied'}


def required_probe_checks(policy):
    return PROBE_CHECKS | ({'unix_allowed'} if policy['unix_sockets'] else set())


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _under(path, parent):
    return path == parent or path.is_relative_to(parent)


def _safe_path(value, *, missing=False):
    if not isinstance(value, str) or not value or len(value) > 4000 or any(ord(c) < 32 for c in value):
        raise ValueError('invalid isolation path')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid isolation path')
    # Resolve only the system's /tmp and /var aliases implicitly. Project links
    # must not turn a reviewed root into another root after admission.
    spelling = str(path)
    for alias, real in (('/tmp', '/private/tmp'), ('/var', '/private/var')):
        if spelling == alias or spelling.startswith(alias + '/'):
            spelling = real + spelling[len(alias):]
    path = Path(spelling)
    current = Path(path.anchor)
    for index, component in enumerate(path.parts[1:]):
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing and index == len(path.parts) - 2:
                return path
            raise ValueError('invalid isolation path') from None
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('invalid isolation path')
    return path


def _quote(value):
    return json.dumps(str(value), ensure_ascii=False)


BROWSER_DENIED_SERVICES = ('com.apple.pasteboard.1', 'com.apple.tccd', 'com.apple.tccd.system', 'com.apple.SecurityServer',
                           'com.apple.securityd', 'com.apple.securityd.xpc', 'com.apple.coreservices.appleevents', 'com.apple.ocspd',
                           'com.apple.CoreServices.coreservicesd', 'com.apple.lsd.modifydb', 'com.apple.cfprefsd.daemon', 'com.apple.cfprefsd.agent')


class SeatbeltBackend:
    """Grants belong to this instance and are consumed once by wrap()."""
    def __init__(self, control_dir):
        self.control_dir = Path(control_dir).absolute()
        self._grants = {}
        self._proofs = {}

    def capability(self):
        if sys.platform != 'darwin':
            return dict(backend=BACKEND, status='unsupported', reason_code='UNSUPPORTED_PLATFORM')
        try:
            info = Path(SANDBOX_EXEC).lstat()
            present = stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and os.access(SANDBOX_EXEC, os.X_OK)
        except OSError:
            present = False
        return dict(backend=BACKEND, status='present_not_probed' if present else 'unavailable',
                    reason_code='SANDBOX_EXEC_PRESENT' if present else 'SANDBOX_EXEC_UNAVAILABLE')

    def _control(self):
        parent = _safe_path(str(self.control_dir.parent))
        if not parent.is_dir():
            raise ValueError('unsafe isolation control path')
        self.control_dir.mkdir(mode=0o700, exist_ok=True)
        path = _safe_path(str(self.control_dir))
        info = path.stat()
        if not path.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('unsafe isolation control path')
        self.control_dir = path
        return path

    def _normalize(self, policy):
        if not isinstance(policy, dict) or set(policy) - {'readonly_files'} != KEYS or policy['scope'] not in SCOPES:
            raise ValueError('invalid isolation policy')
        result = {'scope': policy['scope']}
        for key in ('connect_tcp', 'listen_tcp'):
            values = policy[key]
            if not isinstance(values, list) or len(values) > 64 or any(type(x) is not int or not 1 <= x <= 65535 for x in values):
                raise ValueError('invalid isolation policy')
            result[key] = sorted(set(values))
        for key in KEYS - {'scope', 'connect_tcp', 'listen_tcp'}:
            values = policy[key]
            if not isinstance(values, list) or len(values) > 64:
                raise ValueError('invalid isolation policy')
            paths = [_safe_path(value, missing=key in ('unix_sockets', 'writable_files')) for value in values]
            if key in ('writable_roots', 'readonly_roots', 'protected_roots') and any(not p.is_dir() for p in paths):
                raise ValueError('invalid isolation policy')
            if key == 'writable_files' and any(p.exists() and not p.is_file() for p in paths):
                raise ValueError('invalid isolation policy')
            if key == 'unix_sockets' and any(p.exists() and not stat.S_ISSOCK(p.stat().st_mode) for p in paths):
                raise ValueError('invalid isolation policy')
            result[key] = sorted({str(p) for p in paths})
        # Pojedyncze pliki tylko do odczytu (np. stan monitora zasobów); klucz opcjonalny, pusty nie zmienia skrótu polityki.
        files = policy.get('readonly_files', [])
        if not isinstance(files, list) or len(files) > 8:
            raise ValueError('invalid isolation policy')
        if files:
            paths = [_safe_path(value) for value in files]
            if any(not p.is_file() or p.is_symlink() for p in paths):
                raise ValueError('invalid isolation policy')
            result['readonly_files'] = sorted({str(p) for p in paths})
        protected = [self.control_dir, *map(Path, result['protected_roots'])]
        writes = [*map(Path, result['writable_roots']), *map(Path, result['writable_files'])]
        broad = {Path('/'), Path('/Users'), Path('/private'), Path('/private/tmp'), Path.home()}
        for path in writes:
            if path in broad or any(_under(path, p) or _under(p, path) for p in protected):
                raise ValueError('invalid isolation policy')
        for socket in map(Path, result['unix_sockets']):
            if not any(_under(socket, root) for root in map(Path, result['writable_roots'])):
                raise ValueError('invalid isolation policy')
        return result

    def _compile(self, policy):
        # No system.sb import: it grants Mach and Unix relays. No source-address
        # filter on outbound. A missing rule is an intentional denial.
        lines = ['(version 1)', '(deny default)', '(allow process-fork process-exec)',
                 '(allow sysctl-read)', '(allow signal (target self))',
                 '(allow process-info-pidinfo (target self))', '(allow file-read-metadata)',
                 # macOS 27: dyld czyta sam katalog główny; bez tego każdy proces kończy się SIGABRT.
                 '(allow file-read* (literal "/"))']
        baseline = ['/usr/bin', '/bin', '/usr/lib', '/usr/share', '/System/Library',
                    '/System/Cryptexes', str(Path(sys.base_prefix).resolve()), str(Path(__file__).resolve().parent),
                    # baza stref czasowych: /usr/share/zoneinfo jest dowiązaniem do tego katalogu (zoneinfo, pytz, tzdata)
                    '/private/var/db/timezone']
        for root in sorted(set(baseline + policy['readonly_roots'] + policy['writable_roots'])):
            lines.append('(allow file-read* file-map-executable (subpath ' + _quote(root) + '))')
        for device in ('/dev/null', '/dev/urandom', '/dev/random'):
            lines.append('(allow file-read-data (literal ' + _quote(device) + '))')
        lines.append('(allow file-write-data (literal "/dev/null"))')
        for root in policy['writable_roots']:
            lines.append('(allow file-write* (subpath ' + _quote(root) + '))')
        for file in policy.get('readonly_files', []):
            lines.append('(allow file-read* (literal ' + _quote(file) + '))')
        for file in policy['writable_files']:
            lines.append('(allow file-read* file-write* (literal ' + _quote(file) + '))')
        if policy['scope'] == 'database_server':
            # PostgreSQL wymaga segmentu i semaforów SysV (shmat, semctl); POSIX IPC nie jest potrzebne przy
            # dynamic_shared_memory_type=mmap i pozostaje zabronione. Seatbelt nie filtruje SysV po kluczu,
            # więc serwer może sięgnąć do segmentów SysV tego samego użytkownika: jawne ograniczenie tej izolacji.
            lines.append('(allow ipc-sysv-shm ipc-sysv-sem)')
            # Procesy serwera sygnalizują się nawzajem (checkpoint, DROP DATABASE); tylko w obrębie tej samej izolacji.
            lines.append('(allow signal (target same-sandbox))')
        if policy['scope'] == 'measurement':
            # Przeglądarka pomiarowa (Chrome bez okna) nie startuje bez usług Mach i gniazd uniksowych we własnym katalogu.
            # Dotyczy tylko fazy pomiarów; kod projektu w pozostałych fazach tego nie dostaje.
            # Zestaw ustalony doświadczalnie na macOS 27: usługi tylko o nazwach Apple i własnych Chrome, rejestracja tylko
            # własnych nazw, jawna odmowa usług wrażliwych, bez których Chrome nadal startuje.
            lines.append('(allow mach-lookup (global-name-regex #"^(com\\.apple\\.|com\\.google\\.Chrome|org\\.chromium\\.)"))')
            lines.append('(allow mach-register (global-name-regex #"^(com\\.google\\.Chrome|org\\.chromium\\.)"))')
            lines.append('(deny mach-lookup ' + ' '.join('(global-name ' + _quote(name) + ')' for name in BROWSER_DENIED_SERVICES) + ')')
            # Chrome zakłada katalog i gniazdo pojedynczej instancji w katalogu z MAC_CHROMIUM_TMPDIR, który przebieg
            # ustawia na własny katalog roboczy. Systemowy katalog tymczasowy użytkownika nie dostaje żadnych uprawnień,
            # więc katalogi i gniazda innych instancji Chrome pozostają poza zasięgiem.
            for root in policy['writable_roots']:
                lines.append('(allow network* (local unix-socket (subpath ' + _quote(root) + ')))')
                lines.append('(allow network-outbound (remote unix-socket (subpath ' + _quote(root) + ')))')
        for port in policy['connect_tcp']:
            lines.append(f'(allow network-outbound (remote tcp "localhost:{port}"))')
        for port in policy['listen_tcp']:
            lines.append(f'(allow network-bind network-inbound (local tcp "localhost:{port}"))')
        if policy['unix_sockets']:
            lines.append('(allow system-socket (socket-domain AF_UNIX))')
        for socket in policy['unix_sockets']:
            value = _quote(socket)
            lines.extend(['(allow network-bind network-inbound (local unix-socket (path-literal ' + value + ')))',
                          '(allow network-outbound (remote unix-socket (path-literal ' + value + ')))'])
        # Protected roots preserve trusted code and control data against writes.
        # Explicit trusted read roots must remain readable (including Helix's
        # own browser scripts). Read access still requires an earlier allow.
        for root in policy['protected_roots']:
            lines.append('(deny file-write* (subpath ' + _quote(root) + '))')
        lines.append('(deny file-write* (subpath ' + _quote(self.control_dir) + '))')
        return '\n'.join(lines) + '\n'

    def _publish(self, text, label='policy'):
        directory = self._control()
        path = directory / (label + '-' + secrets.token_hex(12) + '.sb')
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        return path

    def _read_profile(self, path):
        self._control()
        if path.parent != self.control_dir:
            raise ValueError('invalid isolation grant')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o222:
                raise ValueError('invalid isolation grant')
            return stream.read(131073)

    def _probe(self, policy, profile_path, remaining):
        from helix_runtime_isolation_probe import run_probe
        return run_probe(self, policy, profile_path, remaining)

    def admit(self, policy, remaining):
        scope = policy.get('scope') if isinstance(policy, dict) and policy.get('scope') in SCOPES else None
        result = dict(enforcement='blocked', proof_kind='none', backend=BACKEND,
                      reason_code='INVALID_POLICY', policy_hash=None, scope=scope)
        if isinstance(remaining, bool) or not isinstance(remaining, (int, float)) or not 0 < remaining < float('inf'):
            result['reason_code'] = 'BUDGET_EXHAUSTED'
            return result
        capability = self.capability()
        if capability['status'] != 'present_not_probed':
            result['reason_code'] = capability['reason_code']
            return result
        try:
            self._control()
        except (OSError, ValueError):
            result['reason_code'] = 'CONTROL_PATH_UNSAFE'
            return result
        try:
            normalized = self._normalize(policy)
            profile = self._compile(normalized)
            if len(profile.encode()) > 131072:
                raise ValueError('invalid isolation policy')
        except (OSError, ValueError, TypeError):
            return result
        digest = _digest(profile.encode())
        result['policy_hash'] = digest
        try:
            cached = self._proofs.get(digest)
            if cached and _digest(self._read_profile(cached)) == digest:
                path = cached
            else:
                path = self._publish(profile)
                try:
                    proof = self._probe(normalized, path, min(float(remaining), 12.0))
                except (OSError, ValueError, RuntimeError):
                    result['reason_code'] = 'PROBE_FAILED'
                    return result
                if not isinstance(proof, dict) or proof.get('status') != 'passed':
                    reason = proof.get('reason_code') if isinstance(proof, dict) else None
                    result['reason_code'] = reason if reason in ('PROBE_DENIED', 'PROBE_INCOMPLETE', 'PROBE_FAILED', 'BUDGET_EXHAUSTED') else 'PROBE_INCOMPLETE'
                    return result
                if (set(proof) != {'status', 'checks', 'child_checks', 'cleanup', 'policy_hash', 'probe_policy_hash'}
                        or proof['cleanup'] is not True or proof['policy_hash'] != digest
                        or not isinstance(proof['probe_policy_hash'], str)
                        or not re.fullmatch(r'[a-f0-9]{64}', proof['probe_policy_hash'])
                        or any(not isinstance(proof.get(key), dict) or set(proof[key]) != required_probe_checks(normalized)
                               or any(value is not True for value in proof[key].values()) for key in ('checks', 'child_checks'))):
                    result['reason_code'] = 'PROBE_INCOMPLETE'
                    return result
                self._proofs[digest] = path
            result.update(enforcement='enforced', proof_kind='execution', reason_code='LOCAL_PROBE_PASSED')
            token = object()
            grant = dict(result, profile_path=str(path), _token=token)
            self._grants[token] = (dict(result), path)
            return grant
        except (OSError, ValueError):
            result['reason_code'] = 'PROFILE_PUBLICATION_FAILED'
            return result

    def wrap(self, argv, grant):
        invalid = ValueError('invalid isolation grant')
        if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or '\x00' in x for x in argv) or not argv[0]:
            raise invalid
        if not isinstance(grant, dict) or set(grant) != PUBLIC | {'profile_path', '_token'}:
            raise invalid
        token = grant.get('_token')
        try:
            saved = self._grants.pop(token, None)
        except TypeError:
            raise invalid from None
        if not saved:
            raise invalid
        expected, path = saved
        try:
            if ({key: grant[key] for key in PUBLIC} != expected or grant['profile_path'] != str(path)
                    or _digest(self._read_profile(path)) != expected['policy_hash']):
                raise invalid
        except (OSError, ValueError):
            raise invalid from None
        return [SANDBOX_EXEC, '-f', str(path), *argv]
