"""Five explicit, isolated tool installations. Never called implicitly by a scan.

No project argument or arbitrary package input. tools_root/executor are trusted
Python injection points for tests; the future CLI exposes neither of them.
"""
from contextlib import contextmanager
from email.parser import BytesParser
import base64
import fcntl
import grp
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request
import uuid
import zipfile


CATALOG = {
    'ast-grep': dict(package='@ast-grep/cli', version='0.51.0', channel='npm', license='MIT', area='security', runner='none', parser=None),
    'knip': dict(package='knip', version='6.43.0', channel='npm', license='ISC', area='quality', runner='none', parser=None),
    'jscpd': dict(package='jscpd', version='5.4.2', channel='wheel', license='MIT', area='quality', runner='static', parser='jscpd'),
    'squawk': dict(package='squawk-cli', version='2.70.0', channel='wheel', license='Apache-2.0 OR MIT', area='database', runner='static', parser='squawk'),
    'mutmut': dict(package='mutmut', version='3.8.0', channel='wheel', license='BSD-3-Clause', area='tests', runner='mutation', parser='mutmut'),
}
PIN_SOURCES = {
    'ast-grep': 'https://github.com/ast-grep/ast-grep/releases/tag/0.51.0',
    'knip': 'https://github.com/webpro-nl/knip/releases/tag/knip@6.43.0',
    'jscpd': 'https://pypi.org/project/jscpd/5.4.2/',
    'squawk': 'https://pypi.org/project/squawk-cli/2.70.0/',
    'mutmut': 'https://pypi.org/project/mutmut/3.8.0/',
}
WHEEL_HASHES = {
    'jscpd-5.4.2-py3-none-macosx_11_0_arm64.whl': 'c852e732e686df6d74fc860e77741ea4ce4beea47f04101ea1b1ca47f9e08404',
    'squawk_cli-2.70.0-py3-none-macosx_11_0_arm64.whl': 'c6164a083f8bee368fc7c9c1cd7de4704c0775aa75767eefb371c0bd37d3bf08',
}
PIN_ROOT = Path(__file__).resolve().parents[1] / 'data/tool-pins'
TRUST_POLICY = 'repository-pins-v1'
RUNTIME_DIRS = ('/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin')
RUNTIME_ROOTS = ('/opt/homebrew', '/usr/local', '/usr/bin', '/bin', '/Library/Frameworks/Python.framework')
MAX_OUTPUT = 4 * 1024 * 1024
MUTMUT_PYTHON_CANDIDATES = ('python3.12', 'python3.13', 'python3.11', 'python3.10', 'python3')
MUTMUT_CPYTHON_MINORS = (10, 11, 12, 13)
PYTHON_IDENTITY_SCRIPT = ('import json, platform, sys; print(json.dumps({'
                          '"implementation": platform.python_implementation(), '
                          '"version": list(sys.version_info[:3]), '
                          '"releaselevel": sys.version_info.releaselevel}))')


class InstallError(ValueError):
    """Only fixed, public reason codes cross the installer boundary."""
    def __init__(self, code, *, diagnostic=None, runtime_selection=None, smoke_observation=None):
        super().__init__(code)
        self.code = code
        self.diagnostic = diagnostic
        self.runtime_selection = runtime_selection
        self.smoke_observation = smoke_observation


def _diagnostic(code, state=None, *, home=None, install_dir=None, smoke_observation=None):
    from helix_tool_diagnostics import build_diagnostic
    state = state or {}
    return build_diagnostic(phase=state.get('phase', 'runtime_discovery'), code=code,
                            argv=state.get('argv', ()), returncode=state.get('returncode'),
                            stdout=state.get('stdout', ''), stderr=state.get('stderr', ''),
                            home=home, install_dir=install_dir, smoke_observation=smoke_observation)


def _names(names):
    result = list(CATALOG) if names is None else list(names)
    if not result or len(result) != len(set(result)) or any(type(n) is not str or n not in CATALOG for n in result):
        raise InstallError('UNSUPPORTED_TOOL')
    return result


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _root(tools_root=None):
    return Path(tools_root) if tools_root is not None else Path.home() / '.local/share/helix/tools'


def _safe_path(path):
    """Reject symlinks, including parents; canonical system temp aliases allowed."""
    path = Path(os.path.abspath(path))
    for current in [*reversed(path.parents), path]:
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            if str(current) not in ('/var', '/tmp') or str(current.resolve()) not in ('/private/var', '/private/tmp'):
                raise InstallError('UNSAFE_PATH')
    return path


def _canonical(path):
    path = Path(os.path.abspath(path))
    for alias in ('/tmp', '/var'):
        if (str(path) == alias or str(path).startswith(alias + '/')) and Path(alias).is_symlink():
            target = os.path.normpath(os.path.join(os.path.dirname(alias), os.readlink(alias)))
            if target != '/private' + alias:
                raise InstallError('UNSAFE_PATH')
            path = Path('/private' + str(path))
    return path


@contextmanager
def _directory_fd(path, *, create=False):
    """Walk by descriptors: swapping a checked ancestor never redirects I/O."""
    path = _canonical(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _mkdir(path, *, parents=False, exist_ok=False):
    path = _canonical(path)
    with _directory_fd(path.parent, create=parents) as parent:
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            if not exist_ok:
                raise
        child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.close(child)


def _read_at(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise InstallError('UNSAFE_FILE')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise InstallError('UNSAFE_FILE')
        return data
    finally:
        os.close(fd)


def _read(path, limit=MAX_OUTPUT):
    path = _canonical(path)
    with _directory_fd(path.parent) as parent:
        return _read_at(parent, path.name, limit)


def _load(path):
    try:
        return json.loads(_read(path))
    except (UnicodeError, json.JSONDecodeError):
        raise InstallError('INVALID_MANIFEST') from None


def _write_at(parent, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _write(path, raw):
    path = _canonical(path)
    with _directory_fd(path.parent) as parent:
        _write_at(parent, path.name, raw)


def _unlink(path):
    path = _canonical(path)
    with _directory_fd(path.parent) as parent:
        os.unlink(path.name, dir_fd=parent)


def _atomic(path, value):
    path = _canonical(path)
    temporary = '.' + path.name + '-' + uuid.uuid4().hex
    with _directory_fd(path.parent) as parent:
        try:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise InstallError('UNSAFE_FILE')
            except FileNotFoundError:
                pass
            _write_at(parent, temporary, _json(value))
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


@contextmanager
def _lock(root):
    _safe_path(root)
    with _directory_fd(root, create=True) as parent:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise InstallError('UNSAFE_ROOT')
        fd = os.open('.install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise InstallError('UNSAFE_LOCK')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallError('INSTALL_BUSY') from None
            yield
        finally:
            os.close(fd)


def _runtime_roots():
    # The account database, not $HOME: a direnv/env override must not move the
    # trusted version-manager area.
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    managers = ('.local/share/fnm/node-versions', '.nvm/versions/node', '.asdf/installs',
                '.local/share/mise/installs', '.volta/tools', '.pyenv/versions', '.local/share/uv/python')
    return [Path(root).resolve() for root in RUNTIME_ROOTS] + [(home / root).resolve() for root in managers]


def _runtime_trust(path):
    candidate, resolved = Path(path).absolute(), Path(path).resolve()
    cwd = Path.cwd().resolve()
    repo = next((p for p in (cwd, *cwd.parents) if (p / '.git').exists()), cwd)
    if any(p.is_relative_to(repo) for p in (candidate, resolved)) or not any(resolved.is_relative_to(root) for root in _runtime_roots()):
        raise InstallError('UNTRUSTED_RUNTIME')
    observations = []
    for current in (resolved, *resolved.parents):
        info = current.stat()
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o002:
            raise InstallError('UNTRUSTED_RUNTIME')
        if info.st_mode & 0o020:
            try: group = grp.getgrgid(info.st_gid).gr_name
            except KeyError: group = None
            if (platform.system() != 'Darwin' or group not in ('admin', 'wheel') or
                    info.st_gid not in {os.getgid(), *os.getgroups()}):
                raise InstallError('UNTRUSTED_RUNTIME')
            observations.append(dict(path=str(current), mode=stat.S_IMODE(info.st_mode), owner_uid=info.st_uid,
                                     group_id=info.st_gid, group=group))
    return str(resolved), observations


class Executor:
    """Neutral subprocess runner. Output is bounded and never copied to receipts."""
    def locate(self, name):
        # PATH only contributes locations resolving inside known manager roots.
        # Arbitrary project/direnv directories are never searched.
        roots = _runtime_roots()
        managed = [str(Path(value).resolve()) for value in os.environ.get('PATH', '').split(os.pathsep)
                   if value and Path(value).is_absolute() and any(Path(value).resolve().is_relative_to(root) for root in roots)]
        found = shutil.which(name, path=os.pathsep.join(dict.fromkeys([*managed, *RUNTIME_DIRS])))
        if not found: return None
        return _runtime_trust(found)[0]

    def fetch(self, url):
        # Only registry URLs from the repository lock are admitted. Verify the
        # final URL as well: a redirect cannot introduce another source.
        class RegistryRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                target = urlsplit(newurl)
                if target.scheme != 'https' or target.hostname != 'registry.npmjs.org' or target.username or target.password or target.port:
                    raise InstallError('UNTRUSTED_PACKAGE_SOURCE')
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        opener = build_opener(ProxyHandler({}), RegistryRedirect())
        with opener.open(Request(url, headers={'User-Agent': 'helix-pinned-tools'}), timeout=60) as response:
            if urlsplit(response.url).hostname != 'registry.npmjs.org' or urlsplit(response.url).scheme != 'https':
                raise InstallError('UNTRUSTED_PACKAGE_SOURCE')
            raw = response.read(512 * 1024 * 1024 + 1)
            if len(raw) > 512 * 1024 * 1024: raise InstallError('OUTPUT_TOO_LARGE')
            return raw

    def run(self, argv, *, cwd, env, timeout):
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True,
                                       close_fds=True, pass_fds=())
            try:
                process.wait(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                raise
            else:
                # A successful launcher may leave children doing late writes.
                # They belong to this invocation's group, never to another run.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
            stdout.seek(0)
            raw = stdout.read(MAX_OUTPUT + 1)
            if len(raw) > MAX_OUTPUT:
                raise InstallError('OUTPUT_TOO_LARGE')
            stderr.seek(0, os.SEEK_END)
            stderr.seek(max(0, stderr.tell() - MAX_OUTPUT))
            error_tail = stderr.read(MAX_OUTPUT).decode('utf-8', 'replace')
            return subprocess.CompletedProcess(argv, process.returncode, raw.decode('utf-8', 'strict'), error_tail)


def _environment(home, runtime_dirs):
    return dict(PATH=os.pathsep.join(dict.fromkeys([*map(str, runtime_dirs), '/usr/bin', '/bin'])),
                HOME=str(home), XDG_CONFIG_HOME=str(home / 'config'), XDG_CACHE_HOME=str(home / 'cache'),
                TMPDIR=str(home / 'tmp'), CI='true', NO_COLOR='1', NO_UPDATE_NOTIFIER='1',
                npm_config_userconfig=str(home / 'npm-user.config'), npm_config_globalconfig=str(home / 'npm-global.config'),
                npm_config_cache=str(home / 'npm-cache'), npm_config_registry='https://registry.npmjs.org/',
                npm_config_audit='false', npm_config_fund='false', npm_config_update_notifier='false',
                npm_config_ignore_scripts='true', PIP_CONFIG_FILE=os.devnull,
                PIP_DISABLE_PIP_VERSION_CHECK='1', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
                GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='protocol.allow', GIT_CONFIG_VALUE_0='never')


def _version(text):
    match = re.search(r'(?<![0-9A-Za-z_.])v?(\d+\.\d[^\s]*)', text)
    if not match or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', match[1]):
        raise InstallError('VERSION_UNVERIFIED')
    return match[1]


def _normalized(name):
    return re.sub('[-_.]+', '-', name).lower()


def _select_mutmut_python(executor, call, env, state):
    """Select before package resolution, never retry an install on another ABI."""
    selection = dict(policy='mutmut-cpython-stable-v1', candidate_order=list(MUTMUT_PYTHON_CANDIDATES),
                     supported_cpython_minors=['3.' + str(minor) for minor in MUTMUT_CPYTHON_MINORS],
                     candidates=[], selected=None, retry_after_resolution=False)
    state['runtime_selection'] = selection
    seen = set()
    for candidate in MUTMUT_PYTHON_CANDIDATES:
        row = dict(candidate=candidate, status='not_found', version=None, implementation=None)
        selection['candidates'].append(row)
        found = executor.locate(candidate)
        if not found or not Path(found).is_absolute():
            continue
        path = str(Path(found).resolve())
        if path in seen:
            row.update(status='already_probed', reason_code='SAME_INTERPRETER_PATH')
            continue
        seen.add(path)
        before_probe = _file_digest(path)
        env['PATH'] = os.pathsep.join(dict.fromkeys([str(Path(path).parent), '/usr/bin', '/bin']))
        try:
            result = call([path, '-I', '-c', PYTHON_IDENTITY_SCRIPT], phase='runtime_probe', failure='RUNTIME_PROBE_FAILED')
            if _file_digest(path) != before_probe: raise InstallError('RUNTIME_CHANGED')
            value = json.loads(result.stdout)
            version = value.get('version') if type(value) is dict else None
            if not isinstance(version, list) or len(version) != 3 or any(type(part) is not int or part < 0 for part in version):
                raise InstallError('INTERPRETER_PROBE_INVALID')
            row.update(version='.'.join(map(str, version)), implementation='CPython' if value.get('implementation') == 'CPython' else 'other')
            expected_minor = None if candidate == 'python3' else int(candidate.rsplit('.', 1)[1])
            if expected_minor is not None and version[:2] != [3, expected_minor]:
                row.update(status='unsupported', reason_code='INTERPRETER_ALIAS_MISMATCH')
                continue
            if value.get('implementation') != 'CPython' or value.get('releaselevel') != 'final' or version[0] != 3 or version[1] not in MUTMUT_CPYTHON_MINORS:
                row.update(status='unsupported', reason_code='MUTMUT_INTERPRETER_UNSUPPORTED')
                continue
            row['status'] = 'selected'
            selection['selected'] = dict(candidate=candidate, path=path, version=row['version'], implementation='CPython')
            return path, selection
        except InstallError as error:
            row.update(status='probe_failed', reason_code=error.code)
            if error.code in ('INSTALL_TIMEOUT', 'RUNTIME_CHANGED'):
                raise
        except (ValueError, TypeError, KeyError):
            row.update(status='probe_failed', reason_code='INTERPRETER_PROBE_INVALID')
    raise InstallError('MUTMUT_INTERPRETER_UNSUPPORTED' if seen else 'RUNTIME_UNAVAILABLE', runtime_selection=selection)


def _npm_lock(path, spec):
    data = _load(path)
    if type(data) is not dict or data.get('lockfileVersion') not in (2, 3) or type(data.get('packages')) is not dict:
        raise InstallError('INVALID_NPM_LOCK')
    packages = data['packages']
    if type(packages.get('')) is not dict or packages[''].get('dependencies') != {spec['package']: spec['version']}:
        raise InstallError('PIN_MISMATCH')
    rows = []
    for location, item in sorted(packages.items()):
        if not location:
            continue
        if not location.startswith('node_modules/') or '..' in PurePosixPath(location).parts or type(item) is not dict or item.get('link'):
            raise InstallError('INVALID_NPM_LOCK')
        url = urlsplit(item.get('resolved', ''))
        if url.scheme != 'https' or url.hostname != 'registry.npmjs.org' or url.username or url.password or url.port or url.query or url.fragment:
            raise InstallError('UNTRUSTED_PACKAGE_SOURCE')
        integrity = item.get('integrity', '')
        match = re.fullmatch(r'(sha256|sha512)-([A-Za-z0-9+/]+={0,2})', integrity)
        if not match:
            raise InstallError('PACKAGE_HASH_MISSING')
        try:
            digest = base64.b64decode(match[2], validate=True)
        except ValueError:
            raise InstallError('PACKAGE_HASH_MISSING') from None
        if len(digest) != {'sha256': 32, 'sha512': 64}[match[1]]:
            raise InstallError('PACKAGE_HASH_MISSING')
        version = item.get('version')
        if type(version) is not str or not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', version):
            raise InstallError('INVALID_PACKAGE_VERSION')
        rows.append(dict(location=location, version=version, resolved=item['resolved'], integrity=integrity, optional=item.get('optional') is True))
    if not any(row['location'] == 'node_modules/' + spec['package'] and row['version'] == spec['version'] for row in rows):
        raise InstallError('PIN_MISMATCH')
    return rows


def _pin_key(system, machine, python_version=None):
    key = system.lower() + '-' + ('arm64' if machine in ('arm64', 'aarch64') else 'x86_64')
    if python_version: key += '/cp' + ''.join(python_version.split('.')[:2])
    return key


def _approved_pin(name, key):
    """Only checked-in inputs authorize packages; downloads never create trust."""
    if not isinstance(key, str) or not re.fullmatch(r'(darwin|linux)-(arm64|x86_64)(/cp[0-9]{2,3})?', key):
        raise InstallError('PIN_MISMATCH')
    path = PIN_ROOT / key / (name + '.json')
    try:
        raw = _read(path)
    except FileNotFoundError:
        raise InstallError('APPROVED_PIN_MISSING') from None
    pin = json.loads(raw)
    if (type(pin) is not dict or pin.get('schema_version') != 1 or pin.get('tool') != name or
            pin.get('version') != CATALOG[name]['version'] or pin.get('platform') != key):
        raise InstallError('PIN_MISMATCH')
    return pin, _sha(raw)


def _wheel_pins(pin):
    rows = pin.get('wheels')
    if not isinstance(rows, list) or not rows: raise InstallError('PACKAGE_HASH_MISSING')
    result = {}
    for row in rows:
        if (not isinstance(row, dict) or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', row.get('filename', '')) or
                not re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', '')) or
                not re.fullmatch(r'[a-z0-9][a-z0-9-]*', row.get('name', '')) or
                not re.fullmatch(r'[0-9][A-Za-z0-9.+-]*', row.get('version', '')) or row['filename'] in result):
            raise InstallError('PIN_MISMATCH')
        result[row['filename']] = row
    if len({r['name'] for r in result.values()}) != len(result): raise InstallError('PIN_MISMATCH')
    return result


def _requirements(pins):
    return ''.join(f"{row['name']}=={row['version']} --hash=sha256:{row['sha256']}\n" for row in sorted(pins.values(), key=lambda r: r['name'])).encode()


def _wheels(directory, spec, pins=None):
    pins = pins if pins is not None else {name: dict(sha256=digest) for name, digest in WHEEL_HASHES.items()}
    rows = []
    for path in sorted(directory.iterdir()):
        if path.suffix != '.whl':
            raise InstallError('SOURCE_BUILD_FORBIDDEN')
        raw = _read(path, limit=512 * 1024 * 1024)
        digest = _sha(raw)
        if path.name not in pins:
            raise InstallError('PACKAGE_HASH_MISSING')
        if digest != pins[path.name]['sha256']:
            raise InstallError('PACKAGE_HASH_MISMATCH')
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for item in archive.infolist():
                    if PurePosixPath(item.filename).is_absolute() or '..' in PurePosixPath(item.filename).parts or stat.S_ISLNK(item.external_attr >> 16):
                        raise InstallError('UNSAFE_WHEEL')
                metadata = [item for item in archive.infolist() if item.filename.endswith('.dist-info/METADATA')]
                if len(metadata) != 1 or metadata[0].file_size > MAX_OUTPUT:
                    raise InstallError('INVALID_WHEEL_METADATA')
                parsed = BytesParser().parsebytes(archive.read(metadata[0]))
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
            raise InstallError('INVALID_WHEEL') from None
        name, version = parsed.get('Name'), parsed.get('Version')
        if not name or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*', name) or not version or not re.fullmatch(r'\d+(?:\.\d+)*(?:[A-Za-z0-9.+-]*)', version):
            raise InstallError('INVALID_WHEEL_METADATA')
        if 'name' in pins[path.name] and (pins[path.name]['name'] != _normalized(name) or pins[path.name]['version'] != version):
            raise InstallError('PIN_MISMATCH')
        rows.append(dict(name=_normalized(name), version=version, filename=path.name, sha256=digest,
                         index_url_configured='https://pypi.org/simple', resolved_url=None,
                         hash_basis='repository_pin', independently_pinned_hash=True))
    if len({row['name'] for row in rows}) != len(rows) or not any(row['name'] == _normalized(spec['package']) and row['version'] == spec['version'] for row in rows):
        raise InstallError('PIN_MISMATCH')
    return rows


def _native_binary(directory, pin, system, machine):
    suffix = ('darwin-' if system == 'Darwin' else 'linux-') + ('arm64' if machine in ('arm64', 'aarch64') else 'x64') + ('-gnu' if system == 'Linux' else '')
    relative = 'node_modules/@ast-grep/cli-' + suffix + '/ast-grep'
    native = pin.get('native', {})
    if native.get('path') != relative or not re.fullmatch(r'[0-9a-f]{64}', native.get('sha256', '')):
        raise InstallError('PACKAGE_HASH_MISSING')
    binary = directory / relative
    if _file_digest(binary) != native['sha256']: raise InstallError('PACKAGE_HASH_MISMATCH')
    return str(binary)


def _file_digest(path):
    # Trusted installed executables may be bigger than a JSON metadata file.
    return _sha(_read(path, limit=512 * 1024 * 1024))


def _installed_files(directory, subtree, runtime_paths):
    """Record dependencies too. An unchanged launcher is not an intact install."""
    directory = _canonical(directory)
    tree = directory / subtree
    rows = []
    with _directory_fd(tree) as tree_fd:
        for current, directories, files, parent in os.fwalk('.', dir_fd=tree_fd, follow_symlinks=False):
            directories[:] = sorted(directories)
            for name in sorted([*directories, *files]):
                relative = str(Path(subtree) / current / name)
                path = directory / relative
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    link = os.readlink(name, dir_fd=parent)
                    try:
                        target = (path.parent / link).resolve(strict=True)
                    except (OSError, RuntimeError):
                        raise InstallError('INSTALLED_SYMLINK_ESCAPE') from None
                    interpreter = (subtree == 'venv' and Path(relative).parent == Path('venv/bin') and
                                   re.fullmatch(r'python(?:\d+(?:\.\d+)?)?', name) and str(target) in runtime_paths)
                    if not target.is_relative_to(tree) and not interpreter:
                        raise InstallError('INSTALLED_SYMLINK_ESCAPE')
                    rows.append(dict(path=relative, kind='symlink', target=link))
                elif stat.S_ISREG(info.st_mode):
                    rows.append(dict(path=relative, kind='file', sha256=_sha(_read_at(parent, name, 512 * 1024 * 1024)), mode=stat.S_IMODE(info.st_mode)))
                elif not stat.S_ISDIR(info.st_mode):
                    raise InstallError('INSTALLED_FILE_UNSAFE')
    return rows


def _relative(value):
    if type(value) is not str:
        raise InstallError('INVALID_MANIFEST')
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ('.', '..') for part in path.parts):
        raise InstallError('INVALID_MANIFEST')
    return path


def resolve_installed(name, *, tools_root=None):
    """Read receipts and file hashes only; never probe or install anything."""
    _names([name])
    root = _root(tools_root)
    try:
        _safe_path(root)
        info = root.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            return None
        active = _load(root / 'active.json')
        if type(active) is not dict or type(active.get('schema_version')) is not int or active['schema_version'] != 1 or type(active.get('tools')) is not dict:
            return None
        selected = active['tools'].get(name)
        if type(selected) is not dict or not re.fullmatch('[0-9a-f]{32}', selected.get('installation_id', '')):
            return None
        relative = f"{name}/{CATALOG[name]['version']}/{selected['installation_id']}"
        if selected.get('relative_path') != relative:
            return None
        directory = root / relative
        raw = _read(directory / 'receipt.json')
        receipt = json.loads(raw)
        if type(receipt) is not dict or type(receipt.get('schema_version')) is not int or receipt['schema_version'] != 1 or _sha(raw) != selected.get('receipt_sha256') or receipt.get('tool') != name or receipt.get('version') != CATALOG[name]['version'] or receipt.get('installation_id') != selected['installation_id']:
            return None
        if receipt.get('smoke', {}).get('status') != 'PASS' or receipt.get('proof_kind') not in ('subprocess', 'synthetic_test'):
            return None
        if receipt.get('trust_policy') != TRUST_POLICY: return None
        pin, pin_hash = _approved_pin(name, receipt['pin_key'])
        if pin_hash != receipt.get('pin_sha256'): return None
        if CATALOG[name]['channel'] == 'npm' and pin.get('lock_sha256') != receipt['lock_sha256']: return None
        if CATALOG[name]['channel'] == 'wheel' and _sha(_requirements(_wheel_pins(pin))) != receipt['lock_sha256']: return None
        if _file_digest(directory / _relative(receipt['lock_file'])) != receipt['lock_sha256']:
            return None
        runtime_paths = {item['path'] for item in receipt['runtimes']}
        argv = receipt['argv_prefix']
        if not argv or any(type(item) is not str for item in argv):
            return None
        allowed = {str(directory / item['path']) for item in receipt['files'] if item['kind'] == 'file'}
        for runtime in receipt['runtimes']:
            if receipt['proof_kind'] == 'subprocess': _runtime_trust(runtime['path'])
            if _file_digest(runtime['path']) != runtime['sha256'] or stat.S_IMODE(Path(runtime['path']).stat().st_mode) != runtime['mode']:
                return None
            allowed.add(runtime['path'])
        subtree = 'node_modules' if CATALOG[name]['channel'] == 'npm' else 'venv'
        if _installed_files(directory, subtree, runtime_paths) != receipt['files']:
            return None
        if any(item not in allowed for item in argv):
            return None
        return dict(tool=name, version=receipt['version'], argv_prefix=argv,
                    receipt=str(directory / 'receipt.json'), proof_kind=receipt['proof_kind'],
                    usable=receipt['proof_kind'] == 'subprocess', smoke_status='PASS', adapter_status='UNVERIFIED',
                    environment={'PYTHONDONTWRITEBYTECODE': '1'}, runtime_selection=receipt.get('runtime_selection'))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def plan(names=None, *, tools_root=None):
    rows = []
    for name in _names(names):
        installed = resolve_installed(name, tools_root=tools_root)
        rows.append(dict(name=name, **CATALOG[name], install_supported=True,
                         managed_install_status='VERIFIED' if installed and installed['usable'] else 'SYNTHETIC_ONLY' if installed else 'NOT_VERIFIED',
                         smoke_status=installed['smoke_status'] if installed else 'NOT_RUN',
                         adapter_status='UNVERIFIED', external_path_present=bool(shutil.which('ast-grep' if name == 'ast-grep' else name))))
    return dict(schema_version=1, kind='tools-install-plan', tools_root=str(_root(tools_root)), tools=rows,
                execution=dict(commands=0, network=False, target_reads=0, target_writes=0),
                excluded=[dict(name='stryker', reason_code='PINNED_RUNNER_REQUIRED')])


def _smoke(name, prefix, directory, call):
    root = directory / 'fixture'
    _mkdir(root)
    writes = []
    def put(path, text):
        target = root / path
        _mkdir(target.parent, parents=True, exist_ok=True)
        _write(target, text.encode())
        writes.append(dict(path=path, sha256=_sha(text.encode())))
    def parse(argv, *, allowed=(0, 1)):
        try:
            return json.loads(call(prefix + argv, root, allowed=allowed).stdout)
        except json.JSONDecodeError:
            raise InstallError('SMOKE_INVALID_JSON') from None
    if name == 'ast-grep':
        put('input.js', "console.log(123);\nconst text = 'console.log(456)';\n")
        source_hash = _file_digest(root / 'input.js')
        args = ['run', '--pattern', 'console.log($ARG)', '--lang', 'javascript', '--json=compact', 'input.js']
        positive = parse(args)
        if not isinstance(positive, list) or len(positive) != 1 or positive[0].get('range', {}).get('start', {}).get('line') != 0:
            raise InstallError('SMOKE_EXPECTED_FINDING_MISSING')
        _unlink(root / 'input.js')
        put('input.js', "const text = 'console.log(456)';\n")
        if parse(args) != []:
            raise InstallError('SMOKE_NEGATIVE_FAILED')
    elif name == 'knip':
        put('package.json', '{"name":"helix-smoke","private":true,"type":"module"}')
        put('knip.json', '{"entry":["index.js"],"project":["*.js"]}')
        put('tsconfig.json', '{"compilerOptions":{"allowJs":true}}')
        put('index.js', 'export const value = 1;\n')
        put('unused.js', 'export const unused = 2;\n')
        source_hash = _file_digest(root / 'unused.js')
        args = ['--config', str(root / 'knip.json'), '--tsConfig', str(root / 'tsconfig.json'), '--reporter', 'json', '--no-progress', '--no-gitignore']
        positive = parse(args)
        # Knip 6 removed the root `files` array. Each issue group owns its file
        # and consistently uses arrays, including group.files[].name.
        def observe(value, control):
            valid = type(value) is dict and set(value) == {'issues'} and type(value['issues']) is list
            groups = value['issues'] if valid else []
            valid = valid and all(type(row) is dict and type(row.get('file')) is str
                                  and type(row.get('files')) is list
                                  and all(type(item) is dict and type(item.get('name')) is str for item in row['files'])
                                  and all(type(items) is list for key, items in row.items() if key != 'file') for row in groups)
            files = [(row['file'], item['name']) for row in groups for item in row['files']] if valid else []
            return dict(tool='knip', schema='v6' if valid else 'invalid', control=control,
                        issue_groups=len(groups), unused_files=len(files),
                        expected_file_found=('unused.js', 'unused.js') in files)
        observation = observe(positive, 'positive')
        if observation['schema'] != 'v6' or observation['issue_groups'] != 1 or observation['unused_files'] != 1 or not observation['expected_file_found']:
            raise InstallError('SMOKE_EXPECTED_FINDING_MISSING', smoke_observation=observation)
        _unlink(root / 'unused.js')
        negative = parse(args)
        observation = observe(negative, 'negative')
        if observation['schema'] != 'v6' or observation['issue_groups'] != 0:
            raise InstallError('SMOKE_NEGATIVE_FAILED', smoke_observation=observation)
    elif name == 'jscpd':
        source = '\n'.join(f'console.log("helix{i}", {i} + {i+1});' for i in range(12)) + '\n'
        put('a.js', source)
        put('b.js', source)
        put('config.json', json.dumps(dict(minLines=3, minTokens=20, reporters=['json'], semantic=False, silent=True, failOnEmpty=True)))
        source_hash = _sha(source.encode())
        def clone_result(label):
            output = directory / label
            _mkdir(output)
            call(prefix + ['--config', str(root / 'config.json'), '--output', str(output), '.'], root, allowed=(0,))
            result = _load(output / 'jscpd-report.json')
            if type(result.get('statistics', {}).get('total', {}).get('sources')) is not int or result['statistics']['total']['sources'] < 1 or not isinstance(result.get('duplicates'), list):
                raise InstallError('SMOKE_EMPTY_COVERAGE')
            return result['duplicates']
        positive = clone_result('positive')
        if not any({Path(row.get('firstFile', {}).get('name', '')).name, Path(row.get('secondFile', {}).get('name', '')).name} == {'a.js', 'b.js'} and row.get('firstFile', {}).get('startLoc', {}).get('line') == 1 and row.get('secondFile', {}).get('startLoc', {}).get('line') == 1 for row in positive):
            raise InstallError('SMOKE_EXPECTED_FINDING_MISSING')
        _unlink(root / 'b.js')
        if clone_result('negative'):
            raise InstallError('SMOKE_NEGATIVE_FAILED')
    elif name == 'squawk':
        put('config.toml', '')
        put('migration.sql', 'CREATE TABLE IF NOT EXISTS public.helix_smoke (id bigint PRIMARY KEY, name varchar(255));\n')
        source_hash = _file_digest(root / 'migration.sql')
        args = ['--reporter', 'json', '--config', str(root / 'config.toml'), 'migration.sql']
        positive = parse(args)
        if not isinstance(positive, list) or not any(row.get('rule_name') == 'prefer-text-field' and row.get('line') == 0 for row in positive):
            raise InstallError('SMOKE_EXPECTED_FINDING_MISSING')
        _unlink(root / 'migration.sql')
        put('migration.sql', 'CREATE TABLE IF NOT EXISTS public.helix_smoke (id bigint PRIMARY KEY, name text);\n')
        negative = parse(args)
        if negative != []:
            observation = dict(diagnostics_count=len(negative), rule_names=[row.get('rule_name') for row in negative if type(row) is dict]) if isinstance(negative, list) else None
            raise InstallError('SMOKE_NEGATIVE_FAILED', smoke_observation=observation)
    else:
        # This is Helix-owned code, never a caller's project, copied from no repo.
        put('src/helix_smoke/__init__.py', '')
        put('src/helix_smoke/example.py', 'def increment(value):\n    return value + 1\n')
        put('tests/test_example.py', 'from helix_smoke.example import increment\n\ndef test_increment():\n    assert increment(1) == 2\n    assert increment(-1) == 0\n')
        put('pyproject.toml', '[tool.mutmut]\nsource_paths = ["src/"]\npytest_add_cli_args_test_selection = ["tests/"]\nuse_git_change_detection = false\n')
        source_hash = _file_digest(root / 'src/helix_smoke/example.py')
        # Importing mutmut's CLI loads configuration before Click handles flags.
        # Probe usability only after its own complete fixture exists.
        help_text = call(prefix + ['--help'], root, allowed=(0,)).stdout
        help_ok = isinstance(help_text, str) and all(re.search(r'^\s+' + re.escape(command) + r'(?:\s|$)', help_text, re.M) for command in ('run', 'export-cicd-stats'))
        if not help_ok:
            raise InstallError('SMOKE_EXPECTED_FINDING_MISSING', smoke_observation=dict(tool='mutmut', stage='help', stats=None))
        call(prefix + ['run', '--max-children', '1'], root, allowed=(0,))
        call(prefix + ['export-cicd-stats'], root, allowed=(0,))
        try:
            result = _load(root / 'mutants/mutmut-cicd-stats.json')
        except FileNotFoundError:
            result = None
        except InstallError as error:
            if error.code != 'INVALID_MANIFEST':
                raise
            result = None
        keys = ('killed', 'survived', 'no_tests', 'skipped', 'suspicious', 'timeout', 'check_was_interrupted_by_user', 'segfault')
        valid = type(result) is dict and set(result) == {'total', *keys} and all(type(result.get(key)) is int and result[key] >= 0 for key in ('total', *keys))
        if not valid or result['total'] < 1 or result['killed'] != result['total'] or any(result[key] for key in keys[1:]):
            raise InstallError('SMOKE_MUTATION_INCOMPLETE', smoke_observation=dict(tool='mutmut', stage='mutation_stats', stats=result if valid else None))
    revision = '2' if name in ('knip', 'squawk', 'mutmut') else '1'
    return dict(id=name + '-synthetic-v' + revision, sha256=_sha(_json(writes)), status='PASS', scope='helix_owned_fixture', target_execution=False)


def _install_one(name, root, executor, synthetic):
    spec = CATALOG[name]
    system, machine = platform.system(), platform.machine()
    if system not in ('Darwin', 'Linux') or machine not in ('arm64', 'aarch64', 'x86_64'):
        raise InstallError('UNSUPPORTED_PLATFORM')
    if system == 'Linux' and spec['channel'] == 'npm' and name == 'ast-grep' and platform.libc_ver()[0] != 'glibc':
        raise InstallError('UNSUPPORTED_PLATFORM')
    installation_id = uuid.uuid4().hex
    directory = _safe_path(root / name / spec['version'] / installation_id)
    _mkdir(directory, parents=True)
    state = dict(last={}, runtime_selection=None)
    try:
        return _populate_one(name, root, executor, synthetic, directory, installation_id, system, machine, state)
    except BaseException as error:
        if isinstance(error, InstallError):
            if error.diagnostic is None:
                error.diagnostic = _diagnostic(error.code, state['last'], home=Path.home(), install_dir=directory, smoke_observation=error.smoke_observation)
            if error.runtime_selection is None:
                error.runtime_selection = state['runtime_selection']
        # Never remove a completed activation, even if interrupted just after
        # atomic publication and before returning to the caller.
        try:
            active = _load(root / 'active.json') if (root / 'active.json').exists() else {}
            published = active.get('tools', {}).get(name, {}).get('installation_id') == installation_id
        except (OSError, ValueError, TypeError, AttributeError):
            published = True  # Cannot safely prove that the directory is unused.
        if not published:
            try:
                if directory.is_symlink():
                    _unlink(directory)
                else:
                    with _directory_fd(directory.parent) as parent:
                        shutil.rmtree(directory.name, dir_fd=parent)
            except OSError:
                pass
        raise


def _populate_one(name, root, executor, synthetic, directory, installation_id, system, machine, state):
    spec = CATALOG[name]
    home = directory / 'home'
    _mkdir(home / 'tmp', parents=True)
    _write(home / 'npm-user.config', b'')
    _write(home / 'npm-global.config', b'')
    runtimes = []
    required = ('node', 'npm') if spec['channel'] == 'npm' else ('python3',)
    paths = {}
    env = _environment(home, [])
    started = time.monotonic()
    def call(argv, cwd=directory, *, allowed=(0,), failure='COMMAND_FAILED', phase='package_install'):
        state['last'] = dict(phase=phase, argv=argv)
        remaining = 900 - (time.monotonic() - started)
        if remaining <= 0:
            raise InstallError('INSTALL_TIMEOUT')
        try:
            result = executor.run(argv, cwd=cwd, env=env.copy(), timeout=min(remaining, 180))
        except subprocess.TimeoutExpired:
            raise InstallError('INSTALL_TIMEOUT') from None
        except OSError:
            raise InstallError('COMMAND_START_FAILED') from None
        state['last'].update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode not in allowed:
            raise InstallError(failure)
        return result
    if name == 'mutmut':
        paths['python3'], _ = _select_mutmut_python(executor, call, env, state)
    else:
        for runtime in required:
            path = (executor.locate('python3.12') or executor.locate(runtime)) if runtime == 'python3' else executor.locate(runtime)
            if not path or not Path(path).is_absolute():
                raise InstallError('RUNTIME_UNAVAILABLE')
            paths[runtime] = str(Path(path).resolve())
    env.update(_environment(home, [Path(value).parent for value in paths.values()]))
    for runtime, path in paths.items():
        runtime_hash = _file_digest(path)
        if name == 'mutmut' and runtime == 'python3':
            version = state['runtime_selection']['selected']['version']
        else:
            argv = [paths['node'], path, '--version'] if runtime == 'npm' else [path, '--version']
            version = _version(call(argv, failure='RUNTIME_PROBE_FAILED', phase='runtime_probe').stdout)
        if _file_digest(path) != runtime_hash: raise InstallError('RUNTIME_CHANGED')
        observations = [] if synthetic else _runtime_trust(path)[1]
        runtimes.append(dict(name=runtime, path=path, version=version, sha256=runtime_hash, mode=stat.S_IMODE(Path(path).stat().st_mode),
                             group_writable_trusted=observations))
    versions = {row['name']: tuple(map(int, row['version'].split('.'))) for row in runtimes}
    if 'node' in versions and (versions['node'] < (12, 0, 0) or name == 'knip' and not ((20, 19, 0) <= versions['node'] < (21, 0, 0) or versions['node'] >= (22, 12, 0))):
        raise InstallError('RUNTIME_VERSION_UNSUPPORTED')
    if 'python3' in versions and versions['python3'] < ((3, 10, 0) if name == 'mutmut' else (3, 8, 0)):
        raise InstallError('RUNTIME_VERSION_UNSUPPORTED')
    pin_key = _pin_key(system, machine, next((r['version'] for r in runtimes if r['name'] == 'python3'), None))
    pin, pin_hash = _approved_pin(name, pin_key)
    if spec['channel'] == 'npm':
        _write(directory / 'package.json', _json(dict(name='helix-owned-' + name, private=True, dependencies={spec['package']: spec['version']})))
        shared = ['--ignore-scripts', '--include=optional', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/']
        lock_raw = _read(PIN_ROOT / pin_key / (name + '.package-lock.json'))
        if _sha(lock_raw) != pin.get('lock_sha256'): raise InstallError('PIN_MISMATCH')
        _write(directory / 'package-lock.json', lock_raw)
        dependencies = _npm_lock(directory / 'package-lock.json', spec)
        lock_file = 'package-lock.json'
        lock_hash = _file_digest(directory / lock_file)
        # Independently compare every tarball, including optional/transitive
        # packages, with the approved SRI before an offline npm extraction.
        tarballs = directory / 'tarballs'
        _mkdir(tarballs)
        for index, row in enumerate(dependencies):
            raw = executor.fetch(row['resolved'])
            algorithm, digest = row['integrity'].split('-', 1)
            if hashlib.new(algorithm, raw).digest() != base64.b64decode(digest, validate=True):
                raise InstallError('PACKAGE_HASH_MISMATCH')
            archive = tarballs / (str(index) + '.tgz')
            _write(archive, raw)
            call([paths['node'], paths['npm'], 'cache', 'add', str(archive), *shared], failure='PACKAGE_INSTALL_FAILED')
        call([paths['node'], paths['npm'], 'ci', '--offline', *shared], failure='PACKAGE_INSTALL_FAILED')
        if _file_digest(directory / lock_file) != lock_hash:
            raise InstallError('LOCK_CHANGED')
        files = _installed_files(directory, 'node_modules', set(paths.values()))
        for row in dependencies:
            package = directory / row['location']
            if package.exists():
                manifest = _load(package / 'package.json')
                if manifest.get('version') != row['version']:
                    raise InstallError('INSTALLED_PACKAGE_MISMATCH')
            elif not row['optional']:
                raise InstallError('INSTALLED_PACKAGE_MISSING')
            row['installed'] = package.exists()
        package = directory / 'node_modules' / spec['package']
        if name == 'ast-grep':
            prefix = [_native_binary(directory, pin, system, machine)]
        else:
            prefix = [paths['node'], str(package / 'bin/knip.js')]
    else:
        venv = directory / 'venv'
        call([paths['python3'], '-I', '-m', 'venv', str(venv)], failure='VENV_CREATION_FAILED', phase='environment_creation')
        python = str(venv / 'bin/python')
        # venv Python is the one documented intentional runtime symlink.
        if Path(python).resolve() != Path(paths['python3']).resolve():
            if Path(python).is_symlink() or _file_digest(python) != _file_digest(paths['python3']):
                raise InstallError('VENV_RUNTIME_MISMATCH')
        wheels = directory / 'wheels'
        _mkdir(wheels)
        pip = [python, '-I', '-B', '-m', 'pip', '--isolated', '--disable-pip-version-check']
        pip_version = _version(call(pip + ['--version'], phase='version_probe').stdout)
        lock_file = 'requirements.lock'
        wheel_pins = _wheel_pins(pin)
        _write(directory / lock_file, _requirements(wheel_pins))
        lock_hash = _file_digest(directory / lock_file)
        call(pip + ['download', '--require-hashes', '--only-binary=:all:', '--no-deps', '--no-cache-dir', '--index-url', 'https://pypi.org/simple', '--dest', str(wheels), '-r', str(directory / lock_file)], failure='WHEEL_RESOLUTION_FAILED', phase='dependency_resolution')
        dependencies = _wheels(wheels, spec, wheel_pins)
        if {row['filename'] for row in dependencies} != set(wheel_pins): raise InstallError('DEPENDENCIES_INCOMPLETE')
        call(pip + ['install', '--no-index', '--no-deps', '--no-compile', '--require-hashes', '--only-binary=:all:', '--find-links', str(wheels), '-r', str(directory / lock_file)], failure='PACKAGE_INSTALL_FAILED')
        files = _installed_files(directory, 'venv', set(paths.values()))
        call(pip + ['check'], failure='DEPENDENCIES_INCOMPLETE')
        prefix = [str(venv / 'bin' / name)]
    # No package resolving during version/smoke. These env hints are not an OS
    # network sandbox; fixtures contain only Helix code, never customer inputs.
    env.update(npm_config_offline='true', PIP_NO_INDEX='1', UV_OFFLINE='1')
    subtree = 'node_modules' if spec['channel'] == 'npm' else 'venv'
    if name == 'mutmut':
        version_output = call([python, '-I', '-B', '-c', "from importlib.metadata import version; print(version('mutmut'))"], phase='version_probe').stdout
        actual = _version(version_output)
        if version_output.strip() != actual:
            raise InstallError('VERSION_UNVERIFIED')
        version_probe = dict(method='distribution_metadata', distribution='mutmut', version=actual)
    else:
        actual = _version(call(prefix + ['--version'], phase='version_probe').stdout)
        version_probe = dict(method='cli_version', version=actual)
    if actual != spec['version']:
        raise InstallError('VERSION_MISMATCH')
    smoke = _smoke(name, prefix, directory, lambda *args, **kwargs: call(*args, phase='smoke', **kwargs))
    if _file_digest(directory / lock_file) != lock_hash:
        raise InstallError('LOCK_CHANGED')
    if _installed_files(directory, subtree, set(paths.values())) != files: raise InstallError('INSTALLED_TREE_CHANGED')
    if _approved_pin(name, pin_key)[1] != pin_hash: raise InstallError('PIN_MISMATCH')
    if name == 'ast-grep': _native_binary(directory, pin, system, machine)
    if spec['channel'] == 'wheel': _wheels(wheels, spec, wheel_pins)
    for runtime in runtimes:
        if _file_digest(runtime['path']) != runtime['sha256'] or stat.S_IMODE(Path(runtime['path']).stat().st_mode) != runtime['mode']:
            raise InstallError('RUNTIME_CHANGED')
    receipt = dict(schema_version=1, tool=name, version=spec['version'], installation_id=installation_id,
                   trust_policy=TRUST_POLICY, pin_key=pin_key, pin_sha256=pin_hash,
                   platform=dict(system=system, machine=machine), license=spec['license'], pin_source=PIN_SOURCES[name], transitive_license_audit='NOT_RUN',
                   dependencies=dependencies, lock_file=lock_file, lock_sha256=lock_hash, runtimes=runtimes,
                   installer_version=next(row['version'] for row in runtimes if row['name'] == 'npm') if spec['channel'] == 'npm' else pip_version,
                   argv_prefix=prefix, files=files, smoke=smoke, adapter_status='UNVERIFIED',
                   runtime_selection=state['runtime_selection'],
                   version_probe=version_probe,
                   proof_kind='synthetic_test' if synthetic else 'subprocess',
                   installed_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), duration_s=round(time.monotonic() - started, 3))
    _write(directory / 'receipt.json', _json(receipt))
    active_path = root / 'active.json'
    active = _load(active_path) if active_path.exists() else dict(schema_version=1, tools={})
    if type(active) is not dict or type(active.get('schema_version')) is not int or active['schema_version'] != 1 or not isinstance(active.get('tools'), dict):
        raise InstallError('INVALID_ACTIVE_MANIFEST')
    active['tools'][name] = dict(installation_id=installation_id, relative_path=str(directory.relative_to(root)), receipt_sha256=_sha(_json(receipt)))
    _atomic(active_path, active)
    return dict(tool=name, status='INSTALLED_SYNTHETIC' if synthetic else 'INSTALLED', version=actual,
                receipt=str(directory / 'receipt.json'), smoke_status='PASS', adapter_status='UNVERIFIED', runtime_selection=state['runtime_selection'])


def install(names=None, *, yes=False, tools_root=None, offline=False, executor=None):
    names = _names(names)
    if yes is not True:
        return dict(status='BLOCKED', reason_code='EXPLICIT_YES_REQUIRED', tools=[])
    if tools_root is not None and executor is None:
        raise InstallError('ROOT_OVERRIDE_TEST_ONLY')
    root = _root(tools_root)
    existing = {name: resolve_installed(name, tools_root=root) for name in names}
    if offline:
        valid = all(value and value['proof_kind'] == ('synthetic_test' if executor is not None else 'subprocess') for value in existing.values())
        return dict(status='REUSED' if valid else 'BLOCKED',
                    reason_code='EXISTING_INSTALLATION' if valid else 'OFFLINE_PACKAGES_MISSING', tools=list(existing.values()))
    rows = []
    try:
        with _lock(root):
            for name in names:
                current = resolve_installed(name, tools_root=root)
                if current and current['proof_kind'] == ('synthetic_test' if executor is not None else 'subprocess'):
                    rows.append(dict(tool=name, status='REUSED', **{k: v for k, v in current.items() if k != 'tool'}))
                    continue
                try:
                    rows.append(_install_one(name, root, executor or Executor(), executor is not None))
                except InstallError as error:
                    rows.append(dict(tool=name, status='FAILED', reason_code=error.code,
                                     diagnostic=error.diagnostic or _diagnostic(error.code), runtime_selection=error.runtime_selection))
                except subprocess.TimeoutExpired:
                    rows.append(dict(tool=name, status='FAILED', reason_code='INSTALL_TIMEOUT', diagnostic=_diagnostic('INSTALL_TIMEOUT')))
                except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError):
                    rows.append(dict(tool=name, status='FAILED', reason_code='INSTALL_FAILED', diagnostic=_diagnostic('INSTALL_FAILED')))
    except InstallError as error:
        return dict(status='BLOCKED', reason_code=error.code, diagnostic=error.diagnostic or _diagnostic(error.code), tools=rows)
    except OSError:
        return dict(status='BLOCKED', reason_code='UNSAFE_ROOT', diagnostic=_diagnostic('UNSAFE_ROOT'), tools=rows)
    return dict(status='INCOMPLETE' if any(row['status'] == 'FAILED' for row in rows) else 'COMPLETE', tools=rows,
                proof_kind='synthetic_test' if executor is not None else 'subprocess', target_writes=0)
