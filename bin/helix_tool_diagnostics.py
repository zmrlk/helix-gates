"""Pure, bounded installer diagnostics. Unknown output is never echoed."""
import json
from pathlib import PurePath, PurePosixPath
import re
import unicodedata

from helix_data_egress import redact_text

MAX_LINES = 20
MAX_BYTES = 4096
INPUT_BYTES = 65536
PHASES = frozenset(('runtime_discovery', 'runtime_probe', 'dependency_resolution',
    'environment_creation', 'package_install', 'postinstall', 'version_probe',
    'smoke', 'manifest_validation'))
CODES = frozenset('''COMMAND_FAILED RUNTIME_PROBE_FAILED DEPENDENCY_RESOLUTION_FAILED
VENV_CREATION_FAILED WHEEL_RESOLUTION_FAILED PACKAGE_INSTALL_FAILED DEPENDENCIES_INCOMPLETE
INSTALLED_FILE_UNSAFE INSTALLED_PACKAGE_MISMATCH INSTALLED_PACKAGE_MISSING
INSTALLED_SYMLINK_ESCAPE INSTALL_BUSY INSTALL_TIMEOUT INVALID_ACTIVE_MANIFEST
INVALID_MANIFEST INVALID_NPM_LOCK INVALID_PACKAGE_VERSION INVALID_WHEEL
INVALID_WHEEL_METADATA LOCK_CHANGED NATIVE_PACKAGE_UNAVAILABLE OUTPUT_TOO_LARGE
PACKAGE_HASH_MISMATCH PACKAGE_HASH_MISSING PIN_MISMATCH POSTINSTALL_UNVERIFIED
ROOT_OVERRIDE_TEST_ONLY RUNTIME_UNAVAILABLE RUNTIME_VERSION_UNSUPPORTED
SMOKE_EMPTY_COVERAGE SMOKE_EXPECTED_FINDING_MISSING SMOKE_INVALID_JSON
SMOKE_MUTATION_INCOMPLETE SMOKE_NEGATIVE_FAILED SOURCE_BUILD_FORBIDDEN
UNSAFE_FILE UNSAFE_LOCK UNSAFE_PATH UNSAFE_ROOT UNSAFE_WHEEL UNSUPPORTED_PLATFORM
UNSUPPORTED_TOOL UNTRUSTED_PACKAGE_SOURCE VENV_RUNTIME_MISMATCH VERSION_MISMATCH
VERSION_UNVERIFIED'''.split())
CODES = CODES | {'MUTMUT_INTERPRETER_UNSUPPORTED', 'INTERPRETER_ALIAS_MISMATCH', 'INTERPRETER_PROBE_INVALID', 'COMMAND_START_FAILED', 'INSTALL_FAILED',
                 'APPROVED_PIN_MISSING', 'UNTRUSTED_RUNTIME', 'RUNTIME_CHANGED', 'INSTALLED_TREE_CHANGED'}
_SQUAWK_RULES = frozenset(('prefer-text-field', 'require-primary-key', 'prefer-robust-stmts', 'require-table-schema'))
_WORDS = frozenset('''node nodejs npm python python3 pip pip3 venv ast-grep knip
jscpd squawk mutmut install download ci check run export-cicd-stats json
javascript typescript .'''.split())
_FLAGS = frozenset('''-I -m -r --version --isolated --disable-pip-version-check
--ignore-scripts --include=optional --no-audit --no-fund --package-lock-only
--no-cache-dir --only-binary=:all: --no-index --no-deps --no-compile --require-hashes
--find-links --dest --index-url --registry --config --tsConfig --reporter
--no-progress --no-gitignore --output --pattern --lang --json=compact --help --max-children'''.split())
_KNOWN_FILES = frozenset(('knip.js', 'postinstall.js', 'input.js', 'migration.sql',
    'knip.json', 'config.json', 'config.toml', 'tsconfig.json', 'requirements.lock'))
_SECRET_WORD = re.compile(r'secret|password|passwd|credential|authorization|token|api.?key', re.I)
_ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])')
_URL = re.compile(r'\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>"\']+')
_PACKAGE = re.compile(r'(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9][a-zA-Z0-9_.-]*(?:(?:==|>=|<=|~=|@|>|<)[0-9][0-9A-Za-z.*+!<>=~,-]*)?\Z')
_HINTS = {
    'NPM_CONFIG_COLLISION': 'npm otrzymał ten sam plik konfiguracji użytkownika i globalnej; użyj dwóch oddzielnych prywatnych plików.',
    'NO_DISTRIBUTION': 'Brak zgodnego pakietu lub koła dla przypiętej wersji Pythona/platformy; bez przejścia na build ze źródeł.',
    'EXECUTABLE_NOT_FOUND': 'Sprawdź dostępność wymaganego runtime w neutralnym PATH instalatora.',
    'DEPENDENCY_CONFLICT': 'Resolver zgłosił konflikt zależności; nie zmieniaj pinów automatycznie.',
    'ENGINE_UNSUPPORTED': 'Porównaj wersję Node/Pythona z wymaganiami przypiętego pakietu.',
    'PERMISSION_DENIED': 'Sprawdź własność i uprawnienia prywatnego katalogu instalacji.',
    'NETWORK_ERROR': 'Sprawdź dostęp do jawnego rejestru; błąd nie oznacza udanej instalacji.',
    'TLS_ERROR': 'Sprawdź certyfikaty środowiska; nie wyłączaj weryfikacji TLS.',
    'INTEGRITY_ERROR': 'Hash artefaktu jest niezgodny; zachowaj odmowę aktywacji.',
    'MODULE_MISSING': 'Wymagany moduł nie jest dostępny w wybranym prywatnym środowisku.',
    'TOOL_EXCEPTION': 'Narzędzie zgłosiło wyjątek; jego nieopisane dane zostały pominięte.',
    'SMOKE_RULE_OBSERVED': 'Własny smoke otrzymał wskazaną regułę; sprawdź oczekiwany wynik fixture bez pomijania alarmu.',
}


def _clean(value):
    value = _ANSI.sub('', value)
    return ''.join(c for c in value if c in '\n\t' or unicodedata.category(c) not in ('Cc', 'Cf', 'Cs'))


def _string(value):
    return str(value) if isinstance(value, PurePath) else value if isinstance(value, str) else ''


def _public(value):
    """Final shared PII/credential check, without publishing matched substrings."""
    return redact_text(value)[0] if len(value) <= 500 else '[redacted]'


def _package(value):
    value = value.strip().strip('"\'')
    if len(value) > 100 or not _PACKAGE.fullmatch(value) or _SECRET_WORD.search(value):
        return '<package>'
    # A closed npm name plus numeric pin is not an email address.
    if re.fullmatch(r'(?:knip|@ast-grep/cli)@\d+(?:\.\d+){2}', value):
        return value
    return _public(value)


def _path(value, home, install_dir):
    value = _clean(value)
    if len(value) > 1000 or _SECRET_WORD.search(value) or '://' in value:
        return '<path>'
    for prefix, label in ((install_dir, '<install>'), (home, '~')):
        prefix = _string(prefix).rstrip('/')
        if prefix and (value == prefix or value.startswith(prefix + '/')):
            suffix = value[len(prefix):]
            if '..' in suffix.split('/'):
                return '<path>'
            return _public(label + suffix)
    name = PurePosixPath(value).name
    if name in _WORDS or name in _KNOWN_FILES:
        return name
    return '<path>'


def _command(argv, home, install_dir):
    if not isinstance(argv, (list, tuple)):
        return []
    result = []
    for index, raw in enumerate(argv[:32]):
        value = _string(raw)
        if len(value) > 1000:
            result.append('<redacted>')
            continue
        value = _clean(value)
        if value in _WORDS or value in _FLAGS or value in _KNOWN_FILES:
            token = value
        elif value.startswith(('--registry=', '--index-url=')):
            token = value.split('=', 1)[0] + '=<url>'
        elif '://' in value:
            token = '<url>'
        elif value.startswith('/'):
            token = _path(value, home, install_dir)
        elif value.startswith(('@ast-grep/cli@', 'knip@', 'jscpd==', 'squawk-cli==', 'mutmut==')):
            token = _package(value)
        else:
            token = '<redacted>'
        result.append(token if len(token.encode('utf-8')) <= 240 else '<path>')
    return result


def _line(raw, home, install_dir):
    """Reconstruct recognized diagnostics; never pass through a labeled raw line."""
    line = _URL.sub('<url>', _clean(raw)).strip()
    if re.search(r'double-loading config .* as ["\']global["\'], previously loaded as ["\']user["\']', line):
        return 'NPM_CONFIG_COLLISION', 'npm: double-loading config as global, previously loaded as user'
    if line == 'Exit prior to config file resolving':
        return 'NPM_CONFIG_COLLISION', line
    match = re.search(r'No matching distribution found for\s+([^\s()]+)', line, re.I)
    if match:
        return 'NO_DISTRIBUTION', 'No matching distribution found for ' + _package(match[1])
    match = re.search(r'Could not find a version that satisfies the requirement\s+([^\s()]+)', line, re.I)
    if match:
        return 'NO_DISTRIBUTION', 'Could not find a version that satisfies the requirement ' + _package(match[1])
    match = re.search(r'(?:env:\s*|spawn\s+|command not found:\s*)([\w.-]+).*?(?:No such file or directory|not found|ENOENT)', line, re.I)
    if match:
        program = match[1] if match[1] in _WORDS else '<program>'
        return 'EXECUTABLE_NOT_FOUND', 'env: ' + program + ': No such file or directory'
    if re.search(r'conflicting dependencies|ResolutionImpossible|ERESOLVE', line):
        return 'DEPENDENCY_CONFLICT', 'Dependency resolution failed: conflicting requirements'
    if re.search(r'EBADENGINE|Unsupported engine|requires a different Python', line, re.I):
        return 'ENGINE_UNSUPPORTED', 'Unsupported runtime version required by package'
    if re.search(r'EINTEGRITY|HASHES.*DO NOT MATCH|hash mismatch', line, re.I):
        return 'INTEGRITY_ERROR', 'Downloaded package integrity check failed'
    if re.search(r'CERTIFICATE_VERIFY_FAILED|certificate verify failed|UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT|CERT_HAS_EXPIRED', line, re.I):
        return 'TLS_ERROR', 'TLS certificate verification failed'
    if re.search(r'\b(?:ETIMEDOUT|ECONNRESET|ECONNREFUSED|ENOTFOUND|EAI_AGAIN)\b|ReadTimeoutError|ConnectionError', line):
        return 'NETWORK_ERROR', 'Registry connection failed or timed out'
    if re.search(r'\b(?:EACCES|EPERM|PermissionError)\b|Permission denied', line):
        return 'PERMISSION_DENIED', 'Permission denied while running the installer'
    if re.search(r'\bENOENT\b', line):
        return 'EXECUTABLE_NOT_FOUND', 'ENOENT: required program or file was not found'
    match = re.search(r"(?:No module named|Cannot find module)\s+['\"]([^'\"]+)['\"]", line)
    if match:
        value = _path(match[1], home, install_dir) if '/' in match[1] else _package(match[1])
        return 'MODULE_MISSING', 'Required module not found: ' + value
    match = re.fullmatch(r'File "([^"\n]+)", line ([0-9]{1,7})(?:, in .*?)?', line)
    if match:
        return 'TOOL_EXCEPTION', 'File "' + _path(match[1], home, install_dir) + '", line ' + match[2]
    match = re.match(r'(TypeError|ValueError|RuntimeError|SyntaxError|ImportError|ModuleNotFoundError|FileNotFoundError|OSError):', line)
    if match:
        return 'TOOL_EXCEPTION', match[1] + ': details omitted'
    if line == 'Traceback (most recent call last):':
        return 'TOOL_EXCEPTION', line
    return None


def _structured_rules(text):
    """Only known Squawk rule names, never its SQL/message/location payload."""
    try:
        rows = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(rows, list):
        return []
    return sorted({row['rule_name'] for row in rows if isinstance(row, dict)
                   and isinstance(row.get('rule_name'), str) and row['rule_name'] in _SQUAWK_RULES})


def _smoke_hint(observation):
    if isinstance(observation, dict) and observation.get('tool') == 'knip':
        if set(observation) != {'tool', 'schema', 'control', 'issue_groups', 'unused_files', 'expected_file_found'}:
            return None
        if observation['schema'] not in ('v6', 'invalid') or observation['control'] not in ('positive', 'negative') or type(observation['expected_file_found']) is not bool:
            return None
        if any(type(observation[key]) is not int or not 0 <= observation[key] <= 100000 for key in ('issue_groups', 'unused_files')):
            return None
        return ('Smoke Knip: format ' + observation['schema'] + '; kontrola ' + observation['control']
                + '; grupy ' + str(observation['issue_groups']) + '; nieużywane pliki ' + str(observation['unused_files'])
                + '; oczekiwany plik ' + ('obecny.' if observation['expected_file_found'] else 'nieobecny.'))
    if isinstance(observation, dict) and observation.get('tool') == 'mutmut':
        if set(observation) != {'tool', 'stage', 'stats'} or observation['stage'] not in ('help', 'mutation_stats'):
            return None
        stats = observation['stats']
        keys = ('total', 'killed', 'survived', 'no_tests', 'skipped', 'suspicious', 'timeout', 'check_was_interrupted_by_user', 'segfault')
        if stats is None:
            return 'Smoke mutmut: ' + observation['stage'] + '; brak poprawnego wyniku wymaganego etapu.'
        if type(stats) is not dict or set(stats) != set(keys) or any(type(stats[key]) is not int or not 0 <= stats[key] <= 100000 for key in keys):
            return None
        return 'Smoke mutmut: ' + '; '.join(key + '=' + str(stats[key]) for key in keys) + '.'
    if not isinstance(observation, dict) or set(observation) != {'diagnostics_count', 'rule_names'}:
        return None
    count, names = observation['diagnostics_count'], observation['rule_names']
    if type(count) is not int or count < 1 or not isinstance(names, list):
        return None
    known = sorted({name for name in names[:100] if isinstance(name, str) and name in _SQUAWK_RULES})
    if len(names) > 100 or any(not isinstance(name, str) or name not in _SQUAWK_RULES for name in names[:100]):
        known.append('UNRECOGNIZED_RULE')
    amount = str(count) if count <= 100000 else 'ponad 100000'
    return 'Negatywny smoke Squawk: liczba diagnostyk ' + amount + '; reguły: ' + (', '.join(known) or 'UNRECOGNIZED_RULE') + '.'


def build_diagnostic(*, phase, code, argv=(), returncode=None, stdout='', stderr='', home=None, install_dir=None, smoke_observation=None):
    """Return at most twenty reconstructed tail lines and 4096 UTF-8 JSON bytes.

    No filesystem, environment, process or clock access. Diagnostic metadata is
    not a successful installation receipt. Redaction remains heuristic.
    """
    tail, reasons, total, truncated = [], set(), 0, False
    for stream, value in (('stdout', stdout), ('stderr', stderr)):
        if not isinstance(value, (str, bytes)):
            continue
        lf, cr, crlf = (b'\n', b'\r', b'\r\n') if isinstance(value, bytes) else ('\n', '\r', '\r\n')
        total += value.count(lf) + value.count(cr) - value.count(crlf) + bool(value and not value.endswith((lf, cr)))
        sample = value[-INPUT_BYTES:]
        if isinstance(sample, str):
            sample = sample.encode('utf-8', 'replace')
        cut = len(value) > INPUT_BYTES or len(sample) > INPUT_BYTES
        sample = sample[-INPUT_BYTES:]
        if cut:
            sample = sample.split(b'\n', 1)[-1] if b'\n' in sample else b''
            truncated = True
        decoded = sample.decode('utf-8', 'replace')
        if not cut:
            rules = _structured_rules(decoded)
            if rules:
                reasons.add('SMOKE_RULE_OBSERVED')
                tail.append(dict(stream=stream, line='Squawk rule_name: ' + ', '.join(rules)))
        for line in decoded.splitlines():
            found = _line(line, home, install_dir)
            if found:
                reason, public = found
                reasons.add(reason)
                tail.append(dict(stream=stream, line=_public(public)))
    result = dict(schema_version=1, phase=phase if isinstance(phase, str) and phase in PHASES else 'unknown',
        code=code if isinstance(code, str) and code in CODES else 'COMMAND_FAILED',
        command=_command(argv, home, install_dir),
        returncode=returncode if type(returncode) is int and -(2**31) <= returncode < 2**31 else None,
        tail=tail[-MAX_LINES:], omitted_lines=max(0, total-min(len(tail), MAX_LINES)),
        truncated=truncated or len(tail) > MAX_LINES or isinstance(argv, (list, tuple)) and len(argv) > 32,
        reason_codes=sorted(reasons), hints=[_HINTS[reason] for reason in sorted(reasons)])
    smoke = _smoke_hint(smoke_observation) if phase == 'smoke' and code in ('SMOKE_NEGATIVE_FAILED', 'SMOKE_EXPECTED_FINDING_MISSING', 'SMOKE_MUTATION_INCOMPLETE') else None
    if smoke:
        reason = 'SMOKE_CONTRACT_OBSERVED' if isinstance(smoke_observation, dict) and smoke_observation.get('tool') in ('knip', 'mutmut') else 'SMOKE_RULE_OBSERVED'
        result['reason_codes'] = sorted(set(result['reason_codes']) | {reason})
        result['hints'].insert(0, smoke)
    while len(json.dumps(result, ensure_ascii=False).encode('utf-8')) > MAX_BYTES:
        result['truncated'] = True
        if result['tail']:
            result['tail'].pop(0)
            result['omitted_lines'] += 1
        elif result['command']:
            result['command'].pop()
        elif result['hints']:
            result['hints'].pop()
        else:
            break
    return result
