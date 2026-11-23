"""Pure preparation of approved source snapshots. No caller or delivery is wired here.

Redaction is a conservative heuristic, not a guarantee that all personal data or
credentials were recognized. A prepared snapshot never proves model execution.
"""
from datetime import datetime, timezone
import fnmatch
from functools import lru_cache
import hashlib
import json
import re

from helix_provider_plan import FAMILIES


DEFAULT_EXCLUDE_PATHS = (
    '**/.env*', '**/.git/**', '**/.aws/**', '**/.ssh/**', '**/.codex/**',
    '**/.agents/**', '**/.docker/**', '**/.npmrc', '**/.netrc', '**/.pypirc',
    '**/*secret*', '**/*credential*', '**/private/**', '**/*seed*',
    '**/*fixture*', '**/*dump*', '**/*backup*', '**/*.bak', '**/*.sqlite*',
    '**/*.db', '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx', '**/id_rsa*',
    '**/id_ed25519*',
)
LIMITATIONS = (
    'Heurystyczna redakcja nie dowodzi wykrycia wszystkich sekretów i danych osobowych.',
    'Nie rozpoznaje wszystkich nieopisanych nazwisk/adresów, kodowania, fragmentacji ani dynamicznego składania wartości.',
    'Wykluczone i zredagowane fragmenty pozostają lukami przeglądu.',
    'Pakiet NOT_SENT nie dowodzi wysłania danych ani ograniczenia odczytu plików przez natywne CLI.',
)
_ERRORS = {
    'POLICY_REQUIRED', 'POLICY_NOT_APPROVED', 'INVALID_POLICY', 'INVALID_PROVIDER',
    'PROVIDER_NOT_ALLOWED', 'INVALID_SOURCES', 'UNSAFE_SOURCE_PATH',
    'INVALID_COVERAGE', 'INVALID_OBSERVED_AT', 'INVALID_TEXT',
}
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_ASSIGNMENT = re.compile(r'(?<![\w$-])([A-Za-z_$][A-Za-z0-9_$-]*)[\"\']?[ \t]*(?P<operator>:|=)[ \t]*')
_REFERENCE = re.compile(r'(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+|os\.environ\[(?:"[A-Za-z_][A-Za-z0-9_]*"|\'[A-Za-z_][A-Za-z0-9_]*\')\])[ \t]*[;,)}\]]*[ \t]*\Z')
_TYPE = re.compile(r'(?:string|number|boolean|unknown|any|str|int|bool|float)[ \t]*[;,)}\]]*[ \t]*\Z')
_DECLARATION_PREFIX = re.compile(r'[ \t]*(?:(?:export[ \t]+)?(?:const|let|var)[ \t]+)?')
_EMAIL = re.compile(r"(?<![\w.!#$%&'*+/=?^`{|}~-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_NUMBER = re.compile(r'(?<!\w)\+?\d[\d(). \t-]{7,}\d(?!\w)')
_CREDENTIAL = re.compile(
    r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|'
    r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b|'
    r'\bsk_(?:live|test)_[A-Za-z0-9]+\b|\bsk-[A-Za-z0-9_-]{16,}\b|'
    r'\bxox[baprs]-[A-Za-z0-9-]+\b|'
    r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|'
    r'(?i:\b(?:bearer|basic)[ \t]+[A-Za-z0-9+/_.=-]+)')
_IBAN = re.compile(r'\b[A-Z]{2}\d{2}(?:[ \t]?[A-Z0-9]){11,30}\b')
_URL = re.compile(r'(?i:\b[a-z][a-z0-9+.-]*://)[^\s/<>\"\']+')
_PII_KEYS = frozenset(('email', 'phone', 'telephone', 'telefon', 'pesel', 'nip',
    'iban', 'cardnumber', 'firstname', 'lastname', 'fullname', 'birthdate',
    'dateofbirth', 'address', 'street', 'postalcode'))


class DataEgressError(ValueError):
    """Stable diagnostics: never include rejected policy or source contents."""
    status = 'ERROR'

    def __init__(self, code):
        self.code = code if code in _ERRORS else 'INVALID_POLICY'
        super().__init__('data_egress: ' + self.code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


def _text_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _timestamp(value, code):
    if not isinstance(value, str) or len(value) > 64:
        raise DataEgressError(code)
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        raise DataEgressError(code) from None


def _path(value, *, glob=False):
    if not isinstance(value, str) or not value or len(value) > 8192:
        return False
    if value.startswith(('/', '~')) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return False
    if any(c in value for c in ('\\', ':', '\x00', '%')) or any(p in ('', '.', '..') for p in value.split('/')):
        return False
    # Intentionally small glob language: *, ** and ?. No regexp or negation DSL.
    if glob:
        if any(c in value for c in ('[', ']', '{', '}', '!', '@')):
            return False
    # Source names are literals, not patterns: [id], [...path] and (group)
    # are ordinary SvelteKit/Next route components. They must not be rejected.
    try:
        value.encode('utf-8')
    except UnicodeError:
        return False
    return True


def normalize_policy(policy):
    """Validate one canonical policy, without inferring approval or alias families.

    Mandatory exclusions cannot be removed. Custom case-sensitive POSIX globs
    extend them; **/ also matches the root. Metadata is only an owner declaration.
    """
    if policy is None:
        raise DataEgressError('POLICY_REQUIRED')
    allowed = {'schema_version', 'status', 'allowed_providers', 'exclude_paths', 'approved_by', 'approved_at'}
    if not isinstance(policy, dict) or set(policy) - allowed:
        raise DataEgressError('INVALID_POLICY')
    if type(policy.get('schema_version', 1)) is not int or policy.get('schema_version', 1) != 1:
        raise DataEgressError('INVALID_POLICY')
    if policy.get('status') != 'approved':
        raise DataEgressError('POLICY_NOT_APPROVED')
    providers, paths = policy.get('allowed_providers'), policy.get('exclude_paths')
    if (not isinstance(providers, list) or any(not isinstance(p, str) or p not in FAMILIES for p in providers)
            or len(providers) != len(set(providers)) or not isinstance(paths, list)
            or any(not _path(p, glob=True) for p in paths)):
        raise DataEgressError('INVALID_POLICY')
    result = dict(schema_version=1, status='approved', allowed_providers=sorted(providers),
                  exclude_paths=sorted(set(DEFAULT_EXCLUDE_PATHS) | set(paths)))
    if 'approved_by' in policy:
        author = policy['approved_by']
        if not isinstance(author, str) or not author.strip() or len(author) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in author):
            raise DataEgressError('INVALID_POLICY')
        try: author.encode('utf-8')
        except UnicodeError: raise DataEgressError('INVALID_POLICY') from None
        result['approved_by'] = author
    if 'approved_at' in policy:
        result['approved_at'] = _timestamp(policy['approved_at'], 'INVALID_POLICY')
    return result


def policy_sha256(policy):
    return _digest(normalize_policy(policy))


def _line_signals(line, *, allow_references=False):
    reasons, multiline = set(), False
    continued = line.rstrip().endswith('\\')
    declaration_start = _DECLARATION_PREFIX.match(line).end() if allow_references else None
    for match in _ASSIGNMENT.finditer(line):
        key = match[1].lower().replace('_', '').replace('-', '')
        secret = any(word in key for word in ('secret', 'credential', 'password', 'passwd', 'authorization', 'token', 'apikey', 'privatekey'))
        if secret or key in _PII_KEYS:
            # Only a complete, simple code declaration. Never consume a prefix
            # of `process.env.X || "literal"`, comments, a second statement, or
            # a YAML/unknown-language scalar as proof of an absent literal.
            reference = (allow_references and match.start() == declaration_start
                         and (_REFERENCE.fullmatch(line, match.end()) or
                              match['operator'] == ':' and _TYPE.fullmatch(line, match.end())))
            if reference: continue
            reasons.add('CREDENTIAL_ASSIGNMENT' if secret else 'PII_FIELD')
            # Unresolved structured/multiline values cannot safely be exported
            # after merely masking the key line. Suppress the whole input.
            at = match.end()
            head = line[at:at+3]
            if at == len(line) or head.startswith(('"""', "'''", '`', '{', '[', '(', '/*', '//', '#', '|', '>')) or continued:
                multiline = True
    if '@' in line and _EMAIL.search(line): reasons.add('EMAIL')
    if _CREDENTIAL.search(line): reasons.add('CREDENTIAL_TOKEN')
    if any(9 <= sum(c.isdecimal() for c in m[0]) <= 19 for m in _NUMBER.finditer(line)):
        reasons.add('PHONE_OR_IDENTIFIER')
    if _IBAN.search(line): reasons.add('FINANCIAL_IDENTIFIER')
    if '://' in line and any('@' in m[0] for m in _URL.finditer(line)):
        reasons.add('URL_CREDENTIALS')
    return reasons, multiline


def _ending(line):
    for ending in ('\r\n', '\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029'):
        if line.endswith(ending): return ending
    return ''


# Wąskie maskowanie dla promptów do modeli: podmienia wyłącznie wartość sekretu, linia i reszta kodu zostają widoczne.
_SECRET_VALUES = re.compile(
    r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}'                     # JWT (np. klucze Supabase)
    r'|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'        # klucze prywatne PEM
    r'|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}'                                        # Stripe
    r'|\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}'                                              # OpenAI, Anthropic
    r'|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{30,}'          # GitHub
    r'|\bglpat-[A-Za-z0-9_-]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}'                          # GitLab, Slack
    r'|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b')                                   # AWS, Google
_SECRET_ASSIGNMENT = re.compile(
    r'(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|service[_-]?role[_-]?key)'
    r'["\'`]?\s*(?:=>|=|:)\s*)(["\'`])((?:\\.|(?!\2)[^\\\n])+)\2')


def mask_secrets(text):
    """Return (masked text, number of masked values). Line count and all other characters stay as they were."""
    if not isinstance(text, str): raise DataEgressError('INVALID_TEXT')
    count = 0
    def value(match):
        nonlocal count; count += 1
        return '\n'.join('[HELIX_SECRET]' for _ in match.group(0).split('\n'))
    def assignment(match):
        nonlocal count
        if match.group(3) == '[HELIX_SECRET]': return match.group(0)
        count += 1
        return match.group(1) + match.group(2) + '[HELIX_SECRET]' + match.group(2)
    text = _SECRET_VALUES.sub(value, text)
    return _SECRET_ASSIGNMENT.sub(assignment, text), count


def redact_text(text, *, source_path=None):
    """Mask whole affected lines, including '-' lines in a supplied unified diff.

    The function preserves line endings/count and publishes only reason codes and
    line ranges. No matched value, substring or per-secret hash is returned.
    """
    if not isinstance(text, str): raise DataEgressError('INVALID_TEXT')
    if source_path is not None and not _path(source_path): raise DataEgressError('UNSAFE_SOURCE_PATH')
    try: original = _text_hash(text)
    except UnicodeError: raise DataEgressError('INVALID_TEXT') from None
    # This is deliberately not a JS/TS/Python parser. In code without any
    # ambiguous multiline literal/comment/JSX context, a standalone declaration
    # can prove a simple reference. Otherwise retain conservative masking.
    extension = source_path.rsplit('.', 1)[-1].lower() if source_path else None
    references = (extension in ('js', 'ts', 'mjs', 'cjs', 'mts', 'cts', 'py')
                  and not any(token in text for token in ('"""', "'''", '`', '/*', '\\\n', '\\\r', '<')))
    lines = text.splitlines(keepends=True)
    signals, private_key, whole = [], False, False
    for raw in lines:
        ending = _ending(raw)
        line = raw[:-len(ending)] if ending else raw
        analysis_line = line[1:] if line.startswith(('+', '-')) else line
        reasons, multiline = _line_signals(analysis_line,
            allow_references=references and analysis_line == line)
        whole = whole or multiline
        if '-----BEGIN ' in line and 'PRIVATE KEY' in line: private_key = True
        if '-----END ' in line and 'PRIVATE KEY' in line and not private_key:
            whole = True  # The beginning of a supplied key fragment is unknown.
        if private_key: reasons.add('PRIVATE_KEY_BLOCK')
        if '-----END ' in line and 'PRIVATE KEY' in line: private_key = False
        signals.append(reasons)
    output, redactions = [], []
    for number, (raw, reasons) in enumerate(zip(lines, signals), 1):
        if whole: reasons.add('MULTILINE_VALUE_UNRESOLVED')
        if reasons:
            prefix = raw[0] if raw[:1] in ('+', '-', ' ') else ''
            output.append(prefix + '[HELIX_REDACTED]' + _ending(raw))
            codes = sorted(reasons)
            if redactions and redactions[-1]['end_line'] == number-1 and redactions[-1]['codes'] == codes:
                redactions[-1]['end_line'] = number
            else:
                redactions.append(dict(line=number, end_line=number, codes=codes))
        else:
            output.append(raw)
    sanitized = ''.join(output)
    return sanitized, dict(schema_version=1, redactor_version=1,
        original_sha256=original, outbound_sha256=_text_hash(sanitized),
        lines_total=len(lines), redacted_lines=sum(r['end_line']-r['line']+1 for r in redactions),
        redactions=redactions, limitations=list(LIMITATIONS))


def _matches(name, pattern):
    """POSIX segments: ** spans zero or more directories, * never spans /."""
    names, patterns = name.split('/'), pattern.split('/')
    @lru_cache(None)
    def match(i, j):
        if j == len(patterns): return i == len(names)
        if patterns[j] == '**':
            return match(i, j + 1) or i < len(names) and match(i + 1, j)
        return i < len(names) and fnmatch.fnmatchcase(names[i], patterns[j]) and match(i + 1, j + 1)
    return match(0, 0)


def _excluded(name, pattern):
    """Exclusion errs toward not sending: any reading of the pattern counts.

    Owners wrote policies against the earlier fnmatch semantics (* crossing /),
    and a slash-less pattern like *.csv means "this file name anywhere". Every
    ancestor is checked so an excluded folder also covers its contents.
    """
    parts = name.split('/')
    for i in range(1, len(parts) + 1):
        path = '/'.join(parts[:i])
        legacy = (pattern, pattern[3:]) if pattern.startswith('**/') else (pattern,)
        if (_matches(path, pattern)
                or any(fnmatch.fnmatchcase(path, p) or p.endswith('/**') and fnmatch.fnmatchcase(path, p[:-3]) for p in legacy)
                or '/' not in pattern and fnmatch.fnmatchcase(parts[i - 1], pattern)):
            return True
    return False


def _coverage_rows(coverage):
    if coverage is None: return {}, 'UNKNOWN', ['SOURCE_COVERAGE_MISSING']
    if not isinstance(coverage, dict) or not isinstance(coverage.get('files'), list):
        raise DataEgressError('INVALID_COVERAGE')
    status = coverage.get('status')
    if status not in ('COMPLETE', 'INCOMPLETE'): raise DataEgressError('INVALID_COVERAGE')
    rows = {}
    for row in coverage['files']:
        if not isinstance(row, dict) or not _path(row.get('file')) or row['file'] in rows:
            raise DataEgressError('INVALID_COVERAGE')
        # Never project arbitrary source-coverage reasons or other supplied keys.
        if _line_signals(row['file'])[0]: raise DataEgressError('INVALID_COVERAGE')
        if row.get('status') not in ('read', 'skipped'): raise DataEgressError('INVALID_COVERAGE')
        declared = row.get('sha256')
        if declared is not None and (not isinstance(declared, str) or not _SHA.fullmatch(declared)):
            raise DataEgressError('INVALID_COVERAGE')
        rows[row['file']] = {'status': row['status'], 'sha256': declared}
        for field in ('lines_total', 'lines_read'):
            if field in row:
                value = row[field]
                if value is not None and (type(value) is not int or value < 0):
                    raise DataEgressError('INVALID_COVERAGE')
                rows[row['file']][field] = value
    gaps = ['SOURCE_COVERAGE_INCOMPLETE'] if status == 'INCOMPLETE' else []
    if 'files_total' in coverage and (type(coverage['files_total']) is not int or coverage['files_total'] != len(rows)):
        gaps.append('SOURCE_COVERAGE_CONFLICT')
    if 'files_read' in coverage and (type(coverage['files_read']) is not int or coverage['files_read'] != sum(r['status'] == 'read' for r in rows.values())):
        gaps.append('SOURCE_COVERAGE_CONFLICT')
    for field in ('lines_total', 'lines_read', 'unknown_line_totals'):
        if field not in coverage: continue
        value = coverage[field]
        if type(value) is not int or value < 0:
            gaps.append('SOURCE_COVERAGE_CONFLICT')
        elif field == 'unknown_line_totals':
            if status == 'COMPLETE' and value: gaps.append('SOURCE_COVERAGE_CONFLICT')
        elif all(field in row for row in rows.values()) and value != sum(row[field] or 0 for row in rows.values()):
            gaps.append('SOURCE_COVERAGE_CONFLICT')
    return rows, status, sorted(set(gaps))


def prepare_sources(sources, coverage, policy, provider, observed_at):
    """Return (sanitized source map, public manifest), without I/O or delivery.

    Sources must already be a caller-owned no-follow snapshot. This pure helper
    cannot verify filesystem boundaries, native CLI permissions or disclosure.
    """
    normalized = normalize_policy(policy)
    if not isinstance(provider, str) or provider not in FAMILIES: raise DataEgressError('INVALID_PROVIDER')
    if provider not in normalized['allowed_providers']: raise DataEgressError('PROVIDER_NOT_ALLOWED')
    observed = _timestamp(observed_at, 'INVALID_OBSERVED_AT')
    if not isinstance(sources, dict): raise DataEgressError('INVALID_SOURCES')
    for name, text in sources.items():
        if not _path(name) or _line_signals(name)[0]: raise DataEgressError('UNSAFE_SOURCE_PATH')
        if not isinstance(text, str): raise DataEgressError('INVALID_SOURCES')
        try: text.encode('utf-8')
        except UnicodeError: raise DataEgressError('INVALID_SOURCES') from None
    declared, coverage_status, global_gaps = _coverage_rows(coverage)
    gaps = [dict(path=None, code=code) for code in global_gaps]
    sanitized, files, exclusions = {}, [], []
    for name in sorted(set(sources) | set(declared)):
        text, entry = sources.get(name), declared.get(name)
        original = _text_hash(text) if text is not None else None
        row = dict(path=name, original_sha256=original, outbound_sha256=None,
                   status='unavailable', lines_total=len(text.splitlines()) if text is not None else None,
                   redacted_lines=0, redactions=[])
        files.append(row)
        # Default secret/fixture globs also protect descendants of a matching
        # directory. Keep that conservative policy with segment-aware globs.
        ancestors = ['/'.join(name.lower().split('/')[:i]) for i in range(1, len(name.split('/')) + 1)]
        default = any(_matches(parent, p) for parent in ancestors for p in DEFAULT_EXCLUDE_PATHS)
        custom = any(_excluded(name, p) for p in normalized['exclude_paths'])
        if default or custom:
            code = 'DEFAULT_PATH_EXCLUDED' if default else 'POLICY_PATH_EXCLUDED'
            row['status'] = 'excluded'
            exclusions.append(dict(path=name, code=code))
            gaps.append(dict(path=name, code=code))
            continue
        if text is None:
            gaps.append(dict(path=name, code='SOURCE_NOT_SUPPLIED')); continue
        if '\x00' in text:
            gaps.append(dict(path=name, code='BINARY_SOURCE_NOT_SUPPORTED')); continue
        if entry and entry['status'] != 'read':
            gaps.append(dict(path=name, code='SOURCE_COVERAGE_CONFLICT')); continue
        if entry and entry['sha256'] is not None and entry['sha256'] != original:
            gaps.append(dict(path=name, code='SOURCE_HASH_MISMATCH')); continue
        # Match source_coverage.scan's LF-based counters, not model claims. A
        # declared longer/partial source must not be rebound to the supplied text.
        source_lines = text.count('\n') + int(bool(text) and not text.endswith('\n'))
        if entry and any(field in entry and entry[field] != source_lines for field in ('lines_total', 'lines_read')):
            gaps.append(dict(path=name, code='SOURCE_LINE_COVERAGE_MISMATCH')); continue
        if entry is None:
            gaps.append(dict(path=name, code='SOURCE_NOT_IN_COVERAGE'))
        elif entry['sha256'] is None:
            gaps.append(dict(path=name, code='SOURCE_HASH_NOT_RECORDED'))
        safe, redaction = redact_text(text, source_path=name)
        sanitized[name] = safe
        row.update(outbound_sha256=redaction['outbound_sha256'], redacted_lines=redaction['redacted_lines'],
                   redactions=redaction['redactions'], status='redacted' if redaction['redacted_lines'] else 'prepared')
        if redaction['redacted_lines']: gaps.append(dict(path=name, code='CONTENT_REDACTED'))
    if not sources: gaps.append(dict(path=None, code='NO_SOURCES_SUPPLIED'))
    manifest = dict(schema_version=1, status='INCOMPLETE' if gaps else 'PREPARED', delivery='NOT_SENT',
        review_status='NOT_RUN', observed_at=observed, provider=provider,
        policy_sha256=_digest(normalized), policy_status='approved',
        approval_basis='owner_declaration_not_independently_verified',
        source_digest=_digest([[r['path'], r['original_sha256']] for r in files]),
        outbound_digest=_digest([[r['path'], r['outbound_sha256']] for r in files if r['path'] in sanitized]),
        input_coverage_status=coverage_status, files=files, exclusions=exclusions, gaps=gaps,
        counts=dict(supplied_files=len(sources), declared_files=len(declared) if coverage is not None else None,
            prepared_files=len(sanitized), excluded_files=len(exclusions),
            unavailable_files=sum(r['status'] == 'unavailable' for r in files),
            redacted_files=sum(r['redacted_lines'] > 0 for r in files),
            redacted_lines=sum(r['redacted_lines'] for r in files)),
        limitations=list(LIMITATIONS), execution=dict(files_opened=0, commands=0, models=0, network=0))
    return sanitized, manifest
