"""Pure local transport plan from a source snapshot, never execution evidence."""
import hashlib
import json
from pathlib import PurePosixPath
import re

from helix_runtime_integrations import _area, _imports, _lex, _owners, _path, _resolve, CODE_SUFFIXES

LIMITS = [
    'localhost is not production cookie policy evidence',
    'different localhost ports do not prove cross-site SameSite or cookie isolation',
    'HTTPS configuration does not prove login, cookie behavior or WebAuthn',
    'static discovery can miss dynamic cookie and identity configuration',
    'WebSocket transport is not implemented',
]


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _settings(config):
    if config is None: config = {}
    if not isinstance(config, dict) or not isinstance(config.get('runtime', {}), dict):
        raise ValueError('transport: configuration must be an object')
    value = config.get('runtime', {}).get('https', {})
    if not isinstance(value, dict) or set(value) - {'enabled', 'public_host'}:
        raise ValueError('transport: unsupported HTTPS configuration')
    if 'enabled' in value and type(value['enabled']) is not bool:
        raise ValueError('transport: HTTPS enabled must be boolean')
    if value.get('public_host', 'localhost') not in ('localhost', '127.0.0.1'):
        raise ValueError('transport: public host must be localhost or 127.0.0.1')
    return dict(value)


def _tokens(clean, code, literals):
    result = [(m.start(), m[0], 'code') for m in re.finditer(r'[A-Za-z_$][\w$]*|\d+|[^\s]', code)]
    result.extend((start, value, 'string') for start, _, value in literals)
    return sorted(result)


def _pairs(tokens):
    opened = []; pairs = {}
    for index, (_, value, kind) in enumerate(tokens):
        if kind != 'code': continue
        if value in ('(', '[', '{'): opened.append((value, index))
        elif value in (')', ']', '}'):
            if not opened or opened[-1][0] != {')': '(', ']': '[', '}': '{'}[value]: continue
            _, start = opened.pop(); pairs[start] = index
    return pairs


def _segments(tokens, start, end, pairs):
    result = []; begin = start; pos = start
    while pos < end:
        if pos in pairs: pos = pairs[pos] + 1; continue
        if tokens[pos][1:] == (',', 'code'):
            result.append((begin, pos)); begin = pos + 1
        pos += 1
    if begin < end: result.append((begin, end))
    return result


def _object(tokens, span, pairs):
    start, end = span
    if start >= end or tokens[start][1:] != ('{', 'code') or pairs.get(start) != end - 1: return None
    values = {}
    for first, last in _segments(tokens, start + 1, end - 1, pairs):
        if first + 1 < last and tokens[first + 1][1:] == (':', 'code'):
            values[tokens[first][1]] = (first + 2, last)
        else: values[None] = (first, last)  # spread, computed or shorthand options
    return values


def _single(tokens, span):
    start, end = span
    return tokens[start][1:] if end == start + 1 else None


def _receiver(tokens, pos, pairs):
    """Conservative same-block aliases; ambiguous receivers remain candidates."""
    name = tokens[pos][1]
    braces = [(left, right) for left, right in pairs.items() if tokens[left][1] == '{']
    def scope(index): return tuple(left for left, right in braces if left < index < right)
    call_scope = scope(pos)
    seen = set()
    def resolve(variable, before):
        if variable in seen:return 'unknown'
        seen.add(variable)
        binding = None
        for index in range(before - 1):
            if (tokens[index][1:] != (variable, 'code') or tokens[index + 1][1:] != ('=', 'code') or
                    index and tokens[index - 1][1] == '.' or
                    index + 2 < len(tokens) and tokens[index + 2][1] == '='):
                continue
            candidate_scope = scope(index)
            if call_scope[:len(candidate_scope)] == candidate_scope: binding = index + 2
        if binding is None:return 'cookies' if variable == 'cookies' else 'unknown'
        if scope(binding) != call_scope:return 'unknown'
        if binding in pairs and tokens[binding][1] == '{':
            # A locally declared method is not a framework response just because
            # it uses the method name cookie. Its body is scanned separately.
            for first, last in _segments(tokens, binding + 1, pairs[binding], pairs):
                if first + 1 < last and tokens[first][1] in ('cookie', 'set') and tokens[first + 1][1] == '(':
                    return 'local_method'
            return 'unknown'
        rhs = tokens[binding][1]
        following = tokens[binding + 1][1] if binding + 1 < len(tokens) else ';'
        # Resolve only a complete, same-block expression. A later assignment
        # has already replaced binding above; arbitrary chains are not proof.
        start = binding + (rhs == 'await')
        tail = [token[1] for token in tokens[start:start + 4]]
        if (len(tail) == 4 and tail[1:3] == ['.', 'cookies'] and tail[3] in (';', ',')
                and re.fullmatch(r'[A-Za-z_$][\w$]*', tail[0])):
            return 'cookies'
        if (tail[:3] == ['cookies', '(', ')'] and (len(tail) == 3 or tail[3] in (';', ','))):
            return 'cookies'
        if tokens[binding][2] == 'code' and re.fullmatch(r'[A-Za-z_$][\w$]*', rhs) and following in (';', ','):
            return resolve(rhs, binding)
        return 'unknown'
    return resolve(name, pos)


def _source_signals(path, text):
    suffix = PurePosixPath(path).suffix
    clean, code, literals = _lex(text, suffix)
    tokens = _tokens(clean, code, literals); pairs = _pairs(tokens)
    requirements = []; gaps = []
    def record(kind, basis, offset, target=requirements):
        row = dict(kind=kind, basis=basis, path=path, line=text.count('\n', 0, offset) + 1)
        if row not in target: target.append(row)
    # Local aliases only from the known cookie/session packages, not any function
    # whose name happens to contain serialize or session.
    serializers = set(); sessions = set()
    for match in re.finditer(r'''\bimport\s*\{([^}]+)\}\s*from\s*(['"])cookie\2''', clean):
        if code[match.start()].isspace(): continue
        for field in match[1].split(','):
            if found := re.fullmatch(r'\s*serialize(?:\s+as\s+([\w$]+))?\s*', field): serializers.add(found[1] or 'serialize')
    for match in re.finditer(r'''\bimport\s+([\w$]+)\s+from\s*(['"])express-session\2|\b(?:const|let)\s+([\w$]+)\s*=\s*require\(\s*(['"])express-session\4\s*\)''', clean):
        if not code[match.start()].isspace(): sessions.add(match[1] or match[3])
    for pos, (offset, value, kind) in enumerate(tokens):
        if value != '(' or kind != 'code' or pos not in pairs: continue
        args = _segments(tokens, pos + 1, pairs[pos], pairs)
        prefix = [row[1] for row in tokens[max(0, pos - 5):pos]]
        function = prefix[-1] if prefix else ''
        member = len(prefix) >= 3 and prefix[-2] == '.'
        receiver = _receiver(tokens, pos - 3, pairs) if member and function in ('set', 'cookie', 'set_cookie') else 'unknown'
        cookie_call = member and ((function == 'set' and receiver == 'cookies') or function == 'set_cookie')
        # Framework-like .cookie names alone are not sufficient source proof.
        # Known local methods are ignored; other receivers remain visible gaps.
        if member and function == 'cookie' and receiver != 'local_method':
            record('cookie_receiver_unresolved', 'candidate_cookie_method', offset, gaps)
        elif member and function == 'set' and receiver == 'unknown' and args:
            options = _object(tokens, args[0], pairs) if len(args) == 1 else _object(tokens, args[2], pairs) if len(args) > 2 else None
            name = _single(tokens, args[0])
            prefixed = name and name[1] == 'string' and name[0].startswith(('__Secure-', '__Host-'))
            if prefixed or options is not None and 'secure' in options or len(args) > 2 and options is None:
                record('cookie_receiver_unresolved', 'candidate_setter', offset, gaps)
        serializer = function in serializers and (pos < 2 or tokens[pos - 2][1] != '.')
        session = function in sessions and (pos < 2 or tokens[pos - 2][1] != '.')
        if cookie_call or serializer:
            if args and (_single(tokens, args[0]) or ('', ''))[1] == 'string':
                name = _single(tokens, args[0])[0]
                if name.startswith(('__Secure-', '__Host-')): record('secure_cookie', 'cookie_prefix', offset)
            if suffix == '.py':
                for first, last in args:
                    if first + 2 <= last and tokens[first][1] == 'secure' and tokens[first + 1][1] == '=':
                        flag = _single(tokens, (first + 2, last))
                        if flag != ('False', 'code'):
                            record('secure_cookie', 'explicit_setting' if flag == ('True', 'code') else 'conditional_setting', tokens[first][0])
                continue
            options = _object(tokens, args[0], pairs) if len(args) == 1 else _object(tokens, args[2], pairs) if len(args) > 2 else None
            if options is None:
                record('cookie_options_unresolved', 'dynamic_options', offset, gaps)
                continue
            if None in options: record('cookie_options_unresolved', 'dynamic_object_properties', offset, gaps)
            if 'name' in options:
                name = _single(tokens, options['name'])
                if name and name[1] == 'string' and name[0].startswith(('__Secure-', '__Host-')):
                    record('secure_cookie', 'cookie_prefix', offset)
            if 'secure' in options:
                flag = _single(tokens, options['secure'])
                if flag != ('false', 'code'):
                    record('secure_cookie', 'explicit_setting' if flag == ('true', 'code') else 'conditional_setting', tokens[options['secure'][0]][0])
        elif session and args:
            options = _object(tokens, args[0], pairs)
            cookies = _object(tokens, options['cookie'], pairs) if options and 'cookie' in options else None
            if cookies and None in cookies: record('cookie_options_unresolved', 'dynamic_object_properties', offset, gaps)
            if cookies and 'secure' in cookies:
                flag = _single(tokens, cookies['secure'])
                if flag != ('false', 'code'):
                    record('secure_cookie', 'explicit_setting' if flag == ('true', 'code') else 'conditional_setting', tokens[cookies['secure'][0]][0])
            elif options is None: record('cookie_options_unresolved', 'dynamic_session_options', offset, gaps)
        elif function in ('setHeader', 'set', 'append') and len(args) >= 2:
            header = _single(tokens, args[0]); content = _single(tokens, args[1])
            is_header = function == 'setHeader' or prefix[-3:-1] == ['headers', '.']
            if is_header and header and header[1] == 'string' and header[0].lower() == 'set-cookie':
                if content and content[1] == 'string' and re.search(r'(?:^|;)\s*Secure\s*(?:;|$)', content[0], re.I):
                    record('secure_cookie', 'literal_cookie_header', offset)
                elif content is None: record('cookie_options_unresolved', 'dynamic_cookie_header', offset, gaps)
        if prefix[-5:] == ['navigator', '.', 'credentials', '.', 'get'] or prefix[-5:] == ['navigator', '.', 'credentials', '.', 'create']:
            options = _object(tokens, args[0], pairs) if args else None
            basis = 'public_key_operation' if options and 'publicKey' in options else 'possible_browser_credentials'
            record('webauthn', basis, offset)
            if basis == 'possible_browser_credentials': record('credentials_options_unresolved', basis, offset, gaps)
    if suffix == '.py':
        for match in re.finditer(r'\b(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*([^\n;]+)', code):
            flag = match[1].strip()
            if flag != 'False': record('secure_cookie', 'explicit_setting' if flag == 'True' else 'conditional_setting', match.start())
    return requirements, gaps, (clean, code, literals)


def transport_plan(sources, parts, integrations, config=None):
    """Consume snapshot text and inventory; do not open, import, probe or execute."""
    if not isinstance(sources, dict) or not isinstance(parts, list): raise ValueError('transport: sources and parts required')
    settings = _settings(config); roots = []
    for part in parts:
        if not isinstance(part, dict) or _path(part.get('path')) is None or _path(part.get('path')) != part.get('path'):
            raise ValueError('transport: invalid part')
        if part['path'] not in roots: roots.append(part['path'])
    roots.sort()
    if not isinstance(integrations, dict) or not isinstance(integrations.get('integrations'), list):
        raise ValueError('transport: integration inventory required')
    texts = {}; excluded = []; gaps = []
    for path, text in sources.items():
        name = _path(path)
        if name is None or name != path or not isinstance(text, str):
            gaps.append(dict(kind='source_unavailable', reason='invalid source path or content')); continue
        if PurePosixPath(path).name.startswith('.env') or _area(path) != 'active':
            excluded.append(dict(path=path, area=_area(path), reason='outside active source snapshot')); continue
        texts[path] = text
    if not texts: gaps.append(dict(kind='source_unavailable', reason='no active source files'))
    if integrations.get('status') == 'INCOMPLETE': gaps.append(dict(kind='inventory_incomplete', reason='integration discovery incomplete'))
    signals = {}; source_gaps = {}; graph = {}
    for path, text in sorted(texts.items()):
        if PurePosixPath(path).suffix not in CODE_SUFFIXES:
            graph[path] = []; continue
        requirements, missing, lexed = _source_signals(path, text)
        signals[path] = requirements; source_gaps[path] = missing; graph[path] = []
        clean, code, literals = lexed
        for spec, line in _imports(clean, code, literals, PurePosixPath(path).suffix):
            target = _resolve(path, spec, texts, _owners(path, roots))
            if target: graph[path].append(target)
            elif spec.startswith(('.', '$', '@/')) and (requirements or missing):
                source_gaps[path].append(dict(kind='local_import_unresolved', path=path, line=line, basis='static_import'))
    declarations = {root: [] for root in roots}
    unscoped = []
    for item in integrations['integrations']:
        if not isinstance(item, dict): raise ValueError('transport: invalid integration entry')
        if item.get('provider') not in ('keycloak', 'webauthn') or item.get('area') != 'active': continue
        owners = item.get('parts', [])
        if not isinstance(owners, list) or any(owner not in roots for owner in owners):
            raise ValueError('transport: integration part mismatch')
        rows = []
        if not isinstance(item.get('evidence', []), list): raise ValueError('transport: invalid integration evidence')
        for evidence in item.get('evidence', []):
            if (not isinstance(evidence, dict) or _path(evidence.get('path')) is None or _path(evidence.get('path')) != evidence.get('path') or
                    type(evidence.get('line')) is not int or evidence['line'] < 1):
                raise ValueError('transport: invalid integration evidence')
            if _area(evidence['path']) != 'active': continue
            basis = evidence.get('kind')
            basis = basis if basis in ('dependency', 'import', 'environment', 'browser_credentials') else 'declaration'
            # The code scanner below preserves exact line and publicKey certainty.
            if item['provider'] == 'webauthn' and basis == 'browser_credentials': continue
            rows.append(dict(kind='keycloak_transport' if item['provider'] == 'keycloak' else 'webauthn',
                             basis=basis, path=evidence['path'], line=evidence['line']))
        if not rows: rows.append(dict(kind=item['provider'], basis='declaration_without_location'))
        if not owners:
            unscoped.extend(rows); continue
        for root in owners: declarations[root].extend(rows)
    if unscoped: gaps.append(dict(kind='integration_scope_unresolved', reason='identity declaration has no app part', requirements=unscoped))
    planned = []
    for root in roots:
        pending = [path for path in texts if _owners(path, roots) == root]; visited = set()
        while pending:
            path = pending.pop()
            if path in visited: continue
            visited.add(path); pending.extend(graph.get(path, []))
        requirements = declarations[root] + [row for path in sorted(visited) for row in signals.get(path, [])]
        missing = [row for path in sorted(visited) for row in source_gaps.get(path, [])]
        if not visited: missing.append(dict(kind='part_sources_unavailable', reason='no active sources assigned to this app part'))
        requirements = sorted({json.dumps(row, sort_keys=True) for row in requirements})
        requirements = [json.loads(row) for row in requirements]
        enabled = settings.get('enabled', False)
        host = settings.get('public_host', 'localhost') if enabled else '127.0.0.1'
        if requirements and not enabled:
            missing.append(dict(kind='https_not_enabled', reason='HTTPS needed for declared identity or Secure cookie checks'))
        if enabled and host != 'localhost' and any(row['kind'] == 'webauthn' for row in requirements):
            missing.append(dict(kind='webauthn_rp_host', reason='IP address is not the planned WebAuthn RP domain; use localhost'))
        planned.append(dict(part=root, selected='https' if enabled else 'http', selection='explicit' if 'enabled' in settings else 'default',
                            public_host=host, ports='allocated_at_runtime', https_needed=bool(requirements), requirements=requirements,
                            gaps=missing, status='INCOMPLETE' if missing or gaps else 'PLANNED',
                            limits=list(LIMITS), execution='not_run'))
    binding = dict(sources={path: hashlib.sha256(text.encode()).hexdigest() for path, text in sorted(texts.items())},
                   parts=roots, settings=settings, requirements=[part['requirements'] for part in planned], gaps=gaps)
    return dict(schema_version=1, plan_id=_digest(binding), scope='source_declarations_only',
                status='INCOMPLETE' if gaps or any(part['status'] == 'INCOMPLETE' for part in planned) else 'PLANNED' if planned else 'NOT_DETECTED',
                parts=planned, excluded=sorted(excluded, key=lambda row: row['path']), gaps=gaps, limits=list(LIMITS),
                execution=dict(files_opened=0, commands=0, models=0, network=0, application=False))


def derive_transport_coverage(plan, executed_parts, *, selected_parts=None):
    """Derive coverage from declarations and receipts, never a supplied status."""
    if (not isinstance(plan, dict) or plan.get('schema_version') != 1 or
            plan.get('scope') != 'source_declarations_only' or not isinstance(plan.get('gaps'), list) or
            not isinstance(plan.get('parts'), list) or not isinstance(executed_parts, list)):
        raise ValueError('transport: malformed report plan')
    by_path = {}
    for row in plan['parts']:
        if (not isinstance(row, dict) or _path(row.get('part')) is None or row['part'] in by_path or
                row.get('selected') not in ('http', 'https') or not isinstance(row.get('gaps'), list) or
                not isinstance(row.get('requirements'), list) or type(row.get('https_needed')) is not bool or
                row['https_needed'] != bool(row['requirements'])):
            raise ValueError('transport: malformed part declaration')
        by_path[row['part']] = row
    expected = set(by_path) if selected_parts is None else set(selected_parts)
    if expected - set(by_path): raise ValueError('transport: unknown selected part')
    incomplete = bool(plan['gaps']) or not executed_parts; seen = set()
    for part in executed_parts:
        if not isinstance(part, dict): raise ValueError('transport: malformed executed part')
        path = part.get('path', part.get('name'))
        if path not in by_path or path in seen: raise ValueError('transport: executed part binding mismatch')
        seen.add(path); row = by_path[path]; receipt = part.get('transport')
        if (not isinstance(receipt, dict) or receipt.get('selected') != row['selected'] or
                receipt.get('gaps') != row['gaps'] or receipt.get('status') not in ('not_checked', 'starting', 'ready', 'blocked')):
            raise ValueError('transport: missing or inconsistent part receipt')
        incomplete |= bool(row['gaps']) or row['https_needed'] and row['selected'] != 'https'
        incomplete |= receipt.get('cleanup') == 'unknown' or receipt['status'] != 'ready'
        if row['selected'] == 'https':
            incomplete |= receipt['status'] != 'ready'
            if receipt['status'] == 'ready':
                public, backend = receipt.get('public_port'), receipt.get('backend_port')
                if (type(public) is not int or type(backend) is not int or not 1 <= public <= 65535 or
                        not 1 <= backend <= 65535 or public == backend or row.get('public_host') not in ('localhost', '127.0.0.1') or
                        receipt.get('public_origin') != 'https://' + row['public_host'] + ':' + str(public) or
                        receipt.get('backend_origin') != 'http://127.0.0.1:' + str(backend) or
                        receipt.get('tls_health') != 'verified_by_executor_ca_probe' or
                        type(receipt.get('trusted_key_count')) is not int or not 1 <= receipt['trusted_key_count'] <= 2 or
                        not isinstance(receipt.get('log'), str) or not re.fullmatch(r'logs/https-[0-9]+\.log', receipt['log'])):
                    raise ValueError('transport: HTTPS readiness receipt lacks bound probe evidence')
    return 'INCOMPLETE' if incomplete or seen != expected else 'RECORDED'


def project_transport(report, parts=None):
    """Safe public transport projection shared by import and owner reports.

    This describes local transport only. It never grants cookie, session or
    application authorization coverage from an HTTPS readiness observation.
    """
    if not isinstance(report, dict) or not isinstance(report.get('parts', []), list):
        raise ValueError('transport: report object required')
    entries = report.get('parts', [])
    if not all(isinstance(row, dict) for row in entries): raise ValueError('transport: malformed executed part')
    present = ('transport_plan' in report or 'transport_coverage' in report or any('transport' in row for row in entries))
    base = dict(scope='local_transport', limits=list(LIMITS), parts=[], gaps=[])
    if not present: return dict(base, status='NOT_RECORDED')
    plan = report.get('transport_plan')
    actual = derive_transport_coverage(plan, entries)
    if report.get('transport_coverage') != actual: raise ValueError('transport: coverage disagrees with declarations and receipts')
    if parts is not None:
        if (not isinstance(parts, list) or any(not isinstance(path, str) or _path(path) != path for path in parts) or
                len(set(parts)) != len(parts)):
            raise ValueError('transport: exact selected part paths required')
        known = {row.get('path', row.get('name')) for row in entries}
        if set(parts) - known: raise ValueError('transport: unknown selected part')
        entries = [row for row in entries if row.get('path', row.get('name')) in parts]
    def gaps(rows):
        result = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('kind'), str) or not re.fullmatch(r'[a-z_]{1,80}', row['kind']):
                result.append(dict(kind='unrecognized_gap')); continue
            value = dict(kind=row['kind'])
            if isinstance(row.get('path'), str) and _path(row['path']) == row['path']: value['path'] = row['path']
            if type(row.get('line')) is int and row['line'] > 0: value['line'] = row['line']
            result.append(value)
        return result
    base['gaps'] = gaps(plan['gaps'])
    declarations = {row['part']: row for row in plan['parts']}
    for entry in entries:
        receipt = entry['transport']; part = entry.get('path', entry.get('name'))
        projected = dict(part=part, selected=receipt['selected'], status=receipt['status'],
                         coverage=derive_transport_coverage(plan, [entry], selected_parts=[part]), gaps=gaps(receipt['gaps']),
                         requirements=gaps(declarations[part]['requirements']), limits=list(LIMITS))
        if receipt.get('cleanup') in ('not_needed', 'pending', 'stopped', 'unknown', 'kept'): projected['cleanup'] = receipt['cleanup']
        if receipt['selected'] == 'https' and receipt['status'] == 'ready':
            # derive already checked exact loopback origin and actual probe marker.
            projected.update(public_origin=receipt['public_origin'], tls_health=receipt['tls_health'])
        base['parts'].append(projected)
    return dict(base, status=derive_transport_coverage(plan, entries, selected_parts=parts))
