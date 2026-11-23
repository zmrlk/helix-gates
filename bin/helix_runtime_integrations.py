"""Pure integration inventory. Source declarations and execution proof stay separate.

inventory(sources, parts, config=None) consumes already-read relative paths/texts.
config.runtime.integrations (or config.integrations) maps provider or entry id to
{strategy: container|emulator|replay|disabled, required_for_startup: bool}.
execution_inventory(plan, receipts, run_id=...) accepts integration_id receipts
bound to this plan_id and caller-owned run_id;
only route receipts with integration_exercised=True and an artifact path count.
Neither function opens files, probes tools, imports project code or uses a network.
"""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re

from helix_authz_routes import route_path, supplemental
from helix_environment import _source_env, _yaml_env_names

from helix_runtime_registry import load_registry, indexes, host_provider, manifest_signals, source_signals

STRATEGIES = ('container', 'http-sink', 'record-replay', 'disable', 'emulator', 'replay', 'disabled')
_REGISTRY = load_registry()
PROVIDERS, PACKAGES, HOSTS, ENV_PATTERNS = indexes(_REGISTRY)
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ALL', 'unknown'}
CODE_SUFFIXES = {'.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.svelte', '.vue', '.py', '.sh'}
NAME = re.compile(r'[A-Z][A-Z0-9_]*\Z')
VERSION = re.compile(r'v?\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9.-]+)?\Z')
IMPORT_HEAD = re.compile(r'''\b(?:from|import)\s*(?=["'`])|\b(?:require|import)\s*\(\s*(?=["'`])''')
HTTP_HEAD = re.compile(r'\b(?:fetch|(?:axios|requests|httpx)\.(?:get|post|put|patch|delete))\s*\(\s*')


def _path(value):
    if not isinstance(value, str) or not value or len(value) > 500 or any(c in value for c in '\\?\x00\r\n'):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or ':' in value:
        return None
    return path.as_posix()


def _area(path):
    p = PurePosixPath(path); chunks = {x.lower() for x in p.parts}
    if chunks & {'legacy', 'archive', 'archived', 'old', 'deprecated', 'backup', '_unused'}: return 'legacy'
    if chunks & {'test', 'tests', '__tests__', 'fixtures', 'e2e'} or re.search(r'\.(?:test|spec)\.', p.name): return 'tests'
    if chunks & {'examples', 'example', 'samples'} or p.name in ('.env.example', '.env.sample', '.env.template'): return 'examples'
    if p.suffix.lower() in {'.md', '.mdx', '.rst'} or chunks & {'docs', 'documentation'}: return 'docs'
    return 'active'


def _lex(text, suffix):
    comment = r'#[^\n]*' if suffix in ('.py', '.sh', '.yaml', '.yml', '.toml') else r'//[^\n]*|/\*[\s\S]*?\*/|<!--[\s\S]*?-->'
    token = re.compile(r'(?P<string>"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)|(?P<comment>' + comment + ')')
    clean = list(text); code = list(text); literals = []
    for match in token.finditer(text):
        blank = re.sub(r'[^\n]', ' ', match[0])
        code[match.start():match.end()] = blank
        if match.lastgroup == 'comment': clean[match.start():match.end()] = blank
        else: literals.append((match.start(), match.end(), match[0][1:-1]))
    return ''.join(clean), ''.join(code), literals


def _line(text, offset): return text.count('\n', 0, offset) + 1


def _package(name, packages=None):
    packages=PACKAGES if packages is None else packages
    if name in packages: return packages[name]
    base = '/'.join(name.split('/')[:2]) if name.startswith('@') else name.split('/')[0]
    return packages.get(base)


def _imports(clean, code, literals, suffix):
    result = []
    by_start = {start: value for start, _, value in literals}
    # Match the small introducer once, rather than rescan the full file prefix
    # for every string. This preserves comments/whitespace and ignores examples
    # inside literals because code masks those positions.
    for match in IMPORT_HEAD.finditer(clean):
        if match.end() in by_start and not code[match.start()].isspace():
            result.append((by_start[match.end()], _line(clean, match.end())))
    if suffix == '.py':
        for match in re.finditer(r'(?m)^\s*(?:from\s+([.\w]+)\s+import\b|import\s+([\w.]+))', code):
            result.append((match[1] or match[2], _line(clean, match.start())))
    return result


def _resolve(path, spec, sources, owner):
    parent = PurePosixPath(path).parent
    if spec.startswith('.'):
        candidate = str(parent / spec)
    elif spec.startswith('$lib/') and owner is not None:
        candidate = str(PurePosixPath(owner) / 'src/lib' / spec[5:])
    else: return None
    chunks = []
    for chunk in candidate.split('/'):
        if chunk == '..':
            if not chunks: return None
            chunks.pop()
        elif chunk not in ('', '.'): chunks.append(chunk)
    base = '/'.join(chunks)
    for option in [base, *[base + ext for ext in ('.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs', '.py')],
                   *[base + '/index' + ext for ext in ('.ts', '.js', '.tsx', '.jsx')]]:
        if option in sources: return option
    return None


def _owners(path, parts):
    candidates = [p for p in parts if p == '.' or path.startswith(p + '/')]
    return max(candidates, key=lambda p: len(PurePosixPath(p).parts)) if candidates else None


def _route(value):
    return isinstance(value, str) and value.startswith('/') and len(value) <= 300 and not re.search(r'[\s?#\\]|://', value)


def _routes(path, text, code, clean):
    result = []
    file_route = re.search(r'(?:^|/)(?:src/)?(?:routes/.*/?\+(?:server|page(?:\.server)?)|app/.*/?(?:route|page)|pages/.+)\.[^.]+$', path)
    # Root +server/page files are valid too; the .* above is deliberately optional.
    if file_route or re.search(r'(?:^|/)(?:routes/\+server|app/route)\.[^.]+$', path):
        candidate = route_path(path).removesuffix('/+page')
        methods = list(re.finditer(r'\bexport\s+(?:(?:async\s+)?function|(?:const|let))\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b', code))
        if _route(candidate):
            for method, line in [(m[1], _line(text, m.start())) for m in methods] or [('unknown', 1)]:
                result.append(dict(path=candidate, method=method, source=path, line=line))
    for match in re.finditer(r'\b(?:app|router|server|fastify)\.(get|post|put|patch|delete|head|options|all)\s*\(\s*(["\'])(/[^"\']*)\2', clean, re.I):
        if code[match.start():match.start()+3].strip() and _route(match[3]):
            result.append(dict(path=match[3], method=match[1].upper(), source=path, line=_line(text, match.start())))
    for match in re.finditer(r'@(?:app|router)\.(get|post|put|patch|delete|head|options)\s*\(\s*(["\'])(/[^"\']*)\2', clean, re.I):
        if code[match.start()] == '@' and _route(match[3]):
            result.append(dict(path=match[3], method=match[1].upper(), source=path, line=_line(text, match.start())))
    return result


def _settings(config):
    if config is None: return {}
    if not isinstance(config, dict): raise ValueError('integrations: konfiguracja musi być obiektem')
    runtime = config.get('runtime', config)
    if not isinstance(runtime, dict): raise ValueError('integrations: runtime musi być obiektem')
    settings = runtime.get('integrations', {})
    if isinstance(settings,dict): settings={k:v for k,v in settings.items() if k not in ('custom','learning')}
    if not isinstance(settings, dict): raise ValueError('integrations: wymagane mapowanie provider lub id')
    for key, value in settings.items():
        if not isinstance(key, str): raise ValueError('integrations: identyfikator strategii musi być tekstem')
        if not isinstance(value, dict) or value.get('strategy') not in STRATEGIES:
            raise ValueError('integrations: niepoprawna jawna strategia')
        if 'required_for_startup' in value and type(value['required_for_startup']) is not bool:
            raise ValueError('integrations: required_for_startup musi być bool')
    return settings


def inventory(sources, parts, config=None):
    """Build declarations and gaps from caller-supplied text, without execution."""
    if not isinstance(sources, dict) or not isinstance(parts, list): raise ValueError('integrations: wymagane sources i parts')
    settings = _settings(config); texts = {}; excluded = []; errors = []
    registry=load_registry(config); providers,packages,hosts,env_patterns=indexes(registry)
    from helix_runtime_adapters import recordings
    replay_records = recordings(config or {})
    adapter_config = (config or {}).get('runtime', {}).get('adapters', {})
    aliases={alias:r['provider'] for r in registry['providers'] for alias in r.get('recording_aliases',[])}
    replay_providers = {aliases.get(r['provider'],r['provider']) for r in replay_records}

    for path, text in sources.items():
        name = _path(path)
        if name is None or not isinstance(text, str):
            errors.append(dict(reason='niepoprawna ścieżka lub tekst źródła')); continue
        base = PurePosixPath(name).name
        if base == '.env' or base.startswith('.env.') and base not in ('.env.example', '.env.sample', '.env.template'):
            excluded.append(dict(path=name, reason='rzeczywisty plik env')); continue
        texts[name] = text
    roots = sorted(set(_path(p.get('path', '.')) for p in parts if isinstance(p, dict)) - {None})
    fingerprints = {}
    for path, text in texts.items():
        if PurePosixPath(path).name in ('.env.example', '.env.sample', '.env.template'):
            text = '\n'.join(re.findall(r'(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=', text))
        fingerprints[path] = hashlib.sha256(text.encode()).hexdigest()
    binding = dict(sources=fingerprints, parts=roots, registry_sha256=registry['sha256'],
                   settings={key: {k: value[k] for k in ('strategy', 'required_for_startup') if k in value} for key, value in settings.items()})
    binding['strategy_config_sha256']=hashlib.sha256(json.dumps(settings,sort_keys=True).encode()).hexdigest()
    binding['learning']=(config or {}).get('runtime',{}).get('integrations',{}).get('learning',False)
    if replay_records: binding['replay'] = [r['sha256'] for r in replay_records]
    plan_id = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
    lexed = {}; imports = {}; graph = {}; unresolved = {}; routes = []
    signals = []
    def signal(provider, path, line, kind, env=None, version=None):
        signals.append(dict(provider=provider, path=path, line=line, kind=kind, env=env, version=version))
    for path, text in sorted(texts.items()):
        suffix = PurePosixPath(path).suffix; base = PurePosixPath(path).name
        clean, code, literals = _lex(text, suffix); lexed[path] = (clean, code, literals)
        source_like = suffix in CODE_SUFFIXES or _area(path) == 'docs'
        imports[path] = _imports(clean, code, literals, suffix) if source_like else []
        graph[path] = []; unresolved[path] = []
        for spec, line in imports[path]:
            provider = _package(spec,packages)
            if provider: signal(provider, path, line, 'import')
            target = _resolve(path, spec, texts, _owners(path, roots))
            if target: graph[path].append(target)
            elif spec.startswith(('.', '$', '@/')): unresolved[path].append(dict(path=path, line=line, reason='nierozwiązany import lokalny'))
        if source_like:
            routes += _routes(path, text, code, clean)
            for name, line in _source_env(text, suffix):
                matched = [p for p, pattern in env_patterns.items() if re.search(pattern, name)]
                for provider in matched: signal(provider, path, line, 'env_use', env=name)
                if not matched and re.search(r'\b(?:fetch|axios|requests|httpx)\b', code) and name.endswith(('_URL', '_ENDPOINT', '_HOST')):
                    signal('unknown-http', path, line, 'unresolved_endpoint', env=name)
            by_start = {start: value for start, _, value in literals}
            for call in HTTP_HEAD.finditer(clean):
                if code[call.start()].isspace(): continue
                value = by_start.get(call.end())
                if value is not None:
                    host = re.match(r'https?://([^/@\s]+@)?([^/:?#\s]+)', value)
                    if host or not value.startswith('/'):
                        provider = host_provider(host[2].lower(),hosts) if host else 'unknown-http'
                        signal(provider, path, _line(text, call.end()), 'http_call')
                    continue
                argument = clean[call.end():clean.find(')', call.end()) if ')' in clean[call.end():] else len(clean)]
                if not any(re.search(pattern, name) for name, _ in _source_env(argument, suffix) for pattern in env_patterns.values()):
                    signal('unknown-http', path, _line(text, call.start()), 'unresolved_http_call')
            if re.search(r'\bnavigator\s*\.\s*credentials\s*\.\s*(?:create|get)\s*\(', code):
                signal('webauthn', path, 1, 'browser_credentials')
        if base == 'package.json':
            try: package = json.loads(text)
            except ValueError:
                errors.append(dict(path=path, reason='niepoprawny manifest JSON')); continue
            if not isinstance(package, dict): errors.append(dict(path=path, reason='manifest nie jest obiektem')); continue
            for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                deps = package.get(section, {})
                if not isinstance(deps, dict): continue
                for name, version in deps.items():
                    if provider := _package(name,packages):
                        offset = text.find(json.dumps(name)); line = _line(text, max(0, offset))
                        safe_version = version if isinstance(version, str) and re.fullmatch(r'[~^<>= v\d.*|+-]{1,80}', version) else None
                        signal(provider, path, line, 'package_' + section, version=safe_version)
        elif base.startswith('requirements') and suffix == '.txt' or base == 'pyproject.toml':
            for number, line in enumerate(clean.splitlines(), 1):
                for package, provider in packages.items():
                    if re.search(r'(?<![\w-])' + re.escape(package) + r'\s*(?:[<=>~!]|["\']?\s*(?:,|$))', line, re.I):
                        signal(provider, path, number, 'package_declaration')
        if suffix in ('.yaml', '.yml') or base.startswith('Dockerfile'):
            for match in re.finditer(r'(?im)^\s*(?:image:\s*|FROM\s+)["\']?([\w./-]+)(?::([\w.+-]+))?', clean):
                image = match[1].rsplit('/', 1)[-1].lower()
                provider = next((r['provider'] for r in registry['providers'] if image in r.get('images',[])),None)
                if provider: signal(provider, path, _line(text, match.start()), 'image', version=match[2] if match[2] and VERSION.fullmatch(match[2]) else None)
        declared={item['provider'] for item in signals if item['path']==path and item['kind'].startswith('package_')}
        for provider,line in manifest_signals(path,text,registry):
            if provider not in declared:signal(provider,path,line,'package_declaration')
        for provider,line,kind in source_signals(path,clean,code,registry): signal(provider,path,line,kind)
        names = []
        if base in ('.env.example', '.env.sample', '.env.template'):
            names = [(m[1], _line(text, m.start())) for m in re.finditer(r'(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=', text)]
        elif suffix in ('.yaml', '.yml'): names = list(_yaml_env_names(text.splitlines()))
        for name, line in names:
            for provider, pattern in env_patterns.items():
                if re.search(pattern, name): signal(provider, path, line, 'env_declaration', env=name)
    extra = []
    supplemental([(p, lexed[p][0]) for p in sorted(texts) if _area(p) == 'active'], extra)
    routes += [dict(path=r['path'], method=r['method'], source=r['file'], line=r['line']) for r in extra
               if _route(r['path']) and r['file'] in lexed and r['_offset'] < len(lexed[r['file']][1])
               and not lexed[r['file']][1][r['_offset']].isspace()]
    # Import closure is a conservative file-level relation, never a call trace.
    closures = {}
    for path in texts:
        seen = set(); pending = [path]
        while pending:
            current = pending.pop()
            if current in seen: continue
            seen.add(current); pending.extend(graph.get(current, []))
        closures[path] = seen
    grouped = {}
    for item in signals:
        path = item['path']; area = _area(path); scopes = set()
        owner = _owners(path, roots)
        if owner is not None: scopes.add(owner)
        if area == 'active':
            scopes.update(owner for source, reached in closures.items() if path in reached and _area(source) == 'active' and (owner := _owners(source, roots)) is not None)
        for scope in sorted(scopes) or [None]:
            key = (item['provider'], scope, area)
            grouped.setdefault(key, []).append(item)
    entries = []
    # Known Keycloak is not an additional generic OIDC service with a stub fallback.
    for provider, scope, area in list(grouped):
        if provider == 'oidc' and ('keycloak', scope, area) in grouped:
            grouped[('keycloak', scope, area)].extend(grouped.pop((provider, scope, area)))
    for (provider, scope, area), items in sorted(grouped.items(), key=lambda row: str(row[0])):
        kind, default, implemented = providers[provider]
        definition=next(r for r in registry['providers'] if r['provider']==provider)
        ident = provider + ':' + hashlib.sha256((str(scope) + '\0' + area).encode()).hexdigest()[:12]
        setting = settings.get(ident, settings.get(provider, {})); requested = setting.get('strategy')
        selected = requested or default
        node_part = any(p.get('path') == scope and p.get('package_manager') in ('npm','pnpm','yarn') for p in parts)
        if node_part and provider in replay_providers and selected in ('replay','record-replay'): implemented = True
        if selected in ('http-sink','record-replay','disable'): implemented=True
        if selected=='container' and setting.get('preset',definition.get('container')) in registry['containers']: implemented=True
        evidence = sorted({(s['path'], s['line'], s['kind']) for s in items})
        paths = {s['path'] for s in items}; affected = []; unresolved_paths = []
        for route in routes:
            if _area(route['source']) != area or _owners(route['source'], roots) != scope: continue
            if not closures.get(route['source'], set()) & paths: continue
            affected.append(dict(route, relation='direct_file' if route['source'] in paths else 'import_chain'))
        for source, reached in closures.items():
            if _owners(source, roots) == scope and reached & paths:
                unresolved_paths.extend(gap for dependency in reached for gap in unresolved[dependency])
        unresolved_paths += [dict(path=r['source'], line=r['line'], reason='dynamiczna trasa wymaga konkretnych wariantów runtime')
                             for r in affected if re.search(r'[:*{}\[\]]', r['path'])]
        if area == 'active' and not affected:
            unresolved_paths += [dict(path=path, line=1, reason='wpływ na trasy nieustalony; deklaracja nie jest śladem wykonania') for path in sorted(paths)]
        entry = dict(id=ident, plan_id=plan_id, provider=provider, kind=kind, family=definition['family'], area=area, parts=[] if scope is None else [scope],
                     evidence=[dict(path=p, line=l, kind=k, area=area) for p, l, k in evidence],
                     env_names=sorted({s['env'] for s in items if s['env']}),
                     declared_versions=sorted({s['version'] for s in items if s['version']}),
                     strategy=dict(requested=requested, selected=selected, resolution='explicit' if requested else 'proposed' if selected else 'unresolved',
                                   implemented=implemented and (selected == default or selected in ('http-sink','record-replay','disable') or selected=='container' and setting.get('preset',definition.get('container')) in registry['containers']),
                                   reason='jawny wybór; bez automatycznego fallbacku' if requested else 'propozycja dla wykrytego rodzaju; nie dowód wykonania'),
                     affected_paths=sorted(paths), affected_routes=_unique(affected), unresolved_paths=_unique(unresolved_paths),
                     required_for_startup=setting.get('required_for_startup') if area == 'active' else False,
                     execution=dict(status='not_run', readiness='unknown', actual_version=None, logs=[]),
                     coverage=dict(status='not_checked' if area == 'active' else 'not_applicable', tested_routes=[],
                                   untested_because=['brak dowodu wykonania integracji i tras'] if area == 'active' else ['źródło poza aktywnym kodem']))
        entries.append(entry)
    matched_settings = {key for entry in entries for key in (entry['id'], entry['provider'])}
    if settings.keys() - matched_settings:
        errors.append(dict(reason='część jawnych strategii nie pasuje do wykrytej integracji; nie zastosowano fallbacku'))
    return dict(schema_version=1, plan_id=plan_id, scope='source_declarations_only', status='INCOMPLETE' if errors or not texts else 'RECORDED',
                registry=dict(sha256=registry['sha256'],providers=[r['provider'] for r in registry['providers']]),integrations=entries, discovery=dict(files=len(texts), excluded=excluded, errors=errors,
                limitations=['relacje importów są statyczne; dynamiczne adresy i wywołania wymagają dowodu runtime',
                             'brak wykrycia nie potwierdza braku integracji; pakiet nie dowodzi aktywnego połączenia']))


def _unique(rows):
    return [json.loads(value) for value in sorted({json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows})]


def _validate_plan(plan):
    """Validate the inventory contract before reconciling caller-owned data."""
    if (not isinstance(plan, dict) or plan.get('schema_version') != 1 or not isinstance(plan.get('integrations'), list)
            or not isinstance(plan.get('plan_id'), str) or not re.fullmatch(r'[0-9a-f]{64}', plan['plan_id'])):
        raise ValueError('integrations: niepoprawny plan')
    seen = set()
    def require(condition):
        if not condition: raise ValueError('integrations: niepoprawny wpis planu')
    for entry in plan['integrations']:
        try:
            require(isinstance(entry, dict) and entry['provider'] in set(PROVIDERS)|set(plan.get('registry',{}).get('providers',[])))
            require(entry['plan_id'] == plan['plan_id'])
            ident = entry['id']; require(isinstance(ident, str) and re.fullmatch(r'[a-z0-9-]+:[0-9a-f]{12}', ident) and ident not in seen)
            seen.add(ident)
            require(entry['area'] in ('active', 'docs', 'legacy', 'tests', 'examples'))
            require(isinstance(entry['strategy'], dict) and entry['strategy']['selected'] in (*STRATEGIES, None))
            for name in ('affected_routes', 'unresolved_paths'):
                require(isinstance(entry[name], list))
            for route in entry['affected_routes']:
                require(isinstance(route, dict) and _route(route['path']) and route['method'] in METHODS and _path(route['source']))
                require(type(route['line']) is int and route['line'] > 0)
        except (KeyError, TypeError, ValueError):
            raise ValueError('integrations: niepoprawny wpis planu') from None


def execution_inventory(plan, receipts=None, *, run_id=None):
    """Reconcile sanitized explicit receipts, without promoting readiness to tests."""
    if plan is None:
        return dict(schema_version=1, status='NOT_RECORDED', integrations=[], receipt_errors=[], scope='execution_receipts')
    _validate_plan(plan)
    if run_id is not None and (not isinstance(run_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}', run_id)):
        raise ValueError('integrations: niepoprawny identyfikator bieżącego przebiegu')
    result = copy.deepcopy(plan); result['scope'] = 'execution_receipts'; errors = []
    result['run_id'] = run_id
    if receipts is None: receipts = []
    if not isinstance(receipts, list): raise ValueError('integrations: receipts musi być listą')
    by_id = {entry['id']: entry for entry in result['integrations']}
    for entry in by_id.values():
        entry['execution'] = dict(status='not_run', readiness='unknown', actual_version=None, logs=[])
        entry['coverage'] = dict(status='not_checked' if entry['area'] == 'active' else 'not_applicable', tested_routes=[],
                                untested_because=[] if entry['area'] == 'active' else ['źródło poza aktywnym kodem'])
    accepted = {}
    for index, receipt in enumerate(receipts):
        def invalid(reason): errors.append(dict(index=index, reason=reason))
        if not isinstance(receipt, dict) or not isinstance(receipt.get('integration_id'), str) or receipt['integration_id'] not in by_id:
            invalid('nieznany identyfikator integracji'); continue
        entry = by_id[receipt['integration_id']]
        if run_id is None or receipt.get('run_id') != run_id or receipt.get('plan_id') != plan['plan_id']:
            invalid('receipt nie potwierdza bieżących źródeł, konfiguracji i przebiegu'); continue
        if receipt.get('strategy') != entry['strategy']['selected'] or receipt.get('strategy') not in STRATEGIES:
            invalid('receipt nie potwierdza wybranej strategii'); continue
        if receipt.get('status') not in ('ready', 'completed', 'failed', 'blocked', 'incomplete', 'not_run'):
            invalid('niepoprawny status wykonania'); continue
        readiness = receipt.get('readiness', 'unknown')
        version = receipt.get('actual_version'); logs = receipt.get('logs', [])
        if readiness not in ('ready', 'failed', 'unknown') or version is not None and (not isinstance(version, str) or not VERSION.fullmatch(version)):
            invalid('niepoprawna gotowość lub wersja'); continue
        if not isinstance(logs, list) or any(not _path(log) or log == '.' for log in logs):
            invalid('niepoprawna ścieżka artefaktu'); continue
        tests = receipt.get('tested_routes', [])
        if not isinstance(tests, list): invalid('tested_routes musi być listą'); continue
        if receipt.get('disabled_verified') is True and not logs:
            invalid('wyłączenie wymaga ścieżki dowodu egzekwowania'); continue
        normalized = dict(status=receipt['status'], readiness=readiness, actual_version=version,
                          logs=sorted(set(logs)), disabled_verified=receipt.get('disabled_verified') is True)
        accepted.setdefault(entry['id'], []).append(normalized)
        known = {(r['path'], r['method']) for r in entry['affected_routes']}
        for test in tests:
            if not isinstance(test, dict) or test.get('integration_exercised') is not True:
                invalid('trasa nie potwierdza użycia integracji'); continue
            if not isinstance(test.get('route'), str) or not isinstance(test.get('method'), str) or (test['route'], test['method']) not in known or test.get('status') not in ('PASS', 'FAIL'):
                invalid('nieznana trasa lub wynik'); continue
            if not _path(test.get('evidence')) or test['evidence'] == '.':
                invalid('brak bezpiecznej ścieżki dowodu trasy'); continue
            entry['coverage']['tested_routes'].append(dict(route=test['route'], method=test['method'], status=test['status'], evidence=test['evidence']))
    for entry in result['integrations']:
        records = accepted.get(entry['id'], [])
        if records:
            latest = records[-1]
            entry['execution'] = dict(latest, receipts=len(records), logs=sorted({log for r in records for log in r['logs']}))
        if entry['area'] != 'active': continue
        coverage = entry['coverage']; coverage['tested_routes'] = _unique(coverage['tested_routes'])
        tested = {(r['route'], r['method']) for r in coverage['tested_routes']}
        missing = [r for r in entry['affected_routes'] if (r['path'], r['method']) not in tested]
        reasons = []
        if not records: reasons.append('brak receipt wykonania')
        if entry['strategy']['selected'] is None: reasons.append('nierozwiązana strategia integracji')
        if entry['strategy']['selected'] in ('disabled','disable'):
            reasons.append('integracja wyłączona; jej zachowanie nie było testowane' if records and records[-1]['disabled_verified'] else 'wyłączenie zadeklarowane, bez dowodu egzekwowania')
        if records and records[-1]['status'] in ('failed', 'blocked', 'incomplete', 'not_run'): reasons.append('wykonanie integracji nie zostało ukończone')
        if entry['strategy']['selected'] in ('http-sink','record-replay'):
            reasons.append('przechwyt lub replay nie potwierdza zachowania dostawcy; nietestowane')
        if missing: reasons.append('brak dowodu integracji dla części wykrytych tras')
        if entry['unresolved_paths']: reasons.append('wpływ części źródeł lub importów pozostaje nieustalony')
        if not entry['affected_routes']: reasons.append('brak rozpoznanych tras do potwierdzenia')
        if records and not tested: reasons.append('readiness lub start usługi nie potwierdzają wykonania tras')
        coverage['untested_because'] = reasons
        coverage['status'] = 'partial' if tested and reasons else 'tested' if tested else 'not_checked'
    result['receipt_errors'] = errors
    result['status'] = 'INCOMPLETE' if errors or result.get('status') == 'INCOMPLETE' or any(e['area'] == 'active' and e['coverage']['status'] != 'tested' for e in result['integrations']) else 'RECORDED'
    return result


reconcile = execution_inventory
