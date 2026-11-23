"""Pure Keycloak plans and synthetic realm dictionaries; no I/O or entropy.

identity_plan consumes already-read source text and the effective external config.
synthetic_realm takes one selected part plan plus private per-run material.
Mapper identifiers/config are pinned to official Keycloak 26.8.1 sources:
https://github.com/keycloak/keycloak/tree/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/mappers
https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/ProtocolMapperUtils.java
"""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from helix_runtime_integrations import _area, _lex, _path, _resolve
from helix_environment import _source_env

IMAGE = 'quay.io/keycloak/keycloak:26.8.1'
FIELDS = {'client_id', 'client_type', 'callback_paths', 'login_path', 'pkce', 'role_claim', 'roles', 'image', 'env_roles', 'screen_role', 'denied_roles'}
ENV_ROLES = ('issuer', 'idp_origin', 'app_origin', 'realm', 'client_id', 'client_secret', 'callback_uri')
RESERVED_ENV = frozenset({'PATH', 'HOME', 'SHELL', 'USER', 'LANG', 'TMPDIR', 'PWD', 'CI', 'HOST', 'HOSTNAME', 'PORT',
                        'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED',
                        'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'LD_LIBRARY_PATH', 'LD_PRELOAD',
                        'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
                        'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                        'BASH_ENV', 'ENV', 'ZDOTDIR', 'SSLKEYLOGFILE', 'OPENSSL_CONF'})
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}\Z')
STRING_FIELD = re.compile(r'''\b(?P<key>clientId|client_id|KEYCLOAK_CLIENT_ID|redirectUri|redirect_uri|callbackUrl|callbackURL|pkceMethod|code_challenge_method|token_endpoint_auth_method)['"]?\s*(?P<sep>[:=])\s*(?P<quote>['"])(?P<value>[^'"\r\n]*)\3''')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def _identifier(value):
    return isinstance(value, str) and bool(IDENTIFIER.fullmatch(value))


def validate_env_roles(value):
    """Validate names/roles only, without accepting values or process controls."""
    if not isinstance(value, dict): raise ValueError('identity: env_roles wymaga mapowania nazw na role')
    for name, role in value.items():
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]*', name) or name in RESERVED_ENV or
                name.startswith(('HELIX_', 'LD_', 'DYLD_', 'PYTHON', 'BASH_FUNC_', 'NODE_', 'NPM_CONFIG_', 'GIT_')) or
                re.search(r'(?:^|_)(?:DATABASE|POSTGRES|PGHOST|PGPORT|PGUSER|PGPASSWORD|PGDATABASE)(?:_|$)', name) or
                not isinstance(role, str) or role not in ENV_ROLES):
            raise ValueError('identity: niepoprawna lub zastrzeżona rola środowiska')
    return dict(sorted(value.items()))


def _callback(value):
    if not isinstance(value, str) or not value or re.search(r'\s|[\x00-\x1f\x7f]', value) or any(c in value for c in '*\\${}'):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme and (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password):
            return None
        if parsed.query or parsed.fragment or value.startswith('//'):
            return None
        path = parsed.path
        if not path.startswith('/') or any(part in ('.', '..') for part in path.split('/')) or '%' in path:
            return None
        return path
    except ValueError:
        return None


def _settings(config):
    config = {} if config is None else config
    if not isinstance(config, dict): raise ValueError('identity: konfiguracja wymaga obiektu')
    runtime = config.get('runtime', config)
    if not isinstance(runtime, dict): raise ValueError('identity: runtime wymaga obiektu')
    settings = runtime.get('keycloak', {})
    if not isinstance(settings, dict) or set(settings) - {'parts'}:
        raise ValueError('identity: obsługiwane jest wyłącznie keycloak.parts')
    values = settings.get('parts', {})
    if not isinstance(values, dict): raise ValueError('identity: keycloak.parts wymaga mapowania')
    for part, value in values.items():
        if _path(part) != part or not isinstance(value, dict): raise ValueError('identity: niepoprawny part config')
        if set(value) - FIELDS: raise ValueError('identity: nieobsługiwane pola part config; nie importuj realm ani sekretów')
        if 'env_roles' in value: validate_env_roles(value['env_roles'])
        # Rola, której sesją przebieg ogląda ekrany chronione (decyzja właściciela); bez deklaracji sesja nie opuszcza logowania.
        if 'screen_role' in value and (not isinstance(value['screen_role'], str) or not isinstance(value.get('roles'), list) or value['screen_role'] not in value['roles']):
            raise ValueError('identity: screen_role musi być jedną z zadeklarowanych ról')
        # role, którym aplikacja ma odmówić sesji (np. konto zarchiwizowane): odmowa jest wtedy wynikiem oczekiwanym
        if 'denied_roles' in value and (not isinstance(value['denied_roles'], list) or not isinstance(value.get('roles'), list)
                                        or not all(isinstance(role, str) and role in value['roles'] for role in value['denied_roles'])
                                        or value.get('screen_role') in value['denied_roles']):
            raise ValueError('identity: denied_roles muszą być zadeklarowanymi rolami innymi niż screen_role')
    return values


def _braces(code):
    stack = []; pairs = {}; enclosing = {}
    for offset, char in enumerate(code):
        if char == '{': stack.append(offset)
        elif char == '}' and stack: pairs[stack.pop()] = offset
        elif char == ':' and stack: enclosing[offset] = stack[-1]
    return pairs, enclosing


def _environment(text, clean, code, literals, suffix, braces):
    """Names only. A string argument counts only for a local proven env reader."""
    names = set(_source_env(text, suffix))
    aliases = {'process.env'}
    for match in re.finditer(r'''\bimport\s*\{\s*env(?:\s+as\s+(\w+))?\s*\}\s*from\s*['"]\$env/dynamic/(?:private|public)['"]''', clean):
        if not code[match.start()].isspace(): aliases.add(match[1] or 'env')
    helpers = set()
    for match in re.finditer(r'\bfunction\s+(\w+)\s*\(\s*(\w+)[^()]*\)\s*(?::[^{}]+)?\{', code):
        end = braces.get(match.end()-1)
        if end is None: continue
        body = code[match.end():end]
        if any(re.search(r'\b' + re.escape(alias) + r'\s*\[\s*' + re.escape(match[2]) + r'\s*\]', body) for alias in aliases):
            helpers.add(match[1])
    by_start = {start: value for start, _, value in literals}
    for match in re.finditer(r'\b(\w+)\s*\(\s*', clean):
        if match[1] in helpers and not code[match.start()].isspace() and match.end() in by_start:
            name = by_start[match.end()]
            if re.fullmatch(r'[A-Z][A-Z0-9_]*', name): names.add((name, text.count('\n', 0, match.end()) + 1))
    result = []
    for name, line in sorted(names):
        match = re.search(r'(?:^|_)(?:KEYCLOAK|KC)_(URL|REALM|CLIENT_ID|CLIENT_SECRET|ISSUER)$', name)
        if match:
            role = {'URL': 'idp_origin', 'REALM': 'realm', 'CLIENT_ID': 'client_id', 'CLIENT_SECRET': 'client_secret', 'ISSUER': 'issuer'}[match[1]]
            result.append(dict(name=name, role=role, line=line))
        elif re.search(r'(?:^|_)(?:APP|PUBLIC|SITE)(?:_BASE)?_(?:URL|ORIGIN)$', name):
            result.append(dict(name=name, role='app_origin', line=line))
    return result


def _role_arrays(texts, parsed, root):
    """Literal lists used by a local membership predicate, not label maps."""
    declarations = {}
    for path, text in texts.items():
        clean, code, _ = parsed[path]
        for match in re.finditer(r'\b(?:export\s+)?const\s+(\w+)\s*=\s*\[([^\[\]]*)\]', clean):
            if code[match.start()].isspace(): continue
            body = match[2]
            values = re.findall(r'''['"]([A-Za-z0-9][A-Za-z0-9_.:-]{0,99})['"]''', body)
            remainder = re.sub(r'''['"][A-Za-z0-9][A-Za-z0-9_.:-]{0,99}['"]''', '', body)
            if values and not remainder.replace(',', '').strip():
                declarations[path, match[1]] = (values, text.count('\n', 0, match.start()) + 1)
    found = []
    for path, text in texts.items():
        clean, code, _ = parsed[path]
        if not re.search(r'\b(?:realm_access|resource_access)\b', code): continue
        bindings = {name: (path, name) for source, name in declarations if source == path}
        for match in re.finditer(r'''\bimport\s*\{([^{}]*)\}\s*from\s*['"]([^'"\r\n]+)['"]''', clean):
            if code[match.start()].isspace(): continue
            source = _resolve(path, match[2], texts, root)
            for item in match[1].split(','):
                alias = re.fullmatch(r'\s*(\w+)(?:\s+as\s+(\w+))?\s*', item)
                if alias and (source, alias[1]) in declarations: bindings[alias[2] or alias[1]] = (source, alias[1])
        for name, key in bindings.items():
            # The array selects roles from an input membership list. Its literals
            # are a declared test matrix, not proof of production assignments.
            pattern = r'\b' + re.escape(name) + r'\s*\.\s*find\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*(?:roles|\w+Roles|\w+_roles)\s*\.\s*includes\s*\(\s*\1\s*\)'
            for usage in re.finditer(pattern, code):
                values, line = declarations[key]
                for value in values: found.append(dict(field='roles', value=value, source=key[0], line=line))
                found.append(dict(field='role_list_membership', value=True, source=path, line=text.count('\n', 0, usage.start())+1))
    return found


def _observations(texts, parsed=None, root='.'):
    observations = []; detected = False
    def add(field, value, path, text, offset):
        observations.append(dict(field=field, value=value, source=path, line=text.count('\n', 0, offset) + 1))
    for path, text in sorted(texts.items()):
        name = PurePosixPath(path).name
        suffix = PurePosixPath(path).suffix
        clean, code, literals = parsed[path] if parsed is not None else _lex(text, suffix)
        braces, enclosing = _braces(code)
        for binding in _environment(text, clean, code, literals, suffix, braces):
            detected |= binding['role'] != 'app_origin'
            observations.append(dict(field='environment_binding', value=binding, source=path, line=binding['line']))
        if name == 'package.json':
            try: package = json.loads(text)
            except (ValueError, TypeError): package = {}
            if isinstance(package, dict):
                detected |= any(isinstance(package.get(section), dict) and
                    bool(set(package[section]) & {'keycloak-js', 'keycloak-connect'}) for section in ('dependencies', 'devDependencies'))
        if re.search(r'\b(?:Keycloak|KEYCLOAK_[A-Z_]+|KC_(?:REALM|CLIENT|ISSUER))\b', code): detected = True
        for match in re.finditer(r'''\b(?:from|require|import)\s*(?:\(\s*)?['"](?:keycloak-js|keycloak-connect|keycloak)['"]''', clean):
            if not code[match.start()].isspace(): detected = True
        if suffix == '.py' and re.search(r'(?m)^\s*(?:from\s+keycloak\s+import\b|import\s+keycloak\b)', code): detected = True
        if suffix in ('.yaml', '.yml') or name.startswith('Dockerfile'):
            for match in re.finditer(r'''(?im)^\s*(?:image:\s*|FROM\s+)['"]?((?:[\w.-]+/)*keycloak(?::[^\s'"#]+)?)''', clean):
                add('image', match[1], path, text, match.start()); detected = True
        for match in STRING_FIELD.finditer(clean):
            if code[match.start('sep')].isspace(): continue  # example inside a string
            key, value = match['key'], match['value']
            if key in ('clientId', 'client_id', 'KEYCLOAK_CLIENT_ID'):
                field = 'client_id'
                start = enclosing.get(match.start('sep'))
                block = clean[start:braces[start]+1] if start in braces else ''
                grant = re.search(r'''\bgrant_type\s*:\s*['"](password|client_credentials)['"]''', block)
                if value == 'admin-cli' or grant: field = 'service_client'
            elif key in ('redirectUri', 'redirect_uri', 'callbackUrl', 'callbackURL'): field = 'callback_paths'; value = _callback(value)
            elif key == 'token_endpoint_auth_method':
                field = 'client_type'; value = {'none': 'public', 'client_secret_basic': 'confidential', 'client_secret_post': 'confidential'}.get(value)
            else: field = 'pkce'
            add(field, value, path, text, match.start())
        for match in re.finditer(r'\b(?:redirectUri|redirect_uri|callbackUrl|callbackURL)\s*[:=]\s*`([^`]*)`', clean):
            if code[match.start()].isspace(): continue
            # Only a single origin expression plus an exact static path is safe.
            template = re.fullmatch(r'\$\{\s*(?:origin|[A-Za-z_$][\w$]*\.origin)\s*\}(/[^${}]*)', match[1])
            if template is None:
                template = re.fullmatch(r'\$\{\s*[A-Za-z_$][\w$]*\.appUrl\s*\}(/[^${}]*)', match[1])
                if template:
                    # appUrl can contain a path prefix. Retain the static suffix
                    # as a candidate, requiring the owner's exact path contract.
                    add('callback_origin_unresolved', True, path, text, match.start())
            add('callback_paths', _callback(template[1]) if template else None, path, text, match.start())
        for match in re.finditer(r'''\b(?:publicClient|public-client)['"]?\s*(?P<sep>[:=])\s*(true|false)\b''', clean):
            if not code[match.start('sep')].isspace():
                add('client_type', 'public' if match[2] == 'true' else 'confidential', path, text, match.start())
        for match in re.finditer(r'''\brealm_access\s*(?:(?:\?\.)?\s*\[\s*['"]roles['"]\s*\]|\??\.\s*roles\b)''', clean):
            if not code[match.start()].isspace(): add('role_claim', 'realm_access.roles', path, text, match.start())
        for match in re.finditer(r'''\b(?P<function>hasRealmRole|hasResourceRole|requireRole|hasRole)\s*\(\s*(['"])(?P<role>[^'"\r\n]+)\2(?:\s*,\s*(['"])(?P<client>[^'"\r\n]+)\4)?''', clean):
            if code[match.start()].isspace(): continue
            add('roles', match['role'], path, text, match.start())
            if match['function'] == 'hasRealmRole': add('role_claim', 'realm_access.roles', path, text, match.start())
            if match['function'] == 'hasResourceRole': add('resource_client', match['client'], path, text, match.start())
        for match in re.finditer(r'\b(?:hasRealmRole|hasResourceRole|requireRole|hasRole)\s*\(\s*(?![\s\'\"])(?=\w)', clean):
            if not code[match.start()].isspace(): add('dynamic_roles', True, path, text, match.start())
        for match in re.finditer(r'''\bresource_access\s*(?:\?\.)?\s*\[\s*(['"])([^'"\r\n]+)\1\s*\]\s*\??\.\s*roles\b''', clean):
            if not code[match.start()].isspace(): add('resource_client', match[2], path, text, match.start())
        for match in re.finditer(r'\bresource_access\s*(?:\?\.)?\s*\[\s*[A-Za-z_$]', code):
            add('dynamic_role_claim', True, path, text, match.start())
    if parsed is not None: observations.extend(_role_arrays(texts, parsed, root))
    return detected, observations


def identity_plan(sources, parts, config=None):
    """Deterministic public blueprint, never proof of a running identity service."""
    if not isinstance(sources, dict) or not isinstance(parts, list): raise ValueError('identity: wymagane sources i parts')
    settings = _settings(config)
    roots = []
    for part in parts:
        value = _path(part.get('path', '.')) if isinstance(part, dict) else None
        if value is None: raise ValueError('identity: niepoprawna ścieżka części')
        if value not in roots: roots.append(value)
    if set(settings) - set(roots): raise ValueError('identity: config wskazuje nieznaną część')
    texts = {}; excluded = []
    for path, text in sources.items():
        name = _path(path)
        if name is None or not isinstance(text, str): raise ValueError('identity: niepoprawne źródło')
        base = PurePosixPath(name).name
        if (_area(name) != 'active' or base.startswith('.env') or
                re.search(r'(?i)(?:secret|credential|realm[-_.]?export)', base)):
            excluded.append(name); continue
        texts[name] = text
    def owner(path):
        matches = [root for root in roots if root == '.' or path.startswith(root + '/')]
        return max(matches, key=lambda root: len(PurePosixPath(root).parts)) if matches else None
    parsed = {path: _lex(text, PurePosixPath(path).suffix) for path, text in texts.items()}
    # Partition once. Root image declarations remain shared with nested apps.
    partitioned = {root: {path: text for path, text in texts.items() if owner(path) == root} for root in roots}
    observed = {root: _observations(local, parsed, root) for root, local in partitioned.items()}
    unowned = {path: text for path, text in texts.items() if owner(path) is None}
    _, all_observations = _observations(unowned, parsed)
    all_observations += [item for _, rows in observed.values() for item in rows]
    all_images = [row for row in all_observations if row['field'] == 'image']
    plans = []
    for root in sorted(roots):
        detected, found = observed[root]
        explicit = copy.deepcopy(settings.get(root, {}))
        if not detected and root not in settings: continue
        for row in all_images:
            parent = PurePosixPath(row['source']).parent
            if (parent == PurePosixPath('.') or parent == PurePosixPath(root) or parent in PurePosixPath(root).parents) and row not in found:
                found.append(copy.deepcopy(row))
        gaps = []; fields = {}; evidence = []
        def gap(field, reason): gaps.append(dict(field=field, reason=reason))
        for item in found: evidence.append({key: item[key] for key in ('field', 'source', 'line')})
        def resolve(field, many=False):
            inferred = list(dict.fromkeys(item['value'] for item in found if item['field'] == field))
            if None in inferred:
                # Jawna deklaracja rozstrzyga wartość dynamiczną, tak jak przy rolach i claimach.
                if field not in explicit: gap(field, 'dynamic_or_unsupported_source_value')
                inferred.remove(None)
            value = explicit.get(field, inferred if many else inferred[0] if len(inferred) == 1 else None)
            if field in explicit and inferred:
                expected = value if many and isinstance(value, list) else [value]
                if any(candidate not in expected for candidate in inferred): gap(field, 'explicit_source_conflict')
            if not many and len(inferred) > 1: gap(field, 'multiple_source_values')
            if value is None or many and not value: gap(field, 'missing_declaration')
            fields[field] = value
            return value
        client = resolve('client_id')
        env_bindings = [dict(row['value'], source=row['source']) for row in found if row['field'] == 'environment_binding']
        env_roles = validate_env_roles(explicit.get('env_roles', {row['name']: row['role'] for row in env_bindings}))
        if any(row['role'] == 'client_id' for row in env_bindings) and 'client_id' not in explicit:
            gap('client_id', 'environment_value_unresolved')
            # A separate literal does not resolve a configuration-dependent flow.
            client = fields['client_id'] = None
        kind = resolve('client_type')
        callbacks = resolve('callback_paths', True)
        if any(row['field'] == 'callback_origin_unresolved' for row in found) and 'callback_paths' not in explicit:
            gap('callback_paths', 'callback_origin_requires_explicit_contract')
        pkce = resolve('pkce')
        if pkce is False: fields['pkce'] = pkce = 'disabled'
        roles = resolve('roles', True)
        if any(row['field'] == 'role_list_membership' for row in found) and 'roles' not in explicit:
            gap('roles', 'static_membership_list_requires_explicit_role_contract')
        if any(row['field'] == 'dynamic_roles' for row in found) and 'roles' not in explicit:
            gap('roles', 'dynamic_roles_require_explicit_declaration')
        for item in [row for row in found if row['field'] == 'resource_client']:
            target = item['value'] or client
            found.append(dict(item, field='role_claim', value='resource_access.' + target + '.roles' if _identifier(target) else None))
        claim = resolve('role_claim')
        if any(row['field'] == 'dynamic_role_claim' for row in found) and 'role_claim' not in explicit:
            gap('role_claim', 'dynamic_claim_requires_explicit_declaration')
            if claim == 'realm_access.roles':
                gap('role_claim', 'mixed_claim_sources_require_explicit_contract')
                claim = fields['role_claim'] = None
        if not _identifier(client): gap('client_id', 'invalid_identifier')
        if kind not in ('public', 'confidential'): gap('client_type', 'unsupported_client_type')
        if not isinstance(callbacks, list) or not callbacks or any(not isinstance(value, str) or _callback(value) != value for value in callbacks): gap('callback_paths', 'exact_paths_required')
        if pkce not in ('S256', 'disabled'): gap('pkce', 'explicit_S256_or_disabled_required')
        if not isinstance(roles, list) or not roles or any(not _identifier(role) for role in roles): gap('roles', 'explicit_role_names_required')
        if claim not in ('realm_access.roles', 'resource_access.' + str(client) + '.roles'):
            gap('role_claim', 'custom_or_other_client_claim_not_supported')
        if claim != 'realm_access.roles' and isinstance(client, str) and '.' in client:
            gap('role_claim', 'dotted_client_identifier_requires_explicit_mapper_support')
        images = list(dict.fromkeys(row['value'] for row in found if row['field'] == 'image'))
        image = explicit.get('image', images[0] if len(images) == 1 else IMAGE)
        if len(images) > 1 or images and image not in images: gap('image', 'explicit_source_version_conflict')
        if image != IMAGE: gap('image', 'server_contract_not_supported; required_26.8.1_no_fallback')
        login = explicit.get('login_path')
        if login is not None and _callback(login) != login: gap('login_path', 'exact_path_required')
        identities = []
        if isinstance(roles, list) and roles and all(_identifier(role) for role in roles):
            fields['roles'] = sorted(set(roles))
            for role in fields['roles']:
                ident = 'role-' + _digest(role)[:12]
                identities.append(dict(id=ident, username='helix-' + ident, email_verified=True, app_roles=[role]))
            identities += [dict(id='no-app-role', username='helix-no-app-role', email_verified=True, app_roles=[]),
                           dict(id='unverified-email', username='helix-unverified-email', email_verified=False, app_roles=[fields['roles'][0]])]
        # Invalid explicit values are never retained in a public plan.
        safe = dict(client_id=client if _identifier(client) else None, client_type=kind if kind in ('public', 'confidential') else None,
                    callback_paths=sorted(set(callbacks)) if isinstance(callbacks, list) and all(isinstance(value, str) and _callback(value) == value for value in callbacks) else [],
                    pkce=pkce if pkce in ('S256', 'disabled') else None, role_claim=claim if claim in ('realm_access.roles', 'resource_access.' + str(client) + '.roles') else None,
                    roles=fields['roles'] if identities else [], login_path=login if _callback(login) == login else None)
        plan = dict(schema_version=1, provider='keycloak', part=root, status='BLOCKED' if gaps else 'READY',
                    strategy='container', fallback=None, image=image if isinstance(image, str) and re.fullmatch(r'[A-Za-z0-9./:_-]+', image) else None,
                    server_version='26.8.1' if image == IMAGE else None, image_basis='declared' if images or 'image' in explicit else 'ASSUMPTION_supported_default',
                    client=safe, identities=identities, gaps=gaps, evidence=evidence, env_bindings=env_bindings,
                    env_roles=env_roles, env_roles_basis='explicit' if 'env_roles' in explicit else 'source_declaration',
                    service_clients=[dict(client_id=row['value'], source=row['source'], line=row['line']) for row in found if row['field']=='service_client' and _identifier(row['value'])],
                    execution=dict(service_started=False, login_performed=False, tested_routes=[]),
                    constraints=['synthetic_only', 'loopback_callback_with_actual_port', 'private_per_run_material_required', 'no_stub_fallback',
                                 'unverified_email_is_negative_test_variant', 'app_tls_secure_cookie_coverage_not_proven'])
        plan['plan_id'] = _digest(plan)
        plans.append(plan)
    return dict(schema_version=1, status='BLOCKED' if any(p['status'] == 'BLOCKED' for p in plans) else 'READY' if plans else 'NOT_DETECTED',
                parts=plans, excluded=sorted(excluded), execution=dict(files_opened=0, commands=0, models=0, network=0))


def synthetic_realm(plan, material):
    """Return PRIVATE import data for one ready part; caller owns fresh entropy."""
    if not isinstance(plan, dict) or plan.get('provider') != 'keycloak' or plan.get('status') != 'READY' or plan.get('gaps'):
        raise ValueError('identity: wymagany kompletny plan pojedynczej części')
    expected = dict(plan); expected.pop('plan_id', None)
    if plan.get('plan_id') != _digest(expected): raise ValueError('identity: plan zmieniony po walidacji')
    if not isinstance(material, dict) or set(material) - {'realm', 'app_origin', 'user_passwords', 'client_secret'}:
        raise ValueError('identity: prywatny materiał ma nieobsługiwane pola')
    realm = material.get('realm'); origin = material.get('app_origin')
    if not isinstance(realm, str) or not re.fullmatch(r'helix-[a-zA-Z0-9_-]{8,80}', realm):
        raise ValueError('identity: wymagany syntetyczny realm helix z identyfikatorem przebiegu')
    try:
        parsed = urlsplit(origin)
        valid = (parsed.scheme in ('http', 'https') and parsed.hostname in ('127.0.0.1', 'localhost', '::1') and
                 parsed.port is not None and 1 <= parsed.port <= 65535 and not parsed.username and not parsed.password and
                 not parsed.path and not parsed.query and not parsed.fragment and origin == parsed.scheme + '://' + parsed.netloc)
    except (ValueError, TypeError): valid = False
    if not valid: raise ValueError('identity: wymagany dokładny loopback origin z rzeczywistym portem')
    passwords = material.get('user_passwords')
    identifiers = {row['id'] for row in plan['identities']}
    if not isinstance(passwords, dict) or set(passwords) != identifiers or any(not isinstance(value, str) or len(value) < 16 or '${' in value for value in passwords.values()):
        raise ValueError('identity: wymagane prywatne hasło per syntetyczna tożsamość')
    if len(set(passwords.values())) != len(passwords): raise ValueError('identity: hasła syntetyczne muszą być odrębne')
    client = plan['client']; cid = client['client_id']
    secret = material.get('client_secret')
    if client['client_type'] == 'confidential' and (not isinstance(secret, str) or len(secret) < 24 or '${' in secret or secret in passwords.values()):
        raise ValueError('identity: wymagany odrębny prywatny sekret klienta confidential')
    if client['client_type'] == 'public' and secret is not None:
        raise ValueError('identity: klient public nie przyjmuje sekretu')
    mapper = dict(name='helix-app-roles', protocol='openid-connect',
                  protocolMapper='oidc-usermodel-realm-role-mapper' if client['role_claim'] == 'realm_access.roles' else 'oidc-usermodel-client-role-mapper',
                  config={'claim.name': client['role_claim'], 'jsonType.label': 'String', 'multivalued': 'true',
                          'access.token.claim': 'true', 'id.token.claim': 'true', 'userinfo.token.claim': 'true'})
    if client['role_claim'] != 'realm_access.roles': mapper['config']['usermodel.clientRoleMapping.clientId'] = cid
    # Official 26.8.1 AudienceProtocolMapper: scope only this enabled synthetic
    # client. Configuration is not evidence of an issued or verified JWT.
    audience = dict(name='helix-client-audience', protocol='openid-connect', protocolMapper='oidc-audience-mapper',
                    config={'included.client.audience': cid, 'access.token.claim': 'true', 'id.token.claim': 'false',
                            'introspection.token.claim': 'false', 'lightweight.claim': 'false'})
    app = dict(clientId=cid, enabled=True, protocol='openid-connect', publicClient=client['client_type'] == 'public',
               standardFlowEnabled=True, implicitFlowEnabled=False, directAccessGrantsEnabled=False, serviceAccountsEnabled=False,
               redirectUris=[origin + path for path in client['callback_paths']], webOrigins=[origin],
               fullScopeAllowed=True, defaultClientScopes=['basic', 'profile', 'email'], optionalClientScopes=[], protocolMappers=[mapper, audience], attributes={})
    if client['pkce'] == 'S256': app['attributes']['pkce.code.challenge.method'] = 'S256'
    if client['client_type'] == 'confidential': app['secret'] = secret; app['clientAuthenticatorType'] = 'client-secret'
    realm_roles = client['role_claim'] == 'realm_access.roles'
    users = []
    for identity in plan['identities']:
        user = dict(username=identity['username'], enabled=True, email=identity['username'] + '@example.invalid',
                    firstName='Helix', lastName=identity['id'],
                    emailVerified=identity['email_verified'], requiredActions=[],
                    credentials=[dict(type='password', value=passwords[identity['id']], temporary=False)])
        if realm_roles: user['realmRoles'] = list(identity['app_roles'])
        else: user['clientRoles'] = {cid: list(identity['app_roles'])}
        users.append(user)
    role_definitions = [dict(name=role) for role in client['roles']]
    def property_mapper(attribute, claim, kind='String'):
        return dict(name='helix-' + claim, protocol='openid-connect', protocolMapper='oidc-usermodel-property-mapper',
                    config={'user.attribute': attribute, 'claim.name': claim, 'jsonType.label': kind,
                            'access.token.claim': 'true', 'id.token.claim': 'true', 'userinfo.token.claim': 'true'})
    # Zakres „basic” jak w domyślnym realmie Keycloak 25+: bez niego token dostępu nie ma sub ani auth_time
    # i aplikacja sprawdzająca te pola odrzuca sesję zaraz po udanym logowaniu (projekt A, przebieg 29).
    basic = dict(name='basic', protocol='openid-connect', attributes={'include.in.token.scope': 'false', 'display.on.consent.screen': 'false'}, protocolMappers=[
        dict(name='sub', protocol='openid-connect', protocolMapper='oidc-sub-mapper',
             config={'access.token.claim': 'true', 'introspection.token.claim': 'true'}),
        dict(name='auth_time', protocol='openid-connect', protocolMapper='oidc-usersessionmodel-note-mapper',
             config={'user.session.note': 'AUTH_TIME', 'claim.name': 'auth_time', 'jsonType.label': 'long',
                     'id.token.claim': 'true', 'access.token.claim': 'true', 'introspection.token.claim': 'true'})])
    scopes = [basic, dict(name='profile', protocol='openid-connect', protocolMappers=[property_mapper('username', 'preferred_username')]),
              dict(name='email', protocol='openid-connect', protocolMappers=[property_mapper('email', 'email'), property_mapper('emailVerified', 'email_verified', 'boolean')])]
    # Sesja w realmie przebiegu żyje dłużej niż najdłuższy przebieg: domyślne 30 minut bezczynności unieważniało sesje ról,
    # zanim Helix doszedł do porównania ról. Czas życia tokenu dostępu zostaje domyślny, więc odświeżanie w aplikacji nadal działa.
    return dict(realm=realm, enabled=True, sslRequired='all', registrationAllowed=False, resetPasswordAllowed=False,
                ssoSessionIdleTimeout=43200, ssoSessionMaxLifespan=43200,
                verifyEmail=False, loginWithEmailAllowed=False, duplicateEmailsAllowed=False, editUsernameAllowed=False,
                smtpServer={}, identityProviders=[], identityProviderMappers=[], userFederationProviders=[], components={},
                eventsListeners=[], defaultRoles=[], defaultGroups=[], clients=[app], clientScopes=scopes, users=users,
                roles={'realm': role_definitions} if realm_roles else {'client': {cid: role_definitions}})
