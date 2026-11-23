"""Conservative, offline source signals. Never import or execute target code."""
import os
import re
import json
from helix_contracts import VERSION
import helix_authz_routes as route_scopes
from pathlib import Path

SKIP = {'.git', '.aws', '.ssh', '.codex', '.agents', '.helix', 'node_modules', 'vendor', 'dist', 'build', 'coverage', '__pycache__', 'tests', 'fixtures', 'secrets'}
EXT = {'.ts', '.js', '.tsx', '.jsx', '.svelte', '.vue', '.py', '.go', '.php', '.rb', '.java', '.cs', '.sql', '.md'}


def sources(repo, include_tests=False):
    root = Path(repo).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('repo musi być katalogiem')
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if (d not in SKIP or (include_tests and d in {'tests', 'fixtures'})) and not d.startswith('.') and not (Path(directory) / d).is_symlink())
        for name in sorted(names):
            p = Path(directory) / name
            if p.is_symlink() or not p.is_file() or name.startswith('.') or re.search(r'secret|credential|private|\.min\.', name, re.I):
                continue
            if not include_tests and re.search(r'(?:^|/)(?:test|__tests__)/|[._](?:test|spec)\.', p.relative_to(root).as_posix()):
                continue
            if p.suffix in EXT:
                try:
                    yield p.relative_to(root).as_posix(), __import__('helix_audit_context').safe_read(p)
                except (OSError, UnicodeError):
                    continue


def mask(text):
    return re.sub(r'/\*.*?\*/|<!--.*?-->|(?m:^\s*//[^\n]*$)', lambda m: re.sub(r'[^\n]', ' ', m[0]), text, flags=re.S)


def finding(code, title, file, text, offset, why, fix, severity='high', confidence='possible', lens='security'):
    severity = 'medium' if confidence == 'possible' and severity in {'high', 'critical'} else severity
    line = text.count('\n', 0, offset) + 1
    return dict(lens=lens, id=code, title=title, severity=severity, confidence=confidence,
                file=file, line=line, source_offset=offset, why=why, fix=fix, evidence=[f'{file}:{line}'])


# Signals deliberately retain uncertainty: lexical absence is not a proof of reachability.
RULES = [
 ('SEC-SQL', 'Dynamiczne SQL', r'(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|["\'][^\n]*?["\']\s*\+|f["\'])', 'Input może zmieniać strukturę SQL.', 'Użyj parametrów zapytania.'),
 ('SEC-HTML', 'Niezaufany HTML', r'\{@html\s+|dangerouslySetInnerHTML\s*=|v-html\s*=', 'Sink HTML wymaga udowodnionej sanitacji.', 'Sanityzuj z allowlistą albo renderuj tekst.'),
 ('SEC-SHELL', 'Dynamiczne polecenie systemowe', r'(?:(?<![\w.])(?:exec|execSync)|(?:child_process|childProcess|cp)\.(?:exec|execSync)|os\.system|subprocess\.run)\s*\([^\n]*(?:req\.|request\.|\$\{|shell\s*=\s*True)', 'Polecenie może zawierać input użytkownika.', 'Użyj stałego programu i tablicy argumentów bez powłoki.'),
 ('SEC-PATH', 'Ścieżka z żądania', r'(?:readFile|writeFile|sendFile|open)\s*\([^\n]*(?:req\.|request\.|params\.)', 'Brak lokalnego dowodu ograniczenia ścieżki.', 'Rozwiąż ścieżkę i sprawdź, czy należy do katalogu bazowego.'),
 ('SEC-SSRF', 'URL z żądania', r'(?:fetch|axios\.get|requests\.get|http\.Get)\s*\(\s*(?:req\.|request\.|params\.)', 'Użytkownik może wybierać cel połączenia.', 'Allowlista hostów, kontrola DNS i przekierowań.'),
 ('SEC-REDIRECT', 'Przekierowanie z inputu', r'(?:redirect|Redirect)\s*\([^\n]*(?:req\.|request\.|searchParams|params\.)', 'Cel przekierowania może być zewnętrzny.', 'Dopuszczaj wyłącznie lokalne ścieżki lub jawne originy.'),
 ('SEC-HOST', 'Zaufanie do nagłówka Host', r'(?:https?://[^\n]*\$\{[^\n]*(?:host|Host)|(?:get|header)\(["\'](?:host|x-forwarded-host)["\']\))', 'Host może wpływać na linki i granice zaufania.', 'Korzystaj z skonfigurowanego originu.'),
 ('SEC-MASS', 'Mass assignment', r'(?:\.update|\.create|\.assign|\.insert)\s*\([^\n]*(?:req\.body|request\.body|\.\.\.body|\.\.\.data)', 'Pola role/tenant/is_admin mogą trafić do zapisu.', 'Zbuduj allowlistę pól; role i tenant wyznaczaj po stronie serwera.'),
 ('SEC-ROLE', 'Rola z inputu', r'(?:role|is_admin|tenant_id)\s*[:=]\s*(?:req\.body|body\.|request\.)', 'Klient wybiera pole uprawnień.', 'Wymagaj administracyjnej autoryzacji i przypisuj tenant z sesji.'),
 ('SEC-FAILOPEN', 'Fail-open autoryzacji', r'(?:role\s*(?:\|\||\?\?)\s*["\']admin["\']|(?:authorized|isAdmin)\s*=\s*true)', 'Domyślna wartość może nadawać uprawnienia.', 'Brak danych musi odmawiać dostępu.'),
 ('SEC-DEVBYPASS', 'Obejście developerskie', r'(?:SKIP_AUTH|DISABLE_AUTH|BYPASS_AUTH|DEV_AUTH)\b', 'Przełącznik wymaga dowodu niedostępności w produkcji.', 'Usuń bypass z artefaktu produkcyjnego.'),
 ('SEC-GRANT', 'Szerokie uprawnienia SQL', r'GRANT\s+(?:ALL|[^;]*\bUPDATE\b)[^;]*\bTO\s+(?:PUBLIC|anon|authenticated)\b', 'Szeroka rola otrzymuje zapis; RLS wymaga przeglądu.', 'Ogranicz GRANT i dodaj polityki zakresu.'),
 ('SEC-RLS', 'Otwarta polityka RLS', r'(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)', 'Polityka nie ogranicza wierszy.', 'Powiąż zakres z uwierzytelnionym użytkownikiem lub tenantem.'),
]


def analyze(repo, auth_sanity_percent=30, *, source_snapshot=None, engine='lexical'):
    if engine not in ('auto', 'lexical'):
        raise ValueError('engine musi mieć wartość auto albo lexical')
    files = list(sources(repo)) if source_snapshot is None else list(source_snapshot)
    from helix_guard_contracts import load as guard_contracts, call_pattern
    contracts = guard_contracts(repo)
    record_guards = contracts['record_context_guards']
    scope_helpers = inferred_scope_helpers(files, record_guards) | contracts['scope_guards']
    rows, routes, rbac, claims = [], [], [], []
    claim_contexts = []
    for file, raw in files:
        if file.endswith('.md'):
            matches = list(re.finditer(r'(?im)^.*?\b((?:SEC|VULN|FINDING|[A-Z]{2,8})-\d+)\b[^\n]*', raw))
            for i, m in enumerate(matches):
                claim_contexts.append(raw[m.start():matches[i+1].start() if i+1 < len(matches) else len(raw)])
                s = m[0]
                claims.append(dict(id=m[1], title=re.sub(r'[^\w .:-]', '', s)[:160],
                    severity=next((v for v in ('critical','high','medium','low','info') if v in s.lower()), 'unknown'),
                    declared_status=next((v for v in ('fixed','resolved','open','closed') if v in s.lower()), 'unknown'),
                    status='unknown', evidence=[f'{file}:{raw.count(chr(10), 0, m.start())+1}']))
            continue
        text = mask(raw)
        for code, title, pattern, why, fix in RULES:
            for m in re.finditer(pattern, text, re.I):
                if code == 'SEC-MASS' and hash_update(text, m.start()):
                    continue
                if code == 'SEC-SHELL' and re.match(r'exec\s*\(', m[0]) and re.search(r'(?:function\s+exec\s*\(|(?:const|let)\s+exec\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>)', text):
                    continue
                rows.append(finding(code, title, file, text, m.start(), why, fix))
        if file.endswith('.sql'):
            for m in re.finditer(r'(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b.*?(?:\$\$\s*;|$)', text):
                if re.search(r'SECURITY\s+DEFINER', m[0], re.I) and not re.search(r'SET\s+search_path\s*=', m[0], re.I):
                    rows.append(finding('SEC-DEFINER', 'SECURITY DEFINER bez search_path', file, text, m.start(), 'Nazwy obiektów mogą zależeć od search_path wywołującego.', 'Ustaw bezpieczny search_path i kwalifikuj obiekty.', confidence='likely'))
            for m in re.finditer(r'(?im)^.*\b(?:GRANT|POLICY|CREATE\s+TABLE\s+\w*roles?\w*)\b[^\n]*', text):
                entry = dict(file=file, line=text.count('\n',0,m.start())+1, kind='sql', evidence='Deklaracja uprawnień SQL; treść pominięta.')
                grant = re.search(r'GRANT\s+([A-Z, ]+)\s+ON\s+(?:TABLE\s+)?([\w.]+)\s+TO\s+([\w, ]+)',m[0],re.I)
                policy = re.search(r'POLICY\s+(\w+)\s+ON\s+([\w.]+)',m[0],re.I)
                if grant:
                    entry.update(principal=grant[3].strip()[:120],resource=grant[2][:120],permissions=grant[1].strip().upper()[:120])
                elif policy:
                    entry.update(policy=policy[1][:120],resource=policy[2][:120],scope='unrestricted' if re.search(r'(?:USING|CHECK)\s*\(\s*true',m[0],re.I) else 'unknown')
                rbac.append(entry)
        # Segment handlers so auth in one endpoint never blesses another endpoint.
        pattern = r'\b(?:app|router|server|fastify|api)\.(?:get|post|put|patch|delete|all)\s*\(|export\s+(?:async\s+function|const|function)\s+(?:GET|POST|PUT|PATCH|DELETE|load|actions|handle)\b|export\s+default\s+defineEventHandler\s*\(|@(?:app|router)\.(?:route|get|post|put|delete)\s*\(|(?:http\.)?HandleFunc\s*\(|@(?:Get|Post|Put|Patch|Delete)\s*\(|Route::(?:get|post|put|patch|delete)\s*\('
        hono = re.findall(r'\b(?:const|let)\s+(\w+)\s*=\s*new\s+Hono\b', text)
        if hono:
            pattern += r'|\b(?:' + '|'.join(map(re.escape, hono)) + r')\.(?:get|post|put|patch|delete|all)\s*\('
        starts = list(re.finditer(pattern, text))
        if not starts and re.search(r'(?:pages/api/|middleware\.[jt]s$|hooks\.server\.|\+page\.server\.|\+server\.)', file):
            starts = [re.match(r'', text)]
        if re.search(r'(?:hooks\.server\.|(?:^|/)middleware\.[jt]s$|/server/middleware/|\+layout\.server\.)', file):
            starts = []
        for i, m in enumerate(starts):
            chunk = route_scopes.handler_chunk(text, m.start(), starts[i+1].start() if i+1 < len(starts) else len(text), m[0])
            auth = re.search(call_pattern(contracts['identity_guards'] | contracts['middleware_factories']) + r'|if\s*\([^\n]*(?:!.*(?:session|user)|(?:session|user).*==\s*null)', chunk)
            data = re.search(r'\b(?:db|prisma|supabase|pool)\b[^\n]*\.(?:findUnique|findFirst|findMany|select|update|delete|query|from)\s*\(', chunk)
            role = re.search(r'role\s*===?\s*["\']([\w-]+)', chunk)
            line = text.count('\n',0,m.start())+1
            url = re.match(r'\s*["\']([^"\']+)', text[m.end():])
            route_path = url[1] if url else route_scopes.route_path(file)
            if m[0].startswith('@') and not m[0].startswith(('@app', '@router')):
                route_path = route_scopes.nest_path(text, m.start(), route_path)
            method = re.search(r'\b(GET|POST|PUT|PATCH|DELETE|ALL)\b', m[0], re.I)
            routes.append(dict(file=file, line=line, handler=m[0] or Path(file).name,
                _chunk=chunk, _offset=m.start(), path=route_path, method=method[1].upper() if method else 'unknown',
                _ast_start=m.start(), _ast_end=m.start()+len(chunk),
                auth='local_guard' if auth else 'unknown', required_role=role[1] if role else 'unknown'))
            if role:
                rbac.append(dict(file=file, line=line, kind='route_role', evidence='Wymagana rola: '+role[1]))
            if data and auth and auth.start() > data.start():
                rows.append(finding('SEC-AUTH-LATE', 'Autoryzacja po dostępie do danych',file,text,m.start()+data.start(),'Dostęp do danych poprzedza lokalny guard.', 'Sprawdzaj uprawnienia przed odczytem i zapisem.', confidence='likely'))
            # Transaction handles are often copied through a TypeScript cast.
            # Follow simple aliases only; an arbitrary tagged template is not SQL.
            sql_tags = {'sql', 'tx'}
            alias_pairs = re.findall(r'\b(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*(?:as\s+[^;\n]+)?[;\n]', chunk)
            for _ in range(len(alias_pairs)):
                for alias, source in alias_pairs:
                    if source in sql_tags:
                        sql_tags.add(alias)
            tag_pattern = '|'.join(re.escape(tag) for tag in sorted(sql_tags))
            object_data = data or re.search(r'\b(?:' + tag_pattern + r')(?:<[^;`]+>)?\s*`\s*(?:SELECT|UPDATE|DELETE|INSERT)\b', chunk, re.I)
            has_scope = row_scope(chunk, scope_helpers, record_guards)
            if object_data and re.search(r'(?:params|query|body|searchParams)\s*[.\[]', chunk) and not has_scope:
                rows.append(finding('SEC-IDOR','Obiekt z requestu bez lokalnego zakresu',file,text,m.start()+object_data.start(),'ID z żądania i operacja danych bez rozpoznanego zakresu właściciela/tenanta.', 'Dodaj owner/tenant do WHERE lub jawnie sprawdź własność.'))
            # Delegated reads can hide the database operation from local IDOR rules.
            delegated = re.search(r'\b(?:get|load|list|find)[A-Z]\w*\s*\(\s*(?:(?:event|req|request)\.)?params(?:\.\w+|\[\s*["\'][\w-]+["\']\s*\])', chunk)
            scoped_guard = has_scope
            if delegated and not scoped_guard:
                rows.append(finding('SEC-OBJECT-CALL', 'Identyfikator z trasy przekazany do odczytu',
                    file, text, m.start()+delegated.start(),
                    'Helper odczytu otrzymuje identyfikator z trasy bez rozpoznanego lokalnego guarda zakresu; sprawdź implementację helpera i middleware.',
                    'Zweryfikuj zakres obiektu przed wywołaniem lub wewnątrz helpera.', confidence='possible'))
        aliases = {}
        for m in re.finditer(r'\b(?:const|let|var)?\s*([A-Za-z_]\w*)\s*=\s*(?:await\s+)?(?:req|request|params|event)\.(?:body|query|params|json|formData|url|id)\b[^;\n]*', text):
            aliases[m[1]] = m.end()
        for alias, offset in aliases.items():
            tail = text[offset:offset+2000]
            for code, title, pattern in [
                ('SEC-SSRF','URL z aliasu inputu',r'(?:fetch|axios\.get|requests\.get)\s*\(\s*'),
                ('SEC-SHELL','Polecenie z aliasu inputu',r'(?:exec|execSync|os\.system)\s*\(\s*'),
                ('SEC-PATH','Ścieżka z aliasu inputu',r'(?:readFile|writeFile|sendFile|open)\s*\(\s*'),
                ('SEC-REDIRECT','Przekierowanie z aliasu inputu',r'(?:redirect|Redirect)\s*\(\s*')]:
                for sink in re.finditer(pattern+re.escape(alias)+r'\b',tail):
                    # Reassignment breaks this local one-hop trace.
                    if re.search(r'\b'+re.escape(alias)+r'\s*=(?!=)',tail[:sink.start()]):
                        continue
                    rows.append(finding(code,title,file,text,offset+sink.start(),
                        'Jednokrokowy alias inputu trafia do sinka; pełny przepływ i sanitacja wymagają weryfikacji.',
                        'Waliduj input allowlistą odpowiednią dla sinka.'))
        for m in re.finditer(r'\b(?:pin|otp)\b', text, re.I) if not file.endswith('.sql') else []:
            # Icon names, labels and unrelated neighbouring comparisons are not
            # authentication operations. Require an actual use of the variable.
            name = re.escape(m[0])
            operation = (r'\b'+name+r'\s*(?:[!=]={1,2}|\.length\b|=\s*(?:Math\.random|random\.)|,\s*(?:stored|expected|hash))'
                         r'|\b(?:verify\w*|check\w*|compare\w*|timingSafeEqual|compare_digest)\s*\([^;\n]*\b'+name+r'\b')
            line_start = text.rfind('\n', 0, m.start()) + 1
            line_end = text.find('\n', m.end())
            if not re.search(operation, text[line_start:line_end if line_end >= 0 else len(text)], re.I):
                continue
            context = text[max(0,m.start()-160):m.start()+400]
            issues = []
            if not re.search(r'rateLimit|rate_limit|throttle', context, re.I):
                issues.append('brak lokalnego dowodu rate limit')
            if not re.search(r'lockout|maxAttempts|failed_attempts', context, re.I):
                issues.append('brak lokalnego dowodu lockout')
            if re.search(r'===?|!==?', context) and not re.search(r'timingSafeEqual|compare_digest', context):
                issues.append('zwykłe porównanie zamiast stałoczasowego')
            if re.search(r'Math\.random|random\.randint', context):
                issues.append('generator nieprzeznaczony do sekretów')
            if re.search(r'length\s*(?:===?|<=?)\s*[1-4]\b|randint\(\s*0\s*,\s*9999\s*\)',context):
                issues.append('krótki kod')
            if re.search(r'(?:save|store|insert|update)\s*\([^\n]*\b(?:pin|otp)\b',context,re.I) and not re.search(r'hash|digest',context,re.I):
                issues.append('możliwy zapis jawnego kodu')
            if issues and re.search(r'==|random|length|save|store|compare_digest|timingSafeEqual', context, re.I):
                rows.append(finding('SEC-OTP','PIN/OTP wymaga ochrony',file,text,m.start(),
                    '; '.join(issues)+'. Kontrole zewnętrzne wymagają weryfikacji.',
                    'Dodaj bezpieczną losowość, hash, limit prób, expiry, lockout i bezpieczne porównanie.'))
                break
        upload_signals(file, text, starts, rows)
        trust_boundary_signals(file, text, rows)
    route_scopes.supplemental(files, routes)
    import helix_authz_patterns
    helix_authz_patterns.analyze(files, routes, rows, finding, _blocks, contracts['scope_guards'] | record_guards)
    auth_report = effective_guards(files, routes, rows, auth_sanity_percent)
    ast_report = structural_security(files, routes, rows, auth_report, auth_sanity_percent, engine, contracts)
    # A recognizable issue type and an inspected source location are needed for
    # negative correlation. Missing/excluded files never establish a likely fix.
    issue_types = {
        'SEC-SQL': r'sql injection|sqli|dynamiczne sql|wstrzyk\w* sql',
        'SEC-HTML': r'cross.site scripting|\bxss\b|niezaufany html',
        'SEC-IDOR': r'\bidor\b|\bbola\b|insecure direct object',
        'SEC-SSRF': r'\bssrf\b|server.side request forgery',
        'SEC-PATH': r'path traversal|directory traversal',
        'SEC-SHELL': r'command injection|shell injection',
        'SEC-REDIRECT': r'open redirect|otwarte przekierowanie',
    }
    known_ids = {rule[0] for rule in RULES} | {'SEC-IDOR', 'SEC-OBJECT-CALL', 'SEC-AUTH', 'SEC-DEFINER', 'SEC-OTP', 'SEC-UPLOAD'}
    source_names = {file for file, _ in files if not file.endswith('.md')}
    for claim, context in zip(claims, claim_contexts):
        codes = {code for code in known_ids if re.search(r'(?<![\w-])'+re.escape(code)+r'(?![\w-])', context)}
        codes.update(code for code, pattern in issue_types.items() if re.search(pattern, context, re.I))
        # Unclassified document IDs cannot be reconciled with security rules.
        # Keep them unknown without searching every repository path per ID.
        if not codes:
            continue
        # Match complete repository-relative paths, including Markdown links.
        referenced = {file for file in source_names if re.search(r'(?<![\w/.-])'+re.escape(file)+r'(?![\w/.-])', context)}
        mentioned_paths = set(re.findall(r'(?<![\w/.-])([\w./-]+\.(?:ts|tsx|js|jsx|py|go|sql|svelte|vue))(?=[:#`\s)\]]|$)', context))
        candidates = [f for f in rows if f['id'] in codes and (f['file'] in referenced if mentioned_paths else True)]
        if candidates:
            claim['status'] = 'open'
            claim['evidence'] += [f['evidence'][0] for f in candidates[:3]]
        elif codes and referenced and mentioned_paths <= source_names:
            claim['status'] = 'likely-fixed'
            claim['evidence'] += [f'{file}:1' for file in sorted(referenced)[:3]]
            claim['reason'] = 'Rozpoznany wzorzec nie występuje we wskazanym, przeskanowanym pliku; ocena heurystyczna, nie dowód naprawy.'
    return dict(helix_version=VERSION, schema_version=1, authz=auth_report, static_engine=ast_report, findings=rows, endpoints=routes, rbac=rbac, reported_findings=claims,
                scanned_files=len(files), offline_audits={
                    'secrets': {'status':'unknown', 'reason':'Nie czyta sekretów ani historii Git; brak bezpiecznie przygotowanego wyniku gitleaks.'},
                    'dependencies': {'status':'unknown', 'reason':'Brak skonfigurowanej lokalnej bazy advisories; bez sieci.'},
                    'semgrep': {'status':'fallback', 'reason':'Użyto reguł stdlib; zewnętrzne skanery nie są wymagane.'}})


def structural_security(files, routes, rows, auth_report, threshold, engine, contracts=None):
    """Replace the five calibrated families only where private AST facts exist."""
    contracts = contracts or {}
    record_guards = contracts.get('record_context_guards', ())
    identity_guards = contracts.get('identity_guards', ())
    import helix_security_ast_rules as rules
    if engine == 'auto':
        from helix_static_ast import analyze_snapshot
        result = analyze_snapshot(files)
    else:
        result = {'files': {}, 'public': {'engine': {'name': 'lexical', 'used': True},
                  'coverage': {'status': 'INCOMPLETE', 'reason': 'LEXICAL_REQUESTED'},
                  'usage': {'calls': 0, 'input_bytes': 0}}}
    raw_by_file = dict(files)
    parsed = {file: rules.analyze_file(file, raw_by_file[file], record, record_guards=record_guards, identity_guards=identity_guards)
              for file, record in result['files'].items() if record['status'] == 'PARSED'}
    from helix_ast_scope_helpers import build
    helpers = build(raw_by_file, result['files'], record_guards)
    from helix_ast_auth import build as auth_index
    ast_auth = auth_index(raw_by_file, result['files'])
    for file, analysis in parsed.items():
        for scope in analysis['scopes']:
            for effect in scope.calls:
                reason = helpers.guard_reason(file, scope, effect)
                if reason:
                    analysis['signals'] = [row for row in analysis['signals'] if not (row['id'] == 'SEC-IDOR' and row['offset'] == effect['start'])]
                    analysis['omissions'].append({'rule': 'SEC-IDOR', 'offset': effect['start'], 'reason': reason})
    titles = {r[0]: (r[1], r[4]) for r in RULES}
    titles.update({'SEC-IDOR': ('Obiekt z requestu bez lokalnego zakresu', 'Sprawdź zakres tego samego rekordu przed efektem lub ujawnieniem.'),
                   'SEC-UPLOAD': ('Upload bez lokalnych limitów', 'Odrzuć zły rozmiar i typ tego samego pliku przed zapisem.'),
                   'SEC-OTP': ('PIN/OTP wymaga ochrony', 'Egzekwuj bezpieczne porównanie, losowość i limity prób.')})
    def structurally_covered(row):
        if row['file'] not in parsed or row['id'] not in rules.TARGET_RULES - {'SEC-AUTH'}:
            return False
        if not row['file'].endswith('.svelte'):
            return True
        offset = row.get('source_offset')
        return isinstance(offset, int) and any(node['kind'] == 'program' and node['start'] <= offset < node['end']
                                                for node in result['files'][row['file']]['facts'])
    rows[:] = [row for row in rows if not structurally_covered(row)]
    omissions = []
    for file, analysis in parsed.items():
        raw = raw_by_file[file]
        for item in analysis['signals']:
            title, fix = titles[item['id']]
            row = finding(item['id'], title, file, raw, item['offset'], item['why'], fix)
            row['evidence_kind'] = 'ast_local_relation'
            rows.append(row)
        omissions.extend(dict(file=file, line=raw.count('\n', 0, item['offset'])+1,
                              rule=item['rule'], reason=item['reason'], status='local_candidate')
                         for item in analysis['omissions'])
    kept_routes = []
    for route in routes:
        file = route['file']
        start, end = route.pop('_ast_start', None), route.pop('_ast_end', None)
        if file not in parsed or start is None:
            route['evidence_kind'] = 'lexical_fallback'
            kept_routes.append(route)
            continue
        facts = result['files'][file]['facts']
        recognized_syntax = route['handler'].startswith('export') or bool(re.match(r'\w+\.(?:get|post|put|patch|delete|all)\s*\(', route['handler']))
        if recognized_syntax and not any(node['start'] == start and node['kind'] in {'export_statement', 'call_expression'} for node in facts):
            # A route-looking string, regex or comment has no executable node.
            continue
        kept_routes.append(route)
        candidates = [scope for scope in parsed[file]['scopes'] if scope.function
                      and start <= scope.function['start'] < end and scope.function['end'] <= end]
        # The outer handler owns this route, never a nested uncalled closure.
        outer = [scope for scope in candidates if not any(other is not scope and rules.contains(other.function, scope.function) for other in candidates)]
        scope = min(outer, key=lambda scope: scope.function['start']) if outer else None
        locals_found = [rules.auth_candidate(item) or ast_auth.local_candidate(file, item) for item in outer]
        for index, item in enumerate(outer):
            if locals_found[index] is None:
                reasons = [(effect, helpers.guard_reason(file, item, effect)) for effect in item.calls]
                candidate = next(((effect, reason) for effect, reason in reasons if reason), None)
                if candidate:
                    locals_found[index] = {'offset': candidate[0]['start'], 'reason': candidate[1]}
        local = locals_found[0] if locals_found and all(locals_found) else None
        if not local and scope:
            # Middleware factory must be an actual unconditional argument call
            # before the callback, not matching text or an optional expression.
            root_scopes = [s for s in parsed[file]['scopes'] if s.function is None]
            factories = [call for root_scope in root_scopes for call in root_scope.calls
                         if start <= call['start'] < call['end'] <= scope.function['start']
                         and rules.name(call) in contracts.get('middleware_factories', ())
                         and root_scope.direct(call)]
            if factories:
                local = {'offset': factories[0]['start'], 'reason': 'middleware_factory_candidate'}
        inherited = route.get('framework_guard_evidence', [])
        framework = ast_auth.framework_candidate(route)
        if framework:
            route['framework_guard_candidate'] = framework
            inherited = list(dict.fromkeys([*inherited, *framework['evidence']]))
            route['framework_guard_evidence'] = inherited
        route['guard_candidate'] = bool(local or inherited)
        route['auth'] = 'local_guard' if local else 'inherited_guard' if inherited else 'unknown'
        route['evidence_kind'] = 'ast_local_relation' if scope else 'lexical_fallback'
        route['local_guard_candidate'] = local
    routes[:] = kept_routes
    # Local syntax is not complete control flow, even for a direct guard.
    for route in routes:
        route['auth_status'] = 'unknown'
        route['confidence'] = 'possible'
        route['effective_guard']['status'] = 'unknown'
        route['reason'] = 'Kandydat składniowy wymaga weryfikacji wszystkich ścieżek i rzeczywistej polityki.'
    rows[:] = [row for row in rows if row['id'] != 'SEC-AUTH']
    candidates = [route for route in routes if not route['guard_candidate']]
    suspect = bool(routes and 100 * len(candidates) / len(routes) > threshold)
    if candidates:
        first = candidates[0]
        row = finding('SEC-AUTH', 'Trasy bez rozpoznanego guarda, do weryfikacji', first['file'], raw_by_file[first['file']], 0,
                      f'{len(candidates)}/{len(routes)} tras bez kandydata guarda; brak dopasowania nie dowodzi braku ochrony.',
                      'Zweryfikuj middleware i testy odmowy dostępu.')
        locations = [{key: route[key] for key in ('file', 'line', 'path', 'evidence_kind')} for route in candidates]
        row.update(line=first['line'], count=len(candidates), locations=locations, examples=locations[:5],
                   evidence=[f"{place['file']}:{place['line']}" for place in locations[:4]],
                   evidence_kinds=sorted({place['evidence_kind'] for place in locations}), detector_suspect=suspect)
        rows.append(row)
    for row in rows:
        if row['id'] in rules.TARGET_RULES:
            row.setdefault('evidence_kind', 'lexical_fallback' if row['id'] != 'SEC-AUTH' else 'aggregate')
            row['confidence'] = 'possible'
            if row['severity'] in {'high', 'critical'}:
                row['severity'] = 'medium'
    auth_report.update(proven_protected=0, unknown=len(routes), unprotected=0,
                       guard_candidates=sum(bool(route['guard_candidate']) for route in routes), detector_suspect=suspect)
    public = result['public']
    public['local_candidates'] = omissions
    public['rules'] = sorted(rules.TARGET_RULES)
    return public


def _blocks(text):
    """Named functions with bounded bodies; ambiguity never establishes protection."""
    pattern = r'\b(?:function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)(?:\s*:[^=;]+)?\s*=\s*(?:async\s*)?\()'
    for m in re.finditer(pattern, text):
        if m[2]:
            argument_end = route_scopes.balanced_end(text, m.end()-1)
            if argument_end is None or not re.match(r'\s*(?::[^=;]+)?=>\s*\{', text[argument_end:]):
                continue
        start = route_scopes.body_start(text[m.start():])
        if start < 0:
            continue
        start += m.start()
        end = route_scopes.balanced_end(text, start)
        if end is not None:
            yield m[1] or m[2], m.start(), text[start+1:end-1]


def row_scope(text, helpers=(), record_guards=()):
    """Recognized scope candidates; a permission name alone never blesses a row."""
    if re.search(r'\b(?:owner_id|ownerId|tenant_id|tenantId|org_id|organizationId|user_id|userId)\b\s*(?:=|:|IN\s*\()[^;\n]*(?:locals\.|session\.|user\.|actor\.|principal\.|request\.user|req\.user)', text):
        return True
    from helix_guard_contracts import call_pattern
    for match in re.finditer(call_pattern(record_guards), text):
        end = route_scopes.balanced_end(text, match.end()-1)
        if end is None:
            continue
        args = text[match.end():end-1]
        # Feature/action/resource precede explicit record context. A lone {row}
        # argument or module permission cannot satisfy this contract.
        if args.count(',') >= 3 and re.search(r'\{[^;]*\b(?:\w*Row|row|record|object|item|resource|entity|project)\s*:', args):
            return True
    return any(re.search(r'\b' + re.escape(name) + r'\s*\(', text) for name in helpers)


def inferred_scope_helpers(files, record_guards=()):
    from helix_guard_contracts import call_pattern
    functions = {}
    for file, raw in files:
        if file.endswith(('.md', '.sql')):
            continue
        text = mask(raw)
        for name, off, body in _blocks(text):
            opening = text.find('(', off)
            end = route_scopes.balanced_end(text, opening)
            parameters = text[opening+1:end-1] if end else ''
            # Merely reading a principal-scoped dashboard is not an enforcing
            # record guard. Require an object/id input and explicit enforcement.
            record_input = re.search(r'\b(?:\w*Id|id|record|object|item|resource|entity|project)\s*(?::|,|$)', parameters)
            enforcement = re.search(call_pattern(record_guards), body)
            functions.setdefault(name, []).append((body, bool(record_input and enforcement)))
    helpers = set()
    for _ in range(len(functions)+1):
        found = {name for name, bodies in functions.items()
                 if len(bodies) == 1 and name not in helpers and bodies[0][1] and row_scope(bodies[0][0], helpers, record_guards)}
        if not found:
            break
        helpers.update(found)
    return helpers


def hash_update(text, position):
    """Exclude crypto digests, retaining ORM writes and reassigned aliases."""
    prefix = text[:position]
    if re.search(r'\b(?:crypto\.)?createHash\([^;\n]*\)\s*$', prefix):
        return True
    receiver = re.search(r'\b(\w+)\s*$', prefix)
    if not receiver:
        return False
    assignments = list(re.finditer(r'\b' + re.escape(receiver[1]) + r'\s*=(?!=)\s*([^;\n]+)', prefix[:receiver.start()]))
    return bool(assignments and re.match(r'(?:crypto\.)?createHash\s*\(', assignments[-1][1]))


def upload_signals(file, text, starts, rows):
    if file.endswith('.sql'):
        return
    segments = [(m.start(), route_scopes.handler_chunk(text, m.start(), starts[i+1].start() if i+1 < len(starts) else len(text), m[0])) for i, m in enumerate(starts)]
    if not segments:
        segments = [(0, text)]
    for offset, body in segments:
        calls = list(re.finditer(r'\b(?:upload|multipart|formData)\s*\(', body))
        if not calls:
            continue
        explicit = re.search(r'\b(?:upload|multipart)\s*\(', body)
        # formData is equally common for dates, text and checkboxes.
        file_use = re.search(r'instanceof\s+File|\.arrayBuffer\s*\(|\b(?:writeFile|createWriteStream)\s*\(|\.files\b', body)
        if not explicit and not file_use:
            continue
        size = bool(re.search(r'\b(?:maxFileSize|fileSize)\b|\.size\s*[<>]=?\s*\w', body, re.I))
        mime = bool(re.search(r'\b(?:mimetype|allowedTypes)\b|content.type', body, re.I))
        # A sniffing call without an enforcing branch is only an observation.
        for probe in re.finditer(r'\b(?:const|let)\s+(\w+)\s*=\s*(?:await\s+)?(?:sniff\w*|fileTypeFrom\w*|detect\w*(?:Type|Image))\s*\(', body, re.I):
            tail = body[probe.end():]
            if re.search(r'if\s*\(\s*!\s*'+re.escape(probe[1])+r'\s*\)\s*(?:\{\s*)?(?:throw|return|abort)', tail):
                mime = True
        if not (size and mime):
            rows.append(finding('SEC-UPLOAD', 'Upload bez lokalnych limitów', file, text, offset+calls[0].start(),
                'Brak rozpoznanego limitu rozmiaru lub egzekwowanej kontroli typu w tym handlerze.',
                'Ogranicz rozmiar i sprawdzaj sygnaturę oraz typ pliku.'))


def trust_boundary_signals(file, text, rows):
    if file.endswith(('.sql', '.md')):
        return
    blocks = list(_blocks(text))
    bodies = [(off + route_scopes.body_start(text[off:]) + 1, body) for _, off, body in blocks] or [(0, text)]
    for offset, body in bodies:
        for match in re.finditer(r'if\s*\(\s*!(\w+)\s*\)\s*(?:\{\s*)?return\s+true\b', body):
            if re.search(r'\b[A-Za-z_$][\w$]*\s*\([^;]*\b'+re.escape(match[1])+r'\b', body[match.end():]):
                rows.append(finding('SEC-SCOPE-FAILOPEN', 'Brak zakresu pozwala na dostęp', file, text, offset+match.start(),
                    'Brak encji rodzica lub zakresu zwraca zgodę przed autoryzacją; sprawdź kompletność resolvera i kontrakt plików wspólnych.',
                    'Rozróżnij jawnie zasób publiczny od brakującego mapowania i odmawiaj przy nieznanym zakresie.'))
        for match in re.finditer(r'\b(?:rateLimitExhausted|isRateLimited|isLockedOut)\s*\(\s*(["\'])([^"\']+)\1', body):
            tail = body[match.end():]
            if (re.search(r'(?:pin|otp|password|sign.?in|login)', body, re.I)
                    and re.search(r'(?:throw|return)[^;\n]*429', tail)
                    and re.search(r'\b(?:verify\w*|find\w*By\w*(?:Pin|Otp)|compare\w*)\s*\([^;\n]*(?:pin|otp|password)', tail, re.I)):
                rows.append(finding('SEC-GLOBAL-LOCKOUT', 'Wspólny limit blokuje weryfikację logowania', file, text, offset+match.start(),
                    'Stały klucz limitu jest sprawdzany przed poświadczeniami; wyczerpanie puli może blokować poprawne logowania wszystkich użytkowników.',
                    'Zweryfikuj dostępność po wyczerpaniu wspólnego limitu i rozdziel budżety bez tworzenia oracle poprawnych kodów.'))
        for match in re.finditer(r'\bSELECT\b[^`]*?\bWHERE\s+email\s*=\s*\$\{(\w+)\.email\}[^`]*?\b\w*(?:identity|keycloak|subject|external|provider|oidc)\w*\s+IS\s+NULL', body, re.I):
            subject = re.escape(match[1])
            before = body[:match.start()]
            verified = re.search(r'if\s*\(\s*(?:'+subject+r'\.(?:emailVerified|email_verified)\s*!==?\s*true|!'+subject+r'\.(?:emailVerified|email_verified))\s*\)\s*(?:\{\s*)?(?:throw|return|abort)', before)
            if not verified:
                # A positive guard counts only while the lookup is within its
                # balanced body. An earlier, unrelated verified branch is not enough.
                for guard in re.finditer(r'if\s*\(\s*'+subject+r'\.(?:emailVerified|email_verified)\s*===\s*true\s*\)\s*\{', before):
                    end = route_scopes.balanced_end(body, guard.end()-1)
                    if end is not None and match.start() < end:
                        verified = guard
                        break
            link = re.search(r'\bUPDATE\b[^`]*?\b(?:identity|keycloak|subject|external|provider|oidc)\w*\s*=', body[match.end():], re.I)
            if link and not verified:
                rows.append(finding('SEC-EMAIL-LINK', 'Wiązanie tożsamości po niepotwierdzonym adresie', file, text, offset+match.start(),
                    'Profil bez identyfikatora dostawcy jest wyszukiwany po emailu i powiązywany z tożsamością bez wcześniejszego wymogu potwierdzonego emaila. Polityka dostawcy wymaga weryfikacji.',
                    'Przed powiązaniem istniejącego profilu wymagaj email_verified === true albo niezależnego potwierdzenia właściciela.'))


def _denies(text):
    return bool(re.search(r'(?:session|locals\.user|req\.user|request\.user|role|claims|is_authenticated)', text, re.I)
                and re.search(r'(?:throw|return|abort|raise)[^;\n]*(?:401|403)|redirect\s*\([^;\n]*(?:login|sign.?in|logowani)', text, re.I))


def effective_guards(files, routes, rows, threshold):
    if not 0 <= threshold <= 100:
        raise ValueError('auth_sanity_percent musi należeć do 0..100')
    texts = {f: mask(t) for f, t in files if not f.endswith('.md')}
    functions = {}
    for f, t in texts.items():
        for name, off, body in _blocks(t):
            functions.setdefault(name, []).append((f, off, body))
    guards = {}
    # Only unique symbols; imported aliases/dynamic dispatch remain unknown.
    for _ in range(len(functions) + 1):
        changed = False
        for name, defs in functions.items():
            if name in guards or len(defs) != 1:
                continue
            f, off, body = defs[0]
            deps = [n for n in guards if re.search(r'\b'+re.escape(n)+r'\s*\(', body)]
            if _denies(body) or deps:
                guards[name] = [f'{f}:{texts[f].count(chr(10), 0, off)+1}'] + [e for n in deps for e in guards[n]]
                changed = True
        if not changed:
            break

    def evidence(body):
        return list(dict.fromkeys(e for n, chain in guards.items()
                                  if re.search(r'\b'+re.escape(n)+r'\s*(?:\(|[,\)]|$)', body)
                                  for e in chain))

    candidates = []
    for route in routes:
        explicit = route_scopes.explicit_framework_candidates(route['file'], texts[route['file']], route, route['_offset'])
        chunk = route.pop('_chunk')
        off = route.pop('_offset')
        f = route['file']; t = texts[f]
        route_scopes.enrich(route, texts)
        chain = evidence(chunk)
        if _denies(chunk):
            chain.append(f"{f}:{route['line']}")
        # Framework boundaries are scoped to the nearest application tree.
        scopes = explicit[:]
        for boundary, body in texts.items():
            framework = route_scopes.boundary_scope(boundary, body, f, route['path'], route['method']) is True
            if framework and (evidence(body) or _denies(body)):
                # Matchers, route branches and layout rendering cannot prove all paths.
                scopes += [f'{boundary}:1'] + evidence(body)
        # Registration before this handler, same receiver, with path prefix.
        receiver = re.match(r'(\w+)\.', route['handler'])
        if receiver:
            pat = r'\b'+re.escape(receiver[1])+r'\.(?:use|addHook)\s*\(([^;]+)\)\s*;'
            for m in re.finditer(pat, t[:off]):
                arg = m[1]
                prefix = re.match(r'\s*["\']([^"\']+)["\']\s*,', arg)
                if prefix and not (route['path'] == prefix[1] or route['path'].startswith(prefix[1].rstrip('/')+'/')):
                    continue
                if evidence(arg) or _denies(arg):
                    scopes += [f'{f}:{t.count(chr(10),0,m.start())+1}'] + evidence(arg)
        # Explicit framework guard declarations are evidence candidates, not execution proof.
        route['guard_evidence'] = list(dict.fromkeys([f"{f}:{route['line']}"] + chain + scopes))
        route['framework_guard_evidence'] = list(dict.fromkeys(scopes))
        route['auth_status'] = 'unknown'
        route['effective_guard']['evidence'] = list(dict.fromkeys(chain + scopes))
        # Only a straight-line, locally defined guard before the first data effect
        # is proven for this lexical handler. Global registration is still a candidate.
        first = re.match(r'(?:[^{}]*?=>|export\s+(?:async\s+)?function\s+\w+\([^{}]*?\))\s*\{\s*(?:await\s+)?(\w+)\(\s*[\w.]+(?:\s*,\s*[\w.]+)*\s*\);', chunk)
        if first and first[1] in functions and len(functions[first[1]]) == 1:
            gf, go, gb = functions[first[1]][0]
            # Require an explicit deny and no bypass/early return/dispatch.
            if gf == f and _denies(gb) and re.search(r'if\s*\(\s*!(?:req\.user|event\.locals\.user|session|user)\s*\)', gb) and re.fullmatch(r'\s*if\s*\([^{};]+\)\s*(?:throw|raise)[^;{}]+;?\s*', gb):
                route['auth_status'] = 'proven-guarded'
                route['effective_guard']['status'] = 'proven-guarded'
        route['confidence'] = 'likely' if route['auth_status'] == 'proven-guarded' else 'possible'
        route['reason'] = ('VERIFIED: bezpośrednia lokalna odmowa braku użytkownika przed efektem; zakres wierszy i produkcja wymagają weryfikacji.' if route['auth_status'] == 'proven-guarded' else 'ASSUMPTION: statyka nie dowodzi wszystkich ścieżek ani poprawności authz.')
        if chain or scopes or route['auth'] == 'local_guard':
            route['auth'] = 'local_guard' if chain or route['auth'] == 'local_guard' else 'inherited_guard'
            route['guard_candidate'] = True
        else:
            route['guard_candidate'] = False
            candidates.append(route)
    # Unknown routes are grouped, never promoted to HIGH by lexical absence.
    suspect = bool(routes and 100 * len(candidates) / len(routes) > threshold)
    if candidates:
        first = candidates[0]
        row = finding('SEC-AUTH', 'Podejrzenie błędu detektora' if suspect else 'Trasy bez rozpoznanego guarda — do weryfikacji',
                      first['file'], texts[first['file']], 0,
                      f'{len(candidates)}/{len(routes)} tras bez lokalnego lub odziedziczonego kandydata guarda. '
                      + ('Przekroczono próg sanity; sprawdź nierozpoznaną integrację frameworka.' if suspect else 'Brak dopasowania nie dowodzi braku ochrony.'),
                      'Zweryfikuj middleware, call graph i testy odmowy dostępu.', severity='medium')
        row.update(line=first['line'], evidence=[f"{r['file']}:{r['line']}" for r in candidates[:5]],
                   count=len(candidates), examples=[{k:r[k] for k in ('file','line','path')} for r in candidates[:5]],
                   locations=[{k:r[k] for k in ('file','line','path')} for r in candidates], detector_suspect=suspect)
        rows.append(row)
    for f, t in texts.items():
        token_toctou(f, t, rows)
    return dict(proven_protected=sum(r['auth_status'] == 'proven-guarded' for r in routes), unknown=sum(r['auth_status'] == 'unknown' for r in routes), unprotected=sum(r['auth_status'] == 'unguarded' for r in routes),
                guard_candidates=sum(r['guard_candidate'] for r in routes),
                sanity_percent=threshold, detector_suspect=suspect,
                limitation='Odrzucenie alarmów ≠ dowód poprawności authz. Kandydat guarda nie dowodzi dominacji na każdej ścieżce; statyka nie daje punktów za brak alarmu.')


def token_toctou(file, text, rows):
    # Bound the signal to a function body rather than unrelated file-wide keywords.
    bodies = list(_blocks(text)) or [('', 0, text)]
    for _, off, body in bodies:
        read = re.search(r'(?:findUnique|findFirst|findOne|SELECT|\.get)\b', body, re.I)
        check = re.search(r'\b(?:used|consumed|redeemed|used_at|usedAt)\b', body, re.I)
        write = re.search(r'(?:\.update|\.save|UPDATE|\.delete)\b', body, re.I)
        if not (read and check and write and read.start() < check.start() < write.start()
                and re.search(r'token|invite|invitation|magic.?link|coupon|reset|zaproszeni|kupon', body, re.I)):
            continue
        atomic = re.search(r'FOR\s+UPDATE|\b(?:transaction|atomic)\s*\(|UPDATE\b[\s\S]*WHERE\b[\s\S]*(?:used|consumed|redeemed)\s*=\s*(?:false|0|NULL)[\s\S]*RETURNING|updateMany\s*\([^;]*where\s*:[^;]*(?:used|consumed)\s*:\s*false', body, re.I)
        if atomic:
            continue
        rows.append(finding('SEC-TOKEN-TOCTOU', 'Możliwy wyścig jednorazowego tokenu', file, text, (text.find('{', off)+1 if _ else off)+read.start(),
                            'Odczyt, sprawdzenie zużycia i zapis są oddzielone; brak lokalnego dowodu atomowego zajęcia tokenu. Do weryfikacji: izolacja transakcji i ograniczenia DB.',
                            'Atomowo zajmij token: UPDATE … WHERE used=false RETURNING; sprawdź liczbę wierszy, albo blokada SELECT FOR UPDATE w transakcji.', confidence='possible'))
