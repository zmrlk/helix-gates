"""Projekt na Supabase: przygotowanie lokalnej bazy z tego, co jest w repozytorium.

Migracje projektu prowadzonego z panelu (Lovable, Supabase Studio) często nie odtwarzają bazy od zera: część tabel
powstała poza migracjami, a migracje wołają produkcję po adresie wpisanym na stałe. Ten moduł:
- zaślepia każdy adres zewnętrzny w kopii migracji (lokalna baza nie może wołać produkcji),
- ustawia migracje w kolejności znacznika czasu niezależnie od formatu nazwy pliku,
- odtwarza z wygenerowanych typów aplikacji (`types.ts`) tabele i typy wyliczeniowe, których żadna migracja nie tworzy.
Odtworzony schemat jest przybliżeniem (bez ograniczeń, polityk i funkcji spoza migracji); raport podaje jego zakres.
"""
import re

BLOCKED = 'http://helix-blocked.invalid'
_URL = re.compile(r'https?://(?!(?:localhost|127\.0\.0\.1|helix-blocked\.invalid|kong|supabase_)[:/\'"]?)[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?')
_TOKEN = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')


def blind(sql):
    """Adresy zewnętrzne i tokeny JWT wpisane w SQL zastąpione zaślepką; zwraca (tekst, liczba adresów, liczba tokenów)."""
    text, urls = _URL.subn(BLOCKED, sql)
    text, tokens = _TOKEN.subn('helix-blocked-token', text)
    return text, urls, tokens


def ordered(names):
    """Pliki migracji w kolejności znacznika czasu (14 cyfr na początku nazwy); pliki bez znacznika na końcu, po nazwie."""
    stamp = lambda name: (0, name[:14], name) if re.match(r'\d{14}', name) else (1, '', name)
    return sorted((name for name in names if name.endswith('.sql')), key=stamp)


def _block(text, start):
    """Zawartość nawiasu klamrowego otwartego na pozycji start (indeks znaku '{')."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == '{': depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0: return text[start + 1:index]
    raise ValueError('unbalanced types file')


def _section(text, name):
    found = re.search(r'\b' + name + r': \{', text)
    return _block(text, found.end() - 1) if found else ''


def _entries(body):
    """Pary (nazwa, treść) pierwszego poziomu w bloku `nazwa: {...}` albo `nazwa: wartość`."""
    index, out = 0, []
    pattern = re.compile(r'\s*"?([A-Za-z_][A-Za-z0-9_]*)"?(\??):\s*')
    while True:
        found = pattern.match(body, index)
        if not found: break
        start = found.end()
        if body[start:start + 1] == '{':
            value = _block(body, start); index = start + len(value) + 2
        else:
            depth, index = 0, start
            while index < len(body) and not (depth == 0 and body[index] == '\n' and not body[index + 1:].lstrip().startswith('|')):
                depth += body[index] in '{[('; depth -= body[index] in '}])'; index += 1
            value = body[start:index].strip().rstrip(';,')
        out.append((found.group(1), found.group(2) == '?', value))
    return out


def parse_types(text):
    """Tabele i typy wyliczeniowe schematu public z pliku typów generowanego przez Supabase."""
    public = _section(text, 'public')
    enums = {name: re.findall(r'"([^"]*)"', value) for name, _, value in _entries(_section(public, 'Enums'))}
    tables, relations = {}, []
    for name, _, body in _entries(_section(public, 'Tables')):
        row = _entries(_section(body, 'Row'))
        optional = {column for column, maybe, _ in _entries(_section(body, 'Insert')) if maybe}
        links = set(re.findall(r'columns: \["([A-Za-z0-9_]+)"\]', body))
        tables[name] = [dict(name=column, type=kind, optional=column in optional, link=column in links) for column, _, kind in row]
        for key, column, target, other in re.findall(r'foreignKeyName: "([A-Za-z0-9_]+)"\s+columns: \["([A-Za-z0-9_]+)"\]\s+(?:isOneToOne: \w+\s+)?referencedRelation: "([A-Za-z0-9_]+)"\s+referencedColumns: \["([A-Za-z0-9_]+)"\]', body):
            relations.append(dict(table=name, name=key, column=column, target=target, target_column=other))
    return dict(tables=tables, enums=enums, relations=[row for row in relations if row['target'] in tables])


def _column(column, enums):
    kind = column['type']; nullable = bool(re.search(r'\|\s*null\b', kind)); kind = re.sub(r'\s*\|\s*null\b', '', kind).strip()
    array = kind.endswith('[]'); kind = kind[:-2] if array else kind
    name = column['name']; enum = re.search(r'\["Enums"\]\["([A-Za-z0-9_]+)"\]', kind)
    if enum and enum.group(1) in enums: sql, default = 'public."' + enum.group(1) + '"', "'" + (enums[enum.group(1)] or [''])[0].replace("'", "''") + "'"
    elif kind == 'number' and (name == 'id' or column['link']): sql, default = 'bigint', '0'
    elif kind == 'number': sql, default = 'numeric', '0'
    elif kind == 'boolean': sql, default = 'boolean', 'false'
    elif kind == 'string' and (name == 'id' or column['link'] or name.endswith('_id')): sql, default = 'uuid', 'gen_random_uuid()'
    elif kind == 'string' and name.endswith('_at'): sql, default = 'timestamptz', 'now()'
    elif kind == 'string' and re.search(r'(^|_)date$', name): sql, default = 'date', 'current_date'
    elif kind == 'string': sql, default = 'text', "''"
    else: sql, default = 'jsonb', "'{}'::jsonb"
    if array: sql, default = sql + '[]', "'{}'"
    text = '"' + name + '" ' + sql
    if name == 'id': text += ' PRIMARY KEY'
    if not nullable and column['optional']: text += ' DEFAULT ' + default
    if not nullable and name != 'id': text += ' NOT NULL'
    return text


def reconcile(types_text):
    """SQL po migracjach: kolumny i powiązania, które typy aplikacji znają, a baza z migracji ich nie ma (dodane kiedyś poza
    migracjami). Bez nich API odrzuca zapytania ekranów o brakującą kolumnę albo o dane z tabeli powiązanej."""
    parsed = parse_types(types_text); lines = []
    for name in sorted(parsed['tables']):
        for column in parsed['tables'][name]:
            definition = _column(column, parsed['enums']).replace(' PRIMARY KEY', '').replace(' NOT NULL', '')
            lines.append('ALTER TABLE public."' + name + '" ADD COLUMN IF NOT EXISTS ' + definition + ';')
    for row in parsed['relations']:
        lines.append('ALTER TABLE public."%s" ADD CONSTRAINT "%s" FOREIGN KEY ("%s") REFERENCES public."%s" ("%s") NOT VALID;' % (row['table'], row['name'], row['column'], row['target'], row['target_column']))
    return '\n'.join(lines) + '\n', len(parsed['relations'])


def created(sql):
    """Nazwy tabel i typów tworzonych przez podany SQL (schemat public albo bez schematu)."""
    tables = {name.lower() for name in re.findall(r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?(\w+)"?', sql, re.I)}
    kinds = {name.lower() for name in re.findall(r'create\s+type\s+(?:"?public"?\.)?"?(\w+)"?', sql, re.I)}
    return tables, kinds


def bootstrap(types_text, migrations_sql):
    """SQL tworzący tabele i typy obecne w typach aplikacji, a nietworzone przez żadną migrację; zwraca (sql, tabele, typy)."""
    parsed = parse_types(types_text); tables, kinds = created(migrations_sql)
    enums = sorted(name for name in parsed['enums'] if name.lower() not in kinds)
    missing = sorted(name for name in parsed['tables'] if name.lower() not in tables)
    lines = ['CREATE TYPE public."' + name + '" AS ENUM (' + ', '.join("'" + value.replace("'", "''") + "'" for value in parsed['enums'][name]) + ');' for name in enums]
    for name in missing:
        lines.append('CREATE TABLE IF NOT EXISTS public."' + name + '" (\n  ' + ',\n  '.join(_column(column, parsed['enums']) for column in parsed['tables'][name]) + '\n);')
        lines.append('GRANT ALL ON public."' + name + '" TO anon, authenticated, service_role;')
    return '\n'.join(lines) + '\n', missing, enums


# --- lokalny stos Supabase uruchamiany przez przebieg -------------------------------------------------------------

import base64, json, os, secrets, subprocess, urllib.error, urllib.request
from pathlib import Path

CLI = 'supabase@3.1.0'
# Funkcje serwerowe wołają systemy zewnętrzne, więc lokalnie nie startują; pozostałe wyłączone usługi nie są potrzebne ekranom.
EXCLUDED = 'studio,logflare,vector,imgproxy,supavisor,postgres-meta,edge-runtime'
PREFIXES = ('/auth/v1', '/rest/v1', '/storage/v1', '/functions/v1', '/realtime/v1', '/graphql/v1')
RELAY = 'alpine/socat'
EMAIL, PASSWORD = 'helix@example.invalid', 'Helix-' + secrets.token_urlsafe(18) + '-1a!'


def detect(root, deps):
    """Wpis planu dla części korzystającej z Supabase: katalog supabase z konfiguracją i klient w zależnościach."""
    config = Path(root)/'supabase'/'config.toml'
    if '@supabase/supabase-js' not in deps or not config.is_file(): return None
    ref = re.search(r'^project_id\s*=\s*"([a-z0-9]{6,40})"', config.read_text(errors='replace'), re.M)
    migrations = Path(root)/'supabase'/'migrations'; functions = Path(root)/'supabase'/'functions'
    types = next((path.relative_to(root).as_posix() for path in sorted(Path(root).glob('src/**/supabase/types.ts'))[:1]), None)
    return dict(ref=ref.group(1) if ref else None, types=types,
                migrations=len([p for p in migrations.glob('*.sql')]) if migrations.is_dir() else 0,
                functions=len([p for p in functions.iterdir() if p.is_dir() and not p.name.startswith('_')]) if functions.is_dir() else 0)


def token_claims(token):
    try: return json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
    except (ValueError, IndexError): return {}


def localize(text, ref, origin, anon):
    """Kod aplikacji w kopii roboczej: adres projektu i jego klucze wpisane na stałe wskazują lokalny stos."""
    if not ref or ref not in text: return text
    text = re.sub(r'https://' + re.escape(ref) + r'\.supabase\.co', origin, text)
    text = re.sub(r'wss://' + re.escape(ref) + r'\.supabase\.co', origin.replace('http', 'ws', 1), text)
    def key(found):
        claims = token_claims(found.group(0))
        return (anon if claims.get('role') == 'anon' else 'helix-blocked-token') if claims.get('ref') == ref else found.group(0)
    return _TOKEN.sub(key, text)


def localize_tree(folder, ref, origin, anon):
    """Podmiana w całej kopii roboczej poza zależnościami i katalogiem stosu (supabase/ na szczycie projektu).
    Zwraca (liczba zmienionych plików, pliki kodu, w których adres produkcji został): drugi wynik musi być pusty."""
    changed, left = 0, []
    for path in Path(folder).rglob('*'):
        parts = path.relative_to(folder).parts
        if 'node_modules' in parts or parts[0] in ('supabase', '.git', 'dist', 'build'): continue
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 5_000_000: continue
        if path.suffix not in ('.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.html', '.vue', '.svelte') and not path.name.startswith('.env'): continue
        try: text = path.read_text()
        except (UnicodeError, OSError): continue
        fresh = localize(text, ref, origin, anon)
        if fresh != text: path.write_text(fresh); changed += 1
        if ref and ref + '.supabase.co' in fresh: left.append('/'.join(parts))
    return changed, left


def literal(value):
    if value is True or value is False: return 'true' if value else 'false'
    if isinstance(value, (int, float)): return repr(value)
    if not isinstance(value, str) or '\0' in value or len(value) > 200: raise ValueError('runtime.supabase.profile: wartości to krótkie napisy, liczby albo true/false')
    return "'" + value.replace("'", "''") + "'"


ROLE_COLUMNS = ('role', 'effective_role', 'user_role', 'app_role', 'rola')


def profile_sql(columns, user, overrides):
    """Wiersz profilu konta syntetycznego: identyfikator konta, adres, pola zgody ustawione na tak, reszta z konfiguracji właściciela."""
    values = {}
    for name, kind in columns:
        if name in ('id', 'user_id') and kind == 'uuid': values[name] = "'" + user + "'"
        elif name == 'email': values[name] = literal(EMAIL)
        elif kind == 'boolean' and re.search(r'approved|active|verified|confirmed|enabled', name): values[name] = 'true'
        elif kind.startswith('timestamp') and re.search(r'password_changed|approved_at|confirmed_at', name): values[name] = 'now()'
        elif name in ('first_name', 'name', 'full_name', 'username'): values[name] = literal('Helix')
        elif name == 'last_name': values[name] = literal('Syntetyczny')
    known = {name for name, _ in columns}
    for name, value in (overrides or {}).items():
        if not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', str(name)) or name not in known: raise ValueError('runtime.supabase.profile: nieznana kolumna ' + str(name)[:40])
        values[name] = literal(value)
    if not any(name in values for name in ('id', 'user_id')): return None
    names = sorted(values)
    return ('set session_replication_role=replica; insert into public.profiles (' + ', '.join('"' + n + '"' for n in names) + ') values ('
            + ', '.join(values[n] for n in names) + ');')


def storage_state(origin, session):
    """Sesja konta syntetycznego w postaci, w jakiej klient Supabase trzyma ją w przeglądarce."""
    from urllib.parse import urlparse
    label = urlparse(origin).hostname.split('.')[0]
    return dict(cookies=[], origins=[dict(origin=origin, localStorage=[dict(name='sb-' + label + '-auth-token', value=json.dumps(session))])])


def apply_report(output, names):
    """Wynik stosowania migracji jednym poleceniem: znaczniki plików i błędy z wyjścia psql przypisane do plików."""
    rows, current = {name: dict(file=name, errors=0, first=None) for name in names}, None
    for line in output.splitlines():
        if line.startswith('@@ '): current = rows.get(line[3:].strip())
        elif 'ERROR:' in line and current is not None:
            current['errors'] += 1
            current['first'] = current['first'] or re.sub(r'\s+', ' ', line.split('ERROR:', 1)[1]).strip()[:160]
    return [rows[name] for name in names]


def start(runner, part, api_port, db_port, blocked):
    """Lokalny Supabase w sieci Dockera bez wyjścia: baza, logowanie, API i pliki; migracje projektu z zaślepionymi adresami."""
    plan = part['supabase']; docker = runner.tool('docker'); tag = secrets.token_hex(4)
    project, network = 'helix-' + tag, 'helix-supa-' + tag
    work = runner.tmp/'supabase-stack'; (work/'supabase'/'migrations').mkdir(parents=True); apply = work/'apply'; apply.mkdir()
    # Sesja ważna cały przebieg: bez odświeżania tokenu, które przy wielu równoległych przeglądarkach unieważnia sesję.
    settings = runner.config.get('runtime', {}).get('supabase') or {}
    # Zrzut schematu z produkcji (supabase db dump, bez danych) wskazany przez właściciela: baza dokładna zamiast odtwarzanej z repo.
    schema = runner.operator_setting('supabase.schema'); major = settings.get('postgres_major')
    if schema is not None and not (isinstance(schema, str) and os.path.isabs(schema) and Path(schema).is_file() and Path(schema).stat().st_size < 50_000_000):
        raise blocked('runtime.supabase.schema: wymagana bezwzględna ścieżka do pliku zrzutu schematu')
    if major is not None and major not in (15, 17): raise blocked('runtime.supabase.postgres_major: 15 albo 17')
    (work/'supabase'/'config.toml').write_text('project_id = "%s"\n[api]\nport = %d\n[db]\nport = %d\n%s[auth]\njwt_expiry = 604800\nenable_signup = true\n'
                                               % (project, api_port, db_port, 'major_version = %d\n' % major if major else ''))
    relays = ['helix-supa-relay-' + kind + '-' + tag for kind in ('db', 'api')]
    def cleanup():
        for argv in ([docker, 'rm', '-fv'] + relays, [docker, 'ps', '-aq', '--filter', 'label=com.supabase.cli.project=' + project]):
            try: found = runner.command(argv, cleanup=True)
            except Exception: found = ''
            if argv[1] == 'ps' and found.split():
                try: runner.command([docker, 'rm', '-fv'] + found.split(), cleanup=True)
                except Exception: pass
        for argv in ([docker, 'volume', 'ls', '-q', '--filter', 'label=com.supabase.cli.project=' + project],):
            try: volumes = runner.command(argv, cleanup=True).split()
            except Exception: volumes = []
            if volumes:
                try: runner.command([docker, 'volume', 'rm', '-f'] + volumes, cleanup=True)
                except Exception: pass
        try: runner.command([docker, 'network', 'rm', network], cleanup=True)
        except Exception: pass
    runner.cleanup_actions.append(cleanup)
    for attempt in range(8):
        try: runner.command([docker, 'network', 'create', '--internal', '--subnet', '10.213.%d.0/24' % secrets.randbelow(250), network]); break
        except blocked:
            if attempt == 7: raise
    # Dowód blokady: z tej sieci nie da się połączyć z adresem publicznym. Bez dowodu stos nie startuje.
    probe = runner.command([docker, 'run', '--rm', '--network', network, '--entrypoint', 'sh', RELAY, '-c',
                            'socat -T3 /dev/null TCP:1.1.1.1:443,connect-timeout=3 >/dev/null 2>&1 && echo HELIX_EGRESS_OPEN || echo HELIX_EGRESS_BLOCKED'], maximum=120)
    if 'HELIX_EGRESS_BLOCKED' not in probe or 'HELIX_EGRESS_OPEN' in probe:
        raise blocked('supabase: brak dowodu, że sieć kontenerów nie ma wyjścia na zewnątrz; stos nie został uruchomiony')
    for name, host, inner, target in ((relays[0], db_port, 5432, 'supabase_db_' + project), (relays[1], api_port, 8000, 'supabase_kong_' + project)):
        runner.command([docker, 'run', '--detach', '--name', name, '-p', '127.0.0.1:%d:%d' % (host, inner), RELAY, 'TCP-LISTEN:%d,fork,reuseaddr' % inner, 'TCP:%s:%d' % (target, inner)])
        runner.command([docker, 'network', 'connect', network, name])
    npx = str(Path(runner.tool('npm')).parent/'npx')
    from helix_runtime_container import engine_environment
    saved = runner.env
    # Narzędzie Supabase rozmawia z Dockerem samo: dostaje ten sam, sprawdzony adres gniazda co polecenia docker przebiegu.
    host = engine_environment(dict(saved), engine='docker', endpoint=runner.docker_endpoint())['DOCKER_HOST']
    runner.command(['/usr/bin/env', 'DOCKER_HOST=' + host, 'DO_NOT_TRACK=1', npx, '--yes', CLI, 'start', '--workdir', work, '--network-id', network, '-x', EXCLUDED], cwd=work, maximum=900)
    database = 'supabase_db_' + project
    # Migracje: tabele, których nie tworzy żadna migracja, odtworzone z typów aplikacji; potem cała historia po kolei, błędy zapisane.
    source = runner.work/part['path']/'supabase'/'migrations'
    names = ordered(os.listdir(source)) if source.is_dir() and not schema else []
    texts = [(source/name).read_text(errors='replace') for name in names]
    types = runner.work/part['path']/plan['types'] if plan.get('types') and not schema else None
    if schema: names, texts = ['schema.sql'], [Path(schema).read_text(errors='replace')]
    rebuilt, enums = [], []
    master = []
    if types is not None and types.is_file():
        sql, rebuilt, enums = bootstrap(types.read_text(errors='replace'), '\n'.join(texts))
        (apply/'bootstrap.sql').write_text(sql); master.append('\\i /helix-apply/bootstrap.sql')
    urls = tokens = 0
    for index, (name, text) in enumerate(zip(names, texts)):
        text, found, keys = blind(text); urls += found; tokens += keys
        (apply/('%05d.sql' % index)).write_text(text)
        master += ['\\warn @@ ' + name, '\\i /helix-apply/%05d.sql' % index]
    relations = 0
    if types is not None and types.is_file():
        # Po całej historii: kolumny i powiązania znane typom aplikacji, których baza z migracji nie ma.
        sql, relations = reconcile(types.read_text(errors='replace'))
        (apply/'reconcile.sql').write_text(sql); master += ['\\warn @@ helix-reconcile', '\\i /helix-apply/reconcile.sql']
    (apply/'master.sql').write_text('\n'.join(master) + '\n')
    runner.command([docker, 'cp', str(apply), database + ':/helix-apply'])
    try: output = runner.command([docker, 'exec', database, 'psql', '-U', 'postgres', '-q', '-o', '/dev/null', '-v', 'ON_ERROR_STOP=0', '-f', '/helix-apply/master.sql'], maximum=3600)
    except blocked as error: output = str(error)
    applied = apply_report(output, names); failed = [row for row in applied if row['errors']]
    approximate = bool(rebuilt or failed) and not schema
    admin = [docker, 'exec', database, 'psql', '-U', 'supabase_admin', '-d', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1', '-c']
    # Schemat odtworzony w przybliżeniu nie ma wiarygodnych polityk dostępu; zalogowane konto czyta wtedy dane z ich pominięciem.
    if approximate: runner.command(admin + ['alter role authenticated bypassrls'])
    runner.command([docker, 'restart', 'supabase_rest_' + project])
    raw = subprocess.run([npx, '--yes', CLI, 'status', '--workdir', str(work), '-o', 'json'], capture_output=True, text=True, timeout=120, cwd=work,
                         env=dict(saved, DO_NOT_TRACK='1', DOCKER_HOST=host)).stdout
    status, _ = json.JSONDecoder().raw_decode(raw[raw.index('{'):])
    anon, service = status['ANON_KEY'], status['SERVICE_ROLE_KEY']
    runner.private_values = set(getattr(runner, 'private_values', ())) | {anon, service, PASSWORD} | {value for key, value in status.items() if isinstance(value, str) and re.search(r'KEY|SECRET', key)}
    api = 'http://127.0.0.1:%d' % api_port
    def call(path, body, key):
        request = urllib.request.Request(api + path, data=json.dumps(body).encode(), headers={'apikey': key, 'authorization': 'Bearer ' + key, 'content-type': 'application/json'})
        for attempt in range(20):
            try:
                with urllib.request.urlopen(request, timeout=20) as answer: return json.loads(answer.read() or b'{}')
            except urllib.error.HTTPError as error: raise blocked('supabase: ' + path.split('?')[0] + ' odpowiada ' + str(error.code)) from None
            except (urllib.error.URLError, OSError):
                if attempt == 19: raise blocked('supabase: lokalne API nie odpowiada') from None
                import time; time.sleep(1)
    user = call('/auth/v1/admin/users', dict(email=EMAIL, password=PASSWORD, email_confirm=True), service)['id']
    profile = 'no profiles table'
    columns = [tuple(line.split('|')) for line in runner.command(admin + ["select column_name, data_type from information_schema.columns where table_schema='public' and table_name='profiles'"]).splitlines() if line.count('|') == 1]
    columns = [(name, 'timestamp' if kind.startswith('timestamp') else kind) for name, kind in columns]
    if columns:
        overrides = (runner.config.get('runtime', {}).get('supabase') or {}).get('profile') or {}
        sql = profile_sql(columns, user, overrides)
        if sql:
            runner.command(admin + [sql]); profile = 'created'
            # Rola konta: ta, którą dopuszcza najwięcej zabezpieczeń tras w kodzie (projekt B: domyślna „it” zamknęła 9 tras).
            # Osobne polecenie: wartość spoza enumu albo inna kolumna roli nie psuje wstawionego profilu.
            from helix_runtime_seed import guard_roles
            roles = guard_roles(Path(runner.work) / part.get('path', '.'))
            for name in [n for n, _ in columns if n in ROLE_COLUMNS and n not in overrides][:3] if roles else []:
                best = next(iter(roles))
                try:
                    runner.command(admin + ["set session_replication_role=replica; update public.profiles set \"%s\" = %s where id = '%s'" % (name, literal(best), user)])
                    profile = 'created, ' + name + '=' + best
                except Exception as error:   # rola spoza enumu albo kolumna wyliczana: zostaje wartość domyślna bazy
                    profile = 'created, ' + name + ' not set: ' + type(error).__name__
    session = call('/auth/v1/token?grant_type=password', dict(email=EMAIL, password=PASSWORD), anon)
    runner.private_values |= {session.get('access_token', ''), session.get('refresh_token', '')} - {''}
    return dict(anon=anon, session=session, database=database, db_url='postgresql://postgres:postgres@127.0.0.1:%d/postgres' % db_port,
                report=dict(status='RUNNING', fidelity='production schema dump' if schema else 'approximate' if approximate else 'migrations', egress='blocked (probe from the container network failed to connect)',
                            migrations=dict(files=len(names), with_errors=len(failed), failed_statements=sum(row['errors'] for row in applied),
                                            examples=[dict(file=row['file'], error=row['first']) for row in failed[:10]]),
                            rebuilt_from_types=dict(tables=len(rebuilt), enums=len(enums), examples=rebuilt[:10], relations_declared=relations),
                            blinded=dict(external_addresses=urls, tokens=tokens), access_policies='bypassed for the synthetic account' if approximate else 'project policies',
                            server_functions=dict(count=plan.get('functions', 0), status='not started: they call external systems'), synthetic_account=profile))
