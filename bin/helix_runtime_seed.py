"""Dane syntetyczne dla pustych tabel, które czyta aplikacja (projekt na Supabase).

Aplikacje budowane w Lovable trzymają w bazie konfigurację ekranów (menu, uprawnienia, słowniki). Kopia ze schematu nie ma
wierszy, więc ekrany i menu są puste, a eksplorator UX utyka. Helix znajduje tabele czytane w kodzie (`.from('tabela')`),
które są puste, i prosi model o wiersze zgodne ze schematem i kodem. Wiersze trafiają do lokalnej bazy z wyłączonymi
wyzwalaczami (żaden wyzwalacz nie woła funkcji zewnętrznych); błąd wstawienia wraca do modelu jeden raz.
"""
import json
import re
from pathlib import Path

REFERENCE = re.compile(r"""\.from\(\s*['"`]([A-Za-z_]\w*)['"`]\s*\)""")
CODE = ('.ts', '.tsx', '.js', '.jsx', '.mjs', '.svelte', '.vue')
SKIP = ('node_modules', '.git', 'dist', 'build', '.next', 'coverage')
SEP = '\x1f'


def project_files(root, limit=2_000_000):
    """Pliki kodu projektu do odczytu dla modelu: bez dowiązań, tylko wewnątrz projektu, do 2 MB. Sprawdzany projekt bywa cudzy:
    dowiązanie w repozytorium (np. do ~/.ssh) nie może trafić do polecenia dla modelu (przegląd bezpieczeństwa 16.11)."""
    root = Path(root).resolve()
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or path.suffix not in CODE or any(part in SKIP for part in path.relative_to(root).parts): continue
        try:
            if not path.is_file() or path.stat().st_size > limit or not path.resolve().is_relative_to(root): continue
        except OSError: continue
        yield path


def code_references(root, per_table=3, lines=8):
    """Miejsca w kodzie, które czytają albo zapisują tabelę: nazwa tabeli -> [(ścieżka, linia, fragment)]."""
    root = Path(root).resolve(); found = {}
    for path in project_files(root):
        try: text = path.read_text(errors='ignore').splitlines()
        except OSError: continue
        for number, line in enumerate(text):
            for match in REFERENCE.finditer(line):
                rows = found.setdefault(match.group(1), [])
                if len(rows) < per_table:
                    rows.append((path.relative_to(root).as_posix(), number + 1, '\n'.join(text[number:number + lines])))
                else:
                    rows.append(None)
    return {table: [row for row in rows if row] + ([None] * 0) for table, rows in found.items()}, \
           {table: len(rows) for table, rows in found.items()}


GUARD = re.compile(r'\b(?:required|allowed)?[Rr]oles\s*=\s*\{\s*\[([^\]]*)\]')


def guard_roles(root):
    """Role z zabezpieczeń tras w kodzie (requiredRoles={[...]}, allowedRoles, roles): rola -> liczba zabezpieczeń, które ją
    dopuszczają. Projekt B: model dał kontu testowemu rolę „it”, a 9 tras wymaga „manager” albo „advisor” (przekierowanie na start)."""
    found = {}
    for path in project_files(root):
        try: text = path.read_text(errors='ignore')
        except OSError: continue
        for match in GUARD.finditer(text):
            for role in set(re.findall(r'["\']([^"\']+)["\']', match.group(1))): found[role] = found.get(role, 0) + 1
    return dict(sorted(found.items(), key=lambda item: (-item[1], item[0])))


def rows(output):
    return [line.split(SEP) for line in output.splitlines() if line]


def describe(sql, tables):
    """Kolumny, powiązania, wartości enumów i ograniczenia CHECK dla wskazanych tabel (jedno zapytanie na rodzaj)."""
    names = ','.join("'" + t.replace("'", "''") + "'" for t in tables)
    columns = {}
    for table, column, kind, udt, nullable, default in rows(sql(
            "select table_name, column_name, data_type, udt_name, is_nullable, coalesce(column_default,'') from information_schema.columns "
            "where table_schema='public' and table_name in (" + names + ") order by table_name, ordinal_position")):
        columns.setdefault(table, []).append(dict(name=column, type=udt if kind == 'USER-DEFINED' else kind, udt=udt, kind=kind, nullable=nullable == 'YES', default=default))
    links = {}
    for table, column, target, target_column in rows(sql(
            "select tc.table_name, kcu.column_name, ccu.table_name, ccu.column_name from information_schema.table_constraints tc "
            "join information_schema.key_column_usage kcu on tc.constraint_name=kcu.constraint_name and tc.table_schema=kcu.table_schema "
            "join information_schema.constraint_column_usage ccu on ccu.constraint_name=tc.constraint_name and ccu.table_schema=tc.table_schema "
            "where tc.constraint_type='FOREIGN KEY' and tc.table_schema='public' and tc.table_name in (" + names + ")")):
        links.setdefault(table, []).append(dict(column=column, table=target, target=target_column))
    enums = {name: values.split(',') for name, values in rows(sql(
        "select t.typname, string_agg(e.enumlabel, ',' order by e.enumsortorder) from pg_type t join pg_enum e on e.enumtypid=t.oid "
        "join pg_namespace n on n.oid=t.typnamespace where n.nspname='public' group by t.typname"))}
    checks = {}
    for table, definition in rows(sql(
            "select conrelid::regclass::text, pg_get_constraintdef(oid) from pg_constraint where contype in ('c','u') "
            "and connamespace='public'::regnamespace and conrelid::regclass::text in (" + names + ")")):
        checks.setdefault(table.split('.')[-1].strip('"'), []).append(definition)
    return columns, links, enums, checks


def counts(sql, tables):
    if not tables: return {}
    query = ' union all '.join("select '%s', count(*) from public.\"%s\"" % (t, t.replace('"', '""')) for t in tables)
    return {table: int(value) for table, value in rows(sql(query))}


def order(tables, links):
    """Tabele, do których prowadzą powiązania, najpierw (pętle przerwane w kolejności nazw)."""
    left, done, result = set(tables), set(), []
    while left:
        ready = sorted(t for t in left if all(l['table'] in done or l['table'] not in left or l['table'] == t for l in links.get(t, [])))
        if not ready: ready = [sorted(left)[0]]
        for table in ready: result.append(table); done.add(table); left.discard(table)
    return result


def prompt(batch, columns, links, enums, checks, references, existing, user, roles=None):
    lines = ['Jesteś inżynierem danych testowych. Lokalna kopia bazy aplikacji (PostgreSQL, Supabase) ma puste tabele, więc ekrany aplikacji są puste.',
             'Napisz dane syntetyczne dla poniższych tabel: realistyczne, po polsku, spójne między tabelami, zgodne z typami, enumami, ograniczeniami i z tym,',
             'jak kod aplikacji czyta te tabele (kolumny w select, filtry eq/in, oczekiwane wartości). Tabele konfiguracyjne (menu, uprawnienia, role,',
             'słowniki, ustawienia) wypełnij kompletnie tak, aby wszystkie pozycje używane w kodzie istniały; tabele z danymi roboczymi: 6-12 wierszy.',
             'Identyfikatory uuid podawaj jawnie (stałe, poprawne uuid). Odwołuj się tylko do identyfikatorów, które istnieją (lista niżej) albo które',
             'tworzysz w tej odpowiedzi. Zalogowany użytkownik testowy ma id ' + user + '; rekordy „moje” przypisz do niego.',
             *(['Trasy aplikacji są zabezpieczone rolami (rola: liczba zabezpieczeń, które ją dopuszczają): ' +
                ', '.join('%s: %d' % item for item in list(roles.items())[:12]) + '. Użytkownik testowy ma mieć rolę „' + next(iter(roles)) +
                '”, która otwiera najwięcej ekranów, we wszystkich kolumnach i tabelach, z których kod czyta rolę.'] if roles else []),
             'Nie używaj prawdziwych danych osobowych ani sekretów. Nie pisz SQL. Odpowiedz wyłącznie JSON z wartościami:',
             '{"tables": [{"table": "nazwa", "rows": [{"kolumna": wartość, ...}, ...]}]}. Wartości: tekst, liczba, true/false, null,',
             'daty jako tekst ISO 8601, tablice jako listy JSON, kolumny json/jsonb jako obiekty JSON. Pomijaj kolumny z wartością domyślną, jeśli nie są potrzebne.',
             '']
    for table in batch:
        lines.append('## Tabela public.' + table)
        for column in columns.get(table, []):
            kind = column['type'] + ((' enum ' + '|'.join(enums[column['type']])) if column['type'] in enums else '')
            lines.append('- %s %s%s%s' % (column['name'], kind, '' if column['nullable'] else ' NOT NULL', (' DEFAULT ' + column['default'][:60]) if column['default'] else ''))
        for link in links.get(table, []):
            lines.append('- powiązanie: %s -> %s.%s' % (link['column'], link['table'], link['target']))
        for definition in checks.get(table, [])[:8]:
            lines.append('- ograniczenie: ' + definition[:200])
        for path, number, snippet in references.get(table, [])[:3]:
            lines.append('- kod %s:%d\n```\n%s\n```' % (path, number, snippet[:900]))
        lines.append('')
    if existing:
        lines.append('## Istniejące identyfikatory (do powiązań)')
        for table, ids in existing.items(): lines.append('- %s: %s' % (table, ', '.join(ids[:8])))
    return '\n'.join(lines)


_TYPE = re.compile(r'^[a-z_][a-z0-9_ ]*$')


def literal(value, column):
    """Wartość z odpowiedzi modelu jako literał SQL rzutowany na typ kolumny; nigdy wyrażenie ani wywołanie funkcji."""
    if value is None: return 'NULL'
    udt, kind = column.get('udt') or '', column.get('kind') or ''
    if kind == 'ARRAY':
        if not isinstance(value, list): raise ValueError('kolumna %s: oczekiwana lista' % column['name'])
        element = udt.lstrip('_')
        if not _TYPE.match(element): raise ValueError('nieobsługiwany typ tablicy')
        items = ','.join('"' + str(v).replace('\\', '\\\\').replace('"', '\\"') + '"' if v is not None else 'NULL' for v in value)
        body = '{' + items + '}'
        return "'%s'::%s[]" % (body.replace("'", "''"), element)   # cały literał, łącznie z elementami
    if isinstance(value, (dict, list)): text = json.dumps(value, ensure_ascii=False)
    elif isinstance(value, bool): text = 'true' if value else 'false'
    elif isinstance(value, (int, float)): text = repr(value)
    else: text = str(value)
    text = "'" + text.replace("'", "''") + "'"
    if kind == 'USER-DEFINED':
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', udt): raise ValueError('nieobsługiwany typ')
        return '%s::public."%s"' % (text, udt)
    if not _TYPE.match(udt): raise ValueError('nieobsługiwany typ')
    return '%s::%s' % (text, udt)


def insert(table, rows_, columns):
    """INSERT złożony przez Helixa: tylko kolumny ze schematu tabeli, wartości jako literały; model nie przekazuje SQL."""
    known = {c['name']: c for c in columns}
    rows_ = [r for r in rows_ if isinstance(r, dict)]
    names = sorted({k for r in rows_ for k in r if k in known})
    if not rows_ or not names: return None
    values = ['(' + ', '.join(literal(r.get(n), known[n]) if n in r else 'DEFAULT' for n in names) + ')' for r in rows_]
    return 'INSERT INTO public."%s" (%s) VALUES %s' % (table.replace('"', '""'), ', '.join('"%s"' % n.replace('"', '""') for n in names), ', '.join(values))


def seed(sql, execute, ask, root, user, *, limit=None, only=None, batch_size=6, log=lambda message: None, roles=None):
    """sql(query) -> tekst wyniku (psql -At -F 0x1f); execute(statement) -> None albo komunikat błędu; ask(prompt) -> tekst JSON.

    Zwraca raport: liczba tabel kandydatów, wypełnionych, wierszy, błędy (tylko komunikaty bazy, bez danych)."""
    references, frequency = code_references(root)
    public = {name for (name,) in rows(sql("select table_name from information_schema.tables where table_schema='public' and table_type='BASE TABLE'"))}
    used = [t for t in sorted(frequency, key=lambda t: (-frequency[t], t)) if t in public]
    sizes = counts(sql, used)
    # Najpierw konfiguracja (menu, uprawnienia, role, słowniki): od niej zależy, co aplikacja w ogóle pokazuje.
    config = re.compile(r'menu|permission|role|module|config|setting|categor|type|status|dictionar|slownik')
    empty = sorted((t for t in used if sizes.get(t) == 0), key=lambda t: (not config.search(t), -frequency[t], t))
    if only: empty = [t for t in empty if t in set(only)]
    if limit: empty = empty[:limit]
    roles = guard_roles(root) if roles is None else roles
    report = dict(status='NOT_NEEDED' if not empty else 'RUN', referenced_tables=len(used), empty_tables=len(empty), filled=[], rows=0, errors=[], model_calls=0,
                  test_user_role=next(iter(roles), None), guard_roles=roles)
    if not empty: return report
    columns, links, enums, checks = describe(sql, empty)
    sequence = order(empty, links)
    for start in range(0, len(sequence), batch_size):
        batch = sequence[start:start + batch_size]
        targets = sorted({l['table'] for t in batch for l in links.get(t, []) if l['table'] in public})
        existing = {}
        for table in targets:
            key = next((c['name'] for c in (describe(sql, [table])[0].get(table) or []) if c['name'] == 'id'), None)
            if key: existing[table] = [row[0] for row in rows(sql('select id::text from public."%s" limit 8' % table.replace('"', '""')))]
        existing = {t: ids for t, ids in existing.items() if ids}
        text = prompt(batch, columns, links, enums, checks, references, existing, user, roles)
        failures = {}
        for attempt in range(2):
            if attempt and not failures: break
            message = text if not attempt else text + '\n\n## Poprzednia odpowiedź dała błędy bazy; popraw wyłącznie te tabele:\n' + \
                '\n'.join('- %s: %s' % (t, e) for t, e in failures.items())
            report['model_calls'] += 1
            try:
                answer = ask(message)
                data = json.loads(answer[answer.find('{'):answer.rfind('}') + 1])
            except Exception as error:   # odpowiedź modelu jest niezaufanym wejściem
                report['errors'].append(dict(tables=batch, error='model: ' + str(error)[:200])); break
            failures = {}
            for item in data.get('tables', []) if isinstance(data, dict) and isinstance(data.get('tables'), list) else []:
                table = item.get('table') if isinstance(item, dict) else None
                if table not in batch or not isinstance(item.get('rows'), list): continue   # tylko tabele z tej partii
                try: statement = insert(table, item['rows'][:200], columns.get(table, []))
                except ValueError as error: failures[table] = str(error)[:300]; continue
                if not statement: continue
                error = execute(statement)
                if error: failures[table] = error[:300]
            sizes = counts(sql, batch)
            for table in batch:
                if sizes.get(table) and table not in report['filled']: report['filled'].append(table)
        report['errors'] += [dict(tables=[t], error=e) for t, e in failures.items() if t not in report['filled']]
        log('dane syntetyczne: %d/%d tabel wypełnionych' % (len(report['filled']), len(empty)))
    sizes = counts(sql, report['filled'])
    report['rows'] = sum(sizes.values())
    report['status'] = 'SEEDED' if report['filled'] else 'FAILED'
    return report
