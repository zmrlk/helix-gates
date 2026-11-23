"""Lokalne kontrakty pracy; wyłącznie biblioteka standardowa."""
import collections
import csv
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from helix_paths import normalize, relative as relative_path, within as path_within


def read(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def within(root, name):
    p = (root / name).resolve()
    if not path_within(p, root): raise ValueError('Ścieżka poza dozwolonym katalogiem')
    return p


def tasks(ctx):
    return [(p, json.loads(p.read_text().split('```json\n', 1)[1].split('\n```', 1)[0])) for p in sorted((ctx.state_dir / 'tasks').glob('*.md'))]


def task_write(p, t):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('# ' + t['goal'].replace('\n', ' ') + '\n\n```json\n' + json.dumps(t, ensure_ascii=False, indent=2) + '\n```\n')


def task(ctx, a):
    rows = tasks(ctx)
    if a.action == 'list':
        for _, t in rows: print(json.dumps(t, ensure_ascii=False))
        return
    if a.action == 'new':
        if not a.goal or not a.owner: raise ValueError('Wymagane --goal i --owner')
        limit = ctx.cfg.get('tasks', {}).get('wip_limit', 5)
        if sum(t['stage'] != 'closed' for _, t in rows) >= limit: raise ValueError('Przekroczony limit WIP')
        sensitive = re.search(r'wydat|zakup|koszt|migrac|migrat|auth|płat|platno|payment|spend|purchase', a.goal, re.I)
        kind = 'decyzja' if sensitive else a.type
        if kind == 'decyzja' and not all((a.recommendation, a.cost, a.impact)):
            raise ValueError('Decyzja człowieka wymaga --recommendation, --cost i --impact')
        tid = uuid.uuid4().hex[:12]
        t = dict(id=tid, goal=a.goal, owner=a.owner, type=kind, stage='human_decision' if kind == 'decyzja' else 'open', recommendation=a.recommendation, cost=a.cost, impact=a.impact, evidence=None, pr=a.pr, checkpoint=a.checkpoint)
        p = ctx.state_dir / 'tasks' / (tid + '.md'); task_write(p, t); print(p); return
    match = next(((p, t) for p, t in rows if t['id'] == a.id), None)
    if not match: raise ValueError('Nieznane zadanie')
    p, t = match
    if t.get('checkpoint') and not check_connections(ctx, t['checkpoint']): raise ValueError('ERROR: worker.allow_hosts blokuje zamknięcie')
    if not a.evidence: raise ValueError('Zamknięcie wymaga --evidence')
    ep = Path(a.evidence)
    ep = ep.resolve() if ep.is_absolute() else (ctx.repo / ep).resolve()
    if not path_within(ep, ctx.evidence_root) or not ep.is_file() or ep.stat().st_size == 0:
        raise ValueError('Dowód musi być niepustym plikiem w helix-evidence')
    if t['type'] == 'decyzja' and not a.human: raise ValueError('Decyzję zamyka człowiek: --human imię')
    t.update(stage='closed', evidence=str(ep), decided_by=a.human); task_write(p, t); print(p)


def cell(value):
    return str(value or '—').replace('|', '\\|').replace('\n', ' ')


def board(ctx, a):
    lines = ['# Tablica zadań', '', '| Zadanie | Właściciel | Etap | Dowód | PR | Bramki |', '|---|---|---|---|---|---|']
    for p, t in tasks(ctx):
        st = read(ctx.state_dir / (str(t.get('checkpoint')) + '.state.json'), {})
        lines.append('| ' + ' | '.join(map(cell, [t['goal'], t['owner'], t['stage'], f"[dowód]({Path(t['evidence']).as_uri()})" if t.get('evidence') else None, t.get('pr'), json.dumps(st.get('gates', {}))])) + ' |')
    dest = ctx.state_dir / 'BOARD.md'; dest.write_text('\n'.join(lines) + '\n'); print(dest)


def validate_input(value, schema):
    kinds = {'object': dict, 'array': list, 'string': str, 'boolean': bool, 'integer': int, 'number': (int, float), 'null': type(None)}
    kind = schema.get('type')
    if kind in kinds and (not isinstance(value, kinds[kind]) or kind in ('integer', 'number') and isinstance(value, bool)):
        raise ValueError('Wejście niezgodne z typem schematu: ' + kind)
    if 'enum' in schema and value not in schema['enum']: raise ValueError('Wartość poza enum schematu')
    if isinstance(value, dict):
        if any(k not in value for k in schema.get('required', [])): raise ValueError('Brak wymaganego pola schematu')
        props = schema.get('properties', {})
        for k, v in value.items():
            if k in props: validate_input(v, props[k])
            elif schema.get('additionalProperties') is False: raise ValueError('Nieznane pole schematu: ' + k)
    if isinstance(value, list) and 'items' in schema:
        for item in value: validate_input(item, schema['items'])


def tools(ctx, a, model_caller=None):
    if a.action in ('adapters', 'scan', 'simplicity'):
        from helix_tool_adapters import discover, scan
        if a.action == 'simplicity':
            from helix_simplicity import review
            result = review(ctx, since=a.since, execute=a.execute_model, caller=model_caller)
        else:
            result = discover() if a.action == 'adapters' else scan(ctx.repo, a.name, since=getattr(a,'since',None))
        if getattr(a,'out',None) and a.action != 'adapters':
            from helix_advisory import publish
            publish(ctx.repo,a.out,result)
        print(json.dumps(result, ensure_ascii=False, indent=2)); return
    path = ctx.state_dir / 'tools.json'
    if not path.exists(): save(path, {'tools': []})
    entries = read(path, {}).get('tools', [])
    if a.action == 'discover':
        print(json.dumps([{k: t.get(k, False if k == 'enabled' else None) for k in ('name', 'owner', 'enabled', 'schema')} for t in entries], ensure_ascii=False)); return
    t = next((t for t in entries if t['name'] == a.name), None)
    if not t: raise ValueError('Nieznane narzędzie')
    schema = read(within(ctx.repo, t['schema']))
    if a.action == 'schema': print(json.dumps(schema, ensure_ascii=False)); return
    if t.get('enabled') is not True: raise ValueError('Narzędzie wyłączone')
    command = t.get('command')
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command): raise ValueError('Wymagana komenda jako tablica argv')
    payload = json.loads(a.input)
    if not isinstance(payload, dict): raise ValueError('Wejście musi być obiektem JSON')
    validate_input(payload, schema)
    p = subprocess.run(command, input=json.dumps(payload), text=True, capture_output=True, cwd=ctx.repo, timeout=60)
    if p.returncode: raise ValueError('Błąd narzędzia (kod ' + str(p.returncode) + ')')
    result = json.loads(p.stdout)
    # Wartości sekretów nie trafiają do kontekstu ani dowodów.
    def redact(v):
        if isinstance(v, dict): return {k: '[REDACTED]' if re.search(r'password|secret|token|api.?key|authorization', k, re.I) else redact(x) for k, x in v.items()}
        if isinstance(v, list): return [redact(x) for x in v]
        return v
    result = redact(result)
    if isinstance(result, dict):
        result.setdefault('source_status', 'NOT_FOUND')
        result.setdefault('retrieved_at', dt.datetime.now(dt.timezone.utc).isoformat())
        result.setdefault('ttl', t.get('ttl', 3600))
        error = source_error(result)
        if error: raise ValueError(error)
    dest = ctx.evidence_root / 'tools' / (uuid.uuid4().hex + '.json'); save(dest, result)
    projected = {}
    for field in filter(None, (a.fields or '').split(',')):
        value = result
        for part in field.split('.'): value = value.get(part) if isinstance(value, dict) else None
        projected[field] = value
    print(dest)
    print(json.dumps(projected, ensure_ascii=False)[:1000])


def diff_files(ctx, base='HEAD'):
    p = subprocess.run(['git', 'diff', '--name-only', base, '--'], cwd=ctx.repo, capture_output=True, text=True)
    if p.returncode: raise ValueError('Nie udało się odczytać diffu')
    return p.stdout.splitlines()


def glob_matches(file, pattern):
    # **/ dopuszcza również zero katalogów; * nie przekracza separatora.
    regex = ''; i = 0
    while i < len(pattern):
        if pattern[i:i+3] == '**/': regex += '(?:.*/)?'; i += 3
        elif pattern[i:i+2] == '**': regex += '.*'; i += 2
        elif pattern[i] == '*': regex += '[^/]*'; i += 1
        elif pattern[i] == '?': regex += '[^/]'; i += 1
        else: regex += re.escape(pattern[i]); i += 1
    return re.fullmatch(regex, file) is not None


def matching_rules(ctx, files):
    found = []
    for p in sorted((ctx.state_dir / 'rules').glob('*.md')):
        text = p.read_text()
        if p.name.startswith('proposal-'): continue
        if not text.startswith('---\n'): continue
        front = text.split('---', 2)[1]
        match = re.search(r'^paths:\s*(.*)$', front, re.M)
        if not match: continue
        value = match.group(1).strip()
        if value.startswith('['): globs = json.loads(value)
        elif value: globs = [value.strip('"\'')]
        else: globs = re.findall(r'^\s*-\s*["\']?([^\n"\']+)', front, re.M)
        if any(glob_matches(f, g) for f in files for g in globs): found.append((p, text))
    return found


def rules(ctx, a):
    for p, text in matching_rules(ctx, diff_files(ctx, a.base)): print(str(p) + '\n' + text)


def precheck(ctx, checkpoint=None):
    commands = ctx.cfg.get('precheck', {}).get('commands')
    if commands is None:
        scripts = read(ctx.repo / 'package.json', {}).get('scripts', {})
        commands = [['npm', 'run', k] for k in ('lint', 'typecheck', 'type-check') if k in scripts]
    records = []
    if commands and not getattr(ctx, 'trust_repo', False):
        records.append(dict(command=[], exit=1, output='Repository commands require explicit --trust-repo authorization'))
        commands = []
    # A deliberately small environment: repository commands never inherit credentials.
    env = {k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'LC_ALL', 'TMPDIR') if k in os.environ}
    for command in commands:
        try:
            p = subprocess.run(command, cwd=ctx.repo, capture_output=True, text=True, timeout=120, shell=False, env=env)
            records.append(dict(command=command, exit=p.returncode, output=(p.stdout + p.stderr)[-4000:]))
        except (OSError, subprocess.SubprocessError) as ex: records.append(dict(command=command, exit=1, output=str(ex)))
    result = dict(gate='review', precheck=True, **{'pass': all(r['exit'] == 0 for r in records)}, checks=records)
    dest = ctx.ev(checkpoint) if checkpoint else ctx.evidence_root / 'precheck'
    save(dest / 'precheck.json', result)
    return result


def source_error(claim):
    status = claim.get('source_status')
    if status is not None and status not in ('FOUND', 'NOT_FOUND', 'AMBIGUOUS', 'OUT_OF_SCOPE'): return 'Niepoprawny source_status'
    if claim.get('affects_prod') and status != 'FOUND': return 'Twierdzenie o produkcji wymaga source_status FOUND'
    if claim.get('tag') == 'VERIFIED' and status in ('NOT_FOUND', 'AMBIGUOUS', 'OUT_OF_SCOPE'): return 'Źródło nie może potwierdzać cytatu'
    if status is not None:
        try:
            retrieved = dt.datetime.fromisoformat(claim['retrieved_at'].replace('Z', '+00:00'))
            ttl = claim['ttl']
            if retrieved.tzinfo is None or isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0: raise ValueError()
            age = (dt.datetime.now(dt.timezone.utc) - retrieved).total_seconds()
            if age < 0 or age > ttl: return 'Źródło przeterminowane lub z przyszłości'
        except (KeyError, TypeError, ValueError): return 'Wymagane retrieved_at (ISO UTC) i ttl (sekundy)'
    return None


def check_connections(ctx, checkpoint):
    config = ctx.cfg.get('worker', {})
    ev = ctx.ev(checkpoint)
    if (ev / 'worker-network-error.json').exists():
        st = ctx.state(checkpoint); st.update(status='ERROR'); ctx.save_state(st)
        return False
    path = ev / 'worker-connections.jsonl'
    denied = []
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                event = json.loads(line); host = event.get('host', '').lower().rstrip('.')
                if not host or host not in [h.lower().rstrip('.') for h in config.get('allow_hosts', [])]: denied.append(event)
            except (ValueError, TypeError): denied.append({'error': 'Niepoprawny log połączeń'})
    if (ev / 'worker-network-error.json').exists():
        st = ctx.state(checkpoint); st.update(status='ERROR'); ctx.save_state(st)
        return False
    if denied:
        save(ev / 'worker-network-error.json', dict(status='ERROR', denied=denied))
        st = ctx.state(checkpoint); st.update(status='ERROR'); ctx.save_state(st)
        return False
    return True


def worker_connect(ctx, a):
    url = urllib.parse.urlsplit(a.url)
    if url.scheme not in ('http', 'https') or not url.hostname: raise ValueError('Wymagany URL HTTP(S)')
    ev = ctx.ev(a.checkpoint)
    with (ev / 'worker-connections.jsonl').open('a') as f: f.write(json.dumps(dict(host=url.hostname, retrieved_at=dt.datetime.now(dt.timezone.utc).isoformat())) + '\n')
    hosts = ctx.cfg.get('worker', {}).get('allow_hosts', [])
    if url.hostname.lower().rstrip('.') not in [h.lower().rstrip('.') for h in hosts]:
        save(ev / 'worker-network-error.json', dict(status='ERROR', denied=[{'host': url.hostname}]))
        st = ctx.state(a.checkpoint); st.update(status='ERROR'); ctx.save_state(st)
        raise ValueError('ERROR: host poza allowlistą')
    if not check_connections(ctx, a.checkpoint): raise ValueError('ERROR: host poza allowlistą')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): raise ValueError('Przekierowanie wymaga osobnego sprawdzenia hosta')
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(a.url, timeout=30) as response:
        dest = ev / ('connection-' + uuid.uuid4().hex + '.bin'); dest.write_bytes(response.read(10_000_000))
    print(dest)


def audit(ctx, a):
    now = dt.datetime.now(dt.timezone.utc); sessions = {}; errors = collections.Counter(); seen = set()
    roots = [ctx.state_dir, ctx.evidence_root] + [Path(p) for p in (getattr(a, 'logs', None) or [])]
    for root in roots:
        for path in ([root] if root.is_file() else sorted(root.rglob('*'))):
            if not path.is_file() or path.is_symlink() or path.suffix not in ('.json', '.jsonl', '.log', '.csv'): continue
            if (now.timestamp() - path.stat().st_mtime) > 7 * 86400: continue
            raw = path.read_text(errors='replace')
            try: rows = list(csv.DictReader(raw.splitlines())) if path.suffix == '.csv' else [json.loads(x) for x in raw.splitlines()] if path.suffix == '.jsonl' else [json.loads(raw)]
            except ValueError: rows = [dict(session_id=str(path), error=line) for line in raw.splitlines() if re.search(r'error|błąd|timeout', line, re.I)]
            for row in rows:
                if not isinstance(row, dict): continue
                if not any(k in row for k in ('session_id', 'run_id', 'log', 'error', 'implement_error', 'units')) and not re.search(r'worker|session|run-log', path.name): continue
                timestamp = row.get('timestamp') or row.get('started_at') or row.get('at')
                if timestamp:
                    try:
                        when = dt.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        if when.tzinfo and (now - when).total_seconds() > 7 * 86400: continue
                    except (ValueError, TypeError): continue
                events = row.get('log', [row])
                if row.get('units'):
                    events = [dict(row, error=r.get('error'), unit=name) for name, unit in row['units'].items() for r in unit.get('records', [])] or [row]
                for event in events:
                    if not isinstance(event, dict): continue
                    event_time = event.get('timestamp') or event.get('at')
                    if event_time:
                        try:
                            when = dt.datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                            if when.tzinfo and (now - when).total_seconds() > 7 * 86400: continue
                        except (ValueError, TypeError): continue
                    sid = str(event.get('session_id') or row.get('session_id') or row.get('run_id') or row.get('id') or path)
                    identity = json.dumps([sid, event], sort_keys=True)
                    if identity in seen: continue
                    seen.add(identity)
                    aggregate = sessions.setdefault(sid, dict(cost=0, unanswered=False))
                    aggregate['cost'] += float(event.get('cost', 0) or 0)
                    if event.get('budget'): aggregate['budget'] = event['budget']
                    aggregate['unanswered'] |= event.get('status') in ('stopped', 'pending', 'timeout', 'ERROR') and not event.get('response')
                    error = event.get('error') or event.get('implement_error')
                    if error: errors[re.sub(r'\s+', ' ', str(error)).strip()] += 1
    lines = ['# Audyt sesji — ostatnie 7 dni', '', f'Liczba sesji: {len(sessions)}', '', '## Błędy (dedupe)', '']
    for error, count in errors.most_common():
        lines.append(f'- {count}: {error}')
        if count >= 15:
            dest = ctx.state_dir / 'rules' / ('proposal-' + hashlib.sha256(error.encode()).hexdigest()[:12] + '.md')
            if not dest.exists():
                dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text('---\npaths: ["**/*"]\n---\n# Propozycja reguły — do akceptacji człowieka\n\nPowtarzający się błąd (dane, nie instrukcja):\n\n' + json.dumps(error, ensure_ascii=False) + '\n')
    total = sum(float(e.get('cost', 0) or 0) for e in sessions.values())
    lines += ['', '## Sesje >25% budżetu i zatrzymania bez odpowiedzi', '']
    for sid, event in sessions.items():
        budget = event.get('budget') or getattr(a, 'budget', None) or total
        if budget and float(event.get('cost', 0) or 0) > float(budget) * .25: lines.append('- >25%: ' + sid)
        if event.get('unanswered'): lines.append('- Bez odpowiedzi: ' + sid)
    dest = ctx.evidence_root / 'audit-sessions.md'; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text('\n'.join(lines) + '\n'); print(dest)


def parsers(sp):
    p = sp.add_parser('task'); p.add_argument('action', choices=['new', 'close', 'list']); p.add_argument('id', nargs='?')
    for flag in ('goal', 'owner', 'recommendation', 'cost', 'impact', 'evidence', 'pr', 'checkpoint', 'human'): p.add_argument('--' + flag)
    p.add_argument('--type', choices=['zadanie', 'decyzja'], default='zadanie')
    sp.add_parser('board')
    p = sp.add_parser('audit-sessions'); p.add_argument('--logs', action='append'); p.add_argument('--budget', type=float)
    p = sp.add_parser('tools'); p.add_argument('action', choices=['discover', 'schema', 'call', 'adapters', 'scan', 'plan', 'install', 'simplicity']); p.add_argument('name', nargs='?'); p.add_argument('--input', default='{}'); p.add_argument('--fields')
    p.add_argument('--since', help='Ref Git zakresu zmian; wymagany dla migracji, mutacji i prostoty')
    p.add_argument('--execute-model', action='store_true', help='Jawnie wywołaj soczewkę prostoty z planu ról i zgodą data_egress')
    p.add_argument('--tool', action='append', help='Nazwa z rejestru; powtórz dla kilku narzędzi. Install obsługuje tylko przypięty katalog.')
    p.add_argument('--yes', action='store_true', help='Jawnie zezwól na pobranie i instalację pięciu przypiętych narzędzi')
    p.add_argument('--json', action='store_true', help='Pełny raport planu lub instalacji')
    p.add_argument('--out', help='Zewnętrzny katalog nowego raportu tools-plan.json lub tools-install.json')
    p = sp.add_parser('rules'); p.add_argument('action', choices=['for-diff']); p.add_argument('--base', default='HEAD')
    p = sp.add_parser('precheck'); p.add_argument('checkpoint', nargs='?')
    p = sp.add_parser('worker-connect'); p.add_argument('checkpoint'); p.add_argument('url')


def dispatch(ctx, a, model_caller=None):
    try:
        if a.cmd == 'precheck':
            result = precheck(ctx, a.checkpoint); print(json.dumps(result, ensure_ascii=False))
            if not result['pass']: raise SystemExit(2)
        elif a.cmd == 'tools': tools(ctx,a,model_caller=model_caller)
        else: {'task': task, 'board': board, 'rules': rules, 'audit-sessions': audit, 'worker-connect': worker_connect}[a.cmd](ctx, a)
    except (ValueError, OSError, subprocess.SubprocessError) as ex: raise SystemExit(str(ex))
