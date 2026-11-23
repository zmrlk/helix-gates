"""Wersjonowany ledger wymagań; walidacja offline, wyłącznie stdlib."""
import ast
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HOME = Path(__file__).resolve().parents[1]
RANK = {'missing': 0, 'in-progress': 1, 'partial': 2, 'done': 3}


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def schema_check(value, schema, path='$'):
    """Podzbiór JSON Schema używany przez dostarczony schemat (bez zależności)."""
    types = {'object': dict, 'array': list, 'string': str, 'integer': int}
    kind = schema.get('type')
    if kind and (not isinstance(value, types[kind]) or kind == 'integer' and isinstance(value, bool)):
        raise ValueError(f'{path}: oczekiwany typ {kind}')
    if 'const' in schema and value != schema['const']:
        raise ValueError(f'{path}: błędna wersja')
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError(f'{path}: niedozwolona wartość')
    if isinstance(value, str):
        if len(value.strip()) < schema.get('minLength', 0) or ('pattern' in schema and not re.search(schema['pattern'], value)):
            raise ValueError(f'{path}: pusty lub niepoprawny tekst')
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0):
            raise ValueError(f'{path}: pusta lista')
        if schema.get('uniqueItems') and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            raise ValueError(f'{path}: duplikaty')
        for i, item in enumerate(value):
            schema_check(item, schema.get('items', {}), f'{path}[{i}]')
    if isinstance(value, dict):
        for key in schema.get('required', []):
            if key not in value:
                raise ValueError(f'{path}: brak {key}')
        for key, item in value.items():
            props = schema.get('properties', {})
            if key not in props and schema.get('additionalProperties') is False:
                raise ValueError(f'{path}: nieznane pole')
            extra = schema.get('additionalProperties', {})
            child = props.get(key, extra if isinstance(extra, dict) else {})
            schema_check(item, child, f'{path}.{key}')


def reject_secrets(value):
    # Nigdy nie wypisuj podejrzanej wartości w błędzie.
    def strings(node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for key, item in node.items():
                yield str(key)
                yield from strings(item)
        elif isinstance(node, list):
            for item in node:
                yield from strings(item)
    text = '\n'.join(strings(value))
    patterns = (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY',
                r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})',
                r'(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)[\"\x27]?\s*[=:]\s*[\"\x27]?[^\s\"\x27,;]{8,}',
                r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                r'://[^\s/:]+:[^\s/@]+@')
    if any(re.search(p, text) for p in patterns):
        raise ValueError('Wartość wygląda na sekret; zapis/odczyt odrzucony')


def target(repo, mapping):
    repo = Path(repo).resolve()
    parts = re.split(r'::|(?<=\w)\.(?=test_)', mapping)
    if len(parts) != 3 or not re.fullmatch(r'[A-Za-z_]\w*', parts[1]) or not re.fullmatch(r'test_\w+', parts[2]):
        raise ValueError('mapowanie musi mieć postać plik.py::Klasa.test_metoda')
    file = Path(parts[0])
    if file.is_absolute() or '..' in file.parts or file.suffix != '.py':
        raise ValueError('niedozwolona ścieżka testu')
    path = repo / file
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.resolve().is_relative_to(repo.resolve()):
        raise ValueError('symlink/ścieżka poza repo')
    tree = ast.parse(path.read_text(encoding='utf-8'))
    cls = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == parts[1]), None)
    method = next((n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == parts[2]), None) if cls else None
    if method is None:
        raise ValueError('brak klasy/metody testu')
    return path, parts[1], parts[2]


RUNNER = '''import importlib.util, io, json, pathlib, sys, unittest
root, filename, cls, method = sys.argv[1:]
sys.path[:0] = [str(pathlib.Path(filename).parent), root + '/bin', root]
spec = importlib.util.spec_from_file_location(pathlib.Path(filename).stem, filename)
m = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m; spec.loader.exec_module(m)
t = getattr(m, cls)
if not issubclass(t, unittest.TestCase): raise TypeError('not TestCase')
r = unittest.TextTestRunner(stream=io.StringIO()).run(unittest.TestSuite([t(method)]))
ok = r.testsRun == 1 and r.wasSuccessful() and not r.skipped and not r.expectedFailures
print('HELIX_RESULT=' + json.dumps({'passed': ok, 'testsRun': r.testsRun, 'skipped': len(r.skipped)}))
sys.exit(0 if ok else 2)
'''


def run_test(repo, mapping, timeout=120):
    path, cls, method = target(repo, mapping)
    env = {k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'TMPDIR', 'LANG') if k in os.environ}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    try:
        p = subprocess.run([sys.executable, '-c', RUNNER, str(repo.resolve()), str(path.resolve()), cls, method], cwd=repo, env=env, capture_output=True, text=True, timeout=timeout)
        records = [line.removeprefix('HELIX_RESULT=') for line in p.stdout.splitlines() if line.startswith('HELIX_RESULT=')]
        result = json.loads(records[-1]) if records else {}
        return {'passed': p.returncode == 0 and result.get('passed') is True and result.get('testsRun') == 1, 'exit': p.returncode, 'testsRun': result.get('testsRun', 0), 'skipped': result.get('skipped', 0)}
    except subprocess.TimeoutExpired:
        return {'passed': False, 'reason': 'timeout'}


def waiver_valid(waiver):
    if not isinstance(waiver, dict) or waiver.get('owner') != 'Owner' or not str(waiver.get('reason', '')).strip():
        return False
    try:
        date = dt.date.fromisoformat(waiver['date'])
        return date <= dt.datetime.now(dt.timezone.utc).date()
    except (KeyError, TypeError, ValueError):
        return False


def touch_check(repo, since, ledger):
    if not since or since.startswith('-'):
        raise ValueError('--require-ledger-touch wymaga --since REF')
    def git(*args):
        p = subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True)
        if p.returncode:
            raise ValueError('Nie można sprawdzić historii git')
        return p.stdout
    base = git('rev-parse', '--verify', since + '^{commit}').strip()
    relative = str(ledger.resolve().relative_to(repo.resolve()))
    def check_change(files, message):
        statements = any(f == 'docs/owner-statements' or f.startswith('docs/owner-statements/') or f.startswith('docs/owner-statements.') for f in files)
        if (statements or re.search(r'^Owner-Statement:\s*\S', message, re.M | re.I)) and relative not in files:
            raise ValueError('Owner-Statement wymaga zmiany ledgeru w tym samym commicie')
    for sha in git('rev-list', base + '..HEAD').splitlines():
        files = git('diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '-m', sha).splitlines()
        check_change(files, git('show', '-s', '--format=%B', sha))
    check_change(git('diff', '--name-only', 'HEAD').splitlines() + git('ls-files', '--others', '--exclude-standard').splitlines(), '')


def check(repo, ledger, baseline=None, run=False, require_touch=False, since=None):
    repo, ledger = Path(repo).resolve(), Path(ledger)
    errors, execution = [], {}
    result = {'pass': False, 'covered': 0, 'partial': 0, 'missing': 0, 'done': 0, 'debt': [], 'errors': errors, 'execution': execution, 'execution_status': 'not-run'}
    try:
        data = load(ledger)
        reject_secrets(data)
        schema_check(data, load(HOME / 'schemas/requirements-ledger.schema.json'))
        entries = data['requirements']
        seen = set()
        for ident, waiver in data.get('waivers', {}).items():
            if not re.fullmatch(r'REQ-[A-Z]-\d{2,}', ident) or not waiver_valid(waiver):
                errors.append('Niepoprawny waiver usuniętego REQ')
        for item in entries:
            ident = item['id']
            if ident in seen:
                errors.append(f'{ident}: powtórzony ID')
            seen.add(ident)
            if 'waiver' in item and not waiver_valid(item['waiver']):
                errors.append(f'{ident}: niepoprawny waiver właściciela')
            if item['group'] != ident.split('-')[1]:
                errors.append(f'{ident}: niezgodna grupa')
            if item['priority'] == 'MUST' and not item['acceptance'].strip():
                errors.append(f'{ident}: MUST bez testu akceptacyjnego (opisu)')
            if item['status'] == 'done' and not item['tests']:
                errors.append(f'{ident}: done bez mapowania testu')
            valid = bool(item['tests'])
            for mapping in item['tests']:
                try:
                    target(repo, mapping)
                except (OSError, ValueError, SyntaxError):
                    errors.append(f'{ident}: nieistniejący lub niepoprawny test {mapping}')
                    valid = False
            result['covered'] += int(valid)
            result['done'] += int(item['status'] == 'done')
            result['missing' if item['status'] == 'missing' else 'partial'] += int(item['status'] != 'done')
            if item['priority'] == 'MUST' and item['status'] != 'done':
                result['debt'].append({'id': ident, 'status': item['status']})
        if baseline is not None:
            old = load(baseline)
            reject_secrets(old)
            schema_check(old, load(HOME / 'schemas/requirements-ledger.schema.json'))
            current = {r['id']: r for r in entries}
            for previous in old['requirements']:
                ident = previous['id']
                now = current.get(ident)
                regressed = now is None or RANK[now['status']] < RANK[previous['status']] or bool(previous['tests']) and not now['tests']
                if regressed and not waiver_valid((now or {}).get('waiver', data.get('waivers', {}).get(ident))):
                    errors.append(f'{ident}: regresja statusu/pokrycia lub usunięty REQ; brak waivera właściciela')
        if require_touch:
            touch_check(repo, since, ledger)
        if run and not errors:
            for mapping in sorted({m for r in entries for m in r['tests']}):
                execution[mapping] = run_test(repo, mapping)
            for item in entries:
                if any(not execution[m]['passed'] for m in item['tests']):
                    errors.append(f"{item['id']}: regresja REQ — test FAIL/SKIP/timeout/zero testów")
            result['execution_status'] = 'fail' if errors else 'pass'
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # JSON parser exceptions may contain input; do not echo them.
        errors.append('Błędny JSON lub odczyt pliku' if isinstance(exc, (json.JSONDecodeError, OSError)) else str(exc))
    result['pass'] = not errors
    return result


def register(subparsers):
    p = subparsers.add_parser('requirements', help='Ledger wymagań: check/add/report')
    p.add_argument('action', choices=['check', 'add', 'report'])
    p.add_argument('--ledger', default='requirements/ledger.json')
    p.add_argument('--baseline')
    p.add_argument('--run', action='store_true')
    p.add_argument('--json', action='store_true')
    p.add_argument('--require-ledger-touch', action='store_true')
    p.add_argument('--since')
    for name in ('group', 'text', 'source', 'quote', 'acceptance'):
        p.add_argument('--' + name)
    p.add_argument('--priority', choices=['MUST', 'SHOULD'], default='MUST')


def dispatch(args):
    repo = Path(args.repo).resolve()
    ledger = Path(args.ledger)
    ledger = ledger if ledger.is_absolute() else repo / ledger
    try:
        if args.action == 'add':
            data = load(ledger)
            for name in ('group', 'text', 'source', 'quote', 'acceptance'):
                if not getattr(args, name) or not getattr(args, name).strip():
                    raise ValueError('add: wymagane pole --' + name)
            if not re.fullmatch('[A-Z]', args.group):
                raise ValueError('grupa: jedna wielka litera')
            numbers = [int(r['id'].split('-')[-1]) for r in data['requirements'] if r['group'] == args.group]
            ident = f'REQ-{args.group}-{max(numbers, default=0)+1:02d}'
            data['requirements'].append(dict(id=ident, group=args.group, text=args.text, priority=args.priority, sources=[{'file': args.source, 'quote': args.quote}], acceptance=args.acceptance, status='missing', tests=[], evidence=[]))
            reject_secrets(data)
            schema_check(data, load(HOME / 'schemas/requirements-ledger.schema.json'))
            ledger.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(ident)
            return 0
        baseline = Path(args.baseline) if args.baseline else repo / 'requirements/baseline.json'
        if args.baseline and not baseline.is_absolute():
            baseline = repo / baseline
        result = check(repo, ledger, baseline if args.baseline or baseline.exists() else None, args.run, args.require_ledger_touch, args.since)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print('| wynik | covered (mapowania) | partial/in-progress | missing | dług MUST |')
            print('|---|---:|---:|---:|---:|')
            print(f"| {'PASS' if result['pass'] else 'FAIL'} | {result['covered']} | {result['partial']} | {result['missing']} | {len(result['debt'])} |")
            print(f"Wykonanie: {result['execution_status']}. Pokrycie statyczne nie oznacza wykonania.")
            for error in result['errors']:
                print('FAIL: ' + error)
            if args.action == 'report':
                print('\nDług MUST (ASSUMPTION: kompletność realizacji wymaga przeglądu):')
                for row in result['debt']:
                    print(f"- {row['id']}: {row['status']}")
        return 0 if result['pass'] else 2
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # Only our fixed validation messages are safe; never echo user data.
        message = str(exc) if isinstance(exc, ValueError) and str(exc).startswith(('add: wymagane pole --', 'grupa:', 'Wartość wygląda na sekret')) else 'niepoprawne dane lub schemat ledgeru'
        print('FAIL: ' + message, file=sys.stderr)
        return 2
