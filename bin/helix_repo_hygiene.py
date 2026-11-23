"""Read-only, offline repository hygiene; candidates never earn execution credit."""
from collections import defaultdict
import json
from pathlib import Path
import re
from helix_git_readonly import git as read_git
from helix_contracts import VERSION
from helix_audit_context import sensitive, safe_read
from helix_static_security import finding


def report(repo, require_exact=False):
    root = Path(repo).resolve()
    rows, limitations = [], []
    p = read_git(root, 'ls-files', '-z', text=False, timeout=30)
    if p.returncode:
        return dict(helix_version=VERSION, schema_version=1, findings=[], status='not-run', execution_credit=0,
                    limitations=['Brak inwentarza git; brak punktów.'])
    names = p.stdout.decode('utf-8', errors='replace').split('\0')
    texts = {}
    def emit(code, name, why, fix, severity='medium', line=1, confidence='likely'):
        row = finding(code, why, name, '', 0, why, fix, severity, confidence, 'repo_hygiene')
        row.update(line=line, evidence=[f'{name}:{line}'], tag='ASSUMPTION', verification_status='candidate', execution_credit=0)
        rows.append(row)
    for name in filter(None, names):
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
            limitations.append(name + ': pominięty symlink/submodule/brak pliku'); continue
        if (any(sensitive(part) for part in Path(name).parts) or re.search(r'\.(?:pem|key|p12|pfx)$', name, re.I)) and not re.search(r'(?:example|sample|template)', name, re.I):
            emit('HYGIENE-SECRET-PATH', name, 'Śledzona ścieżka potencjalnego sekretu; treści nie odczytano.', 'Usuń sekret z repo i przeprowadź rotację, jeśli zawiera poświadczenia.', 'high', confidence='possible')
            limitations.append(name + ': treść celowo nieodczytana'); continue
        if path.stat().st_size > 5 * 1024 * 1024:
            emit('HYGIENE-LARGE', name, 'Plik przekracza 5 MiB.', 'Przenieś artefakt do magazynu lub LFS.', 'low')
            limitations.append(name + ': treść dużego pliku not-run'); continue
        try:
            text = safe_read(path)
        except OSError:
            limitations.append(name + ': bezpieczny odczyt not-run'); continue
        if '\0' in text: continue
        raw = text.encode('utf-8'); texts[name] = text
        if re.search(r'(?:\.orig|\.bak|~)$', name) or re.match(r'(?:.*/)?tmp[^/]*$', name):
            emit('HYGIENE-TEMP', name, 'Śledzony plik tymczasowy/backup.', 'Usuń artefakt z indeksu i dodaj regułę ignorowania.', 'low')
        for n, line in enumerate(text.splitlines(), 1):
            if re.match(r'^(?:<{7}|>{7}|={7})(?:\s|$)', line):
                emit('HYGIENE-CONFLICT', name, 'Marker konfliktu merge.', 'Rozwiąż konflikt i sprawdź wynik.', 'high', n)
            if re.search(r'\b(?:TODO|FIXME)\b', line) and not re.search(r'(?:#\d+|[A-Z]+-\d+|https?://)', line):
                if re.search(r'(?:auth|security|payment|migration)', name, re.I):
                    emit('HYGIENE-TODO', name, 'TODO/FIXME bez ticketu w potencjalnie krytycznej ścieżce.', 'Powiąż zadanie z ticketem.', 'info', n, 'possible')
        if b'\r\n' in raw and re.search(rb'(?<!\r)\n', raw):
            emit('HYGIENE-EOL', name, 'Mieszane końce linii.', 'Ujednolić końce linii przez .editorconfig.', 'low')
    def missing(parent, candidates, code, why):
        if not any((parent / n).as_posix() in texts for n in candidates):
            anchor = (parent / candidates[0]).as_posix()
            emit(code, anchor, why, 'Dodaj i zacommituj wymagany plik.', 'low', confidence='possible')
    for name, text in texts.items():
        parent = Path(name).parent
        if Path(name).name == 'package.json':
            try: manifest = json.loads(text)
            except ValueError:
                emit('HYGIENE-MANIFEST', name, 'Niepoprawny JSON manifestu.', 'Napraw manifest.', 'high'); continue
            missing(parent, ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'], 'HYGIENE-LOCK', 'Manifest Node bez śledzonego lockfile.')
            lockname = (parent / 'package-lock.json').as_posix()
            if lockname in texts:
                try:
                    lock = json.loads(texts[lockname]); package = lock.get('packages', {}).get('')
                    if package is None:
                        limitations.append(lockname + ': zgodność starego formatu not-run')
                    else:
                        for section in ('dependencies', 'devDependencies', 'optionalDependencies'):
                            if manifest.get(section, {}) != package.get(section, {}):
                                emit('HYGIENE-LOCK-DRIFT', lockname, 'Manifest różni się od wpisu root lockfile.', 'Odtwórz lockfile właściwym managerem.', 'high')
                except ValueError: emit('HYGIENE-LOCK-JSON', lockname, 'Niepoprawny JSON lockfile.', 'Odtwórz lockfile.', 'high')
            elif any((parent / n).as_posix() in texts for n in ('pnpm-lock.yaml', 'yarn.lock')):
                limitations.append(name + ': semantyczna zgodność pnpm/yarn not-run (brak parsera)')
            if require_exact:
                for dep, value in manifest.get('dependencies', {}).items():
                    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[\w.]+)?', value):
                        emit('HYGIENE-PIN', name, 'Zależność produkcyjna bez dokładnego semver: ' + dep, 'Przypnij wersję zgodnie z profilem.', 'medium', text[:text.find('"' + dep + '"')].count('\n') + 1)
        elif Path(name).name == 'pyproject.toml':
            missing(parent, ['poetry.lock', 'uv.lock'], 'HYGIENE-LOCK', 'Projekt Python bez śledzonego lockfile.')
            limitations.append(name + ': semantyczna zgodność Python lockfile not-run')
        elif Path(name).name == 'go.mod':
            missing(parent, ['go.sum'], 'HYGIENE-LOCK', 'Projekt Go bez śledzonego go.sum; sprawdź zależności.')
            limitations.append(name + ': zgodność sum Go not-run; go.sum nie jest ścisłym lockfile')
    for name, text in texts.items():
        if not name.endswith('.json'): continue
        if not re.search(r'(?:ledger|decisions?|registry|register|adr)', name, re.I): continue
        try: document = json.loads(text)
        except ValueError: continue
        arrays = [document] if isinstance(document, list) else [v for k, v in document.items() if k in ('requirements', 'decisions', 'registry', 'ids') and isinstance(v, list)] if isinstance(document, dict) else []
        for items in arrays:
            seen = set()
            for item in items:
                ident = item.get('id') if isinstance(item, dict) else item if isinstance(item, str) else None
                if not isinstance(ident, str): continue
                if ident in seen:
                    emit('HYGIENE-ID-DUP', name, 'Powtórzony identyfikator: ' + ident, 'Nadaj unikalny ID i popraw odwołania.', 'high')
                seen.add(ident)
    migrations = defaultdict(lambda: defaultdict(list))
    for name in texts:
        if re.search(r'(?:^|/)(?:migrations?|versions)/', name):
            match = re.match(r'(\d+)[_.-]', Path(name).name)
            if match: migrations[str(Path(name).parent)][int(match[1])].append(name)
    for directory, numbers in migrations.items():
        for number, files in numbers.items():
            if len(files) > 1:
                emit('HYGIENE-MIGRATION-DUP', files[0], 'Powtórzony numer migracji: ' + str(number), 'Nadaj unikalny numer w tym strumieniu.', 'high')
        ordered = sorted(numbers)
        # Timestamp migrations are not sequential counters.
        if ordered and ordered[-1] < 100000:
            for left, right in zip(ordered, ordered[1:]):
                if right != left + 1:
                    emit('HYGIENE-MIGRATION-GAP', numbers[right][0], 'Luka w numeracji migracji.', 'Wyjaśnij brak lub napraw numerację.', confidence='possible')
    for pattern, code, why in [
        (r'(?:^|/)LICENSE(?:\.[^/]*)?$', 'LICENSE', 'Brak śledzonej licencji.'),
        (r'(?:^|/)CODEOWNERS$', 'OWNERS', 'Brak CODEOWNERS dla przeglądu ścieżek krytycznych.'),
        (r'^\.editorconfig$', 'EDITOR', 'Brak .editorconfig.'),
        (r'(?:^|/)(?:\.nvmrc|\.python-version|\.tool-versions|rust-toolchain.toml)$', 'TOOLCHAIN', 'Brak osobnego pina toolchainu; sprawdź engines/toolchain w manifestach.')]:
        if not any(re.search(pattern, n) for n in texts):
            emit('HYGIENE-' + code, '.', why, 'Dodaj konfigurację odpowiednią dla profilu projektu.', 'low', confidence='possible')
    ignored = texts.get('.gitignore', '')
    for token in ('.env', 'node_modules', '__pycache__', 'dist'):
        if token not in ignored:
            emit('HYGIENE-IGNORE', '.gitignore', 'Brak jawnej reguły ignorowania: ' + token, 'Sprawdź profil i dodaj regułę, jeśli dotyczy.', 'low', confidence='possible')
    if not any(re.search(r'^#\s+v?\d+\.\d+\.\d+', text, re.M) for name, text in texts.items() if Path(name).name.lower().startswith('changelog')):
        emit('HYGIENE-CHANGELOG', 'CHANGELOG.md', 'Brak CHANGELOG z semver.', 'Dokumentuj wersje projektu.', 'low', confidence='possible')
    merges = read_git(root, 'log', '--no-show-signature', '--no-ext-diff', '--no-textconv', '--merges', '-n', '30', '--format=%H', timeout=30)
    if merges.returncode:
        limitations.append('Historia merge: not-run')
    else:
        for sha in merges.stdout.splitlines():
            diff = read_git(root, 'diff-tree', '--no-ext-diff', '--no-textconv', '--no-commit-id', '-r', '--numstat', sha + '^1', sha, timeout=30)
            if diff.returncode:
                limitations.append(sha + ': rozmiar merge not-run'); continue
            stats = [line.split('\t', 2) for line in diff.stdout.splitlines()]
            changed = sum(int(a) + int(b) for a, b, _ in stats if a.isdigit() and b.isdigit())
            if len(stats) >= 30 or changed >= 1000:
                emit('HYGIENE-MERGE-REVIEW', stats[0][2] if stats else '.', 'Duży merge ' + sha[:12] + ': ' + str(len(stats)) + ' plików, ' + str(changed) + ' linii; sposób rozwiązania nieudowodniony.', 'Człowiek powinien przejrzeć rozwiązania konfliktów i testy integracyjne.', confidence='possible')
    if not any(re.search(r'(?:branch protection|required checks|ochron[ayę] gałęzi|wymagane kontrole)', text, re.I) for name, text in texts.items() if name.endswith('.md')):
        emit('HYGIENE-BRANCH-DOC', 'docs/', 'Brak dokumentacji ochrony gałęzi i wymaganych kontroli.', 'Opisz politykę i odpowiedzialność za kontrole CI.', 'low', confidence='possible')
    pin = root / 'helix.json'
    if pin.is_file() and not pin.is_symlink():
        try:
            if json.loads(pin.read_text()).get('helix_version') != VERSION:
                emit('HYGIENE-HELIX-PIN', 'helix.json', 'Pin Helixa różni się od uruchomionej wersji.', 'Uzgodnij aktualizację pina z właścicielem.', 'low')
        except ValueError: emit('HYGIENE-CONFIG', 'helix.json', 'Niepoprawny JSON.', 'Napraw konfigurację.', 'high')
    return dict(helix_version=VERSION, schema_version=1, findings=rows, execution_credit=0,
                status='candidate', limitations=limitations + ['Ochrona gałęzi i required checks na serwerze: not-run offline.',
                'Podpisy commitów i semantyczna analiza rozwiązań merge: not-run; brak punktów.',
                'Brak zastosowania profilu nie jest dowodem N/A.'])


def parsers(sp):
    p = sp.add_parser('repo-hygiene', help='Higiena repo offline (tylko odczyt)')
    p.add_argument('--require-exact', action='store_true')


def dispatch(args):
    data = report(args.repo, args.require_exact)
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 2 if any(r['severity'] == 'high' for r in data['findings']) or data['status'] == 'not-run' else 0
