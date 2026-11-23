"""Opcjonalne adaptery tools; tylko lokalne procesy na odfiltrowanej kopii."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

from helix_runtime import copy_project, locate
from helix_packs import finding, relative, dedupe

# Metadata is explicit even for adapters awaiting an offline execution contract.
GROUPS = {
    'security': 'ast-grep semgrep gitleaks trufflehog osv-scanner trivy grype syft checkov kics zizmor hadolint dockle bandit gosec njsscan eslint-plugin-security retire pip-audit zap',
    'database': 'squawk sqlfluff',
    'quality': 'shellcheck actionlint typos codespell vale markdownlint-cli2 lychee cspell knip depcheck jscpd madge dependency-cruiser radon',
    'ui': 'axe pa11y stylelint svelte-check tsc eslint',
    'tests': 'stryker mutmut',
    'licenses': 'scancode licensee',
}
COMMANDS = {'dependency-cruiser': 'depcruise', 'squawk': 'squawk', 'kics': 'podman', 'zap': 'podman', 'eslint-plugin-security': 'eslint'}
LICENSES = {'ast-grep': 'MIT',
 'shellcheck': 'GPL-3.0',
 'actionlint': 'MIT',
 'typos': 'Apache-2.0 OR MIT',
 'codespell': 'GPL-2.0',
 'hadolint': 'GPL-3.0',
 'bandit': 'Apache-2.0',
 'zizmor': 'MIT',
 'gitleaks': 'MIT',
 'semgrep': 'LGPL-2.1',
 'sqlfluff': 'MIT',
 'radon': 'MIT',
 'trufflehog': 'AGPL-3.0',
 'osv-scanner': 'Apache-2.0',
 'trivy': 'Apache-2.0',
 'grype': 'Apache-2.0',
 'syft': 'Apache-2.0',
 'checkov': 'Apache-2.0',
 'kics': 'Apache-2.0',
 'dockle': 'Apache-2.0',
 'gosec': 'Apache-2.0',
 'njsscan': 'LGPL-3.0',
 'eslint-plugin-security': 'Apache-2.0',
 'retire': 'Apache-2.0',
 'pip-audit': 'Apache-2.0',
 'zap': 'Apache-2.0',
 'squawk': 'Apache-2.0 OR MIT',
 'vale': 'MIT',
 'markdownlint-cli2': 'MIT',
 'lychee': 'Apache-2.0 OR MIT',
 'cspell': 'MIT',
 'knip': 'ISC',
 'depcheck': 'MIT',
 'jscpd': 'MIT',
 'madge': 'MIT',
 'dependency-cruiser': 'MIT',
 'axe': 'MPL-2.0',
 'pa11y': 'LGPL-3.0',
 'stylelint': 'MIT',
 'svelte-check': 'MIT',
 'tsc': 'Apache-2.0',
 'eslint': 'MIT',
 'stryker': 'Apache-2.0',
 'mutmut': 'BSD-3-Clause',
 'scancode': 'Apache-2.0',
 'licensee': 'MIT'}
CONFIG = Path(__file__).resolve().parents[1] / 'config/tools'
ARGS = {
    'checkov': ['-d', '.', '--framework', 'terraform', '--output', 'json', '--quiet', '--compact', '--skip-download', '--skip-results-upload', '--download-external-modules', 'false', '--config-file', str(CONFIG / 'checkov.yml')],
    'njsscan': ['--json', '.'],
    'gosec': ['-fmt=json', './...'],
    'trufflehog': ['--json', '--no-update', 'filesystem', '--no-verification', '.'],
    'squawk': ['--reporter', 'json', '--config', str(CONFIG / 'squawk.toml')],
    'sqlfluff': ['lint', '--ignore-local-config', '--templater', 'raw', '--dialect', 'postgres', '--format', 'json'],
    'radon': ['cc', '--json', '.'],
    'stylelint': ['--formatter', 'json', '--config', str(CONFIG / 'stylelint.json')],
    'jscpd': ['--config', str(CONFIG / 'jscpd.json'), '--output', '.helix-jscpd', '.'],
    'shellcheck': ['--format=json'], 'actionlint': ['-format', '{{json .}}'],
    'typos': ['--format', 'json'], 'codespell': ['--quiet-level=2'],
    'hadolint': ['--format', 'json'], 'bandit': ['-r', '.', '-f', 'json', '-q'],
    'zizmor': ['--offline', '--format', 'json', '.'],
    'gitleaks': ['dir', '.', '--config', str(CONFIG / 'gitleaks.toml'), '--redact=100', '--no-banner', '--report-format', 'json', '--report-path', '.helix-gitleaks.json'],
    'semgrep': ['scan', '--config', str(Path(__file__).resolve().parents[1] / 'config/tools/semgrep.yml'), '--json', '--metrics=off', '--disable-version-check', '.'],
}
PATTERNS = {'squawk': ('**/*.sql',),
 'sqlfluff': ('**/*.sql',),
 'stylelint': ('**/*.css',),
 'shellcheck': ('**/*.sh',),
 'actionlint': ('.github/workflows/*.yml', '.github/workflows/*.yaml'),
 'hadolint': ('**/*Dockerfile*',),
 'typos': ('**/*',),
 'codespell': ('**/*',)}


CATCHES = {'ast-grep': 'strukturalne kandydatury AUTH/IDOR/OTP/UPLOAD/MASS; luki parsera i fallback zapisane per plik',
 'semgrep': 'lokalne reguły Python eval i SvelteKit taint params/searchParams/json → SQL/fetch/fs; bez pobierania reguł',
 'gitleaks': 'potencjalne sekrety; wartości redagowane',
 'trufflehog': 'potencjalne sekrety w filesystem; bez weryfikacji',
 'osv-scanner': 'znane podatności zależności; wymaga lokalnej bazy',
 'trivy': 'podatności zależności i błędy konfiguracji',
 'grype': 'podatności z SBOM; lokalna baza',
 'syft': 'inwentarz zależności SBOM',
 'checkov': 'bezpieczeństwo IaC Terraform',
 'kics': 'bezpieczeństwo IaC w lokalnym obrazie Podman',
 'zizmor': 'ryzykowne GitHub Actions',
 'hadolint': 'błędy Dockerfile',
 'dockle': 'higiena istniejącego obrazu kontenera',
 'bandit': 'niebezpieczne wzorce Python',
 'gosec': 'niebezpieczne wzorce Go',
 'njsscan': 'niebezpieczne wzorce JavaScript/Node',
 'eslint-plugin-security': 'niebezpieczne wzorce JavaScript',
 'retire': 'znane podatności JS; lokalne advisory',
 'pip-audit': 'podatności Python; wymaga bazy offline',
 'zap': 'pasywny baseline lokalnej efemerycznej aplikacji',
 'squawk': 'ryzyko migracji Postgres',
 'sqlfluff': 'składnia i styl SQL (Postgres/raw)',
 'shellcheck': 'błędy skryptów shell',
 'actionlint': 'błędy GitHub Actions',
 'typos': 'literówki',
 'codespell': 'częste literówki',
 'vale': 'styl UI copy i dokumentacji',
 'markdownlint-cli2': 'struktura Markdown',
 'lychee': 'lokalne linki; --offline',
 'cspell': 'pisownia i lokalny słownik PL',
 'knip': 'nieużywane eksporty i zależności',
 'depcheck': 'nieużywane zależności',
 'jscpd': 'zduplikowany kod; bez modeli semantycznych',
 'madge': 'cykle zależności JS/TS',
 'dependency-cruiser': 'granice i cykle zależności',
 'radon': 'złożoność cyklomatyczna Python >10',
 'axe': 'dostępność; istniejący uideep',
 'pa11y': 'dostępność lokalnej aplikacji runtime',
 'stylelint': 'puste bloki i niepoprawne kolory CSS',
 'svelte-check': 'typy i diagnostyka Svelte',
 'tsc': 'typy TypeScript',
 'eslint': 'diagnostyka JavaScript/TypeScript',
 'stryker': 'mutacje JS/TS w kopii runtime',
 'mutmut': 'mutacje Python w kopii runtime',
 'scancode': 'licencje i copyright',
 'licensee': 'licencja projektu'}


# Existence of a dispatch path is distinct from its execution or calibration.
RUNNERS = {name: 'tools scan' for name in ARGS}
RUNNERS.update({'ast-grep': 'review deep / security deep risk plan',
                'knip': 'tools scan',
                'licensee': 'tools scan', 'scancode': 'tools scan',
                'axe': 'ux scan / runtime a11y', 'svelte-check': 'precheck', 'tsc': 'precheck',
                'eslint': 'precheck', 'stryker': 'runtime mutation', 'mutmut': 'runtime mutation'})


def metadata(name, area):
    return dict(name=name, command=COMMANDS.get(name, name), license=LICENSES.get(name, 'unverified'),
                license_status='ASSUMPTION', perspectives={'security':['security','dev','ops'], 'database':['ops','dev','security'], 'quality':['dev','QA','writer'], 'ui':['UI','UX','QA'], 'tests':['QA','dev'], 'licenses':['security','PM','writer']}[area],
                area=area, catches=CATCHES[name], offline=name in ARGS or name == 'knip',
                parser=name if name in ARGS or name == 'knip' else None, timeout=60,
                runner=RUNNERS.get(name), runner_implemented=name in RUNNERS)


REGISTRY = {n: metadata(n, area) for area, names in GROUPS.items() for n in names.split()}


def environment(home):
    return dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), HOME=str(home),
                XDG_CACHE_HOME=str(home / 'cache'), NO_COLOR='1',
                SEMGREP_SEND_METRICS='off', SEMGREP_ENABLE_VERSION_CHECK='0',
                GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local',
                GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')


def discover():
    rows = []
    with tempfile.TemporaryDirectory(prefix='helix-tool-version-') as tmp:
        for name, spec in REGISTRY.items():
            row = dict(spec, executable=locate(spec['command']), version=None)
            row['status'] = 'available' if row['executable'] else 'unavailable'
            row['reason'] = 'lokalny plik wykonywalny' if row['executable'] else 'brak programu'
            # Do not start containers, browsers, mutation engines or project loaders for discovery.
            if row['executable'] and name in ARGS:
                try:
                    p = subprocess.run([row['executable'], '--version'], cwd=tmp, env=environment(Path(tmp)), capture_output=True, text=True, timeout=5)
                    row['version'] = (p.stdout or p.stderr).strip()[:160] if p.returncode == 0 else None
                except (OSError, subprocess.TimeoutExpired):
                    row['reason'] = 'nie udało się odczytać wersji'
            rows.append(row)
    return rows



EXPLANATIONS = {
    'knip': ('Eksport lub plik może nie mieć aktywnego odbiorcy.', 'Sprawdź dynamiczne wejścia przed usunięciem kodu.'),
    'shellcheck': ('Rozwijanie zmiennych i składnia powłoki mogą zmienić argumenty lub przebieg skryptu.', 'Popraw cytowanie i składnię wskazane przez regułę ShellCheck.'),
    'actionlint': ('Niepoprawna definicja workflow może uniemożliwić wykonanie CI.', 'Popraw wskazany klucz, wyrażenie lub etykietę runnera.'),
    'typos': ('Literówka może zmieniać znaczenie nazw albo dokumentacji.', 'Popraw pisownię lub uzasadnij termin w lokalnym słowniku.'),
    'codespell': ('Częsta literówka utrudnia zrozumienie tekstu.', 'Popraw pisownię; nazwy własne dodawaj do słownika po przeglądzie.'),
    'hadolint': ('Instrukcja Dockerfile narusza regułę powtarzalności lub bezpieczeństwa obrazu.', 'Przypnij obraz i popraw instrukcję według wskazanej reguły DL/SC.'),
    'bandit': ('Wzorzec Python może umożliwiać wykonanie niezaufanego kodu lub osłabić ochronę danych.', 'Usuń niebezpieczny mechanizm lub dodaj ścisłą walidację i dowód bezpieczeństwa.'),
    'semgrep': ('Dynamiczne eval może wykonać kod pochodzący z niezaufanego wejścia.', 'Zastąp eval parserem danych albo jawną allowlistą operacji.'),
    'gitleaks': ('Wartość przypomina poświadczenie; jej obecność może ujawnić dostęp do systemu.', 'Zweryfikuj bez publikacji wartości; usuń i zrotuj rzeczywiste poświadczenie.'),
    'trufflehog': ('Detektor wskazał potencjalne poświadczenie; nie wykonywano weryfikacji sieciowej.', 'Zweryfikuj lokalnie bez ujawniania wartości; rzeczywiste poświadczenie usuń i zrotuj.'),
    'zizmor': ('Workflow może nadawać nadmiarowe uprawnienia lub ufać niezaufanemu kodowi akcji.', 'Ogranicz permissions i triggery, przypnij akcje do SHA, oddziel niezaufane wejścia.'),
    'checkov': ('Zasób IaC nie spełnia wskazanej kontroli bezpieczeństwa.', 'Sprawdź wskazany CKV i dodaj brakującą kontrolę w konfiguracji zasobu.'),
    'gosec': ('Wzorzec Go może osłabiać bezpieczeństwo wejść, procesów lub kryptografii.', 'Popraw wskazaną regułę G i potwierdź negatywnym testem bezpieczeństwa.'),
    'njsscan': ('Wzorzec Node/JavaScript może przekazywać niezaufane dane do niebezpiecznego mechanizmu.', 'Ogranicz wejście allowlistą i zastąp niebezpieczny mechanizm bezpiecznym API.'),
    'squawk': ('Migracja może blokować ruch, usunąć dane lub złamać zgodność istniejących klientów.', 'Zastosuj expand/contract, limity blokad i bezpieczny wariant wskazanej operacji.'),
    'sqlfluff': ('SQL narusza regułę składni lub spójnego formatowania dialektu Postgres.', 'Popraw wskazaną regułę SQL; błąd parsowania zweryfikuj względem dialektu.'),
    'stylelint': ('CSS zawiera pusty blok lub niepoprawną wartość koloru.', 'Usuń pusty blok albo popraw wartość koloru wskazanej deklaracji.'),
    'jscpd': ('Powielony fragment może rozchodzić się podczas kolejnych poprawek.', 'Porównaj kopie; ujednolić je lub wydzielić wspólną funkcję, jeśli mają wspólną odpowiedzialność.'),
    'radon': ('Złożoność cyklomatyczna funkcji przekracza 10 i zwiększa liczbę ścieżek wymagających testów.', 'Uprość warunki i wydziel spójne operacje; zachowaj testy wszystkich ścieżek.'),
}

def parse(name, raw, root):
    """Drop source excerpts/messages: tool output can contain credentials."""
    if name == 'actionlint':
        data = json.loads(raw) if raw.strip() else []
    elif name in ('typos', 'trufflehog'):
        data = [json.loads(line) for line in raw.splitlines() if line.strip()]
    elif name == 'codespell':
        import re
        data = [dict(file=m[1], line=int(m[2]), code='spelling') for line in raw.splitlines() if (m := re.match(r'(.+?):(\d+):', line))]
        if raw.strip() and not data:
            raise ValueError('niepoprawny wynik codespell')
    else:
        data = json.loads(raw)
    if name in ('bandit', 'semgrep'):
        if data.get('errors'): raise ValueError('niepełny skan')
        data = data['results']
    if name == 'checkov' and isinstance(data, dict) and data.get('resource_count') == 0 and data.get('failed') == 0 and data.get('parsing_errors') == 0:
        data = []
    if name == 'checkov':
        groups = data if isinstance(data, list) else [data]
        if any(g.get('summary', {}).get('parsing_errors', 0) for g in groups): raise ValueError('niepełny skan')
        data = [dict(file=x['file_path'].lstrip('/'), line=x['file_line_range'][0], code=x['check_id'], level='medium') for group in groups for x in group['results']['failed_checks']]
    if name == 'gosec':
        data = [dict(file=x['file'], line=int(str(x['line']).split('-')[0]), code=x['rule_id'], level=x['severity']) for x in data.get('Issues') or []]
    if name == 'njsscan':
        data = [dict(file=f['file_path'], line=f['match_lines'][0], code=rule, level=group['metadata']['severity']) for rule, group in data['nodejs'].items() for f in group['files']]
    if name == 'trufflehog':
        data = [dict(file=x['SourceMetadata']['Data']['Filesystem']['file'], line=x['SourceMetadata']['Data']['Filesystem']['line'], code=x['DetectorName'], level='high') for x in data]
    if name == 'sqlfluff':
        data = [dict(file=group['filepath'], line=x['start_line_no'], code=x['code'], level='low') for group in data for x in group['violations']]
    if name == 'radon':
        if any(not isinstance(blocks, list) for blocks in data.values()): raise ValueError('niepełny skan')
        data = [dict(file=file, line=x['lineno'], code='complexity-' + x['rank'], level='medium') for file, blocks in data.items() for x in blocks if x.get('complexity', 0) > 10]
    if name == 'stylelint':
        if any(g.get('parseErrors') or g.get('invalidOptionWarnings') for g in data): raise ValueError('niepełny skan')
        data = [dict(file=group['source'], line=x['line'], code=x['rule'], level=x['severity']) for group in data for x in group['warnings']]
    if name == 'jscpd':
        data = [dict(file=x['firstFile']['name'], line=x['firstFile']['startLoc']['line'], code='duplicate-code', level='medium',
                     related_locations=[dict(file=x['secondFile']['name'], line=x['secondFile']['startLoc']['line'])] if 'secondFile' in x else []) for x in data['duplicates']]
    if name == 'knip':
        groups = data['issues']
        if not isinstance(groups, list): raise ValueError('niepoprawny raport Knip6')
        data=[]
        for group in groups:
            for kind, items in group.items():
                if kind == 'file': continue
                if not isinstance(items, list): raise ValueError('niepoprawna grupa Knip6')
                if kind not in ('files','exports','types'):
                    if items: raise ValueError('nieoczekiwany zakres Knip6')
                    continue
                for item in items:
                    data.append(dict(file=item['name'] if kind=='files' else group['file'], line=item.get('line') or 1,
                                     code='unused-'+kind,level='low'))
    if name == 'squawk':
        data = [dict(file=x['file'], line=x['line'] + 1, code=x['rule_name'], level='medium') for x in data]

    if name == 'zizmor':
        normalized = []
        for item in data:
            for location in item['locations']:
                concrete = location['concrete']
                normalized.append(dict(file=location['symbolic']['key']['Local']['verbatim_path'], line=concrete['location']['start_point']['row'] + 1, rule=item['ident'], level=item['determinations']['severity']))
        data = normalized
    if not isinstance(data, list): raise ValueError('oczekiwano listy ustaleń')
    rows = []
    for item in data:
        if not isinstance(item, dict): raise ValueError('niepoprawne ustalenie')
        file = item.get('File') or item.get('filepath') or item.get('file') or item.get('filename') or item.get('path') or item.get('location', {}).get('path')
        line = item.get('StartLine') or item.get('start', {}).get('line') or item.get('line') or item.get('line_number') or item.get('line_num') or item.get('location', {}).get('line')
        if not file or not isinstance(line, int) or line < 1:
            raise ValueError('brak lokalizacji ustalenia')
        file = relative(root, file)
        if not (Path(root) / file).is_file(): raise ValueError('nieistniejąca lokalizacja')
        rule = str(item.get('test_id') or item.get('RuleID') or item.get('check_id') or item.get('code') or item.get('test_id') or item.get('rule') or name)
        # Identifiers are restricted; arbitrary output must never enter reports.
        import re
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', rule): rule = name
        severity = str(item.get('extra', {}).get('severity') or item.get('level') or item.get('issue_severity') or ('high' if name == 'gitleaks' else 'medium')).lower()
        severity = {'error':'high', 'warning':'medium', 'style':'low'}.get(severity, severity)
        rows.append(finding('security' if name in ('bandit', 'gitleaks', 'semgrep', 'zizmor', 'checkov', 'gosec', 'njsscan', 'trufflehog') else 'integrity', name, rule, severity,
                            'Ustalenie ' + name, file, line, snippet=f'{file}:{line}', evidence=f'{file}:{line}',
                            confidence='possible', why=EXPLANATIONS[name][0] + ' Reguła: ' + rule,
                            fix_hint=EXPLANATIONS[name][1], verdict='needs_validation'))
        if item.get('related_locations'):
            places=[]
            for place in item['related_locations']:
                path=relative(root,place['file']);line=place['line']
                if not (Path(root)/path).is_file() or type(line) is not int or line<1: raise ValueError('niepoprawne drugie miejsce duplikatu')
                places.append(dict(file=path,line=line))
            rows[-1]['related_locations']=places
    if name == 'jscpd':
        grouped={}
        for row in rows:
            kept=grouped.setdefault(row['fingerprint'],dict(row,related_locations=[]))
            for place in row.get('related_locations',[]):
                if place not in kept['related_locations']: kept['related_locations'].append(place)
        rows=list(grouped.values())
    return dedupe(rows)


def scan(repo, name, timeout=60, *, since=None):
    if name not in REGISTRY: raise ValueError('Nieznany adapter')
    if name in ('knip','jscpd','squawk'):
        from helix_advisory import scan as advisory_scan
        return advisory_scan(repo,name,timeout,since=since)
    if name in ('mutmut','stryker'):
        from helix_mutation_advisory import run
        return run(repo,name,timeout,since=since)
    if name in ('licensee', 'scancode'):
        from helix_license_adapters import scan as license_scan
        return license_scan(repo, name, timeout)
    spec = REGISTRY[name]
    result = dict(tool=name, status='not-run', reason='', findings=[], score=0)
    executable = locate(spec['command'])
    if not executable:
        reason = 'zadeklarowane, nieuruchomione: brak narzędzia w sprawdzonych lokalizacjach'
        return dict(result, status='unavailable', reason=reason,
                    coverage=dict(status='INCOMPLETE', gaps=[dict(tool=name, reason_code='TOOL_NOT_FOUND', reason=reason)]))
    if name not in ARGS:
        reason = ('sprawdzenie lokalnej DB jeszcze niezaimplementowane; pobieranie zabronione' if name in ('osv-scanner','trivy','grype','pip-audit') else
                  'wymaga kontrolowanego runtime/obrazu' if name in ('zap','dockle','pa11y','axe','stryker','mutmut','kics') else
                  'kontrakt offline i parser jeszcze niezaimplementowane')
        return dict(result, reason=reason, coverage=dict(status='INCOMPLETE',
            gaps=[dict(tool=name, reason_code='RUNNER_NOT_ADMITTED', reason=reason)]))
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 300: raise ValueError('timeout: 0..300 s')
    with tempfile.TemporaryDirectory(prefix='helix-tool-') as tmp:
        home = Path(tmp); target = home / 'project'
        copy_project(Path(repo).resolve(), target)
        files = sorted({'./' + str(p.relative_to(target)) for pattern in PATTERNS.get(name, ()) for p in target.glob(pattern) if p.is_file()})
        if name in PATTERNS and not files:
            return dict(result, status='not-applicable', reason='brak plików obsługiwanych przez adapter')
        argv = [executable, *ARGS[name], *files]
        try:
            p = subprocess.run(argv, cwd=target, env=environment(home), capture_output=True, text=True, timeout=timeout)
            if p.returncode not in {'typos': (0, 2), 'codespell': (0, 65), 'zizmor': (0, 11, 12, 13, 14), 'stylelint': (0, 2), 'njsscan': (0, 1), 'sqlfluff': (0, 1)}.get(name, (0, 1)): return dict(result, status='error', reason='błąd programu; surowe wyjście pominięte')
            raw = (target / '.helix-gitleaks.json').read_text() if name == 'gitleaks' else (target / '.helix-jscpd/jscpd-report.json').read_text() if name == 'jscpd' else p.stderr if name == 'stylelint' else p.stdout
            rows = parse(name, raw, target)
            return dict(result, status='completed', reason='wykonano na kopii; wynik wymaga weryfikacji', findings=rows)
        except subprocess.TimeoutExpired:
            return dict(result, status='timeout', reason='przekroczony budżet czasu')
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return dict(result, status='error', reason='niepoprawny wynik lub błąd procesu; surowe wyjście pominięte')
