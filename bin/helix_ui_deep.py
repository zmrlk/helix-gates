"""Read-only UX/UI source analysis. No target imports, commands, network or browser."""
from collections import Counter, defaultdict
import json
from helix_contracts import VERSION
import os
from pathlib import Path
import re
import tempfile

LENSES = ('ux_designer', 'ui_designer')
EXTENSIONS = {'.html', '.htm', '.svelte', '.vue', '.jsx', '.tsx', '.css', '.scss', '.js', '.ts', '.json'}
SKIP = {'.git', '.helix', 'helix-evidence', 'node_modules', 'vendor', 'dist', 'build', 'coverage', '.next', '.nuxt', '.svelte-kit', '__pycache__', '.aws', '.codex', '.agents', '.ssh', 'secrets', 'tests', 'fixtures', 'test', '__tests__'}
RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
DECL = re.compile(r'(?<![\w-])(?P<prop>--[\w-]+|[\w-]+)\s*:\s*(?P<value>[^;{}\n]+)\s*;?')
TAG = re.compile(r'<(?P<tag>[a-z][\w:-]*)\b(?P<attrs>(?:[^>"\'{}]|"[^"]*"|\'[^\']*\'|\{(?:[^{}]|\{[^{}]*\})*\})*)>', re.S)
ATTR = re.compile(r'(?P<name>[:@\w-]+)(?:\s*=\s*(?P<value>"[^"]*"|\'[^\']*\'|\{(?:[^{}]|\{[^{}]*\})*\}|[^\s>]+))?', re.S)


def checklist():
    """Stable checklist shared with the deep-lens orchestrator."""
    return {
        'ux_designer': ['Etykiety pól i alternatywy obrazów', 'Klawiatura, role i focus',
                        'Stany loading/error/empty przy danych', 'Potwierdzenie lub cofnięcie usunięcia',
                        'Copy i spójność języka', 'Adversarial pass: dynamiczne atrybuty, delegowane stany i ukryte etykiety'],
        'ui_designer': ['Tokeny CSS, Tailwind, theme i komponenty bazowe',
                        'Kolory/spacing/radius/font-size per komponent', 'Powielone kontrolki',
                        'Kontrast jawnych par fg/bg', 'Odchylenia od lokalnych tokenów',
                        'Adversarial pass: kaskada, motywy, aliasy i nieznane tło'],
    }


def source_area(file):
    """Classification is presentation only: legacy/docs remain in the scan."""
    from helix_owner_report import source_area as classify
    return classify(file)


def _sources(repo, coverage=None):
    root = Path(repo).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('repo musi być katalogiem')
    for directory, dirs, names in os.walk(root, followlinks=False):
        included = sorted(d for d in dirs if d not in SKIP and not d.startswith('.') and not (Path(directory) / d).is_symlink())
        if coverage is not None:
            coverage['excluded_subtrees'] += [{'path': (Path(directory) / d).relative_to(root).as_posix(), 'reason': 'excluded directory or symlink', 'descendants': None} for d in dirs if d not in included]
        dirs[:] = included
        for name in sorted(names):
            p = Path(directory) / name
            if (p.is_symlink() or not p.is_file() or name.startswith('.') or p.suffix.lower() not in EXTENSIONS
                    or re.search(r'(?:secret|credential|private|lock|\.min\.)', name, re.I)):
                if coverage is not None: coverage['skipped'].append({'file': p.relative_to(root).as_posix(), 'reason': 'extension, privacy, generated-file or symlink policy'})
                continue
            if p.suffix.lower() == '.json' and not re.search(r'theme|tokens', name, re.I):
                if coverage is not None: coverage['skipped'].append({'file': p.relative_to(root).as_posix(), 'reason': 'non-theme JSON data'})
                continue
            try:
                name = p.relative_to(root).as_posix()
                text = __import__('helix_audit_context').safe_read(p)
                if coverage is not None:
                    coverage['files_read'] += 1
                    coverage['by_area'][source_area(name)] += 1
                yield name, text
            except (UnicodeError, OSError):
                if coverage is not None: coverage['skipped'].append({'file': p.relative_to(root).as_posix(), 'reason': 'unreadable source'})
                continue


def _mask(text):
    # Keep offsets/lines stable; ignore commented-out markup and CSS.
    return re.sub(r'<!--.*?-->|/\*.*?\*/|(?m:^\s*//[^\n]*$)', lambda m: re.sub(r'[^\n]', ' ', m[0]), text, flags=re.S)


def _line(text, offset):
    return text.count('\n', 0, offset) + 1


def _attrs(raw):
    return {m['name'].lower(): (m['value'] or '').strip('"\'') for m in ATTR.finditer(raw)}


def _rgb(value):
    value = value.strip().lower()
    if re.fullmatch(r'#[0-9a-f]{3}', value):
        return tuple(int(c * 2, 16) / 255 for c in value[1:])
    if re.fullmatch(r'#[0-9a-f]{6}', value):
        return tuple(int(value[i:i + 2], 16) / 255 for i in (1, 3, 5))
    if value in {'black', 'white'}:
        return (0., 0., 0.) if value == 'black' else (1., 1., 1.)
    m = re.fullmatch(r'rgb\(\s*(\d+)\s*[, ]\s*(\d+)\s*[, ]\s*(\d+)\s*\)', value)
    if m and all(int(x) <= 255 for x in m.groups()):
        return tuple(int(x) / 255 for x in m.groups())
    return None


def _ratio(a, b):
    def lum(rgb):
        return sum(w * (v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4)
                   for w, v in zip((.2126, .7152, .0722), rgb))
    x, y = sorted((lum(a), lum(b)))
    return (y + .05) / (x + .05)


def focus_replacement(text, offset):
    """A same-block keyboard-focus style is a candidate indicator, not a visibility proof."""
    start = text.rfind('{', 0, offset)
    end = text.find('}', offset)
    if start < 0 or end < 0: return False
    selector_start = max(text.rfind('}', 0, start), text.rfind('{', 0, start), text.rfind('>', 0, start)) + 1
    selectors = text[selector_start:start].strip().split(',')
    keyboard = [selector.strip() for selector in selectors if re.search(r':focus(?:-visible)?\b', selector) and not re.search(r':(?:hover|active|not|has|is|where)\b', selector)]
    bases = {re.sub(r':focus(?:-visible)?\b', '', selector).strip() for selector in keyboard}
    # A comma-separated hover rule for the same element shares the keyboard
    # declaration. A compound :focus-visible:hover still requires a pointer.
    if not keyboard or any(selector.strip() not in keyboard and not (':hover' in selector and re.sub(r':hover\b', '', selector).strip() in bases) for selector in selectors):
        return False
    values = {m['prop'].lower(): m['value'].strip().lower().removesuffix('!important').strip() for m in DECL.finditer(text[start + 1:end])}
    for prop, value in values.items():
        if prop in {'outline', 'box-shadow', 'background', 'background-color', 'border', 'border-color', 'border-bottom', 'border-top', 'border-left', 'border-right'}:
            zero_width = (prop == 'outline' or prop.startswith('border')) and re.match(r'^0(?:px)?\s', value)
            if value not in {'none', '0', '0px', 'transparent', 'inherit', 'initial', 'unset', 'revert'} and not zero_width:
                return True
    return False


def analyze(repo):
    source_coverage = {'status': 'STATIC_ONLY', 'files_read': 0, 'by_area': Counter(), 'skipped': [], 'excluded_subtrees': []}
    sources = list(_sources(repo, source_coverage))
    if not sources: source_coverage['status'] = 'INCOMPLETE'
    findings = []
    tokens = defaultdict(list)
    design = {'css_tokens': [], 'tailwind': [], 'themes': [], 'base_components': []}
    components = {}
    duplicates = defaultdict(list)
    adversarial = {'dynamic_attributes_deferred': 0, 'unresolved_contrast_pairs': 0, 'focus_replacements_needing_runtime': 0}

    def add(lens, code, title, file, text, offset, why, fix, severity='medium', confidence='likely', evidence=None):
        line = _line(text, offset)
        findings.append(dict(lens=lens, id=code, title=title, severity=severity, confidence=confidence,
                             file=file, line=line, why=why, fix=fix,
                             evidence=evidence or [f'{file}:{line}'], source_area=source_area(file)))

    for file, original in sources:
        text = _mask(original)
        if Path(file).suffix in {'.css', '.scss', '.vue', '.svelte', '.html'}:
            for m in DECL.finditer(text):
                if m['prop'].startswith('--'):
                    tokens[m['prop']].append((m['value'].strip(), file, _line(text, m.start())))
                    design['css_tokens'].append(f'{file}:{_line(text, m.start())}')
        name = Path(file).name.lower()
        if name.startswith('tailwind.config') or (name.endswith('.css') and '@theme' in text):
            design['tailwind'].append(file)
        if re.search(r'(?:theme|tokens)', name):
            design['themes'].append(file)
        if re.search(r'(?:^|/)(?:ui|base|primitives)/', file) or re.match(r'(?:Base|Ui)[A-Z]', Path(file).stem):
            design['base_components'].append(file)

    def resolve(value, seen=()):
        m = re.fullmatch(r'var\(\s*(--[\w-]+)\s*\)', value.strip())
        if not m:
            return _rgb(value)
        key = m[1]
        variants = {row[0] for row in tokens.get(key, [])}
        # Ambiguous theme/cascade definitions never count as proven contrast.
        if key in seen or len(variants) != 1:
            return None
        return resolve(next(iter(variants)), seen + (key,))

    for file, original in sources:
        text = _mask(original)
        ext = Path(file).suffix
        if ext == '.json' or (ext in {'.js', '.ts'} and not TAG.search(text)):
            continue  # config discovery only; never execute it
        component = {'hardcoded': {'color': 0, 'spacing': 0, 'radius': 0, 'font_size': 0}, 'controls': 0}
        components[file] = component
        declarations = list(DECL.finditer(text))
        hard_offsets = []
        for m in declarations:
            prop, value = m['prop'].lower(), m['value'].strip()
            if prop.startswith('--') or 'var(' in value or value in {'0', 'auto', 'inherit', 'initial', 'unset', 'transparent', 'currentColor'}:
                continue
            category = None
            if prop in {'color', 'background', 'background-color', 'border-color', 'fill', 'stroke'} and _rgb(value):
                category = 'color'
            elif re.fullmatch(r'(?:margin|padding|gap|row-gap|column-gap)(?:-(?:top|right|bottom|left|inline|block)(?:-start|-end)?)?', prop) and re.search(r'\d(?:px|rem|em)\b', value):
                category = 'spacing'
            elif prop == 'border-radius' and re.search(r'\d(?:px|rem|em)\b', value):
                category = 'radius'
            elif prop == 'font-size' and re.search(r'\d(?:px|rem|em)\b', value):
                category = 'font_size'
            if category:
                component['hardcoded'][category] += 1
                hard_offsets.append(m.start())
        for m in re.finditer(r"\b(?:bg|text|border|p[trblxy]?|m[trblxy]?|gap|rounded)-\[([^\]]+)\]", text):
            value = m[1]
            if 'var(' in value or value.startswith('--'):
                continue
            prefix = m[0].split('-')[0]
            category = ('color' if _rgb(value) else 'font_size') if prefix == 'text' else ('color' if prefix in {'bg', 'border'} else 'radius' if prefix == 'rounded' else 'spacing')
            if _rgb(value) or re.fullmatch(r'\d+(?:\.\d+)?(?:px|rem|em)', value):
                component['hardcoded'][category] += 1
                hard_offsets.append(m.start())
        if hard_offsets and any(design.values()):
            add('ui_designer', 'UI-TOKENS', 'Wartości poza tokenami projektu', file, text, hard_offsets[0],
                'Licznik literałów w pliku: ' + json.dumps(component['hardcoded']) + '. To sygnał do przeglądu, nie dowód błędnego wyglądu.',
                'Porównaj z lokalnymi tokenami; zastąp równoważne literały tokenami.', confidence='possible',
                evidence=[f'{file}:{_line(text, x)}' for x in hard_offsets[:3]] + [f'Łącznie: {len(hard_offsets)}'])
        # Only same declaration block pairs: no global token-name guessing.
        for block in re.finditer(r'\{([^{}]*)\}', text):
            body = block[1]
            pairs = {m['prop'].lower(): m['value'].strip() for m in DECL.finditer(body)}
            fg = resolve(pairs.get('color', ''))
            bg = resolve(pairs.get('background-color', pairs.get('background', '')))
            if 'color' in pairs and ('background' in pairs or 'background-color' in pairs) and (fg is None or bg is None):
                adversarial['unresolved_contrast_pairs'] += 1
            if fg is not None and bg is not None:
                ratio = _ratio(fg, bg)
                if ratio < 4.5:
                    add('ui_designer', 'UI-CONTRAST', 'Niski kontrast jawnej pary kolorów', file, text, block.start(1),
                        f'Obliczona para fg/bg ma kontrast {ratio:.2f}:1; próg zwykłego tekstu AA wynosi 4.5:1. Kaskada, rozmiar tekstu i użycie selektora wymagają weryfikacji.',
                        'Dobierz parę tokenów o kontraście co najmniej 4.5:1 dla zwykłego tekstu.',
                        severity='high' if ratio < 3 else 'medium', confidence='likely')
        for m in re.finditer(r'(?:outline\s*:\s*(?:none|0)\b)', text):
            if focus_replacement(text, m.start()):
                adversarial['focus_replacements_needing_runtime'] += 1
            else:
                add('ux_designer', 'UX-FOCUS', 'Wyłączony wskaźnik focus', file, text, m.start(),
                    'Usunięto outline; w tym samym bloku focus nie znaleziono zastępczego wskaźnika klawiatury.',
                    'Dodaj widoczny :focus-visible; sprawdź style globalne.', confidence='possible')
        markup = re.sub(r'<(?:script|style)\b[^>]*>.*?</(?:script|style)\s*>',
                        lambda m: re.sub(r'[^\n]', ' ', m[0]), text, flags=re.S | re.I)
        tags = list(TAG.finditer(markup))
        labels = re.findall(r'<label\b[^>]*(?:for|htmlFor)\s*=\s*["\']([^"\']+)', markup, re.I)
        for tag in tags:
            name, attrs = tag['tag'].lower(), _attrs(tag['attrs'])
            offset = tag.start()
            spread = bool(re.search(r'\{\s*\.\.\.|v-bind\s*=', tag['attrs']))
            if spread:
                adversarial['dynamic_attributes_deferred'] += 1
            # Wrapping labels: compare last opening and closing label, not unrelated label elsewhere.
            prefix = markup[:offset]
            wrapped = prefix.rfind('<label') > prefix.rfind('</label')
            if name in {'input', 'select', 'textarea'} and not (attrs.get('aria-hidden') == 'true' and attrs.get('tabindex') == '-1') and attrs.get('type') not in {'hidden', 'submit', 'reset', 'button', 'image'}:
                if not (wrapped or attrs.get('id') in labels or any(attrs.get(k) for k in ('aria-label', 'aria-labelledby', ':aria-label', ':aria-labelledby', 'v-bind:aria-label', 'v-bind:aria-labelledby')) or spread):
                    add('ux_designer', 'UX-LABEL', 'Pole bez lokalnej etykiety', file, text, offset,
                        'Brak label, aria-label i aria-labelledby w dostępnym źródle. Placeholder nie zastępuje etykiety.',
                        'Powiąż label z id pola albo dodaj dostępną nazwę.', confidence='likely')
            if name == 'img' and 'alt' not in attrs and not spread and ':alt' not in attrs and 'v-bind:alt' not in attrs:
                add('ux_designer', 'UX-ALT', 'Obraz bez atrybutu alt', file, text, offset,
                    'W znaczniku img nie ma alternatywy tekstowej.', 'Dodaj opisowy alt albo alt="" dla dekoracji.', confidence='confirmed')
            click = any(k in attrs for k in ('onclick', 'on:click', '@click', 'v-on:click'))
            if name in {'div', 'span'} and click:
                role = attrs.get('role') or attrs.get(':role')
                keyboard = any(k.startswith(('onkeydown', 'onkeyup', 'on:keydown', 'on:keyup', '@keydown', '@keyup', 'v-on:keydown', 'v-on:keyup')) for k in attrs)
                tabindex = attrs.get('tabindex', '').strip('{} ').strip()
                focusable = (any(k in attrs for k in ('tabindex', ':tabindex')) and tabindex != '-1') or attrs.get('contenteditable') in {'true', '{true}'}
                if not (role and keyboard and focusable) and not spread:
                    add('ux_designer', 'UX-CLICK', 'Klikalny element bez pełnej obsługi klawiatury', file, text, offset,
                        'Nienatywna kontrolka nie ma kompletu role, tabindex i handlera klawiatury w źródle.',
                        'Użyj button; ewentualnie zapewnij rolę, focus oraz Enter/Spację.', confidence='likely')
            if name in {'button', 'input', 'dialog'}:
                component['controls'] += 1
                style = attrs.get('style', '')
                classes = attrs.get('class', attrs.get('classname', ''))
                signature = (name, re.sub(r'\s+', ' ', style or classes).strip())
                if signature[1] and not spread:
                    duplicates[signature].append((file, offset, text))
            if name == 'button' and click:
                close = markup.find('</button', tag.end())
                label = markup[tag.end():close] if close >= 0 else ''
                if re.search(r'\b(?:delete|remove|usuń|usun|skasuj)\b', label, re.I) and not re.search(r'confirm|dialog|undo|cofn|potwier', text, re.I):
                    add('ux_designer', 'UX-DESTRUCTIVE', 'Usuwanie bez lokalnego zabezpieczenia', file, text, offset,
                        'Przycisk usuwania ma handler; w pliku nie znaleziono potwierdzenia ani cofnięcia. Zabezpieczenie może być delegowane.',
                        'Sprawdź handler i zapewnij potwierdzenie albo możliwość cofnięcia.', confidence='possible')
        fetch = re.search(r'\b(?:fetch|axios\.(?:get|post)|useQuery|useSWR)\s*\(', text)
        listing = re.search(r'\.map\s*\(|\{#each\b|\bv-for\s*=', markup)
        if fetch or listing:
            missing = []
            if fetch:
                if not re.search(r'loading|pending|isFetching|aria-busy|ładow|ladow|\{#await|Suspense', text, re.I):
                    missing.append('loading')
                if not re.search(r'catch\b|\berror\b|isError|błąd|blad|onError|ErrorBoundary', text, re.I):
                    missing.append('error')
            if listing and not re.search(r'\blength\b|empty|brak\b|pust|\{:else\}|v-else', text, re.I):
                missing.append('empty')
            if missing:
                m = fetch or listing
                add('ux_designer', 'UX-STATES', 'Nieudokumentowane stany danych w komponencie', file, text, m.start(),
                    'Nie znaleziono lokalnych sygnałów stanów: ' + ', '.join(missing) + '. Mogą być realizowane przez wrapper.',
                    'Sprawdź przepływ danych i dodaj brakujące loading/error/empty.', confidence='possible')
        # Visible copy only, never JS variable names or CSS comments.
        visible = [(m.start(1), m[1]) for m in re.finditer(r'>([^<>{}]+)<', markup) if m[1].strip()]
        for pos, copy in visible:
            if re.search(r'\blorem\b|\bTODO\b|\bFIXME\b|placeholder text', copy, re.I):
                add('ux_designer', 'UX-COPY', 'Robocza treść w interfejsie', file, text, pos,
                    'W tekście widocznym znaleziono marker roboczy.', 'Zastąp treść docelowym komunikatem.', confidence='confirmed')
        copy = ' '.join(v for _, v in visible)
        if re.search(r'\b(?:Zapisz|Anuluj|Usuń|Wstecz)\b', copy, re.I) and re.search(r'\b(?:Save|Cancel|Delete|Back|Submit)\b', copy, re.I):
            add('ux_designer', 'UX-LANGUAGE', 'Mieszane języki komunikatów', file, text, visible[0][0],
                'W jednym pliku są polskie i angielskie etykiety akcji; intencja lokalizacji wymaga sprawdzenia.',
                'Ujednolić język lub zastosować wspólny mechanizm tłumaczeń.', confidence='possible')
    # Near-identical utility control styles: require at least three shared classes.
    signatures = list(duplicates)
    adversarial['similarity_signatures_not_compared'] = max(0, len(signatures) - 500)
    for index, signature in enumerate(signatures[:500]):
        if signature not in duplicates:
            continue
        left = set(signature[1].split())
        if len(left) < 4 or ':' in signature[1]:
            continue
        for other in signatures[index + 1:500]:
            if other not in duplicates:
                continue
            right = set(other[1].split())
            if signature[0] == other[0] and len(left & right) >= 3 and len(left & right) / len(left | right) >= .7:
                duplicates[signature].extend(duplicates.pop(other, []))
    for signature, locations in duplicates.items():
        files = {x[0] for x in locations}
        if len(files) >= 2:
            file, offset, text = locations[0]
            add('ui_designer', 'UI-REUSE', 'Powtórzony wzorzec kontrolki', file, text, offset,
                f'Identyczne lub zbliżone klasy/style kontrolki {signature[0]} w {len(files)} plikach; sprawdź wspólny komponent.',
                'Porównaj zachowanie; wydziel wspólny prymityw, jeśli semantyka jest jednakowa.', confidence='possible',
                evidence=[f'{f}:{_line(t, o)}' for f, o, t in locations[:3]] + [f'Łącznie plików: {len(files)}'])
    findings.sort(key=lambda f: (RANK[f['severity']], f['file'], f['line'], f['id']))
    return {'helix_version': VERSION, 'schema_version': 1, 'findings': findings, 'design_system': {k: {'examples': v[:3], 'count': len(v)} for k, v in design.items()},
            'components': components, 'scanned_files': len(sources), 'adversarial': adversarial, 'source_coverage': source_coverage}


def run(repo) -> list[dict]:
    return analyze(repo)['findings']


def score(findings) -> int:
    """Legacy API only; Markdown uses evidence counts, never this arithmetic score."""
    evidenced = [f for f in findings if f.get('evidence')]
    if not evidenced:
        return 0
    return max(0, 100 - sum({'critical': 40, 'high': 20, 'medium': 8, 'low': 3, 'info': 0}.get(f.get('severity'), 0) for f in evidenced))


def assessment(rows):
    verified = sum(r.get('verification_status') == 'confirmed' for r in rows)
    rejected = sum(r.get('verification_status') == 'rejected' or r.get('verdict') == 'rejected' for r in rows)
    return {'signals': len(rows), 'confirmed_by_verifier': verified,
            'source_pattern_confirmed': sum(r.get('confidence') == 'confirmed' and 'verification_status' not in r for r in rows),
            'candidates': len(rows) - verified - rejected, 'rejected': rejected,
            'by_area': dict(Counter(r.get('source_area', source_area(r.get('file', ''))) for r in rows)),
            'runtime': 'not_checked'}


def assessment_text(summary):
    return (f"Sygnały: {summary['signals']}; kandydaci: {summary['candidates']}; "
            f"potwierdzone przez weryfikatora: {summary['confirmed_by_verifier']}; "
            f"odrzucone: {summary['rejected']}; wzorce potwierdzone tylko w źródle: {summary['source_pattern_confirmed']}. "
            'Działanie w przeglądarce: nie sprawdzono.')


AREA_TITLES = {'active': 'Aktywny kod', 'docs': 'Dokumentacja i przykłady dokumentacji', 'legacy': 'Starsze warianty i archiwa',
               'tests/examples': 'Testy i przykłady', 'unknown': 'Zakres nierozpoznany'}


def report(repo):
    data = analyze(repo)
    from helix_environment import provenance
    data['provenance'] = provenance(repo, models=[])
    data['schema_version'] = 1
    data['visual_audit'] = {'status': 'needs-runtime', 'reason': 'Statyczny audyt nie uruchamia przeglądarki',
                           'command': 'helix visual audit <URL> --out <DIR> --sweep 280-1600:40'}
    data['limitations'] = ['Analiza statyczna heurystyczna: brak dowodu działania w przeglądarce.',
                          'Nie oblicza pełnej kaskady CSS, layoutu ani dynamicznych nazw dostępnych.',
                          'Tekst dopuszczonych plików czytany w całości, bez limitu 1 MB. Wykluczenia i nieczytelne pliki są w source_coverage.',
                          'Symlinki, ukryte katalogi, zależności i fixtures/testy są pomijane; liczba potomków wykluczonych katalogów jest nieznana.',
                          'Pole score pozostaje wyłącznie dla zgodności API. Raport używa liczników dowodów i nie ocenia wyglądu punktami.']
    data['summary'] = assessment(data['findings'])
    data['lenses'] = {}
    for lens, checks in checklist().items():
        rows = [f for f in data['findings'] if f['lens'] == lens]
        data['lenses'][lens] = dict(checklist=checks, findings=rows, score=score(rows), summary=assessment(rows),
            adversarial_pass={'status': 'static_only', 'checks': checks[-1:], 'observations': data['adversarial'],
                'limitations': ['Dynamiczne propsy, delegowane kontrolki/stany i zewnętrzne style wymagają ręcznej weryfikacji.']})
    return data


def markdown(data):
    lines = ['# UI deep: analiza statyczna', '', assessment_text(data['summary']), '',
             f"Odczytane pliki: {data['scanned_files']}. Zakres: " + ', '.join(f'{area} {count}' for area, count in data['source_coverage']['by_area'].items()) + '.',
             'Wykluczone poddrzewa: ' + str(len(data['source_coverage']['excluded_subtrees'])) + '; pominięte pliki: ' + str(len(data['source_coverage']['skipped'])) + '. Pełny manifest: source_coverage w JSON.',
             'Odroczone kontrole: ' + json.dumps(data['adversarial'], ensure_ascii=False), '']
    for area, title in AREA_TITLES.items():
        rows = [f for f in data['findings'] if f.get('source_area') == area]
        if not rows: continue
        lines += [f'## {title}', '', f'Sygnały: {len(rows)}; pokazano do 30, pełna lista w JSON.', '']
        for f in rows[:30]:
            tag = 'VERIFIED (wzorzec źródłowy)' if f['confidence'] == 'confirmed' else 'ASSUMPTION'
            lines += [f"- **{f['severity']} / {f['confidence']} / {tag}** `{f['file']}:{f['line']}` [{f['id']}] {f['title']}",
                      f"  Dlaczego: {f['why']} Poprawka: {f['fix']}", '  Dowody: ' + '; '.join(f['evidence'][:4])]
    if not data['findings']:
        lines += ['Brak wykrytych wzorców nie dowodzi jakości ani dostępności.']
    lines += ['', 'Audyt wizualny: '+json.dumps(data.get('visual_audit', {}), ensure_ascii=False)]
    lines += ['', '## System projektu i komponenty', '', '```json', json.dumps(data['design_system'], ensure_ascii=False, indent=2), '```']
    for file, counts in list(data['components'].items())[:30]:
        lines += [f"- `{file}`: {json.dumps(counts, ensure_ascii=False)}"]
    lines += [f"Łącznie komponentów/plików stylów: {len(data['components'])}; pokazano maks. 30, pełne liczniki w JSON."]
    for lens, item in data['lenses'].items():
        lines += ['', f"## {lens}", '', assessment_text(item['summary']), '']
        lines += ['- [ ] ' + c + ' (zakres statyczny, bez certyfikacji)' for c in item['checklist'][:-1]]
        lines += ['', f"Findings: {len(item['findings'])}; szczegóły i dowody powyżej.", '', '### Adversarial pass',
                  item['checklist'][-1], json.dumps(item['adversarial_pass']['observations'], ensure_ascii=False), *item['adversarial_pass']['limitations']]
    origin = data.get('provenance', {})
    lines += ['', f"Pochodzenie: Helix {origin.get('helix_version', 'unknown')}; rewizja celu {origin.get('target_head') or 'unknown'}. Pełne metadane: provenance w ui-deep.json."]
    return '\n'.join(lines + ['', '## Ograniczenia', '', *data['limitations'], ''])


def cli(args):
    data = report(args.target_repo)
    if getattr(args, 'visual_report', None):
        from helix_visual import projection
        data['visual_audit'] = projection(args.visual_report)
    if args.out:
        out = Path(args.out).resolve()
        root = Path(args.target_repo).resolve()
        if out == root or root in out.parents:
            raise ValueError('--out musi znajdować się poza analizowanym repo')
        out.mkdir(parents=True, exist_ok=True)
        for filename, content in (('ui-deep.json', json.dumps(data, ensure_ascii=False, indent=2) + '\n'),
                                  ('ui-deep.md', markdown(data))):
            # Replace output symlinks rather than following them into target files.
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=out, delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(content)
                os.replace(temporary, out / filename)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    print(json.dumps(data, ensure_ascii=False, indent=2) if args.format == 'json' else markdown(data))
