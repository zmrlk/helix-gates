"""Syntetyczne odpowiedzi funkcji serwerowych (Supabase Edge Functions) dla przeglądarki w przebiegu runtime.

Projekt B: 123 funkcje nie były uruchamiane (wołają systemy zewnętrzne), więc 20 ze 128 ekranów pokazywało
„Błąd pobierania danych”, a kolejne zera. Funkcja nie startuje; model pisze przykładową poprawną odpowiedź z kodu funkcji
i z miejsc, w których przód aplikacji ją woła (jak dane syntetyczne tabel), a przeglądarka (ux.cjs, runtime-browser.cjs,
ui-audit.mjs) odpowiada nią na /functions/v1/<nazwa>. Odpowiedzi trafiają do pamięci podręcznej po skrócie polecenia.
"""
import hashlib
import json
import re
from pathlib import Path

from helix_runtime_seed import project_files

CALL = re.compile(r'''functions\.invoke\(\s*['"`]([\w-]+)['"`]|/functions/v1/([\w-]+)''')


def callers(root, per_function=2, lines=10):
    """Funkcje wołane przez przód aplikacji: nazwa -> [(plik, linia, fragment kodu)] (bez katalogu supabase/functions)."""
    root = Path(root).resolve(); found = {}
    for path in project_files(root):
        rel = path.relative_to(root).as_posix()
        if rel.startswith('supabase/functions/'): continue
        try: text = path.read_text(errors='ignore').splitlines()
        except OSError: continue
        for number, line in enumerate(text):
            for match in CALL.finditer(line):
                rows = found.setdefault(match.group(1) or match.group(2), [])
                if len(rows) < per_function: rows.append((rel, number + 1, '\n'.join(text[number:number + lines])))
    return found


def source(root, name, limit=6000):
    """Kod funkcji: tylko zwykły plik wewnątrz projektu (bez dowiązań w drodze, nazwa funkcji bez separatorów ścieżki)."""
    root = Path(root).resolve()
    if not re.fullmatch(r'[\w-]+', name): return ''
    folder = root / 'supabase' / 'functions' / name
    for candidate in ('index.ts', 'index.js', 'main.ts'):
        path = folder / candidate
        try:
            if any(p.is_symlink() for p in (root / 'supabase', root / 'supabase' / 'functions', folder, path)): return ''
            if path.is_file() and path.stat().st_size <= 2_000_000 and path.resolve().is_relative_to(root):
                return path.read_text(errors='ignore')[:limit]
        except OSError: return ''
    return ''


def prompt(batch, sources, calls):
    lines = ['Jesteś inżynierem danych testowych. Funkcje serwerowe aplikacji (Supabase Edge Functions) nie działają w lokalnej kopii,',
             'bo wołają systemy zewnętrzne. Dla każdej funkcji niżej napisz jedną przykładową odpowiedź JSON, jaką funkcja zwraca przy',
             'poprawnym działaniu: dokładnie w kształcie z jej kodu i taką, jaką przód aplikacji czyta (pola, tablice, typy). Dane',
             'syntetyczne, realistyczne, po polsku, 5-12 elementów w listach, kwoty i daty wiarygodne. Nie używaj prawdziwych danych osobowych',
             'ani sekretów. Odpowiedz wyłącznie JSON: {"functions": {"nazwa": <odpowiedź funkcji>, ...}}.', '']
    for name in batch:
        lines.append('## Funkcja ' + name)
        if sources.get(name): lines += ['Kod funkcji:', '```', sources[name], '```']
        for path, line, snippet in calls.get(name, []):
            lines += ['Wywołanie w ' + path + ':' + str(line) + ':', '```', snippet, '```']
        lines.append('')
    return '\n'.join(lines)


def generate(root, ask, cache_dir, *, batch_size=4, log=lambda message: None):
    """Zwraca (odpowiedzi {nazwa: json}, raport). ask(prompt) -> tekst JSON; błąd jednej partii nie zatrzymuje pozostałych."""
    calls = callers(root)
    names = sorted(calls)
    sources = {name: source(root, name) for name in names}
    cache = Path(cache_dir); cache.mkdir(parents=True, exist_ok=True)
    stubs, report = {}, dict(functions=len(names), stubbed=0, model_calls=0, cached=0, errors=[])
    for start in range(0, len(names), batch_size):
        batch = names[start:start + batch_size]
        text = prompt(batch, sources, calls)
        hit = cache / (hashlib.sha256(text.encode()).hexdigest() + '.json')
        try:
            if hit.is_file():
                data = json.loads(hit.read_text()); report['cached'] += 1
            else:
                report['model_calls'] += 1
                answer = ask(text)
                data = json.loads(answer[answer.find('{'):answer.rfind('}') + 1])   # odpowiedź modelu jest niezaufanym wejściem
                if not isinstance(data, dict) or not isinstance(data.get('functions'), dict): raise ValueError('brak obiektu "functions"')
                hit.write_text(json.dumps(data, ensure_ascii=False))
        except Exception as error:
            report['errors'].append(dict(functions=batch, error=type(error).__name__ + ': ' + str(error)[:200])); continue
        for name in batch:
            if name in data['functions']: stubs[name] = data['functions'][name]
        log('odpowiedzi funkcji serwerowych: %d/%d' % (len(stubs), len(names)))
    report['stubbed'] = len(stubs)
    return stubs, report
