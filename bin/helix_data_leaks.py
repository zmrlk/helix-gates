"""Offline, value-free data-flow candidates; no target code execution."""
import re
from pathlib import Path
import helix_static_security as security
from helix_audit_context import inventory

CATEGORIES = {
    'kontakt': r'\b(?:email|phone|telephone|telefon)\b',
    'identyfikatory': r'\b(?:pesel|nip|national_id)\b',
    'adres': r'\b(?:address|street|postal_code|adres)\b',
    'zdrowie': r'\b(?:diagnosis|patient|health|medical)\b',
    'płatności': r'\b(?:iban|card_number|payment|billing)\b',
    'uwierzytelnianie': r'\b(?:password|passwd|pin|token|secret)\b',
}
SINKS = {
    'log': r'\b(?:console\.(?:log|error)|logger\.\w+|logging\.\w+|print)\s*\(',
    'odbiorca': r'\b(?:fetch|axios\.\w+|requests\.\w+|webhook|analytics\.\w+|track)\s*\(',
    'cache': r'\b(?:localStorage|sessionStorage|cache|redis)\s*\.',
    'eksport': r'\b(?:csv|pdf|exportCsv|exportData|download)\b',
    'url': r'\b(?:searchParams|URLSearchParams|querystring)\b|https?://[^\s]+\?',
    'błąd': r'\b(?:res|response)\.(?:json|send)\([^\n]*(?:stack|traceback)|detail\s*=\s*str\(',
    'bundle': r'\b(?:PUBLIC_|NEXT_PUBLIC_|VITE_)\w+',
    'overfetch': r'SELECT\s+\*|\b(?:res|response)\.json\(\s*(?:user|record|account)\s*\)',
    'debug': r'(?:route|app\.get|router\.get)\s*\([^\n]*(?:debug|diagnostic)',
    'sourcemap': r'\b(?:sourcemap|productionBrowserSourceMaps)\s*[:=]\s*true',
}
ACTIONS = {'logowanie': r'\b(?:login|signIn)\b', 'uprawnienia': r'\b(?:setRole|grant|revoke)\b',
           'eksport': r'\b(?:exportCsv|exportData|download)\b', 'usunięcie': r'\b(?:delete|destroy)\b',
           'dostęp': r'\b(?:patient|medical|pesel)\b'}


def analyze(repo):
    flows, rows, actions, audit_evidence = [], [], [], []
    files = inventory(Path(repo).resolve())
    for file, raw in files.items():
        if any(p in {'tests', 'test', '__tests__', 'fixtures', 'docs', 'node_modules', 'vendor'} for p in Path(file).parts) or re.search(r'[._](?:test|spec)\.', file):
            continue
        if re.search(r'(?:^|/)(?:public|static|backups?|exports?)/', file, re.I) and re.search(r'\.(?:sql|csv|pdf|bak|dump|map)$', file, re.I):
            rows.append(security.finding('DATA-ARTIFACT', 'Publiczny artefakt danych', file, '', 0,
                'Artefakt może ujawniać dane lub źródła; publikacja niepotwierdzona.',
                'Usuń artefakt z dystrybucji i określ kontrolę dostępu.', 'medium', 'possible'))
        if Path(file).suffix.lower() not in security.EXT | {'.prisma', '.yaml', '.yml', '.json', '.map'}:
            continue
        if Path(file).suffix == '.md':
            continue
        text = security.mask(raw)
        for match in re.finditer(r'\b(?:audit_log|auditLog|audit|append.only|hash.chain|WORM)\b', text, re.I):
            audit_evidence.append(dict(file=file, line=text.count('\n', 0, match.start())+1, status='ASSUMPTION',
                reason='Deklaracja mechanizmu; brak dowodu egzekwowania i pokrycia.'))
        for match in re.finditer(r'\b(?:UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+[\w.]*audit[\w.]*', text, re.I):
            rows.append(security.finding('DATA-AUDIT-MUTABLE', 'Modyfikacja dziennika audytu', file, text, match.start(),
                'Kod zawiera modyfikację lub usunięcie tabeli audytu; polityka retencji i uprawnienia niepotwierdzone.',
                'Oddziel retencję od aplikacji; odbierz UPDATE/DELETE i przetestuj append-only.', 'medium', 'possible', 'ops_data'))
        offset = 0
        for number, chunk in enumerate(text.splitlines(keepends=True), 1):
            line = chunk.rstrip('\r\n')
            categories = [k for k, p in CATEGORIES.items() if re.search(p, line, re.I)]
            sinks = [k for k, p in SINKS.items() if re.search(p, line, re.I)]
            if categories:
                flows.append(dict(file=file, line=number, categories=categories,
                                  stages=['deklaracja/wejście/magazyn: unknown', *sinks],
                                  status='ASSUMPTION', reason='Współwystępowanie nazw; brak dowodu przepływu między funkcjami.'))
            for sink in sinks:
                if not categories and sink not in {'błąd', 'overfetch', 'debug', 'sourcemap'} and not (sink == 'bundle' and re.search(r'(?:PUBLIC_|NEXT_PUBLIC_|VITE_)\w*(?:TOKEN|SECRET|PASSWORD|KEY)', line)):
                    continue
                row = security.finding('DATA-' + sink.upper(), 'Możliwy wyciek: ' + sink,
                    file, text, offset,
                    'Statyczny sygnał granicy danych; odbiorca, cel i sanitacja wymagają potwierdzenia.',
                    'Ogranicz pola, usuń dane wrażliwe i sprawdź autoryzację oraz retencję.',
                    'medium', 'possible', 'security')
                row['sources'] = ['security', 'ops_data', 'data-flow']
                rows.append(row)
            offset += len(chunk)
        for action, pattern in ACTIONS.items():
            for match in re.finditer(pattern, text, re.I):
                # Presence is preparation only, never proof of who/what/when or durability.
                actions.append(dict(action=action, file=file, line=text.count('\n', 0, match.start())+1,
                    coverage='unknown', execution='not-run', who='unknown', what='unknown', when='unknown'))
    for action in actions:
        file, line = action['file'], action['line']
        if not re.search(r'\b(?:audit|auditLog|audit_log)\b', files[file], re.I):
            row = security.finding('DATA-AUDIT-GAP', 'Niepotwierdzony audit trail', file, '', 0,
                'W pliku wrażliwej akcji brak rozpoznanego wywołania audytu; delegowany audyt pozostaje unknown.',
                'Potwierdź zapis kto/co/kiedy i trwałość w niezależnym teście integracyjnym.', 'medium', 'possible', 'ops_data')
            row['line'] = line
            row['evidence'] = [f'{file}:{line}']
            rows.append(row)
    for row in rows:
        row['claim'] = 'ASSUMPTION'
    return dict(findings=rows, flows=flows, audit_trail=dict(actions=actions, mechanism_candidates=audit_evidence,
        coverage='unknown', tamper_resistance='unknown', execution='not-run',
        required=['kto/co/kiedy', 'append-only', 'brak UPDATE/DELETE', 'hash chain lub WORM'],
        reason='Nazwy loggerów i deklaracje nie dowodzą kompletności ani trwałości.'),
        dpia=dict(status='ASSUMPTION', categories=sorted({c for f in flows for c in f['categories']}),
            purposes='unknown: wymaga właściciela', recipients='unknown: wymaga konfiguracji',
            risks=sorted({r['id'] for r in rows}), measures=['minimalizacja', 'redakcja', 'autoryzacja', 'retencja'],
            gaps=['Nie jest oceną prawną art. 35; brak dowodu pełnego przepływu i audit trail.']))
