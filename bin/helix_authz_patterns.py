"""Object-scope hypotheses over the shared route inventory (never proof of exploit)."""
import re

MUTATE = re.compile(r'\b(?:\w+\.)?(?:update|updateMany|delete|deleteMany|unlink|save|writeFile|insert|increment|create)\s*\(|\b(?:UPDATE|DELETE\s+FROM|INSERT\s+INTO)\b', re.I)
SCOPE = re.compile(r'\b(?:owner_?id|tenant_?id|org_?id|organizationId|user_?id)\b', re.I)


def analyze(files, routes, rows, finding, blocks, declared_guards=()):
    from helix_static_security import mask
    texts = {file: mask(text) for file, text in files}
    files = list(texts.items())
    # Infer arbitrary guard names from record+principal parameters and a deny.
    guards = {}
    for file, text in files:
        for name, off, body in blocks(text):
            head = text[off:text.find('{', off)]
            if re.search(r'\b(?:user|actor|principal|session)\b', head, re.I) and re.search(r'\b(?:record|object|item|resource|entity|project)\b', head, re.I) and re.search(r'(?:throw|return|raise|abort)[^;\n]*(?:403|Forbidden|PermissionDenied)', body, re.I):
                guards.setdefault(name, []).append((file, off))
    facts = []
    for route in routes:
        body = route['_chunk']; file = route['file']; offset = route['_offset']
        mutation = MUTATE.search(body)
        scope = SCOPE.search(body)
        calls = []
        call_guards = dict(guards)
        for name in declared_guards:
            call_guards.setdefault(name, [('', 0)])
        for name, definitions in call_guards.items():
            if len(definitions) != 1:
                continue
            for call in re.finditer(r'\b' + re.escape(name) + r'\s*\(([^;()]*)\)', body):
                # A module-only permission string does not establish row scope.
                args = call[1]
                if re.search(r'\b(?:record|object|item|resource|entity|project)\b', args, re.I) and (name in declared_guards or re.search(r'\b(?:user|actor|principal|session)\b', args, re.I)):
                    calls.append(call)
        positions = ([scope.start()] if scope else []) + [c.start() for c in calls]
        before = bool(positions and (not mutation or min(positions) < mutation.start()))
        facts.append((route, before, mutation))

        def emit(code, title, why, fix, position=None, confidence='possible'):
            row = finding(code, title, file, texts[file], offset + (position if position is not None else mutation.start() if mutation else 0),
                          why + ' Hipoteza: middleware i helpery wymagają niezależnej weryfikacji.', fix, confidence=confidence)
            row['precondition'] = 'Eksploatowalne tylko, jeśli w produkcji istnieją konta z ograniczonym zakresem.'
            rows.append(row)

        if mutation and positions and min(positions) > mutation.start():
            emit('SEC-SCOPE-LATE', 'Zakres sprawdzany po efekcie ubocznym', 'Zapis/usunięcie poprzedza lokalne sprawdzenie zakresu.', 'Przenieś sprawdzenie rekordu przed pierwszy efekt uboczny.', confidence='likely')
        if mutation and guards and not before and re.search(r'params|req\.|request\.|event\.', body):
            emit('SEC-ROW-SCOPE', 'Mutacja bez rozpoznanego sprawdzenia rekordu', 'Projekt definiuje funkcję rekord+użytkownik z odmową 403, ale mutacja nie przekazuje obu przed zapisem.', 'Sprawdź zakres na pobranym rekordzie i użytkowniku; dodaj warunek do zapisu.')
        if not mutation:
            continue
        if re.search(r'\b(?:increment|views|visits|likes|counter|count)\b', body, re.I) and not re.search(r'rateLimit|rate_limit|throttle|idempoten|unique', body, re.I):
            emit('SEC-PUBLIC-COUNTER', 'Licznik możliwy do napompowania', 'Mutacja licznika bez lokalnego limitu lub idempotencji.', 'Ogranicz tempo i deduplikuj zdarzenia na serwerze.')
        if re.search(r'\b(?:delete|unlink)\s*\(', body) and re.search(r'Date\.now|timedelta|minutes|createdAt|created_at', body) and not before:
            emit('SEC-DELETE-WINDOW', 'Okno czasu bez zakresu autora', 'Ograniczenie czasu usuwania nie dowodzi własności rekordu.', 'Wymagaj autora/tenanta oprócz limitu czasu.')
        if re.search(r'regenerat|rotate|randomUUID|randomBytes', body, re.I) and re.search(r'public|share|link|token', body, re.I) and not before:
            emit('SEC-LINK-ROTATION', 'Rotacja publicznego linku bez zakresu', 'Zmiana linku/tokena obiektu bez lokalnego dowodu własności.', 'Sprawdź właściciela przed rotacją; unieważnij poprzedni link atomowo.')
        if re.search(r'email|phone|telephone', body, re.I) and re.search(r'verif|confirm', body, re.I) and not before:
            emit('SEC-CONFIRM-TARGET', 'Zmiana celu potwierdzenia bez zakresu', 'Mutacja celu email/telefon potwierdzenia bez lokalnego sprawdzenia właściciela.', 'Powiąż cel potwierdzenia, rekord i użytkownika; unieważnij starsze potwierdzenia.')
    # Compare only the same application, literal resource and file-local router.
    for route, scoped, mutation in facts:
        if not mutation or scoped or route['method'] not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            continue
        def application(file):
            match = re.search(r'^(.*?)(?:src/)?(?:routes|app|pages|server)/', file)
            return match[0] if match else file
        def resource(path):
            return re.sub(r':\w+|<[^>]+>|\{[^}]+\}', ':id', path).rstrip('/')
        target = resource(route['path'])
        peers = [r for r, has_scope, _ in facts if has_scope and r['method'] == 'GET'
                 and application(r['file']) == application(route['file'])
                 and (resource(r['path']) == target or (route['method'] == 'POST' and target.startswith(resource(r['path']) + '/')))]
        if peers:
            row = finding('SEC-METHOD-ASYMMETRY', 'Asymetria zakresu między metodami', route['file'], texts[route['file']], route['_offset'] + mutation.start(),
                          'GET tego zasobu sprawdza zakres, a mutacja nie ma lokalnego sprawdzenia przed zapisem. Silny sygnał, nie dowód braku middleware.',
                          'Zastosuj ten sam zakres rekordu we wszystkich metodach i podakcjach.', confidence='likely')
            row['evidence'] += [f"{r['file']}:{r['line']}" for r in peers[:2]]
            row['precondition'] = 'Eksploatowalne tylko, jeśli w produkcji istnieją konta z ograniczonym zakresem.'
            rows.append(row)
