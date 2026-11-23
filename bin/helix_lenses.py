"""Shared source-only lens registry, finding contract, ranking and reporting."""
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import helix_static_security as security
import helix_ui_deep as ui

RANK = ui.RANK
# Role policy is data, shared by the report and per-part pipeline.
_POLICY = json.loads((Path(__file__).resolve().parents[1] / 'data/senior-pipeline.json').read_text())
REGISTRY = {key: spec['checklist'] for key, spec in _POLICY['roles'].items()}
REGISTRY['repo_hygiene'] = ['Wersje, lockfile, migracje i konflikty', 'Artefakty, piny i własność kodu']
ADVERSARIAL = {key: spec['adversarial'] for key, spec in _POLICY['roles'].items()}
ADVERSARIAL['repo_hygiene'] = ['Brak pliku może wynikać z profilu; sprawdź kontekst.']

RULES = [
 ('senior_developer','DEV-ERROR',r'catch\s*\([^)]*\)\s*\{\s*\}|except[^:\n]*:\s*\n\s*pass\b','Połknięty błąd','Zapisz kontekst i propaguj lub obsłuż błąd.'),
 ('senior_developer','DEV-DEAD',r'\bif\s*\(\s*false\s*\)','Nieosiągalna gałąź','Usuń martwy kod lub popraw warunek.'),
 ('architect','ARCH-BOUNDARY',r'(?:from\s*|require\s*\()["\'][^"\']*\.\./\.\./\.\./','Głębokie zależności między modułami','Wprowadź jawny interfejs modułu.'),
 ('qa','QA-FLAKY',r'\b(?:time\.sleep|Thread\.sleep|waitForTimeout)\s*\(\s*\d','Stałe oczekiwanie','Czekaj na konkretny warunek zamiast opóźnienia.'),
 ('product_manager','PM-TODO',r'\b(?:TODO|FIXME|NotImplementedError)\b','Niedokończona implementacja','Porównaj z wymaganiami i zamknij brakującą ścieżkę.'),
 ('ops_data','OPS-DESTRUCTIVE',r'\b(?:DROP\s+TABLE|TRUNCATE\s+(?:TABLE\s+)?|ALTER\s+TABLE[^;\n]*DROP\s+COLUMN)\b','Destrukcyjna migracja','Zaplanuj kopię, odtworzenie i etapową migrację.'),
 ('ops_data','OPS-LOG',r'console\.log\([^\n]*(?:req\.body|request\.body|password|token)','Wrażliwe dane w logach','Loguj wyłącznie dozwolone metadane.'),
]


def deduplicate(rows):
    found = {}
    for row in rows:
        key = (row['id'],row['file'],row['line'])
        previous = found.get(key)
        if key not in found or RANK[row['severity']] < RANK[found[key]['severity']]:
            sources = set(row.get('sources', [row['lens']]))
            if key in found:
                sources.update(found[key].get('sources', [found[key]['lens']]))
            found[key] = dict(row, sources=sorted(sources))
        else:
            found[key]['sources'] = sorted(set(found[key].get('sources', [found[key]['lens']])) | set(row.get('sources', [row['lens']])))
        kinds = set()
        locations = {}
        for item in (previous, row):
            if item is None:
                continue
            kinds.update(item.get('evidence_kinds', []))
            if item.get('evidence_kind') and item['evidence_kind'] != 'aggregate':
                kinds.add(item['evidence_kind'])
            for place in item.get('locations', []):
                locations[json.dumps(place, sort_keys=True)] = place
        if kinds:
            found[key]['evidence_kinds'] = sorted(kinds)
        if locations:
            found[key]['locations'] = [locations[name] for name in sorted(locations)]
    return sorted(found.values(), key=lambda r:(RANK[r['severity']],r['file'],r['line'],r['id']))


def report(repo, advisories=None, gitleaks_report=None, auth_sanity_percent=30, verdicts=None, state_dir=None, precision_threshold=0.3, precision_minimum=10, quality_snapshot=None):
    data = security.analyze(repo, auth_sanity_percent=auth_sanity_percent, engine='auto')
    import helix_security_offline
    data = helix_security_offline.apply(data, repo, advisories, gitleaks_report)
    visual = ui.report(repo)
    rows = data.pop('findings') + visual['findings']
    rows += structural_signals(repo, data['endpoints'])
    import helix_data_leaks
    data['data_leak_audit'] = helix_data_leaks.analyze(repo)
    rows += data['data_leak_audit']['findings']
    from helix_quality import analyze as quality_analyze
    quality = quality_snapshot if quality_snapshot is not None else quality_analyze(repo)
    rows += quality['findings']
    import helix_repo_hygiene
    hygiene = helix_repo_hygiene.report(repo)
    rows += hygiene['findings']
    data['repo_hygiene'] = hygiene
    from helix_contracts import VERSION
    data['helix_version'] = VERSION
    # The lens report executes static checks, not the configured model plan.
    data['provenance'] = copy.deepcopy(visual['provenance'])
    ast_engine = data.get('static_engine', {}).get('engine', {})
    actual_ast = ast_engine.get('used') is True and ast_engine.get('proof_kind') == 'subprocess'
    data['provenance']['tools']['ast-grep'] = dict(
        status='recorded' if actual_ast else ast_engine.get('proof_kind', 'not_used'),
        version=ast_engine.get('version') if actual_ast else None, used=actual_ast,
        reason='Własny parser snapshotu; zakres i receipt w static_engine, bez wykonania projektu')
    data['quality'] = quality
    data['source_coverage'] = quality['coverage']
    root = Path(repo).resolve()
    for file, raw in security.sources(root):
        text = security.mask(raw)
        for lens, code, pattern, title, fix in RULES:
            inspected = raw if lens == 'product_manager' else text
            for m in re.finditer(pattern,inspected,re.I):
                rows.append(security.finding(code,title,file,inspected,m.start(),
                    'Wzorzec statyczny wymaga sprawdzenia kontekstu i intencji.',fix,'medium','possible',lens))
        if file.endswith('.md'):
            for m in re.finditer(r'\]\(([^)#]+)(?:#[^)]*)?\)',raw):
                link = m[1]
                if ':' in link or link.startswith('/'):
                    continue
                target = (root / file).parent / link
                # Existence only; never read linked files or follow outside-root links.
                if not target.exists():
                    rows.append(security.finding('DOC-LINK','Nieistniejący lokalny odnośnik',file,raw,m.start(),
                        'Ścieżka lokalnego odnośnika nie istnieje.', 'Popraw odnośnik lub dodaj dokument.', 'low','likely','tech_writer'))
    data['visual_audit'] = visual['visual_audit']
    data['performance_weight'] = dict(status='needs-runtime', reason='Wymagany aktualny build', command='helix perf weight <ROOT> --out <DIR>')
    data['screenshot_review'] = dict(status='needs-runtime', command='helix review screenshots <DIR>', reason='Wymagane zrzuty i niezależny recenzent')
    data.update(schema_version=1, findings=deduplicate(rows), lenses={},
        coverage=coverage(repo, data['endpoints']),
        limitations=['Heurystyki statyczne; nie dowodzą zachowania produkcji ani pełnego przepływu taint.',
                      'Auth globalne, aliasy, dynamiczny dispatch i sanitacja wymagają ręcznej weryfikacji.',
                      'Raport pokazuje liczniki i luki dowodów; pole score pozostaje tylko dla zgodności API.',
                      'Zakres poszczególnych detektorów jest ograniczony; pełny odczyt rozlicza source_coverage.',
                      'Brak dopasowania do raportu nie dowodzi naprawy: status unknown.'],
        ui={'design_system':visual['design_system'], 'scanned_files':visual['scanned_files']})
    import helix_verification
    data['verification'] = helix_verification.apply(data['findings'], repo, dict(security.sources(root)), verdicts, state_dir, precision_threshold, precision_minimum, data['endpoints'])
    for key, status in [('proven_protected', 'proven-guarded'), ('unknown', 'unknown'), ('unprotected', 'unguarded')]:
        data['authz'][key] = sum(r['auth_status'] == status for r in data['endpoints'])
    data['findings'] = deduplicate(data['findings'])
    for row in data['findings']: row['source_area'] = ui.source_area(row.get('file', ''))
    data['summary'] = ui.assessment(data['findings'])
    data['owner_findings'] = [f for f in data['findings'] if f['verification_status'] == 'confirmed']
    data['decisions'] = ['Czy w produkcji istnieją konta z ograniczonym zakresem rekordów? Exploitability ustalić po odpowiedzi właściciela.']
    for lens, checks in REGISTRY.items():
        findings = [f for f in data['findings'] if f['lens']==lens]
        data['lenses'][lens] = dict(checklist=checks, findings=findings, score=0, summary=ui.assessment(findings),
            adversarial_pass=dict(status='static_only', checks=ADVERSARIAL.get(lens, checks[-1:]),
                                  observations={'signals':len(findings)}, limitations=data['limitations'][:2]))
        if lens in visual['lenses']:
            data['lenses'][lens]['adversarial_pass'] = visual['lenses'][lens]['adversarial_pass']
    # Static analysis and imported assertions are not execution evidence.
    for item in data['lenses'].values():
        item['score'] = 0
    import helix_senior_pipeline
    data['senior_pipeline'] = helix_senior_pipeline.build(repo, data['findings'], data['lenses'])
    return data


def evidence_summary(evidence):
    examples = [e for e in evidence if not e.startswith('Łącznie:')]
    totals = [e.split(':', 1)[1].strip() for e in evidence if e.startswith('Łącznie:')]
    total = totals[-1] if totals else str(len(examples))
    return '; '.join(examples[:3])+f' (łącznie: {total})'


def markdown(data):
    lines = ['# Deep: statyczny przegląd projektu', '', ui.assessment_text(data.get('summary', ui.assessment(data['findings']))), '',
             'Zakres ustaleń: ' + ', '.join(f'{area} {count}' for area, count in data.get('summary', ui.assessment(data['findings']))['by_area'].items()) + '.',
             'Najpoważniejsze potwierdzone ustalenia aktywnego kodu:', '']
    lines += [json.dumps({k:data[k] for k in ('visual_audit','performance_weight','screenshot_review') if k in data},ensure_ascii=False)]
    if 'authz' in data:
        lines += ['Authz: '+json.dumps(data['authz'], ensure_ascii=False), '']
    for f in [f for f in data.get('owner_findings', []) if f.get('source_area', ui.source_area(f.get('file', ''))) == 'active'][:10]:
        tag = 'VERIFIED' if f['confidence']=='confirmed' else 'ASSUMPTION'
        lines += [f"- **{f['severity']} / {f['confidence']} / {tag}** `{f['file']}:{f['line']}` [{f['id']}] {f['title']}",
                  f"  Dlaczego: {f['why']} Poprawka: {f['fix']}", '  Dowody: '+evidence_summary(f['evidence'])]
    lines += ['', '## Pokrycie i pominięcia', json.dumps({k: ({a: (len(b) if isinstance(b, list) else b) for a, b in v.items()} if isinstance(v, dict) else v) for k, v in data.get('coverage', {}).items() if k not in {'file_inventory', 'excluded_subtrees'}}, ensure_ascii=False),
              'Pełny manifest plików i wykluczonych poddrzew: coverage w JSON.',
              '', f"Pełne findings w JSON: {len(data['findings'])}; poniżej podział na soczewki."]
    for lens, item in data['lenses'].items():
        lines += ['',f"## {lens}", '', ui.assessment_text(item.get('summary', ui.assessment(item['findings']))), '']
        lines += ['- [ ] '+c for c in item['checklist']]
        for f in item['findings']:
            if f.get('verification_status') != 'confirmed':
                continue
            lines += [f"- {f.get('source_area', 'unknown')} / {f['severity']} / {f['confidence']} / {'VERIFIED' if f['confidence']=='confirmed' else 'ASSUMPTION'} `{f['file']}:{f['line']}` [{f['id']}] {f['title']}: {f['why']} Poprawka: {f['fix']}",
                      '  Dowody: '+evidence_summary(f['evidence'])]
        lines += [f"Findings: {len(item['findings'])}", '', '### Adversarial pass', *item['adversarial_pass']['checks'], *item['adversarial_pass']['limitations']]
    for name, title in [('endpoints', 'Inwentarz tras'), ('rbac', 'Deklaracje RBAC'), ('reported_findings', 'Raporty bezpieczeństwa a kod')]:
        lines += ['', '## '+title, f"Łącznie: {len(data[name])}; przykłady (maks. 3):"]
        for item in data[name][:3]:
            lines += [json.dumps(item, ensure_ascii=False)]
    if 'source_coverage' in data:
        coverage_data = data['source_coverage']
        lines += ['', '## Pełny odczyt źródeł', coverage_data['status'] + ': ' + str(coverage_data['files_read']) + '/' + str(coverage_data['files_total']) + ' plików; ' + str(coverage_data['lines_read']) + ' linii. Nieznane sumy linii: ' + str(coverage_data['unknown_line_totals'])]
        lines += ['- ' + r['file'] + ': ' + r['reason'] for r in coverage_data['files'] if r['status'] != 'read']
    if engine := data.get('static_engine'):
        details, parsed = engine.get('engine', {}), engine.get('coverage', {})
        lines += ['', '## Reguły strukturalne security',
                  f"Silnik: {details.get('name', 'unknown')} {details.get('version') or 'unknown'}; pliki z faktami AST: {parsed.get('files_parsed', 0)}/{parsed.get('files_total', 'unknown')}; zakres: {parsed.get('status', 'INCOMPLETE')}.",
                  'Pozostałe pliki i nieobsługiwane obszary mają jawny fallback; lokalny guard nie jest dowodem ochrony produkcji. Pełne miejsca i luki: static_engine w JSON.']
    for area, title in ui.AREA_TITLES.items():
        rows = [f for f in data['findings'] if f.get('source_area', ui.source_area(f.get('file', ''))) == area]
        if rows: lines += ['', '## Zakres: ' + title, ui.assessment_text(ui.assessment(rows))]
    lines += ['', '## Decyzje właściciela', *data.get('decisions', []), '', '## Precyzja detektorów', json.dumps({k:v for k,v in data.get('verification', {}).items() if k not in ('candidates', 'score')}, ensure_ascii=False), '', '## Załącznik: candidate (zagregowane, wymagają weryfikacji)']
    for group in data.get('verification', {}).get('candidates', []):
        lines += [f"- {group['detector']}: {group['count']}"]
        for f in group['examples']:
            lines += [f"  - {ui.source_area(f.get('file', ''))} / candidate / {f['severity']} / {f['confidence']} / ASSUMPTION `{f['file']}:{f['line']}` {f['why']} Poprawka: {f['fix']} ID: {f['finding_id']}"]
    lines += ['', 'Helix: ' + data.get('helix_version', 'unknown') + '; schemat raportu: ' + str(data.get('schema_version', 'unknown'))]
    lines += ['', '## Dziewięć perspektyw per część',
              'Dojrzałość pomocnicza; wykonanie osobno. Pełne kontrole i dowody w JSON.']
    for part in data.get('senior_pipeline', {}).get('parts', []):
        lines += ['', 'Część: ' + part['part']]
        for role, result in part['roles'].items():
            lines += [f"- {role}: maturity={result['maturity_score']}; execution={result['execution_score']}; not-run={result['execution_debt']}; gate={result['gate']}"]
    audit = data.get('data_leak_audit', {})
    lines += ['', '## Przepływ danych i DPIA', json.dumps(audit.get('dpia', {}), ensure_ascii=False),
              f"Mapa: {len(audit.get('flows', []))} lokalizacji; audit trail: {len(audit.get('audit_trail', {}).get('actions', []))} akcji, pokrycie i trwałość unknown. Szczegóły w JSON."]
    origin = data.get('provenance', {})
    lines += ['', f"Pochodzenie: Helix {origin.get('helix_version', 'unknown')}; rewizja celu {origin.get('target_head') or 'unknown'}. Pełne metadane: provenance w review-deep.json."]
    lines += ['', '## Audyty offline', json.dumps(data['offline_audits'],ensure_ascii=False), '', '## Ograniczenia', *data['limitations']]
    return '\n'.join(lines)+'\n'


def cli(args):
    root = Path(args.target_repo).resolve(strict=True)
    out = Path(args.out).resolve() if args.out else None
    if out and (out == root or root in out.parents or out in root.parents):
        raise ValueError('--out musi być poza repo i nie może być jego przodkiem')
    data = report(root, args.advisories, args.gitleaks_report, getattr(args, 'auth_sanity_percent', 30), getattr(args, 'verdicts', None), getattr(args, 'state_dir', None), getattr(args, 'precision_threshold', 0.3), getattr(args, 'precision_minimum', 10))
    from helix_visual import projection
    if getattr(args, 'visual_report', None):
        data['visual_audit'] = projection(args.visual_report)
    if getattr(args, 'weight_report', None):
        data['performance_weight'] = projection(args.weight_report, 'perf')
    if out:
        out.mkdir(parents=True,exist_ok=True)
        for name, content in [('review-deep.json',json.dumps(data,ensure_ascii=False,indent=2)+'\n'),('review-deep.md',markdown(data)),('coverage.json',json.dumps(data['source_coverage'],ensure_ascii=False,indent=2)+'\n')]:
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=out,delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(content)
                os.replace(temporary,out/name)
            finally:
                if temporary:
                    temporary.unlink(missing_ok=True)
    print(json.dumps(data,ensure_ascii=False,indent=2) if args.format=='json' else markdown(data))


def structural_signals(repo, endpoints):
    """Bounded local import graph and independently useful QA/duplication signals."""
    files = list(security.sources(repo))
    names = {name for name,_ in files}
    graph = {name:set() for name in names}
    import_lines = {}
    rows = []
    blocks = {}
    for file, raw in files:
        if file.endswith('.md'):
            continue
        import_source = re.sub(r'''(?m)^[ \t]*import[ \t]+type\b[\s\S]*?\bfrom\s*["'][^"'\n]+["'][ \t]*;?''', lambda m: re.sub(r'[^\n]', ' ', m[0]), raw)
        for m in re.finditer(r'(?:from\s*|require\s*\(|import\s*)["\'](\.[^"\']+)["\']',import_source):
            target = os.path.normpath(str(Path(file).parent/m[1])).replace(os.sep,'/')
            candidates = [target]+[target+ext for ext in ('.ts','.js','.tsx','.jsx','.py')]+[target+'/index'+ext for ext in ('.ts','.js')]
            match = next((c for c in candidates if c in names),None)
            if match:
                graph[file].add(match)
                import_lines[file,match] = raw.count('\n',0,m.start())+1
        # forEach discards async callback results; delegated callers need explicit
        # completion/error ownership, even when parallelism itself is intended.
        code = security.mask(raw)
        async_names = re.findall(r'\basync\s+function\s+(\w+)\s*\(', code)
        callback_patterns = [r"async\s+(?:function\b|(?:\([^)]*\)|[A-Za-z_$]\w*)\s*=>)"]
        callback_patterns.extend(re.escape(name)+r"\s*(?=\))" for name in async_names)
        for callback in callback_patterns:
            for match in re.finditer(r'\.forEach\s*\(\s*'+callback, code):
                rows.append(security.finding('DEV-ASYNC-FOREACH', 'Wyniki async callback odrzucone przez forEach',
                    file, code, match.start(),
                    'forEach nie zbiera Promise callbacka; sprawdź zakończenie operacji, błędy i współdzielony status.',
                    'Zarządzaj zakończeniem jawnie przez Promise.allSettled lub pętlę await.', 'medium', 'possible', 'senior_developer'))
        lines = raw.splitlines()
        for i in range(0,len(lines)-7,8):
            normalized = '\n'.join(line.strip() for line in lines[i:i+8])
            if len(normalized)>240 and not normalized.startswith(('import ','from ')):
                blocks.setdefault(normalized,[]).append((file,i+1))
    # Iterative reachability avoids recursion failures on large source trees.
    for file, targets in sorted(graph.items()):
        for target in sorted(targets):
            pending=[target];seen=set()
            while pending and len(seen)<2000:
                node=pending.pop()
                if node==file:
                    rows.append(security.finding('ARCH-CYCLE','Cykl lokalnych importów',file,'\n'*(import_lines[file,target]-1),import_lines[file,target]-1,
                        'Statyczne importy tworzą cykl; wpływ zależy od inicjalizacji modułów.',
                        'Wydziel wspólny interfejs i usuń zależność zwrotną.','medium','likely','architect'))
                    break
                if node not in seen:
                    seen.add(node);pending.extend(graph.get(node,()))
    for locations in blocks.values():
        if len({file for file,_ in locations})<2:
            continue
        file,line=locations[0]
        row=security.finding('DEV-DUPLICATION','Powielony blok kodu',file,'',0,
            'Identyczne osiem kolejnych linii w kilku plikach; możliwy rozjazd poprawek.',
            'Porównaj intencje i rozważ wspólną funkcję.','low','possible','senior_developer')
        row['line']=line;row['evidence']=[f'{f}:{n}' for f,n in locations[:3]]+[f'Łącznie: {len(locations)}']
        rows.append(row)
    tests = [(file,raw) for file,raw in security.sources(repo,include_tests=True)
             if re.search(r'(?:^|/)(?:tests?|__tests__)/|[._](?:test|spec)\.',file)]
    if endpoints and not tests:
        route=endpoints[0]
        rows.append(security.finding('QA-NO-TESTS','Brak lokalnych testów tras',route['file'],'\n'*(route['line']-1),route['line']-1,
            f'Inwentarz zawiera {len(endpoints)} handlerów, ale nie znaleziono rozpoznanych plików testów.',
            'Dodaj testy odmowy auth, obcych identyfikatorów i błędnego inputu.','medium','possible','qa'))
    for file,raw in tests:
        for m in re.finditer(r'\b(?:time\.sleep|waitForTimeout)\s*\(\s*\d',raw):
            rows.append(security.finding('QA-FLAKY','Stałe oczekiwanie w teście',file,raw,m.start(),
                'Stałe opóźnienie zależy od szybkości środowiska.', 'Czekaj na warunek.','medium','likely','qa'))
    return rows


def coverage(repo, endpoints):
    """Metadata-only accounting; never descend into excluded private directories.

    Counts are explicit lower bounds when subtrees cannot be enumerated safely.
    Detected handlers are not a claim that dynamic dispatch was resolved.
    """
    root = Path(repo).resolve()
    core = {f for f, _ in security.sources(root)}
    visual = {f for f, _ in ui._sources(root)}
    qa = {f for f, _ in security.sources(root, include_tests=True)} - core
    rows, subtrees = [], []
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in list(dirs):
            p = Path(directory)/name
            if name.startswith('.') or name in (security.SKIP | ui.SKIP) - {'tests', 'fixtures', 'test', '__tests__'} or p.is_symlink():
                dirs.remove(name)
                subtrees.append({'path': p.relative_to(root).as_posix(),
                                 'reason': 'excluded subtree; privacy/generated/dependency/test/symlink policy',
                                 'descendant_files': None})
        for name in sorted(names):
            p = Path(directory)/name
            rel = p.relative_to(root).as_posix()
            scanned = rel in core or rel in visual or rel in qa
            reason = 'analyzed' if scanned else ('symlink' if p.is_symlink() else
                     'hidden/private/minified policy' if name.startswith('.') or re.search(r'secret|credential|private|\.min\.', name, re.I) else
                     'unsupported extension/configuration or decoding failure')
            rows.append({'file': rel, 'status': reason})
    route_files = {r['file'] for r in endpoints}
    candidates = route_files | {r['file'] for r in rows if re.search(r'(?:/routes/|/api/|/server/|middleware|hooks\.server)', r['file']) and Path(r['file']).suffix in security.EXT - {'.md', '.sql'}}
    migrations = {r['file'] for r in rows if r['file'].endswith('.sql')}
    return dict(files_enumerated=len(rows), files_analyzed=len(core | visual | qa),
                core_files=len(core), ui_files=len(visual), qa_only_files=len(qa),
                files_skipped=sum(r['status'] != 'analyzed' for r in rows),
                excluded_subtrees=subtrees, file_inventory=rows,
                routes=dict(candidate_files=len(candidates), detected_files=len(route_files),
                            without_detected_handler=sorted(candidates-route_files)),
                handlers=dict(detected=len(endpoints), analyzed_detected=len(endpoints), skipped_detected=0, skipped='unknown: dynamic/unsupported dispatch is not enumerable lexically'),
                migrations=dict(sql_files=len(migrations), analyzed=len(migrations & core),
                                skipped=sorted(migrations-core)),
                limitation='File totals exclude unenumerated subtrees; SQL files are migration candidates, not proof they execute.')
