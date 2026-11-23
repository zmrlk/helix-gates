"""Read-only projection of existing audit evidence for the project owner.

Evidence aggregation executes no commands. Explicit execution contracts may
check the local Git HEAD; neither mode runs application code or models. Reports
retain source identity; unknown identities never imply production acceptance.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
from helix_audit_context import safe_read, system_path

NAMES = {'run.json', 'run-metadata.json', 'gate.json', 'truth-gate.json', 'findings.json',
         'helix-findings.json', 'review-deep.json', 'ui-deep.json', 'static-security.json',
         'report.json', 'coverage.json', 'coverage-ledger.json', 'static.json', 'model-plan-size.json',
         'verification-all.json', 'verification.json', 'runtime.json', 'state.json', 'plan.json',
         'cost-plan.json', 'context-plan.json', 'progress.json', 'owner-current.json',
         'audit.json', 'quality.json', 'runtime-report.json', 'environment.json',
         'tools-plan.json', 'tools-install.json', 'advisory-tools.json', 'ux-report.json'}
SKIP_DIRS = {'.git', '.aws', '.ssh', '.codex', '.agents', 'node_modules', 'vendor', '__pycache__',
             'cache', 'screenshots', 'shots', 'tmp', 'logs'}
LEVELS = ('critical', 'high', 'medium', 'low', 'info')


def clean(value, limit=500):
    if value is not None and not isinstance(value, (str, int, float, bool)):
        return '[invalid field]'
    text = str(value or '')
    text = re.sub(r'(?i)(?:bearer\s+)[\w.\-]+', 'Bearer [REDACTED]', text)
    text = re.sub(r'''(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)["']?\s*[=:]\s*["']?)([^\s,;"']+)''', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(https?://)[^/@\s]+:[^/@\s]+@', r'\1[REDACTED]@', text)
    return ' '.join(text.split())[:limit]


def md(value):
    return clean(value).replace('|', '\\|').replace('`', "'").replace('<', '&lt;').replace('>', '&gt;')


def number(value):
    return value if type(value) in (int, float) and value >= 0 and value < float('inf') else None


def numeric_fields(value, keys):
    if not isinstance(value, dict): return None
    return {key: number(value[key]) for key in keys if number(value.get(key)) is not None}


def cost_value(value):
    if number(value) is not None: return value
    if not isinstance(value, dict): return None
    amount = number(value.get('amount', value.get('usd')))
    if amount is None: return None
    currency = value.get('currency', 'USD' if 'usd' in value else None)
    return {'amount': amount, 'currency': currency if currency in {'USD', 'EUR', 'PLN', 'GBP'} else 'unknown'}


def source_area(file):
    parts = {p.lower() for p in Path(str(file)).parts}
    if parts & {'legacy', 'archive', 'archives', 'old', 'deprecated', 'backup', 'backups'}:
        return 'legacy'
    if parts & {'docs', 'doc', 'documentation'} or Path(str(file)).suffix.lower() in {'.md', '.rst', '.txt'}:
        return 'docs'
    if parts & {'tests', 'test', '__tests__', 'fixtures', 'examples', 'e2e'} or re.search(r'[._](?:test|spec)\.', str(file)):
        return 'tests/examples'
    return 'active' if file else 'unknown'


def projected_provenance(value):
    """Keep imported metadata as data, without probing or copying raw payloads."""
    from helix_environment import normalize_models, normalize_tools
    data = value if isinstance(value, dict) else {}
    result = {'schema_version': 1, 'status': data.get('status') if data.get('status') in ('legacy', 'not_recorded') else 'recorded' if data else 'not_recorded',
              'tools': normalize_tools(data.get('tools')), 'models': normalize_models(data.get('models'))}
    for key in ('helix_version', 'python', 'generated_at', 'scope', 'reproducibility'):
        result[key] = clean(data[key]) if isinstance(data.get(key), str) else None
    for prefix in ('source', 'target'):
        ref = data.get(prefix + '_ref')
        ref = ref if isinstance(ref, dict) else {}
        head = ref.get('head', data.get(prefix + '_head'))
        head = head if isinstance(head, str) and re.fullmatch('[0-9a-fA-F]{7,64}', head) else None
        dirty = ref.get('dirty', data.get(prefix + '_dirty'))
        dirty = dirty if isinstance(dirty, bool) else None
        result[prefix + '_ref'] = {'head': head, 'dirty': dirty, 'status': clean(ref.get('status', 'unknown')), 'reason': clean(ref.get('reason', ''))}
        result[prefix + '_head'], result[prefix + '_dirty'] = head, dirty
    result['helix_head'], result['helix_dirty'] = result['source_head'], result['source_dirty']
    if isinstance(data.get('runtime_python'), dict):
        result['runtime_python'] = normalize_tools({'python': data['runtime_python']})['python']
    return result


def source_metadata(data):
    if not isinstance(data, dict): return projected_provenance(None)
    if isinstance(data.get('provenance'), dict): return projected_provenance(data['provenance'])
    _, head = identity(data)
    legacy = {'helix_version': data.get('helix_version'), 'target_head': head, 'status': 'legacy'}
    return projected_provenance(legacy if head or isinstance(data.get('helix_version'), str) else None)


def generation_metadata(repo):
    from helix_environment import provenance
    return provenance(repo)


def project_source_reports(rows):
    if not isinstance(rows, list): return []
    return [{'kind': clean(row.get('kind')), 'artifact': clean(row.get('artifact')),
             'provenance': projected_provenance(row.get('provenance')),
             'head_relation': clean(row.get('head_relation', 'unknown')),
             'snapshot_equivalence': 'not_established'} for row in rows if isinstance(row, dict)]


def provenance_line(value):
    data = value or {}
    return ('Generowanie raportu: Helix ' + md(data.get('helix_version') or 'unknown')
            + '; kod Helixa ' + md(data.get('source_head') or 'unknown')
            + '; bieżący cel ' + md(data.get('target_head') or 'unknown')
            + '; dirty=' + md(str(data.get('target_dirty')) if data.get('target_dirty') is not None else 'unknown')
            + '. Faktyczne wersje narzędzi i modeli: tylko z zapisanych pomiarów; brak dowodu oznacza unknown. Metadane źródłowych raportów pozostają osobne.')


def identity(data):
    if not isinstance(data, dict): return None, None
    ref = data.get('source_ref') or {}
    sha = ref.get('head') if isinstance(ref, dict) else None
    provenance = data.get('provenance')
    provenance = provenance if isinstance(provenance, dict) else {}
    target_ref = provenance.get('target_ref')
    target_ref = target_ref if isinstance(target_ref, dict) else {}
    sha = sha or data.get('head') or data.get('source_sha') or data.get('sha') or target_ref.get('head') or provenance.get('target_head')
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-fA-F]{7,64}', sha): sha = None
    target = data.get('target') or data.get('project')
    if isinstance(target, str) and Path(target).is_absolute():
        target = str(system_path(target))
    else:
        target = None
    return target, sha


def recognized(name):
    return bool(re.fullmatch(r'model-call-[0-9a-f]{32}\.json', name)) or name in NAMES or bool(re.fullmatch(r'verified-[\w-]+\.json', name))


def validate_shape(data):
    if not isinstance(data, dict): return
    for key in ('tools', 'providers', 'provider_attempts', 'paths', 'problems'):
        if key in data and not isinstance(data[key], list):
            raise ValueError('invalid ' + key)
    for key in ('findings', 'verdicts', 'coverage'):
        if key in data and data[key] is not None and not isinstance(data[key], (list, dict)):
            raise ValueError('invalid ' + key)


def inventory(roots, excluded=()):
    """Only named evidence artifacts, with no-follow reads and explicit gaps."""
    artifacts, gaps, seen = [], [], set()
    excluded = {str(system_path(p)) for p in excluded}
    for value in roots:
        root = system_path(value)
        if not root.is_dir() or any(p.is_symlink() for p in [root, *root.parents]):
            gaps.append({'path': str(root), 'reason': 'Katalog dowodów nie istnieje lub zawiera dowiązanie.'})
            continue
        def onerror(error):
            gaps.append({'path': str(root), 'reason': 'Nie można odczytać katalogu dowodów: ' + type(error).__name__})
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith('.') and not (Path(directory) / d).is_symlink())
            for name in sorted(files):
                if not recognized(name): continue
                path = Path(directory) / name
                if str(path) in seen or str(path) in excluded: continue
                seen.add(str(path))
                if path.is_symlink():
                    gaps.append({'path': str(path), 'reason': 'Pominięto dowiązanie raportu.'}); continue
                try:
                    raw = safe_read(path, errors='strict')
                    data = json.loads(raw)
                    if not isinstance(data, (dict, list)): raise ValueError('report must be an object or list')
                    validate_shape(data)
                except (OSError, UnicodeError, ValueError, RecursionError) as error:
                    gaps.append({'path': str(path), 'reason': 'Nieprawidłowy lub nieczytelny raport: ' + type(error).__name__}); continue
                artifacts.append({'path': str(path), 'directory': str(path.parent), 'name': name,
                                  'sha256': hashlib.sha256(raw.encode()).hexdigest(), 'data': data})
    return artifacts, gaps


def finding_rows(data, name):
    if isinstance(data, list):
        return data if name in {'findings.json', 'helix-findings.json', 'verification-all.json'} or name.startswith('verified-') else []
    rows = data.get('findings', data.get('verdicts', []))
    if isinstance(rows, list): return rows
    # Security deep provider format may group records by disposition.
    if isinstance(rows, dict):
        return [dict(row, verdict=state) for state, values in rows.items() if isinstance(values, list) for row in values if isinstance(row, dict)]
    return []


def coverage_summary(data, name):
    if name == 'static.json' and isinstance(data, dict):
        return {'status': clean(data.get('status') or ('INCOMPLETE' if not data.get('files') else 'unknown')),
                'files_read': number(data.get('files')), 'paths': [clean(x) for x in data.get('paths', [])], 'problems': [clean(x) for x in data.get('problems', [])]}
    cov = data if name in {'coverage.json', 'coverage-ledger.json', 'context-plan.json'} else data.get('source_coverage', data.get('coverage')) if isinstance(data, dict) else None
    if isinstance(cov, list):
        rows = [r for r in cov if isinstance(r, dict)]
        return {'units': len(rows), 'states': dict(Counter(clean(r.get('status') or ('complete' if r.get('ok') else 'incomplete')) for r in rows)),
                'gaps': [{'unit': clean(r.get('unit', r.get('id', r.get('file')))), 'reason': clean(r.get('reason') or '; '.join(map(str, r.get('problems', []))))}
                         for r in rows if r.get('status') in {'blocked', 'uncovered', 'not_checked', 'pending', 'skipped', 'error'} or r.get('ok') is False]}
    if isinstance(cov, dict):
        result = numeric_fields(cov, ('files_total', 'files_read', 'lines_read', 'unknown_line_totals', 'enumerated_files', 'analyzed_files', 'excluded_files', 'handlers'))
        if 'status' in cov: result['status'] = clean(cov['status'])
        return result
    return None


def runtime_integrations_summary(value):
    """Project validated producer data; readiness is never business-flow coverage."""
    if not isinstance(value,dict) or value.get('status')=='NOT_RECORDED':
        return {'status':'NOT_RECORDED','active':0,'tested':None,'failed_routes':None,'entries':[],
                'reason':'Brak inwentarza integracji w dawnym raporcie; pokrycie nieznane.'}
    entries=[]
    for entry in value.get('integrations',[]):
        entries.append(dict(id=clean(entry['id']),provider=clean(entry['provider']),area=clean(entry['area']),
                            parts=[clean(p) for p in entry['parts']],strategy=clean(entry['strategy']['selected']) or 'unresolved',
                            implemented=entry['strategy']['implemented'],readiness=clean(entry['execution']['readiness']),
                            actual_version=clean(entry['execution']['actual_version']) or None,
                            coverage=clean(entry['coverage']['status']),
                            locations=[dict(path=clean(p['path']),line=p['line'],kind=clean(p['kind'])) for p in entry['evidence']],
                            affected_routes=[dict(route=clean(p['path']),method=clean(p['method']),source=clean(p['source']),line=p['line']) for p in entry['affected_routes']],
                            tested_routes=[dict(route=clean(p['route']),method=clean(p['method']),status=clean(p['status']),evidence=clean(p['evidence'])) for p in entry['coverage']['tested_routes']],
                            unresolved_paths=[dict(path=clean(p['path']),line=p['line'],reason=clean(p['reason'])) for p in entry['unresolved_paths']],
                            untested_because=[clean(p) for p in entry['coverage']['untested_because']]))
    active=[entry for entry in entries if entry['area']=='active']
    return dict(status=clean(value.get('status','NOT_RECORDED')),active=len(active),
                tested=sum(entry['coverage']=='tested' for entry in active),entries=entries,
                failed_routes=sum(route['status']=='FAIL' for entry in active for route in entry['tested_routes']),
                reason='Gotowość usługi nie potwierdza wykonania tras; metryki wykonanych kontroli pozostają osobnym dowodem.')


def integration_markdown(summary):
    lines=['Pokrycie integracji: **'+md(summary['status'])+'**; aktywne: '+str(summary['active'])+'; z dowodem tras: '+str(summary['tested'] if summary['tested'] is not None else 'nieznane')+'; trasy FAIL: '+str(summary.get('failed_routes') if summary.get('failed_routes') is not None else 'nieznane')+'.',md(summary['reason']),'']
    if summary['entries']:
        lines += ['| Integracja i zakres | Część | Strategia / adapter | Gotowość | Pokrycie i luka |','|---|---|---|---|---|']
        for row in summary['entries']:
            lines.append('| '+ ' | '.join(md(v) for v in (row['provider']+' ['+row['area']+']',', '.join(row['parts']) or 'nieustalona',row['strategy']+' / '+('dostępny' if row['implemented'] else 'brak'),row['readiness'],row['coverage']+': '+'; '.join(row['untested_because'])))+' |')
        for row in summary['entries']:
            for route in row['tested_routes']:
                if route['status']=='FAIL':lines.append('- FAIL '+md(row['provider'])+': '+md(route['method'])+' '+md(route['route'])+'; dowód: '+md(route['evidence']))
        lines += ['', 'Pełne miejsca z liniami, trasy i nierozwiązane importy pozostają w JSON tego raportu.','']
    return lines


def project_finding(row, artifact):
    if not isinstance(row, dict): return None
    file = row.get('file', '')
    where = row.get('where') or []
    if not isinstance(where, list): where = []
    places = [clean(w) for w in where if isinstance(w, str)]
    locations = row.get('locations', [])
    if isinstance(locations, list):
        places += [clean(value) for value in locations if isinstance(value, str)]
    evidence = row.get('evidence')
    if isinstance(evidence, list):
        places += [f"{clean(e['file'])}:{e.get('line', 0)}" for e in evidence if isinstance(e, dict) and isinstance(e.get('file'), str)]
    if isinstance(file, str) and file:
        places.insert(0, f"{clean(file)}:{row.get('line', 0)}")
    # Never infer a verified vulnerability from confidence or high severity.
    verdict = row.get('verification_status') or row.get('verdict') or 'candidate'
    if verdict not in {'confirmed', 'rejected', 'needs_validation', 'candidate'}: verdict = 'candidate'
    severity = row.get('assessed_severity') or row.get('severity') or row.get('source_severity') or 'info'
    if isinstance(severity, dict): severity = severity.get('overall_severity', 'info')
    if severity not in LEVELS: severity = 'info'
    return {'id': clean(row.get('id', row.get('rule', row.get('fingerprint', 'unknown')))), 'title': clean(row.get('title', row.get('impact', 'Ustalenie bez tytułu'))),
            'severity': severity, 'verdict': verdict, 'locations': list(dict.fromkeys(places)),
            'source_area': source_area(file or (places[0].rsplit(':', 1)[0] if places else '')),
            'count': number(row.get('count', 1)), 'artifact': artifact['path'],
            'verification_key': clean(row.get('verification_key', ''))}


def ponytail_debt_markdown(summary):
    """Render the recorded debt snapshot, without scoring or guessing age."""
    if summary is None: return []
    counts = summary['counts']
    known = lambda value: 'nieznane' if value is None else str(value)
    lines = ['', 'Dług Ponytail: **' + md(summary['status']) + '**; komentarze: ' +
             known(counts['markers']) + '; bez sufitu: ' + known(counts['no_ceiling']) +
             '; bez ścieżki ulepszenia: ' + known(counts['no_trigger']) + '.',
             'Wiek oznacza ostatnią zmianę linii w HEAD w chwili odczytu, nie datę powstania długu. '
             'Rejestr nie przyznaje punktów jakości i nie wykonuje modeli.']
    if summary.get('observed_at'):
        lines.append('Odczyt: `' + md(summary['observed_at']) + '`; aktualność źródeł względem bieżącego drzewa nie została ustalona przez agregację.')
    rows = summary['rows']
    if rows:
        lines += ['', '| Miejsce | Obszar | Sufit | Ścieżka ulepszenia | Wiek przy odczycie |',
                  '|---|---|---|---|---|']
        for row in rows:
            age = 'nieznane' if row['age_days'] is None else str(row['age_days']) + ' dni'
            lines.append('| `' + md(row['file']) + ':' + str(row['line']) + '` | ' + md(row['source_area']) +
                         ' | ' + md(row['ceiling'] or 'niepodany') + ' | ' + md(row['upgrade_path'] or 'niepodana') +
                         ' | ' + age + ' |')
    gaps = summary.get('coverage', {}).get('gaps', [])
    for gap in gaps[:8]:
        if isinstance(gap, dict):
            lines.append('- Luka odczytu komentarzy: ' + md(gap.get('file') or gap.get('path') or 'zakres') +
                         (':' + str(gap['line']) if gap.get('line') else '') + ': ' +
                         md(gap.get('reason') or gap.get('code') or 'nieustalona') + '.')
    if len(gaps) > 8:
        lines.append('Pokazano 8 z ' + str(len(gaps)) + ' luk odczytu komentarzy; pełna lista z miejscami pozostaje w JSON rejestru.')
    return lines


def runtime_sinks_gap(summary):
    if summary is None or summary['coverage_status'] == 'NOT_DETECTED': return None
    if summary['coverage_status'] == 'NOT_RECORDED':
        return 'Brak historycznego zapisu lokalnych skrzynek wysyłek.'
    if summary['execution_status'] == 'NOT_RUN':
        return 'Plan skrzynek nie został wykonany; nie sprawdzono wysyłek aplikacji.'
    if summary['execution_status'] == 'PARTIAL':
        return 'Obserwacje lokalnych wysyłek są niepełne; przyczyny pozostają przy właściwej części.'
    return 'Lokalne obserwacje wysyłek nie potwierdzają jeszcze wykonania tras aplikacji.'


def runtime_sinks_markdown(summary):
    if summary is None: return []
    from helix_runtime_sinks import OPERATIONS_BY_ID
    count = lambda key: 'nieznane' if summary['counts'][key] is None else str(summary['counts'][key])
    lines = ['', 'Lokalne skrzynki wysyłek: plan **' + md(summary['plan_status']) +
             '**, wykonanie **' + md(summary['execution_status']) + '**.',
             'Zarejestrowane lokalne przyjęcia: ' + count('captured_local') +
             '; odmowy: ' + count('rejected_local') + '.',
             'Doręczenie zewnętrzne: **' + md(summary['external_delivery']) +
             '**; zweryfikowane trasy aplikacji w tym zakresie: ' + count('application_routes_verified') + '.',
             'Przyjęcie do skrzynki jest emulacją. Nie oznacza doręczenia wiadomości, publikacji ani wykonania trasy.']
    gap = runtime_sinks_gap(summary)
    if gap: lines.append(gap)
    reasons = {
        'NOT_STARTED': 'Odbiornika nie uruchomiono.',
        'SOURCE_SNAPSHOT_INCOMPLETE': 'Odczyt źródeł jest niepełny.',
        'INTEGRATION_SCOPE_UNRESOLVED': 'Nie ustalono części aplikacji dla integracji.',
        'STRATEGY_DISABLED': 'Integracja jest jawnie wyłączona.',
        'STRATEGY_UNSUPPORTED': 'Wybrana strategia nie ma tego adaptera.',
        'APPLICATION_CONFIGURATION_NOT_PROVEN': 'Nie potwierdzono wymaganych ustawień aplikacji, w tym konfiguracji w bazie.',
        'RECIPIENT_DNS_NOT_PROVEN': 'Nie potwierdzono obsługi walidacji domeny odbiorcy.',
        'SYNTHETIC_SUBSCRIPTION_NOT_PROVEN': 'Brak dowodu użycia własnej syntetycznej subskrypcji push.',
        'NO_CAPTURE_OBSERVED': 'Nie zaobserwowano lokalnego przyjęcia wysyłki.',
        'SINK_START_FAILED': 'Nie udało się uruchomić odbiornika.',
        'SINK_UNAVAILABLE': 'Odbiornik jest niedostępny.',
        'SINK_WRITE_FAILED': 'Nie udało się zapisać dowodu odbioru.',
        'SINK_INPUT_INVALID': 'Konfiguracja odbiornika nie spełnia kontraktu.',
        'REQUEST_REJECTED': 'Odbiornik odrzucił żądanie.',
        'LIMIT_EXCEEDED': 'Przekroczono limit odbiornika.',
        'DEADLINE_EXCEEDED': 'Wyczerpano czas oczekiwania.',
        'INTERRUPTED': 'Przerwano wykonanie.',
        'CLEANUP_UNKNOWN': 'Nie potwierdzono sprzątnięcia własnego odbiornika.',
        'UNSUPPORTED_TRANSPORT': 'Transport lub operacja nie mają adaptera.',
        'OBSERVATIONS_UNAVAILABLE': 'Brak zapisu obserwacji.',
        'OBSERVATIONS_INVALID': 'Obserwacje nie są poprawnie powiązane z tym przebiegiem.',
    }
    readiness = {'not_run': 'nieuruchomiony', 'ready': 'gotowy', 'closed': 'zamknięty', 'blocked': 'zablokowany', 'partial': 'niepełny'}
    cleanup = {'not_needed': 'niewymagane', 'closed': 'potwierdzone', 'unknown': 'niepotwierdzone'}
    for part in summary['parts']:
        lines.append('- Część `' + md(part['part']) + '`: ' + md(part['execution_status']) +
                     '; odbiornik ' + md(readiness[part['readiness']]) + '; sprzątanie ' + md(cleanup[part['cleanup']]) + '.')
        for declaration in part['providers']:
            places = ', '.join('`' + md(e['path']) + ':' + str(e['line']) + '`' for e in declaration['evidence'])
            lines.append('  - ' + md(declaration['provider']) + ': ' + (places or 'brak miejsca deklaracji') + '.')
        for reason in part['gaps']:
            lines.append('  - ' + md(reasons.get(reason, reason)))
        observed = {}
        for row in part['observations']:
            key = (row['provider'], row['operation_id'], row['outcome'], row['http_status'])
            observed[key] = observed.get(key, 0) + 1
        for (provider, operation, outcome, status), total in observed.items():
            label = ('odmowy' if outcome == 'rejected_local' else 'odpowiedzi kontrolne'
                     if OPERATIONS_BY_ID[operation]['effect'] == 'control' else 'przyjęcia')
            lines.append('  - `' + md(provider) + '/' + md(operation) + '`: ' + label + ' ' + str(total) +
                         ', HTTP ' + str(status) + '.')
    for reason in summary['gaps']: lines.append('- ' + md(reasons.get(reason, reason)))
    for declaration in summary['unscoped_declarations']:
        lines.append('- Nieustalona część dla ' + md(declaration['provider']) + ': ' +
                     ', '.join('`' + md(e['path']) + ':' + str(e['line']) + '`' for e in declaration['evidence']) + '.')
    if summary['excluded_declarations']:
        lines.append('Deklaracje poza aktywnym zakresem: ' + str(len(summary['excluded_declarations'])) + '; zachowane w JSON.')
    return lines


def runtime_network_gap(summary):
    if summary is None or summary['coverage_status'] == 'RECORDED': return None
    messages = {
        'NOT_RECORDED': 'Historyczny raport nie zawiera dowodu izolacji procesów.',
        'NOT_RUN': 'Nie sprawdzono izolacji procesów w tym przebiegu.',
        'SIMULATED': 'Atrapa potwierdza test wykonawcy, ale nie ochronę systemu operacyjnego.',
        'BLOCKED': 'Odmowa izolacji zatrzymała objęte nią polecenia projektu lub serwer bazy.',
    }
    return messages.get(summary['status'], 'Zakres dowodu izolacji procesów pozostaje niepełny.')


def runtime_network_markdown(summary):
    if summary is None: return []
    count = lambda key: 'nieznane' if summary['counts'][key] is None else str(summary['counts'][key])
    lines = ['', 'Izolacja procesów runtime: **' + md(summary['status']) + '**.',
             'Dopuszczenia: ' + count('admitted') + '; odmowy: ' + count('blocked') +
             '; wywołane polecenia: ' + count('invoked') + '.',
             'Dowód OS: ' + count('enforced') + '; atrapy testowe: ' + count('simulated') + '.',
             'Zakres obejmuje procesy projektu i osobno własny serwer bazy. '
             'Dopuszczenie procesu nie potwierdza działania aplikacji ani użycia lokalnej skrzynki wysyłek.']
    gap = runtime_network_gap(summary)
    if gap: lines.append(gap)
    phases = {'install': 'instalacja', 'migration': 'migracje i restore', 'build': 'budowanie',
              'application': 'aplikacja', 'measurement': 'pomiary', 'database_server': 'serwer bazy'}
    scopes = {'project': 'projekt', 'database_server': 'serwer bazy', 'measurement': 'pomiary w przeglądarce'}
    states = {'enforced': 'ochrona OS', 'simulated': 'atrapa testowa', 'blocked': 'odmowa'}
    reasons = {
        'LOCAL_PROBE_PASSED': 'Lokalna sonda potwierdziła badany zakres.',
        'UNSUPPORTED_PLATFORM': 'Brak adaptera dla tego systemu.',
        'SANDBOX_EXEC_UNAVAILABLE': 'Brak narzędzia sandbox-exec.',
        'INVALID_POLICY': 'Polityka procesu nie spełnia kontraktu.',
        'CONTROL_PATH_UNSAFE': 'Nie można ochronić plików kontrolnych.',
        'BUDGET_EXHAUSTED': 'Wyczerpano budżet czasu.',
        'PROBE_DENIED': 'System odmówił wykonania sondy.',
        'PROBE_INCOMPLETE': 'Sonda nie zakończyła wymaganych kontroli.',
        'PROBE_FAILED': 'Sonda nie potwierdziła ograniczeń.',
        'PROFILE_PUBLICATION_FAILED': 'Nie udało się bezpiecznie zapisać profilu.',
        'DATABASE_SERVER_UNSUPPORTED': 'Ten serwer bazy nie ma osobnego dowodu izolacji.',
        'WRAPPER_REJECTED': 'Odrzucono opakowanie procesu lub aktualność grantu.',
        'ADMISSION_ERROR': 'Nie udało się sprawdzić dopuszczenia.',
        'SYNTHETIC_TEST': 'Wynik atrapy, bez potwierdzenia OS.',
    }
    groups = {}
    for row in summary['records']:
        key = (row['phase'], row['scope'], row['backend'], row['enforcement'], row['reason_code'])
        group = groups.setdefault(key, dict(count=0, invoked=0))
        group['count'] += 1
        group['invoked'] += int(row['command_invoked'])
    if groups:
        lines += ['', '| Faza / zakres | Mechanizm | Wynik | Liczba / wywołane | Powód |', '|---|---|---|---:|---|']
        for (phase, scope, backend, state, reason), group in groups.items():
            lines.append('| ' + md(phases[phase]) + ' / ' + md(scopes[scope]) + ' | ' + md(backend) +
                         ' | ' + md(states[state]) + ' | ' + str(group['count']) + ' / ' +
                         str(group['invoked']) + ' | ' + md(reasons.get(reason, reason)) + ' (`' + md(reason) + '`) |')
    return lines


def runtime_extensions_summary(fidelity):
    """Present validated catalog observations; readiness is not migration credit."""
    from copy import deepcopy
    counts = ('checks', 'ready', 'blocked', 'incomplete', 'requirements_unknown')
    if not isinstance(fidelity, dict) or 'extension_checks' not in fidelity:
        return dict(status='NOT_RECORDED', counts={key: None for key in counts}, checks=[])
    checks = deepcopy(fidelity['extension_checks'])
    values = dict(checks=len(checks), ready=sum(row['status'] == 'ready' for row in checks),
                  blocked=sum(row['status'] == 'blocked' for row in checks),
                  incomplete=sum(row['status'] in ('checking', 'incomplete') for row in checks),
                  requirements_unknown=sum(row['requirements_status'] == 'unknown' for row in checks))
    status = ('NOT_RUN' if not checks else 'BLOCKED' if values['blocked'] else
              'INCOMPLETE' if values['incomplete'] or values['requirements_unknown'] else 'READY')
    return dict(status=status, counts=values, checks=checks)


def runtime_extensions_markdown(summary):
    if summary is None: return []
    counts = summary['counts']
    value = lambda key: 'nieznane' if counts[key] is None else str(counts[key])
    lines = ['', 'Rozszerzenia PostgreSQL: **' + md(summary['status']) + '**.',
             'Sprawdzenia katalogu: ' + value('checks') + '; gotowe: ' + value('ready') +
             '; zablokowane: ' + value('blocked') + '; niepełne: ' + value('incomplete') + '.',
             'Dostępność nie potwierdza instalacji, uprawnień do aktywacji, wykonania migracji ani działania aplikacji.']
    reasons = {
        'CHECK_PENDING': 'Sprawdzenie nie ma jeszcze wyniku.',
        'CATALOG_OBSERVED': 'Odczytano katalog dostępnych rozszerzeń.',
        'REQUIRED_EXTENSION_UNAVAILABLE': 'Brakuje wymaganego rozszerzenia; migrator nie został dopuszczony.',
        'CATALOG_QUERY_FAILED': 'Nie udało się odczytać katalogu.',
        'CATALOG_INVALID': 'Odpowiedź katalogu jest niepoprawna.',
        'RESOURCE_PAUSED': 'Presja zasobów wstrzymała sprawdzenie.',
        'INTERRUPTED': 'Sprawdzenie zostało przerwane.',
    }
    for check in summary['checks']:
        lines.append('- Baza `' + md(check['database']) + '`, zakres ' + md(check['scope']) +
                     ', część `' + md(check['part'] or 'nieustalona') + '`: **' + md(check['status']) + '**. ' +
                     md(reasons.get(check['reason_code'], check['reason_code'])))
        if check['candidate']: lines.append('  - Próba: `' + md(check['candidate']) + '`.')
        if check['requirements_status'] == 'unknown':
            lines.append('  - Pełny zbiór wymagań jest nieustalony; odczyt katalogu nie zamyka tej luki.')
        if check['missing']: lines.append('  - Brakujące: ' + ', '.join('`' + md(name) + '`' for name in check['missing']) + '.')
        for declaration in check['declarations']:
            lines.append('  - Wymagane `' + md(declaration['name']) + '` w `' + md(declaration['path']) + ':' +
                         str(declaration['line']) + '`' + ('; zadeklarowana wersja ' + md(declaration['declared_version']) +
                         ' nie została zweryfikowana' if declaration['declared_version'] else '') + '.')
        for item in check['observed']:
            installed = item['installed_version'] or ('niezainstalowane w tej bazie' if item['available'] else 'nieustalona')
            lines.append('  - `' + md(item['name']) + '`: ' + ('dostępne' if item['available'] else 'niedostępne') +
                         '; wersja domyślna ' + md(item['default_version'] or 'nieznana') +
                         '; instalacja: ' + md(installed) + '.')
        for gap in check['gaps']:
            lines.append('  - Luka `' + md(gap['reason_code']) + '` w `' + md(gap['path']) + ':' + str(gap['line']) + '`.')
        if check['log']: lines.append('  - Dowód odczytu: `' + md(check['log']) + '`.')
    if summary['status'] == 'NOT_RECORDED': lines.append('Brak zapisu kontroli rozszerzeń w historycznym artefakcie.')
    elif summary['status'] == 'NOT_RUN': lines.append('Nie wykonano sprawdzenia katalogu w tym przebiegu.')
    return lines


def runtime_boundary_markdown(transport=None, identity=None):
    """Render validated projections; transport and form phases earn no session credit."""
    lines = []
    if transport is not None:
        lines += ['', 'Transport runtime: **' + md(transport['status']) + '**.',
                  'Gotowość HTTPS nie potwierdza polityki cookies ani logowania.', '']
        for row in transport.get('parts', []):
            lines.append('- `' + md(row['part']) + '`: ' + md(row.get('selected', 'unknown')) +
                         '; stan ' + md(row.get('status', 'unknown')) + '; luki: ' + str(len(row.get('gaps', []))) + '.')
            for requirement in row.get('requirements', []):
                if requirement.get('path'):
                    lines.append('  - Deklaracja `' + md(requirement['path']) + ':' + md(requirement.get('line', '?')) + '` (' + md(requirement.get('kind', 'unknown')) + ').')
            for gap in row.get('gaps', []):
                location = str(gap.get('path', '')) + (':' + str(gap['line']) if 'line' in gap else '')
                lines.append('  - ' + md(gap.get('reason') or gap.get('kind', 'nieustalona luka')) +
                             ('; `' + md(location) + '`' if location else '') + '.')
        if transport.get('status') == 'NOT_RECORDED':
            lines.append('Brak zapisu transportu w artefakcie; nie odtworzono wykonania z deklaracji.')
    if identity is not None:
        lines += ['', 'Formularz i fazy OIDC: **' + md(identity.get('form_status', 'NOT_RECORDED')) +
                  '**; pokrycie: **' + md(identity['status']) + '**.',
                  'Ten zapis obejmuje formularz i callback. Sesję oraz uprawnienia dokumentuje osobny wynik polityki.',
                  'Przejście formularza i callbacku nie jest dowodem zalogowanej sesji ani dostępu do chronionej trasy.', '']
        for row in identity.get('parts', []):
            lines.append('- `' + md(row['part']) + '`: formularz ' + md(row.get('form_status', 'NOT_RUN')) + '.')
            for account in row.get('identities', []):
                lines.append('  - `' + md(account['id']) + '` (' + md(account.get('variant', 'unknown')) +
                             '): ' + md(account.get('form_status', 'NOT_RUN')) + '.')
        if identity.get('status') == 'NOT_RECORDED':
            lines.append('Brak powiązanego zapisu faz tożsamości w tym artefakcie.')
        elif identity.get('status') == 'NOT_DETECTED':
            lines.append('Nie wykryto Keycloaka w tym zakresie źródeł; nie jest to wynik testu logowania.')
    return lines


def runtime_policy_gap(summary):
    """Describe the validated projection without deriving execution evidence."""
    if summary['plan_status'] == 'NOT_DETECTED': return None
    reason = ('Polityka sesji i tras: ' + summary['plan_status'] + '; wykonanie ' +
              summary['execution_status'] + '; pokrycie ' + summary['coverage_status'] +
              '; wynik wymaganej macierzy ' + summary['outcome'])
    if summary['outcome'] == 'FAIL': return 'failed', reason
    if summary['execution_status'] != 'COMPLETE': return 'unexecuted', reason
    outside = sum(len(part.get('unconfigured_identities', [])) for part in summary['parts'])
    if outside or any(part.get('gaps') for part in summary['parts']):
        return 'outside-scope', reason + '; tożsamości bez przypadków: ' + str(outside)
    return None


def runtime_policy_markdown(summary):
    """Render the shared execution projection, keeping matrix scope explicit."""
    if summary is None: return []
    counts = summary['counts']
    count = lambda name: 'nieznane' if counts[name] is None else str(counts[name])
    lines = ['', 'Polityka sesji i tras: plan **' + md(summary['plan_status']) +
             '**; wykonanie **' + md(summary['execution_status']) +
             '**; pokrycie **' + md(summary['coverage_status']) +
             '**; wynik wymaganej macierzy **' + md(summary['outcome']) + '**.',
             'Zaplanowane komórki rola/trasa: ' + count('required_cells') +
             '; wykonane: ' + count('completed_cells') + '; niesprawdzone: ' + count('not_run_cells') + '.',
             'Komórki PASS: ' + count('passed_cells') + '; FAIL: ' + count('failed_cells') +
             '; zablokowane: ' + count('blocked_cells') + '.',
             'Sesje zakończone: ' + count('completed_sessions') + ' z ' + count('required_sessions') + '.',
             'Wynik dotyczy jawnie wybranej macierzy. Pozostałe role i trasy wymagają osobnych dowodów.', '']
    for part in summary['parts']:
        lines.append('- `' + md(part['part']) + '`: plan ' + md(part['plan_status']) +
                     '; wykonanie ' + md(part['execution_status']) + '; wynik ' + md(part['outcome']) + '.')
        if part.get('config_pointer'):
            lines.append('  - Konfiguracja `' + md(part['config_pointer']) + '`.')
        for session in part['sessions']:
            lines.append('  - Sesja `' + md(session['identity_id']) + '` (' + md(session.get('role') or 'nieustalona rola') +
                         '): ' + md(session['status']) + '; anonimowo ' + md(session['anonymous_status']) +
                         '; przyczyna `' + md(session['reason_code']) + '`.')
        for cell in part['cells']:
            lines.append('  - `' + md(cell['config_id']) + '`: ' + md(cell.get('role') or cell.get('identity_id') or 'nierozpoznana rola') +
                         ', ' + md(cell['method']) + ' `' + md(cell['path']) + '`, oczekiwanie ' + md(cell['expected_access']) +
                         '; plan ' + md(cell['plan_status']) + '; wynik ' + md(cell['result']) +
                         '; anonimowo ' + md(cell['anonymous_status']) + '; przyczyna `' + md(cell['reason_code']) + '`.')
        if part.get('unconfigured_identities'):
            lines.append('  - Tożsamości bez zadeklarowanych przypadków: ' + str(len(part['unconfigured_identities'])) + '.')
    if summary['plan_status'] == 'NOT_RECORDED':
        lines.append('Brak zapisu planu polityki w tym historycznym artefakcie.')
    elif summary['plan_status'] == 'NOT_CONFIGURED':
        lines.append('Wykryta tożsamość wymaga jawnych oczekiwań sesji i dostępu do tras.')
    elif summary['plan_status'] == 'NOT_DETECTED':
        lines.append('Nie wykryto deklaracji wymagającej tego adaptera; nie jest to wynik testu sesji.')
    return lines


def runtime_webauthn_gap(summary):
    """Keep an observed failure visible even when the flow was interrupted."""
    if summary['plan_status'] == 'NOT_DETECTED': return None
    reason = ('WebAuthn: plan ' + summary['plan_status'] + '; wykonanie ' +
              summary['execution_status'] + '; pokrycie ' + summary['coverage_status'])
    if 'outcome' in summary: reason += '; wynik wybranego przebiegu ' + summary['outcome']
    if summary.get('outcome') == 'FAIL': return 'failed', reason
    if summary['execution_status'] != 'COMPLETE': return 'unexecuted', reason
    if summary['coverage_status'] != 'RECORDED': return 'outside-scope', reason
    return None


def runtime_webauthn_markdown(summary):
    """A declared virtual key profile is distinct from an executed ceremony."""
    if summary is None: return []
    counts = summary['counts']
    count = lambda name: 'nieznane' if counts[name] is None else str(counts[name])
    reasons = {
        'DEPENDENCY_WITHOUT_FLOW_CONTRACT': 'Wykryto zależność, ale brak opisanego przebiegu rejestracji i logowania.',
        'DISABLED_BY_CONFIGURATION': 'Funkcja została jawnie wyłączona; brak pokrycia pozostaje widoczny.',
        'PART_NOT_DECLARED': 'Konfiguracja wskazuje nierozpoznaną część projektu.',
        'INTEGRATION_SCOPE_UNRESOLVED': 'Nie ustalono części projektu używającej tej integracji.',
        'IDENTITY_PLAN_MISSING': 'Brak planu syntetycznych tożsamości.',
        'IDENTITY_PLAN_BLOCKED': 'Plan tożsamości ma nierozwiązane braki.',
        'ROLE_NOT_DECLARED': 'Nie ustalono wskazanej roli w planie tożsamości.',
        'POLICY_NOT_PLANNED': 'Brak gotowej jawnej polityki sesji i tras.',
        'POLICY_CELL_NOT_BOUND': 'Przypadki dostępu nie należą do wskazanej roli i części.',
        'TRANSPORT_NOT_READY': 'Brak zgodnego planu HTTPS dla localhost.',
        'RP_OWNER_UNSUPPORTED': 'Ten wariant nie obsługuje wskazanego właściciela uwierzytelniania.',
        'RP_ID_UNSUPPORTED': 'Ten wariant wymaga jawnego RP localhost.',
        'CONTRACT_FIELD_MISSING': 'Brakuje wskazanego pola opisu przebiegu.',
        'SOURCE_SNAPSHOT_INCOMPLETE': 'Odczyt źródeł nie daje kompletnego obrazu projektu.',
    }
    execution_reasons = {
        'VIRTUAL_AUTHENTICATOR_CREATED': 'Przeglądarka utworzyła własne urządzenie wirtualne.',
        'REGISTRATION_VERIFIED': 'Aplikacja przyjęła powiązaną rejestrację.',
        'AUTHENTICATION_VERIFIED': 'Aplikacja przyjęła logowanie tym samym kluczem.',
        'LOGOUT_SESSION_DENIED': 'Po wylogowaniu aplikacja odmówiła dostępu do sesji.',
        'SESSION_MATCHED': 'Nowa sesja ma oczekiwaną tożsamość i role.',
        'SESSION_IDENTITY_MISMATCH': 'Nowa sesja wskazuje inną tożsamość.',
        'SESSION_ROLES_MISMATCH': 'Role nowej sesji nie zgadzają się z kontraktem.',
        'SESSION_NOT_CONFIRMED': 'Nie potwierdzono wymaganej sesji.',
        'ACCESS_MATCHED': 'Dostęp do trasy jest zgodny z oczekiwaniem.',
        'ASSERTION_MISMATCH': 'Odpowiedź aplikacji nie spełnia oczekiwań.',
        'CLEANUP_FAILED': 'Nie potwierdzono zamknięcia własnych zasobów.',
        'PREREQUISITE_NOT_CONFIRMED': 'Brakuje końcowego dowodu wcześniejszych faz.',
        'NOT_ATTEMPTED': 'Nie rozpoczęto tego sprawdzenia.',
        'UNSUPPORTED_BROWSER': 'Przeglądarka nie obsługuje tego adaptera.',
        'VIRTUAL_AUTHENTICATOR_UNAVAILABLE': 'Nie udało się utworzyć wirtualnego klucza.',
        'UNSUPPORTED_REQUEST_FORMAT': 'Format żądania nie jest obsługiwany.',
        'UI_ACTION_UNAVAILABLE': 'Nie znaleziono wskazanego przycisku.',
        'UI_ACTION_AMBIGUOUS': 'Wskazanie pasuje do więcej niż jednego przycisku.',
        'OPTIONS_NOT_OBSERVED': 'Nie zaobserwowano oczekiwanych opcji ceremonii.',
        'VERIFY_NOT_OBSERVED': 'Brakuje oczekiwanej weryfikacji przez serwer.',
        'LOGOUT_REQUEST_NOT_OBSERVED': 'Nie zaobserwowano wymaganego żądania wylogowania.',
        'CREDENTIAL_NOT_OBSERVED': 'Własny klucz nie zgłosił poświadczenia.',
        'RP_MISMATCH': 'Ceremonia dotyczy innej aplikacji niż zadeklarowany RP.',
        'REQUEST_NOT_BOUND': 'Nie powiązano żądania z bieżącą ceremonią.',
        'CREDENTIAL_MISMATCH': 'Logowanie używa innego poświadczenia niż rejestracja.',
        'DUPLICATE_CEREMONY_REQUEST': 'Ceremonia wysłała nadmiarowe żądanie.',
        'PUBLIC_RECEIPT_WRITE_FAILED': 'Nie udało się trwale zapisać dowodu.',
        'DEADLINE_EXHAUSTED': 'Wyczerpano budżet czasu.',
        'OPERATION_TIMEOUT': 'Przekroczono czas tej operacji.',
        'RESOURCE_PAUSED': 'Presja zasobów wstrzymała nowe sprawdzenia.',
    }
    def execution_reason(code):
        return (md(execution_reasons[code]) + ' ' if code in execution_reasons else '') + '`' + md(code) + '`'
    executed = 'required_flows' in counts
    lines = ['', 'WebAuthn: plan **' + md(summary['plan_status']) + '**; wykonanie **' +
             md(summary['execution_status']) + '**; pokrycie **' + md(summary['coverage_status']) + '**.']
    if executed:
        lines += ['Wynik wybranego przebiegu: **' + md(summary['outcome']) + '**.',
                  'Przebiegi zakończone: ' + count('completed_flows') + ' z ' + count('required_flows') +
                  '; podjęte: ' + count('attempted_flows') + '.',
                  'Rejestracje PASS: ' + count('registration_pass') + '; uwierzytelnienia PASS: ' + count('authentication_pass') + '.',
                  'Przypadki tras po logowaniu kluczem: ' + count('completed_cells') + ' z ' + count('required_cells') +
                  '; PASS: ' + count('passed_cells') + '; FAIL: ' + count('failed_cells') +
                  '; zablokowane: ' + count('blocked_cells') + '; niesprawdzone: ' + count('not_run_cells') + '.',
                  'Wynik dotyczy wskazanej roli i przypadków. Nie potwierdza pozostałych ról, fizycznego klucza ani produkcji.']
    else:
        lines += ['Części z planem: ' + count('planned_parts') + '; bez konfiguracji: ' + count('unconfigured_parts') +
                  '; zablokowane: ' + count('blocked_parts') + '; wyłączone: ' + count('disabled_parts') + '.',
                  'Wykonane ceremonie: ' + count('ceremonies_executed') + '; rejestracje PASS: ' + count('registration_pass') +
                  '; uwierzytelnienia PASS: ' + count('authentication_pass') + '.']
    lines += ['Zależność i zadeklarowany profil klucza nie potwierdzają przyjęcia go przez aplikację.', '']
    def declarations(rows):
        for declaration in rows:
            versions = ', '.join(str(value) for value in declaration['declared_versions']) or 'nieustalone'
            lines.append('  - Deklaracja `' + md(declaration['provider']) + '`, wersje deklarowane: ' + md(versions) + '.')
            for place in declaration['evidence']:
                lines.append('    - `' + md(place['path']) + ':' + md(place['line']) + '`.')
    def gaps(rows):
        for gap in rows:
            lines.append('  - ' + md(reasons.get(gap['code'], gap['code'])) +
                         (' Konfiguracja `' + md(gap['config_pointer']) + '`.' if gap.get('config_pointer') else ''))
    for part in summary['parts']:
        lines.append('- `' + md(part['part']) + '`: plan ' + md(part['plan_status']) +
                     '; wykonanie ' + md(part['execution_status']) + '.')
        if part.get('config_pointer'): lines.append('  - Konfiguracja `' + md(part['config_pointer']) + '`.')
        if part.get('role'): lines.append('  - Rola: ' + md(part['role']) + '; zaplanowane przypadki tras: ' + str(len(part['policy_cell_ids'])) + '.')
        if executed:
            for key, label in (('capability', 'Urządzenie wirtualne'), ('registration', 'Rejestracja'),
                               ('logout', 'Wylogowanie'), ('authentication', 'Logowanie kluczem'),
                               ('session_after_authentication', 'Nowa sesja')):
                phase = part.get(key)
                if phase is None: continue
                lines.append('  - ' + label + ': ' + md(phase['status']) + '; ' + execution_reason(phase['reason_code']) +
                             ('; zachowana obserwacja ' + md(phase['observation_status'])
                              if phase.get('observation_status') and phase['observation_status'] != phase['status'] else '') + '.')
            for cell in part.get('cells', []):
                probe = cell['access']
                lines.append('  - Przypadek `' + md(cell['cell_id']) + '`: ' + md(probe['status']) +
                             '; ' + execution_reason(probe['reason_code']) + '.')
            if part.get('cleanup'):
                lines.append('  - Zamknięcie własnych zasobów: ' + '; '.join(
                    label + ' ' + md(part['cleanup'][key]) for key, label in (
                        ('authenticator', 'urządzenie'), ('cdp', 'CDP'), ('page', 'strona'), ('context', 'kontekst'))) + '.')
        declarations(part['declarations'])
        gaps(part['gaps'])
    if summary['unscoped_declarations']:
        lines.append('Nieprzypisane do części projektu deklaracje:')
        declarations(summary['unscoped_declarations'])
    gaps(summary['gaps'])
    if summary['excluded_declarations']:
        lines.append('Deklaracje poza aktywnym zakresem (np. dokumentacja lub testy): ' + str(len(summary['excluded_declarations'])) + '.')
    if summary['plan_status'] == 'NOT_RECORDED':
        lines.append('Historyczny raport nie zawiera zapisu WebAuthn; wykonanie i liczniki są nieznane.')
    elif summary['plan_status'] == 'NOT_DETECTED':
        lines.append('Nie wykryto deklaracji WebAuthn w aktywnym zakresie; to nie dowodzi nieobecności funkcji w produkcji.')
    return lines


def tool_execution_gap(tool, status, reason=''):
    """Installation, presence and smoke are never a project scan receipt."""
    if str(status).lower() in {'completed', 'complete', 'success', 'pass', 'not-applicable', 'n/a'}:
        return None
    prefix = ('zadeklarowane, nieuruchomione: brak narzędzia w sprawdzonych lokalizacjach'
              if str(status).lower() in {'unavailable', 'missing', 'not-found'} else
              'brak pełnego dowodu wykonania narzędzia dla projektu: ' + clean(status or 'unknown'))
    return clean(tool or 'nieznane narzędzie') + ': ' + prefix + ('. ' + clean(reason) if reason else '')


def tool_preparation_rows(data, name):
    """Allowlisted projection of a tool plan/install, without execution credit."""
    expected = 'tools-plan' if name == 'tools-plan.json' else 'tools-install'
    if data.get('kind') != expected or data.get('schema_version') != 1:
        raise ValueError('invalid tools artifact contract')
    rows = []
    for item in data.get('tools', []):
        if not isinstance(item, dict):
            raise ValueError('invalid tools artifact row')
        tool = item.get('name' if expected == 'tools-plan' else 'tool')
        if not isinstance(tool, str) or not tool:
            raise ValueError('invalid tools artifact name')
        if expected == 'tools-plan':
            local = item.get('local') if isinstance(item.get('local'), dict) else {}
            managed = item.get('managed') if isinstance(item.get('managed'), dict) else {}
            missing = local.get('status') == 'MISSING' and managed.get('managed_install_status') not in {'VERIFIED'}
            reason = ('zadeklarowane, nieuruchomione: brak narzędzia w sprawdzonych lokalizacjach' if missing else
                      'Plan narzędzia; brak wykonanego skanu projektu.')
            if item.get('runner_implemented') is not True:
                reason += ' Brak runnera w Helixie.'
            preparation = clean(managed.get('managed_install_status', 'unknown'))
        else:
            preparation = clean(item.get('status', 'unknown'))
            reason = 'Instalacja lub własny test narzędzia: ' + preparation + '; skan projektu nieuruchomiony.'
        rows.append(dict(tool=clean(tool), status='NOT_RUN', duration_seconds=None,
                         reason=reason, preparation_status=preparation,
                         applicability='NOT_ASSESSED', project_execution='NOT_RUN'))
    return rows


def aggregate(repo, roots, excluded=(), generation_provenance=None):
    from helix_contracts import VERSION
    repo = system_path(repo)
    artifacts, gaps = inventory(roots, excluded)
    directories = {}
    for artifact in artifacts: directories.setdefault(artifact['directory'], []).append(artifact)
    groups = []
    for directory, docs in sorted(directories.items()):
        identities = {identity(d['data']) for d in docs} - {(None, None)}
        heads = sorted({sha for _, sha in identities if sha})
        targets = sorted({target for target, _ in identities if target})
        # Directory association is reported, never mistaken for cryptographic binding.
        group = {'directory': directory, 'source_shas': heads, 'targets': targets,
                 'identity_status': 'conflict' if len(heads) > 1 or len(targets) > 1 else 'declared' if heads and targets else 'partial' if heads or targets else 'unknown',
                 'applies_to_requested_repo': None if not targets else targets == [str(repo)],
                 'findings': [], 'gates': [], 'coverage': [], 'tools': [], 'runs': [], 'cost': [], 'assessments': [], 'artifacts': [], 'runtime_integrations': [], 'runtime_transport': [], 'runtime_identity': [], 'runtime_identity_policy': [], 'runtime_webauthn': [], 'runtime_database_extensions': [], 'runtime_network_isolation': [], 'runtime_sinks': [], 'ponytail_debt': []}
        seen, debt_snapshots = set(), {}
        for artifact in docs:
            data, name = artifact['data'], artifact['name']
            artifact_record = {'path': artifact['path'], 'sha256': artifact['sha256'],
                               'source_provenance': source_metadata(data)}
            if isinstance(data, dict) and isinstance(data.get('source_provenance'), dict):
                artifact_record['upstream_provenance'] = projected_provenance(data['source_provenance'])
            if isinstance(data, dict) and isinstance(data.get('source_reports'), list):
                artifact_record['source_reports'] = project_source_reports(data['source_reports'])
            group['artifacts'].append(artifact_record)
            preparation_only = name in {'tools-plan.json', 'tools-install.json'}
            # helix-findings.json przeglądu bezpieczeństwa to te same zapisy co findings.json obok (bez obalonych),
            # w formacie Helixa: liczone raz. Projekt B: 454 zamiast 240 ustaleń.
            copy = name == 'helix-findings.json' and any(d['name'] == 'findings.json' for d in docs)
            for row in ([] if preparation_only or copy else finding_rows(data, name)):
                f = project_finding(row, artifact)
                if f is None: continue
                key = (f['id'], tuple(f['locations']), f['verdict'], f['verification_key'])
                if key not in seen: group['findings'].append(f); seen.add(key)
            cov = None if preparation_only else coverage_summary(data, name)
            if cov is not None: group['coverage'].append({'artifact': artifact['path'], 'summary': cov})
            if not isinstance(data, dict): continue
            # audit.json przeglądu tras (url, runs) to nie audyt projektu z rejestrem długu.
            if name in {'audit.json', 'quality.json', 'owner-current.json'} and not (name == 'audit.json' and 'runs' in data and 'url' in data):
                from helix_ponytail_debt import project_debt
                container = data.get('quality') if name == 'audit.json' else data
                raw_debt = container.get('ponytail_debt') if isinstance(container, dict) else None
                target, sha = identity(data)
                if name == 'quality.json' and (not target or not sha or not isinstance(data.get('provenance'), dict)):
                    gaps.append({'path': artifact['path'], 'reason': 'Rejestr długu quality.json nie ma tożsamości repo i rewizji; nie został przyjęty.'})
                else:
                    try:
                        debt = project_debt(raw_debt)
                    except (ValueError, TypeError, KeyError):
                        gaps.append({'path': artifact['path'], 'reason': 'Nieprawidłowy rejestr długu Ponytail; brak wiarygodnych liczników i wieku.'})
                    else:
                        # Only identical validated snapshots with the same declared
                        # repository/revision are coalesced; disagreements stay visible.
                        key = (target, sha, json.dumps(debt, sort_keys=True, ensure_ascii=False)) if target and sha else (artifact['path'],)
                        if key in debt_snapshots:
                            debt_snapshots[key]['artifacts'].append(artifact['path'])
                        else:
                            item = dict(debt, artifacts=[artifact['path']])
                            debt_snapshots[key] = item
                            group['ponytail_debt'].append(item)
                        if debt['status'] != 'COMPLETE':
                            gaps.append({'path': artifact['path'], 'reason': 'Dług Ponytail: ' + debt['status'] + '. Brak pełnego odczytu komentarzy nie potwierdza braku długu.'})
            if name in {'tools-plan.json', 'tools-install.json'}:
                try:
                    prepared_tools = tool_preparation_rows(data, name)
                except (ValueError, TypeError, AttributeError):
                    gaps.append({'path': artifact['path'], 'reason': 'Nieprawidłowy kontrakt przygotowania narzędzi; brak dowodu skanu.'})
                    continue
                for tool in prepared_tools:
                    group['tools'].append(dict(tool, artifact=artifact['path']))
                    gaps.append({'path': artifact['path'], 'reason': tool['tool'] + ': ' + tool['reason'] +
                                 ' Zastosowanie do tego repo pozostaje nieocenione.'})
                if not prepared_tools:
                    gaps.append({'path': artifact['path'], 'reason': 'Przygotowanie narzędzi: brak pozycji z dowodem wykonania; ' + clean(data.get('reason_code', 'unknown'))})
                group['coverage'].append(dict(artifact=artifact['path'], summary=dict(
                    status='NOT_RUN', kind='tool-preparation', tools=len(prepared_tools), applicability='NOT_ASSESSED')))
            if name=='runtime-report.json':
                from helix_runtime import validate_report, project_network_isolation
                from helix_runtime_transport import project_transport
                from helix_runtime_login import project_identity
                from helix_runtime_identity_policy_run import project_policy_execution
                from helix_runtime_webauthn_run import project_webauthn_execution
                from helix_runtime_sinks import project_sinks
                try:
                    validate_report(data)
                    transport, identity_summary = project_transport(data), project_identity(data)
                    identity_policy = project_policy_execution(data)
                    webauthn = project_webauthn_execution(data)
                    extensions = runtime_extensions_summary(data.get('database_fidelity'))
                    isolation = project_network_isolation(data)
                    sinks = project_sinks(data)
                except (ValueError,TypeError,KeyError) as error:
                    reason = ('Historyczny auth-flow PASS nie ma dowodu tożsamości sesji ani uprawnień. '
                              'Ten artefakt nie przyznaje punktów runtime; wymagany jest powiązany test jawnej polityki.'
                              if isinstance(error, ValueError) and str(error) == 'legacy_auth_claim_unverified' else
                              'Nieprawidłowy kontrakt runtime; integracje i pokrycie nie zostały przyjęte.')
                    gaps.append({'path':artifact['path'],'reason':reason})
                    continue
                summary=runtime_integrations_summary(data.get('integrations'))
                group['runtime_integrations'].append(dict(summary,artifact=artifact['path']))
                group['coverage'].append(dict(artifact=artifact['path'],summary={'status':summary['status'],'active_integrations':summary['active'],'tested_integrations':summary['tested']}))
                if summary['status']!='RECORDED':gaps.append({'path':artifact['path'],'reason':'Niepełne pokrycie integracji runtime: '+summary['status']+'. Pomiary kontroli nie potwierdzają pełnych przepływów biznesowych.'})
                if summary.get('failed_routes'):gaps.append({'path':artifact['path'],'reason':'FAIL tras integracji runtime: '+str(summary['failed_routes'])+'. Wykonanie testu nie oznacza poprawnego wyniku.'})
                for key, projection in (('runtime_transport', transport), ('runtime_identity', identity_summary)):
                    group[key].append(dict(projection, artifact=artifact['path']))
                    group['coverage'].append(dict(artifact=artifact['path'], summary={key: projection['status']}))
                    if projection['status'] in ('INCOMPLETE', 'NOT_RECORDED'):
                        gaps.append({'path': artifact['path'], 'reason':
                                     ('Transport runtime' if key == 'runtime_transport' else 'Fazy tożsamości runtime') +
                                     ': ' + projection['status'] + '. Osobny pomiar nie dowodzi sesji aplikacji ani uprawnień.'})
                group['runtime_identity_policy'].append(dict(identity_policy, artifact=artifact['path']))
                group['runtime_webauthn'].append(dict(webauthn, artifact=artifact['path']))
                group['runtime_database_extensions'].append(dict(extensions, artifact=artifact['path']))
                group['runtime_network_isolation'].append(dict(isolation, artifact=artifact['path']))
                group['runtime_sinks'].append(dict(sinks, artifact=artifact['path']))
                sink_gap = runtime_sinks_gap(sinks)
                if sink_gap: gaps.append({'path': artifact['path'], 'reason': sink_gap})
                isolation_gap = runtime_network_gap(isolation)
                if isolation_gap:
                    gaps.append({'path': artifact['path'], 'reason': isolation_gap})
                if extensions['status'] != 'READY':
                    gaps.append({'path': artifact['path'], 'reason': 'Rozszerzenia PostgreSQL: ' + extensions['status'] +
                                 '. Odczyt katalogu nie zastępuje dowodu instalacji ani wykonania migracji.'})
                webauthn_gap = runtime_webauthn_gap(webauthn)
                if webauthn_gap:
                    gaps.append({'path': artifact['path'], 'reason': webauthn_gap[1]})
                policy_gap = runtime_policy_gap(identity_policy)
                if policy_gap:
                    gaps.append({'path': artifact['path'], 'reason': policy_gap[1]})
                group['runs'].append(dict(status=clean(data.get('status','unknown')),measurement_status=clean(data.get('measurement_status','unknown')),artifact=artifact['path'],providers=[]))
                # Kontrole przebiegu (Lighthouse, e2e, axe, kopia, przegląd tras...) idą do bramek, żeby FAIL i SKIPPED były widoczne na górze.
                controls = data.get('controls') if isinstance(data.get('controls'), list) and data.get('controls') else [
                    dict(check, id=name) for part in data.get('parts') or [] if isinstance(part, dict)
                    for name, check in (part.get('checks') or {}).items() if isinstance(check, dict)]   # controls jest opcjonalne
                for control in controls:
                    if isinstance(control, dict) and control.get('status') != 'PASS':
                        group['gates'].append({'name': 'runtime ' + clean(control.get('id', '?')) + ' (' + clean(control.get('reason', ''), 160) + ')',
                                               'status': clean(control.get('status', 'unknown')), 'artifact': artifact['path'], 'counts': {}})
            if name == 'owner-current.json' and isinstance(data.get('assessment'), dict):
                assessment = data['assessment']
                group['assessments'].append({'artifact': artifact['path'], 'readiness': clean(assessment.get('readiness', 'unknown')),
                                            'counts': numeric_fields(assessment.get('counts'), ('not-run', 'N/A', 'executed')),
                                            'blockers': [clean(x) for x in assessment.get('blockers', []) if isinstance(x, str)] if isinstance(assessment.get('blockers'), list) else [],
                                            'pending_controls': len(data.get('gaps', [])) if isinstance(data.get('gaps'), list) else None})
            # Pakiet UX (skan urządzeń, sędzia zrzutów, eksplorator): wynik na górę raportu. Projekt B: raport go pomijał.
            if name == 'ux-report.json':
                cells = numeric_fields(data.get('counts'), ('pass', 'warn', 'fail'))
                judged = {}
                for issue in data.get('judge_issues') or []:
                    if isinstance(issue, dict): judged[clean(issue.get('severity', 'unknown'))] = judged.get(clean(issue.get('severity', 'unknown')), 0) + 1
                explored = [x for x in data.get('explore') or [] if isinstance(x, dict)]
                status = 'FAIL' if data.get('blocking') else 'PASS' if data.get('pass') else 'INCOMPLETE'
                group['gates'].append({'name': 'ux (%d urządzeń × %d stron; komórki %s; uwagi sędziego %s; eksplorator %d zadań, %d sprawdzonych; przebieg %s)' % (
                    len(data.get('targets') or []), len(data.get('pages') or []), md(json.dumps(cells)), md(json.dumps(judged, ensure_ascii=False)),
                    len(explored), sum(x.get('status') != 'not_checked' for x in explored), clean(data.get('run_status', 'unknown'))),
                    'status': status, 'artifact': artifact['path'], 'counts': {}})
            if name in {'gate.json', 'truth-gate.json'}:
                group['gates'].append({'name': clean(data.get('gate', name)), 'status': clean(data.get('status') or ('PASS' if data.get('pass') else 'FAIL')),
                                       'artifact': artifact['path'], 'counts': numeric_fields(data.get('counts'), ('new', 'baselined', 'waived', 'known', 'incomplete'))})
            if name in {'run.json', 'run-metadata.json', 'runtime.json', 'state.json', 'progress.json', 'advisory-tools.json'}:
                group['runs'].append({'status': clean(data.get('run_status', data.get('status', 'unknown'))), 'artifact': artifact['path'],
                                      'providers': [{'provider': clean(p.get('provider')), 'model': clean(p.get('model')), 'status': clean(p.get('status', 'unknown'))} for p in data.get('providers', []) if isinstance(p, dict)]})
                for tool in data.get('tools', []):
                    if not isinstance(tool, dict): continue
                    reason = clean(tool.get('error_category') or tool.get('error') or tool.get('reason'))
                    group['tools'].append({'tool': clean(tool.get('tool')), 'status': clean(tool.get('status')), 'duration_seconds': number(tool.get('duration')),
                                           'reason': reason, 'artifact': artifact['path']})
                    tool_gap = tool_execution_gap(tool.get('tool'), tool.get('status'), reason)
                    if tool_gap:
                        gaps.append({'path': artifact['path'], 'reason': tool_gap})
                usage = data.get('usage') if isinstance(data.get('usage'), dict) else {}
                group['cost'].append({'artifact': artifact['path'], 'budget': numeric_fields(data.get('budget'), ('seconds', 'calls')),
                                      'measured': cost_value(data.get('cost')) if data.get('cost') is not None else cost_value({'usd': usage.get('cost_usd')}),
                                      'elapsed_seconds': number(usage.get('elapsed_seconds', data.get('elapsed_seconds'))), 'provider_calls': len(data.get('provider_attempts', [])) if isinstance(data.get('provider_attempts'), list) else None,
                                      'plan': numeric_fields(data.get('plan'), ('batches', 'units', 'source_bytes', 'snapshot_bytes', 'min_calls', 'max_calls', 'calls_min', 'calls_max', 'hunter_prompt_bytes_min', 'min_hunter_calls', 'max_hunter_calls_with_ledger_retry'))})
            if name.startswith('model-call-') and data.get('kind') == 'model-call':
                from helix_usage import usage
                telemetry = usage({'usage': data.get('usage')})
                group['cost'].append(dict(artifact=artifact['path'], call_id=clean(data.get('call_id')),
                    provider=clean(data.get('provider')), model=clean(data.get('model')), status=clean(data.get('status')),
                    measured=cost_value({'usd': telemetry['cost_usd']}), usage=telemetry,
                    elapsed_seconds=number(data.get('elapsed_seconds')), provider_calls=1 if data.get('call_invoked') is True else None))
            if name in {'model-plan-size.json', 'plan.json', 'cost-plan.json'}:
                plan = numeric_fields(data, ('batches', 'units', 'planned', 'uncovered', 'snapshot_bytes', 'min_hunter_calls', 'max_hunter_calls_with_ledger_retry', 'source_bytes', 'expected_calls', 'max_calls', 'calls_min', 'calls_max', 'hunter_prompt_bytes_min'))
                if plan: group['cost'].append({'artifact': artifact['path'], 'plan': plan, 'measured': None})
        group['counts'] = {'severity': dict(Counter(f['severity'] for f in group['findings'])),
                           'verification': dict(Counter(f['verdict'] for f in group['findings'])),
                           'areas': dict(Counter(f['source_area'] for f in group['findings']))}
        if group['identity_status'] != 'declared': gaps.append({'path': directory, 'reason': 'Brak jednoznacznej rewizji źródła. Wynik nie poświadcza bieżącego kodu.'})
        if group['applies_to_requested_repo'] is False: gaps.append({'path': directory, 'reason': 'Dowód dotyczy innego repozytorium; pozostaje osobnym przebiegiem.'})
        groups.append(group)
    present = {'scan': any(g['findings'] for g in groups) or any(a['name'] in {'findings.json', 'review-deep.json', 'ui-deep.json', 'helix-findings.json'} for a in artifacts),
               'gate': any(g['gates'] for g in groups), 'coverage': any(g['coverage'] for g in groups),
               'verification': any(a['name'].startswith('verified-') or a['name'] in {'verification-all.json', 'verification.json'} for a in artifacts) or any(f['verdict'] in {'confirmed', 'rejected'} for g in groups for f in g['findings']),
               'cost': any(c.get('measured') is not None for g in groups for c in g['cost'])}
    for area, exists in present.items():
        if not exists: gaps.append({'path': '', 'reason': {'scan':'Brak wyniku skanu.', 'gate':'Brak wyniku bramki.', 'coverage':'Brak raportu pokrycia.', 'verification':'Brak niezależnej weryfikacji ustaleń.', 'cost':'Koszt API nieznany; plan i limit nie są pomiarem kosztu.'}[area]})
    generation_provenance = projected_provenance(generation_provenance)
    return {'schema_version': 1, 'helix_version': VERSION, 'target': str(repo), 'created_at': datetime.now(timezone.utc).isoformat(),
            'provenance': generation_provenance, 'generation_provenance': generation_provenance,
            'status': 'AGGREGATED' if artifacts else 'INCOMPLETE', 'artifact_count': len(artifacts), 'groups': groups, 'gaps': gaps,
            'evidence_available': present, 'meaning': 'Agregacja istniejących dowodów, bez nowego skanu i bez potwierdzenia produkcji. Werdykty pochodzą ze wskazanych artefaktów.'}


def evidence_markdown(report):
    lines = ['# Raport dla właściciela', '', f"Repozytorium: `{md(report['target'])}`.",
             f"Stan raportu: **{report['status']}**. Odczytano {report['artifact_count']} artefaktów; {len(report['groups'])} osobnych grup dowodów.",
             '', report['meaning'], '', provenance_line(report.get('generation_provenance')), '', '## Co wymaga uwagi', '']
    failures = [f"{g['name']}: {g['status']} ({g['artifact']})" for group in report['groups'] for g in group['gates'] if g['status'] != 'PASS']
    lines += ['- ' + md(f) for f in failures] or ['- Brak zgłoszonego FAIL/ERROR w dostarczonych bramkach. Nie oznacza to pełnego PASS audytu.']
    for group in report['groups']:
        if group['findings']:
            counts = group['counts']
            lines.append('- Ustalenia: ' + str(len(group['findings'])) + '; weryfikacja: ' + md(json.dumps(counts['verification'], ensure_ascii=False)) +
                         '; waga: ' + md(json.dumps(counts['severity'], ensure_ascii=False)) + f" `{md(group['directory'])}`")
    # Ta sama uwaga z wielu katalogów (np. każda trasa) raz, z liczbą miejsc.
    places = {}
    for gap in report['gaps']: places.setdefault(gap['reason'], []).append(gap['path'])
    for reason, paths in places.items():
        named = [p for p in paths if p]
        where = (f" `{md(named[0])}`" if len(named) == 1 else f" ({len(named)} miejsc, np. `{md(named[0])}`)" if named else '')
        lines.append('- ' + md(reason) + where)
    lines += ['', '## Wyniki według przebiegu', '']
    for group in report['groups']:
        lines += [f"### {md(group['directory'])}", '',
                  f"Rewizja: `{md(', '.join(group['source_shas']) or 'nieznana')}`; powiązanie: **{group['identity_status']}**.",
                  'Wyniki pozostają w tej grupie. Deklaracja rewizji w raporcie nie potwierdza zgodności aktualnego drzewa.', '']
        if group['gates']:
            lines += ['| Bramka | Wynik |', '|---|---|'] + [f"| {md(g['name'])} | {md(g['status'])} |" for g in group['gates']] + ['']
        counts = group['counts']
        lines += ['Potwierdzone wg artefaktów: ' + str(counts['verification'].get('confirmed', 0)) + '; kandydaci: ' + str(sum(counts['verification'].get(k, 0) for k in ('candidate', 'needs_validation'))) + '; odrzucone: ' + str(counts['verification'].get('rejected', 0)) + '.',
                  'Zakres: ' + ', '.join(f'{k} {counts["areas"].get(k, 0)}' for k in ('active', 'docs', 'legacy', 'tests/examples', 'unknown')) + '.', '']
        for summary in group.get('runtime_integrations',[]):lines += integration_markdown(summary)
        for summary in group.get('runtime_transport', []):lines += runtime_boundary_markdown(transport=summary)
        for summary in group.get('runtime_identity', []):lines += runtime_boundary_markdown(identity=summary)
        for summary in group.get('runtime_identity_policy', []):lines += runtime_policy_markdown(summary)
        for summary in group.get('runtime_webauthn', []):lines += runtime_webauthn_markdown(summary)
        for summary in group.get('runtime_database_extensions', []):lines += runtime_extensions_markdown(summary)
        for summary in group.get('runtime_network_isolation', []):lines += runtime_network_markdown(summary)
        for summary in group.get('runtime_sinks', []):lines += runtime_sinks_markdown(summary)
        for summary in group.get('ponytail_debt', []):lines += ponytail_debt_markdown(summary)
        if group['tools']:
            lines += ['| Narzędzie | Stan | Czas s | Przyczyna |', '|---|---|---:|---|']
            lines += [f"| {md(t['tool'])} | {md(t['status'])} | {md(t['duration_seconds'])} | {md(t['reason'])} |" for t in group['tools']]
            lines += ['']
        for cov in group['coverage']:
            summary = cov['summary']
            lines.append('Pokrycie: ' + md(json.dumps(summary, ensure_ascii=False),) + f" (`{md(cov['artifact'])}`).")
        for assessment in group.get('assessments', []):
            lines.append('Ocena wykonania wg artefaktu: **' + md(assessment['readiness']) + '**; kontrole: ' + md(json.dumps(assessment['counts'], ensure_ascii=False)) + '; luki: ' + md(assessment['pending_controls']) + '.')
        for run in group['runs']:
            lines.append('Przebieg: **' + md(run['status']) + '**; providers: ' + md(', '.join(f"{p['provider']}/{p['model']} ({p['status']})" for p in run['providers']) or 'brak zapisu') + '.')
        for cost in group['cost']:
            if cost.get('call_id'):
                from helix_usage import describe
                lines.append('Wywołanie ' + md(cost['call_id']) + ' ' + md(cost['provider']) + '/' + md(cost['model']) + ': ' + describe(cost) + '.')
            lines.append('Koszt API: ' + (md(json.dumps(cost['measured'], ensure_ascii=False)) if cost.get('measured') is not None else '**nieznany**') + '; wywołania: ' + md(cost.get('provider_calls') if cost.get('provider_calls') is not None else 'nieznane') + '.')
            if cost.get('plan'): lines.append('Plan, nie pomiar: ' + md(json.dumps(cost['plan'], ensure_ascii=False)) + '.')
        active = [f for f in group['findings'] if f['source_area'] == 'active' and f['verdict'] != 'rejected']
        active.sort(key=lambda f: (f['verdict'] != 'confirmed', LEVELS.index(f['severity']), f['id']))
        if active:
            lines += ['', 'Priorytety aktywnego kodu (szczegóły wszystkich miejsc są w JSON):', '', '| Sygnał | Waga | Weryfikacja | Miejsce |', '|---|---|---|---|']
            for f in active[:12]:
                lines.append(f"| {md(f['id'] + ': ' + f['title'])} | {f['severity']} | {f['verdict']} | {md(', '.join(f['locations'][:3]) or 'niepodane')} |")
            if len(active) > 12: lines.append(f"\nPokazano 12 z {len(active)} aktywnych ustaleń. Pełna lista jest w towarzyszącym JSON.")
        lines += ['', 'Artefakty:']
        for artifact in group['artifacts']:
            source = artifact.get('source_provenance', {})
            lines.append('- `' + md(artifact['path']) + '`; SHA-256 `' + artifact['sha256'] + '`; źródłowy Helix ' + md(source.get('helix_version') or 'unknown') + '; źródłowy target HEAD ' + md(source.get('target_head') or 'unknown') + '.')
        lines += ['']
    lines += ['## Granice oceny', '', 'Liczba heurystyk nie jest pomiarem jakości ani bezpieczeństwa. Nieznane pokrycie, koszt i źródło pozostają jawnymi lukami. Nie uruchomiono aplikacji ani modeli, nie zaakceptowano baseline ani wyjątków.', '']
    return '\n'.join(lines)


def dispatch(args):
    out = Path(args.out).expanduser().absolute()
    if out.suffix == '.json': out = out.with_suffix('.md')
    repo = system_path(args.repo)
    if getattr(args, 'state_dir', None) and out.resolve().is_relative_to(repo.resolve()):
        raise ValueError('read-only owner-report: --out musi znajdować się poza repo')
    roots = getattr(args, 'evidence', None) or ([Path(args.state_dir) / 'evidence', Path(args.state_dir) / 'runs'] if getattr(args, 'state_dir', None) else [repo / 'helix-evidence'])
    json_out = out.with_suffix('.json')
    if out.is_symlink() or json_out.is_symlink(): raise ValueError('owner-report: output nie może być dowiązaniem')
    report = aggregate(repo, roots, excluded=(out, json_out), generation_provenance=generation_metadata(repo))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(markdown(report), encoding='utf-8')
    json_out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f"{report['status']}: {out}")
    return 0 if report['artifact_count'] else 2


def weighted(rows, weights=None, findings=()):
    weights = weights or {}
    numerator = denominator = 0
    blockers = []
    counts = {'not-run': 0, 'N/A': 0, 'executed': 0}
    for row in rows:
        key = row['id']
        if any(k in weights for k in ('parts','areas','controls')):
            weight = weights.get('controls',{}).get(key,1)
            for axis in ('part','area'):
                factor = weights.get(axis+'s',{}).get(row.get(axis),1)
                if isinstance(factor,bool) or not isinstance(factor,(int,float)) or not math.isfinite(factor) or factor <= 0:
                    raise ValueError('niepoprawna waga: ' + axis)
                weight *= factor
        else:
            weight = weights.get(key, 1)
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight <= 0:
            raise ValueError('waga musi być dodatnia i skończona: ' + key)
        status = row.get('status', 'not-run')
        if status == 'N/A':
            if not str(row.get('reason', '')).strip():
                raise ValueError('N/A wymaga powodu: ' + key)
            counts['N/A'] += 1
            continue
        denominator += weight
        # An assertion or a static source reference is never execution proof.
        if status not in ('PASS', 'FAIL') or row.get('execution_verified') is not True:
            counts['not-run'] += 1
            blockers.append(key + ': not-run')
            continue
        counts['executed'] += 1
        score = row.get('score', 0)
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
            raise ValueError('wynik poza zakresem 0..100: ' + key)
        numerator += weight * score if status == 'PASS' else 0
        if status == 'FAIL': blockers.append(key + ': FAIL')
    for f in findings:
        if f.get('severity', '').lower() in ('high', 'critical'):
            blockers.append(str(f.get('id', 'finding')) + ': ' + f['severity'])
    return dict(score=round(numerator / denominator, 2) if denominator else 0,
                advisory=True, blockers=blockers, counts=counts,
                readiness='BLOCKED' if blockers or not rows else 'N/A' if not denominator else 'PASS')


def build(data, validation, continuity, details, root=None):
    from helix_lenses import deduplicate
    findings = deduplicate(data.get('findings', []))
    ranking = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings.sort(key=lambda f: (ranking.get(f['severity'].lower(), 5), f['file'], f['line']))
    gaps = []
    assignments = data.get('gap_assignments', {})
    for f in findings:
        a = assignments.get(f['id'], {})
        gaps.append(dict(id=f['id'], file=f['file'], line=f['line'], severity=f['severity'],
                         confidence=f['confidence'], why=f['why'], fix=f['fix'],
                         source_area=source_area(f['file']), locations=f.get('locations', [f"{f['file']}:{f['line']}"]),
                         owner=a.get('owner') or 'do przypisania', due_date=a.get('due_date') or 'do przypisania',
                         effort=a.get('effort') or 'do oszacowania', dependencies=a.get('dependencies', []),
                         closure=a.get('closure') or f['fix']))
    # Generic execution imports must be validated by their producer. No arbitrary scores imported here.
    for pending in data.get('pending_controls', []):
        a = assignments.get(pending['id'], {})
        gaps.append(dict(id=pending['id'], file=None, line=None, severity='unknown', confidence='unknown',
                         why=pending['why'], fix=pending['fix'], evidence=pending.get('evidence', []),
                         source_area='unknown',
                         owner=a.get('owner') or 'do przypisania', due_date=a.get('due_date') or 'do przypisania',
                         effort=a.get('effort') or 'do oszacowania', dependencies=a.get('dependencies', []),
                         closure=a.get('closure') or pending['closure']))
    areas = data.get('assessment', {}).get('controls', [])
    from helix_contracts import executed
    current_sha = None
    if root is not None:
        from helix_release import git
        try: current_sha = git(root, 'rev-parse', 'HEAD')
        except ValueError: pass
    safe = [dict(r, execution_verified=bool(current_sha and executed(root, r.get('run')) and data.get('sha') == current_sha and r['run'].get('sha') == current_sha)) for r in areas]
    score = weighted(safe, data.get('assessment', {}).get('weights', {}), findings)
    for name, result in (('validation', validation), ('continuity', continuity)):
        status = result.get('status')
        if status and status not in ('PASS', 'NOT_CONFIGURED'):
            score['blockers'].append(name + ': ' + clean(status))
            score['readiness'] = 'BLOCKED'
    summary = {'findings': len(findings), 'by_area': dict(Counter(source_area(f['file']) for f in findings)),
               'confirmed': sum(f.get('verification_status') == 'confirmed' for f in findings),
               'candidates': sum(f.get('verification_status') not in ('confirmed', 'rejected') for f in findings)}
    generated = generation_metadata(root) if root is not None else projected_provenance(None)
    return dict(schema_version=1, generated_at=datetime.now(timezone.utc).isoformat(), target=str(system_path(root)) if root is not None else None,
                provenance=generated, generation_provenance=generated, source_provenance=source_metadata(data),
                sha=data.get('sha', 'niepodane'), helix_version=data.get('helix_version', 'niepodane'), state=data.get('owner_report', {}).get('state'), controls=safe, validation=validation, continuity=continuity,
                lenses=data.get('lenses', {}), parts=data.get('parts', []), decisions=data.get('owner_report', {}).get('decisions', []),
                coverage=data.get('coverage', {}), assessment=score, gaps=gaps,
                findings=findings, summary=summary, full_json=str(details), obsolete=data.get('owner_report', {}).get('obsolete', []))


def contract_markdown(report):
    a = report['assessment']
    lines = ['# Raport właściciela', '', 'Źródło kontraktu: SHA ' + report['sha'] + '; Helix ' + report['helix_version'] + '; ' + report['generated_at'],
             provenance_line(report.get('generation_provenance')),
             'Walidacja: ' + report['validation']['status'] + '; gotowość: ' + a['readiness'],
             'Kontrole: wykonane ' + str(a['counts']['executed']) + '; niewykonane ' + str(a['counts']['not-run']) + '; N/A ' + str(a['counts']['N/A']) + '.',
             'Pełne dane i plan luk: [' + report['full_json'] + '](' + report['full_json'] + ')', '',
             'Problemy: ' + str(len(report['gaps'])) + ' (maks. 5 poniżej).']
    if a['counts']['executed']:
        lines += ['Pomocnicza miara wykonanych i niewykonanych kontroli: ' + str(a['score']) + '/100. Niewykonane pozostają w mianowniku; blokery decydują o gotowości.']
    else:
        lines += ['Brak pomiaru wykonania. Statyczne sygnały pozostają kandydatami, nie oceną jakości.']
    summary = report.get('summary', {})
    if report.get('runtime_integrations'):lines += integration_markdown(report['runtime_integrations'])
    lines += runtime_boundary_markdown(report.get('runtime_transport'), report.get('runtime_identity'))
    lines += runtime_policy_markdown(report.get('runtime_identity_policy'))
    lines += runtime_webauthn_markdown(report.get('runtime_webauthn'))
    lines += runtime_extensions_markdown(report.get('runtime_database_extensions'))
    lines += runtime_network_markdown(report.get('runtime_network_isolation'))
    lines += runtime_sinks_markdown(report.get('runtime_sinks'))
    lines += ponytail_debt_markdown(report.get('ponytail_debt'))
    lines += ['Zakres sygnałów: ' + ', '.join(k + ' ' + str(summary.get('by_area', {}).get(k, 0)) for k in ('active', 'docs', 'legacy', 'tests/examples', 'unknown')) + '.']
    priority = sorted(report['gaps'], key=lambda g: g.get('source_area', source_area(g.get('file'))) != 'active')
    for g in priority[:5]:
        lines.append(f"- ASSUMPTION {g['severity']}/{g['confidence']} [{g.get('source_area', 'unknown')}] {str(g['file']) + ':' + str(g['line']) if g['file'] else 'brak dowodu źródłowego'}: {g['why']} Poprawka: {g['fix']} Owner: {g['owner']}; termin: {g['due_date']}; nakład: {g['effort']}.")
    lines += ['', 'Decyzje: ' + str(len(report['decisions']))]
    lines += ['- ' + str(v) for v in report['decisions'][:5]]
    coverage = report['coverage']
    lines += ['', 'Odczyt: ' + str(coverage.get('files_read', 'unknown')) + '/' + str(coverage.get('files_total', 'unknown')) + ' plików; stan: ' + str(coverage.get('status', 'unknown'))]
    lines += ['Soczewki: ' + str(len(report['lenses'])) + '; części: ' + str(len(report['parts'])) + '; szczegóły w JSON.']
    lines += ['', 'Dryf i ciągłość: ' + report['continuity'].get('status', 'unknown'),
              'Pokrycie czytania: szczegóły i pominięcia w JSON; brak danych nie potwierdza odczytu.',
              'Nieaktualne raporty (Obsolete): ' + str(len(report['obsolete'])) + '; lista w JSON.',
              'Statyczne sygnały nie potwierdzają wykonania. N/A wymaga jawnego uzasadnienia.']
    return '\n'.join(lines) + '\n'


def audit_report(repo, out, audit, sources):
    """Reuse lens findings and maturity controls, preserving full details in JSON."""
    from helix_lenses import report as lens_report
    from helix_continuity import Continuity
    from helix_contracts import VERSION
    import json
    lenses = lens_report(repo, quality_snapshot=audit['quality'])
    enabled = any(Continuity(repo).path('agent-policy.' + ext).exists() for ext in ('json','yaml'))
    continuity = Continuity(repo).report() if enabled else {'status': 'NOT_CONFIGURED'}
    controls, pending = [], []
    for area, result in audit['maturity']['areas'].items():
        for requirement in result['requirements']:
            controls.append(dict(id=area + ':' + requirement['id'], area=area, part='.', status='not-run', score=0))
            if not requirement['satisfied'] or requirement['runtime']:
                pending.append(dict(id=area + ':' + requirement['id'], why=requirement['description'],
                    fix='; '.join(requirement['remediation']), closure=requirement['threshold'], evidence=requirement.get('evidence', [])))
    for c in audit['quality']['domains']['checks']:
        controls.append(dict(id=c['id'], status=c['status'], reason=c['reason'], score=0))
        if c['status'] != 'N/A':
            pending.append(dict(id=c['id'], why=c['reason'], fix=c['criterion'], closure=c['criterion'], evidence=c['evidence']))
    runtime_summary=None
    if 'runtime_coverage' in audit['maturity']:
        runtime_summary=runtime_integrations_summary(audit['maturity'].get('runtime_integrations'))
        for row in runtime_summary['entries']:
            failed=[route['method']+' '+route['route'] for route in row['tested_routes'] if route['status']=='FAIL']
            if row['area']=='active' and (row['coverage']!='tested' or failed):
                pending.append(dict(id='runtime-integration:'+row['id'],why=row['provider']+': '+'; '.join(row['untested_because']+(['FAIL '+', '.join(failed)] if failed else [])),
                                    fix='Wykonać właściwy adapter i wskazane trasy na danych syntetycznych.',closure='Receipt powiązany z planem i przebiegiem oraz dowód użycia integracji w trasie.',
                                    evidence=[p['path']+':'+str(p['line']) for p in row['locations']]))
        if runtime_summary['status']=='NOT_RECORDED':
            pending.append(dict(id='runtime-integrations:not-recorded',why=runtime_summary['reason'],fix='Wykonać runtime z inwentarzem integracji.',closure='Jawny inwentarz i pokrycie tras.',evidence=[]))
    runtime_boundaries = {}
    sinks = audit['maturity'].get('runtime_sinks')
    if sinks is not None:
        runtime_boundaries['runtime_sinks'] = sinks
        gap = runtime_sinks_gap(sinks)
        if gap:
            evidence = sorted({entry['path'] + ':' + str(entry['line']) for part in sinks['parts']
                               for declaration in part['providers'] for entry in declaration['evidence']})
            pending.append(dict(id='runtime_sinks:' + sinks['execution_status'].lower(), why=gap,
                                fix='Wykonać obsługiwane trasy na danych syntetycznych i powiązać ich dowody z obserwacjami skrzynki.',
                                closure='Dowód właściwej trasy i lokalnego użycia integracji; bez wysyłki do prawdziwych odbiorców.',
                                evidence=evidence))
    isolation = audit['maturity'].get('runtime_network_isolation')
    if isolation is not None:
        runtime_boundaries['runtime_network_isolation'] = isolation
        gap = runtime_network_gap(isolation)
        if gap:
            pending.append(dict(id='runtime_network_isolation:' + isolation['status'].lower(), why=gap,
                                fix='Uruchomić obsługiwany izolowany backend i zachować wyniki dopuszczenia procesów.',
                                closure='Dowód OS dla procesów projektu i własnego serwera bazy; osobno wyniki kontroli aplikacji.',
                                evidence=[]))
    if 'database_fidelity' in audit['maturity']:
        extensions = runtime_extensions_summary(audit['maturity']['database_fidelity'])
        runtime_boundaries['runtime_database_extensions'] = extensions
        if extensions['status'] != 'READY':
            locations = {place['path'] + ':' + str(place['line']) for row in extensions['checks']
                         for place in row['declarations'] + row['gaps']}
            locations.update(row['log'] for row in extensions['checks'] if row['log'])
            pending.append(dict(id='runtime_database_extensions:' + extensions['status'].lower(),
                                why='Rozszerzenia PostgreSQL: ' + extensions['status'],
                                fix='Wyjaśnić wymagania i braki katalogu, następnie ponowić właściwy preflight.',
                                closure='Odczyt katalogu dla każdej własnej bazy; osobny dowód instalacji i migracji.',
                                evidence=sorted(locations)))
    for key, label in (('runtime_transport', 'Transport runtime'), ('runtime_identity', 'Fazy tożsamości runtime')):
        projection = audit['maturity'].get(key)
        if projection is None: continue
        runtime_boundaries[key] = projection
        if projection['status'] in ('INCOMPLETE', 'NOT_RECORDED'):
            locations = sorted({str(gap['path']) + ':' + str(gap['line'])
                                for part in projection.get('parts', []) for gap in part.get('gaps', []) + part.get('requirements', [])
                                if isinstance(gap, dict) and gap.get('path') and type(gap.get('line')) is int})
            pending.append(dict(id=key + ':' + projection['status'].lower(), why=label + ': ' + projection['status'],
                                fix='Wykonać brakujące fazy i zachować powiązane dowody per część i tożsamość.',
                                closure='Osobne potwierdzenie transportu, sesji i uprawnień; formularz nie zastępuje tych testów.',
                                evidence=locations))
    webauthn = audit['maturity'].get('runtime_webauthn_execution', audit['maturity'].get('runtime_webauthn'))
    if webauthn is not None:
        runtime_boundaries['runtime_webauthn'] = webauthn
        webauthn_gap = runtime_webauthn_gap(webauthn)
        if webauthn_gap:
            declarations = webauthn['unscoped_declarations'] + [declaration for part in webauthn['parts'] for declaration in part['declarations']]
            pending.append(dict(id='runtime_webauthn:' + webauthn_gap[0], why=webauthn_gap[1],
                                fix='Uzupełnić jawny przebieg i zachować dowód rejestracji oraz logowania kluczem.',
                                closure='Osobne wykonanie ceremonii, akceptacji serwera i sesji właściwej tożsamości.',
                                evidence=sorted({str(place['path']) + ':' + str(place['line'])
                                    for declaration in declarations for place in declaration['evidence']} |
                                    {part['config_pointer'] for part in webauthn['parts'] if part.get('config_pointer')})))
    identity_policy = audit['maturity'].get('runtime_identity_policy_execution')
    if identity_policy is not None:
        runtime_boundaries['runtime_identity_policy'] = identity_policy
        policy_gap = runtime_policy_gap(identity_policy)
        if policy_gap:
            pending.append(dict(id='runtime_identity_policy:' + policy_gap[0], why=policy_gap[1],
                                fix='Uzupełnić jawne oczekiwania i wykonać zaplanowane przypadki dla wskazanych tożsamości.',
                                closure='Powiązany z planem i próbą wynik każdej wymaganej komórki oraz dowód sesji.',
                                evidence=[part['config_pointer'] for part in identity_policy['parts'] if part.get('policy_hash') is not None]))
    from helix_config import load
    cfg = load(repo)
    sha = audit['maturity'].get('sha', 'niepodane')
    # Actual SHA from the existing read-only repository helper.
    from helix_release import git
    try: sha = git(repo, 'rev-parse', 'HEAD')
    except ValueError: pass
    policy = cfg.get('owner_report', {})
    selected = policy.get('profiles', {}).get(audit['scope']['profile'], policy)
    data = dict(helix_version=VERSION, sha=sha, provenance=audit.get('provenance'), findings=lenses['findings'] + audit['quality']['findings'],
        pending_controls=pending, coverage=audit['source_coverage'],
        assessment=dict(controls=controls, weights=selected.get('weights',{})),
        gap_assignments=policy.get('gap_assignments',{}),
        owner_report=dict(state='proposal', decisions=lenses.get('decisions',[])))
    result = build(data, dict(status='INCOMPLETE'), continuity, 'owner-current.json', repo)
    from helix_ponytail_debt import project_debt
    result['target'] = str(system_path(repo))
    result['ponytail_debt'] = project_debt(audit['quality'].get('ponytail_debt'))
    if runtime_summary is not None:result['runtime_integrations']=runtime_summary
    result.update(runtime_boundaries)
    result['source_reports'] = [{'kind': kind, 'provenance': projected_provenance(value.get('provenance'))}
                                for kind, value in (('audit', audit), ('review', lenses))]
    result['source_reports'].extend(project_source_reports(audit.get('source_reports')))
    result['lenses'] = lenses['lenses']
    result['domains'] = audit['quality']['domains']
    result['parts'] = lenses.get('senior_pipeline', {}).get('parts', [])
    from helix_requirements import reject_secrets
    reject_secrets(result)
    from helix_new import dump
    dump(out / 'owner-current.json', result)
    (out / 'owner-current.md').write_text(markdown(result))


def markdown(report):
    """Render both evidence aggregation and validated execution contracts."""
    if 'groups' in report:
        return evidence_markdown(report)
    return contract_markdown(report)
