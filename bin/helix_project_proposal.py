"""External proposals; model pings only with an explicit refresh callback."""
import copy
import hashlib
import json
from pathlib import Path

from helix_paths import within
from helix_audit_context import safe_read, system_path

ARTIFACTS = ('helix.proposed.json', 'project-proposal.json', 'provider-plan.json',
             'NEW-REPORT.md', 'environment.json', 'environment.md', 'deep-plan')


def no_links(path):
    return not any(p.is_symlink() for p in (path, *path.parents))


def preflight(repo, out, write=False, state_dir=None):
    repo, out = system_path(repo), system_path(out)
    if within(out, repo) or within(repo, out):
        raise ValueError('proposal wymaga rozłącznego zewnętrznego katalogu wyników')
    if not no_links(out) or not no_links(repo):
        raise ValueError('proposal nie odczytuje ani nie zapisuje przez dowiązania')
    if repo.exists() and not repo.is_dir():
        raise ValueError('proposal wymaga katalogu projektu')
    if out.exists() and not out.is_dir():
        raise ValueError('proposal wymaga katalogu wyników')
    conflicts = [name for name in ARTIFACTS if (out / name).exists() or (out / name).is_symlink()]
    if conflicts:
        raise ValueError('existing artifacts: proposal nie nadpisuje istniejących wyników: ' + ', '.join(conflicts))
    if write and ((repo / 'helix.json').exists() or (repo / 'helix.json').is_symlink()):
        raise ValueError('--write nie nadpisuje istniejącego helix.json')
    if state_dir is not None:
        state = system_path(state_dir)
        if within(state, repo) or within(repo, state) or not no_links(state):
            raise ValueError('state-dir musi być rozłączny z repo celu, bez dowiązań')


def json_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n')


def text_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        stream.write(text)


def availability(path):
    from helix_provider_plan import FAMILIES, model_available
    from helix_packs import redact
    if not path:
        return {}, dict(status='missing', source=None, sha256=None, models=[])
    path = system_path(Path(path).expanduser())
    try:
        text = safe_read(path, errors='strict')
        data = json.loads(text)
        if not isinstance(data, dict) or not isinstance(data.get('models'), list):
            raise ValueError('invalid provider cache')
        rows = []
        for row in data['models']:
            if not isinstance(row, dict) or not isinstance(row.get('provider'), str) or row['provider'] not in FAMILIES:
                continue
            if row.get('model') is not None and not isinstance(row.get('model'), str):
                continue
            item = {key: row.get(key) for key in ('provider', 'model', 'family', 'status', 'method', 'checked_at')
                    if row.get(key) is None or isinstance(row.get(key), str)}
            item['fresh_available'] = model_available(data, row['provider'], row.get('model'))
            if isinstance(row.get('reason'), str):
                item['reason'] = redact(row['reason'])
            rows.append(item)
        clean = {'models': rows}
        status = 'recorded_fresh' if any(r['fresh_available'] for r in rows) else 'recorded_unavailable_or_stale'
        return clean, dict(status=status, source=str(path), sha256=hashlib.sha256(text.encode()).hexdigest(), models=rows)
    except FileNotFoundError:
        return {}, dict(status='missing', source=str(path), sha256=None, models=[])
    except (OSError, ValueError, UnicodeError):
        return {}, dict(status='invalid_or_unreadable', source=str(path), sha256=None, models=[])


def validate_refresh(refresh_providers=False, provider_refresh=None, jobs=3, offline=False):
    if isinstance(jobs, bool) or not isinstance(jobs, int) or jobs < 1:
        raise ValueError('--jobs wymaga dodatniej liczby całkowitej')
    if refresh_providers and offline:
        raise ValueError('--offline nie pozwala na --refresh-providers')
    if refresh_providers and provider_refresh is None:
        raise ValueError('--refresh-providers wymaga wykonawcy rzeczywistych sond')


def prepare_refresh(repo, out, *, state_dir=None, provider_cache=None, refresh_providers=False,
                    provider_refresh=None, jobs=3, offline=False):
    """Only a current callback receipt counts as this command's model execution."""
    from helix_config import load
    from helix_provider_plan import FAMILIES
    validate_refresh(refresh_providers, provider_refresh, jobs, offline)
    receipt = dict(requested=bool(refresh_providers), status='not_requested',
                   availability_probe_calls=0, source_review_calls=0, models=[])
    if not refresh_providers:
        return receipt
    repo, out = system_path(repo), system_path(out)
    state = system_path(state_dir) if state_dir else out / 'state'
    cache = system_path(provider_cache) if provider_cache else state / 'provider-availability.json'
    if within(cache, repo) or within(repo, cache) or not no_links(cache):
        raise ValueError('--refresh-providers wymaga cache poza repo celu, bez dowiązań')
    # Callback receives raw explicit choices, never inferred [None] defaults.
    result = provider_refresh(config=load(repo), cache_path=cache, jobs=jobs, offline=offline)
    if not isinstance(result, dict) or not isinstance(result.get('models'), list):
        raise ValueError('provider refresh nie zwrócił poprawnego potwierdzenia wykonania')
    for row in result['models']:
        if not isinstance(row, dict) or row.get('call_invoked') is not True:
            continue
        provider, model = row.get('provider'), row.get('model')
        if not isinstance(provider, str) or provider not in FAMILIES or (model is not None and not isinstance(model, str)):
            continue
        receipt['models'].append(dict(provider=provider, model=model, status='recorded', role='availability_probe',
                                      family=row.get('family') if isinstance(row.get('family'), str) else None))
    receipt.update(status='complete' if result.get('status') == 'complete' else 'incomplete',
                   availability_probe_calls=len(receipt['models']))
    return receipt


def local_database(environment, target):
    """An installed server binary is not evidence of the running database."""
    component = next((row for row in environment['components'] if row['name'] == target['engine']), {})
    local = copy.deepcopy(component.get('local', {'status': 'not_probed', 'version': None}))
    version = local.get('version')
    try: major = int(version.split('.')[0]) if version else None
    except ValueError: major = None
    local.update(major=major, compatible=(major == target['major'] if major is not None and not target['conflict'] else None),
                 scope='server_binary_not_running_server')
    return local


def schedule(state_dir, repo, jobs=3):
    """Read only the exact COMPLETE cursor and its exact receipt, never old sources."""
    from helix_security_deep import digest
    cursor = Path(state_dir) / 'security-audit' / 'completed' / digest(str(repo)) / 'last-complete.json'
    history = dict(status='missing', head=None, source=str(cursor))
    try:
        data = json.loads(safe_read(cursor, errors='strict'))
        if not isinstance(data, dict) or data.get('target') != str(repo) or data.get('run_status') != 'complete':
            raise ValueError('invalid COMPLETE cursor')
        run = system_path(Path(data['run']))
        if within(run, repo) or within(repo, run): raise ValueError('invalid COMPLETE source')
        meta = json.loads(safe_read(run / 'run-metadata.json', errors='strict'))
        head = data.get('head')
        if not isinstance(head, str) or len(head) not in (40, 64) or any(c not in '0123456789abcdef' for c in head):
            raise ValueError('invalid COMPLETE revision')
        if not isinstance(meta, dict) or not isinstance(meta.get('source_ref'), dict) or meta.get('run_status') != 'complete' or meta['source_ref'].get('head') != head:
            raise ValueError('missing COMPLETE evidence')
        history.update(status='recorded_complete', head=head)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, KeyError):
        history['status'] = 'invalid_or_unreadable'
    condition = 'wcześniejszy pełny COMPLETE; przy braku najpierw full albo jawne --since REF'
    rows = [dict(name='full-night', mode='full', scope='pełny projekt', budget_seconds=None, budget='bez limitu czasu i wywołań', requires='świeże sondy modeli; niezależne role; zakończenie COMPLETE'),
            dict(name='daily', mode='daily', scope='zmiany od ostatniego COMPLETE', budget_seconds=None, budget='bez limitu czasu i wywołań', requires=condition),
            dict(name='release', mode='release', scope='zmiany od COMPLETE i kontekst ryzyka', budget_seconds=1800, budget='30 min', requires=condition + '; wynik niepełny blokuje release')]
    for row in rows:
        row['history_status'] = history['status']
        row['invocation'] = ['security', 'deep', '--mode', row['mode'], '--jobs', str(jobs)]
        if row['budget_seconds']: row['invocation'] += ['--budget', 'time=30m']
    return rows, history


def _source_context(sources, parts, integrations, explicit):
    """Resolve in-memory source scopes once for all proposed runtime plans."""
    from helix_runtime_integrations import inventory, _area, _path
    if sources is None:return None
    if not isinstance(sources,dict):raise ValueError('proposal: sources must be a source snapshot')
    context={'parts_basis':'not_recorded','gaps':[]}
    if parts is None:
        # These are source scopes, not inferred start/build commands or proof that
        # a manifest is an independently runnable service.
        manifests = {'package.json', 'pyproject.toml', 'requirements.txt', 'Cargo.toml',
                     'go.mod', 'composer.json', 'pom.xml', 'build.gradle'}
        roots = {Path(path).parent.as_posix() for path in sources
                 if isinstance(path, str) and _path(path) == path and _area(path) == 'active' and Path(path).name in manifests}
        context['parts_basis'] = 'manifest_source_scopes'
        if not roots:
            roots = {'.'} if any(isinstance(path, str) and _path(path) == path and _area(path) == 'active' and
                                not Path(path).name.startswith('.env') for path in sources) else set()
            context['parts_basis'] = 'repository_source_scope_assumption'
            context['gaps'].append('Brak aktywnych manifestów: zakres źródeł nie potwierdza granic uruchamianych aplikacji.')
        parts = [{'path': path} for path in sorted(roots)]
    else:
        context['parts_basis'] = 'provided_source_scopes'
    if integrations is None:
        integrations = inventory(sources, parts, explicit)
    context.update(parts=parts,integrations=integrations)
    return context


def propose_transport(sources, parts, integrations, explicit, config, source_coverage=None, *, _context=None):
    """Reuse a supplied source snapshot; never discover or execute an application."""
    from helix_runtime_transport import transport_plan
    result = dict(status='NOT_RECORDED', observed=None, proposed=None, proposal_applied=False,
                  parts_basis='not_recorded', source_coverage_status='not_recorded', gaps=[],
                  execution='not_run')
    if sources is None:
        result['gaps'].append('Nie przekazano odczytanych źródeł; potrzeby HTTPS nie zostały sprawdzone.')
        return result
    if not isinstance(sources, dict):
        raise ValueError('proposal: sources must be a source snapshot')
    coverage_status = source_coverage.get('status') if isinstance(source_coverage, dict) else None
    result['source_coverage_status'] = coverage_status if isinstance(coverage_status, str) else 'not_recorded'
    if coverage_status != 'COMPLETE':
        result['gaps'].append('Pełność odczytu źródeł transportu nie jest potwierdzona; zobacz coverage.json.')
    context = _context if _context is not None else _source_context(sources,parts,integrations,explicit)
    parts,integrations=context['parts'],context['integrations']
    result['parts_basis']=context['parts_basis'];result['gaps'].extend(context['gaps'])
    observed = transport_plan(sources, parts, integrations, explicit)
    settings = explicit.get('runtime', {}).get('https', {})
    if any(part['https_needed'] for part in observed['parts']) and 'enabled' not in settings:
        config.setdefault('runtime', {}).setdefault('https', {})['enabled'] = True
        result['proposal_applied'] = True
    proposed = transport_plan(sources, parts, integrations, config) if result['proposal_applied'] else copy.deepcopy(observed)
    result.update(observed=observed, proposed=proposed,
                  status='INCOMPLETE' if result['gaps'] or proposed['status'] == 'INCOMPLETE' else proposed['status'])
    return result


def propose_webauthn(sources, context, transport, explicit, config, source_coverage=None):
    """Only plan from the shared snapshot; never fill in a ceremony contract."""
    result=dict(status='NOT_RECORDED',observed=None,proposed=None,projection=None,
                proposal_applied=False,execution='not_run',gaps=[])
    if sources is None or context is None:
        result['gaps'].append('Brak przekazanego snapshotu: deklaracje WebAuthn pozostają nieznane.')
        return result
    from helix_runtime_identity import identity_plan
    from helix_runtime_identity_policy import policy_plan
    from helix_runtime_webauthn import webauthn_plan,project_webauthn_plan
    parts,integrations=context['parts'],context['integrations']
    try:
        identities=identity_plan(sources,parts,explicit)
    except ValueError as exc:
        # The fallback scope is an assumption, not evidence that a valid
        # externally configured application part does not exist. Do not hide
        # malformed explicit WebAuthn contracts or errors in resolved scopes.
        if (context['parts_basis']!='repository_source_scope_assumption'
                or str(exc)!='identity: config wskazuje nieznaną część'):raise
        settings=explicit.get('runtime',{})
        declared=settings.get('keycloak',{}).get('parts',{})
        unresolved=('webauthn' not in settings
                    and isinstance(declared,dict)
                    and bool(set(declared)-{part['path'] for part in parts}))
        if not unresolved:raise
        result.update(status='INCOMPLETE',stage='identity_scope',reason_code='SOURCE_SCOPE_UNRESOLVED')
        result['gaps'].append('Brak manifestów nie pozwala powiązać zadeklarowanych części tożsamości ze źródłami. Plan WebAuthn nie został utworzony; przekaż potwierdzone zakresy aplikacji.')
        return result
    policies=policy_plan(sources,parts,identities,integrations,explicit)
    observed=webauthn_plan(sources,parts,integrations,identities,transport['observed'],policies,explicit)
    proposed=(webauthn_plan(sources,parts,integrations,identities,transport['proposed'],policies,config)
              if transport['proposal_applied'] else copy.deepcopy(observed))
    sample=dict(parts=parts,integrations=integrations,identity_plan=identities,transport_plan=transport['proposed'],
                identity_policy_plan=policies,identity_policy_receipts=[],webauthn_plan=proposed,webauthn_receipts=[])
    projection=project_webauthn_plan(sample)
    result.update(observed=observed,proposed=proposed,projection=projection,status=projection['coverage_status'])
    if not isinstance(source_coverage,dict) or source_coverage.get('status')!='COMPLETE':
        result['gaps'].append('Pełność odczytu źródeł WebAuthn nie jest potwierdzona; zobacz coverage.json.')
        result['status']='INCOMPLETE'
    return result


def webauthn_markdown(data):
    escape=lambda value:str(value).replace('|','/').replace('\n',' ').replace('\r',' ')
    lines=['','## Plan kluczy WebAuthn','',
           'Status: **'+data['status']+'**. Nie uruchomiono urządzenia, przeglądarki ani ceremonii.',
           'Konfiguracja WebAuthn pozostaje zachowana. Helix nie dopisuje ról, tras, akcji UI ani włączenia funkcji.']
    projection=data.get('projection')
    if projection is not None:
        lines += ['Plan: '+projection['plan_status']+'; wykonane ceremonie: '+str(projection['counts']['ceremonies_executed'])+'.']
        for part in projection['parts']:
            lines += ['','- Część `'+escape(part['part'])+'`: '+part['plan_status']+'.']
            for gap in part['gaps']:
                lines.append('  - '+escape(gap['code'])+(': `'+escape(gap['config_pointer'])+'`' if gap.get('config_pointer') else '')+'.')
            for declaration in part['declarations']:
                for place in declaration['evidence']:
                    if place.get('path'):lines.append('  - Deklaracja: `'+escape(place['path'])+':'+str(place.get('line','?'))+'`.')
        for gap in projection['gaps']:lines.append('- '+escape(gap['code'])+'.')
    lines += ['- '+gap for gap in data['gaps']]
    lines += ['','Zależność lub zadeklarowany profil urządzenia nie potwierdzają rejestracji, wylogowania ani logowania kluczem.']
    return lines


def transport_markdown(data):
    """Owner-facing declarations stay separate from the proposed HTTPS setting."""
    escape = lambda value: str(value).replace('|', '/').replace('\n', ' ').replace('\r', ' ')
    labels = {'secure_cookie': 'cookie wymagające HTTPS', 'keycloak_transport': 'deklaracja Keycloak',
              'keycloak': 'deklaracja Keycloak', 'webauthn': 'deklaracja WebAuthn'}
    gap_labels = {
        'https_not_enabled': 'W obecnej konfiguracji HTTPS nie jest włączone.',
        'cookie_receiver_unresolved': 'Nie ustalono, czy metoda zapisuje cookie odpowiedzi.',
        'cookie_options_unresolved': 'Nie rozstrzygnięto dynamicznych ustawień cookie.',
        'credentials_options_unresolved': 'Nie rozstrzygnięto parametrów operacji przeglądarki.',
        'local_import_unresolved': 'Nie rozstrzygnięto lokalnego importu.',
        'webauthn_rp_host': 'Adres IP nie zastępuje domeny RP WebAuthn; zaplanuj localhost.',
        'source_unavailable': 'Brak dostępnego aktywnego źródła.',
        'inventory_incomplete': 'Inwentarz integracji ma luki.',
        'part_sources_unavailable': 'Nie przypisano aktywnych źródeł do tej części.',
        'integration_scope_unresolved': 'Deklaracja tożsamości nie ma ustalonej części aplikacji.',
    }
    lines = ['', '## Transport lokalnego runtime', '',
             'Status: **' + data['status'] + '**. Wykonanie: nie uruchomiono aplikacji, HTTPS ani przeglądarki.',
             'Odczytane deklaracje i propozycja konfiguracji nie zaliczają logowania, cookie ani WebAuthn.']
    if data['observed'] is None:
        return lines + ['', *['- ' + gap for gap in data['gaps']]]
    lines += ['Propozycja HTTPS: ' + ('dodano `runtime.https.enabled=true` wyłącznie do proponowanej konfiguracji.'
              if data['proposal_applied'] else 'nie dodano ustawienia; jawny wybór właściciela pozostaje zachowany.'),
              'Zakresy pochodzą z dostarczonych części lub manifestów źródeł; nie dowodzą osobnego uruchomienia usług.', '',
              '| Część | Obecny wybór | Potrzeba HTTPS w źródłach | Proponowany wybór |', '|---|---|---|---|']
    proposed = {part['part']: part for part in data['proposed']['parts']}
    for part in data['observed']['parts']:
        current = part['selected'].upper() + (' (jawny)' if part['selection'] == 'explicit' else ' (domyślny)')
        lines.append('| ' + ' | '.join(map(escape, [part['part'], current, 'tak' if part['https_needed'] else 'nie wykryto', proposed[part['part']]['selected'].upper()])) + ' |')
    lines += ['', 'Zaobserwowane wymagania:']
    requirements = [row for part in data['observed']['parts'] for row in part['requirements']]
    lines += ['- ' + labels.get(row['kind'], escape(row['kind'])) + ': ' +
              (escape(row['path']) + ':' + str(row['line']) if 'path' in row else 'brak miejsca w źródłach') + '.'
              for row in requirements] or ['- Nie wykryto jednoznacznego wymagania; dynamiczna konfiguracja może pozostać nierozpoznana.']
    lines += ['', 'Luki po zastosowaniu propozycji (bez uruchomienia):']
    rows = data['proposed']['gaps'] + [gap for part in data['proposed']['parts'] for gap in part['gaps']]
    lines += ['- ' + gap_labels.get(row['kind'], 'Nierozstrzygnięty warunek: ' + escape(row['kind']) + '.') +
              (' Miejsce: ' + escape(row['path']) + ':' + str(row.get('line', '?')) + '.' if row.get('path') else '') for row in rows]
    lines += ['- ' + gap for gap in data['gaps']]
    lines += ['- Localhost nie potwierdza produkcyjnej polityki cookie; różne porty nie dowodzą izolacji cookie ani zachowania SameSite między witrynami.',
              '- Konfiguracja HTTPS nie jest dowodem poprawnego logowania, Secure cookie ani ceremonii WebAuthn. WebSocket nie jest jeszcze obsługiwany.']
    return lines


def markdown(data):
    from helix_owner_report import provenance_line
    escape = lambda value: str(value if value is not None else 'nieustalony').replace('|', '/').replace('\n', ' ')
    roles = data['provider_plan']
    lines = ['# Przygotowanie Helixa dla projektu', '',
             'Status: **' + data['status'] + '**. Propozycja nie potwierdza gotowości produkcyjnej.',
             'Kod aplikacji i baza nie zostały uruchomione. Przegląd kodu przez modele: ' + str(data['execution']['source_review_calls']) + ' wywołań. Sondy dostępności w tym poleceniu: ' + str(data['execution']['availability_probe_calls']) + '. Lokalne sondy wersji: ' + ('tak' if data['execution']['local_version_probes'] else 'nie') + '.',
             provenance_line(data['provenance']), '', '## Zakres i konfiguracja', '',
             'Cel: `' + escape(data['target']) + '`. Propozycja: `helix.proposed.json`.',
             'Ścieżki UI: ' + (', '.join('`' + escape(p) + '`' for p in data['ui_paths']) or 'nie wykryto') + '.',
             'Zapis do repozytorium: ' + ('jawne --write, nowy helix.json' if data['written_to_repo'] else 'nie') + '.', '',
             '## Modele i role', '',
             'Dowód dostępności: ' + data['availability']['status'] + '. Status planu: **' + roles['status'] + '**.',
             'Brak świeżej odpowiedzi oznacza nieznaną dostępność. Istnienie programu lub tokenu nie potwierdza zalogowania ani dostępu do modelu.', '',
             '| Rola | Provider | Model | Rodzina | Status |', '|---|---|---|---|---|']
    for role, entries in roles['roles'].items():
        for item in entries if isinstance(entries, list) else [entries]:
            lines.append('| ' + ' | '.join(escape(x) for x in (role, item['provider'], item['model'], item['family'], item['status'])) + ' |')
    db, local = data['database']['target'], data['database']['local']
    lines += ['', '## Środowisko i baza danych', '',
              f"Cel: {db['engine']} {db['major']} [{db['tag']}]; konflikt deklaracji: {db['conflict']}.",
              'Lokalne binarium serwera: ' + escape(local['version']) + '; zgodność z deklaracją: ' + escape(local['compatible']) + '.',
              'Wersja działającego serwera i produkcji pozostaje nieznana. Deklaracje, lokalne binaria i produkcja są rozdzielone w `environment.md`.',
              'Źródła wersji: ' + (', '.join(escape(e['path']) + ':' + str(e['line']) for e in db['evidence'][:8]) or 'brak dokładnego przypięcia') + '.']
    if data.get('transport') is not None:
        lines += transport_markdown(data['transport'])
    if data.get('webauthn') is not None:
        lines += webauthn_markdown(data['webauthn'])
    lines += ['', '## Koszt i harmonogram', '']
    cost = data['deep']['plan']
    if cost:
        lines += [f"Pełny przebieg: {cost['batches']} partii; {cost['calls_min']}-{cost['calls_max']} wywołań; {cost['source_bytes']} bajtów źródeł; jobs={cost['jobs']}.",
                  'Szacowany czas: ' + (str(cost['estimated_seconds']) + ' s' if cost.get('estimated_seconds') is not None else 'nieznany, brak pomiarów czasu partii') + '. Kwota: nieznana, zależy od modelu i taryfy.']
    else: lines.append('Plan wywołań niedostępny; szczegóły w lukach. Czas i kwota pozostają nieznane.')
    lines += ['', 'Historia COMPLETE: ' + data['history']['status'] + '.', '', '| Tryb | Zakres | Budżet czasu | Warunek |', '|---|---|---|---|']
    for item in data['schedule']:
        lines.append('| ' + ' | '.join(escape(item[k]) for k in ('name', 'scope', 'budget', 'requires')) + ' |')
    lines += ['', 'Budżet jest limitem wykonania, a nie estymatą czasu. Harmonogram jest propozycją, niczego nie uruchamia.', '', '## Decyzje właściciela', '']
    lines += ['- ' + item['question'] for item in data['pending_owner']] or ['Brak nowych pytań wynikających z tego planu.']
    egress = data.get('data_egress', {})
    if egress:
        lines += ['', 'Deklaracja polityki wysyłki: **' + egress['status'] + '**. '
                  'Przygotowanie projektu nie wysyła źródeł; zatwierdzenie listy nie jest dowodem wysłania ani ograniczeń dostępu CLI.']
        if egress['allowed_providers']:
            lines.append('Jawnie wskazani dostawcy: ' + ', '.join(egress['allowed_providers']) + '.')
    lines += ['', '## Luki i następne kroki', '']
    lines.extend('- ' + gap for gap in data['gaps'])
    lines += ['', 'Pełne dane: `project-proposal.json`. Plan modeli: `provider-plan.json`. Ta propozycja nie akceptuje baseline, waiverów ani polityki wysyłania danych.']
    return '\n'.join(lines) + '\n'


def egress_declaration(config):
    """Check a declaration without changing an existing owner policy or sending data."""
    from helix_data_egress import DataEgressError, normalize_policy, policy_sha256
    from helix_model_admission import effective_policy
    # Decyzja właściciela 15.11.2026: bez deklaracji Helix wysyła do wszystkich dostawców; nie pyta i nie dopisuje propozycji.
    declared = config.get('data_egress')
    if declared is None or (isinstance(declared, dict) and declared.get('status') == 'pending_owner'):
        normalized = normalize_policy(effective_policy(declared))
        return dict(status='DEFAULT_ALL_PROVIDERS', allowed_providers=normalized['allowed_providers'],
                    policy_sha256=policy_sha256(normalized), reason=None, delivery='NOT_SENT'), []
    try:
        normalized = normalize_policy(declared)
    except DataEgressError as error:
        return dict(status='PENDING_OWNER', allowed_providers=[], policy_sha256=None,
                    reason=error.code, delivery='NOT_SENT'), [dict(id='data_egress', status='pending_owner',
            question='Którym dostawcom wolno wysyłać dopuszczone źródła projektu? '
                     'Uzupełnij allowed_providers i jawne status=approved w data_egress oraz sprawdź wykluczenia. '
                     'Nie zmieniono istniejącej polityki; dawna lista ścieżek allowlist nie zatwierdza dostawców. '
                     'Sonda dostępności modelu nie zatwierdza wysyłania kodu.')]
    return dict(status='APPROVED_DECLARATION', allowed_providers=normalized['allowed_providers'],
                policy_sha256=policy_sha256(normalized), reason=None, delivery='NOT_SENT'), []


def generate(repo, out, *, profile=None, state_dir=None, provider_cache=None, write=False, probe=False,
             refresh_providers=False, provider_refresh=None, jobs=3, offline=False, _refresh_receipt=None,
             sources=None, parts=None, integrations=None, source_coverage=None):
    from helix_config import load, source
    from helix_contracts import VERSION
    from helix_consistency import DEFAULT_CS, static_paths
    from helix_runtime import database_target
    from helix_environment import report as environment_report, markdown as environment_markdown, provenance
    from helix_provider_plan import FAMILIES, plan, apply_plan
    repo, out = system_path(repo), system_path(out)
    state = system_path(state_dir) if state_dir else out / 'state'
    preflight(repo, out, write, state)
    validate_refresh(refresh_providers, provider_refresh, jobs, offline)
    refresh_receipt = _refresh_receipt if _refresh_receipt is not None else prepare_refresh(
        repo, out, state_dir=state, provider_cache=provider_cache, refresh_providers=refresh_providers,
        provider_refresh=provider_refresh, jobs=jobs, offline=offline)
    explicit = load(repo)
    config = copy.deepcopy(explicit)
    config.update(helix_version=VERSION, profile=profile or explicit.get('profile', 'M'))
    config.setdefault('mode', 'supervised')
    config.setdefault('truth', {'required': True})
    cache = Path(provider_cache) if provider_cache else state / 'provider-availability.json'
    observed, evidence = availability(cache)
    models = {provider: [None] for provider in ('codex', 'claude', 'gemini', 'grok-cli')}
    for row in observed.get('models', []):
        if row.get('provider') in FAMILIES:
            chain = models.setdefault(row['provider'], [])
            if row.get('model') not in chain: chain.append(row.get('model'))
    models.update(copy.deepcopy(explicit.get('models', {})))
    config['models'] = models
    config.setdefault('providers', {})
    role_plan = plan(config, observed, explicit)
    config = apply_plan(config, role_plan, explicit)
    # A written proposal becomes an explicit config on its next load. Keep the
    # selected observed model first, so a guessed default cannot replace it.
    for entries in role_plan['roles'].values():
        for item in entries if isinstance(entries, list) else [entries]:
            provider = item['provider']
            if item['status'] == 'available' and provider not in explicit.get('models', {}):
                config['models'][provider] = [item['model'], *[m for m in config['models'][provider] if m != item['model']]]
    sc = copy.deepcopy(DEFAULT_CS['static'])
    sc.update(explicit.get('consistency', {}).get('static', {}))
    paths = static_paths(repo, sc)
    config.setdefault('consistency', {}).setdefault('static', {}).setdefault('paths', paths)
    config.setdefault('packs', {}).setdefault('security', {}).setdefault('deep', {}).setdefault('jobs', 3)
    jobs = config['packs']['security']['deep']['jobs']
    target = database_target(repo)
    config.setdefault('runtime', {}).setdefault('database', {k: target[k] for k in ('engine', 'major', 'image')})
    context = _source_context(sources,parts,integrations,explicit)
    transport = propose_transport(sources, parts, integrations, explicit, config, source_coverage,_context=context)
    webauthn = propose_webauthn(sources,context,transport,explicit,config,source_coverage)
    if repo.is_dir():
        environment = environment_report(repo, probe=probe)
    else:
        environment = dict(schema_version=1, status='INCOMPLETE',
                           scope='Nowy katalog projektu jeszcze nie istnieje; brak deklaracji i lokalnych sond',
                           components=[], files_scanned=0, errors=[],
                           env_names=dict(used={}, declared={}, missing_from_examples=[], unused_declared=[],
                                          values_parsed=False, values_retained=False, real_env_read=False),
                           coverage=dict(status='INCOMPLETE', reason='Katalog projektu jeszcze nie istnieje'),
                           provenance=provenance(repo))
        environment['markdown'] = environment_markdown(environment)
    local = local_database(environment, target)
    egress, pending = egress_declaration(config)
    gaps = list(role_plan['notes'])
    if evidence['status'] != 'recorded_fresh':
        gaps.append('Dostępność modeli UNKNOWN: brak świeżych rzeczywistych sond. Użyj --refresh-providers albo providers --refresh, potem ponów audyt z nowym katalogiem wyników.')
    if not paths: gaps.append('Nie wykryto katalogów UI; uzupełnij consistency.static.paths po sprawdzeniu projektu.')
    if target['conflict']: gaps.append('Sprzeczne deklaracje silnika lub wersji bazy wymagają rozstrzygnięcia przed runtime.')
    if target['assumption']: gaps.append(target['assumption'])
    if local['compatible'] is False: gaps.append('WARNING: lokalne binarium PostgreSQL różni się od celu projektu. Wymagany zgodny runtime albo jawnie opisany eksperyment; ta wersja nie potwierdza zgodności z projektem.')
    elif local['compatible'] is None: gaps.append('Lokalna wersja binarium serwera pozostaje niezweryfikowana; nie wykonano połączenia z bazą.')
    deep = dict(status='not_planned', plan=None, source_ref=None, model_calls=0)
    if (repo / '.git').exists():
        from helix_security_deep import preview_plan
        try:
            _, meta = preview_plan(repo, config, state, out / 'deep-plan', availability=observed, explicit_cfg=explicit, jobs=jobs, mode='full')
            deep.update(status='plan_only', plan=meta['plan'], source_ref=meta['source_ref'], role_plan=meta.get('role_plan'),
                        role_assignments=meta.get('role_assignments'))
        except (OSError, ValueError) as exc:
            gaps.append('Plan security deep niedostępny: ' + type(exc).__name__ + '; sprawdź HEAD repozytorium i dostępne źródła. Nie uruchomiono przeglądu kodu przez modele.')
    else: gaps.append('Plan security deep wymaga repozytorium Git z HEAD; nowy katalog nie ma jeszcze punktu odniesienia.')
    timings, history = schedule(state, repo, jobs)
    if history['status'] != 'recorded_complete':
        gaps.append('Brak poprawnego poprzedniego COMPLETE. Daily i release wymagają najpierw pełnego przeglądu albo jawnego --since REF; nie udają sprawdzenia zmian.')
    gaps.append('Runtime, przegląd wizualny i niezależna weryfikacja findings nie zostały wykonane.')
    from helix_environment import normalize_models
    current_provenance = copy.deepcopy(environment['provenance'])
    current_provenance['models'] = normalize_models(refresh_receipt['models'])
    data = dict(schema_version=1, helix_version=VERSION,
                status='LIMITED' if pending or role_plan['status'] != 'READY' or deep['status'] != 'plan_only' or transport['status'] in ('NOT_RECORDED', 'INCOMPLETE') or webauthn['status'] in ('NOT_RECORDED','INCOMPLETE') else 'PROPOSED',
                target=str(repo), config_source=str(source(repo)) if source(repo).is_file() else None,
                provenance=current_provenance, provider_refresh=refresh_receipt, source_ref=deep['source_ref'], ui_paths=paths, availability=evidence,
                provider_plan=role_plan, database={'target': target, 'local': local}, environment={'status': environment['status'], 'artifact': 'environment.json'}, transport=transport,webauthn=webauthn,
                deep=deep, schedule=timings, history=history, pending_owner=pending, data_egress=egress, gaps=gaps, written_to_repo=write,
                execution={'models': refresh_receipt['availability_probe_calls'],
                           'availability_probe_calls': refresh_receipt['availability_probe_calls'], 'source_review_calls': 0,
                           'application': False, 'database_started': False, 'local_version_probes': probe and repo.is_dir()})
    json_write(out / 'helix.proposed.json', config)
    json_write(out / 'provider-plan.json', role_plan)
    json_write(out / 'environment.json', {k: v for k, v in environment.items() if k != 'markdown'})
    text_write(out / 'environment.md', environment['markdown'])
    json_write(out / 'project-proposal.json', data)
    text_write(out / 'NEW-REPORT.md', markdown(data))
    if write:
        repo.mkdir(parents=True, exist_ok=True)
        json_write(repo / 'helix.json', config)
    return data
