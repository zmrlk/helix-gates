"""Model availability and role planning. No network or provider calls at import/plan time."""
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import time

FAMILIES = {'codex': 'openai', 'claude': 'anthropic', 'claude-via-agy': 'anthropic',
            'gemini': 'google', 'gemini-flash': 'google', 'grok': 'xai', 'grok-cli': 'xai'}
# Automated callers that can return one JSON response. Manual Grok uses a file handoff.
JSON_PROVIDERS = ('codex', 'claude', 'claude-via-agy', 'gemini', 'gemini-flash', 'grok-cli')
AGY_PROVIDERS = ('gemini', 'gemini-flash', 'claude-via-agy')
TTL_SECONDS = 1800
# Explicit quality preferences, not benchmark claims or invented model versions.
PREFERENCES = {
    'planner': ('claude', 'claude-via-agy', 'codex', 'gemini', 'grok-cli', 'gemini-flash'),
    'implementer': ('codex', 'claude', 'claude-via-agy', 'gemini', 'grok-cli', 'gemini-flash'),
    'hunter': ('codex', 'claude', 'claude-via-agy', 'gemini', 'grok-cli', 'gemini-flash'),
    'verifier': ('grok-cli', 'gemini', 'claude', 'claude-via-agy', 'codex', 'gemini-flash'),
    'reviewers': ('gemini', 'claude', 'claude-via-agy', 'grok-cli', 'codex', 'gemini-flash'),
    'visual_judge': ('gemini', 'codex', 'claude', 'claude-via-agy', 'gemini-flash', 'grok-cli'),
}


def family(provider):
    return FAMILIES.get(provider) if isinstance(provider, str) else None


def _branded_family(model):
    if not isinstance(model, str): return None
    # Only unambiguous vendor brands, not arbitrary aliases or short o* names.
    brands = (('claude', 'anthropic'), ('gemini', 'google'), ('grok', 'xai'), ('gpt', 'openai'))
    for brand, vendor in brands:
        if re.match(r'^(?:' + vendor + r'[/:])?' + brand + r'(?:[-./:]|$)', model, re.I):
            return vendor
    return None


def model_family(provider, model):
    """Known model brands override aliases; agy's unnamed default has no known family."""
    if provider in AGY_PROVIDERS and (model is None or isinstance(model, str) and model.lower() in ('default', 'unknown', 'orchestrator')):
        return None
    return _branded_family(model) or family(provider)


def model_family_basis(provider, model):
    if model_family(provider, model) is None: return 'unknown'
    if _branded_family(model): return 'known_model_brand'
    return 'provider_policy' if provider in AGY_PROVIDERS else 'provider_transport'


def compatible_model(provider, model):
    """A JSON response alone does not prove an alias's claimed model family."""
    if model is not None and (not isinstance(model, str) or not model.strip()): return False
    own = family(provider)
    return bool(own and model_family(provider, model) == own)


def independent_providers(hunter, candidates):
    own = family(hunter)
    return [p for p in dict.fromkeys(candidates) if own and family(p) and family(p) != own]


def configured_models(cfg):
    """Every declared model chain entry, plus role providers using their default."""
    if not isinstance(cfg, dict):
        raise ValueError('konfiguracja providerów wymaga obiektu JSON')
    models = cfg.get('models', {})
    if not isinstance(models, dict) or not isinstance(cfg.get('providers', {}), dict):
        raise ValueError('models i providers muszą być obiektami JSON')
    for role, value in cfg.get('providers', {}).items():
        if role == 'reviewers':
            if not isinstance(value, list) or any(not isinstance(v, dict) or not isinstance(v.get('provider'), str) for v in value):
                raise ValueError('providers.reviewers wymaga listy obiektów z provider')
            for index, entry in enumerate(value):
                if 'model' in entry and entry['model'] is not None and (not isinstance(entry['model'], str) or not entry['model'].strip()):
                    raise ValueError('providers.reviewers.model wymaga nazwy modelu lub null')
                if 'enabled' in entry and not isinstance(entry['enabled'], bool):
                    raise ValueError('providers.reviewers.enabled wymaga wartości logicznej')
                if 'name' in entry and (not isinstance(entry['name'], str) or not entry['name'] or any(c in entry['name'] for c in '/\\')):
                    raise ValueError('providers.reviewers.name wymaga nazwy bez ścieżki')
        elif value is not None and not isinstance(value, str):
            raise ValueError('providers.' + role + ' wymaga nazwy providera; modele ustaw w models')
    providers = list(models)
    for role, value in cfg.get('providers', {}).items():
        values = value if isinstance(value, list) else [value]
        for item in values:
            provider = item.get('provider') if isinstance(item, dict) else item
            if isinstance(provider, str) and provider in FAMILIES and provider not in providers:
                providers.append(provider)
    result = []
    for provider in providers:
        if not isinstance(provider, str) or not provider:
            raise ValueError('models wymaga niepustych nazw providerów')
        chain = models.get(provider, [None])
        if not isinstance(chain, list) or not chain or any(m is not None and (not isinstance(m, str) or not m.strip()) for m in chain):
            raise ValueError('models.' + provider + ' musi być niepustą listą nazw modeli lub null')
        result.extend((provider, model) for model in chain if (provider, model) not in result)
    for entry in cfg.get('providers', {}).get('reviewers', []):
        pair = (entry['provider'], entry.get('model'))
        if 'model' in entry and pair not in result: result.append(pair)
    return result


def _age(record, now=None):
    try:
        stamp = datetime.fromisoformat(record['checked_at'])
        if stamp.tzinfo is None: return None
        age = (now or datetime.now(timezone.utc)).timestamp() - stamp.timestamp()
        return age if age >= 0 else None
    except (KeyError, TypeError, ValueError):
        return None


def model_record(availability, provider, model):
    records = availability.get('models', []) if isinstance(availability, dict) else []
    if not isinstance(records, list): return {}
    matches = [r for r in records if isinstance(r, dict) and r.get('provider') == provider and r.get('model') == model]
    # Refresh produces one receipt per pair. Duplicate receipts are ambiguous,
    # especially when an old success is followed by a new failure.
    return matches[0] if len(matches) == 1 else {}


def model_available(availability, provider, model):
    if provider not in JSON_PROVIDERS or (model is not None and (not isinstance(model, str) or not model.strip())):
        return False
    if not compatible_model(provider, model): return False
    record = model_record(availability, provider, model)
    age = _age(record)
    return bool(record.get('status') == 'available' and record.get('method') in ('short_call', 'model_response')
                and age is not None and age <= TTL_SECONDS and record.get('family') == model_family(provider, model))


def record_success(availability, provider, model):
    """Pure local-run update, called only after this exact model returned valid JSON.

    This is not a probe and does not write the global availability cache. A real
    successful call refreshes only its own model, never another provider/model.
    """
    if provider not in JSON_PROVIDERS or (model is not None and (not isinstance(model, str) or not model.strip())):
        raise ValueError('invalid executed provider/model')
    data = copy.deepcopy(availability) if isinstance(availability, dict) else {}
    rows = data.get('models', [])
    if not isinstance(rows, list): rows = []
    selected_family = model_family(provider, model)
    status = 'available' if compatible_model(provider, model) else 'model_conflict' if selected_family else 'unknown_family'
    checked = datetime.now(timezone.utc).isoformat()
    record = dict(provider=provider, model=model, family=selected_family, family_basis=model_family_basis(provider, model),
                  status=status, method='model_response', checked_at=checked, json_response=True,
                  scope='current_run', reason='Rzeczywista odpowiedź JSON tego modelu w bieżącym przebiegu')
    data['models'] = [r for r in rows if isinstance(r, dict) and (r.get('provider'), r.get('model')) != (provider, model)] + [record]
    data.update(schema_version=1, checked_at=checked)
    return data


def load_availability(path):
    path = Path(path)
    if path.is_symlink(): return {}
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) and isinstance(data.get('models'), list) else {}
    except (OSError, ValueError):
        return {}


def atomic_json(path, data):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(data, output, ensure_ascii=False, indent=2, allow_nan=False)
            output.write('\n'); output.flush(); os.fsync(output.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def _json_answer(text):
    text = (text or '').strip()
    try: return json.loads(text)
    except ValueError: pass
    start, end = text.find('{'), text.rfind('}')
    if start >= 0 and end > start:
        try: return json.loads(text[start:end + 1])
        except ValueError: pass
    raise ValueError('model probe returned invalid JSON confirmation')


def refresh(ctx, callers, path, timeout=30, *, jobs=3):
    """Fixed JSON pings in separate neutral directories, one durable coordinator."""
    if getattr(ctx, 'offline', False): raise ValueError('offline: odświeżenie providerów wymaga wywołań modeli')
    if isinstance(jobs, bool) or not isinstance(jobs, int) or jobs < 1:
        raise ValueError('providers jobs wymaga dodatniej liczby całkowitej')
    from helix_packs import redact
    from helix_audit_context import system_path
    from helix_paths import within
    pairs = configured_models(ctx.cfg)
    target = Path(ctx.repo).expanduser().resolve()
    base = Path(tempfile.gettempdir()).resolve()
    # Check before creating a directory, including unusual targets such as /tmp.
    if within(base, target):
        raise ValueError('providers: systemowy katalog tymczasowy leży w repo celu; brak neutralnego cwd')
    path = system_path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('providers: cache nie może zawierać dowiązania')
    now = lambda: datetime.now(timezone.utc).isoformat()
    effective = jobs
    data = dict(schema_version=1, checked_at=now(), status='in_progress', method='short_call',
                requested_jobs=jobs, jobs=effective, total=len(pairs), completed=0,
                availability_probe_calls=0, source_review_calls=0, models=[])
    atomic_json(path, data)

    def attempt(provider, model):
        record = dict(provider=provider, model=model, family=model_family(provider, model),
                      family_basis=model_family_basis(provider, model), status='unavailable',
                      method='short_call', checked_at=now(), reason=None, seconds=0, call_invoked=False)
        started = time.monotonic()
        try:
            if provider == 'grok':
                raise ValueError('manual handoff cannot be validated by an automatic model call')
            caller = callers.get(provider)
            if caller is None: raise ValueError('unknown provider')
            from helix_model_admission import authorized_probe
            with authorized_probe(ctx, provider, model) as (probe_ctx, fixed_prompt, neutral):
                probe_ctx._deep_deadline = started + timeout
                record['call_invoked'] = True
                answer = caller(probe_ctx, model, fixed_prompt, None, None, False, neutral, timeout)
                # Część CLI dokleja do odpowiedzi linię komentarza (Codex: „No checks performed…”): liczy się obiekt JSON w tekście.
                parsed = _json_answer(answer)
                if not isinstance(parsed, dict) or parsed.get('ok') is not True:
                    raise ValueError('model probe returned invalid JSON confirmation')
            status = 'available' if compatible_model(provider, model) else 'model_conflict' if record['family'] else 'unknown_family'
            reason = ('Krótka odpowiedź JSON potwierdzona' if status == 'available' else
                      'Odpowiedź JSON potwierdzona, ale marka modelu jest sprzeczna z aliasem providera' if status == 'model_conflict' else
                      'Odpowiedź JSON potwierdzona, ale domyślny model agy nie określa rodziny')
            record.update(status=status, reason=reason, json_response=True)
        except Exception as error:
            detail = str(error).lower()
            if provider == 'grok': reason = 'Ręczny handoff nie ma automatycznego dowodu modelu'
            elif 'model' in detail and any(w in detail for w in ('not found', 'unavailable', 'not available', 'unknown')): reason = 'Wybrany model jest niedostępny'
            elif 'json' in detail: reason = 'Model nie potwierdził poprawnej odpowiedzi JSON'
            else: reason = type(error).__name__ + ': ' + redact(str(error))[:1000]
            record['reason'] = reason
        record['seconds'] = round(time.monotonic() - started, 3)
        record['checked_at'] = now()
        return record

    completed = {}
    # Workers never mutate shared evidence. Completion order may differ from the
    # deterministic model-chain order retained by the single writer.
    def retain(index, record):
        completed[index] = record
        data['models'] = [completed[index] for index in sorted(completed)]
        data.update(completed=len(completed), checked_at=now(),
                    availability_probe_calls=sum(row['call_invoked'] for row in data['models']))
        atomic_json(path, data)

    with ThreadPoolExecutor(max_workers=effective, thread_name_prefix='helix-probe') as pool:
        queue = iter(enumerate(pairs))
        pending = {}
        def submit_next():
            item = next(queue, None)
            if item is not None:
                index, (provider, model) = item
                pending[pool.submit(attempt, provider, model)] = index
        for _ in range(min(effective, len(pairs))): submit_next()
        try:
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in sorted(done, key=lambda item: pending[item]):
                    index = pending.pop(future)
                    retain(index, future.result())
                    # Persist each result before admitting its successor, so a
                    # stop never leaves an unbounded queue of paid probes.
                    submit_next()
        except BaseException:
            for future in pending: future.cancel()
            # Running calls have their normal timeout. Retain completed evidence
            # during orderly interruption before closing the executor.
            for future in as_completed(pending):
                if not future.cancelled():
                    try: record = future.result()
                    except BaseException: continue
                    retain(pending[future], record)
            data.update(status='interrupted', checked_at=now())
            atomic_json(path, data)
            raise
    data.update(status='complete', checked_at=now())
    atomic_json(path, data)
    return data


def plan(cfg, availability, explicit_cfg=None):
    """Immutable input; preserve explicit assignments and propose unavailable replacements."""
    explicit_cfg = explicit_cfg or {}
    configured_models(explicit_cfg)
    explicit_roles = explicit_cfg.get('providers', {})
    explicit_models = explicit_cfg.get('models', {})
    models = cfg.get('models', {})
    configured_models(cfg)  # validate the chains even with no availability data
    roles = {}; proposals = []; notes = []

    def options(role, excluded=()):
        result = []
        for provider in PREFERENCES[role]:
            if family(provider) in excluded or provider not in models: continue
            chain = models[provider]
            # A declared model choice is not silently replaced by the next model.
            # A scalar explicit role uses the first configured model at runtime.
            # Do not let another automatic role reorder that owner's selection.
            pinned_role = any(value == provider or isinstance(value, dict) and value.get('provider') == provider and 'model' not in value
                              for selected in explicit_roles.values()
                              for value in (selected if isinstance(selected, list) else [selected]))
            candidates = chain[:1] if provider in explicit_models or pinned_role else chain
            model = next((m for m in candidates if model_available(availability, provider, m)), ...)
            if model is not ...: result.append((provider, model))
        return result

    def select(role, value=None, explicit=False, excluded=()):
        available = options(role, excluded)
        provider = value.get('provider') if isinstance(value, dict) else value
        if explicit:
            model = value.get('model', models.get(provider, [None])[0]) if isinstance(value, dict) else models.get(provider, [None])[0]
            okay = model_available(availability, provider, model)
            selected_family = model_family(provider, model)
            independent = selected_family not in excluded and selected_family is not None
            status = ('model_conflict' if selected_family and not compatible_model(provider, model) else
                      'unknown_family' if not selected_family else
                      'available' if okay and independent else 'not_independent' if okay else 'unavailable')
            reason = ('Jawny wybór właściciela zachowany' if status == 'available' else
                      'Marka modelu jest sprzeczna z aliasem providera; jawny wybór zachowany' if status == 'model_conflict' else
                      'Rodzina domyślnego modelu agy jest nieznana; jawny wybór zachowany' if status == 'unknown_family' else
                      'Jawny wybór niedostępny lub z tej samej rodziny; bez automatycznej zamiany')
            if status != 'available':
                alternatives = [(p,m) for p,m in configured_models(cfg) if family(p) not in excluded and model_available(availability,p,m) and (p,m) != (provider,model)]
                proposals.append(dict(role=role, current=dict(provider=provider, model=model),
                                      alternatives=[dict(provider=p, model=m, family=family(p)) for p, m in alternatives]))
        elif available:
            provider, model = available[0]; status = 'available'
            reason = 'Automatyczna preferencja jakości dla roli ' + role + '; świeży test modelu'
        else:
            provider = model = None; status = 'unavailable'
            reason = 'Brak świeżo sprawdzonego modelu' + (' z niezależnej rodziny' if excluded else '')
        basis = model_family_basis(provider, model)
        if basis == 'provider_policy': reason += '; ASSUMPTION: rodzina nieprzezroczystego modelu wynika z aliasu providera'
        return dict(provider=provider, model=model, family=model_family(provider, model), family_basis=basis, status=status,
                    explicit=explicit, reason=reason)

    for role in ('planner', 'implementer', 'hunter'):
        roles[role] = select(role, explicit_roles.get(role), role in explicit_roles)
    own_hunter = roles['hunter']['family']
    roles['verifier'] = select('verifier', explicit_roles.get('verifier'), 'verifier' in explicit_roles,
                               (own_hunter,) if own_hunter else ())
    roles['visual_judge'] = select('visual_judge', explicit_roles.get('visual_judge'), 'visual_judge' in explicit_roles)
    author = roles['implementer']['family']
    if 'reviewers' in explicit_roles:
        roles['reviewers'] = []
        for index, entry in enumerate(explicit_roles['reviewers']):
            if not entry.get('enabled', True): continue
            item = select('reviewers', entry, True, (author,) if author else ())
            item.update(name=entry.get('name', 'reviewer-' + str(index+1)), prompt=entry.get('prompt', 'review_architecture'))
            roles['reviewers'].append(item)
    else:
        excluded = {author} if author else set()
        roles['reviewers'] = []
        for index in range(2):
            item = select('reviewers', excluded=excluded)
            if item['status'] != 'available' and index:
                item = select('reviewers', excluded=(author,) if author else ())
                if item['status'] == 'available':
                    item['reason'] += '; drugi świeży kontekst tej samej rodziny recenzentów'
            item.update(name='auto-' + ('architecture' if index == 0 else 'tests-security'),
                        prompt='review_architecture' if index == 0 else 'review_tests')
            roles['reviewers'].append(item)
            if item['family']: excluded.add(item['family'])
    reviewers = roles['reviewers']
    families = {r['family'] for r in reviewers if r['status'] == 'available' and r['family'] != author}
    independent_review = bool(author and len(reviewers) >= 2 and families and all(r['status'] == 'available' and r['family'] != author for r in reviewers))
    independent_verifier = bool(own_hunter and roles['verifier']['status'] == 'available'
                                and roles['verifier']['family'] != own_hunter)
    available_families = sorted({family(p) for p, m in configured_models(cfg) if family(p) and model_available(availability, p, m)})
    if len(available_families) < 2:
        notes.append('LIMITED: jedna lub żadna rodzina modeli; brak niezależnej weryfikacji')
    elif not independent_review:
        notes.append('LIMITED: bramka review wymaga dwóch recenzentów z rodzin innych niż implementer')
    status = 'READY' if independent_review and independent_verifier and all(roles[k]['status'] == 'available' for k in ('planner', 'implementer', 'hunter')) else 'LIMITED'
    return dict(schema_version=1, status=status, roles=roles, independent_review=independent_review,
                independent_verifier=independent_verifier, available_families=available_families,
                proposals=proposals, notes=notes,
                policy='Preferencje są jawną polityką jakości, nie benchmarkiem modeli. Jawne role i modele są zachowane; brak dowodu nie daje PASS.')


def apply_plan(cfg, role_plan, explicit_cfg=None):
    """Effective auto roles are separate from the original explicit configuration."""
    explicit = (explicit_cfg or {}).get('providers', {})
    result = copy.deepcopy(cfg)
    result.setdefault('providers', {})
    result.setdefault('models', {})
    for name, item in role_plan['roles'].items():
        if name in explicit:
            if name == 'reviewers':
                for index, entry in enumerate(result['providers'][name]):
                    entry.setdefault('name', 'reviewer-' + str(index + 1))
            continue
        if name == 'reviewers':
            result['providers'][name] = [dict(name=r['name'], provider=r['provider'], model=r['model'], prompt=r['prompt'], enabled=True)
                                         for r in item if r['status'] == 'available']
        elif item['status'] == 'available':
            result['providers'][name] = item['provider']
            provider, model = item['provider'], item['model']
            chain = result['models'].get(provider, [])
            result['models'][provider] = [model] + [value for value in chain if value != model]
    return result
