"""Offline verifier boundary. No provider invocation and no writes to target repos."""
import hashlib
import json
import os
from pathlib import Path
import tempfile


def identity(row, sources):
    # Bind verdicts to the complete inspected file: stale verdicts cannot promote new code.
    digest = row.get('source_hash') or hashlib.sha256(sources.get(row['file'], '').encode()).hexdigest()
    return hashlib.sha256(json.dumps([row['id'], row['file'], row['line'], digest]).encode()).hexdigest()


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
        raise ValueError('Nieprawidłowy plik weryfikacji/stanu')
    data = json.loads(path.read_text(encoding='utf-8'))
    from helix_requirements import reject_secrets
    reject_secrets(data)
    return data


def _apply(rows, repo, sources, verdicts=None, state_dir=None, threshold=0.3, minimum=10, routes=None):
    if not 0 <= threshold <= 1 or minimum < 1:
        raise ValueError('precision threshold: 0..1; minimum >= 1')
    root = Path(repo).resolve()
    project = hashlib.sha256(str(root).encode()).hexdigest()
    state_path = None
    state = {'schema_version': 1, 'projects': {}}
    if state_dir:
        directory = Path(state_dir).resolve()
        if directory == root or root in directory.parents or directory in root.parents:
            raise ValueError('Stan weryfikacji musi być poza repo')
        directory.mkdir(parents=True, exist_ok=True)
        state_path = directory / 'verification.json'
        if state_path.exists() or state_path.is_symlink():
            state = read_json(state_path)
        if state.get('schema_version') != 1 or not isinstance(state.get('projects'), dict):
            raise ValueError('Nieprawidłowy schemat stanu weryfikacji')
    for records in state['projects'].values():
        if not isinstance(records, dict):
            raise ValueError('Nieprawidłowa historia weryfikacji')
        for fid, record in records.items():
            if not isinstance(fid, str) or not isinstance(record, dict) or not isinstance(record.get('detector'), str) or record.get('verdict') not in {'confirmed', 'rejected', 'unclear'} or not isinstance(record.get('reason'), str):
                raise ValueError('Nieprawidłowa próbka weryfikacji')
    history = state['projects'].setdefault(project, {})
    route_history = state.setdefault('route_projects', {}).setdefault(project, {})
    route_ids = {}
    for route in routes or []:
        probe = dict(id='ROUTE:' + route['method'] + ':' + route['path'], file=route['file'], line=route['line'])
        route['route_id'] = identity(probe, sources)
        route_ids[route['route_id']] = route
    by_id = {}
    for row in rows:
        row['finding_id'] = identity(row, sources)
        by_id[row['finding_id']] = row
    if verdicts:
        payload = read_json(verdicts)
        if not isinstance(payload, dict) or payload.get('schema_version') != 1 or not isinstance(payload.get('verdicts'), list):
            raise ValueError('Werdykty wymagają schema_version=1 i verdicts[]')
        hunter, verifier = payload.get('hunter'), payload.get('verifier')
        if not isinstance(hunter, str) or not isinstance(verifier, str) or not hunter.strip() or not verifier.strip() or hunter == verifier:
            raise ValueError('Wymagany niezależny verifier różny od hunter')
        route_imports = {}
        if not isinstance(payload.get('routes', []), list):
            raise ValueError('Wymagane routes[]')
        for item in payload.get('routes', []):
            if not isinstance(item, dict) or item.get('route_id') not in route_ids or item['route_id'] in route_imports or item.get('auth_status') not in {'proven-guarded', 'unknown', 'unguarded'} or not isinstance(item.get('reason'), str) or not item['reason'].strip():
                raise ValueError('Nieprawidłowy lub nieaktualny werdykt trasy')
            route_imports[item['route_id']] = dict(auth_status=item['auth_status'], reason=item['reason'])
        imported = {}
        for item in payload['verdicts']:
            if not isinstance(item, dict):
                raise ValueError('Nieprawidłowy werdykt')
            fid = item.get('finding_id')
            if fid not in by_id or fid in imported:
                raise ValueError('Nieznane, nieaktualne lub powtórzone finding_id')
            if item.get('verdict') not in {'confirmed', 'rejected', 'unclear'} or not isinstance(item.get('reason'), str) or not item['reason'].strip():
                raise ValueError('Wymagane verdict oraz reason')
            # External independent review is an explicit interface, not a claim that a model ran.
            imported[fid] = dict(detector=by_id[fid]['id'], verdict=item['verdict'], reason=item['reason'], hunter=hunter, verifier=verifier)
        history.update(imported)
        route_history.update(route_imports)

    for rid, route in route_ids.items():
        if rid in route_history:
            record = route_history[rid]
            if not isinstance(record, dict) or record.get('auth_status') not in {'proven-guarded', 'unknown', 'unguarded'} or not isinstance(record.get('reason'), str):
                raise ValueError('Nieprawidłowa historia tras')
            route['auth_status'] = record['auth_status']
            route['reason'] = 'VERIFIED (import niezależnej weryfikacji): ' + record['reason']
            route['effective_guard']['status'] = record['auth_status']

    def stats(records):
        result = {}
        for record in records:
            item = result.setdefault(record['detector'], dict(confirmed=0, rejected=0, unclear=0, total=0))
            item[record['verdict']] += 1
            item['total'] += 1
        for item in result.values():
            item['precision'] = item['confirmed'] / item['total']
            item['degraded'] = item['total'] >= minimum and item['precision'] < threshold
        return result

    local = stats(history.values())
    global_stats = stats(record for records in state['projects'].values() for record in records.values())
    groups = {}
    for row in rows:
        record = history.get(row['finding_id'])
        # Exact installed version + local advisory is a deterministic match,
        # not evidence that an application is exploitable. Never learn precision from it.
        if not record and row.get('deterministic_evidence') == 'exact-version-advisory':
            record = dict(verdict='confirmed', reason='Deterministyczne dopasowanie wersji do lokalnej bazy; exploitability unknown.')
        row['verification_status'] = record['verdict'] if record else 'candidate'
        row['verification_reason'] = record['reason'] if record else 'Brak niezależnego werdyktu; wykonanie weryfikatora: not-run, 0 pkt.'
        row['original_severity'] = row['severity']
        degraded = any(s.get(row['id'], {}).get('degraded', False) for s in (local, global_stats))
        row['detector_degraded'] = degraded
        if degraded:
            row['severity'] = {'critical':'high', 'high':'medium', 'medium':'low', 'low':'info', 'info':'info'}[row['severity']]
        if row['verification_status'] != 'confirmed':
            if row['severity'] in {'high', 'critical'}:
                row['severity'] = 'medium'
            if row['verification_status'] != 'rejected':
                group = groups.setdefault(row['id'], {'detector':row['id'], 'count':0, 'examples':[]})
                group['count'] += 1
                if len(group['examples']) < 5:
                    group['examples'].append(row.copy())
        else:
            row['confidence'] = 'confirmed'
    if state_path:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=state_path.parent, delete=False) as handle:
                temporary = Path(handle.name)
                json.dump(state, handle, ensure_ascii=False, indent=2)
                handle.write('\n')
            os.replace(temporary, state_path)
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)
    return dict(status='imported' if verdicts else 'not-run', score=0, project=local, global_precision=global_stats,
                threshold=threshold, minimum=minimum, persistent=bool(state_path), candidates=list(groups.values()))


def apply(rows, repo, sources, verdicts=None, state_dir=None, threshold=0.3, minimum=10, routes=None):
    if not state_dir:
        return _apply(rows, repo, sources, verdicts, None, threshold, minimum, routes)
    # Serialize read/modify/replace so concurrent reviews cannot lose global samples.
    import fcntl
    directory = Path(state_dir).resolve()
    root = Path(repo).resolve()
    if directory == root or root in directory.parents or directory in root.parents:
        raise ValueError('Stan weryfikacji musi być poza repo')
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / 'verification.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return _apply(rows, repo, sources, verdicts, directory, threshold, minimum, routes)
    finally:
        os.close(descriptor)
