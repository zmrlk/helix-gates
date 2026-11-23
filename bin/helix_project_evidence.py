"""Imported project gate evidence; never executes a declared command."""
import hashlib
import json
from pathlib import Path
import re

from helix_audit_context import safe_read


def local(root, name):
    from helix_new import bounded
    if not isinstance(name, str) or not name:
        raise ValueError('evidence: local file required')
    path = bounded(root, name)
    text = safe_read(path, errors='strict')
    if not text.strip():
        raise ValueError('evidence: empty file: ' + name)
    return text


def execution(root, run):
    """Validate a local receipt, not the authenticity of its external host."""
    missing = dict(status='not-run', points_eligible=False, reason='no execution receipt')
    if run is None:
        return missing
    if not isinstance(run, dict):
        return dict(missing, reason='invalid execution receipt')
    if run.get('status') != 'passed' or type(run.get('exit')) is not int or run['exit'] != 0:
        return dict(missing, status='failed' if run.get('status') == 'failed' else 'not-run', reason='no passing execution')
    if not all(isinstance(run.get(k), str) and run[k].strip() for k in ('who', 'where', 'command', 'sha', 'log', 'log_sha256')):
        return dict(missing, reason='incomplete execution receipt')
    try:
        files = run.get('files')
        if not isinstance(files, dict) or not files:
            return dict(missing, reason='source file hashes required')
        for name, digest in files.items():
            if hashlib.sha256(local(root, name).encode()).hexdigest() != digest:
                return dict(missing, reason='source file hash mismatch')
        text = local(root, run['log'])
        if hashlib.sha256(text.encode()).hexdigest() != run['log_sha256']:
            return dict(missing, reason='log hash mismatch')
        from helix_git_readonly import read_ref
        current = read_ref(root, require_root=True)['head']
        if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', run['sha']) or run['sha'] != current:
            return dict(missing, reason='source revision mismatch or unknown')
    except (ValueError, OSError, UnicodeError):
        return dict(missing, reason='execution log or source revision unavailable')
    return dict(status='passed', points_eligible=True, reason='local receipt; host authenticity not established',
                evidence=run['log'], sha=run['sha'], log_sha256=run['log_sha256'])


def mappings(root, standard, custom):
    path = root / 'pro-evidence.json'
    if not path.exists() and not path.is_symlink():
        return {}
    data = json.loads(local(root, 'pro-evidence.json'))
    if not isinstance(data, dict) or data.get('schema_version') != 1 or not isinstance(data.get('controls'), list):
        raise ValueError('pro-evidence: schema_version=1 and controls required')
    rules = {r['id']: r for r in standard['requirements']}
    gates = {g['name']: g for g in custom}
    result = {}
    for entry in data['controls']:
        if not isinstance(entry, dict):
            raise ValueError('pro-evidence: invalid control')
        ident, name = entry.get('requirement'), entry.get('gate')
        if not isinstance(ident, str) or ident not in rules or ident in result:
            raise ValueError('pro-evidence: unknown or duplicate requirement')
        if not isinstance(name, str) or name not in gates or gates[name]['area'] != rules[ident]['area']:
            raise ValueError('pro-evidence: gate must exist in the requirement area')
        refs = entry.get('evidence')
        if not isinstance(refs, list) or not refs:
            raise ValueError('pro-evidence: nonempty local citations required')
        for ref in refs:
            match = re.fullmatch(r'(.+):([1-9][0-9]*)', ref) if isinstance(ref, str) else None
            if not match or int(match[2]) > len(local(root, match[1]).splitlines()):
                raise ValueError('pro-evidence: invalid local citation')
        run = entry.get('run')
        outcome = execution(root, run)
        files = run.get('files', {}) if isinstance(run, dict) else {}
        if outcome['points_eligible'] and not all(ref.rsplit(':', 1)[0] in files for ref in refs):
            outcome = dict(status='not-run', points_eligible=False, reason='cited files absent from source hashes')
        result[ident] = dict(gate=name, evidence=refs, execution=outcome)
    return result


def modules(root, document, project_gates=()):
    if not isinstance(document, dict) or not isinstance(document.get('catalog'), list) or not isinstance(document.get('modules'), list) or not document['modules']:
        raise ValueError('AI modules: nonempty modules and catalog required')
    catalog = document['catalog']
    if not catalog or any(not isinstance(c, str) or not c.strip() for c in catalog) or len(set(catalog)) != len(catalog):
        raise ValueError('AI modules: invalid catalog')
    # Same contract for AI and human modules; project gates cannot be omitted.
    required = sorted({'contract', 'tests', 'permissions', 'appearance', *project_gates})
    rows, ids = [], set()
    for module in document['modules']:
        if not isinstance(module, dict) or not isinstance(module.get('id'), str) or not module['id'].strip() or module['id'] in ids:
            raise ValueError('AI modules: invalid or duplicate module ID')
        ids.add(module['id'])
        local(root, module.get('path'))
        used, runs = module.get('components'), module.get('gates')
        if not isinstance(used, list) or any(not isinstance(c, str) for c in used) or not isinstance(runs, dict):
            raise ValueError('AI modules: explicit components and gates required')
        unknown = sorted(set(used) - set(catalog))
        outcomes = {gate: execution(root, runs.get(gate)) for gate in required}
        for gate, result in outcomes.items():
            run = runs.get(gate)
            files = run.get('files', {}) if isinstance(run, dict) else {}
            if result['points_eligible'] and module['path'] not in files:
                outcomes[gate] = dict(status='not-run', points_eligible=False, reason='module absent from source hashes')
        okay = not unknown and all(g['points_eligible'] for g in outcomes.values())
        rows.append(dict(id=module['id'], status='PASS' if okay else 'FAIL', non_catalog_components=unknown,
                         gates=outcomes, points=100 if okay else 0))
    return dict(status='PASS' if all(r['status'] == 'PASS' for r in rows) else 'FAIL', modules=rows,
                required_gates=required, scope='local declared component inventory and execution receipts; production unverified')


def refresh_points(maturity):
    """Keep per-control points consistent after importing runtime evidence."""
    for area in maturity.get('areas', {}).values():
        for item in area.get('requirements', []):
            item['points'] = item['weight'] if item['satisfied'] and not item['runtime'] and not item.get('exception') else 0
    for part in maturity.get('parts', []):
        if 'maturity' in part:
            refresh_points(part['maturity'])
