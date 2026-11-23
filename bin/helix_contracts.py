"""Offline field-work contracts. Input is data; never executes commands or git."""
import itertools
import json
from datetime import date, datetime, timezone
from pathlib import Path

VERSION = '0.9.3-beta'


def artifact(root, value):
    if not isinstance(value, str) or not value:
        return False
    p = (Path(root) / value).resolve()
    return p.is_relative_to(Path(root).resolve()) and p.is_file() and p.stat().st_size > 0


def executed(root, run):
    return (isinstance(run, dict) and run.get('status') == 'passed'
            and type(run.get('exit')) is int and run['exit'] == 0
            and all(run.get(k) for k in ('who', 'where', 'sha', 'command'))
            and artifact(root, run.get('log')))


def check_pin(root):
    from helix_config import load
    data = load(root)
    if not data:
        # Brak pliku to inna przyczyna niż zła wersja: bez tego rozróżnienia audyt cudzego repo pada bez wskazówki.
        raise ValueError('version: brak helix.json w repo; podaj --config PLIK z {"helix_version": "' + VERSION
                         + '"} poza repo albo utwórz helix.json (helix.json must pin running Helix version ' + VERSION + ')')
    if not isinstance(data, dict) or data.get('helix_version') != VERSION:
        raise ValueError('version: helix.json must pin running Helix version ' + VERSION)


def domain_errors(domain):
    errors = []
    if not isinstance(domain, dict):
        return ['domain: map required']
    for kind in ('mechanisms', 'patterns', 'components', 'industries'):
        nodes = domain.get(kind)
        if not isinstance(nodes, dict) or not nodes or any(not isinstance(k, str) or not k.strip() for k in nodes):
            errors.append('domain: nonempty ' + kind + ' required')
    if errors:
        return errors
    for left, right in (('mechanisms', 'patterns'), ('patterns', 'components'), ('components', 'industries')):
        for ident, refs in domain[left].items():
            if not isinstance(refs, list) or not refs or any(not isinstance(v, str) or v not in domain[right] for v in refs):
                errors.append('domain: dangling or missing links for ' + ident)
    return errors


def ui_conflict(conflict):
    import re
    return isinstance(conflict, str) and bool(re.search(
        r'(?:\.(?:tsx|jsx|vue|svelte|html|css|scss|svg)(?::|$)|(?:^|/)(?:ui|frontend|components|screens)/)', conflict, re.I))


def validate(root, data):
    errors, warnings = [], []
    def require(ok, message):
        if not ok:
            errors.append(message)
    for key in ('decisions', 'merge', 'runs', 'rule_changes', 'budget', 'registry', 'domain',
                'modules', 'catalog', 'owner_report', 'comparisons', 'documentation'):
        require(key in data, 'contract: explicit section required: ' + key)
    for key in ('decisions', 'runs', 'registry', 'domain', 'documentation', 'owner_report', 'budget'):
        require(bool(data.get(key)), 'contract: nonempty section required: ' + key)
    for d in data.get('decisions', []):
        require(isinstance(d.get('number'), int) and d['number'] > 0, 'decision: positive number required')
        require(bool(d.get('executors')) and set(d['executors']) <= set(d.get('acknowledged', [])), 'decision: missing executor acknowledgement')
        require(bool(d.get('test')) and executed(root, d.get('run')), 'decision: enforcing test must pass')
    numbers = [d.get('number') for d in data.get('decisions', [])]
    require(len(numbers) == len(set(numbers)), 'decision: duplicate number')
    merge = data.get('merge', {})
    resolutions = merge.get('resolutions', [])
    require(len({r.get('conflict') for r in resolutions}) == len(resolutions), 'merge: duplicate resolution')
    require(set(merge.get('conflicts', [])) == {r.get('conflict') for r in resolutions}, 'merge: every conflict needs resolution')
    for r in resolutions:
        require(bool(r.get('reviewer')) and bool(r.get('reason')) and r.get('choice') in ('manual', 'ours', 'theirs'), 'merge: reviewed resolution and reason required')
        if r.get('ui') or ui_conflict(r.get('conflict')):
            require(all(artifact(root, r.get(k)) for k in ('before', 'after')), 'merge: UI before/after artifacts required')
    for run in data.get('runs', []):
        require(executed(root, run), 'run: unexecuted tests earn zero points')
        require(artifact(root, run.get('tree')), 'host: DOM/accessibility tree required')
    for change in data.get('rule_changes', []):
        require(all(change.get(k) for k in ('id', 'reason', 'bad_case')) and executed(root, change.get('self_test')), 'rule: reason, registry ID and negative self-test required')
    budget = data.get('budget', {})
    rules = budget.get('rules', [])
    require(type(budget.get('shards', 1)) is int and budget.get('shards', 1) > 0, 'budget: positive shard count required')
    for rule in rules:
        require(all(isinstance(rule.get(k), (int, float)) and not isinstance(rule.get(k), bool) and rule[k] >= 0 for k in ('seconds', 'limit')), 'budget: nonnegative measured cost and limit required')
        require(bool(rule.get('component')), 'budget: component required')
        if isinstance(rule.get('seconds'), (int, float)) and isinstance(rule.get('limit'), (int, float)) and rule['seconds'] > rule['limit']:
            warnings.append('budget: rule ' + str(rule.get('id')) + ' exceeded')
    for component, limit in budget.get('components', {}).items():
        if sum(r['seconds'] for r in rules if r.get('component') == component and isinstance(r.get('seconds'), (int, float))) > limit:
            warnings.append('budget: component ' + component + ' exceeded')
    registry = data.get('registry', [])
    ids, prefixes = set(), {}
    for entry in registry:
        ident, kind, prefix = (entry.get(k) for k in ('id', 'type', 'prefix'))
        require(bool(ident and kind and prefix and entry.get('reserved_by')), 'registry: reserve ID before use')
        require(ident not in ids, 'registry: duplicate ID')
        ids.add(ident)
        require(prefix not in prefixes or prefixes[prefix] == kind, 'registry: prefix collision')
        prefixes[prefix] = kind
        require(isinstance(ident, str) and isinstance(prefix, str) and ident.startswith(prefix), 'registry: ID prefix mismatch')
    errors.extend(domain_errors(data.get('domain', {})))
    product = data.get('product')
    if product is not None:
        axes = product.get('axes', {})
        require(all(axes.get(k) for k in ('theme', 'radius', 'shape', 'density')), 'product: four configuration axes required')
        keys = sorted(axes)
        expected = list(itertools.product(*(axes[k] for k in keys)))
        cases = product.get('cases', [])
        for values in expected:
            require(any(c.get('config') == dict(zip(keys, values)) and executed(root, c.get('run')) and c.get('contrast_passed') is True for c in cases), 'product: missing passing configuration/contrast ' + str(values))
    for module in data.get('modules', []):
        require(set(module.get('components', [])) <= set(data.get('catalog', [])), 'module: non-catalog component')
        for gate in ('contract', 'tests', 'permissions', 'appearance'):
            require(executed(root, module.get('gates', {}).get(gate)), 'module: missing passing ' + gate)
    owner = data.get('owner_report')
    if owner is not None:
        require(bool(owner.get('state')) and artifact(root, owner.get('current')), 'owner: one current artifact required')
        require(owner.get('current') not in owner.get('obsolete', []), 'owner: current artifact marked obsolete')
        require(all(artifact(root, p) for p in owner.get('screenshots', [])), 'owner: missing screenshot')
        require('gates' in owner and 'decisions' in owner, 'owner: gates and pending decisions required')
    pin = data.get('helix_version')
    require(pin == VERSION, 'version: project must pin running Helix version')
    for comparison in data.get('comparisons', []):
        require(comparison.get('before_version') == comparison.get('after_version') == pin, 'version: comparison requires same pinned version')
    for doc in data.get('documentation', []):
        require(bool(doc.get('owner')) and artifact(root, doc.get('path')), 'documentation: owner and file required')
        try:
            reviewed = date.fromisoformat(doc.get('reviewed', ''))
            require(reviewed <= datetime.now(timezone.utc).date(), 'documentation: future review date')
            for code in doc.get('code', []):
                require(artifact(root, code), 'documentation: missing described code')
                if artifact(root, code) and datetime.fromtimestamp((Path(root) / code).stat().st_mtime, timezone.utc).date() > reviewed:
                    warnings.append('documentation: stale ' + str(doc.get('path')))
        except (ValueError, TypeError):
            errors.append('documentation: ISO review date required')
    selected = [r for r in rules if not budget.get('fast') or r.get('component') in budget.get('affected', [])]
    shards = budget.get('shards', 1)
    batches = [selected[i::shards] for i in range(shards)] if type(shards) is int and shards > 0 else []
    return dict(helix_version=VERSION, schema_version=1, status='FAIL' if errors else 'PASS', errors=errors, warnings=warnings,
                points=sum(bool(executed(root, r)) for r in data.get('runs', [])), batches=batches)


def parsers(sp):
    for name in ('contracts', 'merge-audit', 'owner-report'):
        p = sp.add_parser(name, help='Offline field-work contracts (no git or commands)')
        p.add_argument('--input', default=None if name == 'owner-report' else 'helix-contracts.json')
        if name == 'owner-report':
            p.add_argument('--evidence', action='append', metavar='DIR', help='Agreguj istniejące raporty z katalogu; można powtórzyć')
        p.add_argument('--out', required=True)
        p.add_argument('--profile', choices=['standard', 'configurable-product'], default='standard')


def _dispatch(args):
    root = Path(args.repo).resolve()
    if args.cmd == 'owner-report' and not args.input:
        import helix_owner_report
        return helix_owner_report.dispatch(args)
    if not artifact(root, args.input):
        raise ValueError('contract input must be a nonempty project file')
    data = json.loads((root / args.input).read_text())
    result = validate(root, data)
    try:
        check_pin(root)
    except (OSError, ValueError, TypeError):
        result['errors'].append('version: helix.json must pin running Helix version')
    if args.profile == 'configurable-product' and not data.get('product'):
        result['errors'].append('product: configuration matrix required')
    if args.cmd == 'merge-audit' and not data.get('merge', {}).get('conflicts'):
        result['errors'].append('merge: explicit conflict inventory required')
    if args.cmd == 'owner-report' and not data.get('owner_report'):
        result['errors'].append('owner: report contract required')
    result['status'] = 'FAIL' if result['errors'] else 'PASS'
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.cmd == 'owner-report':
        owner = data.get('owner_report', {})
        from helix_continuity import Continuity
        enabled = any(Continuity(root).path('agent-policy.' + ext).exists() for ext in ('json', 'yaml'))
        continuity = Continuity(root).report(data.get('continuity_base')) if enabled else {'status': 'NOT_CONFIGURED'}
        if enabled and continuity['status'] != 'PASS':
            result['errors'].append('continuity: dryf lub niekompletny stan sesji')
            result['status'] = 'FAIL'
        import helix_owner_report
        details = out.with_suffix('.json')
        if details == out:
            details = out.with_name(out.stem + '-details.json')
        projection = helix_owner_report.build(data, result, continuity, details.name, root)
        from helix_requirements import reject_secrets
        reject_secrets(projection)
        details.write_text(json.dumps(projection, indent=2, ensure_ascii=False) + '\n')
        out.write_text(helix_owner_report.markdown(projection))
    else:
        out.write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'] + ': ' + str(out))
    return 2 if result['errors'] else 0


def dispatch(args):
    try:
        return _dispatch(args)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print('ERROR: invalid contract: ' + str(exc))
        return 2
