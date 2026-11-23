"""Offline platform program and design-decision contracts; no target execution."""
import json
from pathlib import Path

PRODUCTS = ('merchant-admin', 'consumer-app', 'pos', 'payments', 'fulfillment',
            'billing', 'partner-app-ecosystem', 'analytics', 'internal-tools')


def platform_check(doc):
    from helix_new import schema_check, load, NEW
    errors = schema_check(doc, load(NEW / 'schemas/platform.json'), 'platform')
    if errors:
        return errors
    def indexed(rows, label):
        result = {x['id']: x for x in rows}
        if len(result) != len(rows):
            errors.append('platform: duplicate ' + label)
        return result
    products = indexed(doc['products'], 'product')
    contexts = indexed(doc['contexts'], 'context')
    teams = indexed(doc['teams'], 'team')
    caps = indexed(doc['capabilities'], 'capability')
    milestones = indexed(doc['milestones'], 'milestone')
    if not set(PRODUCTS) <= products.keys():
        errors.append('platform: missing portfolio products')
    def refs(values, target, label):
        if any(v not in target for v in values):
            errors.append('platform: orphan ' + label)
    for c in contexts.values():
        refs(c['depends_on'], contexts, 'context dependency')
        refs([c['team']], teams, 'context team')
    for c in caps.values():
        refs([c['product']], products, 'capability product')
        refs([c['context']], contexts, 'capability context')
    for p in products:
        if not any(c['product'] == p for c in caps.values()):
            errors.append('platform: uncovered product capability ' + p)
        if not any(m['product'] == p for m in milestones.values()):
            errors.append('platform: missing product roadmap ' + p)
    for team in teams.values():
        refs(team['contexts'], contexts, 'team context')
        for context in team['contexts']:
            if context in contexts and contexts[context]['team'] != team['id']:
                errors.append('platform: conflicting context ownership')
    for c in contexts.values():
        if c['team'] in teams and c['id'] not in teams[c['team']]['contexts']:
            errors.append('platform: context missing from team boundary')
        if not any(cap['context'] == c['id'] for cap in caps.values()):
            errors.append('platform: uncovered context capability')
    for m in milestones.values():
        refs([m['product']], products, 'milestone product')
        refs(m['depends_on'], milestones, 'milestone dependency')
        refs([m['team']], teams, 'milestone team')
        contracts = [c['milestone'] for c in m['dependency_contracts']]
        if set(contracts) != set(m['depends_on']) or len(contracts) != len(set(contracts)):
            errors.append('platform: dependency contract missing')
    visited, active = set(), set()
    def visit(key):
        if key in active:
            errors.append('platform: roadmap cycle'); return
        if key in visited or key not in milestones:
            return
        active.add(key)
        for dep in milestones[key]['depends_on']:
            visit(dep)
        active.remove(key); visited.add(key)
    for key in milestones:
        visit(key)
    return errors


def decision_check(value):
    from helix_new import schema_check, load, NEW
    errors = schema_check(value, load(NEW / 'schemas/design-decision.json'), 'design decision')
    if not errors:
        ids = [x['id'] for x in value['alternatives']]
        if len(set(ids)) != len(ids) or value['selected'] not in ids:
            errors.append('design decision: selected variant missing or duplicate')
        from datetime import datetime
        try:
            if datetime.fromisoformat(value['accepted_at'].replace('Z', '+00:00')).tzinfo is None:
                errors.append('design decision: acceptance needs timezone')
        except ValueError:
            errors.append('design decision: invalid acceptance timestamp')
        if len({x['approach'].strip().lower() for x in value['alternatives']}) < 2:
            errors.append('design decision: alternatives must describe distinct approaches')
    return errors


def checkpoint_decision(root, checkpoint):
    """Called before implementer or git; approval is supplied by a human, never inferred."""
    from helix_new import bounded, load
    path = bounded(root, 'design-decisions/' + checkpoint + '.json')
    if not path.is_file():
        return ['design decision before implementation: missing ' + str(path)]
    return decision_check(load(path))


def explanation_check(text):
    import re
    match = re.search(r'(?im)^## (?:What changed and why|Co zmieniono i dlaczego)\s*\n(.*?)(?=\n## |\Z)', text, re.S)
    from helix_new import PLACEHOLDER
    if not match or len(match[1].split()) < 8 or PLACEHOLDER.search(match[1]):
        return ['handoff: populated What changed and why section required (at least 8 words)']
    return []


def system_map(inventory, sources):
    """Bounded static import hints; explicitly not a production topology."""
    from helix_import_hints import modules
    components = [{'id': x['path'], 'evidence': x['evidence']} for x in inventory if any(c.startswith('language:') for c in x['categories'])]
    edges, unresolved = [], []
    for item in components:
        targets, reason = modules(item['id'], sources.get(item['id'], ''))
        if reason:
            unresolved.append(dict(file=item['id'], reason=reason))
        for target in sorted(targets):
            edges.append(dict(source=item['id'], target=target, tag='ASSUMPTION', reason='static import hint; unresolved dependency'))
    return dict(tag='ASSUMPTION', scope='bounded static components and import hints; not runtime topology', components=components, dependencies=edges, unresolved=unresolved)
