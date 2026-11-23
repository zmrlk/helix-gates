"""Per-part projections over shared detectors; execution and maturity stay separate."""
import json
import re
from pathlib import Path
from helix_audit_context import inventory, parts, config
from helix_tool_adapters import REGISTRY

POLICY = Path(__file__).resolve().parents[1] / 'data/senior-pipeline.json'


def calibrate(controls, findings=()):
    applicable = [c for c in controls if c['status'] != 'not-applicable']
    for c in controls:
        if c['status'] == 'not-applicable' and not c.get('reason'):
            raise ValueError('N/A wymaga powodu')
        if c['status'] not in {'not-applicable', 'not-run', 'observed'}:
            raise ValueError('nieznany status kontroli')
        if c.get('level') is not None and not 0 <= c['level'] <= 5:
            raise ValueError('poziom dojrzałości: 0..5')
    points = sum((c.get('level') or 0) if c['status'] == 'observed' and c.get('evidence') else 0 for c in applicable)
    penalty = sum({'critical':20,'high':10,'medium':3,'low':1}.get(f['severity'],0) for f in findings)
    return dict(maturity_score=max(0, round(100*points/(5*len(applicable)))-penalty) if applicable else None,
        execution_score=0, execution_debt=sum(c['status']=='not-run' for c in applicable),
        gate='BLOCK' if any(f['severity'] in {'high','critical'} for f in findings) else 'UNKNOWN',
        reason='Ocena pomocnicza ze źródeł; brak dowodu wykonania. HIGH/critical blokują niezależnie.')


def build(repo, findings, lenses):
    root = Path(repo).resolve()
    policy = json.loads(POLICY.read_text())
    files = inventory(root)
    detected = parts(root, config(root))
    scopes = [dict(path='.', reason='Pliki wspólne i korzeń'), *detected]
    results = []
    for part in scopes:
        prefix = part['path']
        def belongs(file):
            if prefix != '.': return file.startswith(prefix + '/')
            return not any(file.startswith(p['path'] + '/') for p in detected)
        names = [f for f in files if belongs(f)]
        roles = {}
        for role, spec in policy['roles'].items():
            selected = [f for f in findings if belongs(f['file']) and (role == f['lens'] or role in f.get('sources', []))]
            controls = []
            for control in policy['controls']:
                evidence = [f + ':1' for f in names if re.search(control['pattern'], f)]
                controls.append(dict(id=control['id'], status='observed' if evidence else 'not-run',
                    level=control['level'] if evidence else None, evidence=evidence,
                    reason=control['why'] if evidence else 'Brak dowodu; kontrola nieuruchomiona.'))
            if role in {'ui_designer', 'ux_designer'} and not any(Path(n).suffix in {'.html','.svelte','.vue','.jsx','.tsx','.css'} for n in names):
                controls = [dict(id='ui-profile', status='not-applicable', level=None, evidence=[],
                    reason='Brak rozpoznanych źródeł UI w tej części; dynamiczne UI poza zakresem profilu.')]
            tools = [dict(tool=t, status='not-run', reason='Pipeline statyczny; użyj tools scan na kopii offline.')
                     for t in spec['tools'] if t in REGISTRY]
            # Niewykonane narzędzia pozostają długiem, bez punktów.
            scoring_controls = list(controls)
            scoring_controls += [dict(id='tool:'+t['tool'], status='not-run', level=0, evidence=[]) for t in tools] if not all(c['status']=='not-applicable' for c in controls) else []
            roles[role] = dict(checklist=spec['checklist'], controls=controls, tools=tools, findings=selected,
                adversarial_pass=dict(status='static_only', checks=spec['adversarial'],
                    observations=[f['id'] for f in selected], reason='Hipotezy nadużyć; brak wykonania scenariuszy.'),
                **calibrate(scoring_controls, selected))
        results.append(dict(part=prefix, files=len(names), roles=roles))
    return dict(schema_version=1, parts=results, levels=['brak','ad hoc','zdefiniowane','egzekwowane','mierzone','optymalizowane'],
        limitations=['Heurystyki struktury dają najwyżej poziom 2; poziomy 3–5 wymagają niezależnych dowodów.',
                      'Adaptery niewykonane: jawny dług, bez punktów; brak automatycznej zgodności prawnej.'])
