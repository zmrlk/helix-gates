"""Profile-dependent preparation checklist; lexical signals earn no execution points."""
import json
from pathlib import Path
import re

POLICY = Path(__file__).resolve().parents[1] / 'data/quality-domains.json'


def located_matches(pattern, text, flags=0):
    """Locate ordered matches with one pass over newline spans, not prefixes."""
    line, cursor = 1, 0
    for match in re.finditer(pattern, text, flags):
        line += text.count('\n', cursor, match.start())
        cursor = match.start()
        yield match, line


def analyze(sources, profile=None):
    profile = profile or {}
    if not isinstance(profile, dict) or not isinstance(profile.get('controls',{}),dict):
        raise ValueError('profil dziedziny wymaga mapy')
    if any(not isinstance(v,dict) for v in profile.get('controls',{}).values()):
        raise ValueError('wyłączenie kontroli wymaga mapy')
    checks, findings = [], []
    for spec in json.loads(POLICY.read_text())['checks']:
        declarations = [profile.get(k) for k in spec['requires']]
        override = profile.get('controls', {}).get(spec['id'], {})
        if override.get('applicable') is False:
            if not str(override.get('reason','')).strip(): raise ValueError('N/A wymaga powodu: ' + spec['id'])
            checks.append(dict(spec, status='N/A', reason=override['reason'], score=0, evidence=[]))
            continue
        excluded = [k for k in spec['requires'] if isinstance(profile.get(k), dict) and profile[k].get('applicable') is False]
        if excluded:
            reasons = [str(profile[k].get('reason', '')).strip() for k in excluded]
            if not all(reasons): raise ValueError('N/A wymaga powodu: ' + spec['id'])
            checks.append(dict(spec, status='N/A', reason='; '.join(reasons), score=0, evidence=[]))
            continue
        evidence = []
        for name, text in sources.items():
            previous_line = None
            for _, line in located_matches(spec['signal'], text, re.I):
                if line != previous_line:
                    evidence.append(f'{name}:{line}')
                    previous_line = line
            if spec['id'] == 'test-flaky' and re.search(r'(?:test|spec)', name, re.I):
                for m, line in located_matches(r'retries\s*[:=]\s*[1-9]|retry\s*\(|(?:time\.sleep|waitForTimeout)\s*\(', text):
                    findings.append(dict(id='QA-FLAKY-SIGNAL', lens='qa', title='Retry lub stałe oczekiwanie w teście',
                        file=name, line=line, severity='medium', confidence='possible',
                        why='Sygnał może ukrywać niestabilność; nie dowodzi flaky bez historii wykonań.',
                        fix='Czekaj na warunek i porównaj historię powtórzeń.', evidence=[f'{name}:{line}']))
        checks.append(dict(spec, status='not-run', score=0, evidence=evidence,
                           reason='Sygnały przygotowania; brak dowodu wykonania.' if not declarations or all(v is True or isinstance(v, dict) and v.get('applicable') is True for v in declarations) else 'Zastosowanie wymaga potwierdzenia profilu; brak wyłączenia nie daje N/A.'))
    consent_check = next(c for c in checks if c['id'] == 'eu-consent')
    if consent_check['status'] != 'N/A':
        for name, text in sources.items():
            for m, line in located_matches(r'<script[^>]*src=[\"\'][^\"\']*(?:googletagmanager|google-analytics|connect\.facebook|matomo)[^\"\']*[\"\'][^>]*>', text, re.I):
                if re.search(r'consent|cookie|type=[\"\']text/plain', m[0], re.I): continue
                findings.append(dict(id='COMPLIANCE-CONSENT',lens='security',file=name,line=line,
                    title='Statyczny skrypt trackera bez jawnej bramki zgody',severity='medium',confidence='possible',
                    why='Tag nie pokazuje warunku zgody; zewnętrzny mechanizm pozostaje nieznany.',
                    fix='Wstrzymaj ładowanie do zgody i potwierdź kolejność żądań testem runtime.',evidence=[f'{name}:{line}']))
    test_counts = dict.fromkeys(('unit', 'integration', 'e2e', 'unclassified'), 0)
    for name in sources:
        if not re.search(r'(?:test|spec)', name, re.I): continue
        kind = next((k for k in ('integration','e2e','unit') if k in name.lower()), 'unclassified')
        test_counts[kind] += 1
    total = sum(test_counts.values())
    return dict(checks=checks, findings=findings, test_pyramid=dict(files=test_counts,
        proportions={k: v / total if total else 0 for k,v in test_counts.items()},
        reason='Klasyfikacja ścieżek plików, nie liczba przypadków ani dowód wykonania; brak uniwersalnego progu.'),
        execution_status='not-run', score=0,
        limitations=['Checklista gotowości, nie certyfikacja prawna.', 'Historia flaky i zachowanie trackerów wymagają dowodów runtime.'])
