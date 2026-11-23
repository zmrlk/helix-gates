"""Bounded offline evidence scoring; never executes target repository code."""
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re


def assess(root, profile='S', docs_paths=(), _parts=True):
    from helix_new import NEW, SKIP, EXTENSIONS, PLACEHOLDER, bounded, brand_check
    standard = json.loads((NEW / 'profiles/pro-standard.json').read_text())
    from helix_audit_context import config, documents, gates, parts, inventory
    sources = inventory(root)
    cfg = config(root)
    doc_inputs = [*cfg.get('docs_paths', []), *docs_paths]
    external = documents(root, doc_inputs)
    external_names = {}
    for value in doc_inputs:
        base = Path(value).expanduser()
        if not base.is_absolute():
            base = root / base
        base = base.resolve()
        base = base if base.is_dir() else base.parent
        for path in external:
            if Path(path).is_relative_to(base):
                external_names.setdefault(path, set()).add(Path(path).relative_to(base).as_posix())
    custom = gates(root, sources, cfg)
    from helix_project_evidence import mappings
    project_evidence = mappings(root, standard, custom)
    exceptions = []
    try:
        path = bounded(root, 'pro-exceptions.json')
        if path.is_file():
            exceptions = json.loads(path.read_text()).get('exceptions', [])
    except (ValueError, OSError, AttributeError):
        pass  # Malformed exceptions never waive a requirement.
    areas = {}
    blocking = []
    for area in standard['areas']:
        items = []
        for rule in standard['requirements']:
            if rule['area'] != area or profile not in rule['profiles']:
                continue
            evidence = []
            checks = []
            satisfied = True
            for selector in rule['evidence']:
                matches = []
                observed = []
                candidates = [(p, c, [p], '') for p, c in sources.items()]
                if area in ('backend/architecture', 'data', 'ops/reliability', 'documentation'):
                    candidates += [(p, c, external_names.get(p, []), ' (outside repo)') for p, c in external.items()]
                for path, content, names, suffix in candidates:
                    if any(re.search(selector['path'], name) for name in names):
                        match = re.search(selector['pattern'], evidence_content(content, path))
                        rejection = evidence_rejection(content, path)
                        usable = rejection is None
                        observed.append(dict(evidence=path + ':1' + suffix, reason='matched' if match and usable else rejection if not usable else 'content-predicate-not-met'))
                        if match and usable:
                            matches.append(f'{path}:{content[:match.start()].count(chr(10)) + 1}{suffix}')
                checks.append(dict(selector=selector, candidates=observed, matched=bool(matches)))
                satisfied &= bool(matches)
                evidence.extend(matches)
            if satisfied:
                satisfied = control_content(rule['id'], dict(sources, **external), evidence)
            if rule['id'] == 'design-contract'  and satisfied:
                try:
                    satisfied = not brand_check(root)
                except (ValueError, KeyError, TypeError, OSError):
                    satisfied = False
            if rule['id'] == 'design-references' and satisfied:
                satisfied = valid_references(sources.get('design-references.json', ''))
            doc_warnings = []
            if rule['id'] in ('docs-freshness', 'docs-ownership'):
                satisfied, evidence, doc_warnings = documentation_status(root, sources, external, rule['id'])
            if rule['id'] in ('privacy-contract', 'ai-eval-budget', 'license-inventory', 'observability-contract', 'incident-postmortem'):
                # Keep the same approved inventory and path aliases as selector matching.
                contracts = dict(sources)
                for path, content in external.items():
                    for name in external_names.get(path, []):
                        contracts[name] = content
                satisfied = satisfied and populated_contract(contracts, rule)
            waiver = None
            for entry in exceptions if isinstance(exceptions, list) else []:
                if not isinstance(entry, dict) or entry.get('requirement') != rule['id']:
                    continue
                try:
                    valid = date.fromisoformat(entry.get('expires', '')) >= date.today()
                except (ValueError, TypeError):
                    valid = False
                if valid and all(isinstance(entry.get(k), str) and entry[k].strip() for k in ('reason', 'approved_by')):
                    waiver = entry
            item = dict(id=rule['id'], description=rule['description'], weight=rule['weight'], satisfied=bool(satisfied),
                        tag='VERIFIED' if satisfied else 'ASSUMPTION', evidence=sorted(set(evidence)),
                        status='needs-runtime' if rule['runtime'] else ('offline-evidence' if satisfied else 'missing'),
                        runtime=rule['runtime'], threshold=rule['threshold'], source=rule['source'],
                        remediation=rule['remediation'], template=rule['template'], exception=waiver, warnings=doc_warnings, checks=checks,
                        candidate_evidence=sorted({v['evidence'] for check in checks for v in check['candidates']}),
                        assessment_reason='offline selectors met; runtime unverified' if satisfied else 'Not established in bounded inventory; inspect selector candidates and threshold; absence is not a production claim')
            if not satisfied and item['candidate_evidence'] and not rule['runtime']:
                item['status'] = 'insufficient-evidence'
            if any(v['reason'] == 'parser-missing' for check in checks for v in check['candidates']):
                item['status'] = 'assessment-gap'
                item['warnings'].append('YAML parser unavailable; candidate evidence could not be assessed')
            if area == 'testing/CI':
                item.update(runtime=True, status='needs-runtime', execution_status='not-run')
            mapped = project_evidence.get(rule['id'])
            if mapped:
                outcome = mapped['execution']
                passed = outcome['points_eligible']
                item.update(satisfied=True, runtime=not passed, evidence=mapped['evidence'],
                            tag='VERIFIED', status='local-executed' if passed else 'local-unexecuted',
                            execution_status={'passed': 'PASS', 'failed': 'FAIL'}.get(outcome['status'], 'NOT_RUN'), project_gate=mapped['gate'],
                            execution=outcome, assessment_reason=outcome['reason'],
                            evidence_level='dowód lokalny, wykonany' if passed else 'dowód lokalny, nieuruchomiony')
            item['points'] = item['weight'] if item['satisfied'] and not item['runtime'] and not item['exception'] else 0
            items.append(item)
            if not item['satisfied'] and not waiver and profile != 'S' and rule.get('blocking'):
                blocking.append(rule['id'] + ': ' + rule['description'])
        for g in custom:
            if g['area'] == area:
                items.append(dict(id='custom:' + g['name'], description=g['description'], weight=1,
                    satisfied=True, points=0, tag='ASSUMPTION', evidence=[g['evidence']], status='needs-runtime', runtime=True, execution_status='needs-runtime',
                    threshold='Gate passes with retained command output and exit code 0', source='project declaration',
                    remediation=['Review gate scope and map assertions to area requirements.',
                                  'Run ' + g.get('command', 'the gate defined in ' + g['evidence']) + ' in the project test environment.',
                                  'Retain output, report and exit code for acceptance.'], template='ci/e2e.yml', exception=None))
        total = sum(x['weight'] for x in items)
        areas[area] = dict(score=round(100 * sum(x['weight'] for x in items if x['satisfied'] and not x['runtime'] and not x['exception']) / total) if total else 100,
                           preparation_score=min(100, round(100 * sum(x['weight'] for x in items if x['satisfied'] and not x['exception']) / total)) if total else 100,
                           requirements=items, top_gaps=sorted((x for x in items if not x['satisfied'] or x['runtime'] or x.get('execution_status') == 'needs-runtime' or x['exception']), key=lambda x: (-x['weight'], x['id']))[:3])
    overall = round(sum(areas[a]['score'] * standard['area_weights'][a] for a in areas) / sum(standard['area_weights'].values()))
    report = dict(schema_version=2, score=overall, area_weights=standard['area_weights'], profile=profile, scope='offline evidence maturity; runtime and production behavior unverified', areas=areas, blocking=blocking)
    from helix_contracts import VERSION
    report['helix_version'] = VERSION
    report['warnings'] = sorted({w for a in areas.values() for item in a['requirements'] for w in item.get('warnings', [])})
    areas['documentation']['target'] = standard['documentation_thresholds'][profile]
    areas['documentation']['meets_target'] = areas['documentation']['score'] >= areas['documentation']['target']
    report['documents'] = [dict(path=p, lines=len(t.splitlines()), evidence=p + ':1 (outside repo)') for p, t in external.items()]
    report['custom_gates'] = custom
    report['project_evidence'] = project_evidence
    if _parts:
        report['parts'] = []
        for entry in parts(root, cfg):
            result = dict(entry)
            if not entry.get('excluded') and entry.get('status') != 'excluded':
                result['maturity'] = assess(root / entry['path'], profile, list(external), False)
            report['parts'].append(result)
        active = [p['maturity'] for p in report['parts'] if 'maturity' in p]
        if active:
            report['root_score'] = report['score']
            report['score'] = round(sum(p['score'] for p in active) / len(active))
    return report


def control_content(ident, sources, evidence):
    """Additional offline facets for controls formerly matched by a single word.

    These checks establish declarations only, never deployment or test success.
    """
    selected = [evidence_content(text, path) for path, text in sources.items() if any(e.startswith(path + ':') for e in evidence)]
    text = '\n'.join(selected)
    if ident in ('slo', 'ops-slo'):
        def positive(value):
            return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value < float('inf')
        def populated(value):
            return isinstance(value, str) and bool(value.strip())
        for content in selected:
            try:
                try: doc = json.loads(content)
                except ValueError:
                    import yaml
                    doc = yaml.safe_load(content)
                if not isinstance(doc, dict): continue
                rows = doc.get('critical_paths', doc.get('slis', [doc]))
                if not isinstance(rows, list) or not rows: continue
                def valid(row):
                    if not isinstance(row, dict): return False
                    if not populated(row.get('window')): return False
                    if ident == 'slo':
                        rate = row.get('error_rate')
                        return (positive(row.get('p95_ms')) and isinstance(rate, (int, float))
                                and not isinstance(rate, bool) and 0 <= rate < 1 and populated(row.get('owner')))
                    return (positive(row.get('target')) and populated(row.get('error_budget_action'))
                            and populated(row.get('alert_owner')))
                if all(valid(row) for row in rows): return True
            except (ValueError, TypeError, ImportError):
                continue
        return False
    facets = {
        'threat-model': [r'asset|aktywa|zasob', r'trust.?boundar|granice.?zauf', r'abuse|naduży',
                         r'ASVS[^\n]*\d', r'owner|właściciel', r'review|przegląd'],
        'architecture': [r'boundar|granice|modul', r'owner|właściciel', r'decision|decyzj',
                         r'approved|accepted|zatwierdz', r'trigger|próg|threshold'],
        'data-model': [r'relation|references|foreign.?key|relac', r'constraint|primary.?key|ogranicz',
                       r'invariant|check\s*\(|niezmien'],
        'ha': [r'replica|failover', r'recover|odtworz', r'owner|responsib|właściciel'],
        'observability': [r'structured', r'redact', r'metric', r'trac', r'alert', r'owner'],
        'asvs': [r'ASVS[^\n]*\d', r'owner|właściciel', r'negative|negatyw', r'test'],
        'prr': [r'owner|właściciel', r'SLO', r'alert', r'rollback', r'restore', r'review|przegląd'],
    }
    if ident in facets:
        return all(re.search(pattern, text, re.I) for pattern in facets[ident])
    # These thresholds assert concurrency behavior. Static declarations cannot prove it.
    if ident in ('shared-rate-limit', 'distributed-locks'):
        return False
    return True

def evidence_content(content, path):
    """Ignore unfinished Markdown lines without discarding unrelated completed sections.

    Preserve line positions for evidence references. Structured contracts remain strict.
    """
    from helix_new import PLACEHOLDER
    if Path(path).suffix.lower() != '.md':
        return content
    # HTML markup is content formatting, not a template field.
    probe = re.compile(r'</?(?:div|span|br|p|a|img|table|tr|td|th|details|summary|code|pre|strong|em|h[1-6])\b[^>]*>|<https?://[^>]+>', re.I)
    return '\n'.join(' ' * len(line) if PLACEHOLDER.search(probe.sub('', line)) else line
                     for line in content.split('\n'))


def evidence_rejection(content, path):
    """Return a specific assessment gap, or None for usable content."""
    from helix_new import PLACEHOLDER
    if re.search(r'(?im)^ASSUMPTION:\s*draft\b', content):
        return 'empty-or-placeholder'
    if re.search(r"(?i)if you.re seeing this, you.ve probably already|this is a new .* project, bootstrapped|this project was bootstrapped with", content):
        return 'generated-starter'
    content = evidence_content(content, path)
    clean = re.sub(r'</?(?:div|span|br|p|a|img|table|tr|td|th|details|summary|code|pre|strong|em|h[1-6])\b[^>]*>', '', content, flags=re.I)
    clean = re.sub(r'<https?://[^>]+>', '', clean)
    if not clean.strip() or PLACEHOLDER.search(clean):
        return 'empty-or-placeholder'
    if Path(path).suffix.lower() in ('.json', '.yaml', '.yml'):
        try:
            doc = json.loads(clean)
        except ValueError:
            if Path(path).suffix.lower() == '.json':
                return 'malformed-json'
            try:
                import yaml
            except ImportError:
                return 'parser-missing'
            try:
                doc = yaml.safe_load(clean)
            except yaml.YAMLError:
                return 'malformed-yaml'
        if doc is None or doc == {} or doc == [] or doc == '':
            return 'empty-or-placeholder'
    if Path(path).suffix.lower() == '.md':
        prose = '\n'.join(line for line in clean.splitlines()
                          if not line.lstrip().startswith(('#', '```', '---', '|---')))
        if len(re.findall(r'\w+', prose)) < 3:
            return 'empty-or-placeholder'
    return None


def usable_evidence(content, path):
    return evidence_rejection(content, path) is None


def valid_references(content):
    """Validate declared flow coverage; owner still confirms the inventory is complete."""
    try:
        doc = json.loads(content)
        keys, flows = doc['key_flows'], doc['flows']
        if not isinstance(keys, list) or not keys or any(not isinstance(k, str) or not k.strip() for k in keys):
            return False
        if len(set(keys)) != len(keys) or not isinstance(flows, list):
            return False
        if sorted(f['id'] for f in flows) != sorted(keys):
            return False
        for flow in flows:
            refs = flow['references']
            if flow['platform'] not in ('mobile', 'web', 'mobile/web') or not 3 <= len(refs) <= 5:
                return False
            urls = set()
            for ref in refs:
                if not re.fullmatch(r'https?://[^\s/]+(?:/[^\s]*)?', ref['url']) or not ref['rationale'].strip() or not ref['pattern'].strip():
                    return False
                urls.add(ref['url'])
            if len(urls) != len(refs):
                return False
        return True
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def improvement_plan(report):
    """Deterministic proposal only: never executes remediation or waives a gate."""
    if report.get('schema_version') != 2:
        raise ValueError('rerun audit with the current catalog')
    priorities = {'security': 0, 'data': 0, 'ops/reliability': 1}
    gaps = [(area, area, x) for area, result in report['areas'].items()
            for x in result['requirements'] if not x['satisfied'] or x['runtime'] or x.get('execution_status') == 'needs-runtime' or x['exception']]
    for part in report.get('parts', []):
        if 'maturity' in part:
            gaps.extend((part['path'] + '/' + area, area, x) for area, result in part['maturity']['areas'].items() for x in result['requirements'] if not x['satisfied'] or x['runtime'] or x.get('execution_status') == 'needs-runtime' or x['exception'])
    gaps.sort(key=lambda item: (priorities.get(item[1], 2), -item[2]['weight'], item[0], item[2]['id']))
    checkpoints = []
    for label, area, gap in gaps:
        visual = area in ('UX', 'UI') and (gap['runtime'] or gap.get('execution_status') == 'needs-runtime')
        checkpoints.append(dict(id=f'cp{len(checkpoints)+1}', title=f"{label}: {gap['id']}",
            goal=f"Priority P{priorities.get(area, 2)}. ASSUMPTION: owner-confirm applicability; {gap['description']}. " + ' '.join(gap['remediation']),
            test_cases=[f"Verify {gap['id']}: {gap['threshold']}",
                        'Retain G0, behavior and independent review evidence; configuration alone is not runtime proof.'],
            visual=visual, visual_scope='Key mobile/web flow states against approved brand and references' if visual else 'No visual change'))
    return dict(checkpoints=checkpoints)


def markdown(report):
    from helix_paths import summarize
    lines = ['# Helix Pro standard', '', report['scope'], '', f"Weighted overall: {report['score']}/100", '']
    for audit in report.get('legacy_audits', []):
        lines += ['', 'Zrzuty / DOM / waga stron: '+json.dumps(audit, ensure_ascii=False)]
    for area, result in report['areas'].items():
        lines += [f"## {area}: {result['score']}/100", '', f"Preparation: {result['preparation_score']}/100", '']
        for x in result['top_gaps']:
            lines.append(f"- {x.get('tag', 'ASSUMPTION')}: {x['id']}: {x['status']} — {x['description']}")
            if x.get('evidence') and not x['satisfied']:
                lines.append('  Evidence: '+summarize(x['evidence']))
            lines.extend(f"  {i}. {step}" for i, step in enumerate(x['remediation'], 1))
        lines += [f"- VERIFIED: {x['id']}: {x.get('evidence_level', x['status'])} ({summarize(x['evidence'])})" for x in result['requirements'] if x['satisfied']]
        lines.append('')
    lines += ['- WARNING: ' + w for w in report.get('warnings', [])]
    if report.get('documents'):
        lines.append('- VERIFIED documents outside repo: '+summarize((doc['path']+':1' for doc in report['documents']), 'audit.json/maturity/documents'))
    for part in report.get('parts', []):
        lines.append(f"Part {part['path']} ({part.get('status', 'active')}): " + (str(part['maturity']['score']) + '/100' if 'maturity' in part else 'excluded'))
    return '\n'.join(lines)


def populated_contract(sources, rule):
    """Reject empty nested contracts rather than scoring key names alone."""
    def populated(value):
        if isinstance(value, dict): return bool(value) and all(populated(v) for v in value.values())
        if isinstance(value, list): return bool(value) and all(populated(v) for v in value)
        if isinstance(value, str): return bool(value.strip())
        return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
    for path, content in sources.items():
        if re.search(rule['evidence'][0]['path'], path):
            try:
                doc = json.loads(content)
                from helix_new import schema_check, load, NEW
                schema = load(NEW / 'schemas' / rule['template'].replace('.tpl', ''))
                if not schema_check(doc, schema) and populated(doc):
                    if rule['id'] == 'ai-eval-budget' and not {'injection', 'refusal', 'quality-pl', 'extraction'} <= {x['category'] for x in doc['cases']}:
                        continue
                    return True
            except (ValueError, TypeError):
                pass
    return False


def documentation_status(root, sources, external, control):
    """Every Markdown document needs ownership and explicit described-code links.

    Paths are resolved against the metadata file, then checked against the
    bounded audit inventory. No metadata reference can trigger another read.
    """
    inventory = {str((root / p).resolve()): text for p, text in sources.items()}
    inventory.update(external)
    markdown_docs = {p for p, text in inventory.items() if Path(p).suffix.lower() == '.md' and not PLACEHOLDER_DOC.search(text)}
    structured_docs = {p for p, text in inventory.items()
                       if re.fullmatch(r'(?:openapi|swagger|data-model|schema)\.(?:json|ya?ml)', Path(p).name, re.I)
                       and not PLACEHOLDER_DOC.search(text)}
    docs = markdown_docs | structured_docs
    metadata, errors, warnings, evidence = {}, [], [], []
    for path, text in inventory.items():
        if Path(path).name != 'docs-metadata.json':
            continue
        try:
            entries = json.loads(text)['documents']
            if not isinstance(entries, list):
                raise ValueError('documents must be a list')
            for entry in entries:
                doc = str((Path(path).parent / entry['path']).resolve())
                if doc in metadata:
                    errors.append('documentation: duplicate metadata ' + doc)
                metadata[doc] = (entry, Path(path).parent)
        except (ValueError, KeyError, TypeError):
            errors.append('documentation: invalid metadata ' + path)
    fresh = bool(markdown_docs)
    has_code = False
    for doc in sorted(docs):
        if doc not in metadata:
            errors.append('documentation: missing owner/review metadata ' + doc)
            continue
        entry, base = metadata[doc]
        try:
            if not isinstance(entry.get('owner'), str) or not entry['owner'].strip():
                raise ValueError('owner required')
            reviewed = date.fromisoformat(entry.get('reviewed', ''))
            if reviewed > datetime.now(timezone.utc).date():
                raise ValueError('future review')
            links = entry.get('code')
            if not isinstance(links, list) or any(not isinstance(x, str) or not x for x in links):
                raise ValueError('explicit code list required')
            for link in links:
                code = str((base / link).resolve())
                if code not in inventory or Path(code).suffix.lower() in ('.md', '.json', '.yaml', '.yml', '.txt'):
                    errors.append('documentation: described code missing from inventory ' + str(link))
                    continue
                has_code |= doc in markdown_docs
                code_date = datetime.fromtimestamp(Path(code).stat().st_mtime, timezone.utc).date()
                if Path(doc).stat().st_mtime_ns < Path(code).stat().st_mtime_ns or reviewed < code_date:
                    fresh = False
                    warnings.append('documentation: stale ' + doc + ' describes ' + code)
            evidence.append(doc + ':1 (owner and review metadata; offline mtime heuristic)')
        except (ValueError, TypeError):
            errors.append('documentation: valid owner and ISO review date required ' + doc)
    warnings += errors
    ok = bool(docs) and not errors
    if control == 'docs-freshness':
        ok = ok and fresh and has_code
    return ok, evidence if ok else [], warnings


# HTML and Markdown autolinks are document content, not draft markers.
PLACEHOLDER_DOC = re.compile(r'\b(TODO|TBD|FIXME)\b', re.I)
