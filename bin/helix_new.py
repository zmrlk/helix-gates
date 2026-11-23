"""Offline project preparation. Repository contents are data, never executable input."""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
from helix_paths import within
from helix_dependencies import load_yaml, MissingDependency

HOME = Path(__file__).resolve().parent.parent
NEW = HOME / 'new'
PLACEHOLDER = re.compile(r'\b(TODO|TBD|FIXME)\b|<[^>]+>', re.I)


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def load(path):
    try:
        from helix_contracts import VERSION
        return json.loads(path.read_text().replace('{{HELIX_VERSION}}', VERSION))
    except json.JSONDecodeError:
        try:
            return load_yaml(path)
        except MissingDependency:
            raise
        except Exception as exc:
            raise ValueError('invalid YAML') from exc


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded(root, name):
    p = root / name
    if Path(name).is_absolute() or not within(p, root) or any(x.is_symlink() for x in [p, *p.parents] if within(x, root)):
        raise ValueError('artifact path must stay inside project without symlinks')
    return p


def schema_check(value, schema, where='document'):
    """Validate the JSON Schema subset used by the versioned local contracts."""
    errors = []
    types = {'object': dict, 'array': list, 'string': str, 'number': (int, float), 'integer': int, 'boolean': bool}
    kind = schema.get('type')
    if kind and (not isinstance(value, types[kind]) or kind in ('number', 'integer') and isinstance(value, bool)):
        return [where + ': expected ' + kind]
    if 'enum' in schema and value not in schema['enum']:
        errors.append(where + ': invalid value')
    if isinstance(value, dict):
        errors += [where + ': missing ' + k for k in schema.get('required', []) if k not in value]
        for k, s in schema.get('properties', {}).items():
            if k in value:
                errors += schema_check(value[k], s, where + '.' + k)
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0):
            errors.append(where + ': empty list')
        for i, item in enumerate(value):
            errors += schema_check(item, schema.get('items', {}), f'{where}[{i}]')
    if isinstance(value, str):
        if not value.strip() or PLACEHOLDER.search(value):
            errors.append(where + ': empty or placeholder')
        if 'pattern' in schema and not re.fullmatch(schema['pattern'], value):
            errors.append(where + ': invalid format')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value) or value < schema.get('minimum', float('-inf')):
            errors.append(where + ': invalid number or below minimum')
    return errors


def required(profile, risk, mode, platform=False):
    data = json.loads((NEW / 'profiles' / (profile + '.json')).read_text())
    result = dict(data['artifacts'])
    if risk != 'low' or profile in ('L', 'XL'):
        result['compliance.yaml'] = 'compliance'
    if profile == 'XL' or platform:
        result['platform-program.json'] = 'platform'
    if mode == 'brownfield':
        result.update({'audit.json': 'audit', 'gap-plan.md': 'markdown'})
    return result


def initialize(root, mode, profile, risk, platform=False, proposed_config=None):
    root = root.resolve()
    files = required(profile, risk, mode, platform)
    # Preflight everything before creating anything; never overwrite an existing project.
    for name in [*files, 'handoff-manifest.yaml']:
        if bounded(root, name).exists():
            # CLI already created this exact config after its full preflight.
            if name == 'helix.json' and proposed_config is not None and load(bounded(root, name)) == proposed_config:
                continue
            raise ValueError('init refuses existing artifact: ' + name)
    manifest = load(NEW / 'templates/handoff-manifest.yaml.tpl')
    manifest.update(mode=mode, profile=profile, risk=risk, platform=platform)
    for name, kind in files.items():
        template = NEW / 'templates' / ('platform.json.tpl' if kind == 'platform' else name.replace('/', '__') + '.tpl')
        from helix_contracts import VERSION
        content = template.read_text().replace('{{HELIX_VERSION}}', VERSION)
        p = bounded(root, name)
        p.parent.mkdir(parents=True, exist_ok=True)
        if name == 'helix.json' and proposed_config is not None:
            content = json.dumps(proposed_config, ensure_ascii=False, indent=2) + '\n'
        if name == 'helix.json' and proposed_config is not None and p.exists():
            if load(p) != proposed_config:
                raise ValueError('init refuses changed config: helix.json')
        else:
            with p.open('x', encoding='utf-8') as stream:
                stream.write(content)
        manifest['artifacts'].append(dict(path=name, sha256=digest(p), status='draft', accepted_by=''))
    with (root / 'handoff-manifest.yaml').open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    return ['Draft created; supply evidence, source brand and owner acceptances before design/handoff.']


def brand_check(root):
    errors = []
    paths = [bounded(root, n) for n in ('brand.yaml', 'design-contract.yaml', 'DESIGN.md')]
    if any(not p.is_file() for p in paths):
        return ['brand/design artifacts missing']
    brand, contract = load(paths[0]), load(paths[1])
    errors += schema_check(brand, load(NEW / 'schemas/brand.json'), 'brand')
    errors += schema_check(contract, load(NEW / 'schemas/design.json'), 'design-contract')
    if errors:
        return errors
    for item in [brand['logo'], *brand['colors'], *brand['fonts']]:
        source = item['source']
        if source['kind'] == 'file' and not bounded(root, source['reference']).is_file():
            errors.append('brand source file missing')
        if source['kind'] == 'url' and not re.match(r'^https?://\S+$', source['reference']):
            errors.append('invalid source URL')
    tokens = dict(colors=[x['value'] for x in brand['colors']], fonts=[x['value'] for x in brand['fonts']])
    for key, values in tokens.items():
        if contract['tokens'].get(key) != values:
            errors.append('design-contract tokens differ from brand: ' + key)
    # DESIGN.md has an explicit machine-readable projection, not a loose substring match.
    match = re.search(r'```json\s*\n(.*?)\n```', paths[2].read_text(), re.S)
    if not match or json.loads(match[1]) != tokens:
        errors.append('DESIGN.md tokens differ from brand')
    return errors


def check(root):
    path = bounded(root, 'handoff-manifest.yaml')
    if not path.is_file():
        return ['handoff-manifest.yaml missing']
    m = load(path)
    errors = schema_check(m, load(NEW / 'schemas/manifest.json'), 'manifest')
    if errors:
        return errors
    files = required(m['profile'], m['risk'], m['mode'], m.get('platform', False))
    entries = {x['path']: x for x in m['artifacts']}
    if len(entries) != len(m['artifacts']):
        errors.append('duplicate manifest artifact')
    for name in files:
        if name not in entries:
            errors.append('required manifest artifact missing: ' + name)
    for name, entry in entries.items():
        p = bounded(root, name)
        if not p.is_file():
            errors.append('artifact missing: ' + name)
            continue
        if digest(p) != entry['sha256']:
            errors.append('hash mismatch: ' + name)
        kind = files.get(name)
        # Optional assets (including binary logos) are integrity-checked without decoding them.
        text = p.read_text() if kind or p.suffix.lower() in ('.md', '.json', '.yaml', '.yml') else ''
        if (kind or text) and (not text.strip() or PLACEHOLDER.search(text)):
            errors.append('empty/placeholder artifact: ' + name)
        if kind and kind != 'markdown':
            errors += schema_check(load(p), load(NEW / 'schemas' / (kind + '.json')), name)
        elif kind == 'markdown' and not re.search(r'\b(VERIFIED|ASSUMPTION)\b', text):
            errors.append('claim label missing: ' + name)
    skill = bounded(root, 'SKILL.md')
    if skill.is_file():
        content = skill.read_text().lower()
        for term in ('workflow', 'helix plan', 'helix run', 'helix gate truth', 'closure evidence', 'escalation', 'helix board', 'documentation'):
            if term not in content:
                errors.append('SKILL.md missing: ' + term)
    for claim in m['claims']:
        if claim['tag'] == 'VERIFIED':
            match = re.fullmatch(r'(.+):(\d+)', claim.get('evidence', ''))
            if not match:
                errors.append('VERIFIED needs path:line evidence')
            else:
                p = bounded(root, match[1])
                if not p.is_file() or not 1 <= int(match[2]) <= len(p.read_text().splitlines()):
                    errors.append('invalid claim evidence')
    from helix_contracts import check_pin, domain_errors
    try:
        check_pin(root)
    except (OSError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    domain_path = bounded(root, 'domain-map.json')
    if domain_path.is_file():
        errors += domain_errors(load(domain_path))
    from helix_platform import platform_check, explanation_check
    if 'platform-program.json' in files and bounded(root, 'platform-program.json').is_file():
        errors += platform_check(load(bounded(root, 'platform-program.json')))
    if bounded(root, 'HANDOFF.md').is_file():
        errors += explanation_check(bounded(root, 'HANDOFF.md').read_text())
    if errors:
        return errors
    if m['profile'] in ('S', 'M'):
        arch = bounded(root, 'architecture.yaml')
        if arch.is_file():
            a = load(arch)
            features = set(a.get('advanced_features', []))
            # Declarations in prose also need an ADR, so omitting the feature list cannot bypass the gate.
            prose = a.get('summary', '')
            for doc in ('PRD.md', 'program.md', 'adr/ADR-001.md'):
                if bounded(root, doc).is_file():
                    prose += '\n' + bounded(root, doc).read_text()
            for line in prose.splitlines():
                for match in re.finditer(r'\b(?:cells|multi-region|sharding|microservices|kafka)\b', line.lower()):
                    if not re.search(r'\b(?:no|not|without|non-goals?|avoid|reject|brak|bez|nie)\s*[:：-]?\s*$', line[:match.start()], re.I):
                        features.add(match[0])
            for feature in features:
                decisions = a.get('decisions', [])
                if not any(d.get('feature') == feature and d.get('status') == 'approved' and d.get('threshold', 0) > 0 and d.get('metric') and d.get('accepted_by') and bounded(root, d.get('adr', '')).is_file() and d.get('adr') in entries for d in decisions):
                    errors.append('S/M advanced feature requires approved ADR with numeric threshold: ' + feature)
    if bounded(root, 'HANDOFF.md').is_file() and len((root / 'HANDOFF.md').read_text().split()) >= 400:
        errors.append('HANDOFF.md must be under 400 words')
    errors += brand_check(root)
    from helix_pro import assess
    maturity = assess(root, m['profile'])
    errors += maturity['blocking']
    if (root / 'ai-modules.json').exists() or (root / 'ai-modules.json').is_symlink():
        from helix_project_evidence import local, modules
        result = modules(root, json.loads(local(root, 'ai-modules.json')), [g['name'] for g in maturity['custom_gates']])
        errors += ['AI module gates failed: ' + row['id'] for row in result['modules'] if row['status'] != 'PASS']
    if (root / 'helix-id-registry.json').exists() or (root / 'helix-id-registry.json').is_symlink():
        from helix_id_registry import read
        read(root / 'helix-id-registry.json')
    return errors


SKIP = {'.usage', '.git', '.helix', 'helix-evidence', '.aws', '.codex', '.agents', 'node_modules', 'vendor', 'dist', 'build', '__pycache__', 'secrets', 'credentials', '.ssh'}
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.css', '.scss', '.vue', '.svelte', '.html', '.json', '.yaml', '.yml', '.toml', '.md', '.sql', '.go', '.rs', '.java', '.rb', '.php'}


def palette_source(text):
    """Blank comments while preserving strings and evidence line numbers."""
    pattern = r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')|/\*.*?\*/|//[^\n]*|<!--.*?-->"
    return re.sub(pattern, lambda m: m[0] if m[1] else re.sub(r'[^\n]', ' ', m[0]), text, flags=re.S)


def evidence_counts(maturity):
    """Summarize recorded evidence, without scoring application quality."""
    items = [item for area in maturity.get('areas', {}).values() for item in area.get('requirements', [])]
    executed = lambda item: item.get('execution_status') in ('PASS', 'FAIL')
    return dict(requirements=len(items),
                declarations=sum(bool(item.get('satisfied')) and not executed(item) and not item.get('exception') for item in items),
                passed=sum(item.get('execution_status') == 'PASS' for item in items),
                failed=sum(item.get('execution_status') == 'FAIL' for item in items),
                runtime_pending=sum(bool(item.get('runtime')) and not executed(item) for item in items),
                missing=sum(not item.get('satisfied') and not executed(item) and not item.get('exception') for item in items),
                exceptions=sum(bool(item.get('exception')) for item in items))


def audit_summary(report):
    """Polish console projection, using only already loaded report evidence."""
    maturity, coverage = report['maturity'], report.get('source_coverage', {})
    def summary(value):
        counts = evidence_counts(value)
        return (f"wymagania {counts['requirements']}; dopasowane deklaracje {counts['declarations']}; "
                f"wykonane PASS {counts['passed']}, FAIL {counts['failed']}; "
                f"oczekuje runtime {counts['runtime_pending']}; braki dowodów {counts['missing']}; wyjątki {counts['exceptions']}")
    lines = [f"Profil {report['scope']['profile']}; analiza źródeł i dowodów, bez nowego wykonania aplikacji.",
             f"Pokrycie odczytu: {coverage.get('files_read', 'nieznane')}/{coverage.get('files_total', 'nieznane')} plików, "
             f"{coverage.get('lines_read', 'nieznane')} linii; {coverage.get('status', 'UNKNOWN')}.",
             'Dowody: ' + summary(maturity) + '.',
             'Deklaracje nie są wynikiem wykonania; braki dowodów i oczekiwanie runtime mogą dotyczyć tych samych wymagań.']
    debt=report.get('quality',{}).get('ponytail_debt',{})
    if debt:
        counts=debt.get('counts',{})
        lines.append('Ponytail debt: '+str(debt.get('status','UNKNOWN'))+'; markery '+str(counts.get('markers','nieznane'))+'; no-trigger '+str(counts.get('no_trigger','nieznane'))+'; wiek znany '+str(counts.get('age_known','nieznane'))+', nieznany '+str(counts.get('age_unknown','nieznane'))+'. Komentarze nie potwierdzają jakości ani wykonania modelu.')
    for area, result in maturity['areas'].items():
        lines.append(area + ': ' + summary({'areas': {area: result}}))
        lines.extend(f"  Brak: {item['id']} ({item['status']})" for item in result['top_gaps'][:2])
    for part in maturity.get('parts', [])[:8]:
        lines.append('Część ' + part['path'] + ': ' + (summary(part['maturity']) if 'maturity' in part else 'wyłączona z oceny'))
    if len(maturity.get('parts', [])) > 8:
        lines.append('Pozostałe części: ' + str(len(maturity['parts']) - 8) + '; pełna lista w audit.json.')
    return lines


def audit(repo, out, profile=None, docs_paths=(), strict_profile=False, verbose=False, runtime_report=None,
          *, state_dir=None, provider_cache=None, write=False, probe=False,
          refresh_providers=False, provider_refresh=None, jobs=3, offline=False):
    from helix_project_proposal import preflight, generate, validate_refresh, prepare_refresh
    validate_refresh(refresh_providers, provider_refresh, jobs, offline)
    preflight(repo, out, write, state_dir)
    repo, out = repo.resolve(), out.resolve()
    if not repo.is_dir() or within(out, repo) or within(repo, out):
        raise ValueError('audit requires a directory and a disjoint external output directory')
    artifacts=('system-map.json','audit.json','audit.md','gap-plan.md','reconstruction-proposal.md','proposed','coverage.json','quality.json','readability-model-tasks.json','owner-current.json','owner-current.md')
    conflicts=[name for name in artifacts if (out/name).exists() or (out/name).is_symlink()]
    if conflicts:
        raise ValueError('audit refuses existing artifacts: '+', '.join(conflicts))
    from helix_audit_context import config, documents, parts, infer_profile, inventory as source_inventory
    cfg = config(repo)
    from helix_source_coverage import scan
    readable, source_coverage = scan(repo)
    profile = profile or cfg.get('profile')
    warning = None
    if profile is None:
        if strict_profile:
            raise ValueError('strict-profile requires --profile or helix.json profile')
        docs = documents(repo, [*cfg.get('docs_paths', []), *docs_paths])
        signals = readable
        profile, warning = infer_profile(signals, docs, len(parts(repo, cfg)))
    if profile not in ('S', 'M', 'L', 'XL'):
        raise ValueError('invalid profile')
    refresh_receipt = prepare_refresh(repo, out, state_dir=state_dir, provider_cache=provider_cache,
                                      refresh_providers=refresh_providers, provider_refresh=provider_refresh,
                                      jobs=jobs, offline=offline)
    from helix_dotnet import PROJECT_SUFFIXES, SOURCE_SUFFIXES
    inventory, observations = [], []
    map_sources = {}
    counts = {k: Counter() for k in ('hex', 'variables', 'variable_references', 'fonts')}
    for rel, text in readable.items():
        p = Path(rel)
        name = p.name
        categories = []
        if p.suffix.lower() in {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.go', '.rs', '.java', '.rb', '.php', '.svelte', '.vue', '.html', '.css'} | SOURCE_SUFFIXES: categories.append('language:' + p.suffix)
        if p.suffix.lower() in PROJECT_SUFFIXES or name in ('package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'composer.json') or re.fullmatch(r'requirements(?:[.-][\w.-]+)?\.txt', name): categories.append('manifest')
        if 'test' in rel.lower() or re.search(r'\.(spec\.[cm]?[jt]sx?|sprawdz\.mjs)$', name): categories.append('tests')
        if rel.startswith('.github/workflows/') or name == '.gitlab-ci.yml': categories.append('CI')
        if 'migration' in rel.lower() or p.suffix == '.sql' or re.search(r'(?:^|/)alembic/versions/[^/]+\.py$', rel): categories.append('migrations')
        if name.startswith(('Dockerfile', 'docker-compose', 'compose.')): categories.append('docker')
        if p.suffix == '.md': categories.append('documents')
        inventory.append(dict(path=rel, categories=categories, tag='VERIFIED', evidence=rel + ':1'))
        map_sources[rel] = text
        if name == 'package.json':
            try:
                pkg = json.loads(text)
                for framework in ('react', 'next', 'vue', 'svelte', '@sveltejs/kit', 'express', 'angular'):
                    if framework in {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}:
                        observations.append(dict(tag='VERIFIED', kind='framework-declaration', value=framework, evidence=rel + ':1'))
            except (ValueError, TypeError):
                pass
        if p.suffix in ('.css', '.scss', '.vue', '.svelte') or name.startswith('tailwind.config') or name in ('tokens.json', 'tokens.css'):
            for line_no, line in enumerate(palette_source(text).splitlines(), 1):
                found = {'hex': re.findall(r'#[0-9a-fA-F]{8}\b|#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3,4}\b', line),
                         'variables': re.findall(r'--[a-zA-Z][\w-]*(?=\s*:)', line),
                         'variable_references': re.findall(r'var\(\s*(--[a-zA-Z][\w-]*)', line),
                         'fonts': re.findall(r'font-family\s*:\s*([^;}]+)(?=;|})', line)}
                # Tailwind fontFamily arrays are declarations, never executable configuration.
                if 'fontFamily' in line:
                    for group in re.findall(r'\[([a-zA-Z ,\"\'-]+)\]', line):
                        found['fonts'].extend(re.findall(r'[\"\']([a-zA-Z][a-zA-Z -]*)[\"\']', group))
                for kind, values in found.items():
                    for value in values:
                        value = value.lower() if kind == 'hex' else value.strip()
                        counts[kind][value] += 1
                        observation = dict(tag='VERIFIED', kind=kind, value=value, evidence=f'{rel}:{line_no}')
                        if kind == 'variables':
                            declaration = re.search(re.escape(value) + r'\s*:\s*([^;}]+)', line)
                            if declaration:
                                observation['declared_value'] = declaration[1].strip()
                        observations.append(observation)
    present = {x['path'] for x in inventory}
    gaps = [dict(tag='ASSUMPTION', artifact=n, reason='not observed in bounded source inventory; owner review required') for n in required(profile, 'low', 'brownfield') if n not in present]
    from helix_contracts import VERSION
    from helix_environment import provenance
    report = dict(helix_version=VERSION, schema_version=1, status='proposal', inventory=inventory, observations=observations,
                  palette={k: dict(v.most_common()) for k, v in counts.items()}, gaps=gaps,
                  scope=dict(profile='S', risk='low', mode='brownfield', palette='bounded source declarations and var references; imports and runtime not evaluated'),
                  limitations=['ASSUMPTION: declarations do not establish runtime or production behavior; privacy and read omissions listed in coverage.json; no code executed.'])
    report['provenance'] = provenance(repo, models=refresh_receipt['models'])
    report['provider_refresh'] = refresh_receipt
    report['execution'] = dict(models=refresh_receipt['availability_probe_calls'], availability_probe_calls=refresh_receipt['availability_probe_calls'], source_review_calls=0, application=False, database_started=False)
    report['target'] = str(repo)
    from helix_pro import assess, markdown
    report['maturity'] = assess(repo, profile, docs_paths)
    if (repo / 'ai-modules.json').exists() or (repo / 'ai-modules.json').is_symlink():
        from helix_project_evidence import local, modules
        report['ai_modules'] = modules(repo, json.loads(local(repo, 'ai-modules.json')),
                                       [g['name'] for g in report['maturity']['custom_gates']])
    else:
        report['ai_modules'] = dict(status='NOT_CONFIGURED', scope='no module inventory')
    if runtime_report:
        from helix_runtime import import_evidence
        from helix_owner_report import projected_provenance
        imported = projected_provenance(import_evidence(report['maturity'], Path(runtime_report), repo))
        from helix_project_evidence import refresh_points
        refresh_points(report['maturity'])
        current_head, imported_head = report['provenance'].get('target_head'), imported.get('target_head')
        report['source_reports'] = [{'kind': 'runtime', 'artifact': str(Path(runtime_report).expanduser().absolute()),
                                    'provenance': imported,
                                    'head_relation': 'unknown' if not current_head or not imported_head else 'same' if current_head == imported_head else 'different',
                                    'snapshot_equivalence': 'not_established'}]
        report.setdefault('findings',[]).extend(report['maturity'].get('findings',[]))
    from helix_quality import analyze as quality_analyze, model_packet
    report['source_coverage'] = source_coverage
    report['quality'] = quality_analyze(repo, profile, readable, source_coverage,observed_at=report['provenance']['generated_at'])
    from helix_ponytail_age import collect_line_ages, write_debt_summary
    from helix_ponytail_debt import with_line_ages
    ref=dict(head=report['provenance'].get('target_head'),dirty=report['provenance'].get('target_dirty'))
    line_ages=collect_line_ages(repo,report['quality']['ponytail_debt'],readable,ref,observed_at=report['provenance']['generated_at'])
    report['quality']['ponytail_debt']=with_line_ages(report['quality']['ponytail_debt'],line_ages,observed_at=report['provenance']['generated_at'])
    report['quality'].update(target=str(repo),provenance=report['provenance'])
    dump(out / 'coverage.json', source_coverage)
    dump(out / 'quality.json', report['quality'])
    write_debt_summary(repo,state_dir,out/'quality.json')
    dump(out / 'readability-model-tasks.json', model_packet(readable))
    report['profile_warning'] = warning
    report['scope']['profile'] = profile
    from helix_platform import system_map
    topology = system_map(inventory, map_sources)
    report['system_map'] = topology
    dump(out / 'system-map.json', topology)
    dump(out / 'audit.json', report)
    from helix_owner_report import audit_report
    audit_report(repo, out, report, readable)
    quality = report['quality']
    coverage_text = '\n\n## Pokrycie odczytu\n\n' + source_coverage['status'] + ': ' + str(source_coverage['files_read']) + '/' + str(source_coverage['files_total']) + ' plików; ' + str(source_coverage['lines_read']) + ' linii. Nieznane sumy linii: ' + str(source_coverage['unknown_line_totals']) + '. Szczegóły: coverage.json. Odczyt nie daje punktów poprawności.\n'
    coverage_text += '\n'.join('- ' + r['file'] + ': ' + r['reason'] for r in source_coverage['files'] if r['status'] != 'read')
    findings_text = '\n\n## Precyzja i czytelność — ASSUMPTION\n\n' + '\n'.join('- ' + f["file"] + ':' + str(f['line']) + ' [' + f['severity'] + '/' + f['confidence'] + '] ' + f['title'] + ': ' + f['why'] + ' Poprawka: ' + f['fix'] for f in quality['findings'])
    findings_text += '\n\n## Moduły AI — dowody lokalne\n\n' + json.dumps(report['ai_modules'], ensure_ascii=False) + '\n'
    findings_text+='\n\n## Runtime — VERIFIED (synthetic execution)\n\n'+'\n'.join('- '+f['id']+' ['+f['severity']+'/'+f['category']+'] project: '+json.dumps(f,ensure_ascii=False) for f in report.get('findings',[]))
    from helix_owner_report import provenance_line
    debt=quality['ponytail_debt']
    debt_text='\n\nPonytail debt: '+debt['status']+'; markery '+str(debt['counts']['markers'])+'; no-trigger '+str(debt['counts']['no_trigger'])+'. Pełne lokalizacje i nieznany wiek: quality.json oraz owner-current.md. Modelowy review/audit: nie wykonano.\n'
    (out / 'audit.md').write_text(markdown(report['maturity']) + coverage_text + findings_text + debt_text + '\n\n' + provenance_line(report['provenance']) + '\n\nPrzegląd kodu przez modele: nie wykonano. Sondy dostępności w tym poleceniu: ' + str(refresh_receipt['availability_probe_calls']) + '. Adaptery: quality.json.\n')
    from helix_pro import improvement_plan
    plan = improvement_plan(report['maturity'])
    gap_text = '# Gap plan\n\n' + '\n\n'.join(
        '## ' + cp['id'] + ' ' + cp['title'] + '\n' + cp['goal'] + '\nAcceptance: ' + '; '.join(cp['test_cases'])
        for cp in plan['checkpoints']) + '\n'
    (out / 'gap-plan.md').write_text(gap_text)
    (out / 'reconstruction-proposal.md').write_text('# Reconstruction proposal\n\nASSUMPTION: run helix new init --mode brownfield in a separate preparation directory; review audit.json, preserve current behavior, then approve requirements, ADRs and brand. Palette frequency is evidence, never brand approval.\n')
    initialize(out / 'proposed', 'brownfield', profile, 'low')
    dump(out / 'proposed' / 'audit.json', report)
    (out / 'proposed' / 'gap-plan.md').write_text((out / 'gap-plan.md').read_text())
    # All reconstructed artifacts remain drafts; replacement audit hashes are refreshed, never approvals.
    manifest_path = out / 'proposed' / 'handoff-manifest.yaml'
    manifest = load(manifest_path)
    for entry in manifest['artifacts']:
        entry['sha256'] = digest(out / 'proposed' / entry['path'])
    dump(manifest_path, manifest)
    proposal = generate(repo, out, profile=profile, state_dir=state_dir, provider_cache=provider_cache,
                        write=write, probe=probe, jobs=jobs, offline=offline, _refresh_receipt=refresh_receipt,
                        sources=readable, source_coverage=source_coverage)
    proposal_note = 'Propozycja konfiguracji: ' + proposal['status'] + '; ' + str(out / 'NEW-REPORT.md')
    lines = [warning] if warning else []
    lines.extend(audit_summary(report))
    if verbose:
        lines.extend([gap_text, 'Dowody oraz progi poszczególnych wymagań: ' + str(out / 'audit.json')])
    lines.append('Full details: ' + str(out / 'audit.json') + '; ' + str(out / 'audit.md'))
    lines.append(proposal_note)
    lines.append('Sondy dostępności: ' + str(refresh_receipt['availability_probe_calls']) + '; przegląd kodu przez modele: 0 wywołań.')
    return lines


def plan_from_audit(audit_path, out):
    """Write an external reviewable plan without running project code or providers."""
    from helix_pro import improvement_plan
    audit_path, out = audit_path.resolve(), out.resolve()
    if out.exists():
        raise ValueError('plan refuses existing output')
    report = json.loads(audit_path.read_text())
    result = improvement_plan(report['maturity'])
    if schema_check(result, load(HOME / 'schemas/plan.json')):
        raise ValueError('invalid generated plan')
    dump(out, result)
    return ['ASSUMPTION: improvement proposal; owner confirms applicability, priorities and runtime evidence.', str(out)]


def parsers(sp):
    p = sp.add_parser('new', help='Offline greenfield/brownfield preparation')
    sub = p.add_subparsers(dest='new_action', required=True)
    init = sub.add_parser('init')
    init.add_argument('--mode', choices=['greenfield', 'brownfield'], required=True)
    init.add_argument('--profile', choices=['S', 'M', 'L', 'XL'], required=True)
    init.add_argument('--risk', choices=['low', 'high', 'regulated'], required=True)
    init.add_argument('--dir', default=None, help='Target projektu; bez --write pozostaje bez zmian')
    init.add_argument('--out', help='Zewnętrzny katalog draftów i propozycji')
    init.add_argument('--platform', action='store_true', help='Require multi-product platform program for any profile')
    audit_p = sub.add_parser('audit')
    audit_p.add_argument('--profile', choices=['S', 'M', 'L', 'XL'], default=None)
    audit_p.add_argument('--docs', action='append', default=[])
    audit_p.add_argument('--strict-profile', action='store_true')
    audit_p.add_argument('--runtime-report', help='runtime-report.json with synthetic execution evidence')
    audit_p.add_argument('--verbose', action='store_true')
    audit_p.add_argument('--repo', default=argparse.SUPPRESS)
    audit_p.add_argument('--out', default='../helix-new-audit')
    for item in (init, audit_p):
        item.add_argument('--write', action='store_true', help='Jawnie zapisz nowe artefakty w repo; nigdy nie nadpisuj istniejących')
        item.add_argument('--no-probe', action='store_true', help='Pomiń lokalne sondy wersji narzędzi')
        item.add_argument('--refresh-providers', action='store_true', help='Jawnie wykonaj równoległe sondy modeli bez kodu projektu')
        item.add_argument('--jobs', type=int, default=3, help='Równoległe sondy dostępności, domyślnie 3')
        item.add_argument('--provider-cache', help='Zewnętrzny provider-availability.json po rzeczywistym providers --refresh')
        item.add_argument('--config', default=argparse.SUPPRESS)
        item.add_argument('--state-dir', default=argparse.SUPPRESS)
        item.add_argument('--offline', action='store_true', default=argparse.SUPPRESS)
    ids = sub.add_parser('ids', help='Atomowa rezerwacja identyfikatorów; wspólny plik dla równoległych autorów')
    ids.add_argument('ids_action', choices=['reserve', 'check', 'list'])
    ids.add_argument('--registry', default='helix-id-registry.json')
    ids.add_argument('--prefix'); ids.add_argument('--type', dest='id_type')
    ids.add_argument('--owner'); ids.add_argument('--purpose'); ids.add_argument('--id', dest='identifier')
    modules = sub.add_parser('modules', help='Te same bramki dla modułów AI i ręcznych')
    modules.add_argument('--input', default='ai-modules.json')
    plan = sub.add_parser('plan')
    plan.add_argument('--to', choices=['pro'], required=True)
    plan.add_argument('--audit', required=True, help='audit.json from a current helix new audit')
    plan.add_argument('--out', default='../helix-new-plan.json')
    for name in ('check', 'handoff', 'brand'):
        item = sub.add_parser(name)
        if name == 'brand': item.add_argument('brand_action', choices=['check'])
        item.add_argument('--dir', default='.')


def dispatch(a, provider_refresh=None):
    try:
        from helix_project_proposal import validate_refresh
        refresh_providers = getattr(a, 'refresh_providers', False)
        jobs, offline = getattr(a, 'jobs', 3), getattr(a, 'offline', False)
        validate_refresh(refresh_providers, provider_refresh, jobs, offline)
        if a.new_action == 'ids':
            import helix_id_registry as registry
            path = Path(a.registry)
            if not path.is_absolute():
                path = Path(a.repo) / path
            if a.ids_action == 'reserve':
                value = registry.reserve(path, a.prefix, a.id_type, a.owner, a.purpose, a.identifier)
            else:
                value = registry.read(path)
            print(json.dumps(dict(status='PASS', registry=str(path), result=value), ensure_ascii=False))
            return 0
        if a.new_action == 'modules':
            from helix_project_evidence import local, modules
            from helix_audit_context import config, gates, inventory
            root = Path(a.repo).resolve()
            custom = gates(root, inventory(root), config(root))
            result = modules(root, json.loads(local(root, a.input)), [g['name'] for g in custom])
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result['status'] == 'PASS' else 2
        if a.new_action == 'init':
            from helix_audit_context import system_path
            from helix_project_proposal import preflight, generate
            target = system_path(a.dir or getattr(a, 'repo', '.'))
            out = system_path(a.out) if a.out else target.parent / (target.name + '-helix-new-init')
            if getattr(a, 'config', None):
                from helix_config import configure
                configure(target, a.config)
            preflight(target, out, a.write, getattr(a, 'state_dir', None))
            drafts = target if a.write else out / 'proposed'
            # Check every draft destination before creating the proposal or config.
            for name in [*required(a.profile, a.risk, a.mode, a.platform), 'handoff-manifest.yaml']:
                if bounded(drafts, name).exists():
                    raise ValueError('init refuses existing artifact: ' + name)
            proposal = generate(target, out, profile=a.profile, state_dir=getattr(a, 'state_dir', None),
                                provider_cache=a.provider_cache, write=a.write, probe=not a.no_probe,
                                refresh_providers=refresh_providers, provider_refresh=provider_refresh, jobs=jobs, offline=offline)
            proposed_config = json.loads((out / 'helix.proposed.json').read_text())
            messages = initialize(drafts, a.mode, a.profile, a.risk, a.platform, proposed_config=proposed_config)
            print(json.dumps(dict(status=proposal['status'], notes=messages, drafts=str(drafts), report=str(out / 'NEW-REPORT.md')), ensure_ascii=False))
            return 0
        elif a.new_action == 'audit':
            messages = audit(Path(a.repo), Path(a.out), a.profile, a.docs, a.strict_profile, a.verbose, a.runtime_report or (str(Path(a.state_dir)/'runtime-report.json') if getattr(a,'state_dir',None) and (Path(a.state_dir)/'runtime-report.json').is_file() else None),
                             state_dir=getattr(a, 'state_dir', None), provider_cache=a.provider_cache,
                             write=a.write, probe=not a.no_probe, refresh_providers=refresh_providers,
                             provider_refresh=provider_refresh, jobs=jobs, offline=offline)
            print('\n'.join(messages))
            return 0
        elif a.new_action == 'plan':
            messages = plan_from_audit(Path(a.audit), Path(a.out))
        else:
            messages = (brand_check if a.new_action == 'brand' else check)(Path(a.dir).resolve())
            print(json.dumps(dict(status='FAIL' if messages else 'PASS', findings=messages, scope='preparation completeness; not production readiness'), ensure_ascii=False))
            return 2 if messages else 0
        print(json.dumps(dict(status='PASS', notes=messages), ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, MissingDependency) as e:
        # Parser/internal exceptions may contain source content; audit validation
        # errors are operator diagnostics and contain only paths/contract messages.
        result=dict(status='ERROR', reason=type(e).__name__)
        if isinstance(e, ValueError) and a.new_action in ('init', 'audit', 'ids', 'modules'):
            result.update(reason=str(e), error=type(e).__name__)
        print(json.dumps(result))
        return 3
