"""Shared, stdlib-only pack execution, evidence, baselines and gates."""
import datetime as dt, fnmatch, gzip, hashlib, json, os, re, shutil, statistics, subprocess, sys, time, urllib.parse
from pathlib import Path
from helix_paths import normalize, relative as relative_path, within

PACKS = ('security', 'perf', 'integrity')
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
TOOLS = {'security': ['gitleaks', 'semgrep', 'trivy'], 'perf': ['lighthouse'], 'integrity': []}
SECRET_HINT = "Usuń z repo, zrotuj klucz u dostawcy, dodaj do .gitignore/env; nie baseline'uj bez rotacji"


def read_json(path, default=None):
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def write_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def git(repo, *args, required=False):
    from helix_git_readonly import git as read_git, read_ref, filter_drivers, without_filters, REASONS
    if args and args[0] == 'diff':
        # A worktree diff can execute clean filters even with --name-only.
        # Refuse unknown normalization and never invoke external diff or textconv. Known drivers
        # are emptied here too, so an attribute assigned after read_ref runs nothing.
        ref = read_ref(repo)
        drivers = filter_drivers(repo) if ref['dirty'] is not None else None
        if drivers is None:
            if required: raise ValueError('Nie można bezpiecznie odczytać diff: ' + (ref['reason'] if ref['dirty'] is None else REASONS['git_filter_configuration_unknown']))
            return None
        args = (*without_filters(drivers), 'diff', '--no-ext-diff', '--no-textconv', *args[1:])
    p = read_git(repo, *args)
    if required and p.returncode: raise ValueError('git: ' + p.stderr.strip())
    return p.stdout if not p.returncode else None


def base_ref(repo, cfg):
    requested = cfg.get('base_ref')
    if requested:
        git(repo, 'rev-parse', '--verify', requested, required=True); return requested
    for ref in ('origin/main', 'main', 'HEAD'):
        if git(repo, 'rev-parse', '--verify', ref): return ref
    raise ValueError('Brak bazowego commita Git')


def base_json(repo, ref, path, default):
    raw = git(repo, 'show', f'{ref}:{path}')
    return json.loads(raw) if raw is not None else default


def fingerprint(tool, rule, file, snippet):
    norm = re.sub(r'\s+', ' ', str(snippet)).strip()
    return hashlib.sha1('\0'.join((tool, rule, file.replace('\\', '/'), norm)).encode()).hexdigest()


def finding(pack, tool, rule, severity, title, file='', line=0, snippet='', evidence='', fix_hint='', category=None, **extra):
    verdict = extra.pop('verdict', 'needs_validation' if category == 'secret' or tool in ('gitleaks', 'semgrep', 'trivy', 'osv-scanner', 'bandit') else 'confirmed')
    if tool == 'gitleaks' and verdict == 'confirmed' and not extra.get('verification_evidence'):
        raise ValueError('confirmed dla gitleaks wymaga verification_evidence')
    if verdict not in ('confirmed', 'needs_validation', 'rejected'): raise ValueError('Niepoprawny verdict')
    return dict(id=rule, pack=pack, tool=tool, severity=severity if severity in SEVERITIES else 'info', title=title,
                file=file, line=line or 0, fingerprint=fingerprint(tool, rule, file, snippet), tag='VERIFIED' if verdict == 'confirmed' else 'ASSUMPTION', verdict=verdict,
                evidence=evidence, fix_hint=fix_hint or 'Sprawdź ustalenie i popraw wskazane miejsce.', status='new',
                category=category or rule, **extra)


def dedupe(findings):
    out = []; seen = set(); sca = []
    for f in findings:
        if f['fingerprint'] in seen and f.get('category') != 'sca': continue
        seen.add(f['fingerprint'])
        if f.get('category') == 'sca':
            aliases = set(f.get('aliases', [])) | {f['id']}
            matches = [g for g in sca if (g.get('ecosystem'), g.get('package')) == (f.get('ecosystem'), f.get('package'))
                       and aliases & (set(g.get('aliases', [])) | {g['id']})]
            if matches:
                match = matches[0]
                for g in matches[1:] + [f]:
                    match['occurrences'] = list({json.dumps(x, sort_keys=True): x for x in match.get('occurrences', []) + g.get('occurrences', [])}.values())
                    match['versions'] = sorted({x['version'] for x in match['occurrences']})
                    match['sources'] = sorted({x['source'] for x in match['occurrences']})
                    match['evidence'] = '; '.join(x['evidence'] for x in match['occurrences'])
                    match['aliases'] = sorted(set(match.get('aliases', [])) | {match['id'], g['id']} | set(g.get('aliases', [])))
                    if SEVERITIES.index(g['severity']) < SEVERITIES.index(match['severity']): match['severity'] = g['severity']
                    if g is not f: out.remove(g); sca.remove(g)
                continue
            sca.append(f)
        out.append(f)
    return out


class Runner:
    def __init__(self, repo, timeout=300, version_timeout=30):
        self.repo, self.timeout, self.records = Path(repo), timeout, []
        self.version_timeout = version_timeout

    def run(self, tool, command, allowed=(0,), optional=False, output=None, env=None):
        if tool == 'semgrep':
            env = dict(os.environ if env is None else env, SEMGREP_SEND_METRICS='off', SEMGREP_ENABLE_VERSION_CHECK='0')
        rec = dict(tool=tool, version=None, command=command, exit_code=None, duration=0, error=None, status='ok')
        self.records.append(rec); start = time.monotonic(); stage = 'version'
        try:
            if not shutil.which(command[0]):
                rec.update(status='skipped', error='Narzędzie niedostępne', error_category='missing_dependency'); return None
            vp = subprocess.run([command[0], '--version'], cwd=self.repo, capture_output=True, text=True, timeout=self.version_timeout, env=env)
            if vp.returncode:
                rec['stderr'] = redact(vp.stderr); raise ValueError('Nie udało się odczytać wersji narzędzia')
            rec['version'] = (vp.stdout or vp.stderr).strip()[:200]
            limit = self.timeout.get(tool, 300) if isinstance(self.timeout, dict) else self.timeout
            if output and Path(output).exists(): Path(output).unlink()
            stage = 'execution'
            p = subprocess.run(command, cwd=self.repo, capture_output=True, text=True, timeout=limit, env=env)
            rec['exit_code'] = p.returncode
            rec['stderr'] = redact(p.stderr)
            if p.returncode not in allowed: raise ValueError(f'Narzędzie zakończyło się kodem {p.returncode}')
            stage = 'json'
            raw = Path(output).read_text() if output else p.stdout
            data = json.loads(raw)
            expected = list if tool == 'gitleaks' else dict
            stage = 'schema'
            if not isinstance(data, expected): raise ValueError('Niepoprawny schemat wyniku')
            if tool == 'semgrep':
                if not isinstance(data.get('results'), list):
                    raise ValueError('Semgrep: brak listy results')
                if not isinstance(data.get('errors'), list):
                    raise ValueError('Semgrep: brak listy errors')
                paths = data.get('paths')
                if not isinstance(paths, dict) or not isinstance(paths.get('scanned'), list) or any(not isinstance(p, str) for p in paths['scanned']):
                    raise ValueError('Semgrep: brak poprawnej listy paths.scanned')
                # A warning (e.g. one file parsed only partly) leaves the findings of the other files valid;
                # coverage is marked partial.
                if any(not (isinstance(e, dict) and e.get('level') == 'warn') for e in data['errors']):
                    raise ValueError('Semgrep zgłosił błędy skanowania')
                if data['errors']:
                    files = sorted({e['path'] for e in data['errors'] if isinstance(e.get('path'), str)})
                    rec.update(status='partial', error_category='partial_parse',
                               error=f'Semgrep: ostrzeżenia dla {len(files)} plików, wyniki z nich mogą być niepełne: ' + ', '.join(files[:20]))
            return data
        except (OSError, ValueError, subprocess.TimeoutExpired) as e:
            category = 'timeout' if isinstance(e, subprocess.TimeoutExpired) else stage
            raw_detail = getattr(e, 'stderr', '') or ''
            detail = redact(raw_detail) if raw_detail else ''
            rec.update(status='error', error=redact(str(e)), error_category=category, error_type=type(e).__name__)
            if detail: rec['stderr'] = detail
            return None
        finally: rec['duration'] = round(time.monotonic() - start, 3)


def relative(repo, file):
    repo = normalize(repo)
    p = Path(file or '')
    if p.is_absolute():
        try: return relative_path(p, repo).as_posix()
        except ValueError: raise ValueError(f'Scanner path outside repository: {file}')
    return relative_path(repo / p, repo).as_posix() if file else ''


def local_security(repo):
    repo = normalize(repo)
    findings = []
    for path in sorted(Path(repo).rglob('*')):
        if not path.is_file() or path.is_symlink() or any(x in path.parts for x in ('.git', 'node_modules', 'helix-evidence', '.helix', 'vendor')): continue
        file = relative_path(path, repo).as_posix()
        if any(x in path.parts for x in ('public', 'www', 'static', 'wwwroot', 'htdocs', 'webroot', 'dist')) and re.search(r'\.(sql|dump|bak)(\.(gz|zip))?$', file, re.I):
            findings.append(finding('security', 'local-security', 'web-database-dump', 'high', 'Zrzut bazy w drzewie WWW', file, snippet=file, evidence='Ścieżka pliku w katalogu WWW; ekspozycja wymaga walidacji.', verdict='needs_validation'))
        if not re.search(r'example|sample|template|dist', path.name, re.I): continue
        for n, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            if re.search(r'(password|passwd|pwd|secret)[\"\']?\s*[=:]\s*[\"\']?(admin|password|changeme|root|123456|test|default)\b', line, re.I):
                findings.append(finding('security', 'local-security', 'example-default-credentials', 'high', 'Domyślne poświadczenia w przykładzie konfiguracji', file, n, snippet='default-credential', evidence='Wartość poświadczenia pominięta; sprawdź sposób wdrożenia przykładu.', verdict='needs_validation'))
    return findings


def evidence_text(repo, root=None):
    # truth.json (claims) and scanner reports are not read as acceptance evidence.
    texts = []
    for p in Path(root or Path(repo) / 'helix-evidence').rglob('*'):
        if p.is_file() and not p.is_symlink() and p.name in ('operator.md', 'validation.md', 'database.md', 'deletion.md'):
            texts.append(p.read_text(errors='replace'))
    return '\n'.join(texts)


def security(repo, cfg, out, runner, args):
    findings = []
    repo = normalize(repo)
    scan_repo = normalize(getattr(args, '_scan_root', repo))
    findings.extend(local_security(scan_repo))
    for tool in cfg.get('tools', TOOLS['security']):
        dest = out / f'.{tool}.json'; data = None
        if getattr(args, 'offline', False):
            remote_rules = any(not (repo / config).is_file() for config in cfg.get('configs', ['p/default']))
            if tool in ('trivy', 'osv-scanner') or (tool == 'semgrep' and remote_rules):
                runner.records.append(dict(tool=tool, version=None, command=[], exit_code=None, duration=0,
                                           status='skipped', error_category='offline',
                                           error='offline: wymagane dane sieciowe; kontrola nie została wykonana'))
                continue
        if tool == 'gitleaks':
            cmd = [tool, 'git' if getattr(args, 'full_history', False) else 'dir', str(scan_repo), '--redact', '--no-banner', '-f', 'json', '-r', str(dest)]
            data = runner.run(tool, cmd, (0, 1), output=dest)
            if dest.exists(): dest.unlink()
            for x in data or []:
                rule = x.get('RuleID', 'secret'); file = relative(scan_repo, x.get('File', ''))
                # Secret/Match and raw tool payloads never reach evidence, even if a tool ignores --redact.
                identity = x.get('Secret') or x.get('Match') or rule
                source = repo / file
                historical = git(repo, 'show', f"{x['Commit']}:{file}") if getattr(args, 'full_history', False) and x.get('Commit') else None
                if historical is not None:
                    lines = historical.splitlines()
                elif source.is_file() and not source.is_symlink() and within(source, repo):
                    lines = source.read_text(errors='replace').splitlines()
                else: lines = []
                line = x.get('StartLine', 0)
                if 0 < line <= len(lines): identity = '\n'.join(lines[line-1:max(line, x.get('EndLine') or line)])
                findings.append(finding('security', tool, rule, 'critical' if 'private' in rule.lower() and 'key' in rule.lower() else 'high',
                                        'Wykryto potencjalny sekret', file, x.get('StartLine'), identity,
                                        'gitleaks: wykryto sekret (wartość pominięta)', SECRET_HINT, 'secret'))
        elif tool == 'semgrep':
            cmd = [tool, 'scan']
            for config in cfg.get('configs', ['p/default']): cmd += ['--config', config]
            if (repo / '.helix/semgrep').is_dir(): cmd += ['--config', str(repo / '.helix/semgrep')]
            cmd += ['--json', '--metrics', 'off']
            for excluded in ('node_modules', 'build', 'dist', 'vendor', '.svelte-kit'): cmd += ['--exclude', excluded]
            if scan_repo != repo: cmd.append(str(scan_repo))
            data = runner.run(tool, cmd)
            for x in (data or {}).get('results', []):
                e = x.get('extra', {}); message = e.get('message', 'Ustalenie Semgrep')
                findings.append(finding('security', tool, x['check_id'], {'ERROR':'high','WARNING':'medium','INFO':'low'}.get(e.get('severity'), 'info'),
                                        message, relative(scan_repo, x.get('path')), x.get('start', {}).get('line'), e.get('lines', message),
                                        message[:300], message.split('. ')[0], 'sast'))
        elif tool == 'trivy':
            data = runner.run(tool, [tool, 'fs', '--scanners', 'vuln,misconfig', '--format', 'json', '--skip-dirs', 'node_modules', str(repo)])
            for result in (data or {}).get('Results', []):
                for x in result.get('Vulnerabilities') or []:
                    findings.append(sca(tool, result.get('Target', ''), result.get('Type', ''), x.get('PkgName', ''), x.get('InstalledVersion', ''),
                                        x['VulnerabilityID'], x.get('Severity', 'UNKNOWN').lower(), x.get('FixedVersion', ''), x.get('Aliases', [])))
                for x in result.get('Misconfigurations') or []:
                    if x.get('Status') == 'PASS': continue
                    findings.append(finding('security', tool, x['ID'], x.get('Severity', '').lower(), x.get('Title', x['ID']), result.get('Target', ''),
                                            x.get('CauseMetadata', {}).get('StartLine'), x['ID'], x.get('Message', '')[:300],
                                            x.get('Resolution', 'Popraw wskazaną konfigurację.'), 'misconfig'))
        elif tool == 'osv-scanner':
            data = runner.run(tool, [tool, '--format', 'json', '-r', str(repo)], (0, 1), optional=True)
            for result in (data or {}).get('results', []):
                for item in result.get('packages', []):
                    p = item.get('package', {})
                    for v in item.get('vulnerabilities', []):
                        fixed = next((e['fixed'] for a in v.get('affected', []) for r in a.get('ranges', []) for e in r.get('events', []) if 'fixed' in e), '')
                        sev = v.get('database_specific', {}).get('severity', 'high').lower()
                        findings.append(sca(tool, result.get('source', {}).get('path', ''), p.get('ecosystem', ''), p.get('name', ''), p.get('version', ''), v['id'], sev, fixed, v.get('aliases', [])))
        elif tool == 'bandit':
            data = runner.run(tool, [tool, '-r', str(scan_repo), '-f', 'json'], (0, 1), optional=True)
            if (data or {}).get('errors'): runner.records[-1].update(status='error', error='Bandit zgłosił błędy skanowania')
            for x in (data or {}).get('results', []):
                findings.append(finding('security', tool, x['test_id'], x.get('issue_severity', '').lower(), x.get('issue_text', ''), relative(scan_repo, x.get('filename')),
                                        x.get('line_number'), x.get('code', ''), x.get('issue_text', '')[:300], 'Popraw wskazane użycie API.', 'sast'))
        else: runner.records.append(dict(tool=tool, version=None, command=[], exit_code=None, duration=0, status='error', error='Nieznane narzędzie'))
        if dest.exists(): dest.unlink()  # gitleaks output is not retained, even on failure
    return findings, {}


def sca(tool, file, ecosystem, package, version, vuln, severity, fixed, aliases):
    ecosystem = {'pip':'pypi', 'python':'pypi', 'node-pkg':'npm', 'node':'npm'}.get(ecosystem.lower(), ecosystem.lower())
    return finding('security', tool, vuln, severity, f'{package}: {vuln}', file, snippet=f'{package}@{version}',
                   evidence=f'{package}@{version}: {vuln}', fix_hint=f'Podbij {package} do {fixed}' if fixed else f'Sprawdź poprawioną wersję {package} i zaktualizuj zależność.',
                   category='sca', ecosystem=ecosystem, package=package, aliases=aliases, versions=[version], sources=[file],
                   occurrences=[dict(version=version, source=file, tool=tool, fixed_version=fixed, evidence=f'{package}@{version}: {vuln}')])


METRICS = {'largest-contentful-paint': ('lcp', 2500), 'cumulative-layout-shift': ('cls', .1),
           'total-blocking-time': ('tbt', 200), 'total-byte-weight': ('total-byte-weight', 1600000), 'performance': ('performance', .8)}


def metric_findings(metrics, cfg, previous):
    findings = []; budgets = cfg.get('budgets', {})
    for key, measurement in metrics.items():
        page, metric = key.rsplit('|', 1); value, values = measurement['median'], measurement['values']
        default = next((v for alias, v in METRICS.values() if alias == metric), 350 * 1024)
        budget = budgets.get(metric, budgets.get({'lcp':'LCP','cls':'CLS','tbt':'TBT'}.get(metric, metric), default))
        if metric == 'bundle': budget = budgets.get('bundle_kb_gzip', cfg.get('bundle_kb_gzip', 350)) * 1024
        inverse = metric == 'performance'; breach = value < budget if inverse else value > budget
        old = previous.get(key, {}).get('median')
        noise = .02 if metric == 'cls' else (old or 0) * .05 if metric in ('bundle', 'total-byte-weight') else .02 if inverse else 20
        delta = (old - value if inverse else value - old) if old is not None else 0
        regression = old is not None and delta > noise and delta > abs(old) * (.05 if metric == 'bundle' else .1)
        if not (breach or regression): continue
        high = (value < budget / 1.5 if inverse else value > budget * 1.5) if breach else False
        findings.append(finding('perf', 'bundle' if metric == 'bundle' else 'lighthouse', metric, 'high' if high else 'medium',
                                f'{page}: {metric} — ' + ('przekroczony budżet' if breach else 'regresja'), page, snippet=key,
                                evidence=f'Mediana {value:g}; pomiary {values}; budżet {budget:g}' + (f'; baseline {old:g}' if old is not None else ''),
                                fix_hint=f'Zoptymalizuj {metric} na stronie {page} i powtórz pomiar.', regressed=regression))
    return findings


def safe_url(url, allow):
    import helix_ux as U
    try: return U.assert_safe_url(url, allow)
    except SystemExit:
        raise ValueError(f"perf: niedozwolony host {urllib.parse.urlparse(url).hostname}; wymagany localhost lub ux.allow_hosts") from None


def perf(repo, cfg, out, runner, args, previous, full_cfg):
    import helix_ux as U
    ux = full_cfg.get('ux', {}); visual = full_cfg.get('visual', {})
    url = getattr(args, 'base_url', None) or cfg.get('base_url') or ux.get('base_url') or visual.get('url')
    pages = cfg.get('pages', ux.get('pages', [])); metrics = {}; findings = []
    if getattr(args, 'offline', False) and (pages or cfg.get('k6')):
        raise ValueError('offline: pomiary przeglądarki i k6 wymagają osobnego wykonania; bundle można sprawdzić lokalnie')
    if not isinstance(cfg.get('runs', 3), int) or cfg.get('runs', 3) < 1: raise ValueError('perf.runs musi być dodatnie')
    if (pages or cfg.get('k6')) and not url: raise ValueError('perf: brak base_url')
    if url: safe_url(url, ux.get('allow_hosts', []))
    if cfg.get('k6'):
        # k6 scripts are arbitrary code; require a strictly local BASE_URL even if staging is allowlisted.
        if urllib.parse.urlparse(url).hostname not in U.LOCAL: raise ValueError('k6: BASE_URL musi wskazywać localhost')
        external = os.environ.get('BASE_URL')
        if external and urllib.parse.urlparse(external).hostname not in U.LOCAL: raise ValueError('k6: zewnętrzne BASE_URL jest zabronione')
    env = os.environ.copy()
    if not env.get('CHROME_PATH'):
        browser_root = Path(os.environ.get('PLAYWRIGHT_BROWSERS_PATH') or (Path.home() / 'Library/Caches/ms-playwright' if sys.platform == 'darwin' else Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'ms-playwright'))
        candidates = sorted([*browser_root.glob('chromium-*/chrome-linux*/chrome'), *browser_root.glob('chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium'), *browser_root.glob('chromium-*/chrome-mac*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing')])
        if candidates: env['CHROME_PATH'] = str(candidates[-1])
    start = cfg.get('start_cmd', ux.get('start_cmd') or visual.get('start_cmd'))
    server = None
    try:
        if pages and start and not getattr(args, 'no_start', False):
            server = U.Server(type('Context', (), {'repo': repo})(), dict(start_cmd=start, base_url=url, ready_timeout_s=cfg.get('ready_timeout_s', 60)))
        for pi, page in enumerate(pages):
            target = urllib.parse.urljoin(url.rstrip('/') + '/', page.get('path', '/').lstrip('/'))
            safe_url(target, ux.get('allow_hosts', [])); values = {alias: [] for alias, _ in METRICS.values()}
            for run in range(cfg.get('runs', 3)):
                dest = out / f'.lighthouse-{pi}-{run}.json'
                data = runner.run('lighthouse', ['lighthouse', target, '--output', 'json', '--output-path', str(dest), '--quiet',
                    '--chrome-flags=--headless=new --no-sandbox --disable-dev-shm-usage', '--only-categories=performance,accessibility,best-practices'], output=dest, env=env)
                if data:
                    try:
                        if data.get('runtimeError'): raise ValueError('runtimeError')
                        for audit, (alias, _) in METRICS.items():
                            v = data['categories']['performance']['score'] if audit == 'performance' else data['audits'][audit]['numericValue']
                            if not isinstance(v, (float, int)): raise ValueError('Brak metryki')
                            values[alias].append(v)
                    except (KeyError, TypeError, ValueError): runner.records[-1].update(status='error', error='Lighthouse: niepełny pomiar')
                if dest.exists(): dest.unlink()
            for metric, vals in values.items():
                if len(vals) == cfg.get('runs', 3) and vals: metrics[page['name'] + '|' + metric] = dict(median=statistics.median(vals), values=vals)
        if cfg.get('build_cmd'):
            start_time = time.monotonic(); rec = dict(tool='build', version=None, command=cfg['build_cmd'], duration=0, exit_code=None, error=None, status='ok')
            runner.records.append(rec)
            try:
                p = subprocess.run(cfg['build_cmd'], shell=True, cwd=repo, capture_output=True, timeout=300); rec['exit_code'] = p.returncode
                if p.returncode: rec.update(status='error', error='Błąd budowania')
            except (OSError, subprocess.TimeoutExpired): rec.update(status='error', error='Błąd/czas budowania')
            rec['duration'] = round(time.monotonic() - start_time, 3)
        dirs = [cfg['build_dir']] if cfg.get('build_dir') else ['build', '.svelte-kit/output/client', 'dist']
        build = next((repo / d for d in dirs if (repo / d).is_dir()), None)
        if build:
            total = sum(len(gzip.compress(p.read_bytes(), mtime=0)) for p in build.rglob('*') if p.suffix in ('.js', '.css') and p.is_file() and not p.is_symlink())
            metrics['bundle|bundle'] = dict(median=total, values=[total])
        if not pages and not build and not cfg.get('k6'): raise ValueError('perf: brak stron, bundle i scenariuszy k6')
        for i, job in enumerate(cfg.get('k6', [])):
            dest = out / f'.k6-{i}.json'; env['BASE_URL'] = url
            data = runner.run('k6', ['k6', 'run', '--summary-export', str(dest), job['script']], (0, 99), optional=True, output=dest, env=env)
            if data is not None:
                failed = [f'{name}: {threshold}' for name, m in data.get('metrics', {}).items() for threshold, result in m.get('thresholds', {}).items()
                          if result is False or isinstance(result, dict) and result.get('ok') is False]
                if runner.records[-1]['exit_code'] == 99 and not failed: runner.records[-1].update(status='error', error='k6: brak wyników progów')
                if failed: findings.append(finding('perf', 'k6', 'thresholds', 'high', f"k6: {job['name']} — przekroczone progi", job['script'], snippet=job['name'], evidence='; '.join(failed), fix_hint='Zoptymalizuj endpointy przekraczające progi k6.'))
            if dest.exists(): dest.unlink()
    finally:
        if server: server.__exit__()
    return findings + metric_findings(metrics, cfg, previous), metrics

TEST_GLOBS = ['tests/**', '**/test_*.py', '**/*_test.py', '**/*.test.*', '**/*.spec.*', '**/__tests__/**']
SKIPS = re.compile(r'@pytest\.mark\.(?:skipif|skip|xfail)\b|pytest\.skip\s*\(|\.(?:skip|only)\s*\(|\b(?:xit|xdescribe)\s*\(|\btest\.todo\b')
ASSERTS = re.compile(r'\bassert\s+|\bexpect\s*\(|\bself\.assert\w*\s*\(')


def code_only(text, file):
    """Mask literals/comments while retaining offsets for deterministic marker locations."""
    if file.endswith('.py'):
        import io, tokenize
        chars = list(text); starts = [0]
        for m in re.finditer('\n', text): starts.append(m.end())
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type not in (tokenize.STRING, tokenize.COMMENT): continue
                start = starts[token.start[0]-1] + token.start[1]
                end = starts[token.end[0]-1] + token.end[1]
                for i in range(start, min(end, len(chars))):
                    if chars[i] != '\n': chars[i] = ' '
            return ''.join(chars)
        except (tokenize.TokenError, IndentationError): pass
    pattern = r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|//[^\n]*|/\*.*?\*/"
    return re.sub(pattern, lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)


def test_functions(text, file):
    if file.endswith('.py'):
        import ast
        try:
            tree = ast.parse(text)
            functions = {}
            def visit(node, prefix=''):
                for n in ast.iter_child_nodes(node):
                    if isinstance(n, ast.ClassDef): visit(n, prefix + n.name + '.')
                    elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_'):
                        functions[prefix + n.name] = '\n'.join(text.splitlines()[n.lineno-1:n.end_lineno])
                    else: visit(n, prefix)
            visit(tree)
            return functions
        except SyntaxError: pass
    pattern = re.compile(r"\b(?:test|it)(?:\.(?:skip|only|todo))?\s*\(\s*(['\"`])(.*?)\1", re.S)
    matches = list(pattern.finditer(text))
    return {m.group(2): text[m.start():matches[i+1].start() if i+1 < len(matches) else len(text)] for i, m in enumerate(matches)}


def runner_change(file, before, after):
    name = Path(file).name
    if name == 'pyproject.toml':
        def section(s):
            m = re.search(r'^\[tool\.pytest[^\]]*\].*?(?=^\[(?!tool\.pytest)|\Z)', s, re.M | re.S)
            return m.group(0) if m else ''
        return section(before) != section(after)
    if name == 'package.json':
        def script(s):
            try: return json.loads(s).get('scripts', {}).get('test')
            except ValueError: return s
        return script(before) != script(after)
    if file.startswith('.github/workflows/'):
        return any(re.search(r'test|pytest|jest|vitest|playwright', line, re.I) for line in changed_lines(before, after))
    return name in ('pytest.ini', 'conftest.py') or bool(re.match(r'(?:vitest|jest|playwright)\.config\.', name))


def changed_lines(before, after):
    import difflib
    return [line[1:] for line in difflib.unified_diff(before.splitlines(), after.splitlines())
            if line.startswith(('+', '-')) and not line.startswith(('+++', '---'))]


def base_blobs(repo, base, names):
    """Read changed blobs in one batch by object ID, including unusual filenames."""
    if not names:
        return {}
    tree = git(repo, 'ls-tree', '-r', '-z', base, required=True)
    objects = {}
    for entry in tree.split('\0'):
        if not entry: continue
        header, name = entry.split('\t', 1)
        mode, kind, oid = header.split()
        if name in names and kind == 'blob': objects[name] = oid
    if set(names) != set(objects):
        raise ValueError('integrity: niepełny inwentarz bazowych plików')
    ordered = sorted(objects)
    result = subprocess.run(['git', 'cat-file', '--batch'], cwd=repo, capture_output=True,
                            input=''.join(objects[n] + '\n' for n in ordered).encode(),
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
    if result.returncode:
        raise ValueError('integrity: zbiorczy odczyt Git nie powiódł się')
    offset = 0; blobs = {}
    for name in ordered:
        end = result.stdout.find(b'\n', offset)
        fields = result.stdout[offset:end].split()
        if len(fields) != 3 or fields[0].decode() != objects[name] or fields[1] != b'blob':
            raise ValueError('integrity: niepoprawny nagłówek git cat-file')
        size = int(fields[2]); offset = end + 1
        blobs[name] = result.stdout[offset:offset + size]
        if len(blobs[name]) != size or result.stdout[offset + size:offset + size + 1] != b'\n':
            raise ValueError('integrity: niepełna zawartość git cat-file')
        offset += size + 1
    return blobs


def integrity(repo, cfg, base, runner, evidence_root=None):
    # Enumerate base plus tracked/untracked working files; never follow untracked directories or symlinks.
    repo = normalize(repo)
    old_files = set(filter(None, (git(repo, 'ls-tree', '-r', '--name-only', '-z', base, required=True) or '').split('\0')))
    current = set(filter(None, (git(repo, 'ls-files', '--cached', '--others', '--exclude-standard', '-z', required=True) or '').split('\0')))
    changed = set(filter(None, (git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--name-only', '-z', base, '--', required=True) or '').split('\0'))) | (current - old_files)
    findings = []; skipped = []; start = time.monotonic()
    evidence = evidence_text(repo, evidence_root)
    binary_extensions = {'.woff', '.woff2', '.ttf', '.otf', '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.gz', '.ico', '.so', '.dylib', '.exe'}
    readable_changed = {n for n in changed if not (repo / n).is_symlink() and within(repo / n, repo) and Path(n).suffix.lower() not in binary_extensions}
    blobs = base_blobs(repo, base, readable_changed & old_files)
    for file in sorted(old_files | current):
        path = repo / file
        if path.is_symlink() or not within(path, repo):
            skipped.append(dict(unit=file, status='skipped', reason='symlink or path outside repository'))
            continue
        if path.suffix.lower() in binary_extensions:
            skipped.append(dict(unit=file, status='skipped', reason='binary'))
            if file in changed:
                runner.records.append(dict(tool='git-diff', status='skipped', error='Changed binary or unreadable file: ' + file, version=None, command=[], exit_code=None, duration=0))
            continue
        if file not in changed: continue
        before_bytes = blobs.get(file, b'')
        after_bytes = None
        try:
            after_bytes = path.read_bytes() if path.is_file() else b''
            if b'\0' in before_bytes or b'\0' in after_bytes: raise UnicodeError('binary')
            before = before_bytes.decode('utf-8'); after = after_bytes.decode('utf-8')
        except (UnicodeError, OSError):
            skipped.append(dict(unit=file, status='skipped', reason='binary or unreadable'))
            if before_bytes != after_bytes:
                runner.records.append(dict(tool='git-diff', status='skipped', error='Changed binary or unreadable file: ' + file, version=None, command=[], exit_code=None, duration=0))
            continue
        if before == after: continue
        def add(rule, severity, title, snippet='', line=0):
            findings.append(finding('integrity', 'git-diff', rule, severity, title, file, line, snippet or rule,
                                    evidence=f'Porównanie z {base}: {title}', fix_hint='Przywróć ochronę testami lub uzyskaj uzasadniony waiver właściciela.'))
        if re.search(r'(^|/)(migrations?|alembic/versions)(/|$)', file, re.I) and not re.search(r'^\s*database:\s*\S+', evidence, re.M):
            add('migration-database', 'high', 'Zmiana migracji bez database: w evidence')
        is_test = any(fnmatch.fnmatch(file, g) or fnmatch.fnmatch(file, g.removeprefix('**/')) for g in cfg.get('test_globs', TEST_GLOBS))
        import difflib
        edits = list(difflib.ndiff(before.splitlines(), after.splitlines()))
        removed = [x[2:] for x in edits if x.startswith('- ') and x[2:].strip()]
        added = [x[2:] for x in edits if x.startswith('+ ') and x[2:].strip()]
        production = not is_test and not any(x in Path(file).parts for x in ('tests', 'test', 'fixtures', 'examples', 'docs', 'vendor', '.helix', 'helix-evidence')) and Path(file).suffix in ('.py', '.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx', '.vue', '.svelte', '.cs', '.kt', '.go', '.rs', '.php', '.java', '.c', '.cpp', '.rb', '.swift')
        if production and removed and not added:
            citation = re.search(r'^\s*(telemetry|telemetria|flag|flaga|kill-switch)\s*:\s*(.+)$', evidence, re.M | re.I)
            findings.append(finding('integrity', 'git-diff', 'production-deletion', 'high', 'Kasowanie kodu produkcyjnego — wymagany cytat', file, snippet=hashlib.sha256('\n'.join(removed).encode()).hexdigest(), category='production-deletion', evidence=citation.group(0) if citation else 'Brak cytatu: telemetria, flaga lub kill-switch zostaje.', verdict='needs_validation'))
        if is_test and file in old_files:
            if not path.exists(): add('deleted-test-file', 'high', 'Usunięto plik testowy')
            else:
                old = test_functions(before, file); new = test_functions(after, file)
                for name in sorted(old.keys() - new.keys()): add('deleted-test-function', 'high', f'Usunięto test {name}', name)
                for name in sorted(old.keys() & new.keys()):
                    if ASSERTS.search(code_only(old[name], file)) and not ASSERTS.search(code_only(new[name], file)): add('zero-assertions', 'high', f'Test {name} utracił wszystkie asercje', name)
                if len(ASSERTS.findall(code_only(after, file))) < len(ASSERTS.findall(code_only(before, file))): add('assertion-drop', 'medium', 'Zmniejszono liczbę asercji')
        if is_test:
            from collections import Counter
            old_skips = Counter(m.group(0) for m in SKIPS.finditer(code_only(before, file)))
            for m in SKIPS.finditer(code_only(after, file)):
                marker = m.group(0)
                if old_skips[marker]: old_skips[marker] -= 1; continue
                line = after.count('\n', 0, m.start()) + 1
                add('added-only' if '.only' in marker else 'added-skip', 'high', f'Dodano marker {marker}', after.splitlines()[line-1].strip(), line)
        if runner_change(file, before, after): add('runner-config', 'medium', 'Zmiana konfiguracji testów wymaga uzasadnienia')
        if '__snapshots__' in file or file.endswith('.snap') or 'golden' in file or re.search(r'fixtures/expected', file):
            add('snapshot-change', 'medium', 'Zmieniono snapshot / golden — wymaga uzasadnienia')
    runner.records.append(dict(tool='git-diff', version=(git(repo, '--version') or '').strip(), command=['git', 'diff', base, '--', '.'],
                               exit_code=0, duration=round(time.monotonic()-start, 3), error=None, status='ok'))
    return findings, {"coverage": skipped, "changed_files": len(changed), "inventory_files": len(old_files | current),
                      "base_blobs_read": len(blobs), "scope": "changed tracked and untracked files"}


def policy(repo, pack, args):
    from helix_config import load
    full = load(repo)
    working = full.get('packs', {}); ref = base_ref(repo, working)
    trusted = getattr(args, 'trusted_base', False) or working.get('trusted_base', False)
    base_full = base_json(repo, ref, 'helix.json', {}) if trusted else full
    packs = base_full.get('packs', {})
    cfg = dict(packs.get(pack, {})); cfg.setdefault('mode', 'advisory' if pack == 'perf' else 'blocking'); cfg.setdefault('fail_on', ['critical', 'high'])
    if cfg['mode'] not in ('advisory', 'blocking') or not set(cfg['fail_on']) <= set(SEVERITIES): raise ValueError('Niepoprawna konfiguracja bramki')
    path = f'.helix/baselines/{pack}.json'; metrics_path = f'.helix/baselines/{pack}-metrics.json'
    baseline = base_json(repo, ref, path, {}) if trusted else read_json(repo / path, {})
    metrics = base_json(repo, ref, metrics_path, {}) if trusted else read_json(repo / metrics_path, {})
    changed = trusted and (working != packs or baseline != read_json(repo / path, {}) or metrics != read_json(repo / metrics_path, {}))
    return full if not trusted else base_full, cfg, ref, baseline, metrics, changed


def render_report(pack, findings, record, result):
    from helix_paths import summarize
    lines = [f'# Paczka {pack}', '', f"Bramka: **{result['status']}**; tryb: {result['mode']}; blokowałoby: {result['would_fail']}", '',
             'VERIFIED = potwierdzony fakt; ASSUMPTION = wymaga walidacji.', '', '| Waga | Nowe | Baseline | Waiver |', '|---|---:|---:|---:|']
    for sev in SEVERITIES:
        lines.append('| ' + sev + ' | ' + ' | '.join(str(sum(f['severity'] == sev and f['status'] == status for f in findings)) for status in ('new', 'baselined', 'waived')) + ' |')
    if result.get('trust_changed'): lines += ['', '[!] baseline/config zmienione w tej gałęzi — wymaga akceptacji właściciela']
    for verdict in ('confirmed', 'needs_validation', 'rejected'):
        lines += ['', f'## {verdict} (top 20)', '']
        for f in sorted((f for f in findings if f['status'] == 'new' and f.get('verdict', 'confirmed') == verdict), key=lambda f: SEVERITIES.index(f['severity']))[:20]:
            detail = summarize((x['evidence'] for x in f['occurrences']), 'findings.json/occurrences') if f.get('occurrences') else f['evidence']
            lines += [f"- [{f['severity']}] {f['tag']} {f['title']} — {f['file']}:{f['line']}", f"  {detail}", f"  Poprawka: {f['fix_hint']}"]
    deletions = [f for f in findings if f.get('category') == 'production-deletion']
    if deletions:
        lines += ['', '## Kasowania kodu produkcyjnego', '']
        lines += [f"- {f['file']}: {f['verdict']} — {f['evidence']}" for f in deletions]
    lines += ['', '## Narzędzia' , '', '| Narzędzie | Wersja | Status | Kod | Czas (s) |', '|---|---|---|---|---|']
    for r in record['tools']: lines.append(f"| {r['tool']} | {r['version'] or '-'} | {r['status']} | {r['exit_code']} | {r['duration']} |")
    lines += ['', '## Błędy i pominięcia', '']
    lines += [f"- {r['tool']}: {r['error']} ({r['status']})" for r in record['tools'] if r.get('error')]
    lines += [f"- {u['unit']}: {u['reason']} ({u['status']})" for u in record.get('metrics', {}).get('coverage', [])]
    if pack == 'perf': lines += ['', 'Licznik zapytań SQL: faza 2. Pomiar dotyczy wyłącznie skonfigurowanych stron.']
    provenance = record.get('provenance', {})
    lines += ['', 'Odtwarzalność: Helix ' + str(provenance.get('helix_version', 'nieznany'))
              + '; commit celu ' + str(provenance.get('target_head') or 'nieznany')
              + '. Wersje narzędzi i stan źródeł: `run.json/provenance`.']
    return '\n'.join(lines) + '\n'


def evaluate(pack, findings, cfg, records, changed):
    errors = any(r['status'] == 'error' for r in records)
    would = changed or any(f['status'] == 'new' and f.get('verdict', 'confirmed') in ('confirmed', 'needs_validation') and f['severity'] in cfg['fail_on'] for f in findings)
    incomplete = any(r['status'] in ('skipped', 'partial') for r in records)
    code = 3 if errors or incomplete else 2 if cfg['mode'] == 'blocking' and would else 0
    return dict(gate=pack, status='ERROR' if errors else 'INCOMPLETE' if incomplete else 'FAIL' if code == 2 else 'PASS', **{'pass': code == 0 and not incomplete},
                exit_code=code, mode=cfg['mode'], would_fail=would, trust_changed=changed,
                counts={s: sum(f['status'] == s for f in findings) for s in ('new', 'baselined', 'waived')})


def scan(ctx, pack, args, checkpoint=None):
    repo = normalize(ctx.repo)
    out = Path(getattr(args, 'out', None) or getattr(ctx, 'evidence_root', repo / 'helix-evidence') / f'{pack}-{dt.datetime.now():%Y%m%d-%H%M%S-%f}')
    if not out.is_absolute(): out = repo / out
    out.mkdir(parents=True, exist_ok=True)
    runner = Runner(repo); findings = []; metrics = {}; changed = False
    cfg = dict(mode='advisory' if pack == 'perf' else 'blocking', fail_on=['critical', 'high']); ref = 'HEAD'
    import helix_runs
    session = helix_runs.Session(ctx, pack, args, out, getattr(ctx, 'cfg', {}))
    session.data['checkpoint'] = checkpoint
    try:
        full, cfg, ref, baseline, previous, changed = policy(repo, pack, args)
        runner.timeout = cfg.get('timeouts', cfg.get('timeout_s', 300))
        runner.version_timeout = cfg.get('version_timeout_s', 30)
        session.config = full
        if pack == 'security':
            findings.extend(local_security(repo))
            for tool in cfg.get('tools', TOOLS['security']):
                fs, ms = session.execute(tool, lambda tool=tool: security(repo, dict(cfg, tools=[tool]), out, runner, args), runner)
                findings.extend(fs); metrics.update(ms)
        elif pack == 'perf': findings, metrics = session.execute('perf', lambda: perf(repo, cfg, out, runner, args, previous, full), runner)
        else:
            explicit = getattr(args, 'base', None)
            cp_base = ctx.state(checkpoint).get('base') if checkpoint else None
            ref = explicit or cp_base or git(repo, 'merge-base', 'HEAD', ref, required=True).strip()
            session.config = dict(full, _integrity_base=ref, _validation_evidence=hashlib.sha256(evidence_text(repo, getattr(ctx, 'evidence_root', None)).encode()).hexdigest())
            findings, metrics = session.execute('integrity', lambda: integrity(repo, cfg, ref, runner, getattr(ctx, 'evidence_root', None)), runner)
        findings = dedupe(findings)
        waivers = base_json(repo, ref, '.helix/integrity-waivers.json', {}) if pack == 'integrity' else {}
        today = dt.date.today().isoformat()
        for f in findings:
            b = baseline.get(f['fingerprint'])
            if b and not f.get('regressed') and b.get('review_by', '') >= today and SEVERITIES.index(f['severity']) >= SEVERITIES.index(b['severity']): f['status'] = 'baselined'
            if waivers.get(f['fingerprint']): f['status'] = 'waived'
    except (ValueError, OSError, KeyError, TypeError, AttributeError, SystemExit, subprocess.SubprocessError) as e:
        if runner.records and runner.records[-1]['status'] == 'ok':
            runner.records[-1].update(status='error', error='Niekompletny wynik / błąd analizy')
        runner.records.append(dict(tool=pack, version=None, command=[], exit_code=None, duration=0, error='Nie udało się uruchomić serwera aplikacji' if isinstance(e, SystemExit) else str(e), status='error'))
    if pack == 'security':
        metrics.setdefault('coverage', []).extend(
            dict(unit=p.relative_to(repo).as_posix(), status='skipped', reason='symlink; target not scanned')
            for p in repo.rglob('*') if p.is_symlink()
            and not any(part in ('.git', '.helix', 'helix-evidence', 'node_modules', 'vendor') for part in p.relative_to(repo).parts))
    if 'session' in locals():
        metrics['cache_hits'] = session.hits
        metrics['run_id'] = session.data['run_id']
    record = dict(pack=pack, head=(git(repo, 'rev-parse', 'HEAD') or '').strip(), base_ref=ref, base_sha=(git(repo, 'rev-parse', ref) or '').strip(), tools=runner.records, metrics=metrics)
    from helix_environment import provenance
    record['provenance'] = provenance(repo, tools=runner.records)
    result = evaluate(pack, findings, cfg, runner.records, changed)
    result['provenance'] = record['provenance']
    record['status'] = result['status'].lower(); result['report'] = str(out / 'report.md')
    write_json(out / 'coverage-ledger.json', [dict(unit=r['tool'], status=r['status'], reason=r.get('error')) for r in runner.records] + metrics.get('coverage', []))
    write_json(out / 'findings.json', findings); write_json(out / 'run.json', record)
    (out / 'report.md').write_text(render_report(pack, findings, record, result))
    write_json(out / 'gate.json', result)
    if not getattr(args, '_defer_finish', False): session.finish(result, findings)
    ctx._pack_session = session
    if checkpoint:
        dest = ctx.ev(checkpoint); dest.mkdir(parents=True, exist_ok=True); shutil.copyfile(out / 'report.md', dest / f'{pack}.md')
        write_json(dest / f'{pack}.json', dict(result, findings=findings, run=record))
    return result, findings, record, out


def baseline_write(repo, pack, findings, metrics, args):
    accept = {}
    for value in getattr(args, 'accept_secret', []) or []:
        fp, sep, reason = value.partition('=')
        if not sep or not re.search(r'rotated|revoked|false-positive', reason, re.I): raise ValueError('--accept-secret wymaga fingerprint=powód (rotated/revoked/false-positive)')
        accept[fp] = reason
    secrets = [f for f in findings if f.get('category') == 'secret' and f['fingerprint'] not in accept]
    if secrets: raise ValueError('Sekrety nie zostały zapisane do baseline. Wymagane --accept-secret dla: ' + ', '.join(f['fingerprint'] for f in secrets))
    today = dt.date.today(); reason = getattr(args, 'reason', None) or f'dług zastany {today}'
    entries = {f['fingerprint']: dict(severity=f['severity'], title=f['title'], reason=accept.get(f['fingerprint'], reason), added=str(today),
                                     review_by=str(today + dt.timedelta(days=90))) for f in findings}
    write_json(repo / f'.helix/baselines/{pack}.json', entries)
    if pack == 'perf': write_json(repo / '.helix/baselines/perf-metrics.json', metrics)


def cmd_pack(ctx, args):
    pack = args.cmd
    if pack == 'security' and args.action == 'deep':
        import helix_security_deep as D
        if not getattr(args, 'plan_only', False) and not getattr(ctx, 'offline', False) and not getattr(args, 'resume', None):
            # CLI command: an expired or missing probe of the chosen models is refreshed once before the role plan,
            # so the half-hour probe expiry (helix_provider_plan.TTL_SECONDS) alone does not leave the run LIMITED.
            import helix_provider_plan as RP
            roles = {role: getattr(args, role, None) or (ctx.cfg.get('providers') or {}).get(role) for role in ('hunter', 'verifier')}
            models = ctx.cfg.get('models') or {}
            # The provider's primary model (first in the chain) counts: the plan never swaps an explicit choice for a fallback.
            if any(p and not RP.model_available(getattr(ctx, 'availability', {}), p, (models.get(p) or [None])[0]) for p in roles.values()):
                try: ctx.availability = RP.refresh(ctx, D.H.CALLERS, ctx.state_dir / 'provider-availability.json')
                except (ValueError, OSError) as error: print('[helix] odświeżenie sond nieudane: ' + str(error)[:200])
        return D.cmd_deep(ctx, args)
    if args.action == 'report':
        if not getattr(args, 'out', None): raise SystemExit('report: wymagane --out istniejącego pomiaru')
        out = Path(args.out); out = out if out.is_absolute() else ctx.repo / out
        findings = read_json(out / 'findings.json'); record = read_json(out / 'run.json'); result = read_json(out / 'gate.json')
        if findings is None or record is None or result is None: raise SystemExit('report: brak kompletnego pomiaru')
        (out / 'report.md').write_text(render_report(pack, findings, record, result)); print(out / 'report.md'); return
    result, findings, record, out = scan(ctx, pack, args)
    if args.action == 'baseline' and result['exit_code'] != 3:
        try: baseline_write(ctx.repo, pack, findings, record['metrics'], args)
        except ValueError as e: print(str(e)); raise SystemExit(2)
    print(json.dumps(result, ensure_ascii=False))
    # Scans report findings; enforcement belongs to `gate`.
    if result['exit_code'] == 3: raise SystemExit(3)


def gate_pack(ctx, args):
    checkpoint = getattr(args, 'checkpoint', None)
    args._defer_finish = True
    result, findings, record, out = scan(ctx, args.which, args, checkpoint)
    if args.which == 'security':
        try:
            _, cfg, _, _, _, _ = policy(ctx.repo, 'security', args)
            if cfg.get('deep_required', False):
                import helix_security_deep as D
                runs = D.prior_runs(ctx.repo, ctx.state_dir / 'security-audit' if getattr(ctx, 'external_state', False) else D.run_root(ctx.repo))
                if not runs: raise ValueError('Brak wymaganego security deep run')
                latest = runs[-1]
                metadata = read_json(latest / 'run-metadata.json', {})
                deep = read_json(latest / 'helix-findings.json')
                if not isinstance(deep, list) or metadata.get('errors') or metadata.get('run_status') != 'complete' or metadata.get('uncovered_units'):
                    raise ValueError('Niekompletny security deep run')
                if any(f.get('verdict') == 'confirmed' and f.get('severity') in ('high', 'critical') for f in deep):
                    if result['exit_code'] != 3: result.update(status='FAIL', exit_code=2, **{'pass': False}, would_fail=True)
                result['deep_run'] = str(latest)
        except (ValueError, OSError, TypeError, AttributeError):
            result.update(status='ERROR', exit_code=3, **{'pass': False}, deep_error='Brak poprawnego wymaganego security deep run')
    write_json(out / 'gate.json', result)
    record['status'] = result['status'].lower(); write_json(out / 'run.json', record)
    report = render_report(args.which, findings, record, result)
    if result.get('deep_run'): report += '\nSecurity deep: ' + result['deep_run'] + '\n'
    if result.get('deep_error'): report += '\nSecurity deep ERROR: ' + result['deep_error'] + '\n'
    (out / 'report.md').write_text(report)
    ctx._pack_session.finish(result, findings)
    if checkpoint:
        dest = ctx.ev(checkpoint)
        (dest / f'{args.which}.md').write_text(report)
        write_json(dest / f'{args.which}.json', dict(result, findings=findings, run=record))
    print(json.dumps(result, ensure_ascii=False)); raise SystemExit(result['exit_code'])


def cmd_packs(ctx, args):
    cfg = ctx.cfg.get('packs', {})
    for pack in PACKS:
        print(f'{pack}:')
        for tool in cfg.get(pack, {}).get('tools', TOOLS[pack]):
            path = shutil.which(tool)
            if not path: print(f'  {tool}: brak'); continue
            try:
                p = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=10, cwd=ctx.repo)
                print(f"  {tool}: {(p.stdout or p.stderr).strip()[:160] if not p.returncode else 'błąd wersji'}")
            except (OSError, subprocess.TimeoutExpired): print(f'  {tool}: błąd wersji')
        if pack == 'integrity': print('  git-diff: wbudowany')


def redact(value):
    """Retain diagnostic categories, never arbitrary tool/source payloads."""
    value = str(value or '').lower()
    labels = [('permission', ('permission denied', 'read-only', 'eacces', 'operation not permitted')),
              ('network', ('network', 'connection', 'dns', 'resolve host', 'ssl', 'socket')),
              ('timeout', ('timed out', 'timeout')), ('json', ('json',)),
              ('authentication', ('unauthorized', 'authentication', 'api key'))]
    safe = [label for label, words in labels if any(w in value for w in words)]
    diagnostics = [('ca-certs: empty trust anchors; napraw lokalny magazyn certyfikatów CA', ('empty trust anchors',)),
                   ('certificate verify failed; sprawdź zaufane CA', ('certificate_verify_failed', 'certificate verify failed')),
                   ('niepoprawny schemat wyniku skanera', ('niepoprawny schemat', 'brak listy', 'brak poprawnej listy')),
                   ('narzędzie zgłosiło błędy skanowania', ('błędy skanowania',)),
                   ('brak pliku lub programu', ('no such file or directory', 'not found'))]
    safe += [label for label, words in diagnostics if any(w in value for w in words)]
    codes = re.findall(r'(?:http(?: status)?|status code|exit(?: code)?|kodem)[: =]+([0-9]{1,3})\b', value)
    safe += ['code=' + code for code in codes]
    return '; '.join(safe) or 'details redacted'


def tool_health(name):
    path = shutil.which(name)
    if not path:
        return dict(status='missing', reason='brak programu')
    try:
        result = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, SEMGREP_SEND_METRICS='off', SEMGREP_ENABLE_VERSION_CHECK='0'))
        if result.returncode:
            return dict(status='broken', exit_code=result.returncode, reason=redact(result.stderr or result.stdout))
        match = re.search(r'\b[vV]?(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)', result.stdout or result.stderr)
        return dict(status='available', version=match.group(1) if match else 'not-reported', exit_code=0)
    except subprocess.TimeoutExpired:
        return dict(status='broken', reason='timeout podczas sprawdzania --version')
    except OSError as exc:
        return dict(status='broken', reason=redact(str(exc)))


def doctor(offline=False, repo=None, prod_evidence=None):
    import importlib.util
    checks = {name: bool(shutil.which(name)) for name in ('git', 'node', 'npm', 'gitleaks', 'semgrep', 'trivy', 'lighthouse', 'osv-scanner', 'bandit', 'k6')}
    checks['PyYAML'] = importlib.util.find_spec('yaml') is not None
    checks['Pillow'] = importlib.util.find_spec('PIL') is not None
    for name in ('playwright', 'axe-core', 'js-yaml'):
        try:
            p = subprocess.run(['node', str(Path(__file__).with_name('dependencies.cjs')), name], capture_output=True, text=True, timeout=10)
            checks[name] = p.returncode == 0
        except (OSError, subprocess.TimeoutExpired): checks[name] = False
    import helix_update
    report = {name: 'available' if ok else 'missing' for name, ok in checks.items()}
    from helix_contracts import VERSION
    report['tools'] = {name: tool_health(name) for name in TOOLS['security'] + ['git', 'node', 'lighthouse', 'k6']}
    for name, result in report['tools'].items():
        report[name] = result['status']
    report['helix'] = dict(helix_update.inspect(fetch=not offline), version=VERSION, offline=offline)
    if repo is not None:
        import helix_environment
        report['environment'] = helix_environment.report(repo, prod_evidence=prod_evidence)
    print(json.dumps(report, indent=2, ensure_ascii=False))
