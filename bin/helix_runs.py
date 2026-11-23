"""Durable pack units, content-addressed cache and handoffs (stdlib only)."""
import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from helix_paths import normalize, relative as relative_path, within
import shutil
import subprocess
import tempfile
import uuid
from helix_git_readonly import git as read_git


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temp.replace(path)


def read(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def snapshot(repo, out, state):
    repo, out, state = map(normalize, (repo, out, state))
    p = read_git(repo, 'ls-files', '-co', '--exclude-standard', '-z', text=False, timeout=30)
    p.check_returncode()
    result = {}
    for name in p.stdout.decode().split('\0'):
        if not name: continue
        path = repo / name
        if any(part in ('.git', '.helix', 'helix-evidence', '__pycache__') for part in Path(name).parts): continue
        if within(path, out) or within(path, state): continue
        if path.is_symlink():
            result[name] = digest(['symlink', os.readlink(path)])
            continue
        if not path.is_file(): continue
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class Session:
    def __init__(self, ctx, pack, args, out, config):
        self.root = getattr(ctx, 'state_dir', ctx.repo / '.helix') / 'runs'
        self.path = self.root / (getattr(args, 'resume_id', None) or uuid.uuid4().hex) / 'state.json'
        self.data = read(self.path) or dict(run_id=self.path.parent.name, pack=pack, units={}, args={k: v for k, v in vars(args).items() if not k.startswith('_')}, out=str(out), started_at=stamp())
        self.repo, self.out, self.args, self.config = normalize(ctx.repo), normalize(out), args, config
        self.files = snapshot(ctx.repo, out, self.root.parent)
        head = read_git(ctx.repo, 'rev-parse', 'HEAD')
        self.head = head.stdout.strip()
        from helix_environment import provenance
        self.data['provenance'] = provenance(self.repo)
        self.implementation = digest([Path(__file__).read_text(), (Path(__file__).parent / 'helix_packs.py').read_text(), (Path(__file__).parent / 'helix_paths.py').read_text()])
        self.hits = 0
        save(self.path, self.data)
        save(self.root / 'latest.json', {'path': str(self.path)})

    def execute(self, name, operation, runner):
        version = 'internal-v1'
        executable = 'lighthouse' if name == 'perf' else name
        offline = getattr(self.args, 'offline', False)
        if shutil.which(executable) and not (offline and name in ('semgrep', 'trivy', 'osv-scanner')):
            try:
                p = subprocess.run([executable, '--version'], cwd=self.repo, capture_output=True, text=True, timeout=runner.version_timeout)
                version = (p.returncode, p.stdout, p.stderr)
            except (OSError, subprocess.SubprocessError) as exc: version = str(exc)
        rule_files = {f: h for f, h in self.files.items() if Path(f).name.startswith(('.gitleaks', '.semgrep', '.bandit', '.gitignore'))}
        rules = self.repo / '.helix' / 'semgrep'
        if rules.is_dir():
            rule_files.update({str(relative_path(p, self.repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in rules.rglob('*') if p.is_file() and not p.is_symlink()})
        key = digest([rule_files, self.head, self.implementation, self.files, self.config, name, version, {k: v for k, v in vars(self.args).items() if not k.startswith('_') and k not in ('out', 'resume_id', 'no_cache', 'cmd', 'action')}])
        if any((self.repo / f).is_symlink() for f in self.files):
            key = digest([key, uuid.uuid4().hex])
        cache = self.root / 'cache' / (key + '.json')
        compatibility = digest([rule_files, self.implementation, self.config, name, version, {k: v for k, v in vars(self.args).items() if not k.startswith('_') and k not in ('out', 'resume_id', 'no_cache', 'cmd', 'action')}])
        if getattr(self.args, 'full_history', False): compatibility = digest([compatibility, self.head])
        index = self.root / 'cache' / ('latest-' + compatibility + '.json')
        previous = None if getattr(self.args, 'no_cache', False) else read(index)
        old = self.data['units'].get(name)
        if old and getattr(self.args, 'resume_id', None) and old.get('key') == key and old['status'] in ('completed', 'blocked'):
            runner.records.extend(old.get('records', []))
            self.hits += int(old['status'] == 'completed')
            return old.get('findings', []), old.get('metrics', {})
        cached = None if getattr(self.args, 'no_cache', False) else read(cache)
        if cached:
            self.hits += 1
            runner.records.extend(cached['records'])
            self.data['units'][name] = dict(cached, key=key, cache_hit=True, source_attempts=cached['attempts'], attempts=0)
            save(self.path, self.data)
            return cached['findings'], cached['metrics']
        unit = dict(key=key, status='running', attempts=old.get('attempts', 0) if old and old.get('key') == key and getattr(self.args, 'resume_id', None) else 0, findings=[], metrics={}, records=[])
        self.data['units'][name] = unit
        unit['files'] = self.files
        if any((self.repo / f).is_symlink() for f in self.files): previous = None
        incremental = previous and name in ('gitleaks', 'semgrep', 'bandit') and not getattr(self.args, 'full_history', False)
        changed = {f for f in self.files if not previous or previous.get('files', {}).get(f) != self.files[f]}
        retained = [f for f in previous.get('findings', []) if f.get('file') in self.files and f.get('file') not in changed] if incremental else []
        if incremental:
            self.hits += len(set(previous.get('files', {})).intersection(self.files) - changed)
        while unit['attempts'] < 2:
            unit['attempts'] += 1
            save(self.path, self.data)
            start = len(runner.records)
            try:
                if incremental and not changed:
                    findings, metrics = [], {}
                elif incremental:
                    with tempfile.TemporaryDirectory(prefix='helix-incremental-') as temp:
                        scan_root = Path(temp)
                        for file in changed:
                            target = scan_root / file
                            target.parent.mkdir(parents=True, exist_ok=True)
                            if not (self.repo / file).is_symlink() and within(self.repo / file, self.repo): shutil.copyfile(self.repo / file, target)
                        self.args._scan_root = str(scan_root)
                        try: findings, metrics = operation()
                        finally: del self.args._scan_root
                else:
                    findings, metrics = operation()
                findings = retained + findings
            except (ValueError, OSError, KeyError, TypeError, AttributeError, SystemExit, subprocess.SubprocessError) as exc:
                findings, metrics = [], {}
                runner.records.append(dict(tool=name, version=None, command=[], exit_code=None, duration=0, status='error', error=str(exc)))
            records = runner.records[start:]
            del runner.records[start:]
            failed = any(r['status'] in ('error', 'skipped') for r in records)
            unit.update(findings=findings, metrics=metrics, records=records, status='blocked' if failed else 'completed')
            if failed:
                unit['error'] = '; '.join(r.get('error') or r['status'] for r in records if r['status'] != 'ok')
                record = next(r for r in records if r['status'] != 'ok')
                unit['next_step'] = f'Zainstaluj {name} i sprawdź {name} --version.' if record.get('error_category') == 'missing_dependency' else f'Sprawdź błąd {name} w {self.out / "run.json"}: {unit["error"]}'
            else:
                unit.pop('error', None)
                unit.pop('next_step', None)
                for f in findings:
                    f.setdefault('verified_at', stamp())
                    f.setdefault('evidence_path', str(self.out))
                # Częściowy skan (np. ostrzeżenia semgrep) nie trafia do pamięci podręcznej: ponowne użycie zgubiłoby jego status.
                if not getattr(self.args, 'no_cache', False) and not any(r['status'] == 'partial' for r in records):
                    save(cache, unit)
                    save(index, unit)
            save(self.path, self.data)
            if not failed: break
        if unit['status'] == 'running':
            unit.update(status='blocked', error='Przerwano operację po wykorzystaniu dwóch prób', next_step=f'Sprawdź dowody jednostki {name} i uruchom nowy skan.')
            unit['records'] = [dict(tool=name, version=None, command=[], exit_code=None, duration=0, status='error', error=unit['error'])]
            save(self.path, self.data)
        runner.records.extend(unit['records'])
        return unit['findings'], unit['metrics']

    def finish(self, result, findings):
        units = list(self.data['units'].values())
        if result.get('provenance'):
            self.data['provenance'] = result['provenance']
        else:
            from helix_environment import normalize_tools
            records = [dict(value, tool=name) for name, value in self.data['provenance']['tools'].items()]
            records += [record for unit in units for record in unit.get('records', [])]
            self.data['provenance']['tools'] = normalize_tools(records)
        status = 'blocked' if any(u['status'] == 'blocked' for u in units) or result['status'] in ('ERROR', 'INCOMPLETE') else 'needs_review' if result['would_fail'] or any(f.get('verdict') == 'needs_validation' for f in findings) else 'accepted'
        self.data.update(status=status, finished_at=stamp(), evidence_path=str(self.out), findings_counts={v: sum(f.get('verdict') == v for f in findings) for v in ('confirmed', 'needs_validation', 'rejected')})
        save(self.path, self.data)
        fields = ['run_id', 'pack', 'status', 'retries', 'duration_s', 'confirmed', 'needs_validation', 'rejected', 'cache_hits', 'evidence_path', 'usage']
        row = dict(run_id=self.data['run_id'], pack=self.data['pack'], status=status, retries=sum(max(0, u['attempts'] - 1) for u in units), duration_s=round((dt.datetime.fromisoformat(self.data['finished_at']) - dt.datetime.fromisoformat(self.data['started_at'])).total_seconds(), 3), cache_hits=self.hits, evidence_path=str(self.out), usage='unknown', **self.data['findings_counts'])
        path = self.out / 'run-log.csv'
        rows = []
        if path.exists():
            with path.open(newline='') as stream: rows = [r for r in csv.DictReader(stream) if r['run_id'] != row['run_id']]
        with path.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerows(rows + [row])


def latest(ctx, run_id=None):
    root = getattr(ctx, 'state_dir', ctx.repo / '.helix') / 'runs'
    path = root / run_id / 'state.json' if run_id else Path(read(root / 'latest.json', {}).get('path', root / 'missing'))
    data = read(path)
    if not data: raise SystemExit('Brak zapisanego przebiegu')
    return data


def resume(ctx, args):
    import helix_packs as packs
    data = latest(ctx, args.run_id)
    saved = argparse.Namespace(**dict(data['args'], resume_id=data['run_id'], out=data['out'], no_cache=getattr(args, 'no_cache', False) or data['args'].get('no_cache', False)))
    result = packs.scan(ctx, data['pack'], saved, checkpoint=data.get('checkpoint'))
    print(json.dumps(result[0], ensure_ascii=False))
    if result[0]['exit_code'] == 3: raise SystemExit(3)
    return result


def handoff(ctx, args):
    data = latest(ctx, getattr(args, 'run_id', None))
    path = Path(getattr(args, 'out', None) or Path(data['out']) / 'HANDOFF.md')
    blocked = [name for name, unit in data['units'].items() if unit['status'] == 'blocked']
    problems = '; '.join(name + ': ' + data['units'][name].get('error', 'brak szczegółów') for name in blocked)[:600]
    next_step = data['units'][blocked[0]].get('next_step', 'Sprawdź run.json.')[:600] if blocked else 'Uruchom helix resume dla niedokończonych jednostek; zweryfikuj znaleziska.'
    text = ('# HANDOFF\n\nCel: Dokończyć ocenę paczki ' + data['pack'] + '.\n\n'
            'Decyzje: Status przebiegu: ' + data.get('status', 'interrupted') + '; zachowano daty wyników z cache.\n\n'
            'Ścieżki: Dowody w ' + data['out'] + '; stan: ' + data['run_id'] + '.\n\n'
            'Otwarte pytania: ' + (problems if blocked else 'Walidacja znalezisk needs_validation.') + '\n\n'
            'Następny krok: ' + next_step + '\n')
    # Keep generated handoffs bounded even with long paths/unit names.
    text = ' '.join(text.split()[:390]) + '\n' if len(text.split()) >= 400 else text
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
    print(path)
    return path
