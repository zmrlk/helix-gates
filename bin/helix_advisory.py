"""Pinned tools on source-only snapshots. Advisory signals never grant points."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from helix_git_readonly import git, filter_drivers, without_filters
from helix_tools_manager import resolve_installed


def changed_files(repo, since):
    if not isinstance(since, str) or not since or since.startswith('-'):
        raise ValueError('wymagany jawny ref --since')
    ref = git(repo, 'rev-parse', '--verify', '--end-of-options', since + '^{commit}', local_objects_only=True)
    if ref.returncode or not re.fullmatch(r'[a-f0-9]{40,64}', ref.stdout.strip()):
        raise ValueError('nieznany ref --since')
    # A worktree diff would run the repository's clean filters; with drivers emptied it compares raw content.
    drivers = filter_drivers(repo, local_objects_only=True)
    if drivers is None: raise ValueError('niepełny odczyt różnicy Git')
    diff = git(repo, *without_filters(drivers), 'diff', '--name-only', '--diff-filter=ACMR', '-z', ref.stdout.strip(), '--', local_objects_only=True)
    new = git(repo, 'ls-files', '--others', '--exclude-standard', '-z', local_objects_only=True)
    if diff.returncode or new.returncode: raise ValueError('niepełny odczyt różnicy Git')
    names = set((diff.stdout + new.stdout).split('\0')) - {''}
    if any(Path(p).is_absolute() or '..' in Path(p).parts for p in names): raise ValueError('ścieżka poza repo')
    return sorted(names)


def result(name, **extra):
    return dict(tool=name, status='not-run', reason='', findings=[], score=0, advisory=True, **extra)


def scan(repo, name, timeout=60, *, since=None):
    from helix_tool_adapters import environment, parse
    from helix_source_coverage import scan as source_scan
    if name not in ('knip', 'jscpd', 'squawk'): raise ValueError('nieznany adapter')
    if type(timeout) not in (int, float) or not 0 < timeout <= 300: raise ValueError('timeout: 0..300 s')
    base = result(name)
    if name == 'squawk' and since is None:
        return dict(base, reason='wymagany --since; migracje tylko z różnicy')
    changed = changed_files(repo, since) if since is not None else None
    sources, coverage = source_scan(repo)
    suffixes = {'.sql'} if name == 'squawk' else {'.js','.jsx','.ts','.tsx','.mjs','.cjs','.svelte','.vue'}
    # Do not hand executable project configuration or manifests to plugin loaders.
    selected = {p:t for p,t in sources.items() if Path(p).suffix in suffixes
                and not re.search(r'(?:^|/)[^/]*(?:config|\.d)\.[cm]?[jt]s$', p)
                and (name != 'squawk' or p in changed and re.search(r'(?:^|/)(?:migrations?|sql)(?:/|$)', p, re.I))}
    if not selected: return dict(base, status='not-applicable', reason='brak pasujących źródeł w zakresie', scope=changed)
    installation = resolve_installed(name)
    if not installation or not installation.get('usable'):
        return dict(base, status='unavailable', reason='brak zweryfikowanej instalacji; bez instalowania')
    base.update(version=installation['version'], proof_kind=installation['proof_kind'],
                receipt_sha256=hashlib.sha256(Path(installation['receipt']).read_bytes()).hexdigest(),
                scope=dict(since=since, changed=changed, files=sorted(selected)), coverage=coverage['status'],
                limitations=['Syntaktyczne kandydatury; brak dowodu działania projektu.',
                             'Konfiguracja projektu i pluginy nie są ładowane; Knip nie ocenia zależności pakietowych.'])
    with tempfile.TemporaryDirectory(prefix='helix-advisory-') as tmp:
        home=Path(tmp).resolve(); target=home/'project'; target.mkdir()
        for path, text in selected.items():
            dest=target/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(text)
        env=environment(home);env.update(CI='true',npm_config_offline='true',NO_UPDATE_NOTIFIER='1')
        if name == 'knip':
            (target/'package.json').write_text('{"name":"helix-snapshot","private":true,"type":"module"}')
            config=home/'knip.json';tsconfig=home/'tsconfig.json'
            entries=[p for p in selected if '/routes/' in p or Path(p).name.startswith(('index.','main.','hooks.'))]
            config.write_text(json.dumps(dict(entry=entries,project=sorted(selected))))
            tsconfig.write_text('{"compilerOptions":{"allowJs":true}}')
            args=['--config',str(config),'--tsConfig',str(tsconfig),'--reporter','json','--no-progress','--no-gitignore','--include','files,exports,types','--no-config-hints']
        elif name == 'jscpd':
            config=home/'jscpd.json';config.write_text(json.dumps(dict(minLines=5,minTokens=50,reporters=['json'],silent=True,semantic=False,failOnEmpty=True)))
            args=['--config',str(config),'--output',str(home/'duplicates'),'.']
        else:
            config=home/'squawk.toml';config.write_text('')
            args=['--reporter','json','--config',str(config),*['./'+p for p in sorted(selected)]]
        try:
            proc=subprocess.run(installation['argv_prefix']+args,cwd=target,env=env,capture_output=True,text=True,timeout=timeout)
            if proc.returncode not in (0,1): return dict(base,status='error',reason='błąd narzędzia; bez surowego wyjścia')
            raw=(home/'duplicates/jscpd-report.json').read_text() if name=='jscpd' else proc.stdout
            if name=='jscpd':
                payload=json.loads(raw)
                count=payload.get('statistics',{}).get('total',{}).get('sources')
                if type(count) is not int or count<1 or any('secondFile' not in d for d in payload['duplicates']): raise ValueError('niepełne pokrycie jscpd')
            rows=parse(name,raw,target)
            if changed is not None and name != 'squawk':
                rows=[r for r in rows if r['file'] in changed or any(p['file'] in changed for p in r.get('related_locations',[]))]
            return dict(base,status='completed',reason='wykonano na odfiltrowanym snapshotcie',findings=rows)
        except subprocess.TimeoutExpired:
            return dict(base,status='timeout',reason='przekroczony budżet czasu')
        except (OSError,ValueError,KeyError,TypeError,AttributeError):
            return dict(base,status='error',reason='niepoprawny raport; bez surowych danych')


def publish(repo, out, report):
    """One new external artifact; no overwrite of an older result."""
    from helix_environment import provenance
    root=Path(repo).resolve(); dest=Path(out).expanduser().resolve()
    if dest==root or root in dest.parents or dest in root.parents: raise ValueError('--out musi być poza repo')
    dest.mkdir(parents=True,exist_ok=True)
    value=dict(schema_version=1,kind='advisory-tools',provenance=provenance(root),tools=[report],findings=report.get('findings',[]),execution_credit=0)
    with (dest/'advisory-tools.json').open('x') as f: json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
    with (dest/'advisory-tools.md').open('x') as f:
        f.write('# Narzędzia advisory\n\n'+report['tool']+': '+report['status']+'. '+report['reason']+'\n\nPunkty wykonania: 0. Ustalenia wymagają weryfikacji.\n')
        for row in report.get('findings',[]): f.write(f"- {row['file']}:{row['line']}: {row.get('rule',row.get('id'))}\n")
    return value
