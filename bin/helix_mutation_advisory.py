"""Incremental mutation runner; project code only inside an offline namespace."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

from helix_advisory import changed_files, result
from helix_runtime import copy_project
from helix_runtime_mutation import command, measured
from helix_tool_adapters import environment, locate
from helix_tools_manager import resolve_installed


def run(repo, name, budget=60, *, since=None):
    if name not in ('mutmut','stryker'): raise ValueError('nieznany adapter')
    if type(budget) not in (int,float) or not 0<budget<=300: raise ValueError('budżet: 0..300 s')
    base=result(name)
    if since is None: return dict(base,reason='wymagany --since; mutacje tylko zmienionych plików')
    suffixes={'.py'} if name=='mutmut' else {'.ts','.tsx','.js','.jsx'}
    files=[p for p in changed_files(repo,since) if Path(p).suffix in suffixes and not any(x in ('tests','test','__tests__') for x in Path(p).parts) and not Path(p).name.startswith('test_')]
    if not files: return dict(base,status='not-applicable',reason='brak zmienionych źródeł do mutacji')
    if any(',' in p for p in files): return dict(base,reason='przecinek w ścieżce wymaga jawnego zakresu konfiguracji')
    base.update(scope=dict(since=since,files=files))
    installed=resolve_installed('mutmut') if name=='mutmut' else None
    argv=installed['argv_prefix'] if installed and installed.get('usable') else [locate('stryker')] if name=='stryker' else None
    sandbox=locate('unshare')
    if not argv or not argv[0] or not sandbox: return dict(base,reason='brak adaptera lub izolacji sieci unshare; bez instalacji')
    start=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='helix-mutation-diff-') as tmp:
        home=Path(tmp).resolve();target=home/'project';copy_project(Path(repo).resolve(),target)
        if any(not (target/p).is_file() for p in files): return dict(base,reason='część zakresu wykluczona z bezpiecznej kopii')
        env=environment(home);env.update(CI='true',npm_config_offline='true',UV_OFFLINE='1',PIP_NO_INDEX='1')
        prefix=[sandbox,'--net','--']
        try: command(prefix+['/bin/true'],target,env,min(5,budget))
        except (OSError,ValueError,subprocess.TimeoutExpired): return dict(base,reason='izolacja sieci niedostępna; projekt niewykonany')
        remaining=lambda:max(.001,budget-(time.monotonic()-start))
        try:
            if name=='mutmut':
                config=target/'pyproject.toml';content=config.read_text() if config.exists() else ''
                content=re.sub(r'(?ms)^\[tool\.mutmut\]\s*\n.*?(?=^\[|\Z)','',content)
                # source_paths overrides the mutation scope; pytest configuration stays intact.
                if re.search(r'^\[tool\.mutmut',content,re.M): raise ValueError('złożona konfiguracja mutmut wymaga ręcznego zakresu')
                config.write_text(content+'\n[tool.mutmut]\nsource_paths = '+json.dumps(files)+'\nuse_git_change_detection = false\n')
                command(prefix+argv+['run'],target,env,remaining())
                command(prefix+argv+['export-cicd-stats'],target,env,remaining())
                output=target/'mutants/mutmut-cicd-stats.json'
            else:
                patterns=[re.sub(r'([*?\[\]{}()!+@])',r'\\\1',p) for p in files]
                command(prefix+argv+['run','--mutate',','.join(patterns),'--reporters','json'],target,env,remaining())
                output=target/'reports/mutation/mutation.json'
            if output.is_symlink() or not output.resolve().is_relative_to(target): raise ValueError('raport poza kopią')
            values=measured(name,output.read_text())
            # Never trust a Stryker configuration that expanded the requested set.
            if name=='stryker' and not set(json.loads(output.read_text())['files'])<=set(files): raise ValueError('raport poza zakresem')
            return dict(base,**values,reason='pomiar przyrostowy na kopii; advisory, bez punktów')
        except subprocess.TimeoutExpired: return dict(base,status='timeout',reason='przekroczony wspólny budżet')
        except (OSError,ValueError,KeyError,TypeError): return dict(base,status='error',reason='błąd adaptera lub raportu; bez punktów')
