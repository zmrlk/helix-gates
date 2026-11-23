"""Optional mutation adapters: disposable copy, process budget, network namespace."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from helix_runtime import copy_project
from helix_tool_adapters import locate, environment


def measured(name, raw):
    if name == 'stryker':
        data = json.loads(raw)
        mutants = [m for f in data['files'].values() for m in f['mutants']]
        valid = {'Killed', 'Survived', 'NoCoverage', 'Timeout', 'CompileError', 'RuntimeError', 'Ignored', 'Pending'}
        if any(m.get('status') not in valid for m in mutants): raise ValueError('status mutacji')
        tested = [m for m in mutants if m['status'] in ('Killed','Survived','NoCoverage')]
        killed = sum(m['status'] == 'Killed' for m in tested)
        incomplete = len(tested) != len(mutants)
    else:
        data = json.loads(raw)
        keys = ('total','killed','survived','no_tests','skipped','suspicious','timeout','check_was_interrupted_by_user','segfault')
        if any(type(data.get(k)) is not int or data[k] < 0 for k in keys): raise ValueError('niepoprawne liczniki')
        if data['total'] != sum(data[k] for k in keys[1:]): raise ValueError('niespójne liczniki')
        tested = range(data['killed'] + data['survived'] + data['no_tests'])
        killed = data['killed']
        mutants = range(data['total'])
        incomplete = len(tested) != len(mutants)
    completed = bool(tested) and not incomplete
    return dict(total=len(mutants), tested=len(tested), killed=killed,
                score=0, mutation_score=round(100*killed/len(tested),2) if completed else 0,
                status='completed' if completed else 'incomplete')


def command(argv, cwd, env, seconds):
    with subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, start_new_session=True) as process:
        try:
            stdout, _ = process.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        if process.returncode: raise ValueError('adapter zakończył się błędem')
        return stdout


def run(project, name, budget=60):
    if name not in ('stryker', 'mutmut'): raise ValueError('nieznany adapter mutacji')
    if isinstance(budget,bool) or not isinstance(budget,(int,float)) or not 0 < budget <= 300:
        raise ValueError('budżet: 0..300 sekund')
    result = dict(tool=name, status='not-run', score=0)
    executable, sandbox = locate(name), locate('unshare')
    if not executable or not sandbox:
        return dict(result, reason='brak adaptera lub izolacji sieci unshare; instalacja zabroniona')
    import time
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='helix-mutation-') as tmp:
        home = Path(tmp).resolve(); target = home / 'project'
        copy_project(Path(project).resolve(), target)
        env = environment(home)
        env.update(CI='true', npm_config_offline='true', UV_OFFLINE='1', PIP_NO_INDEX='1')
        prefix = [sandbox, '--net', '--']
        try:
            # Probe the namespace first: an unsupported sandbox gives not-run, never native fallback.
            command(prefix + ['/bin/true'], target, env, min(5, budget))
        except (OSError,ValueError,subprocess.TimeoutExpired):
            return dict(result, reason='izolacja sieci niedostępna; kod projektu nie został uruchomiony')
        try:
            remaining = lambda: max(0.001, budget - (time.monotonic()-started))
            argv = [executable, 'run']
            if name == 'stryker': argv += ['--reporters', 'json']
            command(prefix + argv, target, env, remaining())
            if name == 'stryker':
                path = target / 'reports/mutation/mutation.json'
                if path.is_symlink() or not path.resolve().is_relative_to(target): raise ValueError('raport poza kopią')
                raw = path.read_text()
            else:
                command(prefix + [executable, 'export-cicd-stats'], target, env, remaining())
                path = target / 'mutants/mutmut-cicd-stats.json'
                if path.is_symlink() or not path.resolve().is_relative_to(target): raise ValueError('raport poza kopią')
                raw = path.read_text()
            return dict(result, **measured(name, raw), reason='pomiar na kopii; namespace offline; bez surowych danych')
        except subprocess.TimeoutExpired:
            return dict(result, status='timeout', reason='przekroczony wspólny budżet; procesy zakończone')
        except (OSError,ValueError,KeyError,TypeError):
            return dict(result, status='error', reason='błąd adaptera lub niepoprawny raport; bez punktów')
