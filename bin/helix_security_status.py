"""Read-only COMPLETE status and explicitly installed, model-free Git reminders."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

from helix_audit_context import safe_read, system_path
from helix_paths import within
from helix_git_readonly import git as _git, read_ref

SHA = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')


def _path(value):
    path = system_path(Path(value).expanduser())
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('status: ścieżka nie może zawierać dowiązania')
    return path.resolve()


def _json(path):
    data = json.loads(safe_read(path, errors='strict'))
    if not isinstance(data, dict): raise ValueError('status: oczekiwano obiektu JSON')
    return data


def cursor_path(repo, state_dir=None):
    repo = Path(repo).resolve()
    root = Path(state_dir) / 'security-audit' if state_dir is not None else Path.home() / 'security-audit' / repo.name
    identity = hashlib.sha256(json.dumps(str(repo), sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return root / 'completed' / identity / 'last-complete.json'


def _commands(repo, state_dir, mode, config_path=None):
    prefix = ['helix', '--repo', str(repo)]
    if config_path is not None: prefix += ['--config', str(config_path)]
    if state_dir is not None: prefix += ['--state-dir', str(state_dir)]
    commands = {key: prefix + ['security', 'deep', '--mode', key] for key in ('full', 'daily', 'release')}
    return commands, commands[mode]


def _checkpoints(repo, state_dir):
    """Only exact files declared by an optional plan, never scan state directories."""
    root = Path(state_dir) if state_dir is not None else repo / '.helix'
    result = {'status': 'missing', 'items': []}
    try:
        plan = _json(root / 'plan.json')
        rows = plan.get('checkpoints')
        if not isinstance(rows, list): raise ValueError('invalid checkpoints')
        result['status'] = 'recorded'
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}', row['id']):
                raise ValueError('invalid checkpoint id')
            item = {'id': row['id'], 'title': str(row.get('title', ''))[:200], 'status': 'new', 'gates': {}}
            try:
                saved = _json(root / (row['id'] + '.state.json'))
                if isinstance(saved.get('status'), str): item['status'] = saved['status'][:100]
                if isinstance(saved.get('gates'), dict):
                    item['gates'] = {str(k)[:80]: v if isinstance(v, (str, bool, int)) else 'recorded'
                                     for k, v in saved['gates'].items()}
            except FileNotFoundError: pass
            except (OSError, ValueError, UnicodeError): item['status'] = 'unknown'
            result['items'].append(item)
    except FileNotFoundError: pass
    except (OSError, ValueError, UnicodeError): result.update(status='invalid_or_unreadable', items=[])
    return result


def report(repo, state_dir=None, *, config_path=None):
    """Git and two exact receipts only; no Ctx, source scan, model or filesystem write."""
    repo = _path(repo)
    state = _path(state_dir) if state_dir is not None else None
    config = _path(config_path) if config_path is not None else None
    if state is not None and (within(state, repo) or within(repo, state)):
        raise ValueError('status: zewnętrzny state-dir musi być rozłączny z repo celu')
    path = cursor_path(repo, state)
    commands, next_command = _commands(repo, state, 'full', config)
    data = dict(schema_version=1, target=str(repo), config_path=str(config) if config else None, status='ERROR', current_head=None, reviewed_head=None,
                dirty=None, dirty_reason='not_checked', reviewed_at=None, relation='unknown', commits_since_complete=None,
                cursor_path=str(path), receipt_path=None, reason='Nie ustalono lokalnej rewizji Git',
                commands=commands, next_command=next_command, review_due=True,
                meaning='Zakończony przegląd źródeł, bez potwierdzenia gotowości produkcyjnej',
                execution={'models': 0, 'source_scans': 0, 'writes': 0})
    ref = read_ref(repo, require_root=True)
    from helix_ponytail_age import read_debt_summary
    data['ponytail_debt']=read_debt_summary(repo,state,ref)
    data.update(current_head=ref['head'], dirty=ref['dirty'], dirty_reason=ref['dirty_reason'], git_ref_status=ref['status'])
    if ref['head'] is None:
        return data
    data['checkpoints'] = _checkpoints(repo, state)
    data.update(status='NO_BASELINE', relation='missing', reason='Brak potwierdzonego COMPLETE; najpierw pełny przegląd')
    try:
        cursor = _json(path)
    except FileNotFoundError:
        return data
    except (OSError, ValueError, UnicodeError):
        data.update(status='UNKNOWN_BASELINE', relation='unknown', reason='Cursor COMPLETE jest niepoprawny lub niedostępny')
        return data
    try:
        reviewed = cursor.get('head')
        if cursor.get('target') != str(repo) or cursor.get('run_status') != 'complete' or not isinstance(reviewed, str) or not SHA.fullmatch(reviewed):
            raise ValueError('invalid cursor identity')
        stamp = datetime.fromisoformat(cursor['completed_at'])
        if stamp.tzinfo is None: raise ValueError('missing timestamp timezone')
        if not isinstance(cursor.get('run'), str): raise ValueError('invalid receipt path')
        run = _path(cursor['run'])
        if within(run, repo) or within(repo, run): raise ValueError('receipt overlaps target')
        receipt_path = run / 'run-metadata.json'
        receipt = _json(receipt_path)
        ref = receipt.get('source_ref', {})
        if (receipt.get('target') != str(repo) or receipt.get('run_status') != 'complete'
                or not isinstance(ref, dict) or ref.get('head') != reviewed or ref.get('dirty') is not False
                or receipt.get('profile') != 'standard' or receipt.get('scope_paths') != ['.']):
            raise ValueError('receipt does not establish clean COMPLETE')
        data.update(reviewed_head=reviewed, reviewed_at=stamp.isoformat(), receipt_path=str(receipt_path))
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        data.update(status='UNKNOWN_BASELINE', relation='unknown', reason='Dowód COMPLETE nie potwierdza celu, rewizji lub pełnego czystego zakresu')
        return data
    try:
        ancestor = _git(repo, 'merge-base', '--is-ancestor', reviewed, data['current_head'])
        if ancestor.returncode == 1:
            data.update(status='UNKNOWN_BASELINE', relation='diverged', reason='Historia COMPLETE nie jest przodkiem HEAD; liczba zaległych commitów jest nieznana')
            return data
        if ancestor.returncode: raise ValueError('unknown revision')
        count = _git(repo, 'rev-list', '--count', reviewed + '..' + data['current_head'])
        if count.returncode or not re.fullmatch(r'\d+\s*', count.stdout): raise ValueError('unknown commit count')
        number = int(count.stdout)
        data.update(relation='same' if reviewed == data['current_head'] else 'ancestor', commits_since_complete=number,
                    status='CURRENT' if number == 0 and data['dirty'] is False else 'DUE',
                    reason='HEAD ma potwierdzony COMPLETE' if number == 0 and data['dirty'] is False else 'Nowsze commity lub lokalne zmiany wymagają przeglądu',
                    next_command=commands['daily'], review_due=not (number == 0 and data['dirty'] is False))
        if data['dirty'] is None:
            data.update(status='UNKNOWN_BASELINE', reason=('Nie uruchomiono skonfigurowanych filtrów Git; stan zmian lokalnych pozostaje nieznany'
                        if data['dirty_reason'] == 'git_filters_not_executed' else
                        'Nie uruchomiono statusu submodule; stan zmian lokalnych pozostaje nieznany'
                        if data['dirty_reason'] == 'git_submodules_not_inspected' else
                        'Nie ustalono stanu zmian lokalnych; nie potwierdzono aktualności przeglądu'))
    except (OSError, ValueError, subprocess.SubprocessError):
        data.update(status='UNKNOWN_BASELINE', relation='unknown', reason='Rewizja COMPLETE lub liczba commitów nie jest dostępna w lokalnym Git')
    return data


def text_report(data, reminder_only=False):
    count = data['commits_since_complete']
    dirty = 'tak' if data['dirty'] is True else 'nie' if data['dirty'] is False else 'nieustalone'
    if data.get('dirty_reason') == 'git_filters_not_executed': dirty += ' (filtry Git niewykonane)'
    elif data.get('dirty_reason') == 'git_submodules_not_inspected': dirty += ' (submodule niesprawdzone)'
    next_step = ('daily: ' + shlex.join(data['commands']['daily']) + '; release: ' + shlex.join(data['commands']['release'])
                 if data['relation'] in ('same', 'ancestor') else
                 'najpierw full: ' + shlex.join(data['commands']['full']) + '; potem daily/release')
    summary = ('Helix security ' + data['status'] + ': commitów od COMPLETE ' + (str(count) if count is not None else 'nieznane') +
               '; lokalne zmiany ' + dirty + '; ' + next_step + '.')
    debt=data.get('ponytail_debt',{})
    if debt:
        count=debt.get('counts')
        summary+=' Ponytail debt '+debt.get('status','UNKNOWN')+': markery '+(str(count.get('markers')) if isinstance(count,dict) else 'nieznane dla bieżącego pełnego zakresu')+'.'
    lines = [summary.replace('\r', '\\r').replace('\n', '\\n')]
    if not reminder_only:
        saved=debt.get('last_observation') if debt else None
        if isinstance(saved,dict):
            label='CURRENT' if debt.get('status')=='CURRENT' else 'HISTORY ('+debt.get('status','UNKNOWN')+')'
            for row in saved.get('rows',[]):
                age=str(row['age_days'])+' dni' if row.get('age_days') is not None else 'nieznany'
                tags=', '.join(row.get('tags',[])) or 'ceiling/trigger zapisane'
                line='Ponytail '+label+' '+str(row['file'])+':'+str(row['line'])+' | wiek przy odczycie '+str(saved.get('observed_at'))+': '+age+' | '+tags
                lines.append(line.replace('\r','\\r').replace('\n','\\n'))
        for row in data.get('checkpoints', {}).get('items', []):
            line = row['id'] + ': ' + row['status'] + ' | ' + row['title'] + ' | gates=' + json.dumps(row['gates'], ensure_ascii=False)
            lines.append(line.replace('\r', '\\r').replace('\n', '\\n'))
    return '\n'.join(lines) + '\n'


def _open_directory(path):
    """Create only missing hook directories, without traversing linked parents."""
    path = system_path(path)
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try: child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(component, 0o755, dir_fd=fd)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def install_hook(repo, state_dir=None, *, config_path=None, helix_path=None, python=None):
    """Explicit opt-in only. Never replace or append to an existing hook."""
    repo = _path(repo)
    state = _path(state_dir) if state_dir is not None else None
    config = _path(config_path) if config_path is not None else None
    if state is not None and (within(state, repo) or within(repo, state)):
        raise ValueError('status: zewnętrzny state-dir musi być rozłączny z repo celu')
    top = _git(repo, 'rev-parse', '--show-toplevel')
    if top.returncode or Path(top.stdout.strip()).resolve() != repo: raise ValueError('status: wymagany katalog główny repo Git')
    located = _git(repo, 'rev-parse', '--path-format=absolute', '--git-path', 'hooks/post-commit')
    if located.returncode or not located.stdout.strip(): raise ValueError('status: nie ustalono katalogu hooków Git')
    hook = system_path(located.stdout.strip())
    if any(p.is_symlink() for p in (hook, *hook.parents)) or hook.exists():
        raise ValueError('status: istniejący hook lub dowiązanie; niczego nie nadpisano')
    executable = Path(helix_path or Path(__file__).with_name('helix')).expanduser().resolve()
    interpreter = Path(python or sys.executable).expanduser().resolve()
    if not executable.is_file() or not interpreter.is_file(): raise ValueError('status: brak jawnego Helixa lub interpretera')
    # One shared hook can serve linked worktrees. The external state override is
    # selected only for its original canonical target, never for a sibling.
    mapped_args = (['--config', str(config)] if config else []) + (['--state-dir', str(state)] if state else [])
    script = '\n'.join([
        'import os, subprocess', 'from pathlib import Path',
        "env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')",
        "root = subprocess.run(['git', '--no-optional-locks', 'rev-parse', '--show-toplevel'], capture_output=True, text=True, env=env, timeout=10)",
        "if root.returncode: raise SystemExit('Helix: nie ustalono repo; zaległość przeglądu jest nieznana')",
        'target = str(Path(root.stdout.strip()).resolve())',
        'args = ' + repr([str(interpreter), str(executable), '--repo']) + " + [target, '--offline']",
        'if target == ' + repr(str(repo)) + ':',
        '    args += ' + repr(mapped_args),
        "args += ['status', '--reminder-only']",
        'result = subprocess.run(args, env=env, timeout=30)',
        "if result.returncode: print('Helix: status niedostępny; zaległość przeglądu jest nieznana')",
    ])
    content = '#!/bin/sh\n# Helix: jawne przypomnienie; nie uruchamia przeglądu ani modeli.\n' + shlex.quote(str(interpreter)) + ' -c ' + shlex.quote(script) + "\nif [ \"$?\" -ne 0 ]; then printf '%s\\n' 'Helix: status niedostępny; zaległość przeglądu jest nieznana' >&2; fi\nexit 0\n"
    fd = _open_directory(hook.parent)
    try:
        try: leaf = os.open(hook.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755, dir_fd=fd)
        except FileExistsError as exc: raise ValueError('status: istniejący hook; niczego nie nadpisano') from exc
        with os.fdopen(leaf, 'w', encoding='utf-8') as output:
            output.write(content); output.flush(); os.fchmod(output.fileno(), 0o755); os.fsync(output.fileno())
    finally: os.close(fd)
    return dict(status='INSTALLED', hook=str(hook), target=str(repo), state_dir=str(state) if state else None,
                config_path=str(config) if config else None,
                shared_hooks=True, state_mapping='explicit target only; other worktrees use their own default',
                warning='Hook może być współdzielony przez worktrees lub core.hooksPath. Zewnętrzny config/state-dir przypisano wyłącznie do tego celu.',
                action='offline status reminder only; no review, model, network or automatic approval')
