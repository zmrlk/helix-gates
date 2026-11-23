"""Shared local Git identity. Never run repository filters or fsmonitor hooks."""
import os
from pathlib import Path
import re
import subprocess

SHA = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')
FILTER_KEYS = r'^filter\..*\.(clean|smudge|process|required)$'
REASONS = {
    'not_checked': 'Nie uzyskano lokalnej rewizji Git',
    'git_status_without_filters': 'Lokalny Git; bez filtrów, fsmonitor i odświeżania indeksu',
    'git_filters_not_executed': 'HEAD odczytany; filtry Git nie zostały uruchomione, dirty pozostaje nieznane',
    'git_submodules_not_inspected': 'HEAD odczytany; submodule nie zostały uruchomione ani sprawdzone, dirty pozostaje nieznane',
    'git_filter_configuration_unknown': 'HEAD odczytany; nie ustalono konfiguracji filtrów, dirty pozostaje nieznane',
    'git_index_unavailable': 'HEAD odczytany; nie ustalono obecności submodule w indeksie, dirty pozostaje nieznane',
    'git_status_unavailable': 'HEAD odczytany; stan zmian lokalnych pozostaje nieznany',
}


def git(repo, *args, text=True, timeout=10, input_data=None, local_objects_only=False):
    """Read-only Git callers use explicit arguments; no inherited repo selection."""
    allowed = {'PATH', 'HOME', 'XDG_CONFIG_HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'SYSTEMROOT',
               'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM',
               'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT'}
    environment = {k: v for k, v in os.environ.items()
                   if k in allowed or re.fullmatch(r'GIT_CONFIG_(?:KEY|VALUE)_\d+', k)}
    # Retain global/config overlays so their filters are detected, but omit
    # credentials and GIT_DIR/WORK_TREE/INDEX_FILE that could redirect identity.
    environment.update(GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    prefix=['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false']
    if local_objects_only:
        # A local history reader must not turn missing objects into a fetch or
        # reinterpret commits through replacement refs or legacy grafts.
        environment={key:value for key,value in environment.items() if not key.startswith('GIT_CONFIG_')}
        environment.update(GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_ALLOW_PROTOCOL='',
                           GIT_GRAFT_FILE=os.devnull,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull)
        prefix += ['--no-replace-objects','--literal-pathspecs','-c','protocol.allow=never',
                   '-c','core.hooksPath='+os.devnull,'-c','credential.helper=','-c','core.pager=cat']
    options=dict(cwd=repo,env=environment,capture_output=True,text=text,timeout=timeout)
    if input_data is not None:options['input']=input_data
    return subprocess.run([*prefix,*args],**options)


def read_ref(repo, *, require_root=False):
    """Return containing Git identity; optionally require its exact worktree root."""
    result = dict(head=None, dirty=None, status='unknown', dirty_reason='not_checked',
                  reason=REASONS['not_checked'])
    try:
        repo = Path(repo).expanduser().resolve()
        top = git(repo, 'rev-parse', '--show-toplevel')
        if top.returncode: return result
        git_root = Path(top.stdout.strip()).resolve()
        if require_root and git_root != repo: return result
        repo = git_root
        head = git(repo, 'rev-parse', '--verify', 'HEAD^{commit}')
        if head.returncode or not SHA.fullmatch(head.stdout.strip()): return result
        result.update(head=head.stdout.strip(), status='partial', dirty_reason='git_status_unavailable')
        # git status can launch clean/process filters from local or inherited
        # configuration. Names suffice to fail closed; never read command values.
        filters = git(repo, 'config', '--null', '--name-only', '--get-regexp', FILTER_KEYS)
        if filters.returncode == 0 and filters.stdout:
            result['dirty_reason'] = 'git_filters_not_executed'
        elif filters.returncode == 1 or filters.returncode == 0 and not filters.stdout:
            index = git(repo, 'ls-files', '--stage', '-z')
            if index.returncode:
                result['dirty_reason'] = 'git_index_unavailable'
            elif any(row.startswith('160000 ') for row in index.stdout.split('\0')):
                result['dirty_reason'] = 'git_submodules_not_inspected'
            else:
                dirty = git(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=normal')
                if not dirty.returncode:
                    result.update(dirty=bool(dirty.stdout), status='recorded', dirty_reason='git_status_without_filters')
        else:
            result['dirty_reason'] = 'git_filter_configuration_unknown'
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass
    result['reason'] = REASONS[result['dirty_reason']]
    return result
