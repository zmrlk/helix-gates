"""Portable, conservative updates of the checkout containing this module."""
import os
from pathlib import Path
import subprocess

HELIX_HOME = Path(__file__).resolve().parent.parent


def git(repo, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GCM_INTERACTIVE='never')
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True,
                          text=True, timeout=10, env=env)


def output(repo, *args):
    result = git(repo, *args)
    if result.returncode:
        raise RuntimeError('Polecenie git nie powiodło się: ' + ' '.join(args))
    return result.stdout.strip()


def inspect(repo=None, fetch=True):
    repo = HELIX_HOME if repo is None else repo
    info = {'status': 'nie sprawdzono'}
    try:
        info['commit'] = output(repo, 'rev-parse', '--short', 'HEAD')
        branch = git(repo, 'symbolic-ref', '--quiet', '--short', 'HEAD')
        info['branch'] = branch.stdout.strip() if branch.returncode == 0 else 'HEAD (odłączony)'
        info['dirty'] = bool(output(repo, 'status', '--porcelain', '--untracked-files=all'))
        if branch.returncode:
            return info
        if fetch and git(repo, 'fetch', '--quiet', 'origin').returncode:
            return info
        # Only compare the current branch with its counterpart on origin.
        target = 'refs/remotes/origin/' + info['branch']
        counts = output(repo, 'rev-list', '--left-right', '--count', 'HEAD...' + target)
        ahead, behind = map(int, counts.split())
        info.update(ahead=ahead, behind=behind)
        if ahead and behind:
            info['status'] = 'gałąź się rozjechała – uzgodnij historię ręcznie'
        elif behind:
            info['status'] = f'jest {behind} nowych commitów – uruchom helix update'
        else:
            info['status'] = 'aktualny'
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError):
        pass
    return info


def update(check=False, repo=None, doctor=None):
    repo = HELIX_HOME if repo is None else repo
    if check:
        info = inspect(repo, fetch=False)
        print(info['status'])
        return 0
    try:
        branch = output(repo, 'symbolic-ref', '--quiet', '--short', 'HEAD')
        if output(repo, 'status', '--porcelain', '--untracked-files=all'):
            print('Odmowa: niezatwierdzone zmiany. Zatwierdź je lub przenieś ręcznie, potem uruchom helix update.')
            return 1
        old = output(repo, 'rev-parse', 'HEAD')
        output(repo, 'fetch', '--quiet', 'origin')
        target = 'refs/remotes/origin/' + branch
        ahead, behind = map(int, output(repo, 'rev-list', '--left-right', '--count', 'HEAD...' + target).split())
        if ahead and behind:
            print('Odmowa: gałąź się rozjechała. Uzgodnij historię z origin ręcznie, potem uruchom helix update.')
            return 1
        # Explicit origin/branch avoids pulling from an unrelated configured upstream.
        output(repo, 'pull', '--ff-only', 'origin', branch)
        new = output(repo, 'rev-parse', 'HEAD')
        print(output(repo, 'log', old + '..' + new, '--oneline') if old != new else 'aktualny')
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError):
        print('Aktualizacja nie powiodła się. Sprawdź ręcznie dostęp do origin i gałąź repozytorium Helixa; nie wykonano reset ani stash.')
        return 1
    if doctor:
        doctor()
    return 0
