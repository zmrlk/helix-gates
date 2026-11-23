"""Release coordination. Network only in explicit release execution, never check."""
import argparse
from collections import defaultdict
from datetime import date, datetime
import json
from pathlib import Path
import re
import subprocess
from helix_continuity import Continuity, validate, write, bounded
from helix_contracts import VERSION

VERSION_RE = r'\d+\.\d+\.\d+(?:-[\w.]+)?'


def git(root, *args):
    p = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, timeout=60)
    if p.returncode:
        raise ValueError('git ' + args[0] + ': operacja nie powiodła się')
    return p.stdout.strip()


def source_version(root):
    text = bounded(Path(root).resolve(), 'bin/helix_contracts.py').read_text()
    match = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]+)', text, re.M)
    if not match or not re.fullmatch(VERSION_RE, match[1]):
        raise ValueError('brak poprawnego źródła semver')
    return match[1]


def inventory(root, ref='origin/master', include_head=False):
    """A missing trusted reference fails closed; no hidden fallback to HEAD."""
    versions = defaultdict(set)
    refs = (ref, 'HEAD') if include_head else (ref,)
    for line in git(root, 'log', '--format=%H%x09%s', *refs).splitlines():
        sha, subject = line.split('\t', 1)
        for version in re.findall(r'\bHelix (' + VERSION_RE + r')(?![\w.-])', subject):
            versions[version].add(sha)
    for tag in git(root, 'tag', '--list').splitlines():
        if re.fullmatch('v?' + VERSION_RE, tag):
            versions[tag.removeprefix('v')].add('tag:' + tag)
    # Read changelog at the trusted remote ref, not the uncommitted candidate.
    for version in re.findall(r'^#\s+(' + VERSION_RE + r')\s+—', git(root, 'show', ref + ':CHANGELOG.md'), re.M):
        versions.setdefault(version, set())
    return versions


def check(root, ref='origin/master', staged=False, enforce_change=True):
    root = Path(root)
    errors = []
    versions = inventory(root, ref, include_head=True)
    remote_versions = inventory(root, ref)
    exceptions_path = root / 'requirements/release-history.json'
    exceptions = json.loads(exceptions_path.read_text()) if exceptions_path.exists() else {}
    base = exceptions.get('_enforcement_base')
    if base:
        for sha in git(root, 'rev-list', base + '..HEAD').splitlines():
            diff = git(root, 'show', '--format=', '--first-parent', sha, '--', 'bin/helix_contracts.py')
            match = re.search(r'^\+VERSION\s*=\s*[\'"]([^\'"]+)', diff, re.M)
            if not match: continue
            version = match[1]
            # The same explicit, version-scoped historical exception applies to
            # duplicate subjects and missing receipts; never exempt future SHAs.
            exception = exceptions.get(version, {})
            if exception.get('reason', '').strip() and sha in exception.get('commits', []):
                continue
            try:
                if not re.fullmatch(VERSION_RE, version): raise ValueError('semver')
                receipt = json.loads(git(root, 'show', sha + ':requirements/releases/' + version + '.json'))
                claim = validate('claim', receipt['claim'])
                committed = datetime.fromisoformat(git(root, 'show', '-s', '--format=%cI', sha))
                if (receipt['version'] != version or claim['task_id'] != 'release' or claim['status'] != 'active'
                        or not datetime.fromisoformat(claim['created_at']) <= committed < datetime.fromisoformat(claim['expires_at'])):
                    raise ValueError('claim')
            except (ValueError, KeyError, TypeError):
                errors.append('commit zmienia wersję bez ważnego claimu release: ' + sha)
    for version, occurrences in versions.items():
        commits = {x for x in occurrences if not x.startswith('tag:')}
        exception = exceptions.get(version, {})
        allowed = set(exception.get('commits', [])) if exception.get('reason') else set()
        if len([x for x in occurrences if x.startswith('tag:')]) > 1:
            errors.append('powtórzona wersja w tagach: ' + version)
        if len(commits) > 1 and not commits <= allowed:
            errors.append('powtórzona wersja w historii: ' + version)
    headings = re.findall(r'^#\s+(' + VERSION_RE + r')\s+—', bounded(root.resolve(), 'CHANGELOG.md').read_text(), re.M)
    if len(headings) != len(set(headings)):
        errors.append('powtórzony nagłówek CHANGELOG')
    current = source_version(root)
    if not headings or headings[0] != current or any(tuple(map(int, v.split('-')[0].split('.'))) > tuple(map(int, current.split('-')[0].split('.'))) for v in headings):
        errors.append('wersja źródła różni się od CHANGELOG')
    changed = git(root, 'diff', '--cached' if staged else 'HEAD', '--', 'bin/helix_contracts.py')
    if enforce_change and re.search(r'^\+VERSION\s*=', changed, re.M):
        continuity = Continuity(root)
        claims = [v for _, v in continuity.records('claims') if v['task_id'] == 'release' and continuity.active(v)]
        if len(claims) != 1:
            errors.append('zmiana wersji bez jednego aktywnego claimu release')
        if source_version(root) in remote_versions:
            errors.append('wersja już obecna na origin lub w tagach')
    return errors


def release(root, bump='patch', dry_run=False, offline=False, push_tag=False, agent='release-agent', ttl=3600):
    root = Path(root)
    if push_tag:
        raise ValueError('--push-tag wymaga release tag po commicie wrappera')
    continuity = Continuity(root)
    claim = None
    if not dry_run:
        claim = continuity.claim_take('release', agent, ttl)
    try:
        if not offline:
            git(root, 'fetch', '--tags', 'origin')
        versions = inventory(root, include_head=True)
        current = source_version(root)
        major, minor, patch = map(int, current.split('-')[0].split('.'))
        suffix = '-' + current.split('-', 1)[1] if '-' in current else ''
        candidate = f'{major}.{minor + 1}.0{suffix}' if bump == 'minor' else f'{major}.{minor}.{patch + 1}{suffix}'
        if candidate in versions:
            raise ValueError('wersja już użyta: ' + candidate)
        errors = check(root, enforce_change=False)
        if errors:
            raise ValueError('; '.join(errors))
        tags = git(root, 'tag', '--merged', 'HEAD', '--sort=-creatordate').splitlines()
        commits = git(root, 'log', '--format=- Zmiana %h', (tags[0] + '..HEAD') if tags else 'HEAD')
        entry = f'# {candidate} — {date.today().isoformat()}\n\n{commits}\n\n'
        result = dict(helix_version=VERSION, schema_version=1, version=candidate,
                      status='dry-run' if dry_run else 'prepared', remote_status='not-run: offline snapshot' if offline else 'fetched', changelog=entry)
        if not dry_run:
            # Annotate the source commit honestly: the wrapper must commit the prepared files.
            # Refuse to create a misleading tag pointing at the previous version.
            path = bounded(root.resolve(), 'bin/helix_contracts.py')
            log = bounded(root.resolve(), 'CHANGELOG.md')
            receipt_path = bounded(root.resolve(), 'requirements/releases/' + candidate + '.json')
            if receipt_path.exists():
                raise ValueError('istnieje już receipt tego wydania')
            path.write_text(re.sub(r'^VERSION\s*=.*$', 'VERSION = ' + repr(candidate), path.read_text(), count=1, flags=re.M))
            log.write_text(entry + log.read_text())
            write(receipt_path, dict(
                schema_version=1, helix_version=candidate, version=candidate,
                source_sha=git(root, 'rev-parse', 'HEAD'), claim=claim))
            result.update(status='awaiting-wrapper-commit', lease_id=claim['lease_id'],
                          tag_status='not-run: commit prepared files, then release tag')
        return result
    except Exception:
        if claim:
            continuity.claim_release('release', agent, claim['lease_id'])
        raise


def tag(root, push=False):
    root = Path(root)
    errors = check(root)
    if errors: raise ValueError('; '.join(errors))
    if git(root, 'status', '--porcelain'):
        raise ValueError('tag wymaga czystego drzewa po commicie wrappera')
    c = Continuity(root)
    claims = [v for _, v in c.records('claims') if v['task_id'] == 'release' and c.active(v)]
    if len(claims) != 1: raise ValueError('tag wymaga claimu release')
    version = source_version(root)
    occupied = inventory(root).get(version)
    if occupied is not None and occupied != {git(root, 'rev-parse', 'HEAD')}:
        raise ValueError('wersja już użyta')
    git(root, 'tag', '-a', 'v' + version, '-m', 'Helix ' + version)
    if push: git(root, 'push', 'origin', 'refs/tags/v' + version)
    return {'helix_version': VERSION, 'schema_version': 1, 'tag': 'v' + version}


def parsers(sp):
    p = sp.add_parser('release', help='Kolejka wydań i kontrola historii')
    p.add_argument('action', nargs='?', choices=['check', 'tag'])
    p.add_argument('--bump', choices=['patch', 'minor'], default='patch')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--offline', action='store_true')
    p.add_argument('--push-tag', action='store_true')
    p.add_argument('--staged', action='store_true')
    p.add_argument('--agent', default='release-agent')
    p.add_argument('--ttl', type=int, default=3600)


def dispatch(a):
    try:
        if a.action == 'check':
            errors = check(a.repo, staged=a.staged)
            result = dict(helix_version=VERSION, schema_version=1, errors=errors, status='FAIL' if errors else 'PASS')
        elif a.action == 'tag':
            if a.offline and a.push_tag:
                raise ValueError('--offline wyklucza --push-tag')
            if a.dry_run:
                raise ValueError('tag --dry-run: pominięto; użyj release --dry-run')
            result = tag(a.repo, a.push_tag); errors = []
        else:
            result = release(a.repo, a.bump, a.dry_run, a.offline, a.push_tag, a.agent, a.ttl); errors = []
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if errors else 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'error': str(error), 'helix_version': VERSION, 'schema_version': 1}))
        return 2
