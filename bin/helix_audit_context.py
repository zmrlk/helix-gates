"""Read-only contextual evidence for offline audits."""
import json
import os
import stat
import fnmatch
import re
import sys
from pathlib import Path

DENY = re.compile(r'secret|credential|private|memory|mail|session|klucz|has[lł]o|password|passwd|api[-_]?key|id_rsa|id_ed25519|\.env', re.I)

def sensitive(component):
    return bool(DENY.search(component) or ('token' in component.lower() and component not in ('tokens.json', 'tokens.css')))


def system_path(path):
    """Canonicalize only macOS system aliases, never a project-owned symlink."""
    path = Path(path).absolute()
    if sys.platform == 'darwin' and len(path.parts) > 1 and path.parts[1] in ('var', 'tmp', 'etc'):
        alias = Path('/') / path.parts[1]
        expected = Path('/private') / path.parts[1]
        if alias.is_symlink() and alias.resolve() == expected:
            return expected.joinpath(*path.parts[2:])
    return path


def user_parts(path):
    """Path components without the macOS /private system-alias prefix."""
    parts = Path(path).parts
    if sys.platform == 'darwin' and parts[1:2] == ('private',) and parts[2:3] and parts[2] in ('var', 'tmp', 'etc'):
        return parts[:1] + parts[2:]
    return parts


def safe_read(path, errors='replace'):
    """Read the opened regular-file descriptor, never a re-opened pathname.

    Resolve every directory component using no-follow descriptors too: a parent
    replacement cannot turn the final open into an escape. Fail closed where
    the platform cannot supply this primitive.
    """
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise OSError('bounded no-follow reads unavailable')
    path = system_path(path)
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            meta = os.fstat(leaf)
            if not stat.S_ISREG(meta.st_mode):
                raise OSError('not a regular file')
            with os.fdopen(leaf, 'rb', closefd=False) as stream:
                data = b''.join(iter(lambda: stream.read(65536), b''))
            return data.decode('utf-8', errors=errors)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)

def inventory(root):
    """One deterministic, non-executing inventory for all audit consumers."""
    from helix_source_coverage import scan
    return scan(root)[0]

def config(root):
    from helix_config import load
    return load(root)

def documents(root, paths):
    result = {}
    for value in paths:
        p = Path(value).expanduser()
        if not p.is_absolute():
            p = root / p
        # macOS /var -> /private/var is a system alias, not a project symlink;
        # its "private" component must not mark ordinary temp dirs sensitive.
        p = system_path(p)
        if not p.exists() or any(x.is_symlink() for x in [p, *p.parents]):
            raise ValueError('docs path must exist and must not be a symlink')
        if any(sensitive(x) for x in user_parts(p)):
            continue
        if p.is_dir():
            candidates = {str(p / name): text for name, text in inventory(p).items()}
        else:
            try:
                candidates = {str(p): safe_read(p)}
            except OSError:
                candidates = {}
        for path, text in candidates.items():
            f = Path(path)
            if f.suffix.lower() in ('.md', '.txt', '.yaml', '.yml', '.json', '.sql'):
                result[str(f.absolute())] = text
    return result

def gates(root, sources, cfg):
    found = []
    areas = {'performance', 'security', 'backend/architecture', 'UX', 'UI', 'ops/reliability', 'data', 'testing/CI', 'documentation'}
    for g in cfg.get('custom_gates', []):
        if not isinstance(g, dict) or not all(isinstance(g.get(k), str) and g[k].strip() for k in ('name', 'area', 'description')):
            raise ValueError('invalid custom gate')
        if g['area'] not in areas:
            raise ValueError('unknown custom gate area: ' + g['area'])
        path = g.get('file')
        command = g.get('command')
        if path is not None and (not isinstance(path, str) or path not in sources):
            raise ValueError('custom gate file missing or outside readable inventory')
        if command is not None and (not isinstance(command, str) or not command.strip()):
            raise ValueError('invalid custom gate command')
        if not path and not command:
            raise ValueError('custom gate requires file or command')
        if path and path in sources:
            found.append(dict(g, evidence=path + ':1'))
        elif g.get('command'):
            found.append(dict(g, evidence='helix.json:1'))
    for path, text in sources.items():
        names = []
        if path.endswith('package.json'):
            try:
                names = [k for k in json.loads(text).get('scripts', {}) if k.startswith(('gate:', 'check:'))]
            except (ValueError, AttributeError):
                pass
        elif Path(path).name == 'Makefile':
            names = re.findall(r'^(?:(?:gate|check|test)[\w-]*):', text, re.M)
        if (Path(path).suffix.lower() in ('.md', '.yaml', '.yml', '.json')
                and re.fullmatch(r'(?:visual[-_]?rules|reguly|test[-_]?matrix|macierz)(?:[-_][\w-]+)?\.(?:md|ya?ml|json)', Path(path).name, re.I)):
            names.append(path)
        if re.fullmatch(r'playwright\.config\.[cm]?[jt]s', Path(path).name):
            # Static declaration only; never evaluate target JavaScript.
            clean = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
            if re.search(r'\bprojects\s*:\s*\[', clean):
                names.append(path + ':projects')
        for name in names:
            area = 'UI' if re.search(r'visual|reguly|style|token', name, re.I) else 'testing/CI'
            found.append(dict(name=name, area=area, description='Detected project gate; execution unverified', evidence=path + ':1'))
    return found

def parts(root, cfg):
    from helix_dotnet import PROJECT_SUFFIXES, SOURCE_SUFFIXES
    root = system_path(root)
    declared = cfg.get('parts')
    if declared is not None:
        entries = [dict(path=k, **v) for k, v in declared.items()] if isinstance(declared, dict) else declared
    else:
        sources = inventory(root)
        paths = set()
        manifests = {'package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'composer.json',
                     'requirements.txt', 'pom.xml', 'build.gradle', 'project.json'}
        containers = {'apps', 'packages', 'services', 'libs', 'modules'}
        ignored = {'docs', 'doc', 'tests', 'test', 'examples', 'fixtures', 'coverage'}
        code = {'.py', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.go', '.rs',
                '.java', '.rb', '.php', '.sql', '.sh', '.tf', '.hcl', '.prisma'} | SOURCE_SUFFIXES
        for name in sources:
            p = Path(name)
            if len(p.parts) < 2 or p.parts[0].startswith('.') or p.parts[0] in ignored:
                continue
            if p.name in manifests or p.suffix.lower() in PROJECT_SUFFIXES:
                paths.add(p.parent.as_posix())
            if p.suffix.lower() in code or p.name.startswith(('Dockerfile', 'docker-compose', 'compose.')) or p.name == 'crontab':
                depth = 2 if p.parts[0] in containers and len(p.parts) > 2 else 1
                paths.add('/'.join(p.parts[:depth]))
        try:
            work = json.loads(sources.get('package.json', '{}')).get('workspaces', [])
            if isinstance(work, dict): work = work.get('packages', [])
            if not isinstance(work, list): work = []
        except (ValueError, AttributeError):
            work = []
        work += re.findall(r'^\s*-\s*[\'\"]?([^\s\'\"#]+)', sources.get('pnpm-workspace.yaml', ''), re.M)
        candidates = {str(Path(p).parent) for p in sources if '/' in p}
        for pattern in work:
            if isinstance(pattern, str) and not pattern.startswith('!'):
                paths.update(p for p in candidates if fnmatch.fnmatchcase(p, pattern))
        excludes = [p[1:] for p in work if isinstance(p, str) and p.startswith('!')]
        paths = {p for p in paths if p != '.' and not p.startswith('.') and not any(fnmatch.fnmatchcase(p, e) for e in excludes)}
        # A manifest-bearing parent is a part; nested source folders are not extra services.
        paths = {p for p in paths if not any(p.startswith(q + '/') for q in paths if q != p)}
        entries = [dict(path=p) for p in sorted(paths)]
    for entry in entries:
        p = root / entry['path']
        if any(x.is_symlink() for x in [p, *p.parents]) or not p.is_dir() or root.resolve() not in p.resolve().parents:
            raise ValueError('part must be a child directory')
    return entries

def infer_profile(sources, docs, part_count):
    signals = []
    # Examples, tests and prose counts are not evidence of deployed scale.
    operational = {p: t for p, t in sources.items()
                   if not any(x.lower() in {'examples', 'fixtures', 'tests', 'test', '__tests__'} for x in Path(p).parts)
                   and not re.search(r'(?:[._](?:test|spec)\.)', p)}
    for label, pattern in [('tenancy', r'multi.?tenan|tenant_id'), ('queues', r'celery|rabbitmq|kafka|bullmq'), ('replicas', r'replicas\s*:\s*[2-9]')]:
        for path, text in sorted(operational.items()):
            match = re.search(pattern, text, re.I)
            if match:
                signals.append(f'{label} ({path}:{text[:match.start()].count(chr(10)) + 1})')
                break
    if part_count > 1: signals.append(f'{part_count} services/parts')
    profile = 'XL' if len(signals) >= 4 else 'L' if len(signals) >= 2 else 'M' if signals else 'S'
    return profile, 'WARNING / UWAGA: ASSUMPTION inferred profile ' + profile + '; reasons: ' + (', '.join(signals) or 'no scale signals in bounded inventory') + '; declarations do not establish deployed scale; confirm with --profile.'
