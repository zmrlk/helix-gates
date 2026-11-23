"""Offline inventory and complete no-follow reads; never execute target code."""
import hashlib
import os
from pathlib import Path
import subprocess
import time
from helix_audit_context import safe_read, sensitive
from helix_dotnet import SOURCE_SUFFIXES
from helix_source_policy import AGENT_STATE_DIRECTORIES

PRIVATE = {'.git', '.aws', '.ssh', '.docker', '.npmrc', '.netrc', '.pypirc'} | AGENT_STATE_DIRECTORIES
CODE = {'.py', '.js', '.ts', '.jsx', '.tsx', '.svelte', '.vue', '.go', '.rs', '.java', '.php', '.rb', '.cs', '.sql', '.sh'} | SOURCE_SUFFIXES


# Pamięć sesji narzędzi (memsearch) zapisywana w katalogu roboczym Codexa i Claude: nie jest kodem projektu.
TOOL_STATE = frozenset({'.memsearch'})


def tool_state(name):
    return Path(name).parts[:1] and Path(name).parts[0] in TOOL_STATE


def paths(root):
    """Git tracks ignored files too; fallback is explicit in the result."""
    try:
        from helix_git_readonly import git as read_git
        listed = {}
        for kind in ('--cached', '--others'):
            result = read_git(root, 'ls-files', kind, *(['--exclude-standard'] if kind == '--others' else []), '-z', text=False, timeout=30)
            if result.returncode: raise subprocess.CalledProcessError(result.returncode, ['git', 'ls-files'])
            listed[kind] = {os.fsdecode(p) for p in result.stdout.split(b'\0') if p}
        # Pomijamy tylko nieśledzony stan narzędzia; plik dodany do repozytorium w .memsearch/ zostaje w przeglądzie.
        return sorted(listed['--cached'] | {n for n in listed['--others'] if not tool_state(n)}), 'git'
    except (OSError, subprocess.SubprocessError):
        names = []
        for base, dirs, files in os.walk(root, followlinks=False):
            top = Path(base) == root
            excluded = [d for d in dirs if d in PRIVATE or sensitive(d) or (Path(base)/d).is_symlink() or (top and d in TOOL_STATE)]
            names.extend((Path(base)/d).relative_to(root).as_posix() for d in excluded if d != '.git')   # widoczne jako pominięte
            dirs[:] = sorted(d for d in dirs if d not in excluded)
            names.extend((Path(base) / n).relative_to(root).as_posix() for n in files)
        return sorted(names), 'filesystem (git unavailable; ignored scope unknown)'


def classify(name):
    p = Path(name)
    if p.name.endswith(('.lock', '-lock.json')) or p.name == 'go.sum': return 'lock'
    if any(x in p.parts for x in ('vendor', 'node_modules')): return 'vendored'
    if 'migration' in name.lower() or p.suffix == '.sql': return 'migrations'
    if any(x in name.lower() for x in ('locales/', 'i18n/', 'translations/')): return 'i18n'
    if p.suffix in CODE: return 'code'
    if p.suffix in {'.md', '.rst', '.txt'}: return 'docs'
    return 'config'


def scan(repo, time_budget_seconds=None):
    root = Path(repo).resolve(strict=True)
    started = time.monotonic()
    if time_budget_seconds is not None and time_budget_seconds < 0: raise ValueError('negative time budget')
    names, method = paths(root)
    sources, rows = {}, []
    for name in names:
        p = root / name
        row = dict(file=name, category=classify(name), status='skipped', reason=None,
                   lines_total=None, lines_read=0)
        rows.append(row)
        if time_budget_seconds is not None and time.monotonic() - started >= time_budget_seconds:
            row['reason'] = 'time budget exceeded; not read'; continue
        if Path(name).is_absolute() or '..' in Path(name).parts:
            row['reason'] = 'unsafe path'; continue
        if any(c in PRIVATE or sensitive(c) for c in Path(name).parts):
            row['reason'] = 'privacy policy; content not opened'; continue
        if p.is_symlink() or not p.resolve().is_relative_to(root):
            row['reason'] = 'symlink or outside repository'; continue
        try:
            text = safe_read(p, errors='strict')
        except (OSError, UnicodeError):
            row['reason'] = 'unreadable or non-UTF-8'; continue
        if '\0' in text:
            row.update(category='binary', reason='NUL byte in content'); continue
        count = text.count('\n') + int(bool(text) and not text.endswith('\n'))
        row.update(status='read', lines_total=count, lines_read=count,
                   sha256=hashlib.sha256(text.encode()).hexdigest())
        # Generated classification requires a declaration, never just a directory name.
        if any(x in text[:2048].lower() for x in ('@generated', 'automatically generated', 'do not edit')):
            row.update(category='generated', classification_evidence=f'{name}:1 (generation marker in header)')
        row['chunks'] = [dict(offset=start, characters=len(window), sha256=hashlib.sha256(window.encode()).hexdigest()) for start, window in chunks(text)]
        sources[name] = text
    skipped = [r for r in rows if r['status'] != 'read']
    coverage = dict(schema_version=1, status='INCOMPLETE' if skipped or method != 'git' else 'COMPLETE',
                    inventory_method=method, files_total=len(rows), files_read=len(sources),
                    lines_total=sum(r['lines_total'] or 0 for r in rows),
                    lines_read=sum(r['lines_read'] for r in rows),
                    unknown_line_totals=sum(r['lines_total'] is None for r in rows), files=rows,
                    meaning='Read coverage only; no correctness or execution credit. Unknown totals are not zero lines.')
    return sources, coverage


def chunks(text, size=65536, overlap=4096):
    """Bounded windows for local multiline detectors, with absolute offsets."""
    if size <= overlap or overlap < 0: raise ValueError('invalid overlap')
    for start in range(0, len(text), size - overlap):
        yield start, text[start:start + size]
