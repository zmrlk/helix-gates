"""Atomic identifier reservations in an explicitly selected shared registry."""
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import tempfile

from helix_audit_context import safe_read, system_path


def validate(data):
    if not isinstance(data, dict) or data.get('schema_version') != 1 or not isinstance(data.get('entries'), list):
        raise ValueError('registry: invalid schema')
    ids, prefixes = set(), {}
    for row in data['entries']:
        if not isinstance(row, dict) or not all(isinstance(row.get(k), str) and row[k].strip() for k in ('id', 'prefix', 'type', 'reserved_by', 'purpose')):
            raise ValueError('registry: incomplete reservation')
        prefix, kind, ident = row['prefix'], row['type'], row['id']
        if not re.fullmatch('[A-Z][A-Z0-9]{0,15}', prefix) or not re.fullmatch(re.escape(prefix) + r'-[0-9]{4,}', ident) or int(ident.split('-')[-1]) < 1:
            raise ValueError('registry: ID prefix mismatch')
        if ident in ids:
            raise ValueError('registry: duplicate ID: ' + ident)
        if prefix in prefixes and prefixes[prefix] != kind:
            raise ValueError('registry: prefix/type collision: ' + prefix)
        ids.add(ident)
        prefixes[prefix] = kind
    return data


def registry_path(value):
    path = system_path(value)
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError('registry: symlinks forbidden')
    if not path.parent.is_dir():
        raise ValueError('registry: parent directory must already exist')
    return path


def read(path):
    path = registry_path(path)
    if not path.exists():
        raise ValueError('registry: missing')
    return validate(json.loads(safe_read(path, errors='strict')))


def reserve(path, prefix, kind, owner, purpose, ident=None):
    path = registry_path(path)
    # Lock inode is stable across atomic replacements; kernel releases on exit.
    fd = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        data = read(path) if path.exists() else dict(schema_version=1, entries=[])
        if ident is None:
            used = [int(row['id'].rsplit('-', 1)[1]) for row in data['entries'] if row['prefix'] == prefix]
            ident = f'{prefix}-{max(used, default=0) + 1:04d}'
        row = dict(id=ident, prefix=prefix, type=kind, reserved_by=owner, purpose=purpose,
                   reserved_at=datetime.now(timezone.utc).isoformat())
        data['entries'].append(row)
        validate(data)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, prefix='.' + path.name, delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(data, stream, ensure_ascii=False, indent=2)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return row
    finally:
        os.close(fd)
