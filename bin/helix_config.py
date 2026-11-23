"""Explicit audit configuration; never write into the inspected repository."""
import json
from pathlib import Path

_overrides = {}


def configure(repo, path):
    root = Path(repo).resolve()
    source = Path(path).expanduser().absolute()
    data = _read(source, required=True)
    _overrides[root] = (source, data)
    return data


def _read(path, required=False):
    if path.is_symlink():
        if required:
            raise ValueError('config: plik nie może być dowiązaniem')
        return {}
    if not path.is_file():
        if required:
            raise ValueError('config: brak pliku konfiguracji')
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('config: niepoprawny JSON') from exc
    if not isinstance(data, dict):
        raise ValueError('config: wymagany obiekt JSON')
    return data


def load(repo):
    root = Path(repo).resolve()
    if root in _overrides:
        # Callers merge copies, never mutate the shared input.
        return json.loads(json.dumps(_overrides[root][1]))
    return _read(root / 'helix.json')


def source(repo):
    root = Path(repo).resolve()
    return _overrides[root][0] if root in _overrides else root / 'helix.json'
