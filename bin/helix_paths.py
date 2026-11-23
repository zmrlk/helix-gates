"""Canonical filesystem identities, including paths through symlinked ancestors."""
from pathlib import Path


def normalize(path):
    return Path(path).expanduser().resolve()


def relative(path, root):
    return normalize(path).relative_to(normalize(root))


def within(path, root):
    return normalize(path).is_relative_to(normalize(root))


def summarize(values, full='audit.json/evidence', limit=5):
    """Human output is bounded; the machine artifact retains every evidence path."""
    values = list(values)
    examples = ', '.join(str(x) for x in values[:limit])
    return f'{len(values)} paths: {examples}; full list: {full}'
