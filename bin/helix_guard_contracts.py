"""Explicit project guard contracts; names have no default security meaning."""
import re
from helix_config import load as project_config

FIELDS = ('record_context_guards', 'scope_guards', 'identity_guards', 'middleware_factories')


def load(repo):
    config = project_config(repo).get('static_security', {})
    if not isinstance(config, dict):
        raise ValueError('static_security musi być obiektem')
    result = {}
    for field in FIELDS:
        names = config.get(field, [])
        if not isinstance(names, list) or any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_$][\w$]*', name) for name in names):
            raise ValueError('static_security.' + field + ' wymaga listy nazw funkcji')
        result[field] = frozenset(names)
    return result


def call_pattern(names):
    return r'\b(?:' + '|'.join(re.escape(name) for name in sorted(names)) + r')\s*\(' if names else r'(?!)'
