"""Pure, bounded SQL declaration and PostgreSQL availability readers.

Callers supply already-read migration SQL and the output of the constant catalog
query. This module never reads files, executes SQL or installs extensions.
Only literal top-level CREATE EXTENSION statements are requirements. VERSION is
a declaration, never proof that the requested extension version is available.
"""
import json
from pathlib import PurePosixPath
import re


COMMON_EXTENSIONS = ('pg_trgm', 'btree_gist', 'fuzzystrmatch', 'pgcrypto')
AVAILABLE_EXTENSIONS_SQL = """SELECT COALESCE(json_agg(json_build_object(
  'name', name,
  'default_version', default_version,
  'installed_version', installed_version
) ORDER BY name), '[]'::json)
FROM pg_available_extensions;"""

_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.+-]{0,62}\Z')
_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+~:-]{0,127}\Z')
_WORD = re.compile(r'[A-Za-z_][A-Za-z0-9_$]*')
_DOLLAR = re.compile(r'\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$')


def _path(value):
    if not isinstance(value, str) or not value or len(value) > 1000:
        raise ValueError('invalid extension source path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or any(c in value for c in '\\:\x00\r\n'):
        raise ValueError('invalid extension source path')
    return path.as_posix()


def _tokens(sql):
    """Lex only enough SQL to separate statements, literals and real markers."""
    i = 0
    line = 1
    while i < len(sql):
        start, token_line = i, line
        ch = sql[i]
        kind, value = None, None
        if ch.isspace():
            i += 1
        elif sql.startswith('--', i):
            end = sql.find('\n', i)
            i = len(sql) if end < 0 else end
            marker = re.fullmatch(r'--\s*migrate:(up|down)\b[^\r\n]*', sql[start:i], re.I)
            if marker and not sql[sql.rfind('\n', 0, start) + 1:start].strip():
                kind, value = 'directive', marker[1].lower()
        elif sql.startswith('/*', i):
            depth = 1
            i += 2
            while i < len(sql) and depth:
                if sql.startswith('/*', i):
                    depth += 1
                    i += 2
                elif sql.startswith('*/', i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                kind, value = 'invalid', None
        elif ch in "'\"" or (ch in 'eE' and sql[i:i + 2].lower() == "e'"):
            escaped = ch in 'eE'
            quote = "'" if escaped else ch
            i += 2 if escaped else 1
            chunks = []
            closed = False
            while i < len(sql):
                if sql[i] == quote:
                    if sql[i:i + 2] == quote * 2:
                        chunks.append(quote)
                        i += 2
                    else:
                        i += 1
                        closed = True
                        break
                elif escaped and sql[i] == '\\':
                    # E-string contents are opaque; do not infer a version from
                    # PostgreSQL escape syntax or execute string decoding.
                    chunks.append('\x00')
                    i = min(i + 2, len(sql))
                else:
                    chunks.append(sql[i])
                    i += 1
            kind = ('identifier' if quote == '"' else 'literal') if closed else 'invalid'
            value = ''.join(chunks) if closed else None
        elif ch == '$' and (dollar := _DOLLAR.match(sql, i)):
            end = sql.find(dollar[0], dollar.end())
            i = len(sql) if end < 0 else end + len(dollar[0])
            kind, value = ('invalid' if end < 0 else 'body'), None
        elif word := _WORD.match(sql, i):
            i = word.end()
            kind, value = 'word', word[0]
        else:
            i += 1
            kind, value = 'symbol', ch
        line += sql.count('\n', start, i)
        if kind:
            yield kind, value, token_line


def sql_extensions(sql, *, path):
    """Return declarations and unresolved declaration gaps, with original lines.

    dbmate down sections, comments, quoted strings and dollar bodies cannot
    introduce requirements. Dynamic SQL remains outside this literal scope.
    Unsupported names/options produce a location and fixed reason, not raw SQL.
    """
    path = _path(path)
    if not isinstance(sql, str):
        raise ValueError('invalid extension source SQL')
    tokens = list(_tokens(sql))
    start = next((i + 1 for i, token in enumerate(tokens)
                  if token[:2] == ('directive', 'up')), 0)
    declarations, gaps = [], []

    def gap(line, reason):
        row = dict(path=path, line=line, reason_code=reason)
        if row not in gaps:
            gaps.append(row)

    def statement(items):
        if items and items[0][0] == 'word' and items[0][1].lower() in ('do', 'execute', 'call'):
            gap(items[0][2], 'dynamic_sql_requirements_unresolved')
            return
        if len(items) < 2 or [(x[0], str(x[1]).lower()) for x in items[:2]] != [
            ('word', 'create'), ('word', 'extension')
        ]:
            return
        line = items[0][2]
        pos = 2
        if [(x[0], str(x[1]).lower()) for x in items[pos:pos + 3]] == [
                ('word', 'if'), ('word', 'not'), ('word', 'exists')]:
            pos += 3
        if pos >= len(items) or items[pos][0] not in ('word', 'identifier'):
            gap(line, 'extension_name_unresolved')
            return
        name = items[pos][1].lower() if items[pos][0] == 'word' else items[pos][1]
        pos += 1
        if not _NAME.fullmatch(name) or (pos < len(items) and items[pos][:2] == ('symbol', '.')):
            gap(line, 'extension_name_unresolved')
            return
        version = None
        version_seen = False
        if pos < len(items) and items[pos][0] == 'word' and items[pos][1].lower() == 'with':
            pos += 1
        while pos < len(items):
            token = items[pos]
            option = token[1].lower() if token[0] == 'word' else None
            pos += 1
            if option == 'cascade':
                continue
            if option == 'schema' and pos < len(items) and items[pos][0] in ('word', 'identifier'):
                pos += 1
                continue
            if option == 'version':
                if version_seen:
                    version = None
                    gap(line, 'extension_version_unresolved')
                    break
                version_seen = True
                if (pos < len(items) and items[pos][0] in ('literal', 'identifier', 'word')
                        and _VERSION.fullmatch(items[pos][1])):
                    version = items[pos][1]
                    pos += 1
                    continue
                gap(line, 'extension_version_unresolved')
                break
            gap(line, 'extension_options_unresolved')
            break
        declarations.append(dict(name=name, path=path, line=line, declared_version=version))

    current = []
    for token in tokens[start:]:
        if token[:2] == ('directive', 'down'):
            break
        if token[0] == 'directive':
            continue
        if token[:2] == ('symbol', ';'):
            statement(current)
            current = []
        else:
            current.append(token)
    statement(current)
    return dict(declarations=declarations, gaps=gaps)


def parse_available_extensions(output):
    """Validate only the three selected catalog fields; never echo bad output."""
    def invalid():
        raise ValueError('invalid available extensions catalog')

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                invalid()
            result[key] = value
        return result

    if not isinstance(output, str):
        invalid()
    try:
        rows = json.loads(output, object_pairs_hook=object_pairs, parse_constant=lambda value: invalid())
    except (ValueError, TypeError, RecursionError):
        raise ValueError('invalid available extensions catalog') from None
    if not isinstance(rows, list):
        invalid()
    result = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'name', 'default_version', 'installed_version'}:
            invalid()
        name = row['name']
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in result:
            invalid()
        for key in ('default_version', 'installed_version'):
            value = row[key]
            if value is not None and (not isinstance(value, str) or not _VERSION.fullmatch(value)):
                invalid()
        result[name] = dict(default_version=row['default_version'], installed_version=row['installed_version'])
    return dict(sorted(result.items()))
