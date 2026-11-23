"""Static module names, never prose or imported Python symbol names."""
import ast
from pathlib import Path
import re

TOKENS = re.compile(r'''(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(?P<word>[A-Za-z_$][\w$]*)|(?P<punct>[^\s])''')


def modules(path, source):
    suffix = Path(path).suffix.lower()
    if suffix == '.py':
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return set(), 'Python syntax not parsed; no import guesses'
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add('.' * node.level + (node.module or ''))
        return names, None
    if suffix not in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts'}:
        return set(), 'Import syntax unsupported; dependency graph incomplete'
    tokens = [(m.lastgroup, m.group()) for m in TOKENS.finditer(source) if m.lastgroup != 'comment']
    names = set()
    def literal(index):
        if index >= len(tokens) or tokens[index][0] != 'string':
            return None
        match = re.fullmatch(r'''(['"])([\w@./:+#~!?-]+)\1''', tokens[index][1])
        return match[2] if match else None
    for index, (kind, word) in enumerate(tokens):
        if kind != 'word' or word not in {'import', 'export', 'require'} or index and tokens[index - 1][1] == '.':
            continue
        if word in {'import', 'require'} and index + 1 < len(tokens) and tokens[index + 1][1] == '(':
            if target := literal(index + 2):
                names.add(target)
        elif word == 'import' and (target := literal(index + 1)):
            names.add(target)
        elif word != 'require':
            for position in range(index + 1, len(tokens)):
                token_kind, value = tokens[position]
                if value in {';', 'import', 'export', '='}:
                    break
                if token_kind == 'word' and value == 'from':
                    if target := literal(position + 1):
                        names.add(target)
                    break
    return names, 'JS/TS lexical import hints; dynamic expressions, templates and shadowing unresolved'
