"""One-hop local helper candidates over already validated private AST facts.

No files, imports, configuration or project code are evaluated here. A result is
only a recognized source relation ending in an explicitly configured four-argument guard.
It is not independent evidence of production authorization.
"""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import re

import helix_security_ast_rules as R

_REF = re.compile(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\Z')
_IDENTIFIER = re.compile(r'[A-Za-z_$][\w$]*\Z')
_NONNULL_REF = re.compile(r'[A-Za-z_$][\w$]*!?(?:\.[A-Za-z_$][\w$]*!?)*\Z')
_LITERAL_DEFAULT = re.compile(r'''(?:null|true|false|-?\d+(?:\.\d+)?|'[^'\\\r\n]*'|"[^"\\\r\n]*")\Z''')
_ROW_KEY = re.compile(r'(?:record|row|resource|object|item|entity|project|[A-Za-z_$][\w$]*Row)\Z')
_REQUEST_REF = re.compile(r'(?:params|query|body|searchParams|(?:event|req|request)\.(?:params|query|body))\.[\w$]+\Z')
_PRINCIPAL_REF = re.compile(r'(?:locals(?:\.user)?|event\.locals(?:\.user)?|(?:req|request)\.user|user|actor|principal|session(?:\.user)?)\Z')
_DATABASE_READ = re.compile(r'(?:db|prisma|supabase|pool)\b.*\.(?:findUnique|findFirst|find|select|query|from|get)\Z')
_ID_KEY = re.compile(r'(?:id|[A-Za-z_$][\w$]*(?:Id|_id))\Z')
_EXTENSIONS = ('.ts', '.js', '.tsx', '.jsx', '.mts', '.mjs', '.cts', '.cjs')


def _split(value):
    """Split only balanced, ordinary arguments; templates/dynamic syntax refuse.

    The range is already an AST arguments/parameters node. This tiny splitter
    is not used to discover nodes or to infer an arbitrary data-flow graph.
    """
    if not isinstance(value, str) or not value.startswith('(') or not value.endswith(')'):
        return None
    value = value[1:-1]
    pieces, start, stack, quote, escape = [], 0, [], None, False
    for i, char in enumerate(value):
        if quote:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char == '`' or value[i:i+2] in ('/*', '//'):
            return None
        elif char in '([{':
            stack.append(char)
        elif char in ')]}':
            if not stack or '([{'.index(stack.pop()) != ')]}'.index(char):
                return None
        elif char == ',' and not stack:
            pieces.append(value[start:i].strip()); start = i + 1
    if quote or stack:
        return None
    last = value[start:].strip()
    if last:
        pieces.append(last)
    return pieces if all(pieces) else None


def _reference(value):
    value = re.sub(r'\s*\.\s*', '.', value.strip())
    # TS non-null assertions do not select another value. Optional access,
    # calls, indexing, negation and other operators remain unresolved.
    return value.replace('!', '') if _NONNULL_REF.fullmatch(value) else None


def _parameters(function):
    raw = R.text(function, 'parameters')
    values = _split(raw) if raw else [R.text(function, 'parameter')]
    if values is None:
        return None
    names = []
    for value in values:
        # A constant default cannot execute a call or choose a new principal.
        # The caller still has to supply the actual ID/principal positions.
        declaration, separator, default = value.partition('=')
        if separator and not _LITERAL_DEFAULT.fullmatch(default.strip()):
            return None
        value = declaration.strip()
        if value.startswith(('...', '{', '[')):
            return None
        match = re.fullmatch(r'''([A-Za-z_$][\w$]*)(?:\s*:\s*[\w$.<>\[\]| &'\"]+)?''', value)
        if not match or match[1] in names:
            return None
        names.append(match[1])
    return names


def _canonical(scope, value, before):
    value = _reference(value)
    if value is None:
        return None
    base = value.split('.')[0]
    if not scope.unchanged(base, scope.body['start'], before):
        return None
    bindings = [n for n in scope.bindings if R.text(n, 'name').strip() == base and n['start'] < before]
    if not bindings:
        return value
    if len(bindings) != 1 or value != base or not scope.direct(bindings[0]):
        return None
    original = _reference(R.text(bindings[0], 'value'))
    if original is None or not scope.unchanged(original.split('.')[0], bindings[0]['start'], before):
        return None
    return original


def _operation_ids(scope, effect):
    arguments = R.field(effect, 'arguments')
    if not arguments:
        return set()
    args = _split(R.text(arguments))
    candidates = set()
    if args is not None and len(args) == 1:
        ref = _reference(args[0])
        if ref:
            candidates.add(ref)
    # In ORM arguments only the operation's own where.id, never data.id.
    wheres = R.operation_where_pairs(scope,effect) if args and args[0].startswith('{') else []
    for where in wheres:
        context=R.field(where,'value')
        if any(R.contains(context,n) for n in scope.kind('spread_element')):
            continue
        for pair in R.direct_pairs(scope,context):
            key = R.text(pair, 'key').strip().strip('"\'')
            if _ID_KEY.fullmatch(key):
                ref = _reference(R.text(pair, 'value'))
                if ref:
                    candidates.add(ref)
    # Tagged SQL retains a deliberately narrow, explicit WHERE id = ${ref}.
    if R.text(arguments).startswith('`'):
        for part in scope.kind('template_substitution'):
            if not R.contains(arguments, part):
                continue
            match = re.fullmatch(r'\$\{\s*([^{}]+?)\s*\}', R.text(part))
            prefix = scope.raw[arguments['start']:part['start']]
            reference = _reference(match[1]) if match else None
            if reference and re.search(r'\bWHERE\b[^`]*\b(?:[\w]+\.)?(?:id|[\w]+_id)\s*=\s*$', prefix, re.I):
                candidates.add(reference)
    return {value for ref in candidates if (value := _canonical(scope, ref, effect['start'])) is not None}


def _awaited(scope, call):
    return scope.direct(call) and any(n['kind'] == 'await_expression' and R.contains(n, call) for n in scope.nodes)


def _shadowed(scope, name, until):
    params = R.identifiers(R.text(scope.function, 'parameters') or R.text(scope.function, 'parameter')) if scope.function else set()
    return (name in params
            or any(R.text(n, 'name').strip() == name and n['start'] < until for n in scope.bindings)
            or not scope.unchanged(name, scope.body['start'], until))


def _helper_contract(raw, facts, function, record_guards=()):
    params = _parameters(function)
    if not params:
        return None
    scope = R.Scope(raw, facts, function)
    reads = [n for n in scope.calls if _DATABASE_READ.fullmatch(R.name(n))
             or (R.name(n) in ('sql', 'tx') and re.match(r'`\s*SELECT\b', R.text(n, 'arguments'), re.I))]
    # A single explicit read is the supported contract, not a helper graph.
    if len(reads) != 1 or not _awaited(scope, reads[0]):
        return None
    read = reads[0]; row = scope.binding(read)
    if not row or not _IDENTIFIER.fullmatch(row):
        return None
    ids = _operation_ids(scope, read) & set(params)
    if len(ids) != 1:
        return None
    identifier = next(iter(ids))
    for guard in scope.calls:
        if R.name(guard) not in record_guards or not _awaited(scope, guard) or guard['start'] <= read['end']:
            continue
        if _shadowed(scope, R.name(guard), guard['start']) or not scope.unchanged(row, read['end'], guard['start']):
            continue
        args = _split(R.text(guard, 'arguments'))
        principal = _reference(args[0]) if args and len(args) == 4 else None
        if principal is None or principal.split('.')[0] not in params:
            continue
        principal_name = principal.split('.')[0]
        if not scope.unchanged(principal_name, scope.body['start'], guard['start']):
            continue
        # The row belongs to the declared guard's fourth context argument, not an
        # unrelated record-looking object in another argument.
        raw_args = R.text(guard, 'arguments')
        tail = raw_args[:-1].rstrip().removesuffix(',').rstrip()
        context = dict(start=R.field(guard, 'arguments')['start'] + len(tail) - len(args[3]),
                       end=R.field(guard, 'arguments')['start'] + len(tail))
        # A context spread or duplicate row slot may replace the guarded row.
        record = [n for n in R.direct_pairs(scope,context)
                  if _ROW_KEY.fullmatch(R.text(n, 'key').strip().strip('"\''))]
        named_row = len(record) == 1 and _reference(R.text(record[0], 'value')) == row
        # The facts vocabulary has no shorthand-property node. Recognize only
        # this complete single-property object from the existing AST argument.
        shorthand = re.fullmatch(r'\{\s*([A-Za-z_$][\w$]*)\s*,?\s*\}', args[3])
        shorthand_row = bool(shorthand and _ROW_KEY.fullmatch(shorthand[1]) and shorthand[1] == row)
        if (not (named_row or shorthand_row)
                or any(R.contains(context,n) for n in scope.kind('spread_element'))):
            continue
        # An early return, mutable escape or caught/conditional guard cannot
        # establish an enforcing sequence. Throwing before it remains safe.
        if any(n['start'] < guard['end'] for n in scope.kind('return_statement')):
            continue
        if any(read['end'] < n['start'] < guard['start'] and row in R.identifiers(R.text(n))
               and not R.contains(guard, n) for n in scope.calls):
            continue
        return dict(id_parameter=params.index(identifier), principal_parameter=params.index(principal_name))
    return None


def _normalize_relative(path):
    pieces = []
    for part in path.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            if not pieces:
                return None
            pieces.pop()
        else:
            pieces.append(part)
    return '/'.join(pieces)


def _resolve(file, specifier, snapshot):
    if specifier.startswith(('./', '../')):
        stem = _normalize_relative(str(PurePosixPath(file).parent) + '/' + specifier)
    elif specifier.startswith('$lib/'):
        components = file.split('/')
        positions = [i for i, part in enumerate(components[:-1]) if part == 'src']
        if not positions:
            return None
        stem = '/'.join(components[:positions[-1]+1] + ['lib', specifier[5:]])
        stem = _normalize_relative(stem)
    else:
        return None
    if not stem:
        return None
    suffix = PurePosixPath(stem).suffix
    possibilities = [stem] if suffix else [stem+ext for ext in _EXTENSIONS] + [stem+'/index'+ext for ext in _EXTENSIONS]
    # TS source may intentionally import its emitted .js name. Ambiguity fails.
    if suffix in ('.js', '.mjs', '.cjs'):
        possibilities.append(stem[:-len(suffix)] + {'.js':'.ts','.mjs':'.mts','.cjs':'.cts'}[suffix])
    found = [p for p in possibilities if p in snapshot]
    return found[0] if len(found) == 1 else None


def _imports(facts):
    result = {}
    for node in facts:
        if node['kind'] != 'import_statement':
            continue
        match = re.fullmatch(r'\s*import\s*\{([^{}]+)\}\s*from\s*(["\'])([^"\'\n]+)\2\s*;?\s*', R.text(node))
        if not match:
            continue
        for part in match[1].split(','):
            item = re.fullmatch(r'\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*', part)
            if item:
                result.setdefault(item[2] or item[1], []).append((match[3], item[1]))
    return result


def _definitions(facts):
    functions = [n for n in facts if n['kind'] in R.FUNCTIONS]
    result = {}
    for function in functions:
        if any(n is not function and R.contains(n, function) for n in functions) or any(
                n['kind'] in R.BRANCHES and R.contains(n,function) for n in facts):
            continue
        name = R.text(function, 'name').strip()
        if not name:
            bindings = [n for n in facts if n['kind'] == 'variable_declarator' and R.contains(R.field(n, 'value'), function)]
            if len(bindings) == 1:
                name = R.text(bindings[0], 'name').strip()
        if _IDENTIFIER.fullmatch(name):
            result.setdefault(name, []).append(function)
    return result


class ScopeHelperIndex:
    def __init__(self, snapshot, records, record_guards=()):
        self.snapshot = dict(snapshot)
        self.files = {}
        for file, raw in self.snapshot.items():
            record = records.get(file, {})
            if (record.get('status') != 'PARSED' or record.get('source_sha256') != hashlib.sha256(raw.encode()).hexdigest()):
                continue
            facts = record.get('facts', [])
            if not isinstance(facts, list) or any(not isinstance(n, dict) or not isinstance(n.get('start'), int)
                    or not isinstance(n.get('end'), int) or not 0 <= n['start'] <= n['end'] <= len(raw)
                    or n.get('text') != raw[n['start']:n['end']]
                    or type(n.get('captures',{})) is not dict
                    or any(type(c) is not dict or type(c.get('start')) is not int or type(c.get('end')) is not int
                           or not n['start'] <= c['start'] <= c['end'] <= n['end']
                           or c.get('text') != raw[c['start']:c['end']] for c in n.get('captures',{}).values())
                    for n in facts):
                continue
            self.files[file] = dict(facts=facts, definitions=_definitions(facts), imports=_imports(facts))
        self.contracts = {}
        for file, data in self.files.items():
            for name, definitions in data['definitions'].items():
                if len(definitions) == 1 and not self._mutated(file,name) and not any(self._mutated(file, guard) for guard in record_guards):
                    contract = _helper_contract(self.snapshot[file], data['facts'], definitions[0], record_guards)
                    if contract:
                        exported = any(n['kind'] == 'export_statement' and R.contains(n, definitions[0]) for n in data['facts'])
                        self.contracts[(file,name)] = dict(contract,exported=exported)

    def _mutated(self, file, name):
        return any(n['kind'] in ('assignment_expression','augmented_assignment_expression','update_expression')
                   and name in R.identifiers(R.text(n,'left') or R.text(n,'argument'))
                   for n in self.files[file]['facts'])

    def guard_reason(self, file, scope, effect):
        if file not in self.files or scope.raw != self.snapshot[file] or not R.contains(scope.body, effect):
            return None
        ids = _operation_ids(scope, effect)
        ids = {identifier for identifier in ids if _REQUEST_REF.fullmatch(identifier)}
        if len(ids) != 1:
            return None
        requested = next(iter(ids))
        for call in scope.calls:
            name = R.name(call)
            if not _IDENTIFIER.fullmatch(name) or not scope.before(call,effect) or not _awaited(scope,call) or _shadowed(scope,name,call['start']):
                continue
            if self._mutated(file,name):
                continue
            data = self.files[file]; definitions = data['definitions'].get(name,[]); imports = data['imports'].get(name,[])
            imported = False
            if len(definitions) == 1 and not imports:
                contract = self.contracts.get((file,name))
            elif len(imports) == 1 and not definitions:
                target = _resolve(file,imports[0][0],self.snapshot)
                contract = self.contracts.get((target,imports[0][1]))
                if contract and not contract['exported']:
                    contract = None
                imported = True
            else:
                continue
            args = _split(R.text(call,'arguments'))
            if not contract or args is None or max(contract['id_parameter'],contract['principal_parameter']) >= len(args):
                continue
            actual_id = _canonical(scope,args[contract['id_parameter']],effect['start'])
            principal = _canonical(scope,args[contract['principal_parameter']],effect['start'])
            if actual_id != requested or principal is None or not _PRINCIPAL_REF.fullmatch(principal):
                continue
            return 'imported_same_id_row_guard_candidate' if imported else 'local_same_id_row_guard_candidate'
        return None


def build(snapshot, records, record_guards=()):
    """Build an index from the supplied snapshot and adapter result['files']."""
    return ScopeHelperIndex(dict(snapshot), records, record_guards)
