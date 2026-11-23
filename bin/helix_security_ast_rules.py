"""Local security relations over ast-grep facts, never target-code execution.

This is deliberately not a control-flow or interprocedural proof. A recognized
guard is a local candidate and each omitted signal retains an explanation.
"""
import re


FUNCTIONS = {'function_declaration', 'function_expression', 'arrow_function',
             'method_definition', 'generator_function_declaration', 'generator_function'}
BRANCHES = {'if_statement', 'switch_statement', 'for_statement', 'for_in_statement',
            'while_statement', 'do_statement', 'try_statement', 'catch_clause',
            'ternary_expression', 'conditional_expression', 'binary_expression'}
TARGET_RULES = {'SEC-AUTH', 'SEC-IDOR', 'SEC-OTP', 'SEC-UPLOAD', 'SEC-MASS'}
REQUEST = re.compile(r'\b(?:params|query|body|searchParams)\s*[.\[]|\b(?:request|req)\.(?:json|body|query|params)\b')
PRINCIPAL_SCOPE = re.compile(r'\b(?:owner_id|ownerId|tenant_id|tenantId|org_id|organizationId|user_id|userId)\b\s*(?:=|:|IN\s*\()[^;\n]*(?:locals\.|session\.|user\.|actor\.|principal\.|request\.user|req\.user)', re.I)


def field(node, key):
    value = node.get('captures', {}).get(key)
    return value if isinstance(value, dict) else {}


def text(node, key=None):
    return (field(node, key) if key else node).get('text', '')


def contains(outer, inner):
    return outer.get('start', -1) <= inner.get('start', -2) and inner.get('end', -2) <= outer.get('end', -1)


def name(node):
    return text(node, 'function').strip()


def identifiers(value):
    return set(re.findall(r'\b[A-Za-z_$][\w$]*\b', value))


class Scope:
    def __init__(self, raw, facts, function=None, program=None, *, record_guards=(), identity_guards=()):
        self.raw, self.function = raw, function
        self.record_guards, self.identity_guards = frozenset(record_guards), frozenset(identity_guards)
        unit = (function or program or {}).get('unit')
        facts = [n for n in facts if n.get('unit') == unit] if unit is not None else facts
        self.facts = facts
        self.body = field(function, 'body') if function else program or {'start': 0, 'end': len(raw), 'text': raw}
        if not self.body:
            self.body = function
        self.functions = [n for n in facts if n['kind'] in FUNCTIONS]
        self.nodes = [n for n in facts if contains(self.body, n) and not any(
            fn is not function and contains(self.body, fn) and contains(fn, n)
            for fn in self.functions)]
        self.calls = self.kind('call_expression')
        self.bindings = self.kind('variable_declarator')

    def kind(self, *kinds):
        return [n for n in self.nodes if n['kind'] in kinds]

    def direct(self, node):
        """Only a top-level sequence; optional branches never bless a later sink."""
        return not any(n is not node and n['kind'] in BRANCHES and contains(n, node)
                       for n in self.nodes)

    def before(self, guard, effect):
        return guard['end'] <= effect['start'] and self.direct(guard)

    def aliases(self, initial):
        values = set(initial)
        for _ in range(len(self.bindings) + 1):
            extra = {text(n, 'name').strip() for n in self.bindings
                     if re.sub(r'\s+as\s+[\w$.<> ,\[\]|]+$', '', text(n, 'value').strip()) in values
                     and re.fullmatch(r'[\w$]+', text(n, 'name').strip())}
            if extra <= values:
                break
            values |= extra
        return values

    def unchanged(self, symbol, start, end):
        return not any(start < n['start'] < end and symbol in identifiers(text(n, 'left') or text(n, 'argument'))
                       for n in self.kind('assignment_expression', 'augmented_assignment_expression', 'update_expression'))

    def shadows(self, symbol):
        parameters = (text(self.function, 'parameters') or text(self.function, 'parameter')) if self.function else ''
        return symbol in identifiers(parameters) or any(
            symbol in identifiers(text(n, 'name')) for n in self.bindings) or any(
            symbol == text(n, 'left').strip() for n in self.kind('assignment_expression'))

    def binding(self, effect):
        enclosing = [n for n in self.bindings if contains(field(n, 'value'), effect)]
        if not enclosing:
            return None
        target = min(enclosing, key=lambda n: n['end'] - n['start'])
        value = text(target, 'name').strip()
        match = re.fullmatch(r'(?:\[\s*)?([\w$]+)(?:\s*\])?', value)
        return match[1] if match else None

    def denying_branches(self, before):
        result = []
        for branch in self.kind('if_statement'):
            if not self.before(branch, before):
                continue
            consequence = field(branch, 'consequence')
            exits = [n for n in self.kind('throw_statement', 'return_statement') if contains(consequence, n)]
            # A nested conditional exit is not an unconditional rejection.
            if any(not any(other is not branch and other['kind'] in BRANCHES
                           and contains(consequence, other) and contains(other, exit_node)
                           for other in self.nodes) for exit_node in exits):
                result.append(branch)
        return result

    def request_bound(self, effect):
        arguments = field(effect, 'arguments')
        def refs(capture):
            value = text(capture).strip()
            values = {value} if re.fullmatch(r'[\w$]+(?:\.[\w$]+)*', value) else set()
            for node in self.nodes:
                if not contains(capture, node):
                    continue
                if node['kind'] in {'member_expression', 'subscript_expression'}:
                    values.add(text(node).strip())
                elif node['kind'] == 'pair':
                    candidate = text(node, 'value').strip()
                    if re.fullmatch(r'[\w$]+(?:\.[\w$]+)*', candidate):
                        values.add(candidate)
                elif node['kind'] == 'template_substitution':
                    candidate = text(node)[2:-1].strip()
                    if re.fullmatch(r'[\w$]+(?:\.[\w$]+)*', candidate):
                        values.add(candidate)
            return values
        references = refs(arguments)
        if any(REQUEST.search(value) for value in references):
            return True
        aliases = set()
        for _ in range(len(self.bindings) + 1):
            old = set(aliases)
            for n in self.bindings:
                if n['start'] >= effect['start']:
                    continue
                source = text(n, 'value')
                binding_refs = refs(field(n, 'value'))
                if any(REQUEST.search(value) for value in binding_refs) or (source.strip() in {'params', 'query', 'body'}):
                    aliases |= identifiers(text(n, 'name'))
                elif any(value.split('.')[0] in aliases for value in binding_refs):
                    aliases |= identifiers(text(n, 'name'))
            if old == aliases:
                break
        return any(value.split('.')[0] in aliases and self.unchanged(value.split('.')[0], self.body['start'], effect['start']) for value in references)


def direct_pairs(scope, object_capture):
    objects = [node for node in scope.kind('object') if contains(object_capture, node)]
    return [pair for pair in scope.kind('pair') if contains(object_capture, pair)
            and not any(node['start'] > object_capture.get('start', -1) and contains(node, pair) for node in objects)]


def operation_where_pairs(scope, effect):
    arguments = field(effect, 'arguments')
    objects = [node for node in scope.kind('object') if contains(arguments, node)]
    if not objects:
        return []
    first = min(objects, key=lambda node: (node['start'], -node['end']))
    return [pair for pair in direct_pairs(scope, first) if text(pair, 'key').strip() == 'where']


def signal(code, node, why):
    return {'id': code, 'offset': node['start'], 'why': why,
            'evidence_kind': 'ast_local_relation', 'confidence': 'possible'}


def _crypto(scope, call):
    fn = name(call)
    if not fn.endswith('.update'):
        return False
    receiver = fn[:-7].strip()
    if scope.shadows('createHash') or scope.shadows('crypto'):
        return False
    if re.fullmatch(r'(?:crypto\.)?createHash\([\s\S]*\)', receiver):
        return True
    for binding in scope.bindings:
        if (text(binding, 'name').strip() == receiver and binding['end'] < call['start']
                and re.fullmatch(r'(?:crypto\.)?createHash\([\s\S]*\)', text(binding, 'value').strip())
                and scope.unchanged(receiver, binding['end'], call['start'])):
            return True
    return False


def mass(scope):
    rows = []
    for call in scope.calls:
        request_value = any(contains(field(call, 'arguments'), node) and
                            ((node['kind'] == 'member_expression' and text(node).strip() in {'req.body', 'request.body'})
                             or (node['kind'] == 'spread_element' and text(node, 'argument').strip() in {'body', 'data'}))
                            for node in scope.kind('member_expression', 'spread_element'))
        if (re.search(r'\.(?:update|create|insert|assign)$', name(call))
                and request_value
                and not _crypto(scope, call)):
            rows.append(signal('SEC-MASS', call, 'Rzeczywiste wywołanie zapisu otrzymuje body lub szeroki spread; brak rozpoznanej allowlisty pól.'))
    return rows


def upload(scope):
    rows, omitted = [], []
    forms = [n for n in scope.calls if name(n).endswith('.formData') or name(n).split('.')[-1] in {'upload', 'multipart'}]
    if not forms:
        return rows, omitted
    files = set()
    for call in scope.calls:
        if name(call).endswith('.arrayBuffer'):
            files.add(name(call).rsplit('.', 1)[0])
    for binary in scope.kind('binary_expression'):
        if re.search(r'\binstanceof\s+File\b', text(binary)):
            files.add(text(binary, 'left').strip())
    for sink in scope.calls:
        if name(sink).split('.')[-1] not in {'writeFile', 'writeFileSync', 'createWriteStream', 'upload', 'putObject', 'put', 'send'}:
            continue
        sink_files = set(files & identifiers(text(sink, 'arguments')))
        for symbol in files:
            buffers = set()
            for binding in sorted(scope.bindings, key=lambda n: n['start']):
                variable = text(binding, 'name').strip()
                if not re.fullmatch(r'[\w$]+', variable) or binding['end'] >= sink['start']:
                    continue
                conversions = [call for call in scope.calls if contains(field(binding, 'value'), call)
                               and name(call) == symbol + '.arrayBuffer']
                if (conversions or text(binding, 'value').strip() in buffers) and scope.unchanged(variable, binding['end'], sink['start']):
                    buffers.add(variable)
            if buffers & identifiers(text(sink, 'arguments')):
                sink_files.add(symbol)
        for symbol in sorted(sink_files):
            size, mime = False, False
            for branch in scope.denying_branches(sink):
                condition = text(branch, 'condition')
                if not scope.unchanged(symbol, branch['start'], sink['start']):
                    continue
                # Conjunctions, optional branches and unrelated boolean terms
                # cannot turn the observation into an enforcing rejection.
                condition = condition.strip()
                if condition.startswith('(') and condition.endswith(')'):
                    condition = condition[1:-1].strip()
                size |= bool(re.fullmatch(re.escape(symbol) + r'\.size\s*(?:>|>=)\s*(?:\d+|[A-Za-z_$][\w$]*)', condition))
                mime |= bool(re.fullmatch(r'!\s*[\w$.]+\.includes\(\s*' + re.escape(symbol) + r'\.(?:type|mimetype)\s*\)', condition)
                             or re.fullmatch(re.escape(symbol) + r'\.(?:type|mimetype)\s*!==?\s*[\"\'][^\"\']+[\"\']', condition))
                for binding in scope.bindings:
                    probe = [n for n in scope.calls if contains(field(binding, 'value'), n)
                             and re.search(r'(?:sniff\w*|fileTypeFrom\w*|detect\w*(?:Type|Image))$', name(n), re.I)
                             and symbol in identifiers(text(n, 'arguments'))]
                    variable = text(binding, 'name').strip()
                    awaited = probe and any(n['kind'] == 'await_expression' and contains(n, probe[0]) for n in scope.nodes)
                    if (awaited and binding['end'] <= branch['start'] and re.fullmatch(r'\(?\s*!\s*' + re.escape(variable) + r'\s*\)?', condition.strip())
                            and scope.unchanged(variable, binding['end'], branch['start'])):
                        mime = True
            if not (size and mime):
                # Keep the original operation location, allowing exact benchmark comparisons.
                rows.append(signal('SEC-UPLOAD', forms[0], 'Zapis konkretnego pliku nie ma wcześniejszej odmowy dla jego rozmiaru lub typu; kontrola innego pliku nie chroni tego zapisu.'))
            else:
                omitted.append({'rule': 'SEC-UPLOAD', 'offset': sink['start'], 'reason': 'same_file_size_and_type_rejection_candidate'})
    return rows, omitted


def otp(scope):
    operations = []
    for node in scope.kind('binary_expression', 'variable_declarator', 'call_expression'):
        value = text(node)
        if not re.search(r'\b(?:pin|otp)\b', value, re.I):
            continue
        binary_code = any(re.fullmatch(r'(?:[\w$]+\.)*(?:pin|otp)(?:\.length)?', text(node, side).strip(), re.I) for side in ('left', 'right'))
        if ((node['kind'] == 'binary_expression' and binary_code and re.search(r'[!=]={1,2}|\.length\b', value))
                or (node['kind'] == 'variable_declarator' and text(node, 'name').lower() in {'pin', 'otp'}
                    and re.search(r'\b(?:Math\.random|random\.)', text(node, 'value')))
                or (node['kind'] == 'call_expression' and re.search(r'^(?:verify\w*|check\w*|compare\w*|timingSafeEqual|compare_digest)$', name(node)))):
            operations.append(node)
    if not operations:
        return []
    operation = min(operations, key=lambda n: n['start'])
    controls = []
    for branch in scope.denying_branches(operation):
        condition = field(branch, 'condition')
        if not re.search(r'&&|\|\||\?', text(condition)):
            controls.extend(name(n) for n in scope.calls if contains(condition, n))
    issues = []
    if not any(re.search(r'rateLimit|rate_limit|throttle', n, re.I) for n in controls):
        issues.append('brak wcześniejszego lokalnego limitu prób')
    if not any(re.search(r'lockout|maxAttempts|failed_attempts', n, re.I) for n in controls):
        issues.append('brak wcześniejszego lokalnego lockout')
    if any(n['kind'] == 'binary_expression' and re.search(r'[!=]={1,2}', text(n)) for n in operations):
        issues.append('zwykłe porównanie kodu')
    if any(re.search(r'\bMath\.random\b', text(n)) for n in scope.calls):
        issues.append('generator nieprzeznaczony do sekretów')
    return [signal('SEC-OTP', operation, '; '.join(issues) + '. Kontrole zewnętrzne wymagają weryfikacji.')] if issues else []


def _record_guard(scope, effect):
    args = text(effect, 'arguments')
    sql_where = re.search(r'\bWHERE\b([\s\S]*)', args, re.I) if args.startswith('`') else None
    # ORM write payload is not a filter. Only a principal field inside the
    # operation's own `where` object can establish this candidate.
    wheres = operation_where_pairs(scope, effect)
    principal_pairs = [pair for where in wheres for pair in direct_pairs(scope, field(where, 'value'))
                       if text(pair, 'key').strip() in {'owner_id', 'ownerId', 'tenant_id', 'tenantId', 'org_id', 'organizationId', 'user_id', 'userId'}
                       and re.fullmatch(r'(?:locals|session|user|actor|principal|request\.user|req\.user)(?:\.[\w$]+)+', text(pair, 'value').strip())
                       ]
    if ((sql_where and not re.search(r'\bOR\b|--|/\*', sql_where[1], re.I) and PRINCIPAL_SCOPE.search(sql_where[1]))
            or principal_pairs and not any(re.search(r'\b(?:OR|NOT)\s*:', text(n, 'value')) for n in wheres)):
        return 'principal_scope_in_this_operation'
    row = scope.binding(effect)
    read = bool(re.search(r'\.(?:findUnique|findFirst|findMany|select|query|from)$', name(effect))
                or re.match(r'`\s*SELECT\b', text(effect, 'arguments'), re.I))
    for guard in scope.calls:
        if name(guard) not in scope.record_guards or scope.shadows(name(guard)) or not scope.direct(guard):
            continue
        awaited = any(n['kind'] == 'await_expression' and contains(n, guard) for n in scope.nodes)
        if not awaited:
            continue
        if not row or not scope.unchanged(row, effect['end'], guard['start']):
            continue
        # Reuse the bounded splitter of the one-hop helper contract. Import is
        # deferred because that module consumes Scope, never target modules.
        from helix_ast_scope_helpers import _split
        arguments = _split(text(guard, 'arguments'))
        if arguments is None or len(arguments) != 4:
            continue
        context = arguments[3]
        # An explicit row argument is only a local permission-helper candidate.
        if not re.search(r'\b(?:\w*Row|row|record|object|item|resource|entity|project)\s*:\s*' + re.escape(row) + r'\b', context):
            continue
        if guard['end'] <= effect['start']:
            return 'same_row_guard_before_operation'
        if read and effect['end'] < guard['start']:
            uses = [n for n in scope.kind('return_statement', 'call_expression')
                    if effect['end'] < n['start'] < guard['end'] and n is not guard
                    and row in identifiers(text(n)) and not contains(guard, n)]
            if not uses:
                return 'same_row_guard_before_exposure'
    return None


def idor(scope):
    rows, omitted = [], []
    tags = {'sql', 'tx'}
    tags = scope.aliases(tags)
    for effect in scope.calls:
        fn, args = name(effect), text(effect, 'arguments')
        database = bool(re.match(r'(?:db|prisma|supabase|pool)\b', fn)
                        and re.search(r'\.(?:findUnique|findFirst|findMany|select|update|delete|query|from)$', fn))
        tagged = fn in tags and bool(re.match(r'`\s*(?:SELECT|UPDATE|DELETE|INSERT)\b', args, re.I))
        if not (database or tagged) or not scope.request_bound(effect):
            continue
        reason = _record_guard(scope, effect)
        if reason:
            omitted.append({'rule': 'SEC-IDOR', 'offset': effect['start'], 'reason': reason})
        else:
            rows.append(signal('SEC-IDOR', effect, 'Ta operacja danych używa identyfikatora z żądania bez rozpoznanej kontroli zakresu tego samego rekordu przed efektem lub ujawnieniem.'))
    return rows, omitted


def _identity_denial(scope, boundary):
    for branch in scope.denying_branches(boundary):
        condition = text(branch, 'condition')
        condition = condition.strip().removeprefix('(').removesuffix(')').strip()
        if (re.fullmatch(r'(?:!\s*[\w$.]*(?:session|user)|[\w$.]*(?:session|user)\s*==={0,1}\s*(?:null|undefined))', condition)
                and re.search(r'\b(?:401|403)\b|\blogin\b|sign.?in', text(branch, 'consequence'), re.I)):
            return {'offset': branch['start'], 'reason': 'local_identity_rejection_candidate'}
    return None


def auth_candidate(scope):
    """A local candidate only; no production, row-scope or independent credit."""
    if scope.function is None:
        return None
    effects = [n for n in scope.calls if re.match(r'(?:db|prisma|supabase|pool)\b', name(n))
               or name(n) in {'sql', 'tx'}]
    boundary = min(effects, key=lambda n: n['start']) if effects else {'start': scope.body['end'], 'end': scope.body['end']}
    denial = _identity_denial(scope, boundary)
    if denial:
        return denial
    for call in scope.calls:
        if (name(call) in (scope.identity_guards | scope.record_guards)
                and not scope.shadows(name(call)) and scope.before(call, boundary)):
            # A promise that is ignored cannot establish an enforcing sequence.
            if name(call) in scope.record_guards and not any(n['kind'] == 'await_expression' and contains(n, call) for n in scope.nodes):
                continue
            return {'offset': call['start'], 'reason': 'configured_permission_helper_candidate'}
        definitions = [fn for fn in scope.functions if fn is not scope.function and text(fn, 'name') == name(call)]
        if len(definitions) != 1 or scope.shadows(name(call)) or not scope.before(call, boundary):
            continue
        definition = definitions[0]
        arguments = text(call, 'arguments').strip().removeprefix('(').removesuffix(')').strip()
        parameters = identifiers(text(scope.function, 'parameters') or text(scope.function, 'parameter'))
        if not re.fullmatch(r'[\w$]+', arguments) or arguments not in parameters:
            continue
        if re.match(r'async\b', text(definition)) and not any(n['kind'] == 'await_expression' and contains(n, call) for n in scope.nodes):
            continue
        helper = Scope(scope.raw, scope.facts, definition)
        # A helper with early returns/calls before its check stays unresolved.
        checks = helper.kind('if_statement')
        if len(checks) != 1:
            continue
        prefix = scope.raw[helper.body['start']:checks[0]['start']].strip()
        if prefix not in ('', '{'):
            continue
        if _identity_denial(helper, {'start': helper.body['end'], 'end': helper.body['end']}):
            return {'offset': call['start'], 'reason': 'local_defined_identity_helper_candidate'}
    return None


def analyze_file(file, raw, record, *, record_guards=(), identity_guards=()):
    """Return private offsets and safe reasons; caller constructs public findings."""
    if record.get('status') != 'PARSED':
        return {'signals': [], 'omissions': [], 'scopes': [], 'status': 'UNSUPPORTED'}
    facts = record['facts']
    functions = [node for node in facts if node['kind'] in FUNCTIONS]
    programs = [node for node in facts if node['kind'] == 'program']
    scopes = [Scope(raw, facts, program=program, record_guards=record_guards, identity_guards=identity_guards) for program in programs] + [Scope(raw, facts, function, record_guards=record_guards, identity_guards=identity_guards) for function in functions]
    signals, omissions = [], []
    for scope in scopes:
        signals.extend(mass(scope))
        signals.extend(otp(scope))
        upload_rows, upload_omissions = upload(scope)
        signals.extend(upload_rows); omissions.extend(upload_omissions)
        idor_rows, idor_omissions = idor(scope)
        signals.extend(idor_rows); omissions.extend(idor_omissions)
    unique = {(row['id'], row['offset']): row for row in signals}
    return {'signals': sorted(unique.values(), key=lambda r: (r['offset'], r['id'])),
            'omissions': omissions, 'scopes': scopes, 'status': 'ANALYZED'}
