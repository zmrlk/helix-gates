"""Framework scope selectors; unsupported/dynamic configuration stays unknown."""
import re
from pathlib import PurePosixPath


def route_path(file):
    path = re.sub(r'^.*?/(?:routes|app|pages)/|^(?:app|pages|routes)/', '/', file)
    if re.search(r'(?:^|/)server/(?:api|routes)/', file):
        path = re.sub(r'^.*?server/', '/', file)
        path = re.sub(r'^/routes/', '/', path)
    path = re.sub(r'/(?:\+server|\+page\.server|route|index)\.[^.]+$', '', path)
    path = re.sub(r'\.[^.]+$', '', path)
    path = re.sub(r'/\([^/]+\)', '', path)
    path = re.sub(r'\[\.\.\.(\w+)\]', r':\1*', path)
    path = re.sub(r'\[(\w+)\]', r':\1', path)
    return '/' + path.strip('/')


def matches(pattern, path):
    """Literal framework globs only. Regex/dynamic selectors never claim coverage."""
    if re.search(r'[(){}?\\]', pattern):
        return None
    expression = re.escape(pattern.rstrip('/'))
    # /staff/:path* includes /staff itself.
    expression = re.sub(r'/:\w+\\\*', '(?:/.*)?', expression)
    expression = re.sub(r':\w+', '[^/]+', expression)
    expression = expression.replace(r'\*', '.*')
    return bool(re.fullmatch(expression + '/?', path))


def boundary_scope(boundary, body, file, path, method):
    """True=applicable, False=excluded, None=unresolved. Never execution proof."""
    parent = str(PurePosixPath(boundary).parent)
    prefix = '' if parent == '.' else parent + '/'
    if re.search(r'hooks\.server\.[jt]s$', boundary):
        if not file.startswith(prefix + 'routes/') or not re.search(r'\bhandle\b', body):
            return False
        # Resolve literal SvelteKit route-id selectors, including route groups.
        if re.search(r'!\s*(?:event\.)?route\.id|route\.id[^;\n]*!==?', body):
            return None
        equalities = re.findall(r'(?:event\.)?route\.id\s*===?\s*["\']([^"\']+)["\']', body)
        if equalities:
            rid = '/' + file.split('/routes/', 1)[-1].rsplit('/', 1)[0]
            return rid in equalities
        selectors = re.findall(r'(?:event\.)?route\.id\??\.(?:startsWith|includes)\(["\']([^"\']+)["\']\)', body)
        if selectors:
            rid = '/' + file.split('/routes/', 1)[-1].rsplit('/', 1)[0]
            return any(rid.startswith(s) if s.startswith('/') else s in rid for s in selectors)
        # Custom matchers are not guessed from their name.
        if re.search(r'\b(?:matches|matchers)\b', body):
            return None
        return True
    if re.search(r'\+layout\.server\.[jt]s$', boundary):
        # Svelte layouts do not protect endpoint requests/actions automatically.
        if not file.startswith(prefix) or not re.search(r'\+page\.server\.', file) or method != 'unknown':
            return False
        return None  # load may run independently; await parent is not guaranteed.
    if re.search(r'(?:^|/)middleware\.[jt]s$', boundary):
        if not (file.startswith(prefix + 'app/') or file.startswith(prefix + 'pages/') or file.startswith(prefix + 'src/app/') or file.startswith(prefix + 'src/pages/')):
            return False
        selector = re.search(r'\bmatcher\s*:\s*(\[[^\]]*\]|["\'][^"\']+["\'])', body)
        if not selector:
            return None if re.search(r'\bmatcher\b', body) else True
        patterns = re.findall(r'["\']([^"\']+)["\']', selector[1])
        results = [matches(p, path) for p in patterns]
        return True if True in results else None if None in results or not results else False
    if '/server/middleware/' in boundary or boundary.startswith('server/middleware/'):
        base = boundary.split('server/middleware/')[0]
        return file.startswith(base + 'server/')
    return False


def enrich(route, texts):
    """Retain explicit selector exclusions and provenance for the owner."""
    route['effective_guard'] = dict(status='unknown', evidence=[], excluded=[], unresolved=[])
    for file, body in texts.items():
        if file == route['file']:
            continue
        result = boundary_scope(file, body, route['file'], route['path'], route['method'])
        if result is None:
            route['effective_guard']['unresolved'].append(file + ':1')
        elif result is False and re.search(r'middleware|hooks\.server|\+layout\.server', file):
            route['effective_guard']['excluded'].append(file + ':1')


def supplemental(files, routes):
    """Small explicit registrations omitted by JS handler segmentation."""
    texts = dict(files)
    for file, body in files:
        if file.endswith('.md'):
            continue
        # Django function views: resolve only local views module, never import it.
        if file.endswith('urls.py'):
            parent = str(PurePosixPath(file).parent)
            view_file = ('' if parent == '.' else parent + '/') + 'views.py'
            views = texts.get(view_file, '')
            for match in re.finditer(r'\bpath\(\s*["\']([^"\']*)["\']\s*,\s*views\.(\w+)\b', body):
                function = re.search(r'(?m)^((?:@[^\n]+\n)*)(?:async\s+)?def\s+' + re.escape(match[2]) + r'\([^\n]*\):', views)
                if not function:
                    continue
                end = re.search(r'(?m)^(?:@|(?:async\s+)?def |class )', views[function.end():])
                stop = function.end() + end.start() if end else len(views)
                chunk = views[function.start():stop]
                routes.append(dict(file=view_file, line=views.count('\n', 0, function.start())+1,
                                   handler=match[2], path='/' + match[1].strip('/'), method='ALL',
                                   auth='unknown', required_role='unknown', _offset=function.start(), _chunk=chunk))
        # Fastify object registrations (URL/method literal only).
        for match in re.finditer(r'\b(?:fastify|server|app)\.route\(\s*\{', body):
            end = body.find('\n});', match.end())
            chunk = body[match.start():end+4 if end >= 0 else len(body)]
            url = re.search(r'\burl\s*:\s*["\']([^"\']+)["\']', chunk)
            method = re.search(r'\bmethod\s*:\s*["\'](GET|POST|PUT|PATCH|DELETE)["\']', chunk, re.I)
            if url and method:
                routes.append(dict(file=file, line=body.count('\n',0,match.start())+1, handler=match[0], path=url[1], method=method[1].upper(), auth='unknown', required_role='unknown', _offset=match.start(), _chunk=chunk))


def explicit_framework_candidates(file, text, route, offset):
    """Declarations establish candidates only: guard implementations can allow access."""
    evidence = []
    chunk = route.get('_chunk', '')
    for match in re.finditer(r'@(?:login_required|permission_required|UseGuards)\b|\bpreHandler\s*:|->middleware\s*\(|\bmiddleware\s*\(\s*["\']auth', chunk):
        evidence.append(f"{file}:{text.count(chr(10),0,offset+match.start())+1}")
    adjacent = re.search(r'(?:@\w+(?:\([^\n]*\))?\s*)+$', text[:offset])
    if adjacent and '@UseGuards' in adjacent[0]:
        evidence.append(f"{file}:{text.count(chr(10),0,adjacent.start())+1}")
    # Nest class-level guards belong only to this controller, not neighboring classes.
    prefix = text[:offset]
    class_start = list(re.finditer(r'\bclass\s+\w+', prefix))
    if class_start:
        previous_end = prefix.rfind('}', 0, class_start[-1].start())
        decorators = prefix[previous_end+1:class_start[-1].start()]
        if '@UseGuards' in decorators:
            evidence.append(f"{file}:{text.count(chr(10),0,previous_end+1)+1}")
    if file.endswith('.php'):
        # Enclosing Route middleware group; close before handler means no inheritance.
        for match in re.finditer(r'Route::middleware\([^;]*?\)->group\(\s*function[^{}]*\{', prefix):
            tail = prefix[match.end():]
            if tail.count('{') == tail.count('}'):
                evidence.append(f"{file}:{text.count(chr(10),0,match.start())+1}")
    return evidence


def handler_chunk(text, start, stop, registration):
    """Bound a literal handler registration, ignoring quoted delimiters."""
    segment = text[start:stop]
    # JS route registration ends at balanced call; exported handlers at body end.
    call = bool(re.match(r'\w+\.(?:get|post|put|patch|delete|all)\s*\(|Route::', registration))
    delimiter = '(' if call else '{'
    index = segment.find(delimiter) if call else body_start(segment)
    if index < 0:
        return segment
    stack = []; quote = None; escaped = False
    for i in range(index, len(segment)):
        char = segment[i]
        if quote:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'", '`'}:
            quote = char
        elif char in '({[':
            stack.append(char)
        elif char in ')}]':
            if not stack or stack[-1] != {')':'(', '}':'{', ']':'['}[char]:
                return segment  # malformed syntax remains uncertain
            stack.pop()
            if not stack:
                return segment[:i+1]
    return segment


def balanced_end(text, index):
    """Exclusive end of one balanced JS delimiter, ignoring strings/comments."""
    stack = []; quote = None; escaped = False; i = index
    while i < len(text):
        char = text[i]
        if quote:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == quote: quote = None
        elif text.startswith('//', i):
            end = text.find('\n', i)
            i = len(text) if end < 0 else end
            continue
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0: return None
            i = end + 2
            continue
        elif char in {'"', "'", '`'}: quote = char
        elif char in '({[': stack.append(char)
        elif char in ')}]':
            if not stack or stack[-1] != {')':'(', '}':'{', ']':'['}[char]: return None
            stack.pop()
            if not stack: return i + 1
        i += 1
    return None


def body_start(text):
    """Find a function body after parameters, not a destructuring/type brace.

    This is a lexical helper, not a JavaScript parser. Unknown shapes remain
    unbounded candidates and never establish proven protection.
    """
    function = re.match(r'(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+\w+\s*\(', text)
    if function:
        end = balanced_end(text, function.end() - 1)
        if end is None: return -1
        # Skip generic/union return types, including Promise<{id: string}>.
        i = end; angle = 0
        while i < len(text):
            char = text[i]
            if char == '<': angle += 1
            elif char == '>': angle = max(0, angle - 1)
            elif char == '{':
                if angle:
                    end_type = balanced_end(text, i)
                    if end_type is None: return -1
                    i = end_type; continue
                return i
            elif char == ';': return -1
            i += 1
        return -1
    # Typed const handlers commonly contain destructured arguments. The arrow
    # belongs after the balanced argument list, not after its first brace.
    assignment = re.match(r'(?:export\s+)?(?:const|let|var)\s+\w+(?:\s*:[^=;]+)?\s*=\s*(?:async\s*)?', text)
    if assignment:
        i = assignment.end()
        if i < len(text) and text[i] == '(':
            end = balanced_end(text, i)
            if end is None: return -1
            arrow = re.match(r'\s*(?::[^=;]+)?=>\s*', text[end:])
            if arrow:
                i = end + arrow.end()
                return i if text[i:i+1] == '{' else -1
        elif text[i:i+1] == '{':
            return i  # Svelte action maps and explicit registration objects.
        arrow = re.match(r'\w+\s*=>\s*', text[i:])
        if arrow:
            i += arrow.end()
            return i if text[i:i+1] == '{' else -1
    return text.find('{')


def nest_path(text, offset, path):
    """Nearest literal controller prefix; dynamic controller paths remain unresolved."""
    declarations = list(re.finditer(r'@Controller\(\s*["\']([^"\']*)["\']\s*\)[\s\S]*?\bclass\s+\w+\s*\{', text[:offset]))
    if not declarations:
        return path
    declaration = declarations[-1]
    tail = text[declaration.end():offset]
    if tail.count('}') > tail.count('{'):
        return path
    return '/' + '/'.join(part.strip('/') for part in (declaration[1], path) if part.strip('/'))
