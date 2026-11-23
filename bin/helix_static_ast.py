"""Private AST facts from a verified ast-grep installation and an in-memory snapshot.

Only ``result['public']`` is suitable for reports. Facts/captures deliberately
retain source text for the local detector; they must never be serialized there.
This is syntax evidence, not proof of authorization or production behavior.
"""
from __future__ import annotations

import bisect
from array import array
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import tempfile
import time

VERSION = '0.51.0'
RULES_PATH = Path(__file__).resolve().parents[1] / 'config/static-ast/facts.json'
FUNCTION_KINDS = frozenset(('function_declaration', 'function_expression', 'generator_function_declaration',
                            'generator_function', 'arrow_function', 'method_definition'))
MAX_OUTPUT = 64 * 1024 * 1024
BATCH_BYTES = 1024 * 1024
BATCH_FILES = 32
TIMEOUT = 30
_EXTENSIONS = {'.js': 'js', '.mjs': 'js', '.cjs': 'js', '.jsx': 'js',
               '.ts': 'ts', '.mts': 'ts', '.cts': 'ts', '.tsx': 'tsx'}
_RAW_REQUIRED = {'text', 'range', 'file', 'lines', 'charCount', 'language', 'ruleId', 'severity', 'note', 'message', 'labels'}


class ASTError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode('utf-8')).hexdigest()


def _digest(value):
    return _sha(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')))


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ASTError('DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ASTError('INVALID_JSON')))
    except (ValueError, TypeError, UnicodeError):
        raise ASTError('INVALID_JSON') from None


def _path(value):
    if (type(value) is not str or not value or value.startswith('/') or '\\' in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(p in ('', '.', '..') for p in value.split('/'))):
        raise ASTError('INVALID_SOURCE_PATH')
    return value


def _rules():
    raw = RULES_PATH.read_bytes()
    cfg = _json(raw)
    if cfg.get('schema_version') != 1 or cfg.get('engine_version') != VERSION:
        raise ASTError('RULES_INVALID')
    mapping, documents = {}, []
    for ext, language in cfg['languages'].items():
        nodes = dict(cfg['nodes'])
        if ext != 'js':
            nodes.update(cfg['typescript_nodes'])
        if ext == 'tsx':
            nodes.pop('type_assertion', None)
        for kind, fields in nodes.items():
            rule_id = f'hx-{ext}-{kind}'
            clauses = [{'kind': kind}]
            for field in fields:
                name = field.removeprefix('@')
                capture, exists = {'pattern': '$' + name.upper()}, {'regex': '.*'}
                if not field.startswith('@'):
                    capture['field'] = exists['field'] = field
                # Optional fields must not make an otherwise valid kind vanish.
                clauses.append({'any': [{'has': capture}, {'not': {'has': exists}}]})
            documents.append(dict(id=rule_id, language=language, rule={'all': clauses},
                                  severity='hint', message='Helix private AST fact'))
            mapping[rule_id] = dict(kind=kind, language=language, ext=ext,
                                    captures={f.removeprefix('@').upper() for f in fields})
    return '\n---\n'.join(json.dumps(d, separators=(',', ':')) for d in documents), mapping, _sha(raw)


def _svelte(text):
    # HTMLParser handles comments and quoted attributes without treating a fake
    # <script> inside either as executable source. Script bodies stay byte-for-
    # byte identical to the supplied snapshot and have independent scopes.
    line_starts = [0] + [m.end() for m in re.finditer('\\n', text)]

    class Scripts(HTMLParser):
        # HTML raw-text/RCDATA elements can contain a displayed <script>.
        # HTMLParser only defaults to script/style, so explicitly retain those
        # other bodies as text instead of inventing executable script units.
        CDATA_CONTENT_ELEMENTS = ('script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes')

        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.active = None
            self.units = []

        def source_offset(self):
            line, column = self.getpos()
            return line_starts[line - 1] + column

        def handle_starttag(self, tag, attrs):
            if tag != 'script':
                return
            if self.active is not None:
                raise ASTError('SVELTE_SCRIPT_UNRESOLVED')
            values = {}
            for name, value in attrs:
                if name in values or name not in ('lang', 'context', 'module', 'type'):
                    raise ASTError('SVELTE_SCRIPT_UNRESOLVED')
                values[name] = value
            if (values.get('lang', 'js') not in ('js', 'javascript', 'ts', 'typescript')
                    or values.get('context', 'module') != 'module'
                    or values.get('type', 'text/javascript') not in ('text/javascript', 'application/javascript')
                    or ('module' in values and values['module'] is not None)):
                raise ASTError('SVELTE_SCRIPT_UNRESOLVED')
            mode = 'module' if 'context' in values or 'module' in values else 'instance'
            if mode in [u['scope'] for u in self.units]:
                raise ASTError('SVELTE_SCRIPT_UNRESOLVED')
            self.active = dict(offset=self.source_offset() + len(self.get_starttag_text()),
                               ext='ts' if values.get('lang') in ('ts', 'typescript') else 'js', scope=mode)

        def handle_endtag(self, tag):
            if tag == 'script':
                if self.active is None:
                    raise ASTError('SVELTE_SCRIPT_UNRESOLVED')
                self.active['text'] = text[self.active['offset']:self.source_offset()]
                self.units.append(self.active)
                self.active = None

        def handle_startendtag(self, tag, attrs):
            if tag == 'script':
                raise ASTError('SVELTE_SCRIPT_UNRESOLVED')

    parser = Scripts()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        raise ASTError('SVELTE_SCRIPT_UNRESOLVED') from None
    if parser.active is not None:
        raise ASTError('SVELTE_SCRIPT_UNRESOLVED')
    if not parser.units:
        raise ASTError('SVELTE_NO_SCRIPT')
    return parser.units


class Executor:
    """No target cwd, inherited configuration, stdin, shell or network operation."""
    def run(self, argv, *, cwd, env, timeout, max_output_bytes):
        started = time.monotonic()
        process = None
        with tempfile.TemporaryFile(dir=cwd) as stdout, tempfile.TemporaryFile(dir=cwd) as stderr:
            try:
                process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, close_fds=True, pass_fds=(), start_new_session=True)
                while process.poll() is None:
                    if time.monotonic() - started > timeout:
                        raise ASTError('AST_TIMEOUT')
                    if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > max_output_bytes:
                        raise ASTError('AST_OUTPUT_LIMIT')
                    time.sleep(0.02)
                if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > max_output_bytes:
                    raise ASTError('AST_OUTPUT_LIMIT')
                stdout.seek(0); stderr.seek(0)
                return subprocess.CompletedProcess(argv, process.returncode, stdout.read(), stderr.read())
            finally:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()


def _index(text):
    offsets, total = array('Q', [0]), 0
    for character in text:
        total += len(character.encode('utf-8'))
        offsets.append(total)
    return dict(bytes=offsets, lines=[0] + [m.end() for m in re.finditer('\\n', text)])


def _character(index, byte):
    position = bisect.bisect_left(index['bytes'], byte)
    if position >= len(index['bytes']) or index['bytes'][position] != byte:
        raise ASTError('INVALID_RANGE')
    return position


def _range(record, unit, offsets):
    if type(record) is not dict or set(record) != {'byteOffset', 'start', 'end'}:
        raise ASTError('INVALID_RANGE')
    br = record['byteOffset']
    if type(br) is not dict or set(br) != {'start', 'end'} or any(type(br[k]) is not int for k in br):
        raise ASTError('INVALID_RANGE')
    if br['end'] < br['start']:
        raise ASTError('INVALID_RANGE')
    start, end = _character(offsets, br['start']), _character(offsets, br['end'])
    for key, position in (('start', start), ('end', end)):
        point = record[key]
        if (type(point) is not dict or set(point) != {'line', 'column'}
                or any(type(point[k]) is not int or point[k] < 0 for k in point)
                or point['line'] != bisect.bisect_right(offsets['lines'], position) - 1):
            raise ASTError('INVALID_RANGE')
    return start, end


def normalize_matches(raw, *, units, rule_map):
    """Normalize only exact synthetic filenames/rules and ranges in the snapshot.

    Returns private per-unit facts, not public report data. UTF-8 byte ranges
    from ast-grep are converted to Python string offsets exactly once.
    """
    records = _json(raw)
    if type(records) is not list:
        raise ASTError('INVALID_AST_OUTPUT')
    result = {name: [] for name in units}
    indexes = {name: _index(u['text']) for name, u in units.items()}
    seen = set()
    for row in records:
        if (type(row) is not dict or not _RAW_REQUIRED <= set(row)
                or set(row) - _RAW_REQUIRED - {'metaVariables'}):
            raise ASTError('INVALID_AST_OUTPUT')
        filename, rule_id = row['file'], row['ruleId']
        if type(filename) is not str or filename not in units or type(rule_id) is not str or rule_id not in rule_map:
            raise ASTError('FOREIGN_AST_OUTPUT')
        unit, spec = units[filename], rule_map[rule_id]
        if (unit['ext'] != spec['ext'] or row['language'] != spec['language']
                or row['severity'] != 'hint' or row['message'] != 'Helix private AST fact'
                or row['note'] is not None or type(row['lines']) is not str
                or type(row['charCount']) is not dict or type(row['labels']) is not list):
            raise ASTError('INVALID_AST_OUTPUT')
        start, end = _range(row['range'], unit, indexes[filename])
        if type(row['text']) is not str or row['text'] != unit['text'][start:end]:
            raise ASTError('AST_TEXT_MISMATCH')
        key = (filename, rule_id, start, end)
        if key in seen:
            raise ASTError('DUPLICATE_AST_FACT')
        seen.add(key)
        captures = {}
        variables = row.get('metaVariables', {'single': {}, 'multi': {}, 'transformed': {}})
        if (type(variables) is not dict or set(variables) != {'single', 'multi', 'transformed'}
                or type(variables['single']) is not dict or type(variables['multi']) is not dict
                or variables['transformed'] != {} or set(variables['multi']) - {'secondary'}):
            raise ASTError('INVALID_CAPTURE')
        for name, value in variables['single'].items():
            if name not in spec['captures'] or type(value) is not dict or set(value) != {'text', 'range'}:
                raise ASTError('INVALID_CAPTURE')
            a, b = _range(value['range'], unit, indexes[filename])
            if not start <= a <= b <= end or value['text'] != unit['text'][a:b]:
                raise ASTError('INVALID_CAPTURE')
            captures[name.lower()] = dict(text=value['text'], start=a + unit['offset'], end=b + unit['offset'])
        absolute_start, absolute_end = start + unit['offset'], end + unit['offset']
        identifier = _digest([unit['path'], unit['source_sha256'], unit['scope'], spec['kind'], absolute_start, absolute_end])
        result[filename].append(dict(id=identifier, kind=spec['kind'], start=absolute_start, end=absolute_end,
             text=row['text'], captures=captures, owner_function=None, parent_id=None, unit=unit['scope'],
             line=unit.get('line_offset', unit['source'].count('\n', 0, unit['offset'])) + bisect.bisect_right(indexes[filename]['lines'], start)))
    for filename, facts in result.items():
        unit = units[filename]
        programs = [f for f in facts if f['kind'] == 'program']
        if len(programs) != 1:
            raise ASTError('PROGRAM_RECEIPT_MISSING')
        before = programs[0]['start'] - unit['offset']
        after = programs[0]['end'] - unit['offset']
        if unit['text'][:before].strip() or unit['text'][after:].strip():
            raise ASTError('PROGRAM_RECEIPT_MISSING')
        # Range nesting is syntax only. Never infer execution or dominance here.
        stack = []
        for fact in sorted(facts, key=lambda f: (f['start'], -f['end'], f['kind'] != 'program', f['kind'])):
            while stack and not (stack[-1]['start'] <= fact['start'] and fact['end'] <= stack[-1]['end']):
                stack.pop()
            parents = [f for f in stack if (f['start'], f['end']) != (fact['start'], fact['end'])]
            if parents:
                fact['parent_id'] = parents[-1]['id']
            owners = [f for f in parents if f['kind'] in FUNCTION_KINDS]
            if owners:
                fact['owner_function'] = owners[-1]['id']
            stack.append(fact)
        facts.sort(key=lambda f: (f['start'], f['end'], f['kind']))
    return result


def _installation(installation):
    if (type(installation) is not dict or installation.get('tool') != 'ast-grep'
            or installation.get('version') != VERSION or installation.get('usable') is not True
            or installation.get('proof_kind') != 'subprocess' or installation.get('smoke_status') != 'PASS'
            or type(installation.get('argv_prefix')) is not list or not installation['argv_prefix']
            or any(type(a) is not str or not Path(a).is_absolute() for a in installation['argv_prefix'])):
        raise ASTError('AST_NOT_AVAILABLE')
    # Resolver has already verified receipt and installed bytes; only its digest
    # is public. Avoid keeping absolute installation paths in reports.
    receipt = installation.get('receipt')
    if type(receipt) is not str:
        raise ASTError('AST_NOT_AVAILABLE')
    import helix_tools_manager
    return _sha(helix_tools_manager._read(Path(receipt)))


def analyze_snapshot(files, *, installation=None, executor=None):
    """Use the supplied source snapshot; never open or execute target files.

    ``executor`` is a trusted Python injection point for deterministic tests,
    never read from project configuration. Production resolves only managed
    ast-grep 0.51.0; no PATH fallback, installation or network lookup.
    """
    snapshot = {}
    for name, text in files.items() if isinstance(files, dict) else files:
        name = _path(name)
        if name in snapshot or type(text) is not str:
            raise ASTError('INVALID_SOURCE_SNAPSHOT')
        try:
            text.encode('utf-8')
        except UnicodeError:
            raise ASTError('INVALID_SOURCE_SNAPSHOT') from None
        snapshot[name] = text
    rules, rule_map, rules_hash = _rules()
    sources = {name: dict(status='UNSUPPORTED', facts=[], gaps=[], source_sha256=_sha(text)) for name, text in snapshot.items()}
    unit_list = []
    for name, text in sorted(snapshot.items()):
        ext = _EXTENSIONS.get(PurePosixPath(name).suffix.lower())
        try:
            if ext:
                extracted = [dict(text=text, offset=0, ext=ext, scope='file')]
            elif name.lower().endswith('.svelte'):
                extracted = _svelte(text)
                sources[name]['gaps'].append({'code': 'SVELTE_MARKUP_NOT_ANALYZED'})
            else:
                sources[name]['gaps'].append({'code': 'LANGUAGE_UNSUPPORTED'})
                continue
        except ASTError as exc:
            sources[name]['gaps'].append({'code': exc.code})
            continue
        for unit in extracted:
            unit.update(path=name, source=text, source_sha256=_sha(text), line_offset=text.count('\n', 0, unit['offset']))
            unit_list.append(unit)
        sources[name]['status'] = 'PENDING'
    public = dict(schema_version=1, engine=dict(name='ast-grep', version=VERSION, receipt_sha256=None, used=False, proof_kind='not_run'),
                  rules_sha256=rules_hash, source_digest=_digest({n: _sha(t) for n, t in sorted(snapshot.items())}),
                  coverage={}, usage=dict(calls=0, input_bytes=0), limitations=['syntax_and_local_relations_only', 'missing_nodes_not_exposed'])
    failure = None
    if not unit_list:
        failure = 'NO_SUPPORTED_SOURCES'
    else:
        try:
            if installation is None:
                from helix_tools_manager import resolve_installed
                installation = resolve_installed('ast-grep')
            public['engine']['receipt_sha256'] = _installation(installation)
        except (ASTError, OSError, ValueError, TypeError):
            failure = 'AST_NOT_AVAILABLE'
    if failure:
        for row in sources.values():
            if row['status'] == 'PENDING':
                row['status'] = 'UNAVAILABLE'
                row['gaps'].append({'code': failure})
    else:
        runner = executor or Executor()
        with tempfile.TemporaryDirectory(prefix='helix-static-ast-') as directory:
            tmp = Path(directory).resolve()
            os.chmod(tmp, 0o700)
            for sub in ('home', 'tmp'):
                (tmp / sub).mkdir(mode=0o700)
            (tmp / 'rules.yml').write_text(rules, encoding='utf-8')
            (tmp / 'config.yml').write_text('ruleDirs: []\n', encoding='utf-8')
            for name in ('rules.yml', 'config.yml'):
                (tmp / name).chmod(0o600)
            environment = {'HOME': str(tmp/'home'), 'XDG_CONFIG_HOME': str(tmp/'home'), 'XDG_CACHE_HOME': str(tmp/'home'),
                           'TMPDIR': str(tmp/'tmp'), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'NO_COLOR': '1'}
            batches, batch, size = [], [], 0
            for unit in unit_list:
                length = len(unit['text'].encode('utf-8'))
                if batch and (len(batch) >= BATCH_FILES or size + length > BATCH_BYTES):
                    batches.append(batch); batch, size = [], 0
                batch.append(unit); size += length
            if batch:
                batches.append(batch)
            for batch in batches:
                units = {f'input-{i}.{u["ext"]}': u for i, u in enumerate(batch)}
                for name, unit in units.items():
                    (tmp/name).write_bytes(unit['text'].encode('utf-8'))
                    (tmp/name).chmod(0o600)
                argv = installation['argv_prefix'] + ['scan', '--rule', 'rules.yml', '--config', 'config.yml',
                         '--custom-languages', 'ignore', '--json=compact', '--color', 'never', '--threads', '1']
                for ignore in ('hidden', 'dot', 'exclude', 'global', 'parent', 'vcs'):
                    argv += ['--no-ignore', ignore]
                argv += list(units)
                public['usage']['calls'] += 1
                public['usage']['input_bytes'] += sum(len(u['text'].encode('utf-8')) for u in batch)
                public['engine'].update(used=True, proof_kind='subprocess' if executor is None else 'synthetic_test')
                try:
                    completed = runner.run(argv, cwd=str(tmp), env=environment, timeout=TIMEOUT, max_output_bytes=MAX_OUTPUT)
                    if completed.returncode != 0:
                        raise ASTError('AST_PROCESS_FAILED')
                    raw = completed.stdout
                    if not isinstance(raw, (str, bytes)) or len(raw.encode() if isinstance(raw, str) else raw) > MAX_OUTPUT:
                        raise ASTError('AST_OUTPUT_LIMIT')
                    normalized = normalize_matches(raw, units=units, rule_map=rule_map)
                    for name, facts in normalized.items():
                        entry = sources[units[name]['path']]
                        if entry['status'] != 'ERROR':
                            entry['facts'].extend(facts)
                            entry['status'] = 'PARTIAL' if any(f['kind'] == 'ERROR' for f in entry['facts']) else 'PARSED'
                        if any(f['kind'] == 'ERROR' for f in facts):
                            entry['gaps'].append({'code': 'AST_ERROR_NODE'})
                except (ASTError, OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
                    code = exc.code if isinstance(exc, ASTError) else 'AST_TIMEOUT' if isinstance(exc, subprocess.TimeoutExpired) else 'AST_PROCESS_FAILED'
                    for unit in batch:
                        entry = sources[unit['path']]
                        entry['status'] = 'ERROR'
                        entry['facts'] = []
                        entry['gaps'].append({'code': code})
                finally:
                    for name in units:
                        (tmp/name).unlink(missing_ok=True)
    for entry in sources.values():
        if entry['status'] in ('PARSED', 'PARTIAL'):
            entry['gaps'].append({'code': 'MISSING_NODES_NOT_EXPOSED'})
        entry['parser_completeness'] = 'PARTIAL' if entry['status'] == 'PARSED' else 'UNKNOWN'
        entry['gaps'] = [dict(code=c) for c in sorted({g['code'] for g in entry['gaps']})]
    public['coverage'] = dict(status='INCOMPLETE', files_total=len(sources),
        files_parsed=sum(r['status'] == 'PARSED' for r in sources.values()),
        files_partial=sum(r['status'] == 'PARTIAL' for r in sources.values()),
        files=[dict(path=n, source_sha256=r['source_sha256'], status=r['status'], parser_completeness=r['parser_completeness'],
                    facts_count=len(r['facts']), gaps=r['gaps']) for n, r in sorted(sources.items())],
        gaps=[{'code': 'EMPTY_SNAPSHOT'}] if not sources else [])
    return {'files': sources, 'public': public}
