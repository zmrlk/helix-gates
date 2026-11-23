"""Closed local-send catalogue and pure evidence projection. No delivery credit."""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from helix_runtime_integrations import _validate_plan as validate_inventory

CATALOG_VERSION = 1
from helix_runtime_registry import load_registry
_REGISTRY=load_registry()
PROVIDERS=tuple(_REGISTRY['legacy_providers'])
SYNTHETIC_DOMAINS = ('helix-mail.invalid',)
COUNTS = ('parts', 'providers', 'captured_local', 'rejected_local',
          'external_deliveries_verified', 'application_routes_verified')


OPERATIONS = tuple(_REGISTRY['legacy_operations'])
OPERATIONS_BY_ID = {row['id']: row for row in OPERATIONS}
REASONS = frozenset(('NOT_STARTED', 'SOURCE_SNAPSHOT_INCOMPLETE', 'INTEGRATION_SCOPE_UNRESOLVED',
    'STRATEGY_DISABLED', 'STRATEGY_UNSUPPORTED', 'APPLICATION_CONFIGURATION_NOT_PROVEN',
    'RECIPIENT_DNS_NOT_PROVEN', 'SYNTHETIC_SUBSCRIPTION_NOT_PROVEN', 'NO_CAPTURE_OBSERVED',
    'SINK_START_FAILED', 'SINK_UNAVAILABLE', 'SINK_WRITE_FAILED', 'SINK_INPUT_INVALID',
    'REQUEST_REJECTED', 'LIMIT_EXCEEDED', 'DEADLINE_EXCEEDED', 'INTERRUPTED', 'CLEANUP_UNKNOWN',
    'UNSUPPORTED_TRANSPORT', 'OBSERVATIONS_UNAVAILABLE', 'OBSERVATIONS_INVALID'))
OBSERVATION_FIELDS = {'sequence', 'operation_id', 'provider', 'http_status', 'outcome'}
BINDING_FIELDS = {'run_id', 'plan_id', 'integration_plan_id', 'part', 'attempt_id'}


def _error():
    raise ValueError('runtime sinks: invalid or unbound evidence') from None


def _require(condition):
    if not condition: _error()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _path(value):
    return (isinstance(value, str) and 0 < len(value) <= 500 and not any(c in value for c in '\\:?\x00\r\n')
            and not value.startswith('/') and '..' not in PurePosixPath(value).parts
            and PurePosixPath(value).as_posix() == value)


def _declaration(entry):
    _require(entry['provider'] in PROVIDERS and type(entry.get('parts')) is list
             and all(_path(part) for part in entry['parts']) and len(entry['parts']) == len(set(entry['parts'])))
    _require(isinstance(entry['id'], str) and re.fullmatch(re.escape(entry['provider'])+r':[0-9a-f]{12}', entry['id'])
             and entry['strategy']['selected'] in ('container','http-sink','record-replay','disable','emulator','replay','disabled',None))
    evidence = entry.get('evidence'); versions = entry.get('declared_versions'); names = entry.get('env_names')
    _require(type(evidence) is list and type(versions) is list and type(names) is list)
    for item in evidence:
        _require(type(item) is dict and set(item) == {'path', 'line', 'kind', 'area'}
                 and _path(item['path']) and type(item['line']) is int and item['line'] > 0
                 and isinstance(item['kind'], str) and re.fullmatch(r'[a-zA-Z_]+', item['kind'])
                 and item['area'] == entry['area'])
    _require(all(isinstance(v, str) and re.fullmatch(r'[~^<>= v\d.*|+-]{1,80}', v) for v in versions)
             and all(isinstance(n, str) and re.fullmatch(r'[A-Z][A-Z0-9_]*', n) for n in names))
    return dict(integration_id=entry['id'], provider=entry['provider'], area=entry['area'],
                parts=copy.deepcopy(entry['parts']), evidence=copy.deepcopy(evidence),
                declared_versions=copy.deepcopy(versions), env_names=copy.deepcopy(names),
                strategy=entry['strategy']['selected'])


def sink_plan(integrations, parts=None):
    """Use the existing inventory, retaining inactive and unresolved scopes."""
    try:
        validate_inventory(integrations)
        declarations = [_declaration(row) for row in integrations['integrations'] if row['provider'] in PROVIDERS]
        if parts is None: roots = sorted({p for row in declarations for p in row['parts']})
        else:
            _require(type(parts) is list)
            roots = [item.get('path', item.get('name')) if type(item) is dict else item for item in parts]
            _require(all(_path(p) for p in roots) and len(roots) == len(set(roots)))
            roots = sorted(roots)
        _require(all(set(row['parts']).issubset(roots) for row in declarations))
        active = [row for row in declarations if row['area'] == 'active']
        excluded = [row for row in declarations if row['area'] != 'active']
        unscoped = [row for row in active if not row['parts']]
        gaps = ['INTEGRATION_SCOPE_UNRESOLVED'] if unscoped else []
        discovery = integrations.get('discovery', {})
        if not discovery.get('files') or discovery.get('errors'): gaps.append('SOURCE_SNAPSHOT_INCOMPLETE')
        rows = []
        for part in roots:
            providers = [row for row in active if part in row['parts']]
            if not providers: continue
            local_gaps = ['APPLICATION_CONFIGURATION_NOT_PROVEN']
            names = {row['provider'] for row in providers}
            if 'resend' in names: local_gaps.append('RECIPIENT_DNS_NOT_PROVEN')
            if 'web-push' in names: local_gaps.append('SYNTHETIC_SUBSCRIPTION_NOT_PROVEN')
            if any(row['strategy'] == 'disabled' for row in providers): local_gaps.append('STRATEGY_DISABLED')
            if any(row['strategy'] not in ('disabled', 'emulator') for row in providers): local_gaps.append('STRATEGY_UNSUPPORTED')
            enabled = {row['provider'] for row in providers if row['strategy'] == 'emulator'}
            rows.append(dict(part=part, status='PLANNED' if enabled else 'BLOCKED', providers=providers,
                             operation_ids=[op['id'] for op in OPERATIONS if op['provider'] in enabled], gaps=sorted(local_gaps)))
        plan = dict(schema_version=1, kind='runtime-sink-plan', catalog_version=CATALOG_VERSION,
                    catalog_hash=_digest(OPERATIONS), integration_plan_id=integrations['plan_id'],
                    roots=roots, status='BLOCKED' if gaps or any(row['status']=='BLOCKED' for row in rows) else 'PLANNED' if rows else 'NOT_DETECTED',
                    parts=rows, excluded_declarations=excluded, unscoped_declarations=unscoped,
                    gaps=sorted(gaps), external_delivery='NOT_RUN')
        plan['plan_id'] = _digest(plan)
        return plan
    except (KeyError, TypeError, ValueError, AttributeError, UnicodeError): _error()


def _binding(value):
    _require(type(value) is dict and set(value) == BINDING_FIELDS)
    _require(isinstance(value['run_id'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}', value['run_id'])
             and _path(value['part']) and isinstance(value['attempt_id'], str)
             and re.fullmatch(r'sink-[0-9a-f]{32}', value['attempt_id']))
    _require(all(isinstance(value[k], str) and re.fullmatch(r'[0-9a-f]{64}', value[k]) for k in ('plan_id', 'integration_plan_id')))


def _private_plan(plan):
    fields = {'schema_version','kind','catalog_version','catalog_hash','integration_plan_id','roots','status',
              'parts','excluded_declarations','unscoped_declarations','gaps','external_delivery','plan_id'}
    _require(type(plan) is dict and set(plan) == fields and type(plan['schema_version']) is int
             and plan['schema_version'] == 1 and plan['kind'] == 'runtime-sink-plan'
             and type(plan['catalog_version']) is int and plan['catalog_version'] == CATALOG_VERSION
             and plan['catalog_hash'] == _digest(OPERATIONS) and plan['external_delivery'] == 'NOT_RUN'
             and plan['plan_id'] == _digest({k:v for k,v in plan.items() if k != 'plan_id'}))
    _require(type(plan['roots']) is list and all(_path(root) for root in plan['roots'])
             and plan['roots'] == sorted(set(plan['roots'])) and type(plan['parts']) is list)
    seen = set()
    for row in plan['parts']:
        _require(type(row) is dict and set(row) == {'part','status','providers','operation_ids','gaps'}
                 and row['part'] in plan['roots'] and row['part'] not in seen)
        seen.add(row['part']); _require(type(row['providers']) is list and bool(row['providers']))
        for declaration in row['providers']:
            _require(type(declaration) is dict and set(declaration) == {'integration_id','provider','area','parts','evidence','declared_versions','env_names','strategy'}
                     and declaration['area'] == 'active' and row['part'] in declaration['parts'])
            restored = dict(declaration, id=declaration['integration_id'], strategy={'selected':declaration['strategy']})
            _require(_declaration(restored) == declaration)
        enabled = {d['provider'] for d in row['providers'] if d['strategy'] == 'emulator'}
        _require(row['operation_ids'] == [op['id'] for op in OPERATIONS if op['provider'] in enabled]
                 and row['status'] == ('PLANNED' if enabled else 'BLOCKED'))


def build_sink_input(plan, *, run_id, part, attempt_id, origin, mailbox_path, bearer_token,
                     public_path, deadline_unix_ms, own_origins=(), synthetic_domains=SYNTHETIC_DOMAINS):
    """Private owned-process input. Paths/tokens are never projected publicly."""
    try:
        _private_plan(plan)
        selected = next((row for row in plan['parts'] if row['part'] == part), None)
        _require(selected is not None and selected['status'] == 'PLANNED' and selected['operation_ids'])
        binding = dict(run_id=run_id, plan_id=plan['plan_id'], integration_plan_id=plan['integration_plan_id'], part=part, attempt_id=attempt_id)
        _binding(binding)
        parsed = urlsplit(origin)
        _require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port is not None
                 and 1 <= parsed.port <= 65535 and origin == 'http://127.0.0.1:'+str(parsed.port))
        for path in (mailbox_path, public_path):
            _require(isinstance(path, str) and path.startswith('/') and '..' not in PurePosixPath(path).parts
                     and not any(c in path for c in '\x00\r\n') and str(PurePosixPath(path)) == path)
        _require(isinstance(bearer_token, str) and re.fullmatch(r'[0-9a-f]{64}', bearer_token)
                 and type(deadline_unix_ms) is int and 0 < deadline_unix_ms < 2**53)
        _require(type(synthetic_domains) in (tuple, list) and len(synthetic_domains) == len(set(synthetic_domains))
                 and set(synthetic_domains).issubset({'helix-mail.invalid', 'example.invalid'}))
        _require(type(own_origins) in (tuple, list) and len(own_origins) == len(set(own_origins)))
        for value in own_origins:
            local = urlsplit(value)
            _require(local.scheme in ('http', 'https') and local.hostname in ('127.0.0.1', 'localhost', '::1')
                     and not local.username and not local.password and local.path == '' and not local.query and not local.fragment
                     and local.port is not None and 1 <= local.port <= 65535)
        operations = [copy.deepcopy(OPERATIONS_BY_ID[ident]) for ident in selected['operation_ids']]
        return dict(schema_version=1, kind='runtime-sinks-input', binding=binding, catalog_version=CATALOG_VERSION,
                    catalog_hash=plan['catalog_hash'], operations=operations, providers=copy.deepcopy(selected['providers']),
                    origin=origin, mailbox_path=mailbox_path, public_path=public_path, bearer_token=bearer_token,
                    deadline_unix_ms=deadline_unix_ms, own_origins=list(own_origins), synthetic_domains=list(synthetic_domains),
                    webpush_endpoint=origin+'/web-push/helix-synthetic',
                    limits=dict(max_body_bytes=1048576, max_requests=1000), external_delivery='NOT_RUN')
    except (KeyError, TypeError, ValueError, AttributeError, UnicodeError): _error()


def _snapshot(value, plan, selected, run_id):
    _require(type(value) is dict and set(value) == {'schema_version','binding','status','cleanup','observations','gaps'}
             and type(value['schema_version']) is int and value['schema_version'] == 1)
    binding = value['binding']; _binding(binding)
    _require(binding['run_id'] == run_id and binding['part'] == selected['part']
             and binding['plan_id'] == plan['plan_id'] and binding['integration_plan_id'] == plan['integration_plan_id'])
    _require(value['status'] in ('not_run','ready','closed','blocked','partial')
             and value['cleanup'] in ('not_needed','closed','unknown'))
    _require(type(value['gaps']) is list and len(value['gaps']) == len(set(value['gaps']))
             and all(reason in REASONS for reason in value['gaps']))
    observations = value['observations']; _require(type(observations) is list and len(observations) <= 1000)
    for index, row in enumerate(observations, 1):
        _require(type(row) is dict and set(row) == OBSERVATION_FIELDS
                 and type(row['sequence']) is int and row['sequence'] == index
                 and row['operation_id'] in selected['operation_ids'])
        operation = OPERATIONS_BY_ID[row['operation_id']]
        _require(row['provider'] == operation['provider'] and type(row['http_status']) is int
                 and row['outcome'] in ('captured_local','rejected_local'))
        _require(row['http_status'] == operation['response_status'] if row['outcome'] == 'captured_local'
                 else 400 <= row['http_status'] <= 599)
    _require(not observations or value['status'] != 'not_run')
    _require(value['status'] != 'not_run' or value['cleanup'] == 'not_needed')
    _require(value['status'] != 'closed' or value['cleanup'] == 'closed')
    return copy.deepcopy(value)


def project_sinks(report, parts=None):
    """Validate all observations before scoping; never grant routes or delivery."""
    try:
        _require(type(report) is dict)
        result = dict(schema_version=1, plan_status='NOT_RECORDED', execution_status='NOT_RECORDED',
                      coverage_status='NOT_RECORDED', plan_id=None, counts={k:None for k in COUNTS},
                      external_delivery='NOT_RECORDED', parts=[], gaps=[], excluded_declarations=[], unscoped_declarations=[])
        if 'sink_plan' not in report and 'sink_observations' not in report: return result
        plan = report['sink_plan']; _require(type(plan) is dict)
        expected = sink_plan(report['integrations'], plan['roots'])
        _require(_digest(plan) == _digest(expected) and type(report.get('sink_observations')) is list)
        selected = {row['part']: row for row in plan['parts']}; snapshots = {}
        for snapshot in report['sink_observations']:
            name = snapshot['binding']['part']
            _require(name in selected and name not in snapshots)
            snapshots[name] = _snapshot(snapshot, plan, selected[name], report.get('run_id'))
        if parts is not None:
            _require(type(parts) is list and all(_path(p) for p in parts) and len(parts) == len(set(parts))
                     and set(parts).issubset(plan['roots']))
            selected = {name:row for name,row in selected.items() if name in parts}
        rows = []
        for name, declaration in selected.items():
            snapshot = snapshots.get(name); observations = snapshot['observations'] if snapshot else []
            status = snapshot['status'] if snapshot else 'not_run'; cleanup = snapshot['cleanup'] if snapshot else 'not_needed'
            gaps = sorted(set(declaration['gaps'] + (snapshot['gaps'] if snapshot else ['NOT_STARTED'])))
            if cleanup == 'unknown': gaps = sorted(set(gaps + ['CLEANUP_UNKNOWN']))
            execution = 'PARTIAL' if status in ('partial','blocked') or cleanup == 'unknown' else 'OBSERVED' if observations else 'READY' if status in ('ready','closed') else 'NOT_RUN'
            rows.append(dict(part=name, plan_status=declaration['status'], execution_status=execution,
                             readiness=status, cleanup=cleanup, providers=copy.deepcopy(declaration['providers']),
                             observations=observations, gaps=gaps))
        status = 'BLOCKED' if plan['gaps'] or any(row['plan_status']=='BLOCKED' for row in rows) else 'PLANNED' if rows else 'NOT_DETECTED'
        observations = [observation for row in rows for observation in row['observations']]
        execution = 'PARTIAL' if any(row['execution_status'] == 'PARTIAL' for row in rows) else 'OBSERVED' if observations else 'READY' if any(row['execution_status'] == 'READY' for row in rows) else 'NOT_RUN'
        result.update(plan_status=status, execution_status=execution, coverage_status='NOT_DETECTED' if status == 'NOT_DETECTED' else 'INCOMPLETE',
                      plan_id=plan['plan_id'], external_delivery='NOT_RUN', parts=rows, gaps=copy.deepcopy(plan['gaps']),
                      excluded_declarations=copy.deepcopy(plan['excluded_declarations']), unscoped_declarations=copy.deepcopy(plan['unscoped_declarations']),
                      counts=dict(parts=len(rows), providers=sum(len(row['providers']) for row in rows),
                          captured_local=sum(row['outcome'] == 'captured_local' and OPERATIONS_BY_ID[row['operation_id']]['effect'] == 'capture' for row in observations),
                          rejected_local=sum(row['outcome'] == 'rejected_local' for row in observations),
                          external_deliveries_verified=0, application_routes_verified=0))
        return result
    except (KeyError, TypeError, ValueError, AttributeError, UnicodeError): _error()
