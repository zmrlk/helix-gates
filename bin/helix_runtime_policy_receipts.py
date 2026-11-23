"""Pure projection of explicit identity policy plans, without execution credit.

Version one deliberately accepts no execution receipts. A future executor needs
a separate evidence contract; a configured expectation is never a passed test.
"""
import copy
import hashlib
import json
import re


GAPS = frozenset(('POLICY_NOT_CONFIGURED', 'PART_NOT_DECLARED', 'IDENTITY_PLAN_MISSING',
    'IDENTITY_PLAN_BLOCKED', 'ROLE_NOT_DECLARED', 'SESSION_IDENTITY_ASSERTION_MISSING',
    'SESSION_ROLES_ASSERTION_MISSING'))
EXECUTION = dict(files_opened=0, commands=0, models=0, network=0, application=False)
PLAN_FIELDS = {'schema_version', 'kind', 'plan_id', 'source_digest', 'identity_plan_digest',
               'status', 'parts', 'execution'}
PART_FIELDS = {'part', 'identity_plan_id', 'policy_hash', 'status', 'config_pointer',
               'session', 'cells', 'gaps', 'unconfigured_identities'}
CELL_FIELDS = {'id', 'config_id', 'config_pointer', 'identity_id', 'identity_selector',
               'role', 'request', 'anonymous', 'expected', 'status', 'gaps'}


def _require(condition):
    if not condition:
        raise ValueError('identity policy plan: invalid or inconsistent public declaration')


def _digest(value):
    try:
        return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                        separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    except (TypeError, ValueError, OverflowError):
        raise ValueError('identity policy plan: invalid public declaration') from None


def _fields(value, keys):
    _require(type(value) is dict and set(value) == set(keys))


def _text(value, maximum=500):
    return (isinstance(value, str) and 0 < len(value) <= maximum and
            re.search(r'[\x00-\x1f\x7f]', value) is None)


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def _part(value):
    return (_text(value) and not value.startswith('/') and not re.search(r'[\\:?%]', value) and
            (value == '.' or all(piece not in ('', '.', '..') for piece in value.split('/'))))


def _path(value):
    return (_text(value) and value.startswith('/') and not value.startswith('//') and
            '//' not in value[1:] and
            not re.search(r'[\\%*?#${}\s]', value) and
            not any(piece in ('.', '..') for piece in value.split('/')))


def _pointer(value):
    if not _text(value, 1000) or not value.startswith('/') or re.search(r'[*]|~(?![01])', value):
        return False
    return all(piece.replace('~1', '/').replace('~0', '~') not in ('', '__proto__', 'prototype', 'constructor')
               for piece in value.split('/')[1:])


def _identity(value):
    return isinstance(value, str) and re.fullmatch(r'role-[a-f0-9]{12}|no-app-role|unverified-email', value) is not None


def _config_pointer(value):
    return value is None or (_pointer(value) and value.startswith('/runtime/identity_policy/parts/'))


def _gaps(rows):
    _require(type(rows) is list)
    seen = set()
    for row in rows:
        _fields(row, {'code', 'config_pointer'})
        _require(isinstance(row['code'], str) and row['code'] in GAPS and _config_pointer(row['config_pointer']))
        key = (row['code'], row['config_pointer'])
        _require(key not in seen)
        seen.add(key)
    return {row['code'] for row in rows}


def _denial(value):
    _fields(value, {'kind', 'codes'})
    _require(value['kind'] == 'status' and type(value['codes']) is list and bool(value['codes']))
    _require(all(type(code) is int and code in (401, 403) for code in value['codes']))
    _require(len(set(value['codes'])) == len(value['codes']))


def _session(value):
    _fields(value, {'path', 'method', 'http_status', 'anonymous', 'assertions'})
    _require(_path(value['path']) and value['method'] == 'GET' and type(value['http_status']) is int and value['http_status'] == 200)
    _denial(value['anonymous'])
    _require(type(value['assertions']) is list and bool(value['assertions']))
    pointers, fields = set(), set()
    for row in value['assertions']:
        _require(type(row) is dict)
        field = row.get('equals_identity')
        _require(isinstance(field, str) and field in ('username', 'email', 'email_verified', 'app_roles'))
        _fields(row, {'pointer', 'equals_identity', 'comparison'} if field == 'app_roles' else {'pointer', 'equals_identity'})
        _require(_pointer(row['pointer']) and row['pointer'] not in pointers)
        if field == 'app_roles':
            _require(row['comparison'] == 'set_exact')
        pointers.add(row['pointer']); fields.add(field)
    missing = set()
    if not fields.intersection(('username', 'email')):
        missing.add('SESSION_IDENTITY_ASSERTION_MISSING')
    if 'app_roles' not in fields:
        missing.add('SESSION_ROLES_ASSERTION_MISSING')
    return missing


def _expected(value):
    _require(type(value) is dict)
    if value.get('access') == 'deny':
        _fields(value, {'access', 'denial'})
        _denial(value['denial'])
        return
    _fields(value, {'access', 'http_status', 'json'})
    _require(value['access'] == 'allow' and type(value['http_status']) is int and value['http_status'] == 200)
    _require(type(value['json']) is list and bool(value['json']))
    pointers = set()
    for row in value['json']:
        _fields(row, {'pointer', 'kind', 'value_hash'})
        _require(_pointer(row['pointer']) and row['pointer'] not in pointers and row['kind'] == 'literal' and _hash(row['value_hash']))
        pointers.add(row['pointer'])


def validate_policy_plan(plan):
    """Validate hashes, public-only fields and planning semantics; never execute."""
    _fields(plan, PLAN_FIELDS)
    _require(type(plan['schema_version']) is int and plan['schema_version'] == 1 and plan['kind'] == 'identity-policy-plan')
    _require(all(_hash(plan[key]) for key in ('plan_id', 'source_digest', 'identity_plan_digest')))
    _fields(plan['execution'], EXECUTION)
    _require(all(type(plan['execution'][key]) is type(value) and plan['execution'][key] == value for key, value in EXECUTION.items()))
    _require(type(plan['parts']) is list)
    parts = set()
    for part in plan['parts']:
        _fields(part, PART_FIELDS)
        name = part['part']
        _require(_part(name) and name not in parts)
        parts.add(name)
        _require(part['identity_plan_id'] is None or _hash(part['identity_plan_id']))
        _require(part['policy_hash'] is None or _hash(part['policy_hash']))
        _require(_config_pointer(part['config_pointer']) and type(part['cells']) is list)
        codes = _gaps(part['gaps'])
        _require(type(part['unconfigured_identities']) is list and all(_identity(item) for item in part['unconfigured_identities']))
        _require(len(set(part['unconfigured_identities'])) == len(part['unconfigured_identities']))
        if part['policy_hash'] is None:
            _require(part['status'] == 'NOT_CONFIGURED' and part['config_pointer'] is None and part['session'] is None and
                     not part['cells'] and 'POLICY_NOT_CONFIGURED' in codes)
            continue
        pointer = '/runtime/identity_policy/parts/' + name.replace('~', '~0').replace('/', '~1')
        _require(part['config_pointer'] == pointer and 'POLICY_NOT_CONFIGURED' not in codes and bool(part['cells']))
        _require(_session(part['session']).issubset(codes))
        if part['identity_plan_id'] is None:
            _require('IDENTITY_PLAN_MISSING' in codes)
        ids, config_ids, selected, requests = set(), set(), set(), set()
        for index, cell in enumerate(part['cells']):
            _fields(cell, CELL_FIELDS)
            _require(isinstance(cell['id'], str) and re.fullmatch(r'cell-[a-f0-9]{16}', cell['id']) is not None and cell['id'] not in ids)
            _require(_text(cell['config_id'], 100) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}', cell['config_id']) is not None and cell['config_id'] not in config_ids)
            _require(cell['config_pointer'] == pointer + '/cells/' + str(index))
            _fields(cell['identity_selector'], {'role_sha256'})
            _require(_hash(cell['identity_selector']['role_sha256']))
            _fields(cell['request'], {'path', 'method'})
            _require(_path(cell['request']['path']) and cell['request']['method'] == 'GET')
            request_key = (cell['identity_selector']['role_sha256'], cell['request']['method'], cell['request']['path'])
            _require(request_key not in requests)
            requests.add(request_key)
            _denial(cell['anonymous']); _expected(cell['expected'])
            cell_codes = _gaps(cell['gaps'])
            if cell['identity_id'] is None:
                _require(cell['role'] is None and bool(cell_codes) and cell['status'] == 'BLOCKED')
            else:
                _require(isinstance(cell['identity_id'], str) and re.fullmatch(r'role-[a-f0-9]{12}', cell['identity_id']) is not None)
                _require(_text(cell['role'], 100) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}', cell['role']) is not None)
                _require(_digest(cell['role']) == cell['identity_selector']['role_sha256'] and cell['identity_id'] == 'role-' + _digest(cell['role'])[:12])
                _require(cell['status'] == ('BLOCKED' if cell_codes else 'READY'))
                selected.add(cell['identity_id'])
            payload = {key: cell[key] for key in ('identity_selector', 'identity_id', 'role', 'request', 'anonymous', 'expected')}
            _require(cell['id'] == 'cell-' + _digest(dict(part=name, **payload))[:16])
            ids.add(cell['id']); config_ids.add(cell['config_id'])
        _require(not selected.intersection(part['unconfigured_identities']))
        _require(part['status'] == ('BLOCKED' if codes or any(cell['status'] == 'BLOCKED' for cell in part['cells']) else 'PLANNED'))
    expected = ('NOT_DETECTED' if not plan['parts'] else 'NOT_CONFIGURED' if all(part['status'] == 'NOT_CONFIGURED' for part in plan['parts'])
                else 'BLOCKED' if any(part['status'] != 'PLANNED' for part in plan['parts']) else 'PLANNED')
    _require(plan['status'] == expected)
    _require(plan['plan_id'] == _digest({key: value for key, value in plan.items() if key != 'plan_id'}))
    return None


def _bind_identities(plan, declaration):
    """A matching top hash does not establish membership of individual roles."""
    _require(type(declaration) is dict and type(declaration.get('schema_version')) is int and
             declaration['schema_version'] == 1 and type(declaration.get('parts')) is list)
    _require(plan['identity_plan_digest'] == _digest(declaration))
    known = {}
    for part in declaration['parts']:
        _require(type(part) is dict and _part(part.get('part')) and part['part'] not in known and
                 part.get('provider') == 'keycloak' and part.get('status') in ('READY', 'BLOCKED') and
                 type(part.get('identities')) is list and _hash(part.get('plan_id')))
        _require(part['plan_id'] == _digest({key: value for key, value in part.items() if key != 'plan_id'}))
        identities = {}
        for account in part['identities']:
            _require(type(account) is dict and _identity(account.get('id')) and account['id'] not in identities)
            roles = account.get('app_roles')
            _require(type(roles) is list)
            if account['id'].startswith('role-'):
                _require(len(roles) == 1 and _text(roles[0], 100) and
                         re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}', roles[0]) is not None and
                         account['id'] == 'role-' + _digest(roles[0])[:12] and account.get('email_verified') is True)
            identities[account['id']] = account
        known[part['part']] = (part, identities)
    # Removing a whole declaration cannot turn an untested identity system into
    # NOT_DETECTED. Missing policy must remain an explicit NOT_CONFIGURED row.
    _require(set(known).issubset({part['part'] for part in plan['parts']}))
    for part in plan['parts']:
        bound, accounts = known.get(part['part'], (None, {}))
        _require(part['identity_plan_id'] == (bound['plan_id'] if bound else None))
        codes = {gap['code'] for gap in part['gaps']}
        if part['policy_hash'] is not None:
            if bound is None:
                _require('IDENTITY_PLAN_MISSING' in codes)
            elif bound['status'] != 'READY':
                _require('IDENTITY_PLAN_BLOCKED' in codes)
        selected = set()
        for cell in part['cells']:
            if cell['identity_id'] is None:
                continue
            account = accounts.get(cell['identity_id'])
            _require(bound is not None and bound['status'] == 'READY' and account is not None and
                     account['app_roles'] == [cell['role']] and account.get('email_verified') is True)
            selected.add(cell['identity_id'])
        _require(set(part['unconfigured_identities']) == set(accounts) - selected)


def project_policy_plan(report, parts=None):
    """Project a public planning matrix. Nonempty execution receipts are refused."""
    _require(type(report) is dict)
    result = dict(schema_version=1, scope='identity_policy_plan', plan_status='NOT_RECORDED',
                  execution_status='NOT_RECORDED', coverage_status='NOT_RECORDED', plan_id=None, source_digest=None,
                  identity_plan_digest=None, counts=dict(parts=None, required_cells=None, ready_cells=None,
                                                       blocked_cells=None, not_run=None, executed=None), parts=[])
    if 'identity_policy_plan' not in report and 'identity_policy_receipts' not in report:
        return result
    _require('identity_policy_plan' in report and 'identity_policy_receipts' in report)
    receipts = report['identity_policy_receipts']
    if type(receipts) is not list or receipts:
        raise ValueError('identity policy plan: execution receipts are unsupported in this version')
    plan = report['identity_policy_plan']
    validate_policy_plan(plan)
    _require('identity_plan' in report)
    _bind_identities(plan, report['identity_plan'])
    selected = {part['part'] for part in plan['parts']}
    if parts is not None:
        _require(type(parts) is list and all(_part(part) for part in parts) and len(set(parts)) == len(parts))
        _require(type(report.get('parts', [])) is list)
        known = {part.get('path', part.get('name')) for part in report.get('parts', []) if isinstance(part, dict)}
        _require(all(_part(part) for part in known))
        _require(set(parts).issubset(selected | known))
        selected.intersection_update(parts)
    result.update({key: plan[key] for key in ('plan_id', 'source_digest', 'identity_plan_digest')})
    result['plan_status'] = plan['status']
    result.update(execution_status='NOT_RUN', coverage_status='NOT_RUN')
    for part in plan['parts']:
        if part['part'] not in selected:
            continue
        session = part['session']
        row = {key: copy.deepcopy(part[key]) for key in ('part', 'identity_plan_id', 'policy_hash', 'config_pointer', 'gaps', 'unconfigured_identities')}
        row.update(plan_status=part['status'], execution_status='NOT_RUN',
                   session=dict(configured=session is not None, path=session['path'] if session else None,
                                method=session['method'] if session else None,
                                assertion_count=len(session['assertions']) if session else 0,
                                execution_status='NOT_RUN'), cells=[])
        for cell in part['cells']:
            public = {key: copy.deepcopy(cell[key]) for key in ('id', 'config_id', 'identity_id', 'role', 'config_pointer', 'gaps')}
            public.update(plan_status=cell['status'], execution_status='NOT_RUN', method=cell['request']['method'],
                          path=cell['request']['path'], expected_access=cell['expected']['access'],
                          assertion_count=len(cell['expected'].get('json', [])))
            row['cells'].append(public)
        result['parts'].append(row)
    cells = [cell for part in result['parts'] for cell in part['cells']]
    result['counts'] = dict(parts=len(result['parts']), required_cells=len(cells),
                           ready_cells=sum(cell['plan_status'] == 'READY' for cell in cells),
                           blocked_cells=sum(cell['plan_status'] == 'BLOCKED' for cell in cells), not_run=len(cells), executed=0)
    return result
