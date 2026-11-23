"""Pure binding and reduction of explicit application identity policy evidence.

Private input contains synthetic credentials and assertion values. Public
receipts contain only declared identifiers, status codes and fixed observations.
No file, clock, environment, process or network access occurs in this module.
"""
import copy
import re
from urllib.parse import urlsplit

import helix_runtime_identity_policy as compiler
import helix_runtime_login as login
import helix_runtime_policy_receipts as plans


REASONS = frozenset(('NOT_ATTEMPTED', 'EXPECTED_DENIAL', 'UNEXPECTED_STATUS',
    'REDIRECT_NOT_SUPPORTED', 'ORIGIN_MISMATCH', 'REQUEST_PATH_MISMATCH', 'TRANSPORT_ERROR',
    'OPERATION_TIMEOUT', 'DEADLINE_EXHAUSTED', 'RESOURCE_PAUSED', 'BODY_TOO_LARGE',
    'CONTENT_TYPE_MISMATCH', 'JSON_INVALID', 'JSON_POINTER_MISSING', 'ASSERTION_MISMATCH',
    'SESSION_MATCHED', 'SESSION_IDENTITY_MISMATCH', 'SESSION_ROLES_MISMATCH', 'ACCESS_MATCHED',
    'FORM_NOT_CONFIRMED', 'SESSION_NOT_CONFIRMED', 'BASELINE_NOT_CONFIRMED', 'CLEANUP_FAILED',
    'EXECUTOR_ERROR', 'PUBLIC_RECEIPT_WRITE_FAILED', 'UNSUPPORTED_IDENTITY', 'INPUT_INVALID'))
FAIL_REASONS = frozenset(('UNEXPECTED_STATUS', 'REDIRECT_NOT_SUPPORTED', 'JSON_POINTER_MISSING',
    'ASSERTION_MISMATCH', 'SESSION_IDENTITY_MISMATCH', 'SESSION_ROLES_MISMATCH'))
PASS_REASONS = frozenset(('EXPECTED_DENIAL', 'SESSION_MATCHED', 'ACCESS_MATCHED'))
BINDING_FIELDS = {'run_id', 'integration_id', 'integration_plan_id', 'identity_plan_id',
                  'policy_plan_id', 'policy_hash', 'form_attempt_id', 'policy_attempt_id', 'part'}
COUNTS = ('required_sessions', 'completed_sessions', 'required_cells', 'completed_cells',
          'passed_cells', 'failed_cells', 'blocked_cells', 'not_run_cells')
LIMITS = ['EXPLICIT_POSITIVE_POLICY_ONLY', 'UNCONFIGURED_IDENTITIES_OUTSIDE_SCOPE',
          'ACCEPTED_JSON_SIZE_NOT_TRANSPORT_LIMIT', 'COOKIE_POLICY_NOT_TESTED',
          'GLOBAL_EGRESS_ISOLATION_NOT_ESTABLISHED']


def _require(condition):
    if not condition:
        raise ValueError('identity policy execution: invalid or unbound evidence')


def _fields(value, fields):
    _require(type(value) is dict and set(value) == set(fields))


def _binding(value):
    _fields(value, BINDING_FIELDS)
    form = {key: value[key] for key in ('run_id', 'integration_id', 'integration_plan_id', 'identity_plan_id', 'part')}
    form['attempt_id'] = value['form_attempt_id']
    login._binding(form)
    _require(plans._hash(value['policy_plan_id']) and plans._hash(value['policy_hash']) and
             isinstance(value['policy_attempt_id'], str) and
             re.fullmatch(r'policy-[a-f0-9]{32}', value['policy_attempt_id']) is not None)
    return form


def _form_input(value, declaration):
    _fields(value, {'schema_version', 'binding', 'app_origin', 'issuer', 'authorization_endpoint',
        'client_id', 'callback_paths', 'login_path', 'pkce', 'identities', 'deadline_unix_ms', 'operation_timeout_ms'})
    _require(type(value['schema_version']) is int and value['schema_version'] == 1)
    binding = login._binding(value['binding'])
    _require(binding['part'] == declaration['part'] and binding['identity_plan_id'] == declaration['plan_id'])
    app = login._origin(value['app_origin'], ('localhost', '127.0.0.1'))
    _require(isinstance(value['issuer'], str))
    try:
        issuer = urlsplit(value['issuer'])
        origin = issuer.scheme + '://' + issuer.netloc
        parsed = login._origin(origin, ('127.0.0.1',))
    except (ValueError, TypeError):
        raise ValueError('identity policy execution: invalid private issuer') from None
    _require(parsed.port != app.port and re.fullmatch(r'/realms/helix-[A-Za-z0-9_-]{8,80}', issuer.path) is not None and
             value['issuer'] == origin + issuer.path and value['authorization_endpoint'] == value['issuer'] + '/protocol/openid-connect/auth')
    client = declaration.get('client')
    _require(type(client) is dict and all(field in client for field in ('client_id', 'callback_paths', 'login_path', 'pkce')))
    for field in ('client_id', 'callback_paths', 'login_path', 'pkce'):
        _require(value[field] == client[field])
    _require(login._path(value['login_path']) and value['login_path'] not in value['callback_paths'] and
             type(value['callback_paths']) is list and bool(value['callback_paths']) and all(login._path(path) for path in value['callback_paths']))
    for field, maximum in (('deadline_unix_ms', login.MAX_SAFE_INTEGER), ('operation_timeout_ms', 60000)):
        _require(type(value[field]) is int and 1 <= value[field] <= maximum)
    positive = [row for row in declaration['identities'] if row['id'].startswith('role-')]
    _require(type(value['identities']) is list and len(value['identities']) == len(positive) and bool(positive))
    passwords = set()
    for row, known in zip(value['identities'], positive):
        _fields(row, {'id', 'username', 'email_verified', 'app_roles', 'password'})
        _require(row['id'] == known['id'] and row['username'] == known.get('username') == 'helix-' + known['id'] and
                 row['email_verified'] is True and row['app_roles'] == known['app_roles'])
        password = row['password']
        _require(isinstance(password, str) and 16 <= len(password) <= 512 and
                 re.search(r'[\x00-\x1f\x7f]', password) is None and password not in passwords)
        passwords.add(password)
    return binding


def build_policy_input(public_plan, part, identity_plan, raw_part_config, form_input, *, policy_attempt_id):
    """Rebind private expectations and credentials to the immutable public plan."""
    plans.project_policy_plan(dict(identity_policy_plan=public_plan, identity_policy_receipts=[], identity_plan=identity_plan))
    _require(isinstance(part, str))
    selected = next((row for row in public_plan['parts'] if row['part'] == part), None)
    declaration = next((row for row in identity_plan['parts'] if row['part'] == part), None)
    _require(selected is not None and selected['status'] == 'PLANNED' and declaration is not None and declaration['status'] == 'READY')
    _require(plans._digest(raw_part_config) == selected['policy_hash'])
    roots = [{'path': row['part']} for row in public_plan['parts']]
    rebound = compiler.policy_plan({}, roots, identity_plan, {}, {'runtime': {'identity_policy': {
        'schema_version': 1, 'parts': {part: raw_part_config}}}})
    _require(next(row for row in rebound['parts'] if row['part'] == part) == selected)
    form = _form_input(form_input, declaration)
    binding = {key: form[key] for key in ('run_id', 'integration_id', 'integration_plan_id', 'identity_plan_id', 'part')}
    binding.update(policy_plan_id=public_plan['plan_id'], policy_hash=selected['policy_hash'],
                   form_attempt_id=form['attempt_id'], policy_attempt_id=policy_attempt_id)
    _binding(binding)
    return copy.deepcopy(dict(schema_version=1, kind='identity-policy-input', binding=binding,
        form_input=form_input, public_plan_part=selected, policy=raw_part_config, limits={'accepted_json_bytes': 1048576}))


def _probe(row, *, mode, expected):
    fields = {'status', 'http_status', 'reason_code'}
    if mode == 'session': fields |= {'identity_matched', 'roles_matched'}
    if mode == 'access': fields |= {'assertions_matched'}
    _fields(row, fields)
    status, code, reason = row['status'], row['http_status'], row['reason_code']
    _require(isinstance(status, str) and status in ('NOT_RUN', 'PASS', 'FAIL', 'BLOCKED') and
             (code is None or type(code) is int and 100 <= code <= 599) and isinstance(reason, str) and reason in REASONS)
    for field in fields - {'status', 'http_status', 'reason_code'}:
        _require(row[field] is None or type(row[field]) is bool)
    if status == 'NOT_RUN':
        _require(code is None and reason == 'NOT_ATTEMPTED' and all(row[key] is None for key in fields - {'status', 'http_status', 'reason_code'}))
    elif status == 'PASS':
        _require(code in expected)
        if mode == 'session':
            _require(reason == 'SESSION_MATCHED' and row['identity_matched'] is True and row['roles_matched'] is True)
        elif mode == 'access' and expected == [200]:
            _require(reason == 'ACCESS_MATCHED' and row['assertions_matched'] is True)
        else:
            _require(reason == 'EXPECTED_DENIAL' and (mode != 'access' or row['assertions_matched'] is None))
    elif status == 'FAIL':
        _require(reason in FAIL_REASONS and code is not None)
        if reason == 'UNEXPECTED_STATUS': _require(code not in expected and not 300 <= code <= 399)
        elif reason == 'REDIRECT_NOT_SUPPORTED': _require(300 <= code <= 399)
        else: _require(code == 200)
        if reason == 'SESSION_IDENTITY_MISMATCH': _require(mode == 'session' and row['identity_matched'] is False)
        if reason == 'SESSION_ROLES_MISMATCH': _require(mode == 'session' and row['identity_matched'] is True and row['roles_matched'] is False)
        if reason == 'ASSERTION_MISMATCH': _require(mode == 'access' and row['assertions_matched'] is False)
    else:
        _require(reason not in PASS_REASONS | FAIL_REASONS | {'NOT_ATTEMPTED'})


def _result(probes, cleanup):
    statuses = [row['status'] for row in probes]
    if 'FAIL' in statuses: return 'FAIL'
    if all(status == 'PASS' for status in statuses) and cleanup == 'closed': return 'PASS'
    return 'NOT_RUN' if all(status == 'NOT_RUN' for status in statuses) else 'BLOCKED'


def _complete(probes, cleanup):
    return cleanup == 'closed' and all(probe['status'] in ('PASS', 'FAIL') for probe in probes)


def _suite(suite, report, plan, part, forms):
    _fields(suite, {'schema_version', 'type', 'binding', 'identities', 'cells'})
    _require(type(suite['schema_version']) is int and suite['schema_version'] == 1 and suite['type'] == 'identity-policy-suite')
    form_binding = _binding(suite['binding']); binding = suite['binding']
    integrations = report.get('integrations', {})
    _require(type(integrations) is dict and type(integrations.get('integrations', [])) is list)
    integration = next((row for row in integrations.get('integrations', []) if isinstance(row, dict) and row.get('id') == binding['integration_id']), None)
    _require(part['status'] == 'PLANNED' and binding['part'] == part['part'] and binding['run_id'] == report.get('run_id') and
             binding['policy_plan_id'] == plan['plan_id'] and binding['policy_hash'] == part['policy_hash'] and
             binding['identity_plan_id'] == part['identity_plan_id'] and binding['integration_plan_id'] == integrations.get('plan_id') and
             integration is not None and integration.get('provider') == 'keycloak' and
             type(integration.get('parts')) is list and part['part'] in integration['parts'])
    _require(type(report.get('parts')) is list and part['part'] in {row.get('path', row.get('name')) for row in report['parts'] if isinstance(row, dict)})
    declaration = next(row for row in report['identity_plan']['parts'] if row['part'] == part['part'])
    selected = {cell['identity_id'] for cell in part['cells']}
    identities = [row['id'] for row in declaration['identities'] if row['id'] in selected]
    _require(type(suite['identities']) is list and len(suite['identities']) == len(identities) and
             type(suite['cells']) is list and len(suite['cells']) == len(part['cells']))
    rows = {}
    for row, identity_id in zip(suite['identities'], identities):
        _fields(row, {'identity_id', 'anonymous_session', 'session', 'cleanup'})
        _require(row['identity_id'] == identity_id and isinstance(row['cleanup'], str) and row['cleanup'] in ('closed', 'unknown', 'not_needed'))
        _probe(row['anonymous_session'], mode='anonymous', expected=part['session']['anonymous']['codes'])
        _probe(row['session'], mode='session', expected=[200])
        form = forms.get((part['part'], identity_id))
        if form and form.get('binding') is not None:
            _require(form['binding'] == form_binding)
        form_confirmed = bool(form and form.get('binding') == form_binding and form['form_status'] == 'PASS')
        if row['session']['status'] in ('PASS', 'FAIL') or row['session']['http_status'] is not None:
            # A checkpoint may precede final form-suite publication. Preserve
            # its observations, but unknown cleanup can never complete a case.
            _require((form_confirmed or row['cleanup'] == 'unknown') and row['anonymous_session']['status'] == 'PASS')
        rows[identity_id] = row
    for cell, declared in zip(suite['cells'], part['cells']):
        _fields(cell, {'cell_id', 'identity_id', 'anonymous', 'access', 'result'})
        _require(cell['cell_id'] == declared['id'] and cell['identity_id'] == declared['identity_id'])
        _probe(cell['anonymous'], mode='anonymous', expected=declared['anonymous']['codes'])
        expected = [200] if declared['expected']['access'] == 'allow' else declared['expected']['denial']['codes']
        _probe(cell['access'], mode='access', expected=expected)
        row = rows[cell['identity_id']]
        if cell['access']['status'] in ('PASS', 'FAIL') or cell['access']['http_status'] is not None:
            _require(row['session']['status'] == 'PASS' and cell['anonymous']['status'] == 'PASS')
        probes = [row['anonymous_session'], row['session'], cell['anonymous'], cell['access']]
        _require(cell['result'] == _result(probes, row['cleanup']))
    # not_needed describes no allocated context, never an observed response.
    for identity_id, row in rows.items():
        probes = [row['anonymous_session'], row['session']] + [probe for cell in suite['cells'] if cell['identity_id'] == identity_id for probe in (cell['anonymous'], cell['access'])]
        if row['cleanup'] == 'not_needed': _require(all(probe['http_status'] is None and probe['status'] not in ('PASS', 'FAIL') for probe in probes))
    return rows


def _statuses(required, complete, results, has_attempt, missing=False):
    outcome = 'FAIL' if 'FAIL' in results else 'PASS' if required and complete == required and all(result == 'PASS' for result in results) and not missing else 'UNKNOWN' if has_attempt else 'NOT_RUN'
    execution = 'COMPLETE' if required and complete == required and not missing else 'INCOMPLETE' if has_attempt else 'NOT_RUN'
    return execution, 'RECORDED' if execution == 'COMPLETE' else 'INCOMPLETE' if has_attempt else 'NOT_RUN', outcome


def project_policy_execution(report, parts=None):
    """Validate all suites, then derive coverage and outcome for declared cases."""
    base = plans.project_policy_plan(report, parts)
    suites = report.get('identity_policy_executions', [])
    _require(type(suites) is list)
    result = {key: copy.deepcopy(base[key]) for key in ('schema_version', 'plan_status', 'plan_id', 'source_digest', 'identity_plan_digest')}
    result.update(scope='identity_policy_execution', execution_status='NOT_RECORDED', coverage_status='NOT_RECORDED',
                  outcome='NOT_RUN', counts={key: None for key in COUNTS}, parts=[], limits=list(LIMITS))
    if base['plan_status'] == 'NOT_RECORDED':
        _require(not suites)
        return result
    plan = report['identity_policy_plan']
    # Validate even receipts outside the caller's selected rendering scope.
    forms = {}
    if suites:
        form_projection = login.project_identity(report)
        forms = {(part['part'], row['id']): row for part in form_projection['parts'] for row in part['identities']}
    recorded = {}; attempts = set()
    for suite in suites:
        _require(type(suite) is dict and type(suite.get('binding')) is dict)
        name = suite['binding'].get('part')
        _require(isinstance(name, str) and name not in recorded)
        part = next((row for row in plan['parts'] if row['part'] == name), None)
        _require(part is not None)
        rows = _suite(suite, report, plan, part, forms)
        attempt = suite['binding']['policy_attempt_id']
        _require(attempt not in attempts); attempts.add(attempt)
        recorded[name] = (suite, rows)
    counts = {key: 0 for key in COUNTS}; all_results = []; any_attempt = False; missing = False
    for projected in base['parts']:
        part = next(row for row in plan['parts'] if row['part'] == projected['part'])
        row = {key: copy.deepcopy(projected[key]) for key in ('part', 'identity_plan_id', 'policy_hash', 'config_pointer', 'plan_status', 'gaps', 'unconfigured_identities')}
        suite, identities = recorded.get(row['part'], (None, {}))
        selected = {cell['identity_id']: cell['role'] for cell in part['cells'] if cell['identity_id'] is not None}
        row.update(sessions=[], cells=[])
        required_sessions = len(selected); completed_sessions = 0; completed_cells = 0; results = []; attempted = False
        for identity_id, role in selected.items():
            actual = identities.get(identity_id)
            session = actual['session'] if actual else {'status': 'NOT_RUN', 'identity_matched': None, 'roles_matched': None, 'reason_code': 'NOT_ATTEMPTED'}
            anonymous = actual['anonymous_session'] if actual else {'status': 'NOT_RUN'}
            cleanup = actual['cleanup'] if actual else 'not_needed'
            form = forms.get((row['part'], identity_id))
            form_confirmed = bool(form and form.get('form_status') == 'PASS' and suite and
                                  form.get('binding') == _binding(suite['binding']))
            completed_sessions += bool(actual and _complete([anonymous, session], cleanup))
            attempted |= session['status'] != 'NOT_RUN' or anonymous['status'] != 'NOT_RUN'
            results.extend([session['status'], anonymous['status']])
            unconfirmed = session['status'] == 'PASS' and not form_confirmed
            row['sessions'].append(dict(identity_id=identity_id, role=role,
                status='BLOCKED' if unconfirmed else session['status'], observation_status=session['status'],
                anonymous_status=anonymous['status'], identity_matched=session['identity_matched'], roles_matched=session['roles_matched'],
                reason_code='FORM_NOT_CONFIRMED' if unconfirmed else session['reason_code'], cleanup=cleanup))
        for declared, public in zip(part['cells'], projected['cells']):
            actual = next((cell for cell in suite['cells'] if cell['cell_id'] == declared['id']), None) if suite else None
            cell = copy.deepcopy(public)
            if actual:
                identity = identities[actual['identity_id']]
                probes = [identity['anonymous_session'], identity['session'], actual['anonymous'], actual['access']]
                completed = _complete(probes, identity['cleanup'])
                completed_cells += completed
                cell_attempted = any(probe['status'] != 'NOT_RUN' for probe in probes)
                attempted |= cell_attempted
                failed = next((probe for probe in probes if probe['status'] == 'FAIL'), None)
                reason = (failed or actual['access'])['reason_code']
                if identity['cleanup'] == 'unknown' and not failed: reason = 'CLEANUP_FAILED'
                cell.update(anonymous_status=actual['anonymous']['status'], access_status=actual['access']['status'],
                    result=actual['result'], reason_code=reason, execution_status='COMPLETE' if completed else 'INCOMPLETE' if cell_attempted else 'NOT_RUN')
            else:
                cell.update(anonymous_status='NOT_RUN', access_status='NOT_RUN', result='BLOCKED' if declared['status'] == 'BLOCKED' else 'NOT_RUN',
                            reason_code='INPUT_INVALID' if declared['status'] == 'BLOCKED' else 'NOT_ATTEMPTED', execution_status='NOT_RUN')
            row['cells'].append(cell); results.append(cell['result'])
            counts[{'PASS': 'passed_cells', 'FAIL': 'failed_cells', 'BLOCKED': 'blocked_cells', 'NOT_RUN': 'not_run_cells'}[cell['result']]] += 1
        absent = part['status'] != 'PLANNED'
        row['execution_status'], row['coverage_status'], row['outcome'] = _statuses(required_sessions + len(part['cells']), completed_sessions + completed_cells, results, attempted, absent)
        if suite: row['binding'] = copy.deepcopy(suite['binding'])
        counts['required_sessions'] += required_sessions; counts['completed_sessions'] += completed_sessions
        counts['required_cells'] += len(part['cells']); counts['completed_cells'] += completed_cells
        result['parts'].append(row); all_results.extend(results); any_attempt |= attempted; missing |= absent
    result['counts'] = counts
    result['execution_status'], result['coverage_status'], result['outcome'] = _statuses(
        counts['required_sessions'] + counts['required_cells'], counts['completed_sessions'] + counts['completed_cells'], all_results, any_attempt, missing)
    return result


def derive_identity_assessment(report, parts=None):
    """Combine form observations with the separate, explicitly selected matrix."""
    policy = project_policy_execution(report, parts)
    forms = login.project_identity(report, parts)
    outside = [dict(part=part['part'], identity_id=identity_id) for part in policy['parts'] for identity_id in part['unconfigured_identities']]
    result = dict(scope='declared_identity_policy', status='INCOMPLETE', coverage_status='INCOMPLETE', outcome=policy['outcome'],
                  form_status=forms['form_status'], policy_execution_status=policy['execution_status'], unconfigured_identities=outside)
    if policy['execution_status'] == 'COMPLETE':
        result.update(status=policy['outcome'], coverage_status='RECORDED')
    elif not policy['parts'] and forms['status'] == 'NOT_DETECTED':
        result.update(status='NOT_DETECTED', coverage_status='NOT_DETECTED', outcome='NOT_RUN')
    elif not policy['parts'] and forms['status'] == 'NOT_RECORDED':
        result.update(status='NOT_RECORDED', coverage_status='NOT_RECORDED', outcome='NOT_RUN')
    return result
