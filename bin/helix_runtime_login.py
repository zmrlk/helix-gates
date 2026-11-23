"""Pure PRIVATE Keycloak browser input. No files, entropy, process or network.

Caller supplies a fresh attempt binding and publishes the result only inside its
owned private runtime directory. This value contains synthetic passwords and
must never be placed in public reports, command arguments or environment.
"""
import re
from urllib.parse import urlsplit

from helix_runtime_identity import synthetic_realm, _digest

MAX_SAFE_INTEGER = 9007199254740991
BINDING = dict(run_id=r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}',
               integration_id=r'keycloak:[0-9a-f]{12}',
               integration_plan_id=r'[0-9a-f]{64}', identity_plan_id=r'[0-9a-f]{64}',
               attempt_id=r'login-[0-9a-f]{32}')
PHASES = ('authorization', 'form', 'callback', 'application_session', 'protected_routes')
LIMITS = ['FORM_FLOW_ONLY', 'TOKEN_VALIDATION_NOT_TESTED', 'COOKIE_POLICY_NOT_TESTED',
          'GLOBAL_EGRESS_ISOLATION_NOT_ESTABLISHED']
REASONS = frozenset(('NOT_ATTEMPTED', 'NO_SESSION_ASSERTION', 'NO_ROUTE_POLICY', 'BOUND_AUTHORIZATION_OBSERVED',
    'OWNED_FORM_SUBMITTED', 'BOUND_CALLBACK_RESPONSE_OBSERVED', 'AUTHORIZATION_NOT_OBSERVED', 'BROWSER_OPERATION_FAILED',
    'CALLBACK_BINDING_MISMATCH', 'CALLBACK_HTTP_ERROR', 'CALLBACK_RESPONSE_INVALID', 'CREDENTIAL_SUBMISSION_NOT_OBSERVED',
    'FLOW_DEADLINE_EXHAUSTED', 'FORM_ACTION_CHANGED', 'IDENTITY_REQUEST_REJECTED', 'INVALID_AUTHORIZATION_PARAMETERS',
    'INVALID_CALLBACK_TARGET', 'OIDC_ERROR_RESPONSE', 'OUTSIDE_IDENTITY_ALLOWLIST', 'PKCE_CONTRACT_MISMATCH',
    'RESOURCE_PAUSED', 'UNEXPECTED_AUTHORIZATION_RESTART', 'UNEXPECTED_FORM_PAGE', 'UNSAFE_CREDENTIAL_SUBMISSION',
    'UNSAFE_FORM_ACTION', 'UNSUPPORTED_LOGIN_FORM', 'PUBLIC_RECEIPT_WRITE_FAILED', 'FORM_HTTP_ERROR', 'CREDENTIAL_IN_URL'))


def _part(value):
    return (isinstance(value,str) and bool(value) and len(value)<=500 and not value.startswith('/') and
            not re.search(r'[\\:?%\x00-\x1f\x7f]',value) and
            (value=='.' or all(piece not in ('','.','..') for piece in value.split('/'))))


def _binding(value):
    if (not isinstance(value, dict) or set(value) != set(BINDING) | {'part'} or
            any(not isinstance(value[key], str) or not re.fullmatch(pattern, value[key]) for key, pattern in BINDING.items()) or
            not _part(value['part'])):
        raise ValueError('login: exact current run and identity plan binding required')
    return dict(value)


def _origin(value, hosts):
    if not isinstance(value, str): raise ValueError('login: exact local HTTPS origin required')
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == 'https' and parsed.hostname in hosts and parsed.port is not None and
                 1 <= parsed.port <= 65535 and value == 'https://' + parsed.hostname + ':' + str(parsed.port))
    except (ValueError, TypeError): valid = False
    if not valid: raise ValueError('login: exact local HTTPS origin required')
    return parsed


def _path(value):
    return (isinstance(value, str) and value.startswith('/') and not value.startswith('//') and
            not re.search(r'[\s\\%*?#${}\x00-\x1f\x7f]', value) and
            not any(part in ('.', '..') for part in value.split('/')))


def build_login_input(part_plan, material, *, binding, issuer, deadline_unix_ms, operation_timeout_ms=15000):
    """Return v1 private browser input for positive synthetic identities only."""
    # Reuse the exact realm contract and hash check before copying credentials.
    # Discard the private realm value immediately; it is never returned here.
    synthetic_realm(part_plan, material)
    binding = _binding(binding)
    if (binding['identity_plan_id'] != part_plan['plan_id'] or binding['part'] != part_plan['part']):
        raise ValueError('login: exact current run and identity plan binding required')
    app = _origin(material['app_origin'], ('localhost', '127.0.0.1'))
    if not isinstance(issuer, str): raise ValueError('login: exact owned Keycloak issuer required')
    try: parsed = urlsplit(issuer)
    except ValueError: raise ValueError('login: exact owned Keycloak issuer required') from None
    idp_origin = parsed.scheme + '://' + parsed.netloc
    idp = _origin(idp_origin, ('127.0.0.1',))
    if (issuer != idp_origin + '/realms/' + material['realm'] or idp.port == app.port):
        raise ValueError('login: exact owned Keycloak issuer required')
    client = part_plan['client']; login = client.get('login_path'); callbacks = client['callback_paths']
    if not _path(login) or not callbacks or login in callbacks or any(not _path(path) for path in callbacks):
        raise ValueError('login: explicit exact login and callback paths required')
    if (type(deadline_unix_ms) is not int or not 1 <= deadline_unix_ms <= MAX_SAFE_INTEGER or
            type(operation_timeout_ms) is not int or not 1 <= operation_timeout_ms <= 60000):
        raise ValueError('login: finite positive integer deadlines required')
    positives = []
    for row in part_plan['identities']:
        if row['id'] in ('no-app-role', 'unverified-email'): continue
        if (row.get('email_verified') is not True or not isinstance(row.get('app_roles'), list) or
                len(row['app_roles']) != 1 or row['app_roles'][0] not in client['roles'] or
                not re.fullmatch(r'role-[0-9a-f]{12}', row.get('id', '')) or row.get('username') != 'helix-' + row['id']):
            raise ValueError('login: positive synthetic identity contract required')
        positives.append(dict(id=row['id'], username=row['username'], email_verified=True,
                              app_roles=list(row['app_roles']), password=material['user_passwords'][row['id']]))
    if (not positives or len({row['id'] for row in positives}) != len(positives) or
            sorted(row['app_roles'][0] for row in positives) != sorted(client['roles'])):
        raise ValueError('login: one positive synthetic identity per declared role required')
    return dict(schema_version=1, binding=dict(binding), app_origin=material['app_origin'], issuer=issuer,
                authorization_endpoint=issuer + '/protocol/openid-connect/auth', client_id=client['client_id'],
                callback_paths=list(callbacks), login_path=login, pkce=client['pkce'], identities=positives,
                deadline_unix_ms=deadline_unix_ms, operation_timeout_ms=operation_timeout_ms)


def _phases_not_run():
    return [dict(phase=phase, status='NOT_RUN', reason_code='NO_SESSION_ASSERTION' if phase == 'application_session' else
                 'NO_ROUTE_POLICY' if phase == 'protected_routes' else 'NOT_ATTEMPTED') for phase in PHASES]


def _flow(row, binding, identity_id):
    fields = {'type','binding','identity_id','status','form_status','phases','execution','limits','cleanup'}
    if (not isinstance(row, dict) or set(row) != fields or row['type'] != 'identity-flow' or
            row['binding'] != binding or row['identity_id'] != identity_id or
            row['status'] not in ('INCOMPLETE','FAIL','BLOCKED') or row['form_status'] not in ('NOT_RUN','PASS','FAIL','BLOCKED') or
            row['cleanup'] not in ('closed','not_needed','unknown') or row['limits'] != LIMITS):
        raise ValueError('login: malformed or unbound public flow receipt')
    phases = row['phases']; execution = row['execution']
    if (not isinstance(phases, list) or len(phases) != len(PHASES) or any(
            not isinstance(item, dict) or set(item) != {'phase','status','reason_code'} or item['phase'] != phase or
            item['status'] not in ('NOT_RUN','PASS','FAIL','BLOCKED') or not isinstance(item['reason_code'],str) or item['reason_code'] not in REASONS
            for phase, item in zip(PHASES, phases)) or
            not isinstance(execution, dict) or set(execution) != {'form_submitted','callback_observed','session_asserted','protected_routes_tested'} or
            type(execution['form_submitted']) is not bool or type(execution['callback_observed']) is not bool or
            execution['session_asserted'] is not False or type(execution['protected_routes_tested']) is not int or execution['protected_routes_tested'] != 0):
        raise ValueError('login: invalid phase observations')
    if (any(item['status'] != 'NOT_RUN' for item in phases[3:]) or
            execution['callback_observed'] and not execution['form_submitted'] or
            phases[1]['status'] == 'PASS' and not execution['form_submitted'] or
            phases[2]['status'] == 'PASS' and not execution['callback_observed']):
        raise ValueError('login: observation does not establish application session or route authorization')
    successful = all(item['status'] == 'PASS' for item in phases[:3])
    if (row['form_status'] == 'PASS' and (not successful or not execution['form_submitted'] or
            not execution['callback_observed'] or row['status'] != 'INCOMPLETE' or row['cleanup'] != 'closed') or
            row['form_status'] == 'NOT_RUN' and (row['status'] != 'INCOMPLETE' or any(item['status'] != 'NOT_RUN' for item in phases) or
                execution['form_submitted'] or execution['callback_observed']) or
            row['form_status'] in ('FAIL','BLOCKED') and row['status'] != row['form_status']):
        raise ValueError('login: form status disagrees with phase observations')
    success_reasons = ('BOUND_AUTHORIZATION_OBSERVED','OWNED_FORM_SUBMITTED','BOUND_CALLBACK_RESPONSE_OBSERVED')
    if any(item['status'] == 'PASS' and item['reason_code'] != reason for item, reason in zip(phases[:3], success_reasons)):
        raise ValueError('login: successful phase requires its exact observation')
    return dict(id=identity_id, variant='positive', binding=dict(binding), form_status=row['form_status'],
                phases=[dict(item) for item in phases], execution=dict(execution), cleanup=row['cleanup'])


def project_identity(report, parts=None):
    """Validate final suites and project public form phases, never session PASS."""
    base = dict(scope='identity_form_only', status='NOT_RECORDED', form_status='NOT_RECORDED',
                session_coverage='NOT_RUN', authorization_coverage='NOT_RUN', parts=[], gaps=[], limits=list(LIMITS))
    if not isinstance(report, dict): raise ValueError('login: report object required')
    if 'identity_plan' not in report and 'identity_forms' not in report: return base
    plan = report.get('identity_plan'); suites = report.get('identity_forms'); entries = report.get('parts')
    if (not isinstance(plan, dict) or plan.get('schema_version') != 1 or not isinstance(plan.get('parts'), list) or
            not isinstance(suites, list) or not isinstance(entries, list) or any(not isinstance(row, dict) for row in entries)):
        raise ValueError('login: complete identity plan and final suites required')
    executed = {row.get('path', row.get('name')) for row in entries}
    declared = {}
    for item in plan['parts']:
        if (not isinstance(item, dict) or item.get('provider') != 'keycloak' or not _part(item.get('part')) or
                item['part'] in declared or not isinstance(item.get('identities'), list)):
            raise ValueError('login: malformed identity declaration')
        identifiers=[]
        for identity in item['identities']:
            if (not isinstance(identity,dict) or not isinstance(identity.get('id'),str) or
                    not re.fullmatch(r'role-[0-9a-f]{12}|no-app-role|unverified-email',identity['id'])):
                raise ValueError('login: invalid declared synthetic identity')
            identifiers.append(identity['id'])
        if len(set(identifiers))!=len(identifiers):raise ValueError('login: duplicate declared synthetic identity')
        copy = dict(item); copy.pop('plan_id', None)
        if item.get('plan_id') != _digest(copy): raise ValueError('login: identity plan hash mismatch')
        declared[item['part']] = item
    if parts is not None:
        if not isinstance(parts, list) or any(not isinstance(path, str) for path in parts) or len(set(parts)) != len(parts) or set(parts) - executed:
            raise ValueError('login: exact executed part paths required')
        selected = set(parts)
    else: selected = executed or set(declared)
    recorded = {}
    integrations = report.get('integrations', {})
    if not isinstance(integrations,dict) or not isinstance(integrations.get('integrations',[]),list):
        raise ValueError('login: integration declaration required')
    for suite in suites:
        if (not isinstance(suite, dict) or set(suite) != {'type','binding','status','form_status','identities','session_coverage','authorization_coverage'} or
                suite['type'] != 'identity-form-suite' or suite['status'] != 'INCOMPLETE' or
                suite['form_status'] not in ('PASS','INCOMPLETE') or suite['session_coverage'] != 'NOT_RUN' or
                suite['authorization_coverage'] != 'NOT_RUN' or not isinstance(suite['identities'], list)):
            raise ValueError('login: invalid final suite coverage')
        binding = _binding(suite['binding']); part = binding['part']; declaration = declared.get(part)
        integration = next((item for item in integrations.get('integrations', []) if isinstance(item, dict) and item.get('id') == binding['integration_id']), None)
        if (part not in executed or declaration is None or declaration.get('status') != 'READY' or part in recorded or
                binding['run_id'] != report.get('run_id') or binding['integration_plan_id'] != integrations.get('plan_id') or
                binding['identity_plan_id'] != declaration['plan_id'] or integration is None or integration.get('provider') != 'keycloak' or
                part not in integration.get('parts', [])):
            raise ValueError('login: final suite binding does not match runtime declaration')
        positive_ids = [row['id'] for row in declaration['identities'] if row['id'] not in ('no-app-role','unverified-email')]
        if len(suite['identities']) != len(positive_ids): raise ValueError('login: final suite omits declared positive identity')
        rows = [_flow(row, binding, identity_id) for row, identity_id in zip(suite['identities'], positive_ids)]
        form = 'PASS' if rows and all(row['form_status'] == 'PASS' for row in rows) else 'INCOMPLETE'
        if suite['form_status'] != form: raise ValueError('login: suite form status disagrees with observations')
        recorded[part] = rows
    for part, declaration in declared.items():
        if part not in selected: continue
        rows = recorded.get(part, [])
        known = {row['id'] for row in rows}
        for identity in declaration['identities']:
            if identity['id'] in known: continue
            rows.append(dict(id=identity['id'], variant='negative' if identity['id'] in ('no-app-role','unverified-email') else 'positive',
                form_status='NOT_RUN', phases=_phases_not_run(), execution=dict(form_submitted=False,callback_observed=False,session_asserted=False,protected_routes_tested=0)))
        positives = [row for row in rows if row['variant'] == 'positive']
        form = 'PASS' if positives and all(row['form_status'] == 'PASS' for row in positives) else 'INCOMPLETE' if part in recorded else 'NOT_RUN'
        missing = [dict(kind='application_session_not_tested'),dict(kind='protected_routes_not_tested')]
        if any(row['variant'] == 'negative' for row in rows): missing.append(dict(kind='negative_identity_variants_not_run'))
        if part not in recorded: missing.append(dict(kind='identity_form_not_run'))
        base['parts'].append(dict(part=part,plan_id=declaration['plan_id'],form_status=form,identities=rows,gaps=missing))
    if base['parts']:
        base['status'] = 'INCOMPLETE'
        base['form_status'] = 'PASS' if all(row['form_status'] == 'PASS' for row in base['parts']) else 'INCOMPLETE'
    else:
        base.update(status='NOT_DETECTED', form_status='NOT_RUN')
    return base
