"""Private WebAuthn rebind and strict public execution reduction; no I/O."""
import copy
import re

import helix_runtime_webauthn as plans
import helix_runtime_identity_policy_run as policy
import helix_runtime_login as login

NEW_PASS = frozenset(('VIRTUAL_AUTHENTICATOR_CREATED','REGISTRATION_VERIFIED','LOGOUT_SESSION_DENIED','AUTHENTICATION_VERIFIED'))
NEW_BLOCK = frozenset(('UNSUPPORTED_BROWSER','VIRTUAL_AUTHENTICATOR_UNAVAILABLE','UNSUPPORTED_REQUEST_FORMAT',
    'UI_ACTION_UNAVAILABLE','UI_ACTION_AMBIGUOUS','OPTIONS_NOT_OBSERVED','VERIFY_NOT_OBSERVED',
    'LOGOUT_REQUEST_NOT_OBSERVED','CREDENTIAL_NOT_OBSERVED','PREREQUISITE_NOT_CONFIRMED'))
NEW_FAIL = frozenset(('RP_MISMATCH','REQUEST_NOT_BOUND','CREDENTIAL_MISMATCH','DUPLICATE_CEREMONY_REQUEST'))
REASONS = policy.REASONS | NEW_PASS | NEW_BLOCK | NEW_FAIL
BINDING_FIELDS = policy.BINDING_FIELDS | {'webauthn_plan_id','webauthn_config_hash','webauthn_attempt_id',
    'transport_plan_id','app_origin','identity_id','webauthn_integration_ids'}
FLAGS = ('options_observed','verify_observed','credential_observed','rp_matched','request_bound','assertions_matched')
CEREMONY_FIELDS = {'status','reason_code','options_http_status','http_status','credential_alias',*FLAGS}
CLEANUP = dict(authenticator=('not_needed','removed','unknown'),cdp=('not_needed','detached','unknown'),
               page=('not_needed','closed','unknown'),context=('not_needed','closed','unknown'))
COUNTS = ('required_flows','attempted_flows','completed_flows','registration_pass','authentication_pass',
          'required_cells','completed_cells','passed_cells','failed_cells','blocked_cells','not_run_cells')
LIMITS = ['APPLICATION_OWNED_LOCALHOST_POSITIVE_FLOW_ONLY','DECLARED_IDENTITY_AND_CELLS_ONLY',
          'VIRTUAL_AUTHENTICATOR_NOT_PHYSICAL_OR_PRODUCTION_PROOF','SERVER_UV_POLICY_NOT_TESTED',
          'DIRECT_WEBAUTHN_JSON_ONLY','ACCEPTED_JSON_SIZE_NOT_TRANSPORT_LIMIT','GLOBAL_EGRESS_ISOLATION_NOT_ESTABLISHED']


def _error():
    raise ValueError('webauthn execution: invalid or unbound evidence') from None


def _require(condition):
    if not condition:_error()


def _fields(value, fields):
    _require(type(value) is dict and set(value)==set(fields))


def _binding(value):
    _fields(value,BINDING_FIELDS)
    base={key:value[key] for key in policy.BINDING_FIELDS};policy._binding(base)
    _require(all(plans._hash(value[key]) for key in ('webauthn_plan_id','webauthn_config_hash','transport_plan_id')))
    _require(isinstance(value['webauthn_attempt_id'],str) and re.fullmatch(r'webauthn-[0-9a-f]{32}',value['webauthn_attempt_id']))
    _require(isinstance(value['identity_id'],str) and re.fullmatch(r'role-[0-9a-f]{12}',value['identity_id']))
    login._origin(value['app_origin'],('localhost',))
    ids=value['webauthn_integration_ids']
    _require(type(ids) is list and all(isinstance(item,str) and re.fullmatch(r'webauthn:[0-9a-f]{12}',item) for item in ids)
             and ids==sorted(set(ids)))
    return base


def _transport(report, part, origin):
    entries=report.get('parts');_require(type(entries) is list)
    selected=[row for row in entries if type(row) is dict and row.get('path',row.get('name'))==part]
    _require(len(selected)==1)
    receipt=selected[0].get('transport')
    _require(type(receipt) is dict and receipt.get('status')=='ready' and receipt.get('public_origin')==origin)


def build_webauthn_input(report, part, raw_part_config, policy_input, *, webauthn_attempt_id):
    """Rebind the original private expectations to the current immutable plan."""
    try:
        plans.project_webauthn_plan(report)
        plan=report['webauthn_plan'];_require(isinstance(part,str))
        selected=next((row for row in plan['parts'] if row['part']==part),None)
        _require(selected is not None and selected['status']=='PLANNED')
        context=plans._context(report['integrations'],report['identity_plan'],report['transport_plan'],report['identity_policy_plan'])
        rebound=plans._row(part,plans._configuration(raw_part_config,part),context)
        _require(plans._digest(rebound)==plans._digest(selected))
        _require(type(policy_input) is dict)
        rebuilt=policy.build_policy_input(report['identity_policy_plan'],part,report['identity_plan'],policy_input['policy'],
            policy_input['form_input'],policy_attempt_id=policy_input['binding']['policy_attempt_id'])
        _require(plans._digest(rebuilt)==plans._digest(policy_input))
        binding=dict(rebuilt['binding']);origin=rebuilt['form_input']['app_origin']
        binding.update(webauthn_plan_id=plan['plan_id'],webauthn_config_hash=selected['config_hash'],
            webauthn_attempt_id=webauthn_attempt_id,transport_plan_id=plan['transport_plan_id'],app_origin=origin,
            identity_id=selected['identity_id'],webauthn_integration_ids=sorted(row['integration_id'] for row in selected['declarations']))
        _binding(binding);_bound_report(report,selected,binding);_transport(report,part,origin)
        return copy.deepcopy(dict(schema_version=1,kind='webauthn-input',binding=binding,policy_input=rebuilt,
            public_plan_part=selected,webauthn=raw_part_config,limits={'accepted_json_bytes':1048576}))
    except (KeyError,TypeError,ValueError,AttributeError,UnicodeError):_error()


def _bound_report(report, selected, binding):
    base=_binding(binding);plan=report['webauthn_plan'];inventory=report['integrations']
    integration=next((row for row in inventory['integrations'] if row['id']==binding['integration_id']),None)
    _require(binding['run_id']==report.get('run_id') and binding['part']==selected['part'] and selected['status']=='PLANNED'
        and binding['webauthn_plan_id']==plan['plan_id'] and binding['webauthn_config_hash']==selected['config_hash']
        and binding['transport_plan_id']==plan['transport_plan_id'] and binding['identity_id']==selected['identity_id']
        and binding['identity_plan_id']==selected['identity_plan_id'] and binding['policy_hash']==selected['policy_hash']
        and binding['policy_plan_id']==plan['identity_policy_plan_id'] and binding['integration_plan_id']==inventory['plan_id']
        and integration is not None and integration['provider']=='keycloak' and integration['area']=='active'
        and selected['part'] in integration['parts']
        and binding['webauthn_integration_ids']==sorted(row['integration_id'] for row in selected['declarations']))
    return base


def _state(row):
    _require(isinstance(row.get('status'),str) and row['status'] in ('NOT_RUN','PASS','FAIL','BLOCKED')
             and isinstance(row.get('reason_code'),str) and row['reason_code'] in REASONS)


def _http(value):
    return value is None or type(value) is int and 100<=value<=599


def _ceremony(row, name):
    _fields(row,CEREMONY_FIELDS);_state(row)
    _require(all(type(row[key]) is bool for key in FLAGS) and _http(row['options_http_status']) and _http(row['http_status']))
    alias=row['credential_alias'];_require(alias is None or isinstance(alias,str) and re.fullmatch(r'credential-[0-9a-f]{32}',alias))
    status=row['status'];reason=row['reason_code']
    if row['options_http_status'] is not None:_require(row['options_observed'])
    if row['http_status'] is not None:_require(row['verify_observed'])
    if row['credential_observed']:_require(alias is not None)
    if alias is not None:_require(row['credential_observed'])
    if row['request_bound']:_require(row['credential_observed'] and row['rp_matched'] and row['options_observed'])
    if row['assertions_matched']:_require(row['verify_observed'] and row['http_status']==200)
    if status=='NOT_RUN':
        _require(reason=='NOT_ATTEMPTED' and alias is None and row['options_http_status'] is None and row['http_status'] is None
                 and not any(row[key] for key in FLAGS))
    elif status=='PASS':
        _require(reason==('REGISTRATION_VERIFIED' if name=='registration' else 'AUTHENTICATION_VERIFIED')
                 and row['options_http_status']==200 and row['http_status']==200 and all(row[key] for key in FLAGS))
    elif status=='FAIL':
        _require(reason in NEW_FAIL|{'UNEXPECTED_STATUS','REDIRECT_NOT_SUPPORTED','JSON_POINTER_MISSING','ASSERTION_MISMATCH'})
        codes=[value for value in (row['options_http_status'],row['http_status']) if value is not None]
        if reason=='UNEXPECTED_STATUS':_require(any(code!=200 and not 300<=code<=399 for code in codes))
        elif reason=='REDIRECT_NOT_SUPPORTED':_require(any(300<=code<=399 for code in codes))
        elif reason in ('JSON_POINTER_MISSING','ASSERTION_MISMATCH'):_require(row['http_status']==200 and not row['assertions_matched'])
        elif reason=='RP_MISMATCH':_require(not row['rp_matched'])
        elif reason in ('REQUEST_NOT_BOUND','CREDENTIAL_MISMATCH'):_require(not row['request_bound'])
    else:_require(reason in policy.REASONS-policy.PASS_REASONS-policy.FAIL_REASONS-{'NOT_ATTEMPTED'}|NEW_BLOCK)


def _capability(row):
    _fields(row,{'status','reason_code','authenticator_created','browser_version'});_state(row)
    _require(type(row['authenticator_created']) is bool)
    version=row['browser_version']
    _require(version is None or isinstance(version,str) and len(version)<=60 and re.fullmatch(r'\d+(?:\.\d+){1,4}',version))
    if row['status']=='PASS':_require(row['authenticator_created'] and row['reason_code']=='VIRTUAL_AUTHENTICATOR_CREATED')
    elif row['status']=='NOT_RUN':_require(not row['authenticator_created'] and version is None and row['reason_code']=='NOT_ATTEMPTED')
    else:_require(row['status']=='BLOCKED' and row['reason_code'] in policy.REASONS-policy.PASS_REASONS-policy.FAIL_REASONS-{'NOT_ATTEMPTED'}|NEW_BLOCK)


def _observed(probe):
    return probe['status'] in ('PASS','FAIL') or probe.get('http_status') is not None


def _dependencies(report, selected, binding):
    """Validate current preliminary observations separately from final credit."""
    policy.project_policy_execution(report)
    projected_forms=login.project_identity(report)
    form_binding=policy._binding({key:binding[key] for key in policy.BINDING_FIELDS})
    forms=[row for part in projected_forms['parts'] if part['part']==selected['part'] for row in part['identities'] if row['id']==binding['identity_id']]
    form=forms[0] if len(forms)==1 else None
    if form and form.get('binding') is not None:_require(form['binding']==form_binding)
    suites=[row for row in report.get('identity_policy_executions',[]) if row['binding']['part']==selected['part']]
    if not suites:return False,False
    _require(len(suites)==1);suite=suites[0]
    _require(suite['binding']=={key:binding[key] for key in policy.BINDING_FIELDS})
    identity=next((row for row in suite['identities'] if row['identity_id']==binding['identity_id']),None)
    cells={row['cell_id']:row for row in suite['cells']}
    observed=bool(identity and identity['anonymous_session']['status']=='PASS' and identity['session']['status']=='PASS'
        and all(cell in cells and cells[cell]['identity_id']==binding['identity_id'] and cells[cell]['anonymous']['status']=='PASS'
                and cells[cell]['access']['status']=='PASS' for cell in selected['policy_cell_ids']))
    final=bool(observed and identity['cleanup']=='closed' and form and form.get('binding')==form_binding and form['form_status']=='PASS'
               and form.get('cleanup')=='closed')
    return observed,final


def _validate_suite(suite, report, selected):
    _fields(suite,{'schema_version','type','binding','capability','registration','logout','authentication','session_after_authentication','cells','cleanup'})
    _require(type(suite['schema_version']) is int and suite['schema_version']==1 and suite['type']=='webauthn-suite')
    binding=suite['binding'];_bound_report(report,selected,binding);_transport(report,selected['part'],binding['app_origin'])
    _capability(suite['capability']);_ceremony(suite['registration'],'registration');_ceremony(suite['authentication'],'authentication')
    declared=next(row for row in report['identity_policy_plan']['parts'] if row['part']==selected['part'])
    logout=suite['logout'];_fields(logout,{'status','reason_code','request_observed','session_denial'});_state(logout)
    _require(type(logout['request_observed']) is bool)
    policy._probe(logout['session_denial'],mode='anonymous',expected=declared['session']['anonymous']['codes'])
    if logout['status']=='PASS':_require(logout['reason_code']=='LOGOUT_SESSION_DENIED' and logout['request_observed'] and logout['session_denial']['status']=='PASS')
    elif logout['status']=='NOT_RUN':_require(logout['reason_code']=='NOT_ATTEMPTED' and not logout['request_observed'] and logout['session_denial']['status']=='NOT_RUN')
    elif logout['status']=='FAIL':
        denial_failed=logout['session_denial']['status']=='FAIL' and logout['reason_code']==logout['session_denial']['reason_code']
        guarded=logout['request_observed'] and logout['session_denial']['status']=='NOT_RUN' and logout['reason_code'] in ('DUPLICATE_CEREMONY_REQUEST','REDIRECT_NOT_SUPPORTED')
        _require(denial_failed or guarded)
    else:_require(logout['reason_code'] in policy.REASONS-policy.PASS_REASONS-policy.FAIL_REASONS-{'NOT_ATTEMPTED'}|NEW_BLOCK)
    policy._probe(suite['session_after_authentication'],mode='session',expected=[200])
    _require(type(suite['cells']) is list and len(suite['cells'])==len(selected['policy_cell_ids']))
    declared_cells={cell['id']:cell for cell in declared['cells']}
    for cell,ident in zip(suite['cells'],selected['policy_cell_ids']):
        _fields(cell,{'cell_id','identity_id','access'});_require(cell['cell_id']==ident and cell['identity_id']==binding['identity_id'])
        known=declared_cells[ident];expected=[200] if known['expected']['access']=='allow' else known['expected']['denial']['codes']
        policy._probe(cell['access'],mode='access',expected=expected)
    _fields(suite['cleanup'],CLEANUP)
    _require(all(isinstance(value,str) and value in CLEANUP[key] for key,value in suite['cleanup'].items()))
    created=suite['capability']['authenticator_created']
    if created:_require(all(suite['cleanup'][key]!='not_needed' for key in ('authenticator','cdp','page')))
    registration=suite['registration'];authentication=suite['authentication']
    if any(registration[key] for key in FLAGS) or _observed(registration):_require(suite['capability']['status']=='PASS' and created)
    if logout['request_observed'] or _observed(logout['session_denial']):_require(registration['status']=='PASS')
    if _observed(logout['session_denial']):_require(logout['request_observed'])
    if any(authentication[key] for key in FLAGS) or _observed(authentication):_require(logout['status']=='PASS')
    if authentication['status']=='PASS':_require(authentication['credential_alias']==registration['credential_alias'])
    if _observed(suite['session_after_authentication']):_require(authentication['status']=='PASS')
    if any(_observed(cell['access']) for cell in suite['cells']):_require(suite['session_after_authentication']['status']=='PASS')
    observed,final=_dependencies(report,selected,binding)
    if created or any(registration[key] for key in FLAGS) or _observed(registration):_require(observed)
    if suite['cleanup']['context']=='closed' and (created or _observed(registration)):_require(final)
    closed=all(value==CLEANUP[key][1] for key,value in suite['cleanup'].items())
    return final and closed


def _pending(selected):
    probe=dict(status='NOT_RUN',http_status=None,reason_code='NOT_ATTEMPTED')
    ceremony=dict(probe,options_http_status=None,credential_alias=None,**{key:False for key in FLAGS})
    return dict(binding=None,capability=dict(status='NOT_RUN',reason_code='NOT_ATTEMPTED',authenticator_created=False,browser_version=None),
        registration=copy.deepcopy(ceremony),authentication=copy.deepcopy(ceremony),logout=dict(status='NOT_RUN',reason_code='NOT_ATTEMPTED',request_observed=False,session_denial=copy.deepcopy(probe)),
        session_after_authentication=dict(probe,identity_matched=None,roles_matched=None),
        cells=[dict(cell_id=ident,identity_id=selected['identity_id'],access=dict(probe,assertions_matched=None)) for ident in selected['policy_cell_ids']],
        cleanup={key:'not_needed' for key in CLEANUP})


def _probes(value):
    return [value[key] for key in ('registration','logout','authentication','session_after_authentication')]+[cell['access'] for cell in value['cells']]


def _statuses(required, complete, outcomes, attempted, no_detection=False):
    if no_detection:return 'NOT_DETECTED','NOT_RUN','NOT_DETECTED','NOT_RUN'
    failed='FAIL' in outcomes
    if required and complete==required:
        outcome='FAIL' if failed else 'PASS'
        return outcome,'COMPLETE','RECORDED',outcome
    return 'INCOMPLETE','INCOMPLETE' if attempted else 'NOT_RUN','INCOMPLETE','FAIL' if failed else 'UNKNOWN' if attempted else 'NOT_RUN'


def project_webauthn_execution(report, parts=None):
    """Validate current per-phase observations, then derive scoped execution."""
    try:
        base=plans.project_webauthn_plan(report,parts)
        suites=report.get('webauthn_executions',[]);_require(type(suites) is list)
        result={key:copy.deepcopy(base[key]) for key in ('schema_version','plan_status','plan_id','source_digest','unscoped_declarations','excluded_declarations','gaps')}
        result.update(status='NOT_RECORDED',execution_status='NOT_RECORDED',coverage_status='NOT_RECORDED',outcome='NOT_RUN',
                      counts={key:None for key in COUNTS},parts=[],limits=list(LIMITS))
        if base['plan_status']=='NOT_RECORDED':_require(not suites);return result
        plan=report['webauthn_plan'];recorded={};attempts=set()
        for suite in suites:
            _require(type(suite) is dict and type(suite.get('binding')) is dict)
            part=suite['binding'].get('part');_require(isinstance(part,str) and part not in recorded)
            selected=next((row for row in plan['parts'] if row['part']==part),None);_require(selected is not None)
            credited=_validate_suite(suite,report,selected);attempt=suite['binding']['webauthn_attempt_id']
            _require(attempt not in attempts);attempts.add(attempt);recorded[part]=(suite,credited)
        counts={key:0 for key in COUNTS};outcomes=[]
        for projected in base['parts']:
            selected=next(row for row in plan['parts'] if row['part']==projected['part'])
            actual,credited=recorded.get(selected['part'],(_pending(selected),False))
            original=copy.deepcopy(actual);row=copy.deepcopy(projected)
            row.update({key:copy.deepcopy(actual[key]) for key in ('binding','capability','registration','logout','authentication','session_after_authentication','cells','cleanup')})
            probes=_probes(original);attempted=actual['capability']['status']!='NOT_RUN' or any(probe['status']!='NOT_RUN' for probe in probes)
            complete=bool(credited and actual['capability']['status']=='PASS' and all(probe['status'] in ('PASS','FAIL') for probe in probes))
            raw_outcomes=[probe['status'] for probe in probes]
            row['status'],row['execution_status'],row['coverage_status'],row['outcome']=_statuses(1,int(complete),raw_outcomes,attempted)
            # Preserve raw observations without promoting an in-flight checkpoint.
            for probe in _probes(row):
                probe['observation_status']=probe['status']
                if probe['status']=='PASS' and not credited:
                    probe.update(status='BLOCKED',reason_code='CLEANUP_FAILED' if 'unknown' in actual['cleanup'].values() else 'PREREQUISITE_NOT_CONFIRMED')
            counts['required_flows']+=1;counts['attempted_flows']+=int(attempted);counts['completed_flows']+=int(complete)
            counts['registration_pass']+=int(row['registration']['status']=='PASS');counts['authentication_pass']+=int(row['authentication']['status']=='PASS')
            counts['required_cells']+=len(row['cells'])
            for cell,raw in zip(row['cells'],original['cells']):
                state=cell['access']['status'];counts[{'PASS':'passed_cells','FAIL':'failed_cells','BLOCKED':'blocked_cells','NOT_RUN':'not_run_cells'}[state]]+=1
                counts['completed_cells']+=int(credited and raw['access']['status'] in ('PASS','FAIL'))
            result['parts'].append(row);outcomes.append(row['outcome'])
        result['counts']=counts
        result['status'],result['execution_status'],result['coverage_status'],result['outcome']=_statuses(
            counts['required_flows'],counts['completed_flows'],outcomes,bool(counts['attempted_flows']),base['coverage_status']=='NOT_DETECTED')
        # Unscoped/source gaps cannot be discharged by a successful known part.
        if base['gaps'] and result['status'] in ('PASS','FAIL'):
            result.update(status='INCOMPLETE',execution_status='INCOMPLETE',coverage_status='INCOMPLETE')
            if result['outcome']=='PASS':result['outcome']='UNKNOWN'
        return result
    except (KeyError,TypeError,ValueError,AttributeError,UnicodeError):_error()
