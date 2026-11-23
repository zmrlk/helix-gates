"""Pure application-owned WebAuthn planning; no device or application credit."""
import copy
from pathlib import PurePosixPath
import re

from helix_runtime_identity import _digest
from helix_runtime_identity_policy import _route, _pointer, _literal, _part, IDENTIFIER
from helix_runtime_integrations import _area, _validate_plan as validate_inventory
from helix_runtime_policy_receipts import project_policy_plan

EXECUTION = dict(files_opened=0, commands=0, models=0, network=0, application=False)
PROFILE = dict(basis='declared_emulation_profile', capabilities='not_checked', protocol='ctap2',
               transport='internal', hasResidentKey=True, hasUserVerification=True,
               isUserVerified=True, automaticPresenceSimulation=True)
RAW_FIELDS = {'enabled','rp_owner','rp_id','role','policy_cell_ids','registration','logout','authentication'}
COUNTS = ('parts','configured_parts','planned_parts','blocked_parts','disabled_parts',
          'unconfigured_parts','identities_planned','ceremonies_executed','registration_pass','authentication_pass')
PART_FIELDS = {'part','enabled','status','config_pointer','config_hash','declarations','identity_plan_id',
               'identity_selector','identity_id','role','policy_hash','policy_cell_ids','transport_part_digest',
               'rp_owner','rp_id','profile','registration','logout','authentication','gaps','contract_gaps'}
PLAN_FIELDS = {'schema_version','kind','plan_id','source_digest','integration_plan_id','identity_plan_digest',
               'identity_policy_plan_id','transport_plan_id','status','parts','unscoped_declarations',
               'excluded_declarations','gaps','execution'}


def _error():
    raise ValueError('webauthn plan: invalid or unsupported explicit contract') from None


def _require(condition):
    if not condition: _error()


def _obj(value, allowed, required=()):
    _require(type(value) is dict and not set(value)-set(allowed) and not set(required)-set(value))
    return value


def _hash(value):
    return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) is not None


def _location(part):
    return '/runtime/webauthn/parts/'+part.replace('~','~0').replace('/','~1')


def _gap(code, pointer=None):
    return dict(code=code,config_pointer=pointer)


def _unique(rows):
    return [value for _,value in sorted({_digest(row):row for row in rows}.items())]


def _flow(value, pointer, *, logout=False, public=False, optional=False):
    """Normalize only the small declared UI/request contract; literals stay hashed."""
    keys={'path','action','request'} if logout else {'path','action','options','verify'}
    _obj(value,keys)
    gaps=[];result={key:None for key in sorted(keys)}
    def missing(name):
        if not optional:gaps.append(_gap('CONTRACT_FIELD_MISSING',pointer+'/'+name))
    for name in sorted(keys):
        if name not in value or public and value[name] is None:
            missing(name);continue
        item=value[name]
        if name=='path': result[name]=_route(item)
        elif name=='action':
            _obj(item,{'test_id'})
            if 'test_id' not in item or public and item['test_id'] is None:
                missing('action/test_id');result[name]=dict(test_id=None)
            else:
                _require(isinstance(item['test_id'],str) and IDENTIFIER.fullmatch(item['test_id']))
                result[name]=dict(item)
        else:
            fields={'method','path','http_status','json'} if name=='verify' else {'method','path'}
            _obj(item,fields)
            out={key:None for key in sorted(fields)}
            for key in sorted(fields):
                if key not in item or public and item[key] is None:
                    missing(name+'/'+key);continue
                field=item[key]
                if key=='method':_require(field in ('GET','POST'));out[key]=field
                elif key=='path':out[key]=_route(field)
                elif key=='http_status':_require(type(field) is int and field==200);out[key]=200
                else:
                    _require(type(field) is list and bool(field));rows=[];seen=set()
                    for row in field:
                        allowed={'pointer','kind','value_hash'} if public else {'pointer','equals_literal'}
                        _obj(row,allowed,allowed);loc=_pointer(row['pointer'])
                        _require(loc not in seen);seen.add(loc)
                        if public:
                            _require(row['kind']=='literal' and _hash(row['value_hash']));digest=row['value_hash']
                        else:digest=_literal(row['equals_literal'])
                        rows.append(dict(pointer=loc,kind='literal',value_hash=digest))
                    out[key]=rows
            result[name]=out
    return result,gaps


def _configuration(raw, part):
    pointer=_location(part);_obj(raw,RAW_FIELDS)
    result=dict(enabled=None,config_pointer=pointer,config_hash=_digest(raw),identity_selector=None,
                policy_cell_ids=[],rp_owner=None,rp_id=None,registration=None,logout=None,authentication=None)
    gaps=[];enabled=raw.get('enabled')
    if 'enabled' in raw:_require(type(enabled) is bool);result['enabled']=enabled
    else:gaps.append(_gap('CONTRACT_FIELD_MISSING',pointer+'/enabled'))
    for key in sorted(RAW_FIELDS-{'enabled'}):
        if key not in raw:
            if enabled is not False:gaps.append(_gap('CONTRACT_FIELD_MISSING',pointer+'/'+key))
            continue
        value=raw[key]
        if key=='role':
            _require(isinstance(value,str) and IDENTIFIER.fullmatch(value))
            result['identity_selector']=dict(role_sha256=_digest(value))
        elif key=='rp_owner':
            _require(value in ('application','keycloak'));result[key]=value
            if value!='application':gaps.append(_gap('RP_OWNER_UNSUPPORTED',pointer+'/'+key))
        elif key=='rp_id':
            _require(isinstance(value,str) and 0<len(value)<=253 and re.fullmatch(r'[a-zA-Z0-9.-]+',value))
            result[key]=value if value=='localhost' else None
            if value!='localhost':gaps.append(_gap('RP_ID_UNSUPPORTED',pointer+'/'+key))
        elif key=='policy_cell_ids':
            _require(type(value) is list and bool(value) and all(isinstance(x,str) and re.fullmatch(r'cell-[0-9a-f]{16}',x) for x in value)
                     and len(value)==len(set(value)))
            result[key]=list(value)
        else:
            normalized,missing=_flow(value,pointer+'/'+key,logout=key=='logout',optional=enabled is False)
            result[key]=normalized;gaps+=missing
    # Disabled configuration is still type checked, but has no selected flow.
    if enabled is False:
        for key in ('registration','logout','authentication'):result[key]=None
    result['contract_gaps']=_unique(gaps)
    return result


def _context(integrations, identities, transport, policies):
    validate_inventory(integrations)
    project_policy_plan(dict(identity_plan=identities,identity_policy_plan=policies,identity_policy_receipts=[]))
    _require(type(transport) is dict and type(transport.get('schema_version')) is int and transport['schema_version']==1
             and _hash(transport.get('plan_id')) and type(transport.get('parts')) is list)
    roots={};declared={};excluded=[];unscoped=[];gaps=[]
    for row in transport['parts']:
        _require(type(row) is dict and _part(row.get('part')) and row['part'] not in roots)
        roots[row['part']]=row
    for entry in integrations['integrations']:
        if entry['provider']!='webauthn':continue
        _require(type(entry.get('parts')) is list and len(entry['parts'])==len(set(entry['parts']))
                 and all(_part(part) for part in entry['parts']))
        _require(type(entry.get('evidence')) is list and type(entry.get('declared_versions')) is list)
        for evidence in entry['evidence']:
            _obj(evidence,{'path','line','kind','area'},{'path','line','kind','area'})
            _require(_part(evidence['path']) and type(evidence['line']) is int and evidence['line']>0
                     and evidence['area']==entry['area'] and isinstance(evidence['kind'],str)
                     and re.fullmatch(r'[a-zA-Z_]+',evidence['kind']))
        _require(all(isinstance(v,str) and re.fullmatch(r'[~^<>= v\d.*|+-]{1,80}',v) for v in entry['declared_versions']))
        declaration=dict(integration_id=entry['id'],**{key:copy.deepcopy(entry[key]) for key in ('provider','area','parts','evidence','declared_versions')})
        if entry['area']!='active':excluded.append(declaration);continue
        if not entry['parts']:unscoped.append(declaration);continue
        for part in entry['parts']:declared.setdefault(part,[]).append(declaration)
    if unscoped:gaps.append(_gap('INTEGRATION_SCOPE_UNRESOLVED'))
    discovery=integrations.get('discovery',{})
    if not discovery.get('files') or discovery.get('errors'):gaps.append(_gap('SOURCE_SNAPSHOT_INCOMPLETE'))
    return dict(roots=roots,declarations=declared,excluded=excluded,unscoped=unscoped,gaps=gaps,
                identities={row['part']:row for row in identities['parts']},policies={row['part']:row for row in policies['parts']})


def _row(part, configured, context):
    empty=dict(enabled=None,config_pointer=None,config_hash=None,identity_selector=None,policy_cell_ids=[],rp_owner=None,
               rp_id=None,registration=None,logout=None,authentication=None,contract_gaps=[])
    selected=copy.deepcopy(configured if configured is not None else empty);pointer=selected['config_pointer']
    declarations=copy.deepcopy(context['declarations'].get(part,[]));identity=context['identities'].get(part)
    policy=context['policies'].get(part);transport=context['roots'].get(part)
    row=dict(part=part,**selected,declarations=declarations,identity_plan_id=identity['plan_id'] if identity else None,
             identity_id=None,role=None,policy_hash=policy['policy_hash'] if policy else None,
             transport_part_digest=_digest(transport) if transport else None,profile=copy.deepcopy(PROFILE),gaps=[])
    gaps=copy.deepcopy(selected['contract_gaps'])
    if configured is None or selected['enabled'] is False:
        if declarations:gaps.append(_gap('DEPENDENCY_WITHOUT_FLOW_CONTRACT',pointer or _location(part)))
        if selected['enabled'] is False:gaps.append(_gap('DISABLED_BY_CONFIGURATION',pointer+'/enabled'))
        row['status']='DISABLED' if selected['enabled'] is False else 'NOT_CONFIGURED'
    else:
        if transport is None:gaps.append(_gap('PART_NOT_DECLARED',pointer))
        if identity is None:gaps.append(_gap('IDENTITY_PLAN_MISSING',pointer+'/role'))
        elif identity['status']!='READY':gaps.append(_gap('IDENTITY_PLAN_BLOCKED',pointer+'/role'))
        selector=selected['identity_selector']
        if identity and identity['status']=='READY' and selector:
            for person in identity['identities']:
                roles=person.get('app_roles',[])
                if person['id'].startswith('role-') and person.get('email_verified') is True and len(roles)==1 and _digest(roles[0])==selector['role_sha256']:
                    row.update(identity_id=person['id'],role=roles[0]);break
        if selector and row['identity_id'] is None:gaps.append(_gap('ROLE_NOT_DECLARED',pointer+'/role'))
        if not policy or policy['status']!='PLANNED':gaps.append(_gap('POLICY_NOT_PLANNED',pointer+'/policy_cell_ids'))
        cells={cell['id']:cell for cell in policy['cells']} if policy else {}
        for index,cell_id in enumerate(selected['policy_cell_ids']):
            cell=cells.get(cell_id)
            if not cell or cell['status']!='READY' or row['identity_id'] is None or cell['identity_id']!=row['identity_id']:
                gaps.append(_gap('POLICY_CELL_NOT_BOUND',pointer+'/policy_cell_ids/'+str(index)))
        if not transport or transport.get('selected')!='https' or transport.get('public_host')!='localhost' or transport.get('status')!='PLANNED':
            gaps.append(_gap('TRANSPORT_NOT_READY',pointer))
        row['status']='BLOCKED' if gaps else 'PLANNED'
    row['gaps']=_unique(gaps)
    return row


def _status(rows,gaps):
    if gaps:return 'BLOCKED'
    if not rows:return 'NOT_DETECTED'
    if all(row['status']=='DISABLED' for row in rows):return 'DISABLED'
    return 'PLANNED' if all(row['status']=='PLANNED' for row in rows) else 'BLOCKED'


def webauthn_plan(sources, parts, integrations, identity_plan, transport_plan, identity_policy_plan, config=None):
    """Use supplied snapshots only. Missing declarations remain explicit gaps."""
    try:
        _require(type(sources) is dict and type(parts) is list)
        roots=[];snapshot={}
        for part in parts:
            _require(type(part) is dict and _part(part.get('path')) and part['path'] not in roots);roots.append(part['path'])
        for path,text in sources.items():
            _require(_part(path) and isinstance(text,str))
            if _area(path)=='active' and not PurePosixPath(path).name.startswith('.env'):snapshot[path]=text
        context=_context(integrations,identity_plan,transport_plan,identity_policy_plan)
        _require(set(roots)==set(context['roots']) and _digest(snapshot)==identity_policy_plan['source_digest'])
        config={} if config is None else config;_require(type(config) is dict and type(config.get('runtime',{})) is dict)
        raw=config.get('runtime',{}).get('webauthn')
        configured={}
        if 'webauthn' in config.get('runtime',{}):
            _obj(raw,{'schema_version','parts'},{'schema_version','parts'})
            _require(type(raw['schema_version']) is int and raw['schema_version']==1 and type(raw['parts']) is dict)
            for part,value in raw['parts'].items():_require(_part(part));configured[part]=_configuration(value,part)
        rows=[_row(part,configured.get(part),context) for part in sorted(set(configured)|set(context['declarations']))]
        gaps=list(context['gaps'])
        if not snapshot:gaps.append(_gap('SOURCE_SNAPSHOT_INCOMPLETE'))
        result=dict(schema_version=1,kind='webauthn-plan',source_digest=_digest(snapshot),integration_plan_id=integrations['plan_id'],
                    identity_plan_digest=_digest(identity_plan),identity_policy_plan_id=identity_policy_plan['plan_id'],
                    transport_plan_id=transport_plan['plan_id'],status=_status(rows,gaps),parts=rows,
                    unscoped_declarations=context['unscoped'],excluded_declarations=context['excluded'],gaps=_unique(gaps),execution=dict(EXECUTION))
        result['plan_id']=_digest(result)
        return result
    except (KeyError,TypeError,ValueError,AttributeError,UnicodeError):
        _error()


def _public_configuration(row):
    """Reject forged public values; preserve only normalized raw planning fields."""
    _obj(row,PART_FIELDS,PART_FIELDS);pointer=row['config_pointer'];part=row['part']
    if pointer is None:
        _require(row['config_hash'] is None and row['enabled'] is None)
        return None
    _require(pointer==_location(part) and _hash(row['config_hash']) and (row['enabled'] is None or type(row['enabled']) is bool))
    selector=row['identity_selector']
    if selector is not None:_obj(selector,{'role_sha256'},{'role_sha256'});_require(_hash(selector['role_sha256']))
    _require(row['rp_owner'] in (None,'application','keycloak') and row['rp_id'] in (None,'localhost'))
    ids=row['policy_cell_ids']
    _require(type(ids) is list and len(ids)==len(set(ids)) and all(isinstance(x,str) and re.fullmatch(r'cell-[0-9a-f]{16}',x) for x in ids))
    expected=[];disabled=row['enabled'] is False
    if row['enabled'] is None:expected.append(_gap('CONTRACT_FIELD_MISSING',pointer+'/enabled'))
    for key,target in (('role',selector),('policy_cell_ids',ids or None),('rp_owner',row['rp_owner']),('rp_id',row['rp_id'])):
        if target is None and not disabled:
            expected.append(_gap('CONTRACT_FIELD_MISSING',pointer+'/'+key))
    if row['rp_owner']=='keycloak':expected.append(_gap('RP_OWNER_UNSUPPORTED',pointer+'/rp_owner'))
    for key in ('registration','logout','authentication'):
        value=row[key]
        if disabled:_require(value is None);continue
        if value is None:expected.append(_gap('CONTRACT_FIELD_MISSING',pointer+'/'+key));continue
        normalized,missing=_flow(value,pointer+'/'+key,logout=key=='logout',public=True)
        _require(normalized==value);expected+=missing
    supplied=row['contract_gaps'];_require(type(supplied) is list)
    # Unsupported RP is deliberately not echoed. Its fixed gap replaces the
    # missing-RP gap; both states remain blocked and cannot be promoted.
    unsupported=_gap('RP_ID_UNSUPPORTED',pointer+'/rp_id')
    if unsupported in supplied:
        _require(row['rp_id'] is None)
        expected=[gap for gap in expected if gap!=_gap('CONTRACT_FIELD_MISSING',pointer+'/rp_id')]+[unsupported]
    # Disabled fields were type checked at compile time; only safe unsupported
    # markers survive, never the unused raw flow or unknown RP value.
    if disabled:
        expected=[gap for gap in supplied if gap in (unsupported,_gap('RP_OWNER_UNSUPPORTED',pointer+'/rp_owner'))]
    _require(_unique(expected)==supplied)
    return {key:copy.deepcopy(row[key]) for key in ('enabled','config_pointer','config_hash','identity_selector','policy_cell_ids',
               'rp_owner','rp_id','registration','logout','authentication','contract_gaps')}


def project_webauthn_plan(report, parts=None):
    """Strict plan projection: legacy unknown, known execution zero, never PASS."""
    try:
        _require(type(report) is dict)
        result=dict(schema_version=1,plan_status='NOT_RECORDED',execution_status='NOT_RECORDED',coverage_status='NOT_RECORDED',
                    plan_id=None,source_digest=None,counts={key:None for key in COUNTS},parts=[],unscoped_declarations=[],excluded_declarations=[],gaps=[])
        if 'webauthn_plan' not in report and 'webauthn_receipts' not in report:return result
        _require('webauthn_plan' in report and type(report.get('webauthn_receipts')) is list and not report['webauthn_receipts'])
        plan=report['webauthn_plan'];_obj(plan,PLAN_FIELDS,PLAN_FIELDS)
        _require(type(plan['schema_version']) is int and plan['schema_version']==1 and plan['kind']=='webauthn-plan'
                 and _hash(plan['source_digest']) and plan['execution']==EXECUTION
                 and all(type(plan['execution'][key]) is type(value) for key,value in EXECUTION.items()))
        _require(plan['plan_id']==_digest({key:value for key,value in plan.items() if key!='plan_id'}))
        context=_context(report['integrations'],report['identity_plan'],report['transport_plan'],report['identity_policy_plan'])
        _require(plan['integration_plan_id']==report['integrations']['plan_id'] and plan['identity_plan_digest']==_digest(report['identity_plan'])
                 and plan['identity_policy_plan_id']==report['identity_policy_plan']['plan_id'] and plan['transport_plan_id']==report['transport_plan']['plan_id']
                 and plan['source_digest']==report['identity_policy_plan']['source_digest'])
        _require(type(plan['parts']) is list);rows=[];seen=set()
        for row in plan['parts']:
            _require(type(row) is dict and _part(row.get('part')) and row['part'] not in seen);seen.add(row['part'])
            configured=_public_configuration(row)
            _require(configured is not None or row['part'] in context['declarations'])
            expected=_row(row['part'],configured,context);_require(_digest(row)==_digest(expected));rows.append(row)
        _require(set(context['declarations']).issubset(seen) and [row['part'] for row in rows]==sorted(seen))
        _require(plan['unscoped_declarations']==context['unscoped'] and plan['excluded_declarations']==context['excluded'])
        expected_gaps=list(context['gaps'])
        if plan['source_digest']==_digest({}):expected_gaps.append(_gap('SOURCE_SNAPSHOT_INCOMPLETE'))
        _require(plan['gaps']==_unique(expected_gaps) and plan['status']==_status(rows,expected_gaps))
        if parts is not None:
            _require(type(parts) is list and all(_part(part) for part in parts) and len(parts)==len(set(parts))
                     and set(parts).issubset(set(context['roots'])|seen))
            rows=[row for row in rows if row['part'] in parts]
        scoped_status=_status(rows,plan['gaps'])
        result.update(plan_status=scoped_status,execution_status='NOT_RUN',coverage_status='NOT_DETECTED' if scoped_status=='NOT_DETECTED' else 'INCOMPLETE',
                      plan_id=plan['plan_id'],source_digest=plan['source_digest'],unscoped_declarations=copy.deepcopy(plan['unscoped_declarations']),
                      excluded_declarations=copy.deepcopy(plan['excluded_declarations']),gaps=copy.deepcopy(plan['gaps']))
        for row in rows:
            item={key:copy.deepcopy(row[key]) for key in ('part','config_pointer','identity_id','role','policy_cell_ids','declarations','gaps')}
            item.update(plan_status=row['status'],execution_status='NOT_RUN',coverage_status='INCOMPLETE');result['parts'].append(item)
        result['counts']=dict(parts=len(rows),configured_parts=sum(row['config_pointer'] is not None for row in rows),
            planned_parts=sum(row['status']=='PLANNED' for row in rows),blocked_parts=sum(row['status']=='BLOCKED' for row in rows),
            disabled_parts=sum(row['status']=='DISABLED' for row in rows),unconfigured_parts=sum(row['status']=='NOT_CONFIGURED' for row in rows),
            identities_planned=sum(row['status']=='PLANNED' and row['identity_id'] is not None for row in rows),
            ceremonies_executed=0,registration_pass=0,authentication_pass=0)
        return result
    except (KeyError,TypeError,ValueError,AttributeError,UnicodeError):
        _error()
