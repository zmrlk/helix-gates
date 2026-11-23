"""Pure explicit identity policy compilation. No execution or inferred access.

Public plans contain hashes of literal assertions. Private configuration remains
with the caller, to be rebound before a future policy executor may use it.
"""
import json
from pathlib import PurePosixPath
import re

from helix_runtime_identity import _digest
from helix_runtime_integrations import _area, _path

EXECUTION = dict(files_opened=0,commands=0,models=0,network=0,application=False)
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}\Z')
SYNTHETIC = re.compile(r'(?:role-[0-9a-f]{12}|no-app-role|unverified-email)\Z')


def _error(): raise ValueError('identity policy: invalid or unsupported explicit contract')


def _object(value, required, optional=()):
    if not isinstance(value,dict) or set(value)-set(required)-set(optional) or set(required)-set(value):_error()
    return value


def _part(value):
    return isinstance(value,str) and _path(value)==value and not re.search(r'[\x00-\x1f\x7f%]',value)


def _route(value):
    if (not isinstance(value,str) or len(value)>500 or not value.startswith('/') or '//' in value or
            re.search(r'[\s\\%*?#${}\x00-\x1f\x7f]',value) or
            any(piece in ('.','..') for piece in value.split('/'))):_error()
    return value


def _pointer(value):
    if (not isinstance(value,str) or not value.startswith('/') or len(value)>1000 or
            re.search(r'[\x00-\x1f\x7f*]',value) or re.search(r'~(?![01])',value)):_error()
    pieces=[piece.replace('~1','/').replace('~0','~') for piece in value[1:].split('/')]
    if any(piece in ('','__proto__','prototype','constructor') for piece in pieces):_error()
    return value


def _denial(value):
    _object(value,('kind','codes'))
    codes=value['codes']
    if (value['kind']!='status' or not isinstance(codes,list) or not codes or
            any(type(code) is not int or code not in (401,403) for code in codes) or len(set(codes))!=len(codes)):_error()
    return dict(kind='status',codes=sorted(codes))


def _literal(value):
    if value is not None and type(value) not in (str,bool,int):_error()
    if type(value) is int and not -9007199254740991<=value<=9007199254740991:_error()
    return _digest(value)


def _session(value):
    _object(value,('path','method','http_status','anonymous','assertions'))
    if value['method']!='GET' or type(value['http_status']) is not int or value['http_status']!=200:_error()
    rows=value['assertions']
    if not isinstance(rows,list) or not rows:_error()
    assertions=[];seen=set()
    for row in rows:
        _object(row,('pointer','equals_identity'),('comparison',))
        pointer=_pointer(row['pointer']);field=row['equals_identity']
        if field not in ('username','email','email_verified','app_roles') or pointer in seen:_error()
        if (field=='app_roles' and row.get('comparison')!='set_exact' or
                field!='app_roles' and 'comparison' in row):_error()
        seen.add(pointer);assertions.append(dict(row))
    return dict(path=_route(value['path']),method='GET',http_status=200,anonymous=_denial(value['anonymous']),assertions=assertions)


def _expected(value):
    if not isinstance(value,dict):_error()
    if value.get('access')=='deny':
        _object(value,('access','denial'));return dict(access='deny',denial=_denial(value['denial']))
    _object(value,('access','http_status','json'))
    if value['access']!='allow' or type(value['http_status']) is not int or value['http_status']!=200:_error()
    if not isinstance(value['json'],list) or not value['json']:_error()
    rows=[];seen=set()
    for row in value['json']:
        _object(row,('pointer','equals_literal'));pointer=_pointer(row['pointer'])
        if pointer in seen:_error()
        seen.add(pointer);rows.append(dict(pointer=pointer,kind='literal',value_hash=_literal(row['equals_literal'])))
    return dict(access='allow',http_status=200,json=rows)


def _config_pointer(part):return '/runtime/identity_policy/parts/'+part.replace('~','~0').replace('/','~1')


def _gap(code,pointer):return dict(code=code,config_pointer=pointer)


def cell_id(part,cell):
    return 'cell-'+_digest(dict(part=part,**{key:cell[key] for key in ('identity_selector','identity_id','role','request','anonymous','expected')}))[:16]


def policy_plan(sources,parts,identity_plan,integrations,config=None):
    """Compile only explicit policy; keep unknown bindings as visible blockers."""
    if not isinstance(sources,dict) or not isinstance(parts,list) or not isinstance(integrations,dict):_error()
    if (not isinstance(identity_plan,dict) or type(identity_plan.get('schema_version')) is not int or
            identity_plan['schema_version']!=1 or not isinstance(identity_plan.get('parts'),list)):_error()
    config={} if config is None else config
    if not isinstance(config,dict) or not isinstance(config.get('runtime',{}),dict):_error()
    roots=[]
    for part in parts:
        root=part.get('path') if isinstance(part,dict) else None
        if not _part(root) or root in roots:_error()
        roots.append(root)
    snapshot={}
    for path,text in sources.items():
        if not _part(path) or not isinstance(text,str):_error()
        if _area(path)=='active' and not PurePosixPath(path).name.startswith('.env'):snapshot[path]=text
    declarations={}
    for declaration in identity_plan['parts']:
        if (not isinstance(declaration,dict) or declaration.get('provider')!='keycloak' or
                not _part(declaration.get('part')) or declaration['part'] not in roots or declaration['part'] in declarations or
                declaration.get('status') not in ('READY','BLOCKED') or not isinstance(declaration.get('identities'),list)):_error()
        bound=dict(declaration);bound.pop('plan_id',None)
        if declaration.get('plan_id')!=_digest(bound):_error()
        ids=set()
        for row in declaration['identities']:
            if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not SYNTHETIC.fullmatch(row['id']) or row['id'] in ids:_error()
            ids.add(row['id'])
        declarations[declaration['part']]=declaration
    configured={}
    if 'identity_policy' in config.get('runtime',{}):
        raw=_object(config['runtime']['identity_policy'],('schema_version','parts'))
        if type(raw['schema_version']) is not int or raw['schema_version']!=1 or not isinstance(raw['parts'],dict):_error()
        configured=raw['parts']
        if any(not _part(part) for part in configured):_error()
    planned=[]
    selected=set(configured)|{part for part in declarations if part in roots}
    for part in sorted(selected):
        declaration=declarations.get(part);identities=declaration['identities'] if declaration else []
        identity_id=declaration['plan_id'] if declaration else None
        if part not in configured:
            planned.append(dict(part=part,identity_plan_id=identity_id,policy_hash=None,status='NOT_CONFIGURED',config_pointer=None,
                session=None,cells=[],gaps=[_gap('POLICY_NOT_CONFIGURED',None)],unconfigured_identities=[row['id'] for row in identities]))
            continue
        raw=_object(configured[part],('basis','session','cells'))
        if raw['basis']!='explicit_config' or not isinstance(raw['cells'],list) or not raw['cells']:_error()
        pointer=_config_pointer(part);gaps=[];session=_session(raw['session']);cells=[];names=set();semantic=set();requests=set()
        if part not in roots:gaps.append(_gap('PART_NOT_DECLARED',pointer))
        if declaration is None:gaps.append(_gap('IDENTITY_PLAN_MISSING',pointer))
        elif declaration['status']!='READY':gaps.append(_gap('IDENTITY_PLAN_BLOCKED',pointer))
        fields={row['equals_identity'] for row in session['assertions']}
        if not fields.intersection(('username','email')):gaps.append(_gap('SESSION_IDENTITY_ASSERTION_MISSING',pointer+'/session/assertions'))
        if 'app_roles' not in fields:gaps.append(_gap('SESSION_ROLES_ASSERTION_MISSING',pointer+'/session/assertions'))
        roles={}
        for row in identities:
            if row['id'] in ('no-app-role','unverified-email'):continue
            values=row.get('app_roles')
            if (not isinstance(values,list) or len(values)!=1 or not isinstance(values[0],str) or not IDENTIFIER.fullmatch(values[0]) or
                    row['id']!='role-'+_digest(values[0])[:12] or row.get('email_verified') is not True or values[0] in roles):_error()
            roles[values[0]]=row['id']
        for index,raw_cell in enumerate(raw['cells']):
            _object(raw_cell,('id','identity','request','anonymous','expected'))
            name=raw_cell['id']
            if not isinstance(name,str) or not IDENTIFIER.fullmatch(name) or name in names:_error()
            names.add(name);selector=_object(raw_cell['identity'],('role',));role=selector['role']
            if not isinstance(role,str) or not IDENTIFIER.fullmatch(role):_error()
            request=_object(raw_cell['request'],('method','path'))
            if request['method']!='GET':_error()
            location=pointer+'/cells/'+str(index);cell_gaps=[]
            resolved=roles.get(role) if declaration and declaration['status']=='READY' and part in roots else None
            if resolved is None:
                code='ROLE_NOT_DECLARED' if declaration and declaration['status']=='READY' and part in roots else 'IDENTITY_PLAN_BLOCKED' if declaration else 'IDENTITY_PLAN_MISSING'
                cell_gaps.append(_gap(code,location+'/identity'))
            cell=dict(config_id=name,config_pointer=location,identity_id=resolved,role=role if resolved else None,
                identity_selector=dict(role_sha256=_digest(role)),request=dict(method='GET',path=_route(request['path'])),
                anonymous=_denial(raw_cell['anonymous']),expected=_expected(raw_cell['expected']),
                status='BLOCKED' if cell_gaps else 'READY',gaps=cell_gaps)
            cell['id']=cell_id(part,cell)
            # No ordered/stateful scenarios in v1. Combine predicates into one
            # cell; one identity cannot simultaneously allow and deny one GET.
            request_key=(cell['identity_selector']['role_sha256'],cell['request']['method'],cell['request']['path'])
            if request_key in requests:raise ValueError('identity policy: duplicate identity and GET path; combine assertions in one cell')
            requests.add(request_key)
            if cell['id'] in semantic:_error()
            semantic.add(cell['id']);cells.append(cell)
        used={cell['identity_id'] for cell in cells if cell['identity_id']}
        planned.append(dict(part=part,identity_plan_id=identity_id,policy_hash=_digest(raw),
            status='BLOCKED' if gaps or any(cell['status']=='BLOCKED' for cell in cells) else 'PLANNED',config_pointer=pointer,
            session=session,cells=cells,gaps=gaps,unconfigured_identities=[row['id'] for row in identities if row['id'] not in used]))
    status=('NOT_DETECTED' if not planned else 'NOT_CONFIGURED' if all(row['status']=='NOT_CONFIGURED' for row in planned) else
            'BLOCKED' if any(row['status']!='PLANNED' for row in planned) else 'PLANNED')
    result=dict(schema_version=1,kind='identity-policy-plan',source_digest=_digest(snapshot),identity_plan_digest=_digest(identity_plan),
                status=status,parts=planned,execution=dict(EXECUTION))
    result['plan_id']=_digest(result)
    return result
