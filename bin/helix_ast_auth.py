"""Bounded AST authentication candidates, never runtime or production proof.

A framework candidate requires a real exported SvelteKit handle and at most one
same-file invoked delegate. Custom helpers require their actual local/imported
body. Unknown selectors stay unknown; literal exclusions stay excluded.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

import helix_ast_scope_helpers as H
import helix_security_ast_rules as R

UNKNOWN = None
IDENTIFIER = re.compile(r'[A-Za-z_$][\w$]*\Z')
PRINCIPAL = re.compile(r'(?:locals(?:\.user)?|event\.locals(?:\.user)?|(?:request|req)\.user|user|actor|principal|session(?:\.user)?)\Z')


def _capture(raw, a, b):
    return dict(start=a,end=b,text=raw[a:b])


def _strip(scope, capture):
    a,b=capture.get('start',0),capture.get('end',0)
    while a<b and scope.raw[a].isspace():a+=1
    while b>a and scope.raw[b-1].isspace():b-=1
    for _ in range(20):
        parent=next((n for n in scope.nodes if n['kind']=='parenthesized_expression' and n['start']==a and n['end']==b),None)
        if not parent or not R.field(parent,'expression'):break
        a,b=R.field(parent,'expression')['start'],R.field(parent,'expression')['end']
    return _capture(scope.raw,a,b)


def _literal(value):
    match=re.fullmatch(r'(["\'])(/[^"\'\\\r\n]*)\1',value.strip())
    return match[2] if match else None


def _params(function):
    values=H._split(R.text(function,'parameters')) if R.text(function,'parameters') else [R.text(function,'parameter')]
    if values is None:return []
    result=[]
    for value in values:
        match=re.fullmatch(r'([A-Za-z_$][\w$]*)(?:\s*:\s*[\w$.<>\[\]| &]+)?',value)
        result.append(match[1] if match else None)
    return result


def _plain(value):
    value=re.sub(r'\s+as\s+[\w$.<> ,\[\]|&]+$','',value.strip())
    return value if re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*',value) else None


def _principal_refs(scope):
    params=[p for p in _params(scope.function) if p] if scope.function else []
    # Destructured framework event/locals are explicit source names, not global
    # function-name inference. Imported helpers additionally bind parameters.
    refs={'event.locals.user','locals.user','request.user','req.user','session.user'}
    refs.update(p+suffix for p in params for suffix in ('.user','.locals.user','.session.user'))
    for _ in range(len(scope.bindings)+1):
        previous=set(refs)
        for binding in scope.bindings:
            name=R.text(binding,'name').strip();value=_plain(R.text(binding,'value'))
            if IDENTIFIER.fullmatch(name) and value in refs and scope.unchanged(name,binding['end'],scope.body['end']):refs.add(name)
        if refs==previous:break
    return refs


def _path_refs(scope):
    refs={'event.url.pathname':'path','event.route.id':'route_id','url.pathname':'path','route.id':'route_id'}
    for node in scope.nodes:
        if node['kind'] not in ('variable_declarator','assignment_expression'):continue
        name=R.text(node,'name' if node['kind']=='variable_declarator' else 'left').strip()
        value=R.text(node,'value' if node['kind']=='variable_declarator' else 'right')
        if not IDENTIFIER.fullmatch(name):continue
        for reference,kind in list(refs.items()):
            if value.strip()==reference or value.strip().startswith(reference+'.'):
                refs[name]=kind
    return refs


def _array_literals(value):
    if not value.strip().startswith('[') or not value.strip().endswith(']'):return None
    value=value.strip()[1:-1];items=[];pos=0
    token=re.compile(r'\s*(?:(//[^\n]*(?:\n|$)|/\*[\s\S]*?\*/)|(["\'])(/[^"\'\\\r\n]*)\2|(,))')
    expect=True
    while pos<len(value):
        if not value[pos:].strip():break
        match=token.match(value,pos)
        if not match:return None
        pos=match.end()
        if match[1]:continue
        if match[3] is not None:
            if not expect:return None
            items.append(match[3]);expect=False
        elif match[4]:
            if expect:return None
            expect=True
    return items


def _truth_and(values):
    return False if False in values else None if None in values else True


def _truth_or(values):
    return True if True in values else None if None in values else False


def _eval(scope,capture,route,principals,paths,seen=()):
    capture=_strip(scope,capture);value=R.text(capture).strip()
    if not value:return UNKNOWN
    if value in ('true','false'):return value=='true'
    if value in principals:return False  # evaluate the missing-principal branch
    if paths.get(value)=='route_id':return True  # this is an actual declared route
    node=next((n for n in scope.kind('binary_expression') if n['start']==capture['start'] and n['end']==capture['end']),None)
    if node:
        left,right=R.field(node,'left'),R.field(node,'right')
        operator=scope.raw[left['end']:right['start']].strip()
        if operator in ('&&','||'):
            values=[_eval(scope,c,route,principals,paths,seen) for c in (left,right)]
            return _truth_and(values) if operator=='&&' else _truth_or(values)
        l,r=R.text(left).strip(),R.text(right).strip()
        if operator in ('==','===','!=','!=='):
            if (l in principals and r in ('null','undefined')) or (r in principals and l in ('null','undefined')):
                return operator in ('==','===')
            literal=_literal(r) if l in paths else _literal(l) if r in paths else None
            reference=l if l in paths else r
            if literal is not None and route is not None:
                actual=route.get('path') if paths[reference]=='path' else route.get('_route_id')
                result=actual==literal
                return result if operator in ('==','===') else not result
    if value.startswith('!') and not value.startswith('!=') and any(n['kind']=='unary_expression' and n['start']==capture['start'] and n['end']==capture['end'] for n in scope.nodes):
        result=_eval(scope,_capture(scope.raw,capture['start']+1,capture['end']),route,principals,paths,seen)
        return None if result is None else not result
    call=next((n for n in scope.calls if n['start']==capture['start'] and n['end']==capture['end']),None)
    if call and route is not None:
        match=re.fullmatch(r'([\w$.]+)\.(startsWith|includes|endsWith)',R.name(call));args=H._split(R.text(call,'arguments'))
        if match and match[1] in paths and args and len(args)==1:
            literal=_literal(args[0]);actual=route.get('path') if paths[match[1]]=='path' else route.get('_route_id')
            if literal is not None and isinstance(actual,str):
                return actual.startswith(literal) if match[2]=='startsWith' else actual.endswith(literal) if match[2]=='endsWith' else literal in actual
        # Literal array.some(p => pathname.startsWith(p)); no arbitrary callback.
        some=re.fullmatch(r'([\w$]+)\.some\(\s*\(?([\w$]+)\)?\s*=>\s*([\w$.]+)\.startsWith\(\s*\2\s*\)\s*\)',R.text(call).strip())
        if some and some[3] in paths:
            bindings=[n for n in scope.bindings if R.text(n,'name').strip()==some[1] and n['end']<call['start']]
            if len(bindings)==1:
                values=_array_literals(R.text(bindings[0],'value'));actual=route.get('path') if paths[some[3]]=='path' else route.get('_route_id')
                if values is not None and isinstance(actual,str):return any(actual.startswith(x) for x in values)
    if IDENTIFIER.fullmatch(value) and value not in seen and len(seen)<20:
        bindings=[n for n in scope.bindings if R.text(n,'name').strip()==value and n['end']<=capture['start']]
        if len(bindings)==1 and scope.unchanged(value,bindings[0]['end'],capture['start']):
            return _eval(scope,R.field(bindings[0],'value'),route,principals,paths,seen+(value,))
    return UNKNOWN


def _missing_principal(scope,condition,principals):
    # Conditions must actually contain an AST missing-principal predicate.
    for unary in scope.kind('unary_expression'):
        if R.contains(condition,unary) and R.text(unary).lstrip().startswith('!') and _plain(R.text(unary,'argument')) in principals:return True
    for binary in scope.kind('binary_expression'):
        if not R.contains(condition,binary):continue
        left,right=R.text(binary,'left').strip(),R.text(binary,'right').strip()
        operator=scope.raw[R.field(binary,'left')['end']:R.field(binary,'right')['start']].strip()
        if operator in ('==','===') and ((left in principals and right in ('null','undefined')) or (right in principals and left in ('null','undefined'))):return True
    return False


def _argument(scope,node,index):
    capture=R.field(node,'arguments')
    if not capture or not R.text(capture).startswith('('):return None
    # AST container ranges skip nested objects/templates, so interpolated query
    # strings are never reparsed as commas separating arguments.
    spans={}
    for n in scope.nodes:
        if n['kind'] in ('object','array','template_string','call_expression','new_expression','parenthesized_expression') and R.contains(capture,n) and n['start']>capture['start']:
            spans[n['start']]=max(spans.get(n['start'],0),n['end'])
    begin=position=capture['start']+1;end=capture['end']-1;pieces=[];quote=None;escape=False
    while position<end:
        char=scope.raw[position]
        if quote:
            if escape:escape=False
            elif char=='\\':escape=True
            elif char==quote:quote=None
        elif position in spans:position=spans[position];continue
        elif char in "\"'":quote=char
        elif char in '`([{':return None
        elif char==',':pieces.append(_strip(scope,_capture(scope.raw,begin,position)));begin=position+1
        position+=1
    if quote:return None
    pieces.append(_strip(scope,_capture(scope.raw,begin,end)))
    return pieces[index] if index<len(pieces) else None


def _return_value(scope,value,call):
    value=_strip(scope,value)
    if value['start']==call['start'] and value['end']==call['end']:return True
    for node in scope.kind('await_expression','ternary_expression'):
        if node['start']!=value['start'] or node['end']!=value['end']:continue
        if node['kind']=='await_expression':return _return_value(scope,R.field(node,'argument'),call)
        return any(R.contains(R.field(node,key),call) and _return_value(scope,R.field(node,key),call) for key in ('consequence','alternative'))
    return False


def _propagates_response(scope,call):
    for returned in scope.kind('return_statement'):
        value=R.field(returned,'argument')
        if _return_value(scope,value,call):return True
        symbol=R.text(value).strip()
        if not IDENTIFIER.fullmatch(symbol) or returned['start']<call['end']:continue
        definitions=[n for n in scope.kind('variable_declarator','assignment_expression')
                     if R.text(n,'name' if n['kind']=='variable_declarator' else 'left').strip()==symbol and n['end']<=returned['start']
                     and R.field(n,'value' if n['kind']=='variable_declarator' else 'right')]
        if len(definitions)!=1:continue
        bound=definitions[0];expression=R.field(bound,'value' if bound['kind']=='variable_declarator' else 'right')
        if _return_value(scope,expression,call) and scope.unchanged(symbol,bound['end'],returned['start']):return True
    return False


def _login_location(value):
    value=value.strip()
    literal=_literal(value)
    if literal is not None:
        path=literal.split('?',1)[0]
    elif value.startswith('`') and value.endswith('`'):
        prefix=value[1:-1].split('${',1)[0]
        if '?' not in prefix:return False
        path=prefix.split('?',1)[0]
    else:return False
    return bool(re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*(?:login|sign-in|signin|logowanie)',path))


def _denial(scope,exit_node,*,allow_response):
    if exit_node['kind']=='throw_statement':
        for call in scope.calls:
            if _strip(scope,R.field(exit_node,'argument')) != _capture(scope.raw,call['start'],call['end']):continue
            if scope.shadows(R.name(call)) or not scope.unchanged(R.name(call),scope.body['start'],call['end']):continue
            arguments=[R.text(_argument(scope,call,i) or {}) for i in range(2)]
            if R.name(call)=='error' and arguments and arguments[0] in ('401','403'):return int(arguments[0])
            if R.name(call)=='redirect' and arguments and len(arguments)>=2 and arguments[0] in ('302','303') and _login_location(arguments[1]):return int(arguments[0])
    if allow_response and exit_node['kind']=='return_statement':
        for response in scope.kind('new_expression'):
            if _strip(scope,R.field(exit_node,'argument')) != _capture(scope.raw,response['start'],response['end']) or R.text(response,'constructor').strip()!='Response' or scope.shadows('Response'):continue
            context=_argument(scope,response,1)
            if not context:continue
            pairs=R.direct_pairs(scope,context)
            statuses=[R.text(p,'value').strip() for p in pairs if R.text(p,'key').strip()=='status']
            if len(statuses)!=1:continue
            if statuses[0] in ('401','403'):return int(statuses[0])
            if statuses[0] in ('302','303'):
                headers=[R.field(p,'value') for p in pairs if R.text(p,'key').strip()=='headers']
                locations=[R.text(p,'value') for h in headers for p in R.direct_pairs(scope,h) if R.text(p,'key').strip().strip('"\'')=='location']
                if len(locations)==1 and _login_location(locations[0]):return int(statuses[0])
    return None


def _ancestors(scope,node):
    return [branch for branch in scope.kind('if_statement') if R.contains(R.field(branch,'consequence'),node)]


def _deny_candidates(scope,*,allow_response):
    principals=_principal_refs(scope);result=[]
    for exit_node in scope.kind('throw_statement','return_statement'):
        status=_denial(scope,exit_node,allow_response=allow_response)
        ancestors=_ancestors(scope,exit_node)
        if status and any(_missing_principal(scope,R.field(b,'condition'),principals) for b in ancestors):
            # Catch/loop control is not an enforcing local helper contract.
            if not allow_response and any(n['kind'] in ('try_statement','catch_clause','for_statement','while_statement','do_statement') and R.contains(n,exit_node) for n in scope.nodes):continue
            result.append((exit_node,ancestors,status))
    return result


def _reach(scope,node,route):
    values=[];principals=_principal_refs(scope);paths=_path_refs(scope)
    for branch in scope.kind('if_statement','ternary_expression'):
        if not R.contains(branch,node):continue
        condition=R.field(branch,'condition');consequence=R.field(branch,'consequence');alternative=R.field(branch,'alternative')
        value=_eval(scope,condition,route,principals,paths)
        if R.contains(consequence,node):values.append(value)
        elif R.contains(alternative,node):values.append(None if value is None else not value)
    if any(R.contains(n,node) for n in scope.kind('try_statement','catch_clause','for_statement','while_statement','do_statement')):values.append(None)
    return _truth_and(values)


def _route_id(file):
    if '/routes/' in file:return '/'+file.split('/routes/',1)[1].rsplit('/',1)[0]
    return '/'+file.removeprefix('routes/').rsplit('/',1)[0]


class AuthIndex:
    def __init__(self,snapshot,records):
        self.snapshot=dict(snapshot);self.files={};self.boundaries=[];self.local={}
        for file,raw in self.snapshot.items():
            record=records.get(file,{})
            if record.get('status')!='PARSED' or record.get('source_sha256')!=hashlib.sha256(raw.encode()).hexdigest():continue
            facts=record.get('facts',[])
            if any(type(n.get('start')) is not int or type(n.get('end')) is not int or not 0<=n['start']<=n['end']<=len(raw) or n.get('text')!=raw[n['start']:n['end']] for n in facts):continue
            if any(type(c.get('start')) is not int or type(c.get('end')) is not int or not n['start']<=c['start']<=c['end']<=n['end'] or c.get('text')!=raw[c['start']:c['end']] for n in facts for c in n.get('captures',{}).values()):continue
            definitions=H._definitions(facts);self.files[file]=dict(facts=facts,definitions=definitions,imports=H._imports(facts))
            for name,functions in definitions.items():
                if len(functions)!=1 or self._mutated(file,name):continue
                scope=R.Scope(raw,facts,functions[0]);denials=_deny_candidates(scope,allow_response=False)
                candidates=[]
                for node,branches,status in denials:
                    values=[_eval(scope,R.field(b,'condition'),None,_principal_refs(scope),{}) for b in branches]
                    if _truth_and(values) is not True:continue
                    if any(n['start']<node['start'] for n in scope.kind('return_statement')):continue
                    candidates.append(node)
                if candidates:
                    parameters=_params(functions[0]);refs=_principal_refs(scope)
                    parameter_ids=[i for i,p in enumerate(parameters) if p and any(ref.startswith(p+'.') for ref in refs)
                                   and any(re.search(r'\b'+re.escape(p)+r'\.',R.text(n)) for n in scope.nodes)]
                    if len(parameter_ids)==1:
                        exported=any(n['kind']=='export_statement' and R.contains(n,functions[0]) for n in facts)
                        self.local[(file,name)]=dict(function=functions[0],principal=parameter_ids[0],node=min(candidates,key=lambda n:n['start']),exported=exported)
            if re.search(r'(?:^|/)hooks\.server\.[jt]s$',file):self._boundary(file)

    def _mutated(self,file,name):
        return any(n['kind'] in ('assignment_expression','augmented_assignment_expression','update_expression') and name in R.identifiers(R.text(n,'left') or R.text(n,'argument')) for n in self.files[file]['facts'])

    def _boundary(self,file):
        data=self.files[file];facts=data['facts'];definitions=data['definitions'];handles=[]
        for fn in definitions.get('handle',[]):
            if any(n['kind']=='export_statement' and R.contains(n,fn) for n in facts):handles.append(fn)
        for node in facts:
            if node['kind']=='variable_declarator' and R.text(node,'name').strip()=='handle' and any(n['kind']=='export_statement' and R.contains(n,node) for n in facts):
                alias=R.text(node,'value').strip()
                if IDENTIFIER.fullmatch(alias) and len(definitions.get(alias,[]))==1:handles.append(definitions[alias][0])
            if node['kind']=='export_statement':
                alias=re.fullmatch(r'\s*export\s*\{\s*([\w$]+)\s+as\s+handle\s*\}\s*;?\s*',R.text(node))
                if alias and len(definitions.get(alias[1],[]))==1:handles.append(definitions[alias[1]][0])
        unique={n['id']:n for n in handles}
        if len(unique)!=1 or self._mutated(file,'handle'):return
        handle=next(iter(unique.values()))
        if any(handle in definitions.get(name,[]) and self._mutated(file,name) for name in definitions):return
        scope=R.Scope(self.snapshot[file],facts,handle);scopes=[(scope,None)]
        parameters=_params(handle)
        for call in scope.calls:
            name=R.name(call);args=H._split(R.text(call,'arguments'))
            if name=='handle' or len(definitions.get(name,[]))!=1 or self._mutated(file,name) or not args:continue
            if len(parameters)!=1 or parameters[0] is None or args[0]!=parameters[0]:continue
            waited=any(n['kind'] in ('await_expression','return_statement') and R.contains(n,call) for n in scope.nodes)
            if not waited:continue
            scopes.append((R.Scope(self.snapshot[file],facts,definitions[name][0]),call))
        for selected,invocation in scopes:
            denials=_deny_candidates(selected,allow_response=True)
            # Await propagates rejection, but a fulfilled Response is discarded
            # unless its value reaches the exported handle's return.
            if invocation and not _propagates_response(scope,invocation):denials=[d for d in denials if d[0]['kind']=='throw_statement']
            if denials:self.boundaries.append(dict(file=file,handle=handle,scope=selected,denials=denials,entry_scope=scope,invocation=invocation))

    def framework_candidate(self,route):
        candidates=[]
        for boundary in self.boundaries:
            prefix=str(PurePosixPath(boundary['file']).parent)
            prefix='' if prefix=='.' else prefix+'/'
            if not route.get('file','').startswith(prefix+'routes/'):continue
            # A nested app's own hooks are a distinct framework boundary.
            nearer=[f for f in self.files if re.search(r'(?:^|/)hooks\.server\.[jt]s$',f)
                    and f!=boundary['file'] and str(PurePosixPath(f).parent).startswith(prefix)
                    and route['file'].startswith(str(PurePosixPath(f).parent)+'/routes/')]
            if nearer:continue
            scope=boundary['scope'];principals=_principal_refs(scope);paths=_path_refs(scope)
            selected=dict(route,_route_id=_route_id(route['file']))
            entry=boundary['entry_scope'];invocation=boundary['invocation']
            entry_state=_reach(entry,invocation,selected) if invocation else True
            if entry_state is False:continue
            for node,branches,status in boundary['denials']:
                applicability=_reach(scope,node,selected)
                if applicability is False:continue
                bypass=False;unresolved=applicability is None or entry_state is None
                for previous in scope.kind('return_statement'):
                    if previous['start']>=node['start']:continue
                    passthrough=any(R.name(c)=='resolve' and R.contains(previous,c) for c in scope.calls)
                    if not passthrough:continue
                    decision=_reach(scope,previous,selected)
                    if decision is True:bypass=True;break
                    if decision is None:unresolved=True
                if bypass:continue
                evidence=[f"{boundary['file']}:{self.snapshot[boundary['file']].count(chr(10),0,n['start'])+1}" for n in (boundary['handle'],scope.function,node)]
                candidates.append(dict(reason='exported_framework_denial_candidate',evidence=list(dict.fromkeys(evidence)),
                    applicability='unknown',gaps=['CONTROL_FLOW_NOT_PROVEN']+(['DYNAMIC_SELECTOR_UNRESOLVED'] if unresolved else [])))
        if not candidates:return None
        return dict(reason='exported_framework_denial_candidate',evidence=sorted({x for c in candidates for x in c['evidence']}),
                    applicability='unknown',gaps=sorted({x for c in candidates for x in c['gaps']}))

    def local_candidate(self,file,scope):
        if file not in self.files or scope.raw!=self.snapshot[file]:return None
        effects=[n for n in scope.calls if re.match(r'(?:db|prisma|supabase|pool)\b',R.name(n)) or R.name(n) in ('sql','tx')]
        boundary=min(effects,key=lambda n:n['start']) if effects else {'start':scope.body['end'],'end':scope.body['end']}
        for call in scope.calls:
            name=R.name(call)
            if not IDENTIFIER.fullmatch(name) or not scope.before(call,boundary) or scope.shadows(name) or self._mutated(file,name):continue
            data=self.files[file];definitions=data['definitions'].get(name,[]);imports=data['imports'].get(name,[])
            target=file;contract=None
            if len(definitions)==1 and not imports:contract=self.local.get((file,name))
            elif len(imports)==1 and not definitions:
                target=H._resolve(file,imports[0][0],self.snapshot);contract=self.local.get((target,imports[0][1]))
                if contract and not contract['exported']:contract=None
            if not contract:continue
            if re.match(r'\s*async\b',R.text(contract['function'])) and not any(n['kind']=='await_expression' and R.contains(n,call) for n in scope.nodes):continue
            if any(n['start']<call['start'] for n in scope.kind('return_statement')):continue
            args=H._split(R.text(call,'arguments'))
            principal=_plain(args[contract['principal']]) if args and contract['principal']<len(args) else None
            refs=_principal_refs(scope)
            if principal is None or (not PRINCIPAL.fullmatch(principal) and principal not in refs):continue
            return dict(offset=call['start'],reason='resolved_helper_identity_denial_candidate',applicability='unknown',
                evidence=[f"{file}:{scope.raw.count(chr(10),0,call['start'])+1}",f"{target}:{self.snapshot[target].count(chr(10),0,contract['node']['start'])+1}"],
                gaps=['CONTROL_FLOW_NOT_PROVEN'])
        return None


def build(snapshot,records):
    return AuthIndex(dict(snapshot),records)
