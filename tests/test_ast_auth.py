"""Synthetic source and AST fixtures; no parser process, filesystem or network."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from test_ast_scope_helpers import N, capture, args, call, await_, stmt, pair, obj, query, binding, assign, ret, block, function, record, imported
import helix_ast_auth as A
import helix_security_ast_rules as R

HOOK='web/src/hooks.server.ts'
GUARD='web/src/lib/access.ts'
ROUTE='web/src/routes/api/items/+server.ts'

def unary(value):return N('unary_expression','!',capture('argument',value))
def binary(left,operator,right):return N('binary_expression',capture('left',left),' '+operator+' ',capture('right',right))
def paren(value):return N('parenthesized_expression','(',capture('expression',value),')')
def condition(value,*nodes,alternative=None):
    parts=['if ',capture('condition',paren(value)),' ',capture('consequence',block(*nodes))]
    if alternative is not None:parts+=[' else ',capture('alternative',block(*alternative))]
    return N('if_statement',*parts)
def throw(value):return N('throw_statement','throw ',capture('argument',value),';\n')
def response(status,location=None):
    options=[pair('status',str(status))]
    if location is not None:options.append(pair('headers',obj(pair('location',location))))
    return ret(N('new_expression','new ',capture('constructor','Response'),capture('arguments',args('null',obj(*options)))))
def arrow(parameters,*nodes):return N('arrow_function','async ',capture('parameters','('+parameters+')'),' => ',capture('body',block(*nodes)))
def handle(*nodes,name='handle',export=True,parameters='{event,resolve}'):
    value=binding(name,arrow(parameters,*nodes))
    return N('export_statement','export ',value) if export else value

def framework(*,selector=None,location=None,existence=True,delegate=False,export=True):
    rejects=[]
    if existence:rejects.append(condition(unary('event.route.id'),response(404)))
    rejects.append(response(401) if location is None else response(302,location))
    predicate=unary('event.locals.user') if selector is None else binary(selector,'&&',unary('event.locals.user'))
    body=[condition(predicate,*rejects),ret(call('resolve','event'))]
    if delegate:return record(handle(ret(await_(call('dispatch','input'))),parameters='input',export=export),handle(*body,name='dispatch',export=False))
    return record(handle(*body,export=export))

def helper(*,mode='good',export=True):
    rejection=throw(call('error','401',"'denied'"))
    if mode=='boolean':rejection=ret('false')
    if mode=='response':rejection=response(401)
    nodes=[binding('principal','context.user as UserLike | undefined'),condition(unary('principal'),rejection),
           condition(binary('principal.role','===',"'admin'"),ret('undefined')),
           binding('permissions',await_(call('loadPermissions','principal'))),
           condition(unary(call('permissions.has','permission')),throw(call('error','403',"'denied'")))]
    if mode=='nested':nodes=[function('unused','',*nodes)]
    if mode=='early_return':nodes.insert(0,condition('disabled',ret('undefined')))
    if mode=='shadow_error':nodes.insert(0,binding('error','fake'))
    if mode=='different_principal':nodes[0]=binding('principal','serviceAccount.user')
    if mode=='mutated_principal':nodes.insert(1,assign('principal','serviceUser'))
    return function('requireFeature','context: Context, permission: string',*nodes,export=export)

def client(*,mode='good',principal='locals'):
    invoke=call('check',principal,"'items'")
    node=stmt(invoke if mode=='unawaited' else await_(invoke))
    if mode=='optional':node=condition('enabled',node)
    if mode=='nested':node=function('unused','',node)
    nodes=[node,ret(query('params.id'))]
    if mode=='late':nodes.reverse()
    if mode=='shadow':nodes.insert(0,binding('check','fake'))
    if mode=='mutated':nodes.insert(0,assign('check','fake'))
    return function('GET','{locals,params}',*nodes,export=True)

class AuthTests(unittest.TestCase):
    def test_real_parser_discarded_response_does_not_guard_route(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/security-ast/auth-response.json').read_text())
        self.assertEqual(fixture['capture']['version'], '0.51.0')
        self.assertEqual(fixture['capture']['proof_kind'], 'subprocess')
        for case in fixture['cases']:
            with self.subTest(case=case['name']):
                candidate = A.build({case['path']: case['source']}, {case['path']: case['record']}).framework_candidate(
                    {'file': 'src/routes/api/items/+server.ts', 'path': '/api/items'})
                if case['name'] == 'discarded':
                    self.assertIsNone(candidate)
                else:
                    self.assertCandidate(candidate)

    def index(self,modules):
        sources={p:v[0] for p,v in modules.items()};records={p:v[1] for p,v in modules.items()};before=copy.deepcopy((sources,records))
        with mock.patch('builtins.open',side_effect=AssertionError('pure API')):result=A.build(sources,records)
        self.assertEqual((sources,records),before)
        return result
    def framework(self,module=None,*,path='/api/items',file=ROUTE,extra=None):
        modules={HOOK:module or framework()};modules.update(extra or {})
        return self.index(modules).framework_candidate({'file':file,'path':path})
    def local(self,*,h=None,c=None,extra=None,specifier='$lib/access',missing=False):
        modules={GUARD:record(h or helper()),ROUTE:record(*([] if missing else [imported('check',specifier,'requireFeature')]),c or client())};modules.update(extra or {})
        index=self.index(modules);raw,rec=modules[ROUTE]
        fn=next(n for n in rec['facts'] if n['kind']=='function_declaration' and R.text(n,'name')=='GET')
        return index.local_candidate(ROUTE,R.Scope(raw,rec['facts'],fn))
    def assertCandidate(self,value):
        self.assertIsNotNone(value);self.assertEqual(value['applicability'],'unknown');self.assertIn('CONTROL_FLOW_NOT_PROVEN',value['gaps'])
        self.assertNotIn('proven',value);self.assertTrue(value['evidence'])

    def test_framework_actual_handle_and_single_delegate(self):
        self.assertCandidate(self.framework());self.assertCandidate(self.framework(framework(delegate=True)))
    def test_existence_404_does_not_exclude_declared_route(self):
        self.assertCandidate(self.framework(framework(existence=True)))
        self.assertIsNone(self.framework(record(handle(condition(unary('event.locals.user'),condition(unary('event.route.id'),response(404))),ret(call('resolve','event'))))))
    def test_literal_public_selector_is_excluded_dynamic_remains_unknown(self):
        selector=unary(call('event.url.pathname.startsWith',"'/public/'"))
        self.assertIsNone(self.framework(framework(selector=selector),path='/public/items'))
        protected=self.framework(framework(selector=selector));self.assertCandidate(protected)
        self.assertNotIn('DYNAMIC_SELECTOR_UNRESOLVED',protected['gaps'])
        self.assertIsNone(self.framework(framework(selector='false')))
        dynamic=self.framework(framework(selector='featureEnabled'));self.assertCandidate(dynamic);self.assertIn('DYNAMIC_SELECTOR_UNRESOLVED',dynamic['gaps'])
    def test_public_alias_and_literal_array_passthrough(self):
        module=record(handle(binding('pathname','event.url.pathname'),binding('publicRoute',call('pathname.startsWith',"'/public/'")),
            condition(binary(unary('publicRoute'),'&&',unary('event.locals.user')),response(401)),ret(call('resolve','event'))))
        self.assertCandidate(self.framework(module));self.assertIsNone(self.framework(module,path='/public/item'))
        some=call('openRoutes.some',N('arrow_function',capture('parameter','p'),' => ',capture('body',call('event.url.pathname.startsWith','p'))))
        module=record(handle(binding('openRoutes',"['/public/', '/health']"),condition(some,ret(call('resolve','event'))),condition(unary('event.locals.user'),response(401))))
        self.assertIsNone(self.framework(module,path='/public/item'));self.assertCandidate(self.framework(module))
    def test_no_export_no_call_comments_and_nested_definition_do_not_apply(self):
        self.assertIsNone(self.framework(framework(export=False)))
        self.assertIsNone(self.framework(record(handle(ret(call('resolve','event'))),handle(condition(unary('event.locals.user'),response(401)),name='unused',export=False))))
        self.assertIsNone(self.framework(record(handle(function('unused','event',condition(unary('event.locals.user'),response(401))),ret(call('resolve','event'))))))
        self.assertIsNone(self.framework(record(N('comment','// export const handle = deny;'))))
    def test_delegation_requires_await_or_return_and_one_hop(self):
        delegate=handle(condition(unary('event.locals.user'),response(401)),name='dispatch',export=False)
        self.assertIsNone(self.framework(record(handle(stmt(call('dispatch','input')),ret('null'),parameters='input'),delegate)))
        self.assertIsNone(self.framework(record(handle(ret(await_(call('intermediate','input'))),parameters='input'),handle(ret(await_(call('dispatch','input'))),name='intermediate',export=False,parameters='input'),delegate)))
        self.assertIsNone(self.framework(record(handle(condition('false',ret(await_(call('dispatch','input')))),ret('null'),parameters='input'),delegate)))
    def test_discarded_delegate_response_is_not_a_framework_guard(self):
        delegate=handle(condition(unary('event.locals.user'),response(401)),name='dispatch',export=False)
        self.assertIsNone(self.framework(record(handle(stmt(await_(call('dispatch','input'))),ret(call('resolve','input')),parameters='input'),delegate)))
        self.assertCandidate(self.framework(record(handle(binding('result',await_(call('dispatch','input'))),ret('result'),parameters='input'),delegate)))
        self.assertCandidate(self.framework(record(handle(assign('result',await_(call('dispatch','input'))),ret('result'),parameters='input'),delegate)))
        self.assertIsNone(self.framework(record(handle(binding('result',await_(call('dispatch','input'))),assign('result','other'),ret('result'),parameters='input'),delegate)))
        throwing=handle(condition(unary('event.locals.user'),throw(call('error','401',"'denied'"))),name='dispatch',export=False)
        self.assertCandidate(self.framework(record(handle(stmt(await_(call('dispatch','input'))),ret(call('resolve','input')),parameters='input'),throwing)))

    def test_declared_then_assigned_conditional_response_is_propagated(self):
        selected=N('ternary_expression',capture('condition','cacheEnabled'),' ? ',capture('consequence',call('cacheResult')),' : ',capture('alternative',call('dispatch','input')))
        wrapper=handle(N('lexical_declaration','let ',N('variable_declarator',capture('name','result')),';\n'),assign('result',await_(paren(selected))),ret('result'),parameters='input')
        delegate=handle(condition(unary('event.locals.user'),response(401)),name='dispatch',export=False)
        self.assertCandidate(self.framework(record(wrapper,delegate)))

    def test_export_alias_resolves_actual_body_without_mutation(self):
        local=handle(condition(unary('event.locals.user'),response(401)),name='actual',export=False)
        self.assertCandidate(self.framework(record(local,N('export_statement','export { actual as handle };'))))
        self.assertCandidate(self.framework(record(local,N('export_statement','export ',binding('handle','actual')))))
        self.assertIsNone(self.framework(record(local,assign('actual','fake'),N('export_statement','export { actual as handle };'))))
    def test_framework_is_scoped_to_nearest_application(self):
        self.assertIsNone(self.framework(file='other/src/routes/api/items/+server.ts'))
        self.assertIsNone(self.framework(file='web/src/child/src/routes/api/items/+server.ts',extra={'web/src/child/src/hooks.server.ts':record(handle(ret(call('resolve','event'))))}))
    def test_login_redirect_requires_exact_relative_login_path(self):
        for location in ("'/login'","'/auth/login?next=/items'",'`/login?next=${event.url.pathname}`'):
            with self.subTest(location=location):self.assertCandidate(self.framework(framework(location=location)))
        for location in ("'https://example.invalid/login'","'//example.invalid/login'",'`${origin}/login`',"'/other'",'dynamicLocation'):
            with self.subTest(location=location):self.assertIsNone(self.framework(framework(location=location)))
        module=record(handle(condition(unary('event.locals.user'),throw(call('redirect','303',"'/login'")))))
        self.assertCandidate(self.framework(module))
    def test_literal_false_in_alternative_excludes_denial(self):
        module=record(handle(condition(unary('event.locals.user'),condition('true',ret('null'),alternative=[response(401)]))))
        self.assertIsNone(self.framework(module))
    def test_imported_helper_checks_principal_before_early_admin_return(self):
        self.assertCandidate(self.local());self.assertCandidate(self.local(specifier='../../../lib/access'))
    def test_missing_import_other_app_or_nonexported_helper_not_assumed(self):
        self.assertIsNone(self.local(missing=True));self.assertIsNone(self.local(specifier='$lib/missing'))
        self.assertIsNone(self.local(h=helper(export=False)))
        self.assertIsNone(self.local(h=helper(mode='boolean'),extra={'other/src/lib/access.ts':record(helper())}))
    def test_actual_helper_body_required_not_boolean_nested_or_early_return(self):
        for mode in ('boolean','response','nested','early_return','shadow_error','different_principal','mutated_principal'):
            with self.subTest(mode=mode):self.assertIsNone(self.local(h=helper(mode=mode)))
    def test_await_precedes_effect_and_is_direct(self):
        for mode in ('unawaited','optional','nested','late','shadow','mutated'):
            with self.subTest(mode=mode):self.assertIsNone(self.local(c=client(mode=mode)))
        self.assertIsNone(self.local(c=client(principal='serviceUser')))
    def test_duplicate_alias_or_target_mutation_refuse(self):
        modules={GUARD:record(helper(),assign('requireFeature','fake')),ROUTE:record(imported('check','$lib/access','requireFeature'),client())}
        index=self.index(modules);raw,rec=modules[ROUTE];fn=next(n for n in rec['facts'] if n['kind']=='function_declaration')
        self.assertIsNone(index.local_candidate(ROUTE,R.Scope(raw,rec['facts'],fn)))
        self.assertIsNone(self.local(extra={GUARD:record(helper(),helper())}))
    def test_partial_stale_and_forged_capture_do_not_credit(self):
        for mode in ('partial','sha','capture'):
            raw,rec=framework()
            if mode=='partial':rec['status']='PARTIAL'
            elif mode=='sha':rec['source_sha256']='0'*64
            else:next(n for n in rec['facts'] if n['captures'])['captures']['evil']={'start':0,'end':1,'text':'wrong'}
            with self.subTest(mode=mode):self.assertIsNone(self.framework((raw,rec)))

if __name__=='__main__':unittest.main()
