"""Small synthetic source/AST pairs. No process, target repository or parser I/O."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_ast_scope_helpers as H
import helix_security_ast_rules as R


class N:
    def __init__(self,kind,*parts):self.kind,self.parts=kind,parts


def capture(name,value):return (name,value)

def args(*values):
    parts=['(']
    for i,value in enumerate(values):
        if i:parts.append(', ')
        parts.append(value)
    return N('arguments',*parts,')')

def call(name,*values):return N('call_expression',capture('function',name),capture('arguments',args(*values)))
def await_(node):return N('await_expression','await ',capture('argument',node))
def stmt(node):return N('expression_statement',capture('expression',node),';\n')
def pair(key,value):return N('pair',capture('key',key),':',capture('value',value))
def obj(*pairs):
    pieces=['{']
    for i,p in enumerate(pairs):
        if i:pieces.append(',')
        pieces.append(p)
    return N('object',*pieces,'}')
def query(identifier):return call('db.documents.findUnique',obj(pair('where',obj(pair('id',identifier)))))
def binding(name,value):return N('lexical_declaration','const ',N('variable_declarator',capture('name',name),' = ',capture('value',value)),';\n')
def assign(left,right):return stmt(N('assignment_expression',capture('left',left),' = ',capture('right',right)))
def ret(value):return N('return_statement','return ',capture('argument',value),';\n')
def block(*nodes):return N('statement_block','{\n',*nodes,'}')
def branch(node):return N('if_statement','if ',capture('condition','(enabled)'),' ',capture('consequence',block(node)))
def function(name,parameters,*nodes,export=False):
    f=N('function_declaration','async function ',capture('name',name),capture('parameters','('+parameters+')'),' ',capture('body',block(*nodes)))
    return N('export_statement','export ',capture('declaration',f),'\n') if export else f


def record(*nodes):
    chunks=[];facts=[];position=0
    def append(value):
        nonlocal position
        if isinstance(value,str):chunks.append(value);position+=len(value);return
        if isinstance(value,tuple):append(value[1]);return
        start=position;captures={}
        for part in value.parts:
            if isinstance(part,tuple):
                a=position;append(part[1]);captures[part[0]]={'start':a,'end':position}
            else:append(part)
        facts.append(dict(kind=value.kind,start=start,end=position,captures=captures,unit='file'))
    append(N('program',*nodes));raw=''.join(chunks)
    for fact in facts:
        fact['text']=raw[fact['start']:fact['end']]
        fact['id']=hashlib.sha256(f"{fact['kind']}:{fact['start']}:{fact['end']}".encode()).hexdigest()
        for field in fact['captures'].values():field['text']=raw[field['start']:field['end']]
    return raw,dict(status='PARSED',source_sha256=hashlib.sha256(raw.encode()).hexdigest(),facts=facts)


def helper(*,name='requireAccess',mode='good',export=True,guard_name='requireCan'):
    read=await_(query('itemId')) if mode!='unawaited_read' else query('itemId')
    nodes=[binding('row',read)]
    guard=call(guard_name if mode!='boolean' else 'canUser','locals.user',"'read'","'doc'",obj(pair('record','other' if mode=='wrong_row' else 'row')))
    if mode=='constant_principal':guard=call('requireCan','serviceUser',"'read'","'doc'",obj(pair('record','row')))
    guard=stmt(guard if mode=='unawaited_guard' else await_(guard))
    if mode=='nested':guard=function('unused','',guard)
    if mode=='optional':guard=branch(guard)
    if mode=='reassigned_row':nodes.append(assign('row','different'))
    if mode=='mutated_row':nodes.append(stmt(call('mutate','row')))
    if mode=='early_return':nodes.append(branch(ret('false')))
    if mode=='shadow_guard':nodes.append(binding('requireCan','fakeGuard'))
    if mode=='changed_id':nodes.insert(0,assign('itemId','otherId'))
    nodes.extend([guard,ret('row')])
    return function(name,'locals: Context, itemId: string',*nodes,export=export)


def client(*,name='check',guard_id='params.id',effect_id='params.id',mode='good'):
    guard=stmt(await_(call(name,'locals',guard_id)))
    if mode=='unawaited':guard=stmt(call(name,'locals',guard_id))
    if mode=='optional':guard=branch(guard)
    if mode=='nested':guard=function('unused','',guard)
    nodes=[guard]
    if mode=='reassign_alias':nodes.insert(0,assign(name,'fake'))
    if mode=='shadow_alias':nodes.insert(0,binding(name,'fake'))
    if mode=='changed_id':nodes.append(assign('params.id','otherId'))
    if mode=='changed_principal':nodes.append(assign('locals.user','otherUser'))
    nodes.append(ret(query(effect_id)))
    if mode=='late':nodes.reverse()
    return function('GET','{locals,params}',*nodes,export=True)


def imported(alias='check',specifier='$lib/access',symbol='requireAccess'):
    return N('import_statement',f"import {{{symbol} as {alias}}} from '{specifier}';\n")


def typed_helper(*,default="'read'",row='documentRow',context=None,tagged=False):
    read=query('itemId')
    if tagged:
        read=N('call_expression',capture('function','sql'),'<Array<DocumentRow>>',
               capture('arguments',N('template_string','`SELECT * FROM documents WHERE id = ',
                   N('template_substitution','${itemId}'),'`')))
    return function('requireAccess',f'locals: Context, itemId: string, action: Action = {default}',
        binding(row,await_(read)),stmt(await_(call('requireCan','locals.user','action',"'doc'",
            context if context is not None else obj(pair('documentRow',row))))),ret(row),export=True)


class ScopeHelperTests(unittest.TestCase):
    def setup_case(self,h=None,c=None,*,specifier='$lib/access',extra=None):
        modules={'frontend/src/lib/access.ts':record(h or helper()),
                 'frontend/src/routes/[id]/+server.ts':record(imported(specifier=specifier),c or client())}
        if extra:modules.update(extra)
        return modules

    def reasons(self,modules,file='frontend/src/routes/[id]/+server.ts',guards=('requireCan',)):
        sources={p:x[0] for p,x in modules.items()};records={p:x[1] for p,x in modules.items()}
        before=copy.deepcopy((sources,records))
        with mock.patch('builtins.open',side_effect=AssertionError('filesystem forbidden')):
            index=H.build(sources,records,record_guards=guards)
            fn=next(n for n in records[file]['facts'] if n['kind']=='function_declaration' and R.text(n,'name')=='GET')
            scope=R.Scope(sources[file],records[file]['facts'],fn)
            reasons=[index.guard_reason(file,scope,e) for e in scope.calls if R.name(e)=='db.documents.findUnique']
        self.assertEqual(before,(sources,records))
        return reasons

    def test_imported_real_helper_binds_same_parameter_and_row(self):
        self.assertEqual(self.reasons(self.setup_case()),['imported_same_id_row_guard_candidate'])
        self.assertEqual(self.reasons(self.setup_case(specifier='../../lib/access')),['imported_same_id_row_guard_candidate'])
        self.assertEqual(self.reasons(self.setup_case(specifier='$lib/access.js')),['imported_same_id_row_guard_candidate'])

    def test_same_file_definition_requires_no_import(self):
        file='frontend/src/routes/[id]/+server.ts'
        modules={file:record(helper(export=False),client(name='requireAccess'))}
        self.assertEqual(self.reasons(modules),['local_same_id_row_guard_candidate'])

    def test_missing_import_or_global_unique_name_is_not_resolution(self):
        modules=self.setup_case();file='frontend/src/routes/[id]/+server.ts'
        modules[file]=record(client(name='requireAccess'))
        self.assertEqual(self.reasons(modules),[None])
        self.assertEqual(self.reasons(self.setup_case(specifier='$lib/missing')),[None])
        self.assertEqual(self.reasons(self.setup_case(specifier='untrusted-package')),[None])

    def test_wrong_row_wrong_id_boolean_and_constant_principal_do_not_bless(self):
        for mode in ('wrong_row','boolean','constant_principal','changed_id'):
            with self.subTest(mode=mode):self.assertEqual(self.reasons(self.setup_case(h=helper(mode=mode))),[None])
        self.assertEqual(self.reasons(self.setup_case(c=client(guard_id='params.other'))),[None])

    def test_nested_optional_late_or_unawaited_caller_is_not_enforcing(self):
        for mode in ('nested','optional','late','unawaited'):
            with self.subTest(mode=mode):self.assertEqual(self.reasons(self.setup_case(c=client(mode=mode))),[None])

    def test_helper_nested_optional_unawaited_early_return_and_escape_refuse(self):
        for mode in ('nested','optional','unawaited_guard','unawaited_read','early_return','mutated_row'):
            with self.subTest(mode=mode):self.assertEqual(self.reasons(self.setup_case(h=helper(mode=mode))),[None])

    def test_reassignment_and_shadowing_break_the_relation(self):
        for mode in ('reassigned_row','shadow_guard'):
            with self.subTest(helper=mode):self.assertEqual(self.reasons(self.setup_case(h=helper(mode=mode))),[None])
        for mode in ('reassign_alias','shadow_alias','changed_id','changed_principal'):
            with self.subTest(caller=mode):self.assertEqual(self.reasons(self.setup_case(c=client(mode=mode))),[None])

    def test_duplicate_alias_definitions_and_ambiguous_modules_refuse(self):
        modules=self.setup_case();file='frontend/src/routes/[id]/+server.ts'
        modules[file]=record(imported(),imported(),client())
        self.assertEqual(self.reasons(modules),[None])
        modules=self.setup_case();modules['frontend/src/lib/access.ts']=record(helper(),helper())
        self.assertEqual(self.reasons(modules),[None])
        modules=self.setup_case(extra={'frontend/src/lib/access.js':record(helper())})
        self.assertEqual(self.reasons(modules),[None])

    def test_nonexported_and_reexported_implementations_not_followed(self):
        self.assertEqual(self.reasons(self.setup_case(h=helper(export=False))),[None])
        modules=self.setup_case();modules['frontend/src/lib/access.ts']=record(N('export_statement',"export {requireAccess} from './other';"))
        modules['frontend/src/lib/other.ts']=record(helper())
        self.assertEqual(self.reasons(modules),[None])

    def test_lib_alias_uses_nearest_src_scope_only(self):
        modules=self.setup_case(h=helper(mode='wrong_row'),extra={'backend/src/lib/access.ts':record(helper())})
        self.assertEqual(self.reasons(modules),[None])
        modules=self.setup_case(extra={'backend/src/lib/access.ts':record(helper(mode='wrong_row'))})
        self.assertEqual(self.reasons(modules),['imported_same_id_row_guard_candidate'])

    def test_each_effect_requires_its_own_identifier(self):
        file='frontend/src/routes/[id]/+server.ts';modules=self.setup_case()
        modules[file]=record(imported(),function('GET','{locals,params}',stmt(await_(call('check','locals','params.id'))),
            stmt(query('params.id')),ret(query('params.other')),export=True))
        self.assertEqual(self.reasons(modules),['imported_same_id_row_guard_candidate',None])

    def test_record_in_other_argument_does_not_guard_fourth_argument(self):
        wrong=function('requireAccess','locals, itemId',binding('row',await_(query('itemId'))),
            stmt(await_(call('requireCan','locals.user',"'read'",obj(pair('record','row')),obj(pair('record','other'))))),
            ret('row'),export=True)
        self.assertEqual(self.reasons(self.setup_case(h=wrong)),[None])

    def test_module_assignment_and_conditional_definition_refuse(self):
        file='frontend/src/routes/[id]/+server.ts'
        modules={file:record(helper(export=False),assign('requireAccess','fake'),client(name='requireAccess'))}
        self.assertEqual(self.reasons(modules),[None])
        modules={file:record(branch(helper(export=False)),client(name='requireAccess'))}
        self.assertEqual(self.reasons(modules),[None])
        modules=self.setup_case();modules[file]=record(imported(),assign('check','fake'),client())
        self.assertEqual(self.reasons(modules),[None])

    def test_nested_where_identifier_and_spread_do_not_guard_row_id(self):
        for where in (obj(pair('owner',obj(pair('id','itemId')))),
                      obj(pair('id','itemId'),N('spread_element','...',capture('argument','otherFilter')))):
            read=call('db.documents.findUnique',obj(pair('where',where)))
            nested=function('requireAccess','locals, itemId',binding('row',await_(read)),
                stmt(await_(call('requireCan','locals.user',"'read'","'doc'",obj(pair('record','row'))))),ret('row'),export=True)
            with self.subTest(where=where):self.assertEqual(self.reasons(self.setup_case(h=nested)),[None])

    def test_stale_source_partial_parser_and_mutated_fact_refuse(self):
        for mutation in ('hash','status','text','capture'):
            with self.subTest(mutation=mutation):
                modules=self.setup_case();raw,rec=modules['frontend/src/lib/access.ts']
                if mutation=='hash':rec['source_sha256']='0'*64
                elif mutation=='status':rec['status']='PARTIAL'
                elif mutation=='text':rec['facts'][0]['text']='not source'
                else:next(n for n in rec['facts'] if n['captures'])['captures']['forged']={'start':0,'end':1,'text':'wrong'}
                self.assertEqual(self.reasons(modules),[None])

    def test_literal_default_parameter_preserves_id_and_principal_positions(self):
        for default in ("'read'",'"read"','true','false','null','7','-2.5'):
            with self.subTest(default=default):
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(default=default))),
                                 ['imported_same_id_row_guard_candidate'])
        typed=function('requireAccess',"locals: Context, itemId: string, action: 'read' | 'write' = 'read'",
            binding('row',await_(query('itemId'))),
            stmt(await_(call('requireCan','locals.user','action',"'doc'",obj(pair('record','row'))))),
            ret('row'),export=True)
        self.assertEqual(self.reasons(self.setup_case(h=typed)),['imported_same_id_row_guard_candidate'])

    def test_effectful_or_dynamic_default_does_not_create_helper_contract(self):
        for default in ('chooseAction()','session.action','{}','[]',"`read`",'other = replace()',
                        "'read' || dangerous()",'undefined'):
            with self.subTest(default=default):
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(default=default))),[None])

    def test_row_suffix_requires_the_exact_read_binding(self):
        for key in ('documentRow','invoiceRow','row'):
            with self.subTest(key=key):
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=obj(pair(key,'documentRow'))))),
                                 ['imported_same_id_row_guard_candidate'])
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=obj(pair(key,'otherRow'))))),[None])
        self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=obj(pair('message','documentRow'))))),[None])

    def test_single_shorthand_context_requires_same_row_not_a_matching_name_only(self):
        self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=obj('documentRow')))),
                         ['imported_same_id_row_guard_candidate'])
        self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=obj('otherRow')))),[None])
        self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=obj(pair('nested',obj('documentRow')))))),[None])
        self.assertEqual(self.reasons(self.setup_case(h=typed_helper(row='message',context=obj('message')))),[None])

    def test_row_slot_overrides_and_spread_do_not_bless_a_different_context(self):
        for context in (obj(pair('documentRow','documentRow'),pair('documentRow','otherRow')),
                        obj(pair('documentRow','documentRow'),N('spread_element','...',capture('argument','other'))),
                        obj('documentRow',N('spread_element','...',capture('argument','other')))):
            with self.subTest(context=context):
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=context))),[None])

    def test_nonnull_assertion_preserves_same_identifier_and_never_changes_another(self):
        for guard_id,effect_id in (('params.id!','params.id'),('params!.id!','params.id!')):
            with self.subTest(guard=guard_id,effect=effect_id):
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(),c=client(guard_id=guard_id,effect_id=effect_id))),
                                 ['imported_same_id_row_guard_candidate'])
        for value in ('params.other!','!params.id','params?.id','params.id || params.other','params.id()','params.id!!'):
            with self.subTest(value=value):
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(),c=client(guard_id=value))),[None])

    def test_typed_tagged_read_with_literal_default_and_same_shorthand_row(self):
        self.assertEqual(self.reasons(self.setup_case(h=typed_helper(tagged=True,context=obj('documentRow')),
                         c=client(guard_id='params.id!'))),['imported_same_id_row_guard_candidate'])
        self.assertEqual(self.reasons(self.setup_case(h=typed_helper(tagged=True,context=obj('otherRow')),
                         c=client(guard_id='params.id!'))),[None])

    def test_new_syntax_still_requires_await_unchanged_id_and_principal(self):
        for mode in ('unawaited','nested','optional','changed_id','changed_principal'):
            with self.subTest(mode=mode):
                self.assertEqual(self.reasons(self.setup_case(h=typed_helper(context=obj('documentRow')),
                                 c=client(guard_id='params.id!',mode=mode))),[None])

    def test_missing_required_id_and_destructured_event_stay_unresolved(self):
        file='frontend/src/routes/[id]/+server.ts'
        modules=self.setup_case(h=typed_helper())
        modules[file]=record(imported(),function('GET','{locals,params}',
            stmt(await_(call('check','locals'))),ret(query('params.id')),export=True))
        self.assertEqual(self.reasons(modules),[None])
        raw,rec=record(function('requireAccess',"{locals,params}: Event, action: Action = 'read'",
            binding('documentRow',await_(query('params.id'))),
            stmt(await_(call('requireCan','locals','action',"'doc'",obj('documentRow')))),export=True))
        self.assertEqual(H.build({'access.ts':raw},{'access.ts':rec}).contracts,{})


if __name__=='__main__':unittest.main()
