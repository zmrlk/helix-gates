"""Offline adapter tests. Raw records mirror calibrated ast-grep 0.51.0 JSON.

No test resolves or launches the host's ast-grep. Real CLI calibration is a
separate local artifact, not a hidden dependency of this suite.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_static_ast as AST


def unit(text, path='src/routes/[id]/+server.ts', ext='ts', offset=0, source=None, scope='file'):
    source = text if source is None else source
    return dict(text=text, path=path, ext=ext, offset=offset, source=source,
                source_sha256=hashlib.sha256(source.encode()).hexdigest(), scope=scope)


def location(text, start, end):
    def point(n):
        return dict(line=text.count('\n', 0, n), column=n - (text.rfind('\n', 0, n) + 1))
    return dict(byteOffset=dict(start=len(text[:start].encode()), end=len(text[:end].encode())),
                start=point(start), end=point(end))


def row(u, kind, start=0, end=None, captures=None, filename='input-0.ts'):
    text = u['text']; end = len(text) if end is None else end
    result = dict(text=text[start:end], range=location(text, start, end), file=filename,
        lines=text, charCount=dict(leading=0, trailing=0),
        language={'ts':'TypeScript','js':'JavaScript','tsx':'Tsx'}[u['ext']],
        ruleId=f'hx-{u["ext"]}-{kind}', severity='hint', note=None,
        message='Helix private AST fact', labels=[])
    if captures:
        single = {name.upper():dict(text=text[a:b], range=location(text,a,b)) for name,(a,b) in captures.items()}
        result['metaVariables'] = dict(single=single,multi={'secondary':list(single.values())},transformed={})
    return result


class FakeExecutor:
    def __init__(self, response=None, mutate=None):
        self.response, self.mutate, self.calls, self.directories = response, mutate, [], []

    def run(self, argv, **kwargs):
        self.calls.append((copy.deepcopy(argv),copy.deepcopy(kwargs)))
        self.directories.append(kwargs['cwd'])
        if isinstance(self.response, BaseException):
            raise self.response
        if self.response is not None:
            return self.response
        records = []
        for name in argv:
            if not name.startswith('input-'):
                continue
            p=Path(kwargs['cwd']) / name
            text=p.read_bytes().decode()
            u=unit(text,ext=p.suffix[1:])
            records.append(row(u,'program',filename=name))
        if self.mutate:
            self.mutate(records, argv, kwargs)
        return subprocess.CompletedProcess(argv,0,json.dumps(records).encode(),b'')


class StaticASTTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='helix-ast-unit-')
        self.addCleanup(self.tmp.cleanup)
        receipt=Path(self.tmp.name).resolve()/'receipt.json';receipt.write_text('{"test":"synthetic"}')
        self.installation=dict(tool='ast-grep',version='0.51.0',usable=True,proof_kind='subprocess',
                              smoke_status='PASS',argv_prefix=['/synthetic/ast-grep'],receipt=str(receipt))
        self.rules,self.rulemap,self.rulehash=AST._rules()

    def analyze(self, sources, executor=None, installation=None):
        with mock.patch.object(AST.subprocess,'Popen',side_effect=AssertionError('real process forbidden')):
            return AST.analyze_snapshot(sources,installation=self.installation if installation is None else installation,
                                        executor=executor or FakeExecutor())

    def normalize(self, u, rows):
        return AST.normalize_matches(json.dumps(rows),units={'input-0.ts':u},rule_map=self.rulemap)['input-0.ts']

    def test_exact_calibrated_fields_and_nearest_function_are_preserved(self):
        text='const f = () => { const row = db.find(id); return row; };'
        u=unit(text)
        a=text.index('() =>'); b=text.index('};')+1
        call_a=text.index('db.find'); call_b=text.index(';',call_a)
        ret_a=text.index('return');ret_b=text.index(';',ret_a)+1
        rows=[row(u,'program'),row(u,'arrow_function',a,b,{'parameters':(a,a+2),'body':(text.index('{'),b)}),
              row(u,'call_expression',call_a,call_b,{'function':(call_a,call_a+7),'arguments':(call_a+7,call_b)}),
              row(u,'return_statement',ret_a,ret_b,{'argument':(ret_a+7,ret_b-1)})]
        facts=self.normalize(u,rows)
        function=next(f for f in facts if f['kind']=='arrow_function')
        call=next(f for f in facts if f['kind']=='call_expression')
        self.assertEqual(call['owner_function'],function['id'])
        self.assertEqual(call['captures']['function']['text'],'db.find')
        self.assertEqual(next(f for f in facts if f['kind']=='return_statement')['captures']['argument']['text'],'row')

    def test_nested_function_owns_guard_instead_of_outer_handler(self):
        text='() => { const hidden = () => guard(); return data(); }'
        u=unit(text);inner=text.index('() =>',1);g=text.index('guard()');d=text.index('data()')
        facts=self.normalize(u,[row(u,'program'),row(u,'arrow_function',0,len(text)),
            row(u,'arrow_function',inner,g+7),row(u,'call_expression',g,g+7),row(u,'call_expression',d,d+6)])
        functions=[f for f in facts if f['kind']=='arrow_function']
        guards=[f for f in facts if f['kind']=='call_expression']
        self.assertNotEqual(guards[0]['owner_function'],guards[1]['owner_function'])
        self.assertEqual(guards[0]['owner_function'],next(f['id'] for f in functions if f['start']==inner))

    def test_unicode_crlf_ranges_are_python_offsets_and_exact_source(self):
        text='const ż = "🦀";\r\nż.foo();';u=unit(text);start=text.index('ż.foo')
        facts=self.normalize(u,[row(u,'program'),row(u,'call_expression',start,len(text)-1)])
        call=next(f for f in facts if f['kind']=='call_expression')
        self.assertEqual(call['start'],start);self.assertEqual(call['line'],2)
        self.assertEqual(text[call['start']:call['end']],'ż.foo()')
        invalid=row(u,'call_expression',start,len(text)-1);invalid['range']['byteOffset']['start']+=1
        with self.assertRaises(AST.ASTError):self.normalize(u,[row(u,'program'),invalid])

    def test_foreign_path_rule_language_text_duplicate_and_capture_fail_closed(self):
        u=unit('foo();');base=[row(u,'program'),row(u,'call_expression',0,5)]
        mutations=[lambda r:r[1].update(file='../target.ts'),lambda r:r[1].update(ruleId='foreign'),
                   lambda r:r[1].update(language='Python'),lambda r:r[1].update(text='secret'),
                   lambda r:r.append(copy.deepcopy(r[1])),lambda r:r[1].update(extra='secret')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                rows=copy.deepcopy(base);mutation(rows)
                with self.assertRaises(AST.ASTError):self.normalize(u,rows)
        capture=row(u,'call_expression',0,5,{'function':(0,3)})
        capture['metaVariables']['single']['FUNCTION']['text']='other'
        with self.assertRaises(AST.ASTError):self.normalize(u,[row(u,'program'),capture])

    def test_program_receipt_required_and_empty_json_not_success(self):
        result=self.analyze({'x.ts':'foo();'},FakeExecutor(subprocess.CompletedProcess([],0,b'[]',b'')))
        self.assertEqual(result['files']['x.ts']['status'],'ERROR')
        self.assertEqual(result['files']['x.ts']['gaps'],[{'code':'PROGRAM_RECEIPT_MISSING'}])
        u=unit('\n  foo();\n')
        self.assertEqual(len(self.normalize(u,[row(u,'program',3,len(u['text']))])),1)
        with self.assertRaises(AST.ASTError):self.normalize(u,[row(u,'program',5,len(u['text']))])

    def test_error_node_means_partial_without_claiming_missing_node_coverage(self):
        def inject(records, *_):
            records.append(row(unit('function broken('),'ERROR',0,16))
        result=self.analyze({'bad.ts':'function broken('},FakeExecutor(mutate=inject))
        self.assertEqual(result['files']['bad.ts']['status'],'PARTIAL')
        self.assertIn({'code':'AST_ERROR_NODE'},result['files']['bad.ts']['gaps'])
        parsed=self.analyze({'ok.ts':'foo();'})
        self.assertEqual(parsed['files']['ok.ts']['status'],'PARSED')
        self.assertEqual(parsed['public']['coverage']['status'],'INCOMPLETE')
        self.assertIn({'code':'MISSING_NODES_NOT_EXPOSED'},parsed['files']['ok.ts']['gaps'])

    def test_svelte_exact_offsets_separate_module_instance_and_markup_gap(self):
        source='<p title="<script>fake()</script>">x</p>\n<script context="module" lang="ts">\nmod();\n</script>\n<script>inst();</script>'
        result=self.analyze({'src/(group)/[...path]/Widget.svelte':source})
        f=next(iter(result['files'].values()))
        self.assertEqual(f['status'],'PARSED');self.assertEqual(len(f['facts']),2)
        self.assertEqual({n['unit'] for n in f['facts']},{'module','instance'})
        for n in f['facts']:self.assertEqual(source[n['start']:n['end']],n['text'])
        self.assertIn({'code':'SVELTE_MARKUP_NOT_ANALYZED'},f['gaps'])

    def test_svelte_unknown_src_lang_missing_close_and_duplicates_are_gaps(self):
        for source in ['<script src="x.js"></script>','<script lang="coffee">x()</script>',
                       '<script>x()','<script>x()</script><script>y()</script>',
                       '<!--<script>x()</script>--><p>pin</p>']:
            with self.subTest(source=source):
                runner=FakeExecutor();result=self.analyze({'x.svelte':source},runner)
                self.assertEqual(result['files']['x.svelte']['status'],'UNSUPPORTED');self.assertFalse(runner.calls)

    def test_no_target_config_environment_or_source_path_enters_process(self):
        sources={'src/routes/[id]/+server.ts':'const privateValue="CANARY";',
                 'sgconfig.yml':'customLanguages: malicious','node_modules/config.js':'throw 1;'}
        runner=FakeExecutor()
        with mock.patch.dict(os.environ,{'NODE_OPTIONS':'--require /secret','AST_GREP_CONFIG':'/client/config','HOME':'/client/home'}):
            result=self.analyze(sources,runner)
        argv,kw=runner.calls[0]
        self.assertNotIn('src/routes/[id]/+server.ts',argv)
        self.assertEqual(kw['env']['PATH'],'/usr/bin:/bin');self.assertNotIn('NODE_OPTIONS',kw['env'])
        self.assertNotIn('AST_GREP_CONFIG',kw['env']);self.assertNotEqual(kw['env']['HOME'],'/client/home')
        self.assertEqual(argv[argv.index('--custom-languages')+1],'ignore')
        self.assertIn('--config',argv);self.assertIn('--rule',argv);self.assertNotIn('--update-all',argv)
        self.assertTrue(all(not Path(d).exists() for d in runner.directories))
        public=json.dumps(result['public'])
        self.assertNotIn('CANARY',public);self.assertNotIn('malicious',public);self.assertNotIn('/synthetic',public)
        self.assertEqual(result['public']['engine']['proof_kind'],'synthetic_test')

    def test_unavailable_wrong_pin_and_synthetic_installation_never_execute(self):
        for change in [{'usable':False},{'version':'0.52.0'},{'proof_kind':'synthetic_test'},{'smoke_status':'FAIL'}]:
            runner=FakeExecutor();install=dict(self.installation,**change)
            result=self.analyze({'x.ts':'foo();'},runner,install)
            self.assertEqual(result['files']['x.ts']['status'],'UNAVAILABLE');self.assertFalse(runner.calls)
        with mock.patch('helix_tools_manager.resolve_installed',return_value=None),mock.patch.object(AST.Executor,'run',side_effect=AssertionError()):
            result=AST.analyze_snapshot({'x.ts':'foo();'})
        self.assertFalse(result['public']['engine']['used'])

    def test_bad_json_process_failure_timeout_limit_no_public_stderr(self):
        cases=[subprocess.CompletedProcess([],0,b'notjson CANARY',b'private password'),
               subprocess.CompletedProcess([],2,b'[]',b'private password'),
               subprocess.TimeoutExpired(['private'],1),AST.ASTError('AST_OUTPUT_LIMIT')]
        for response in cases:
            with self.subTest(response=type(response).__name__):
                runner=FakeExecutor(response);result=self.analyze({'x.ts':'foo();'},runner)
                self.assertEqual(result['files']['x.ts']['status'],'ERROR');self.assertEqual(result['files']['x.ts']['facts'],[])
                self.assertNotIn('CANARY',json.dumps(result));self.assertNotIn('password',json.dumps(result['public']))
                self.assertTrue(all(not Path(d).exists() for d in runner.directories))

    def test_paths_sources_immutability_and_deterministic_hashes(self):
        sources={'app/[slug]/+server.ts':'foo();','app/(group)/[...rest].tsx':'bar();'}
        before=copy.deepcopy(sources);a=self.analyze(sources);b=self.analyze(dict(reversed(list(sources.items()))))
        self.assertEqual(a,b);self.assertEqual(sources,before)
        for invalid in ['/outside.ts','../outside.ts','x/../x.ts','x\\file.ts','x\nfile.ts','./x.ts']:
            with self.subTest(path=invalid),self.assertRaises(AST.ASTError):self.analyze({invalid:'foo();'})
        with self.assertRaises(AST.ASTError):self.analyze([('x.ts','a'),('x.ts','b')])

    def test_full_large_source_is_batched_not_silently_truncated(self):
        text='// padding\n' * 20000 + 'endMarker();'
        runner=FakeExecutor();result=self.analyze({'large.ts':text,'other.ts':'other();'},runner)
        self.assertEqual(result['public']['usage']['input_bytes'],len(text.encode())+len('other();'))
        self.assertEqual(result['files']['large.ts']['facts'][0]['text'],text)
        self.assertEqual(result['files']['large.ts']['facts'][0]['end'],len(text))

    def test_zero_sources_and_unsupported_language_are_explicit(self):
        empty=self.analyze({});self.assertEqual(empty['public']['coverage']['gaps'],[{'code':'EMPTY_SNAPSHOT'}])
        unsupported=self.analyze({'x.py':'def f(): pass'})
        self.assertEqual(unsupported['files']['x.py']['status'],'UNSUPPORTED')
        self.assertFalse(unsupported['public']['engine']['used'])

    def test_svelte_displayed_script_in_raw_text_is_not_executable(self):
        for tag in ('textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes'):
            with self.subTest(tag=tag):
                fake = f'<{tag}><script>displayedOnly();</script></{tag}>'
                source = fake + '<script lang="ts">actual();</script>'
                units = AST._svelte(source)
                self.assertEqual(len(units), 1)
                self.assertEqual(units[0]['text'], 'actual();')
                self.assertEqual(units[0]['offset'], source.index('actual();'))
                with self.assertRaises(AST.ASTError) as error:
                    AST._svelte(fake)
                self.assertEqual(error.exception.code, 'SVELTE_NO_SCRIPT')

    def test_executor_closes_group_on_normal_exit_and_interrupt(self):
        process=mock.Mock(pid=12345);process.poll.return_value=0;process.returncode=0
        with mock.patch.object(AST.subprocess,'Popen',return_value=process) as popen, mock.patch.object(AST.os,'killpg') as kill:
            AST.Executor().run(['/synthetic'],cwd=self.tmp.name,env={},timeout=1,max_output_bytes=100)
        self.assertTrue(popen.call_args.kwargs['close_fds']);self.assertEqual(popen.call_args.kwargs['pass_fds'],())
        self.assertEqual(popen.call_args.kwargs['stdin'],subprocess.DEVNULL)
        kill.assert_called_once_with(12345,signal.SIGKILL)
        process.poll.side_effect=KeyboardInterrupt
        with mock.patch.object(AST.subprocess,'Popen',return_value=process),mock.patch.object(AST.os,'killpg') as kill:
            with self.assertRaises(KeyboardInterrupt):
                AST.Executor().run(['/synthetic'],cwd=self.tmp.name,env={},timeout=1,max_output_bytes=100)
        kill.assert_called_once_with(12345,signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
