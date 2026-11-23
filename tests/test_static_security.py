"""Hand-labelled synthetic security oracle and source-only integration tests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_lenses as lenses
import helix_static_security as security
ROOT=Path(__file__).resolve().parents[1]
FIXTURES=ROOT/'tests/fixtures/security-deep'

# These older oracle fixtures declare their opaque guard API explicitly. Tests
# of default (unconfigured) recognition live in test_guard_contracts.py.
def declared_guard_scan(repo, **kwargs):
    contract = {'identity_guards': ['requireAuth', 'requireRole'],
                'middleware_factories': ['requireAuth', 'requireRole'],
                'scope_guards': ['checkOwnership'], 'record_context_guards': ['requireCan']}
    with patch('helix_guard_contracts.project_config', return_value={'static_security': contract}):
        return security.analyze(repo, **kwargs)


class StaticSecurityTests(unittest.TestCase):
    def test_precision_recall(self):
        manifest=json.loads((FIXTURES/'expected.json').read_text())
        tp=fp=fn=0
        for case, labels in manifest.items():
            expected={tuple(x) for x in labels}
            actual={(place['file'],place['line'],f['id'])
                    for f in declared_guard_scan(FIXTURES/case)['findings']
                    for place in f.get('locations', [f])}
            tp+=len(expected & actual);fp+=len(actual-expected);fn+=len(expected-actual)
            self.assertEqual(actual,expected,case)
        self.assertEqual(fn,0)
        self.assertEqual(fp,0)
        self.assertEqual(tp,27)

    def test_all_registered_lenses_and_ranking(self):
        data=lenses.report(FIXTURES/'express')
        self.assertEqual(set(data['lenses']), set(lenses.REGISTRY))
        self.assertIn('repo_hygiene', data['lenses'])
        self.assertEqual(data['findings'],lenses.deduplicate(data['findings']*2))
        self.assertEqual(lenses.ui.score([]),0)
        for lens in data['lenses'].values():
            self.assertTrue(lens['checklist'])
            self.assertTrue(lens['adversarial_pass']['checks'])
        visual=lenses.report(ROOT/'tests/fixtures/ui-deep/bad')
        self.assertTrue(any(f['lens']=='ux_designer' for f in visual['findings']))
        self.assertTrue(any(f['lens']=='ui_designer' for f in visual['findings']))

    def test_handler_auth_does_not_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'routes.ts').write_text("router.get('/a', requireAuth(), () => {});\nrouter.get('/b', () => {});")
            result=declared_guard_scan(tmp)
            self.assertEqual([r['auth'] for r in result['endpoints']],['local_guard','unknown'])
            self.assertEqual([f['line'] for f in result['findings'] if f['id']=='SEC-AUTH'],[2])

    def test_read_only_cli_and_safe_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'target';target.mkdir()
            (target/'route.ts').write_text('export const GET = () => { throw Error("never execute"); };')
            out=Path(tmp)/'out';out.mkdir()
            (out/'review-deep.json').symlink_to(target/'route.ts')
            before=(target/'route.ts').read_text()
            result=subprocess.run([str(ROOT/'bin/helix'),'review','deep',str(target),'--out',str(out)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(set(json.loads(result.stdout)['lenses']), set(lenses.REGISTRY))
            self.assertEqual((target/'route.ts').read_text(),before)
            self.assertFalse((out/'review-deep.json').is_symlink())
            result=subprocess.run([str(ROOT/'bin/helix'),'review','deep',str(target),'--out',str(target/'out')],capture_output=True)
            self.assertEqual(result.returncode,2)
            self.assertFalse((target/'out').exists())

    def test_symlinks_private_and_comment_mask(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'secret.ts').write_text('exec(req.body.command)')
            (root/'linked.ts').symlink_to(root/'secret.ts')
            (root/'.aws').mkdir();(root/'.aws'/'code.ts').write_text('exec(req.body.command)')
            (root/'source.ts').write_text('/* exec(req.body.command) */\n// exec(req.body.command)\n')
            self.assertEqual(declared_guard_scan(root)['findings'],[])

    def test_schema_and_report_claims(self):
        schema=json.loads((ROOT/'schemas/review_deep.json').read_text())
        data=lenses.report(FIXTURES/'next')
        self.assertTrue(set(schema['required']) <= set(data))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'report.md').write_text('SEC-123 high fixed SEC-SQL\nSEC-124 low resolved\n')
            (root/'source.js').write_text('db.query(`SELECT ${req.query.id}`)')
            claims=declared_guard_scan(root)['reported_findings']
            self.assertEqual([c['status'] for c in claims],['open','unknown'])



class OfflineAndStructuralTests(unittest.TestCase):
    def test_offline_exact_versions_and_redacted_history(self):
        import helix_security_offline as offline
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'package-lock.json').write_text(json.dumps({'packages':{'node_modules/sample-lib':{'version':'1.0.0'}}}))
            (root/'requirements.txt').write_text('example-lib==2.0.0\n')
            (root/'pnpm-lock.yaml').write_text('packages:\n  example-pkg@3.0.0:\n')
            (root/'yarn.lock').write_text('"demo-lib@^4.0.0":\n  version "4.0.0"\n')
            self.assertEqual({x[:2] for x in offline.dependencies(root)},
                {('sample-lib','1.0.0'),('example-lib','2.0.0'),('example-pkg','3.0.0'),('demo-lib','4.0.0')})
            db=root/'advisories.json';db.write_text(json.dumps({'advisories':[{'package':'sample-lib','versions':['1.0.0'],'severity':'critical'}]}))
            meta=root/'scan.json';meta.write_text(json.dumps({'redacted':True,'findings':[{'file':'src/code.ts','line':4,'scope':'history','Secret':'MUST_NEVER_APPEAR'}]}))
            data=lenses.report(root,db,meta)
            self.assertIn('SEC-DEPENDENCY',{x['id'] for x in data['findings']})
            self.assertIn('SEC-SECRET',{x['id'] for x in data['findings']})
            self.assertNotIn('MUST_NEVER_APPEAR',json.dumps(data))
            self.assertEqual(data['offline_audits']['secrets']['history'],'reported')
            self.assertEqual(data['findings'][0]['severity'],'critical')
            meta.write_text('[]')
            with self.assertRaises(ValueError):
                lenses.report(root,gitleaks_report=meta)

    def test_cycles_negative_tests_and_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'tests').mkdir()
            (root/'a.ts').write_text("import b from './b';\n// TODO implement error state\ntry {} catch(e) {}")
            (root/'b.ts').write_text("import a from './a';")
            (root/'tests'/'routes.test.ts').write_text('await page.waitForTimeout(1000);')
            (root/'README.md').write_text('[Missing](missing.md)')
            data=lenses.report(root)
            self.assertTrue({'ARCH-CYCLE','QA-FLAKY','PM-TODO','DEV-ERROR','DOC-LINK'} <= {f['id'] for f in data['findings']})

    def test_safe_sinks_and_upload_partial_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'safe.ts').write_text('''db.query('SELECT * FROM items WHERE id=$1', [id]);
fetch('https://example.invalid');
redirect('/home');
execFile('ls', ['-l']);
readFile('/public/index.html');
const isAdmin = false;
const allowedTypes = ['image/png'];
const maxFileSize = 1024;
upload(req);
''')
            self.assertEqual(declared_guard_scan(root)['findings'],[])
            (root/'partial.ts').write_text('const maxFileSize = 1024;\nupload(req);')
            self.assertEqual([f['id'] for f in declared_guard_scan(root)['findings']],['SEC-UPLOAD'])

    def test_one_hop_taint_and_reassignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'source.ts').write_text("const target = req.query.url;\nfetch(target);\nconst path = req.query.path;\npath = '/public';\nreadFile(path);")
            rows=declared_guard_scan(root)['findings']
            self.assertEqual([(f['id'],f['line']) for f in rows],[('SEC-SSRF',2)])

    def test_python_go_inventory_and_special_files(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'api.py').write_text("@app.get('/items')\ndef items():\n    return []\n")
            (root/'server.go').write_text('http.HandleFunc("/items", handler)')
            if hasattr(os,'mkfifo'):
                os.mkfifo(root/'pipe.ts')
            data=lenses.report(root)
            self.assertEqual(len(data['endpoints']),2)
            self.assertEqual({r['path'] for r in data['endpoints']},{'/items'})


if __name__ == '__main__':
    unittest.main()

class CalibrationRegressionTests(unittest.TestCase):
    def test_regex_exec_local_dispatch_sql_upload_and_colocated_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'hook.ts').write_text("new RegExp('x').exec(request.body);\n")
            (root/'view.svelte').write_text("<script>function exec(command) { command.run(); }\nexec({run: () => goto(`${params.id}`)});</script>")
            (root/'schema.sql').write_text('CREATE TABLE images (image text REFERENCES upload(id));')
            (root/'auth.test.ts').write_text('exec(req.body.command)')
            self.assertFalse(declared_guard_scan(root)['findings'])
            self.assertIn('auth.test.ts',dict(security.sources(root,include_tests=True)))
            (root/'real.ts').write_text('exec(req.body.command)')
            self.assertTrue(any(f['id']=='SEC-SHELL' for f in declared_guard_scan(root)['findings']))

    def test_shell_namespace_and_local_wrapper_keep_real_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'source.ts').write_text("function exec(command) { return command.run(); }\nchild_process.exec(req.body.command);\nexecSync(req.body.command);")
            self.assertEqual(len([f for f in declared_guard_scan(root)['findings'] if f['id']=='SEC-SHELL']),2)
            (root/'source.ts').write_text("const exec = require('child_process').exec;\nexec(req.body.command);")
            self.assertTrue(any(f['id']=='SEC-SHELL' for f in declared_guard_scan(root)['findings']))

    def test_coverage_and_bounded_leading_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'route.ts').write_text('\n'.join("router.get('/x', () => {});" for _ in range(15)))
            (root/'unsupported.bin').write_bytes(b'xx')
            (root/'secret.ts').write_text('not to be inspected')
            (root/'migration.sql').write_text('DROP TABLE example;')
            (root/'.private').mkdir()
            (root/'.private'/'hidden.ts').write_text('not inspected')
            data = lenses.report(root)
            cov = data['coverage']
            self.assertEqual(cov['files_enumerated'],4)
            self.assertEqual(cov['files_analyzed'],2)
            self.assertEqual(cov['files_skipped'],2)
            self.assertEqual(cov['migrations']['analyzed'],1)
            self.assertEqual(cov['handlers']['detected'],15)
            self.assertEqual(cov['excluded_subtrees'][0]['descendant_files'],None)
            md = lenses.markdown(data)
            # The verifier boundary added on master excludes unconfirmed
            # static candidates from the owner's leading findings.
            self.assertEqual(data['owner_findings'], [])
            self.assertEqual(md.split('## Pokrycie')[0].count('Dlaczego:'),0)
            self.assertIn('Adversarial pass',md)
            self.assertEqual(lenses.evidence_summary(['a:1','b:2','c:3','Łącznie: 99']), 'a:1; b:2; c:3 (łącznie: 99)')

    def test_type_only_imports_do_not_form_runtime_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'render.ts').write_text("import {validate} from './validate';\nexport type Zone = string;")
            (root/'validate.ts').write_text("import type {Zone} from './render';\nexport function validate(x: Zone) { return x; }")
            self.assertFalse(any(f['id']=='ARCH-CYCLE' for f in lenses.report(root)['findings']))
            (root/'validate.ts').write_text("import type {Zone} from './render'\nimport {render} from './render';\n")
            self.assertTrue(any(f['id']=='ARCH-CYCLE' for f in lenses.report(root)['findings']))
            (root/'validate.ts').write_text("import {render} from './render';\nexport function validate() { return render(); }")
            self.assertTrue(any(f['id']=='ARCH-CYCLE' for f in lenses.report(root)['findings']))

    def test_comment_markup_and_hidden_honeypot_are_not_missing_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'hook.ts').write_text('// browser supports <input capture>\n')
            (root/'view.svelte').write_text('<input aria-hidden="true" tabindex="-1" name="trap"><input name="visible">')
            rows = lenses.ui.run(root)
            labels = [f for f in rows if f['id']=='UX-LABEL']
            self.assertEqual(len(labels),1)
            self.assertEqual(labels[0]['file'],'view.svelte')

    def test_delegated_object_read_needs_scope_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'route.ts').write_text("export const GET = async ({params,locals}) => { if (!locals.user) throw Error(); return getDocumentsForProject(params.id); };\nexport const POST = async ({params,locals}) => { await checkOwnership(params.id, locals.user.id); return getDocumentsForProject(params.id); };")
            rows = [f for f in declared_guard_scan(root)['findings'] if f['id']=='SEC-OBJECT-CALL']
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['line'],1)
            self.assertEqual(rows[0]['confidence'],'possible')

    def test_async_foreach_results_need_explicit_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'upload.ts').write_text('async function uploadFile(file) { await send(file); }\nfiles.forEach(uploadFile);')
            rows = lenses.report(root)['findings']
            self.assertEqual(len([f for f in rows if f['id']=='DEV-ASYNC-FOREACH']),1)
            (root/'upload.ts').write_text('async function uploadFile(file) { await send(file); }\nawait Promise.allSettled(files.map(uploadFile));')
            self.assertFalse(any(f['id']=='DEV-ASYNC-FOREACH' for f in lenses.report(root)['findings']))

    def test_parameterized_tagged_sql_still_needs_object_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'route.ts').write_text('export const GET = async ({params}) => { return await sql`SELECT * FROM documents WHERE id = ${params.id}`; };')
            rows = declared_guard_scan(root)['findings']
            self.assertTrue(any(f['id']=='SEC-IDOR' for f in rows))
            self.assertFalse(any(f['id']=='SEC-SQL' for f in rows))
            (root/'route.ts').write_text('export const GET = async ({params,locals}) => { return await sql`SELECT * FROM documents WHERE id = ${params.id} AND owner_id = ${locals.user.id}`; };')
            self.assertFalse(any(f['id']=='SEC-IDOR' for f in declared_guard_scan(root)['findings']))
            (root/'route.ts').write_text("export const GET = async ({params,locals}) => { const row = await sql`SELECT * FROM documents WHERE id = ${params.id}`; await checkOwnership(params.id, locals.user.id); return row; };")
            self.assertFalse(any(f['id']=='SEC-IDOR' for f in declared_guard_scan(root)['findings']))

    def test_transaction_tag_alias_preserves_object_scope_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            route = root / 'route.ts'
            body = "const t = tx as unknown as Database; const q = t; return await q`UPDATE records SET priority = 1 WHERE id = ${params.id}`;"
            route.write_text("export const POST = async ({params,locals}) => { " + body + " };")
            self.assertTrue(any(f['id'] == 'SEC-IDOR' for f in declared_guard_scan(root)['findings']))
            route.write_text("export const POST = async ({params,locals}) => { await checkOwnership(params.id, locals.user.id); " + body + " };")
            self.assertFalse(any(f['id'] == 'SEC-IDOR' for f in declared_guard_scan(root)['findings']))
            route.write_text("export const POST = async ({params}) => { const t = render; return t`SELECT text ${params.id}`; };")
            self.assertFalse(any(f['id'] == 'SEC-IDOR' for f in declared_guard_scan(root)['findings']))


class ReviewBlockerRegressionTests(unittest.TestCase):
    def test_custom_guard_name_does_not_prove_scope(self):
        for guard in ('customGuard', 'requireCan', 'requireLeadAccess'):
            with self.subTest(guard=guard), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root/'route.ts').write_text("export const GET = async ({params}) => { await "+guard+"({row}); const item = db.findUnique({id: params.id}); return getItem(params.id); };")
                codes = {f['id'] for f in declared_guard_scan(root)['findings']}
                self.assertTrue({'SEC-IDOR', 'SEC-OBJECT-CALL'} <= codes)

    def test_delegated_reads_across_request_conventions(self):
        for value in ('params.id', 'event.params.id', 'req.params.id', 'request.params.id', "req.params['id']"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root/'route.ts').write_text("router.get('/items/:id', async (req, res) => { customGuard(); return getItem("+value+"); });")
                self.assertIn('SEC-OBJECT-CALL', {f['id'] for f in declared_guard_scan(root)['findings']})
                (root/'route.ts').write_text("router.get('/items/:id', async (req, res) => { checkOwnership("+value+", user.id); return getItem("+value+"); });")
                self.assertNotIn('SEC-OBJECT-CALL', {f['id'] for f in declared_guard_scan(root)['findings']})

    def test_inline_async_foreach_and_sync_negative(self):
        for callback in ('async (item) => { await send(item); }', 'async item => send(item)', 'async function(item) { await send(item); }'):
            with self.subTest(callback=callback), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root/'work.ts').write_text('items.forEach('+callback+');')
                self.assertEqual([(f['id'], f['line']) for f in lenses.structural_signals(root, [])], [('DEV-ASYNC-FOREACH', 1)])
                # Full-line comments are masked by the lexical analyzer.
                (root/'work.ts').write_text('items.forEach(item => send(item));\n// .forEach(async x => send(x))')
                self.assertFalse(lenses.structural_signals(root, []))

    def test_report_correlation_requires_inspected_location_for_likely_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'report.md').write_text('## VULN-1 high fixed SQL injection in `api.ts:1`\n## VULN-2 high fixed SQL injection in `missing.ts:1`\n## VULN-3 high fixed Unrecognized problem in `api.ts:1`\n## VULN-4 low fixed SQL injection\n')
            source = root/'api.ts'
            source.write_text('db.query(`SELECT ${req.query.id}`)')
            self.assertEqual([c['status'] for c in declared_guard_scan(root)['reported_findings']], ['open', 'unknown', 'unknown', 'open'])
            source.write_text("db.query('SELECT * FROM items WHERE id=$1', [id]);")
            claims = declared_guard_scan(root)['reported_findings']
            self.assertEqual([c['status'] for c in claims], ['likely-fixed', 'unknown', 'unknown', 'unknown'])
            self.assertIn('api.ts:1', claims[0]['evidence'])
            source.unlink()
            self.assertEqual(declared_guard_scan(root)['reported_findings'][0]['status'], 'unknown')
