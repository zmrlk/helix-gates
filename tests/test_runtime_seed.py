"""Dane syntetyczne dla pustych tabel czytanych przez kod oraz porządkowanie formy pokrycia przeglądu bezpieczeństwa."""
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_seed as S
import helix_security_deep as D



class GuardRoles(unittest.TestCase):
    # Projekt B: konto testowe dostało rolę „it”, a 9 tras wymaga „manager” albo „advisor” (przekierowanie na start).
    def test_role_admitted_by_most_route_guards_goes_to_the_test_user(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'src').mkdir()
            Path(d, 'src', 'App.tsx').write_text('<Route path="/a" element={<PrivateRoute requiredRoles={["manager", "it"]} />} />\n'
                                                 '<Route path="/b" element={<PrivateRoute requiredRoles={["manager"]} />} />\n'
                                                 '<Guard allowedRoles={[\'advisor\', "it"]} /><Guard roles={["manager"]} />')
            Path(d, 'node_modules').mkdir(); Path(d, 'node_modules', 'x.tsx').write_text('<G requiredRoles={["obcy"]} />')
            roles = S.guard_roles(Path(d))
            self.assertEqual(roles, {'manager': 3, 'it': 2, 'advisor': 1})
            text = S.prompt(['profiles'], {'profiles': []}, {}, {}, {}, {}, {}, 'u-1', roles)
            self.assertIn('Użytkownik testowy ma mieć rolę „manager”', text)
            self.assertNotIn('rolę „', S.prompt(['profiles'], {'profiles': []}, {}, {}, {}, {}, {}, 'u-1'))

class FakeDatabase:
    """Minimalna baza: tabele, kolumny, powiązanie, liczba wierszy; INSERT do znanej tabeli dodaje wiersze."""
    def __init__(self):
        self.rows = {'menu_configuration': 0, 'orders': 0, 'profiles': 1, 'unused_table': 0}
        self.statements = []

    def sql(self, query):
        if 'information_schema.tables' in query:
            return '\n'.join(self.rows)
        if 'information_schema.columns' in query:
            return '\n'.join(S.SEP.join(row) for row in (
                ('menu_configuration', 'id', 'uuid', 'uuid', 'NO', 'gen_random_uuid()'),
                ('menu_configuration', 'label', 'text', 'text', 'NO', ''),
                ('orders', 'id', 'uuid', 'uuid', 'NO', ''),
                ('orders', 'menu_id', 'uuid', 'uuid', 'YES', '')))
        if 'FOREIGN KEY' in query:
            return S.SEP.join(('orders', 'menu_id', 'menu_configuration', 'id'))
        if 'pg_enum' in query or 'pg_constraint' in query:
            return ''
        if 'union all' in query or query.startswith("select '"):
            return '\n'.join(S.SEP.join((table, str(self.rows[table]))) for table in self.rows if "'%s'" % table in query)
        if query.startswith('select id::text'):
            return '\n'.join('00000000-0000-0000-0000-00000000000%d' % i for i in range(1, self.rows['menu_configuration'] + 1))
        return ''

    def execute(self, statement):
        self.statements.append(statement)
        table = statement.split('public."')[1].split('"')[0]
        if 'BŁĄD' in statement: return 'ERROR: invalid input syntax for type uuid'
        self.rows[table] += statement.count('), (') + 1
        return None


class SyntheticData(unittest.TestCase):
    def project(self):
        folder = Path(tempfile.mkdtemp())
        (folder / 'src').mkdir()
        (folder / 'src' / 'menu.tsx').write_text("const { data } = await supabase.from('menu_configuration').select('label');\n")
        (folder / 'src' / 'orders.ts').write_text("supabase.from('orders').select('*').eq('menu_id', id);\nsupabase.from('profiles').select('*');\n")
        (folder / 'node_modules' / 'x').mkdir(parents=True)
        (folder / 'node_modules' / 'x' / 'a.js').write_text("x.from('unused_table')")
        return folder

    def test_only_empty_tables_read_by_the_code_are_filled_configuration_first_and_errors_go_back_once(self):
        database, prompts = FakeDatabase(), []
        answers = iter([
            json.dumps({'tables': [{'table': 'menu_configuration', 'rows': [{'id': 'a', 'label': 'Magazyn'}, {'id': 'b', 'label': 'Operacje'}]}]}),
            json.dumps({'tables': [{'table': 'orders', 'rows': [{'id': 'BŁĄD'}]}, {'table': 'profiles', 'rows': [{'id': 'x'}]}]}),
            json.dumps({'tables': [{'table': 'orders', 'rows': [{'id': 'o1', 'menu_id': 'a'}]}]}),
        ])
        def ask(prompt):
            prompts.append(prompt); return '```json\n' + next(answers) + '\n```'
        report = S.seed(database.sql, database.execute, ask, self.project(), 'user-1', batch_size=1)
        self.assertEqual((report['status'], report['empty_tables'], sorted(report['filled']), report['model_calls']), ('SEEDED', 2, ['menu_configuration', 'orders'], 3))
        self.assertIn('## Tabela public.menu_configuration', prompts[0])   # konfiguracja przed danymi roboczymi
        self.assertIn('menu_configuration: 00000000-0000-0000-0000-000000000001', prompts[1])   # istniejące identyfikatory do powiązań
        self.assertIn('invalid input syntax for type uuid', prompts[2])   # błąd bazy wraca do modelu jeden raz
        self.assertFalse(any('profiles' in s for s in database.statements))   # tylko tabele z bieżącej partii
        self.assertNotIn('unused_table', ' '.join(prompts))   # node_modules nie liczy się jako kod aplikacji
        self.assertEqual(report['errors'], [])

    def test_model_supplies_values_only_and_helix_builds_the_insert(self):
        database = FakeDatabase()
        answer = json.dumps({'tables': [{'table': 'menu_configuration', 'sql': 'DROP TABLE public.orders',
            'rows': [{'id': 'a', 'label': "x'); DROP TABLE public.orders; --", 'evil': "pg_read_file('/etc/passwd')"}]},
            {'table': 'orders', 'rows': [{'id': 'o'}]}]})
        S.seed(database.sql, database.execute, lambda prompt: answer, self.project(), 'user-1', only=['menu_configuration'])
        self.assertEqual(len(database.statements), 1)
        statement = database.statements[0]
        self.assertTrue(statement.startswith('INSERT INTO public."menu_configuration" ("id", "label") VALUES ('))
        self.assertIn("'x''); DROP TABLE public.orders; --'::text", statement)   # tekst pozostaje literałem
        self.assertNotIn('pg_read_file', statement); self.assertNotIn('DROP TABLE public.orders\'', statement)


class ToolState(unittest.TestCase):
    def test_memsearch_written_by_model_sessions_is_not_project_source(self):
        # Hak memsearch sesji Codexa i Groka zapisał .memsearch/ w kopii projektu B i zmienił źródła przeglądu.
        import subprocess
        import helix_source_coverage as C
        repo = Path(tempfile.mkdtemp())
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        (repo / 'src').mkdir(); (repo / 'src' / 'a.ts').write_text('export const a = 1;\n')
        (repo / '.memsearch' / 'memory').mkdir(parents=True); (repo / '.memsearch' / '.index-state.json').write_text('{}')
        names, method = C.paths(repo)
        self.assertEqual((method, names), ('git', ['src/a.ts']))
        batches, units = D.context_plan(repo, ['.'], 'standard')
        self.assertEqual([u['unit'] for u in units], ['src/a.ts'])
        # Przegląd bezpieczeństwa commita: plik śledzony przez git w .memsearch/ nie znika z przeglądu.
        (repo / '.memsearch' / 'ukryty.ts').write_text('export const b = 2;\n')
        subprocess.run(['git', '-C', str(repo), 'add', '-f', '.memsearch/ukryty.ts'], check=True)
        self.assertEqual(C.paths(repo)[0], ['.memsearch/ukryty.ts', 'src/a.ts'])
        self.assertEqual(sorted(u['unit'] for u in D.context_plan(repo, ['.'], 'standard')[1]), ['.memsearch/ukryty.ts', 'src/a.ts'])
        # Bez gita katalog na najwyższym poziomie zostaje w wyniku jako pominięty, nie znika.
        with unittest.mock.patch('helix_git_readonly.git', side_effect=OSError('brak gita')):
            names, method = C.paths(repo)
        self.assertIn('.memsearch', names); self.assertNotIn('.memsearch/ukryty.ts', names); self.assertTrue(method.startswith('filesystem'))


class Literals(unittest.TestCase):
    def test_quotes_in_array_elements_stay_inside_the_literal(self):
        column = dict(name='tags', udt='_text', kind='ARRAY')
        value = S.literal(["a'); DROP TABLE public.orders; --", 'b"c', None], column)
        self.assertEqual(value, "'{\"a''); DROP TABLE public.orders; --\",\"b\\\"c\",NULL}'::text[]")
        body = value[1:value.rindex("'::")]
        self.assertNotIn("'", body.replace("''", ''))   # żaden pojedynczy apostrof nie kończy literału


class CoverageForm(unittest.TestCase):
    def test_identifier_is_derived_from_canonical_refs_and_units_are_sorted(self):
        refs = lambda surface: dict(surface=surface, boundary='src/b.ts#f', subsystem='packages/x', attack_class='ATTACK-CLASSES.md#Access control')
        ledger = [dict(coverage_id='zzz', canonical_refs=refs('src/z.tsx#a')), dict(coverage_id='bad id', canonical_refs=refs('src/a.tsx#b'))]
        fixed = D.canonical_ledger(ledger)
        self.assertEqual([u['coverage_id'].split('::')[0] for u in fixed], ['src%2Fa.tsx%23b', 'src%2Fz.tsx%23a'])
        self.assertTrue(fixed[0]['coverage_id'].endswith('::ATTACK-CLASSES.md%23Access%20control'))

    def test_candidate_files_are_found_in_any_field_and_form(self):
        known = {'src/a.ts', 'src/a.tsx', 'supabase/m.sql', 'src/other.ts'}
        forms = [dict(evidence=[dict(file='src/a.tsx')]), dict(evidence=[dict(path='src/a.tsx', lines='1-2')]),
                 dict(evidence='In src/a.tsx lines 4-16: ...'), dict(evidence=dict(source_reference='src/a.tsx#L68-L72')),
                 dict(trace=[dict(step=1, file='src/a.tsx')])]
        for candidate in forms:
            self.assertEqual(D.candidate_paths(candidate, known), {'src/a.tsx'}, candidate)   # .ts nie łapie się na .tsx
        self.assertEqual(D.candidate_paths(dict(evidence='brak pliku'), known), set())
        # G3 16.11: cała ścieżka, nie końcówka; kropka kończąca zdanie; ./ i ścieżka bezwzględna do kopii.
        known = {'src/auth.ts', 'apps/web/src/auth.ts', 'app/[id]/page.tsx'}
        self.assertEqual(D.candidate_paths(dict(evidence='apps/web/src/auth.ts:12'), known), {'apps/web/src/auth.ts'})
        self.assertEqual(D.candidate_paths(dict(evidence='Błąd w src/auth.ts.'), known), {'src/auth.ts'})
        self.assertEqual(D.candidate_paths(dict(evidence='./src/auth.ts#L3'), known), {'src/auth.ts'})
        self.assertEqual(D.candidate_paths(dict(evidence='/Users/x/kopia/apps/web/src/auth.ts'), known, '/Users/x/kopia'), {'apps/web/src/auth.ts'})
        self.assertEqual(D.candidate_paths(dict(evidence='zob. [app/[id]/page.tsx]'), known), {'app/[id]/page.tsx'})
        # G3 r2: nawiasy, $ i spacje w nazwie pliku.
        known = {'src/app/(auth)/login/page.tsx', 'src/routes/users.$id.tsx', 'src/moje pliki/a.ts', 'src/auth.ts'}
        for name in known:
            self.assertEqual(D.candidate_paths(dict(evidence=dict(file=name)), known), {name})
            self.assertEqual(D.candidate_paths(dict(evidence='Zob. (' + name + ').'), known), {name})
        self.assertEqual(D.candidate_paths(dict(evidence='linia\nsrc/auth.ts'), known), {'src/auth.ts'})
        # Zawężone sprawdzenie G3: spacja w pełnej ścieżce nie robi z jej końcówki osobnego pliku.
        self.assertEqual(D.candidate_paths(dict(file='src/my files/a.ts'), {'src/my files/a.ts', 'files/a.ts'}), {'src/my files/a.ts'})

    def test_model_json_tolerates_regex_escapes_control_characters_and_a_restarted_answer(self):
        self.assertEqual(D.model_json('{"a": "`\\d+` i \\\\ i \\n"}'), {'a': '`\\d+` i \\ i \n'})   # \d bez podwojenia
        self.assertEqual(D.model_json('{"a": "linia\tpo tabulatorze"}'), {'a': 'linia\tpo tabulatorze'})
        self.assertEqual(D.model_json('{"a": "urwane, "b\n{"a": 1}\n'), {'a': 1})   # model zaczął od nowa
        with self.assertRaises(json.JSONDecodeError): D.model_json('{"a": ')
        # G3 16.11: obiekt zacytowany w środku odpowiedzi i pierwszy z dwóch obiektów nie są odpowiedzią.
        quoted = '{"uszkodzony": "\\q\nźródło:\n{"verdict": "rejected"}\nkoniec opisu'
        with self.assertRaises(json.JSONDecodeError): D.model_json(quoted)
        with self.assertRaises(ValueError): D.model_json('{"v": 1, "x": "\\d"}\n{"v": 2, "x": "\\d"}\n')   # dwa obiekty
        # G3 r2: dwa bloki ```json z różnymi werdyktami to odpowiedź niejednoznaczna; jeden blok z komentarzem wokół jest jednoznaczny.
        with self.assertRaises(ValueError): D.model_json('```json\n{"verdict": "rejected"}\n```\npoprawka:\n```json\n{"verdict": "confirmed"}\n```')
        self.assertEqual(D.model_json('Wynik:\n```json\n{"verdict": "rejected"}\n```\nKoniec.'), {'verdict': 'rejected'})
        with self.assertRaises(json.JSONDecodeError): D.model_json('Wynik: {"verdict": "rejected"} i dalszy komentarz')
        # Zawężone sprawdzenie G3: drugi, wcięty obiekt po bloku to też niejednoznaczność; fragmenty wewnątrz JSON-a nie.
        with self.assertRaises(ValueError): D.model_json('```json\n{"verdict":"rejected"}\n```\n  {"verdict":"confirmed"}')
        self.assertEqual(D.model_json('Wynik:\n{\n  "a": [{"b": 1}, {"c": 2}],\n  "d": {"e": 3}\n}\n'), {'a': [{'b': 1}, {'c': 2}], 'd': {'e': 3}})
        self.assertEqual(D.model_json('{"x": [{"p": 1}, {"q": "\\d"}], "urw\n{"x": [{"p": 1}], "y": "\\s"}'), {'x': [{'p': 1}], 'y': '\\s'})


if __name__ == '__main__':
    unittest.main()
