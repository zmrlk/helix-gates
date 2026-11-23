"""Zachowania domykające po pełnych przebiegach na trzech projektach: sesja wygasająca w trakcie przeglądu,
ekran szczegółów osiągany kliknięciem wiersza, żądania z danych syntetycznych, część główna delegująca do podkatalogu."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime
import helix_visual


def audit(folder, url, status='passed', errors=(), states=()):
    folder.mkdir(parents=True, exist_ok=True)
    run = dict(finalURL=url, httpStatus=200, errors=[], states=list(states))
    (folder/'audit.json').write_text(json.dumps(dict(url=url, errors=list(errors), runs=[run],
        summary=dict(status=status, complete=status == 'passed', completed=1, planned=1, blockers=0))))


class SessionRenewal(unittest.TestCase):
    def run_audits(self, lost, **extra):
        calls, renewals = [], []
        with tempfile.TemporaryDirectory() as directory:
            def execute(argv, cwd, maximum):
                calls.append(argv[2]); folder = Path(argv[argv.index('--out')+1]); route = argv[argv.index('--case')+1]
                dead = route in lost and calls.count(argv[2]) <= lost[route]
                audit(folder, argv[2], *(('incomplete', ['Trasa odsyła na inny ekran; pominięto pozostałe pomiary (1 z 2)']) if dead else ()),
                      states=extra.get('states', {}).get(route, ()))
            state = Path(directory)/'session.json'; state.write_text('{}')
            data = helix_visual.runtime_audits(execute, 'node', Path(directory), 'https://localhost:1', ['/a', '/b'], Path(directory)/'out', weight_result={},
                                               storage_state=state, renew=lambda route: renewals.append(route) or True, patterns=extra.get('patterns', ()))
        return data, calls, renewals

    def test_expired_session_is_renewed_once_and_the_route_measured_again(self):
        data, calls, renewals = self.run_audits({'/a': 1})
        self.assertEqual([row['status'] for row in data['visual']], ['passed', 'passed'])
        self.assertEqual((len(renewals), data['session_renewals'], len(calls)), (1, 1, 3))

    def test_redirect_right_after_renewal_is_the_route_itself_not_a_dead_session(self):
        data, calls, renewals = self.run_audits({'/a': 1, '/b': 9})
        self.assertEqual([row['status'] for row in data['visual']], ['passed', 'incomplete'])
        self.assertEqual(len(renewals), 1)

    def test_detail_screen_reached_by_a_row_click_is_measured_once_per_pattern(self):
        states = {'/a': [dict(kind='navigation', target='/rzecz/7'), dict(kind='navigation', target='/rzecz/8'), dict(kind='navigation', target='/b')]}
        data, calls, _ = self.run_audits({}, states=states, patterns=['/rzecz/[id]', '/inne/[id]'])
        self.assertEqual([row['route'] for row in data['visual']], ['/a', '/b', '/rzecz/7'])
        self.assertEqual(data['reached_by_click'], [dict(pattern='/rzecz/[id]', route='/rzecz/7', reached_from='/a')])


class SmallRules(unittest.TestCase):
    def test_404_caused_by_the_synthetic_placeholder_is_not_an_application_error(self):
        row = lambda url, status=404, source='app': dict(url=url, status=status, source=source)
        self.assertTrue(helix_runtime.synthetic_request(row('https://localhost:1/media/synthetic-item')))
        self.assertTrue(helix_runtime.synthetic_request(row('https://localhost:1/synthetic-item%203')))
        self.assertTrue(helix_runtime.synthetic_request(row('https://localhost:1/media/bardzo%20d%C5%82uga%20nazwa%20pozycji%20testowej%20bardzo')))
        self.assertFalse(helix_runtime.synthetic_request(row('https://localhost:1/synthetic-item/edit')))
        self.assertFalse(helix_runtime.synthetic_request(row('https://localhost:1/media/synthetic-item', 500)))
        self.assertFalse(helix_runtime.synthetic_request(row('https://localhost:1/logo.png')))

    def test_scenario_without_a_part_does_not_run_for_an_api_only_part(self):
        fake = type('Fake', (), {'config': dict(runtime=dict(scenarios=[dict(id='ekran'), dict(id='api', part='apps/api')]))})()
        pick = lambda part: [row['id'] for row in helix_runtime.Runner.declared_scenarios(fake, part)]
        self.assertEqual(pick(dict(path='apps/web')), ['ekran'])
        self.assertEqual(pick(dict(path='apps/api', api_only='non-HTML content')), ['api'])

    def test_root_with_its_own_start_script_stays_a_part_even_when_another_script_delegates(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'package.json').write_text('{"name":"root","scripts":{"start":"node server.js","build:web":"npm --prefix apps/web run build"},"dependencies":{"express":"4"}}')
            Path(d, 'server.js').write_text('require("express")().listen(process.env.PORT)\n')
            Path(d, 'apps', 'web').mkdir(parents=True)
            Path(d, 'apps', 'web', 'package.json').write_text('{"name":"web","scripts":{"dev":"vite dev","build":"vite build"},"devDependencies":{"vite":"5","@sveltejs/kit":"2"}}')
            self.assertIn('.', [part['path'] for part in helix_runtime.plan(Path(d))['parts']])

    def test_root_launcher_mixing_local_and_delegated_execution_stays_a_part(self):
        for launcher in ('concurrently "vite" "npm --prefix apps/web run dev"', 'npm --prefix apps/web run dev\nvite'):
          with self.subTest(launcher), tempfile.TemporaryDirectory() as d:
            Path(d, 'package.json').write_text(json.dumps(dict(name='root', scripts=dict(dev=launcher), devDependencies=dict(vite='5'))))
            Path(d, 'apps', 'web').mkdir(parents=True)
            Path(d, 'apps', 'web', 'package.json').write_text('{"name":"web","scripts":{"dev":"vite dev","build":"vite build"},"devDependencies":{"vite":"5","@sveltejs/kit":"2"}}')
            self.assertIn('.', [part['path'] for part in helix_runtime.plan(Path(d))['parts']])

    def test_only_a_scenario_marked_renewable_and_used_by_the_route_is_replayed(self):
        with tempfile.TemporaryDirectory() as d:
            files = {name: Path(d)/('scenario-'+name+'.json') for name in ('login', 'pin')}
            for path in files.values(): path.write_text('old')
            played = []
            class Fake:
                config = dict(runtime=dict(scenarios=[dict(id='login', renewable=True, save_session=dict(as_screen_session=True)), dict(id='pin', save_session=dict(routes_prefix='/hub/'))]))
                out = Path(d); scenario_files = list(files.values())
                declared_scenarios = helix_runtime.Runner.declared_scenarios
                def project_temporary(self): return Path(d)
                def screen_file(self, part): return files['login']
                def route_session(self, route, default): return files['pin'] if route.startswith('/hub/') else default
                def scenario(self, part, url, screen, out, row): played.append(row['id']); files[row['id']].write_text('new'); return [dict(status='PASS')]
            renew = lambda route: helix_runtime.Runner.renew_sessions(Fake(), dict(path='web'), 'https://localhost:1', None, 0, route)
            self.assertFalse(renew('/hub/start')); self.assertEqual(files['pin'].read_text(), 'old')
            self.assertTrue(renew('/admin')); self.assertEqual((played, files['login'].read_text()), (['login'], 'new'))

    def test_test_files_that_are_plain_scripts_run_directly_when_the_runner_finds_no_cases(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = Path(d)/'worker'; cwd.mkdir(); (cwd/'test_a.py').write_text('assert True\n'); (cwd/'test_b.py').write_text('assert True\n')
            def make(broken, scripts):
                class Fake:
                    work = Path(d); env = {}; config = dict(runtime=dict(worker_scripts=scripts))
                    def install(self, part): pass
                    def redact_private(self, text): return text
                    def project_command(self, argv, cwd, maximum=0, phase=''):
                        if argv[:3] == ['python', '-c', 'import pytest']: raise helix_runtime.Blocked('exit 1')
                        if argv[1] == '-m': raise helix_runtime.Blocked('exit 5: NO TESTS RAN')
                        if argv[1] in broken: raise helix_runtime.Blocked('exit 1: AssertionError')
                        return ''
                return Fake()
            run = lambda broken, scripts=('test_a.py', 'test_b.py', '../x.py'): helix_runtime.Runner.worker_tests(make(broken, list(scripts)), dict(path='worker'), {}, Path(d)/'worker.log')
            self.assertEqual(run(())[0], 'PASS')
            status, message = run(('test_b.py',)); self.assertEqual(status, 'FAIL'); self.assertIn('test_b.py', message)
            self.assertEqual(run((), ())[0], 'BLOCKED')

    def test_trial_run_keeps_a_few_routes_and_one_for_every_scenario_session(self):
        routes=['/login','/a','/b','/c','/d','/hub/start','/hub/czas']
        kept=helix_runtime.quick_routes(routes,3,['/hub/',None])
        self.assertEqual(len(kept),4); self.assertEqual([r for r in kept if r.startswith('/hub/')],['/hub/start'])
        self.assertEqual(len(helix_runtime.quick_routes(routes,3)),3)

    def test_routes_with_a_scenario_session_replace_their_first_result_and_the_check_is_recounted(self):
        row=lambda route,status,reachable,**extra:dict(dict(route=route,status=status,reachable=reachable,errors=[],violations=[]),**extra)
        first=dict(routes=[row('/a','PASS',True),row('/hub/start','REDIRECTED',False,redirected_to='/hub'),row('/hub/zakupy','FAIL',False,errors=['HTTP 401'])],
                   requests=[dict(url='https://localhost:1/hub/zakupy',status=401,source='app'),dict(url='https://localhost:1/a/x',status=404,source='app')],not_completed=0)
        fresh={'/hub/start':row('/hub/start','PASS',True),'/hub/zakupy':row('/hub/zakupy','PASS',True)}
        status,data=helix_runtime.merge_scenario_routes(first,fresh,[],'/hub/')
        self.assertEqual((status,data['pages'],data['errors'],data['redirected']),('PASS',['/a','/hub/start','/hub/zakupy'],[],{}))
        self.assertEqual(data['cause'],'HTTP 404 from app on https://localhost:1/a/x')
        self.assertEqual(data['scenario_sessions'],[dict(routes_prefix='/hub/',routes=2,reachable=2,not_completed=0,interrupted=False)])
        fresh['/hub/zakupy']=row('/hub/zakupy','FAIL',False,errors=['HTTP 403'])
        status,data=helix_runtime.merge_scenario_routes(first,fresh,[dict(url='https://localhost:1/hub/zakupy',status=403,source='app')],'/hub/')
        self.assertEqual(status,'FAIL'); self.assertIn('HTTP 403 from app on https://localhost:1/hub/zakupy',data['cause']); self.assertNotIn('401',data['cause'])
        # przerwany drugi pomiar: jedna trasa naprawiona, druga bez wyniku; to nie może dać PASS
        status,data=helix_runtime.merge_scenario_routes(first,{'/hub/zakupy':row('/hub/zakupy','PASS',True)},[],'/hub/',requested=['/hub/start','/hub/zakupy'])
        self.assertEqual((status,data['not_completed']),('FAIL',1)); self.assertIn('did not finish',data['cause'])
        status,stopped=helix_runtime.merge_scenario_routes(first,fresh,[],'/hub/',interrupted=True)
        self.assertEqual(status,'FAIL')
        # kolejna sesja z kompletem wyników nie kasuje wcześniejszego przerwania
        self.assertEqual(helix_runtime.merge_scenario_routes(stopped,{'/a':row('/a','PASS',True)},[],'/a')[0],'FAIL')
        self.assertEqual(helix_runtime.merge_scenario_routes(first,{},[],'/hub/',requested=['/hub/start'])[0],'FAIL')

    def test_react_router_routes_come_from_route_elements_with_nested_paths_joined_to_the_parent(self):
        text = '''<Routes><Route path="/" element={<Layout a={x => 1} />}><Route index element={<Home />} />
          <Route path="orders" element={<Orders />}><Route path=":id" element={<One />} /></Route><Route path="admin" element={<A />} /></Route>
          <Route path="/login" element={<L />} /><Route path="*" element={<N/>} /></Routes>'''
        self.assertEqual(helix_runtime.react_router_paths(text), ({'/', '/admin', '/login', '/orders', '/orders/[id]'}, 0))
        # ścieżka względna bez rodzica w tym pliku nie znika po cichu: jest policzona jako nierozwiązana
        self.assertEqual(helix_runtime.react_router_paths('<Route path="child" element={<X/>} />'), (set(), 1))
        self.assertEqual(helix_runtime.react_router_paths("const routes = [{ path: '/c/:id', element: <C/> }]")[0], {'/c/[id]'})
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'package.json').write_text('{"name":"a","scripts":{"dev":"vite","build":"vite build"},"dependencies":{"react":"18","react-router-dom":"6"},"devDependencies":{"vite":"5"}}')
            Path(d, 'src', 'pages', 'parts').mkdir(parents=True); Path(d, 'src', 'pages', 'parts', 'Widget.tsx').write_text('export default 1')
            Path(d, 'src', 'App.tsx').write_text('<Routes><Route path="/orders" element={<O/>} /><Route path="extra" element={<E/>} /></Routes>')
            part = helix_runtime.plan(Path(d))['parts'][0]
            self.assertEqual(part['routes'], ['/', '/orders']); self.assertEqual(part['routes_unresolved']['count'], 1)
            # sama ścieżka względna: żadnej trasy nie ma, ale pominięcie jest zapisane
            Path(d, 'src', 'App.tsx').write_text('<Routes><Route path="orders" element={<O/>} /></Routes>')
            self.assertEqual(helix_runtime.plan(Path(d))['parts'][0]['routes_unresolved']['count'], 1)
        self.assertEqual(helix_runtime.react_router_paths("[{ path: '/', children: [{ path: 'orders', element: <O/> }] }]"), ({'/'}, 1))

    def test_module_with_own_routes_mounted_under_splat_gets_the_parent_prefix(self):
        # Projekt B: Tasks.tsx ma <Routes><Route path="/types">, zamontowany pod /tasks/* przez lazy(); Helix sprawdzał /types.
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'package.json').write_text('{"name":"a","scripts":{"dev":"vite","build":"vite build"},"dependencies":{"react":"18","react-router-dom":"6"},"devDependencies":{"vite":"5"}}')
            Path(d, 'src', 'pages', 'settings').mkdir(parents=True)
            Path(d, 'src', 'App.tsx').write_text('import AppRoutes from "./AppRoutes";\nexport default () => <BrowserRouter><AppRoutes /></BrowserRouter>')
            Path(d, 'src', 'AppRoutes.tsx').write_text('<Routes><Route path="/orders" element={<O/>} />'
                '<Route path="/tasks/*" element={<Guard />}><Route path="*" element={<Wrap><LazyTasks /></Wrap>} /></Route></Routes>')
            Path(d, 'src', 'Lazy.tsx').write_text("export const LazyTasks = lazy(() => import('@/pages/Tasks'));")
            Path(d, 'src', 'pages', 'Tasks.tsx').write_text('<Routes><Route path="/" element={<L/>} /><Route path="/types" element={<T/>} /><Route path="board/:id" element={<B/>} /></Routes>')
            Path(d, 'src', 'pages', 'settings', 'Orphan.tsx').write_text('<Routes><Route path="/schedules" element={<S/>} /></Routes>')
            part = helix_runtime.plan(Path(d))['parts'][0]
            self.assertEqual(part['routes'], ['/', '/orders', '/tasks', '/tasks/types'])
            self.assertEqual(part['route_patterns'], ['/tasks/board/[id]'])
            self.assertEqual(part['routes_unresolved']['count'], 1)   # /schedules z modułu, którego router nie montuje

    def test_older_interpreters_come_from_the_file_name_without_running_anything(self):
        self.assertEqual(helix_runtime.older_pythons('/nonexistent/python'), [])

    def test_root_that_only_delegates_to_a_nested_part_is_not_a_part(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'package.json').write_text('{"name":"root","scripts":{"dev":"npm --prefix apps/web run dev"},"devDependencies":{"prettier":"3"}}')
            Path(d, 'apps', 'web').mkdir(parents=True)
            Path(d, 'apps', 'web', 'package.json').write_text('{"name":"web","scripts":{"dev":"vite dev","build":"vite build"},"devDependencies":{"vite":"5","@sveltejs/kit":"2"}}')
            self.assertEqual([part['path'] for part in helix_runtime.plan(Path(d))['parts']], ['apps/web'])


if __name__ == '__main__':
    unittest.main()
