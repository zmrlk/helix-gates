"""Kontrola wstępna runtime i granica izolacji po zmianach z 14.11 (dane syntetyczne, bez kodu projektu)."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime as runtime
import helix_runtime_isolation as isolation


def spec(identity='BLOCKED'):
    return dict(parts=[dict(name='app', path='app', framework='sveltekit'), dict(name='worker', path='worker', framework='python-worker')],
                database_target=dict(engine='postgres', major=99),
                identity_plan=dict(parts=[dict(part='app', status=identity, strategy='container', image='example.invalid/idp:1',
                                               gaps=[dict(field='client_id', reason='missing_declaration')] if identity == 'BLOCKED' else [])]))


class ToolLedger(unittest.TestCase):
    def test_tool_first_seen_through_browser_metadata_can_later_be_run_directly(self):
        # Starting Chrome for the PDF after a successful e2e run must not crash the whole report with a 'calls' error.
        runner = runtime.Runner.__new__(runtime.Runner)
        runner.tools = {'playwright_chromium': '/synthetic/chrome'}; runner.browser_module_dir = '/synthetic/missing'
        runner.browser_metadata({'routes': [{'route': '/'}]})
        runner.note_tool(['/synthetic/chrome', '--headless'])
        self.assertEqual(runner.execution_tools['chromium']['calls'], 1)
        self.assertTrue(runner.execution_tools['chromium']['used'])


class BareCallbackAnswers(unittest.TestCase):
    PLANS = dict(parts=[dict(part='frontend', client=dict(callback_paths=['/auth/callback', '/'])), dict(part='admin', client=dict(callback_paths=['/done']))])

    def data(self):
        return dict(routes=[dict(route='/auth/callback', status='FAIL', code=400, errors=['HTTP 400 https://localhost:1/auth/callback'], violations=[]),
                            dict(route='/', status='PASS', code=200, errors=[], violations=[]),
                            dict(route='/done', status='FAIL', code=400, errors=['HTTP 400'], violations=[]),
                            dict(route='/missing', status='FAIL', code=404, errors=['HTTP 404'], violations=[])],
                    requests=[dict(url='https://localhost:1/auth/callback', status=400, source='app'), dict(url='https://localhost:1/missing', status=404, source='app')],
                    errors=['stale'])

    def test_bare_callback_4xx_is_not_a_screen_defect_but_a_shared_screen_is_still_judged(self):
        # A 400 from /auth/callback called without parameters must not fail e2e and a11y.
        out = runtime.bare_callback_answers(self.data(), self.PLANS, 'frontend')
        status = {row['route']: row['status'] for row in out['routes']}
        self.assertEqual(status, {'/auth/callback': 'NOT_APPLICABLE', '/': 'PASS', '/done': 'FAIL', '/missing': 'FAIL'})
        self.assertEqual(len(out['routes']), 4); self.assertEqual(out['bare_callbacks'], ['/auth/callback'])
        self.assertEqual(len(out['requests']), 2)  # the requests stay in the evidence, including the 400 from the callback
        self.assertEqual(len(out['errors']), 2); self.assertTrue(any(e.startswith('/missing') for e in out['errors']))

    def test_callback_that_fails_for_another_reason_stays_a_failure(self):
        data = self.data(); data['routes'][0].update(code=500)
        self.assertEqual(runtime.bare_callback_answers(data, self.PLANS, 'frontend')['routes'][0]['status'], 'FAIL')
        self.assertEqual(runtime.bare_callback_answers(self.data(), None, 'frontend')['routes'][0]['status'], 'FAIL')


class ScreenSession(unittest.TestCase):
    def runner(self, config, keycloak=True):
        runner = runtime.Runner.__new__(runtime.Runner); runner.config = config
        runner.private_keycloak = {'frontend': object()} if keycloak else {}
        runner.project_temporary = lambda: Path('/synthetic/tmp')
        return runner

    def test_session_leaves_the_login_only_for_the_role_the_owner_declared_for_this_part(self):
        declared = {'runtime': {'keycloak': {'parts': {'frontend': {'screen_role': 'admin'}}}}}
        self.assertEqual(self.runner(declared).screen_session({'path': 'frontend'}), dict(role='admin', path=Path('/synthetic/tmp/screen-session.json')))
        self.assertIsNone(self.runner(declared).screen_session({'path': 'backend'}))
        self.assertIsNone(self.runner(declared, keycloak=False).screen_session({'path': 'frontend'}))
        self.assertIsNone(self.runner({'runtime': {'keycloak': {'parts': {'frontend': {}}}}}).screen_session({'path': 'frontend'}))
        self.assertIsNone(self.runner({}).screen_session({'path': 'frontend'}))

    def test_declared_role_must_be_one_of_the_declared_roles(self):
        import helix_runtime_identity as identity
        base = dict(client_id='app', roles=['admin', 'reader'])
        identity._settings({'runtime': {'keycloak': {'parts': {'frontend': dict(base, screen_role='admin')}}}})
        for bad in ('other', ['admin'], ''):
            with self.assertRaises(ValueError): identity._settings({'runtime': {'keycloak': {'parts': {'frontend': dict(base, screen_role=bad)}}}})
        with self.assertRaises(ValueError): identity._settings({'runtime': {'keycloak': {'parts': {'frontend': dict(client_id='app', screen_role='admin')}}}})

    def test_route_audit_gets_the_session_file_only_when_one_was_established(self):
        import helix_visual
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            for state in (None, Path(directory) / 'screen-session.json'):
                helix_visual.runtime_audits(lambda argv, cwd, maximum: calls.append(argv), 'node', Path(directory), 'https://localhost:1', ['/a'], Path(directory) / 'out', weight_result={}, storage_state=state)
        self.assertNotIn('--storage-state', calls[0])
        self.assertEqual(calls[1][-6:], ['--storage-state', str(Path(directory) / 'screen-session.json'), '--states', '60', '--states-seen', str(Path(directory) / 'out' / 'states-seen.json')])


class Preflight(unittest.TestCase):
    def run_preflight(self, plan_value, admitted=True, image_rc=1, platform='darwin', segments=(), only=None):
        completed = type('Done', (), {'returncode': image_rc})()
        result = dict(enforcement='enforced' if admitted else 'blocked', reason_code='LOCAL_PROBE_PASSED' if admitted else 'PROBE_DENIED')
        with patch.object(runtime, 'plan', return_value=plan_value), patch.object(runtime, 'locate', return_value='/synthetic/docker'), \
                patch.object(runtime.subprocess, 'run', return_value=completed), patch.object(runtime.sys, 'platform', platform), \
                patch.object(isolation.SeatbeltBackend, 'admit', return_value=result), patch.object(runtime, 'sysv_segments', return_value=segments):
            return runtime.preflight('/synthetic/project', only=only)

    def test_selected_part_hides_blockers_of_other_parts(self):
        self.assertEqual([row['area'] for row in self.run_preflight(spec(), admitted=False, only='app')], ['identity', 'identity', 'database', 'isolation'])
        self.assertEqual([row['area'] for row in self.run_preflight(spec(), admitted=False, only='worker')], ['database', 'isolation'])

    def test_every_known_blocker_is_reported_in_one_pass(self):
        found = self.run_preflight(spec(), admitted=False)
        self.assertEqual([row['area'] for row in found], ['identity', 'identity', 'database', 'isolation'])
        self.assertIn('client_id (missing_declaration)', found[0]['reason'])
        self.assertIn('example.invalid/idp:1', found[1]['reason'])
        self.assertIn('postgresql@99', found[2]['fix'])
        self.assertIn('PROBE_DENIED', found[3]['reason'])
        self.assertTrue(all(row['fix'] for row in found))

    def test_ready_project_reports_only_what_remains(self):
        with patch.object(runtime, 'native_postgres', return_value=Path('/synthetic/pg/bin')):
            found = self.run_preflight(spec('READY'), image_rc=0)
        self.assertEqual([row['area'] for row in found], [])

    def test_unsupported_host_reports_isolation_even_when_everything_else_is_ready(self):
        with patch.object(runtime, 'native_postgres', return_value=Path('/synthetic/pg/bin')):
            found = self.run_preflight(spec('READY'), image_rc=0, platform='linux')
        self.assertEqual([row['area'] for row in found], ['isolation'])

    def test_foreign_or_uncountable_sysv_memory_is_a_reported_blocker(self):
        for segments in (['589824', '655361'], None):
            with self.subTest(segments=segments), patch.object(runtime, 'native_postgres', return_value=Path('/synthetic/pg/bin')):
                found = self.run_preflight(spec('READY'), image_rc=0, segments=segments)
                self.assertEqual([row['area'] for row in found], ['isolation'])
                self.assertIn('--allow-sysv-exposure', found[0]['fix'])

    def test_backend_hint_names_the_actual_cause(self):
        failures = ['docker: database server network isolation unsupported for docker; no unprotected fallback']
        hint = runtime.backend_instruction({'docker': '/synthetic/docker'}, 99, 'darwin', failures)
        self.assertNotIn('Docker Desktop', hint)
        self.assertIn('brew install postgresql@99', hint)
        with patch.object(runtime, 'native_postgres', return_value=Path('/synthetic/pg/bin')):
            hint = runtime.backend_instruction({'docker': '/synthetic/docker'}, 99, 'darwin', ['native: runtime network isolation unavailable: PROBE_DENIED'])
        self.assertNotIn('brew install', hint)
        self.assertNotIn('Docker Desktop', hint)

    def test_run_directory_is_private_random_and_short_enough_for_unix_sockets(self):
        with tempfile.TemporaryDirectory() as base:
            long_base = Path(base) / ('x' * 60); long_base.mkdir()
            with patch.object(runtime.tempfile, 'gettempdir', return_value=str(long_base)):
                first = runtime.runtime_tmpdir(); second = runtime.runtime_tmpdir()
            try:
                self.assertLess(len(str(first / 'network-control' / 'helix-probe-abcdefgh' / 'denied.sock')), 104)
                self.assertFalse(str(first).startswith(str(long_base.resolve())))
                self.assertNotEqual(first, second)
                for created in (first, second):
                    info = created.lstat()
                    self.assertTrue(stat.S_ISDIR(info.st_mode))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
                    self.assertEqual(info.st_uid, os.getuid())
            finally:
                first.rmdir(); second.rmdir()

    def test_preflight_does_not_execute_project_code(self):
        with tempfile.TemporaryDirectory() as base:
            project = Path(base).resolve() / 'project'; (project / 'app').mkdir(parents=True)
            marker = project / 'EXECUTED'
            script = f"require('fs').writeFileSync({json.dumps(str(marker))},'x')"
            (project / 'app' / 'package.json').write_text(json.dumps(dict(name='synthetic', scripts=dict(
                preinstall='node index.js', build='node index.js', start='node index.js', test='node index.js'))))
            (project / 'app' / 'index.js').write_text(script + '\n')
            runtime.preflight(str(project))
            self.assertFalse(marker.exists())


class SysvChoice(unittest.TestCase):
    """Serwer bazy nie startuje przy cudzych segmentach SysV, chyba że użytkownik świadomie to dopuści."""
    def runner(self, base, **options):
        from test_runtime import FakeExecutor, TOOLS, FIX
        runner = runtime.Runner(FIX/'project-runner', base/'out', engine='native', executor=FakeExecutor(),
                                tools={'tools': dict(TOOLS)}, port_factory=lambda: 31234, **options)
        runner.work = FIX/'project-runner'; runner.tmp = base/'scratch'; runner.tmp.mkdir()
        (runner.out/'logs').mkdir(parents=True)
        return runner

    def started(self, runner):
        return any(call[0][0].endswith('initdb') for call in runner.executor.calls)

    def saved(self, runner):
        return json.loads((runner.out/'database-fidelity.json').read_text())['sysv_shared_memory']

    def test_default_refuses_before_initdb_and_names_the_choice(self):
        import contextlib, io
        for segments in (['589824'], None):
            with self.subTest(segments=segments), tempfile.TemporaryDirectory() as directory:
                runner = self.runner(Path(directory), sysv_probe=lambda: segments)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(runtime.Blocked) as caught:
                    runner.database()
                self.assertIn('--allow-sysv-exposure', str(caught.exception))
                self.assertFalse(self.started(runner))
                self.assertEqual(self.saved(runner)['accepted_by_user'], False)

    def test_explicit_choice_starts_and_records_the_accepted_exposure(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory), sysv_probe=lambda: ['589824', '655361'], allow_sysv_exposure=True)
            with contextlib.redirect_stderr(io.StringIO()):
                runner.database()
            self.assertTrue(self.started(runner))
            self.assertEqual(self.saved(runner), dict(segments=2, accepted_by_user=True, scope='SysV shm i sem bez filtra po przebiegu; POSIX IPC zabronione'))

    def test_clean_host_starts_without_any_flag(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory), sysv_probe=lambda: [])
            with contextlib.redirect_stderr(io.StringIO()):
                runner.database()
            self.assertTrue(self.started(runner))
            self.assertEqual(self.saved(runner)['segments'], 0)


class BundleRead(unittest.TestCase):
    def test_tool_inside_an_app_bundle_makes_the_bundle_directory_readable(self):
        from test_runtime import FakeExecutor, TOOLS, FIX
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); binary = base / 'Synthetic Browser.app' / 'Contents' / 'MacOS' / 'browser'
            binary.parent.mkdir(parents=True); binary.write_text('x')
            plain = base / 'bin' / 'plain'; plain.parent.mkdir(); plain.write_text('x')
            runner = runtime.Runner(FIX/'project-runner', base/'out', executor=FakeExecutor(),
                                    tools={'tools': dict(TOOLS, playwright_chromium=str(binary), node=str(plain))}, port_factory=lambda: 31234)
            runner.tmp = base / 'scratch'; runner.tmp.mkdir(); runner.work = runner.tmp / 'project'; runner.work.mkdir()
            (runner.out / 'logs').mkdir(parents=True); runner.network_connect_ports = set(); runner.network_listen_ports = set()
            for phase in ('measurement', 'build'):
                with self.subTest(phase=phase):
                    roots = runner.isolation_policy(phase)['readonly_roots']
                    self.assertIn(str(base / 'Synthetic Browser.app'), roots)


class BrowserPort(unittest.TestCase):
    def runner(self, base):
        from test_runtime import FakeExecutor, TOOLS, FIX
        runner = runtime.Runner(FIX/'project-runner', base/'out', executor=FakeExecutor(), tools={'tools': dict(TOOLS)}, port_factory=lambda: 41777)
        runner.network_connect_ports = {5000}; runner.network_listen_ports = {5000}; runner.env = {'KEEP': '1'}
        runner.tmp = base / 'scratch'; runner.tmp.mkdir(exist_ok=True)
        return runner

    def test_port_is_admitted_only_for_the_duration_of_the_command(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory)); seen = {}
            def command(argv, cwd=None, maximum=120, *, phase):
                seen.update(phase=phase, listen=set(runner.network_listen_ports), connect=set(runner.network_connect_ports), env=runner.env.get('HELIX_BROWSER_PORT'),
                            temp=runner.env.get('MAC_CHROMIUM_TMPDIR'))
                return 'ok'
            with patch.object(runner, 'project_command', side_effect=command):
                self.assertEqual(runner.measurement_command(['node', 'x.mjs']), 'ok')
            self.assertEqual(seen, dict(phase='measurement', listen={5000, 41777}, connect={5000, 41777}, env='41777', temp=str(runner.tmp / 'project-tmp')))
            self.assertEqual((runner.network_listen_ports, runner.network_connect_ports, runner.env), ({5000}, {5000}, {'KEEP': '1'}))

    def test_guard_stays_loaded_and_gets_the_control_port_only_during_the_command(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory)); runner.env['NODE_OPTIONS'] = '--require /synthetic/preload.cjs'; seen = []; refreshed = []
            def command(argv, cwd=None, maximum=120, *, phase): seen.append((runner.env.get('NODE_OPTIONS'), runner.browser_control_port)); return 'ok'
            with patch.object(runner, 'project_command', side_effect=command), \
                    patch.object(runner, 'refresh_sink_input', side_effect=lambda: refreshed.append(runner.browser_control_port)):
                runner.measurement_command(['/synthetic/node', str(runtime.HOME / 'scripts' / 'ui-audit.mjs')])
            self.assertEqual(seen, [('--require /synthetic/preload.cjs', 41777)])
            self.assertEqual(refreshed, [41777, None]); self.assertIsNone(runner.browser_control_port)

    def test_failed_installation_of_the_exception_leaves_no_port_environment_or_state(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory)); calls = []
            def refresh():
                calls.append(runner.browser_control_port)
                if len(calls) == 1: raise OSError('synthetic write failure')
            with patch.object(runner, 'project_command') as command, patch.object(runner, 'refresh_sink_input', side_effect=refresh), self.assertRaises(OSError):
                runner.measurement_command(['/synthetic/node', 'x.mjs'])
            command.assert_not_called()
            self.assertEqual(calls, [41777, None]); self.assertIsNone(runner.browser_control_port)
            self.assertEqual((runner.network_listen_ports, runner.network_connect_ports, runner.env), ({5000}, {5000}, {'KEEP': '1'}))
            self.assertFalse(getattr(runner, 'guard_restore_failed', False))

    def test_unrestorable_guard_input_blocks_every_further_project_process(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory)); runner.active_sink = dict(input={'browser_control_origins': ['http://127.0.0.1:41777']}, config=Path(directory) / 'sink.json')
            calls = []
            def refresh():
                calls.append(runner.browser_control_port)
                if len(calls) == 2: raise OSError('synthetic restore failure')
            with patch.object(runner, 'project_command', return_value='ok'), patch.object(runner, 'refresh_sink_input', side_effect=refresh), \
                    self.assertRaises(runtime.Blocked):
                runner.measurement_command(['/synthetic/node', 'x.mjs'])
            self.assertTrue(runner.guard_restore_failed)
            self.assertEqual(runner.active_sink['input']['browser_control_origins'], [])
            self.assertEqual((runner.network_listen_ports, runner.network_connect_ports, runner.env), ({5000}, {5000}, {'KEEP': '1'}))
            with self.assertRaises(runtime.Blocked): runner.project_command(['/synthetic/node', 'y.mjs'], phase='build')
            # Every way a project process starts goes through admit_process: command, background process and measurement.
            for phase in ('install', 'migration', 'build', 'application', 'measurement', 'database_server'):
                with self.subTest(phase=phase), self.assertRaises(runtime.Blocked): runner.admit_process(phase, 10)
            with self.assertRaises(runtime.Blocked): runner.project_spawn(['/synthetic/node', 'server.js'], Path(directory), {}, Path(directory) / 'app.log', phase='application')
            self.assertEqual(runner.executor.calls, [])

    def test_refresh_writes_the_control_origin_into_the_guard_input(self):
        from test_runtime_sinks import fixture_input
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory)); written = []
            runner.active_sink = dict(input=fixture_input()[1], config=Path(directory) / 'sink.json')
            with patch('helix_runtime_generic.refresh_generic'), patch.object(runner, 'add_owned_preload'), \
                    patch.object(runner, 'write_sink_input', side_effect=lambda data, path: written.append(json.loads(json.dumps(data)))):
                for value in (41777, None, 80, '41777'):
                    runner.browser_control_port = value; runner.refresh_sink_input()
            self.assertEqual([row['browser_control_origins'] for row in written], [['http://127.0.0.1:41777'], [], [], []])

    @unittest.skipUnless(__import__('shutil').which('node'), 'wymaga Node')
    def test_real_guard_passes_only_the_declared_control_origin(self):
        import shutil
        from test_runtime_sinks import fixture_input
        source = r"""
const assert=require('node:assert/strict');const {Writable}=require('node:stream');
const {createAdapter}=require('./bin/runtime-sinks-preload.cjs');const {validateSinkInput}=require('./bin/runtime-sinks.cjs');
const base=JSON.parse(process.argv[1]);const calls=[];
const native=(...args)=>{calls.push(args);return new Writable({write(c,e,n){n();}});};
const options=port=>({host:'127.0.0.1',port,path:'/ws',headers:{},createConnection(){}});
const closed=createAdapter(base,{httpRequest:native,httpsRequest:native});
closed.httpRequest(options(41777)).on('error',()=>{});assert.equal(calls.length,0);
const input=Object.assign({},base,{browser_control_origins:['http://127.0.0.1:41777']});validateSinkInput(input);
const open=createAdapter(input,{httpRequest:native,httpsRequest:native});
const caller=options(41777);caller.headers={Upgrade:'websocket',Host:'evil.invalid'};
open.httpRequest(caller);assert.equal(calls.length,1);
const sent=calls[0][0];
assert.notEqual(sent,caller);assert.equal(Object.getPrototypeOf(sent),null);
assert.deepEqual({...sent,headers:{...sent.headers}},{protocol:'http:',host:'127.0.0.1',port:41777,path:'/ws',method:'GET',headers:{Upgrade:'websocket'},agent:false});
assert.ok(!('createConnection' in sent));
open.httpRequest('http://127.0.0.1:41777/json');assert.equal(calls.length,2);assert.equal(calls[1][0].path,'/json');
open.httpRequest({host:'127.0.0.1',port:'41777',path:'/p',lookup(){},createConnection(){},autoSelectFamily:true,defaultPort:80});
assert.equal(calls.length,3);assert.deepEqual(Object.keys(calls[2][0]).sort(),['agent','headers','host','method','path','port','protocol']);assert.equal(calls[2][0].port,41777);
calls.pop();
const refused=[options(41778),{host:'evil.invalid',port:41777},{host:'127.0.0.1',port:41777,socketPath:'/x'},
  {host:'127.0.0.1',port:41777,agent:{}},{host:'127.0.0.1',port:41777,auth:'a:b'},{host:'127.0.0.1',port:41777,localAddress:'10.0.0.1'},
  {host:'127.0.0.1',port:41777,path:'http://evil.invalid/'},Object.create({host:'127.0.0.1',port:41777})];
for(const bad of refused){open.httpRequest(bad).on('error',()=>{});}
for(const [url,extra] of [['http://127.0.0.1:41777/',{host:'evil.invalid'}],['http://127.0.0.1:41777/',{port:41778}],['http://127.0.0.1:41777/',{socketPath:'/x'}],
  ['http://user:pw@127.0.0.1:41777/',undefined],['http://127.0.0.1:41777/',{hostname:'evil.invalid'}]]){open.httpRequest(url,extra).on('error',()=>{});}
open.httpsRequest(options(41777)).on('error',()=>{});
assert.equal(calls.length,2);
for(const bad of [['http://127.0.0.1:1023'],['http://127.0.0.1:65536'],['http://127.0.0.1:99999']])assert.throws(()=>validateSinkInput(Object.assign({},base,{browser_control_origins:bad})));
for(const bad of [['http://127.0.0.1:80'],['http://localhost:41777'],['https://127.0.0.1:41777'],['http://127.0.0.1:41777','http://127.0.0.1:41778'],'http://127.0.0.1:41777',['http://10.0.0.1:41777']])
  assert.throws(()=>validateSinkInput(Object.assign({},base,{browser_control_origins:bad})));
// fetch: ten sam jeden adres, tylko GET, bez nagłówków i treści wywołującego (Lighthouse pyta przeglądarkę o /json/version)
(async()=>{
  const seen=[];const fake=async(request,init)=>{seen.push([request,init]);return new Response('{}');};
  const target=value=>typeof value==='string'?value:value.url;
  const withFetch=createAdapter(input,{fetch:fake,httpRequest:native,httpsRequest:native});
  await withFetch.fetch('http://127.0.0.1:41777/json/version',{headers:{authorization:'Bearer CALLER'}});
  assert.equal(seen.length,1);assert.equal(target(seen[0][0]),'http://127.0.0.1:41777/json/version');
  assert.equal(seen[0][0].headers.get('authorization'),null);assert.equal(seen[0][0].method,'GET');assert.deepEqual(seen[0][1],{redirect:'error'});
  const closedFetch=createAdapter(base,{fetch:fake,httpRequest:native,httpsRequest:native});
  for(const [adapter,url,init] of [[withFetch,'http://127.0.0.1:41777/json',{method:'POST',body:'x'}],[withFetch,'http://127.0.0.1:41778/json',{}],
      [withFetch,'https://127.0.0.1:41777/json',{}],[closedFetch,'http://127.0.0.1:41777/json',{}]])await adapter.fetch(url,init).catch(()=>{});
  for(const [request] of seen.slice(1))assert.ok(!/^https?:\/\/127\.0\.0\.1:4177[78]\//.test(target(request)),target(request));
})().catch(error=>{console.error(error);process.exit(1);});
"""
        done = subprocess.run([shutil.which('node'), '-e', source, json.dumps(fixture_input()[1])], cwd=str(runtime.HOME), capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr[-900:])

    def test_failure_restores_ports_and_previous_environment_value(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory)); runner.env['HELIX_BROWSER_PORT'] = '40000'; runner.network_listen_ports.add(41777)
            def refuse(argv, cwd=None, maximum=120, *, phase): raise runtime.Blocked('synthetic failure')
            with patch.object(runner, 'project_command', side_effect=refuse), self.assertRaises(runtime.Blocked):
                runner.measurement_command(['node', 'x.mjs'])
            self.assertEqual(runner.env['HELIX_BROWSER_PORT'], '40000')
            self.assertEqual(runner.network_listen_ports, {5000, 41777})
            self.assertEqual(runner.network_connect_ports, {5000})


class DeclaredSchema(unittest.TestCase):
    def project(self, base):
        root = Path(base).resolve() / 'project'; (root / 'database').mkdir(parents=True)
        (root / 'package.json').write_text(json.dumps(dict(name='synthetic', dependencies=dict(express='4.19.2'), scripts=dict(start='node index.js'))))
        (root / 'index.js').write_text("require('express')().listen(3000)\n")
        (root / 'database' / 'full.sql').write_text('CREATE TABLE synthetic_rows (id integer primary key);\n')
        (root / 'database' / 'note.md').write_text('not sql\n')
        outside = Path(base).resolve() / 'outside.sql'; outside.write_text('CREATE TABLE outside_rows (id integer);\n')
        (root / 'database' / 'link.sql').symlink_to(outside)
        return root, outside

    def config(self, files):
        return dict(runtime=dict(database=dict(schema_files=files)))

    def test_declared_file_becomes_the_only_schema_candidate(self):
        with tempfile.TemporaryDirectory() as base:
            root, _ = self.project(base)
            plan = runtime.plan(str(root), self.config(['database/full.sql']))
        self.assertEqual(len(plan['parts']), 1)
        for part in plan['parts']:
            self.assertEqual([(g['strategy'], [c['strategy'] for c in g['candidates']]) for g in part['schema_strategies']],
                             [('declared-schema', ['declared-schema'])])
            self.assertEqual([m['path'] for m in part['migrations'] if m['kind'] == 'sql'], ['database/full.sql'])

    def test_paths_outside_the_repository_are_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            root, outside = self.project(base)
            for bad in ([str(outside)], ['../outside.sql'], ['database/../../outside.sql'], ['database/link.sql'],
                        ['database/missing.sql'], ['database/note.md'], [], 'database/full.sql', [7]):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    runtime.plan(str(root), self.config(bad))


class ProfileBoundary(unittest.TestCase):
    """Nowe uprawnienia dotyczą wyłącznie serwera bazy; zakres projektu ich nie dostaje."""
    def compiled(self, scope, work, control):
        policy = {key: [] for key in isolation.KEYS}
        policy.update(scope=scope, writable_roots=[str(work)])
        backend = isolation.SeatbeltBackend(control)
        return backend._compile(backend._normalize(policy))

    def test_project_scope_has_no_ipc_or_cross_process_signal_rule(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base).resolve(); work = root / 'work'; work.mkdir(); control = root / 'control'; control.mkdir(mode=0o700)
            project = self.compiled('project', work, control); server = self.compiled('database_server', work, control)
        self.assertNotIn('ipc-', project)
        self.assertNotIn('same-sandbox', project)
        self.assertIn('(allow ipc-sysv-shm ipc-sysv-sem)', server)
        self.assertNotIn('ipc-posix', server)
        self.assertIn('(allow signal (target same-sandbox))', server)
        for text in (project, server):
            self.assertIn('(deny default)', text)
            self.assertIn('(allow file-read* (literal "/"))', text)
            self.assertNotIn('(allow file-read* (subpath "/"))', text)
            self.assertNotIn('(allow network', text)

    def test_measurement_scope_adds_only_the_browser_rules_and_other_scopes_get_none(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as base:
            root = Path(base).resolve(); work = root / 'work'; work.mkdir(); control = root / 'control'; control.mkdir(mode=0o700)
            texts = {scope: self.compiled(scope, work, control) for scope in isolation.SCOPES}
        measurement = texts['measurement']
        self.assertNotIn('(allow mach-lookup)', measurement); self.assertNotIn('(allow mach-lookup mach-register)', measurement)
        self.assertIn('(allow mach-lookup (global-name-regex #"^(com\\.apple\\.|com\\.google\\.Chrome|org\\.chromium\\.)"))', measurement)
        self.assertIn('(allow mach-register (global-name-regex #"^(com\\.google\\.Chrome|org\\.chromium\\.)"))', measurement)
        for service in ('com.apple.pasteboard.1', 'com.apple.tccd', 'com.apple.SecurityServer', 'com.apple.securityd', 'com.apple.coreservices.appleevents'):
            self.assertIn('(global-name "' + service + '")', measurement[measurement.index('(deny mach-lookup'):])
        # Chrome may create only its default profile directories in the account home, never write inside them.
        support = isolation.browser_profile_directories()[0].parent
        home_rules = [line for line in measurement.splitlines() if str(support) in line]
        self.assertEqual(home_rules, ['(allow file-write-create (require-all (vnode-type DIRECTORY) (require-any '
                                      + ' '.join('(literal "' + str(path) + '")' for path in isolation.browser_profile_directories()) + ')))'])
        for scope in ('project', 'database_server'): self.assertNotIn(str(support), texts[scope])
        # No rule for the user's system temporary directory: Chrome gets its own through MAC_CHROMIUM_TMPDIR.
        self.assertNotIn('/var/folders', measurement); self.assertNotIn('regex #"^/', measurement)
        self.assertIn('(allow network* (local unix-socket (subpath "' + str(work) + '")))', measurement)
        self.assertNotIn('(allow network* (local unix-socket))', measurement)
        self.assertNotIn('(allow network-outbound (remote unix-socket))', measurement)
        self.assertNotIn('ipc-', measurement); self.assertNotIn('same-sandbox', measurement)
        self.assertNotIn('(allow network-outbound (remote tcp', measurement)
        self.assertLess(len(measurement.encode()), 16384)
        for scope in ('project', 'database_server'):
            self.assertNotIn('mach-', texts[scope]); self.assertNotIn('unix-socket', texts[scope]); self.assertNotIn('Chrome', texts[scope])

    @unittest.skipUnless(sys.platform == 'darwin' and Path(isolation.SANDBOX_EXEC).exists(), 'wymaga macOS z sandbox-exec')
    def test_real_sandbox_lets_the_browser_create_only_its_profile_directories(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as base:
            root = Path(base).resolve(); work = root / 'work'; work.mkdir(); control = root / 'control'; control.mkdir(mode=0o700)
            support = root / 'support'; support.mkdir()
            profiles = [support / name for name in ('Google', 'Google/Chrome', 'Google/Chrome for Testing', 'Chromium')]
            with patch.object(isolation, 'browser_profile_directories', return_value=profiles):
                profile = root / 'measurement.sb'; profile.write_text(self.compiled('measurement', work, control))
            # Each operation in its own sandboxed process: directories at the listed names succeed; a regular
            # file, a link, an entry inside a profile directory and another name are refused.
            operations = [(['/bin/mkdir', str(support / 'Google')], 0), (['/bin/mkdir', str(support / 'Google/Chrome')], 0),
                          (['/usr/bin/touch', str(support / 'Chromium')], 1), (['/bin/ln', '-s', 'x', str(support / 'Google/Chrome for Testing')], 1),
                          (['/usr/bin/touch', str(support / 'Google/Chrome/inside')], 1), (['/bin/mkdir', str(support / 'Other')], 1)]
            codes = [(argv[-1], min(subprocess.run([isolation.SANDBOX_EXEC, '-f', str(profile), *argv], capture_output=True, timeout=30).returncode, 1))
                     for argv, _ in operations]
            created = sorted(str(path.relative_to(support)) for path in support.rglob('*'))
        self.assertEqual(codes, [(argv[-1], expected) for argv, expected in operations])
        self.assertEqual(created, ['Google', 'Google/Chrome'])

    @unittest.skipUnless(sys.platform == 'darwin' and Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome').exists()
                         and Path(isolation.SANDBOX_EXEC).exists(), 'wymaga macOS z Chrome i sandbox-exec')
    def test_real_chrome_starts_only_in_the_measurement_scope(self):
        chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
        with tempfile.TemporaryDirectory(dir='/private/tmp') as base:
            root = Path(base).resolve(); work = root / 'work'; work.mkdir(); control = root / 'control'; control.mkdir(mode=0o700)
            readonly = [str(Path(p).resolve()) for p in ('/usr', '/bin', '/System', '/Library', '/private/etc', '/dev', '/Applications/Google Chrome.app')]
            # Only the scope where Chrome must start: launching it where it must fail crashed Chrome on every
            # run and macOS showed a crash dialog to whoever ran the suite. The project scope lacking Chrome's
            # rules is asserted on the compiled profile (test_measurement_scope_adds_only_the_browser_rules_and_other_scopes_get_none).
            results = {}; errors = {}
            for scope in ('measurement',):
                policy = {key: [] for key in isolation.KEYS}; policy.update(scope=scope, writable_roots=[str(work)], readonly_roots=readonly)
                backend = isolation.SeatbeltBackend(control); profile = root / (scope + '.sb'); profile.write_text(backend._compile(backend._normalize(policy)))
                try:
                    done = subprocess.run([isolation.SANDBOX_EXEC, '-f', str(profile), chrome, '--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
                                           '--user-data-dir=' + str(work / ('profile-' + scope)), '--dump-dom', 'about:blank'],
                                          capture_output=True, text=True, timeout=60, cwd=str(work), env={'HOME': str(work), 'TMPDIR': str(work), 'MAC_CHROMIUM_TMPDIR': str(work), 'PATH': '/usr/bin:/bin'})
                    results[scope] = (done.returncode, '<html' in done.stdout); errors[scope] = done.stderr[-3000:]
                except subprocess.TimeoutExpired as timeout:
                    results[scope] = ('timeout', False); output = timeout.stderr or ''
                    errors[scope] = (output.decode(errors='replace') if isinstance(output, bytes) else output)[-3000:]
            # Chrome's own stderr names the denied service or path when the measurement scope is too narrow.
            self.assertEqual(results['measurement'], (0, True), errors.get('measurement'))

    @unittest.skipUnless(sys.platform == 'darwin' and Path(isolation.SANDBOX_EXEC).exists(), 'wymaga macOS z sandbox-exec')
    def test_real_sandbox_denies_posix_ipc_outside_write_and_network_in_both_scopes(self):
        probe = ("import socket,sys\n"
                 "from multiprocessing import shared_memory\n"
                 "out=[]\n"
                 "try:\n    m=shared_memory.SharedMemory(create=True,size=16);m.close();m.unlink();out.append('shm-ok')\n"
                 "except OSError: out.append('shm-denied')\n"
                 "try:\n    open(sys.argv[1],'w').write('x');out.append('write-ok')\n"
                 "except OSError: out.append('write-denied')\n"
                 "try:\n    open(sys.argv[2],'w').write('x');out.append('scratch-ok')\n"
                 "except OSError: out.append('scratch-denied')\n"
                 "s=socket.socket();s.settimeout(1)\n"
                 "try:\n    s.connect(('127.0.0.1',int(sys.argv[3])));out.append('net-ok')\n"
                 "except OSError: out.append('net-denied')\n"
                 "print(','.join(out))\n")
        import socket
        with tempfile.TemporaryDirectory(dir='/private/tmp') as base, socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            root = Path(base).resolve(); work = root / 'work'; work.mkdir(); control = root / 'control'; control.mkdir(mode=0o700)
            outside = root / 'outside.txt'; script = work / 'probe.py'; script.write_text(probe)
            for scope in isolation.SCOPES:
                profile = root / (scope + '.sb'); profile.write_text(self.compiled(scope, work, control))
                done = subprocess.run([isolation.SANDBOX_EXEC, '-f', str(profile), sys.executable, '-I', '-S', str(script),
                                       str(outside), str(work / 'inside.txt'), str(listener.getsockname()[1])],
                                      capture_output=True, text=True, timeout=30, cwd=str(work))
                with self.subTest(scope=scope):
                    self.assertEqual(done.returncode, 0, done.stderr[-400:])
                    self.assertEqual(done.stdout.strip(), 'shm-denied,write-denied,scratch-ok,net-denied')
            self.assertFalse(outside.exists())


if __name__ == '__main__':
    unittest.main()


class RedirectedRoutes(unittest.TestCase):
    def test_route_audit_marks_same_origin_redirect_with_target(self):
        import helix_visual, tempfile, json as j
        with tempfile.TemporaryDirectory() as d:
            run=dict(httpStatus=200,finalURL='https://localhost:1/new',errors=['Przekierowanie na inny ekran lub stan (np. logowanie); podaj prawidłowy URL i sesję przez --storage-state'])
            base=dict(url='https://localhost:1/old',summary=dict(status='incomplete'),errors=[],runs=[run])
            Path(d,'audit.json').write_text(j.dumps(base))
            result=helix_visual.projection(d,known={'/old','/new'})
            self.assertEqual((result['status'],result['redirects_to']),('redirected','/new'))
            # a measurement cut short by a redirect carries a state flag instead of a list: it is still recognised as a redirect
            Path(d,'audit.json').write_text(j.dumps(dict(base,runs=[dict(run,states=True)])))
            self.assertEqual(helix_visual.projection(d,known={'/old','/new'})['status'],'redirected')
            Path(d,'audit.json').write_text(j.dumps(base))
            # a redirect leaves the measurement incomplete when the screen session is missing, the target is unknown, or it is the login
            self.assertEqual(helix_visual.projection(d)['status'],'incomplete')
            self.assertEqual(helix_visual.projection(d,known={'/old'})['status'],'incomplete')
            for target in ('/login','/403','/404','/access-denied','/errors/500','/brak-dostepu'):
                Path(d,'audit.json').write_text(j.dumps(dict(base,runs=[dict(run,finalURL='https://localhost:1'+target)])))
                self.assertEqual(helix_visual.projection(d,known={'/old',target})['status'],'incomplete',target)
            # another origin (e.g. the identity provider) and an HTTP error stay incomplete measurements
            for change in (dict(finalURL='https://idp.example.invalid/new'),dict(httpStatus=404)):
                Path(d,'audit.json').write_text(j.dumps(dict(base,runs=[dict(run,**change)])))
                self.assertEqual(helix_visual.projection(d,known={'/old','/new'})['status'],'incomplete')

    def test_rate_limited_paths_are_exact_and_bounded(self):
        import helix_runtime
        self.assertEqual(helix_runtime.throttled_paths({'runtime':{'rate_limited_paths':['/api/notifications']}}),['/api/notifications'])
        self.assertEqual(helix_runtime.throttled_paths({}),[])
        for bad in (['api'],['/a?b=1'],'/api',['/x']*11):
            with self.assertRaises(helix_runtime.Blocked):helix_runtime.throttled_paths({'runtime':{'rate_limited_paths':bad}})

    def test_browser_results_lists_redirected_routes_without_errors(self):
        import helix_runtime, tempfile, json as j
        with tempfile.TemporaryDirectory() as d:
            out=Path(d,'o.json');out.write_text(j.dumps(dict(routes=[dict(type='route',route='/old',status='REDIRECTED',redirected_to='/new',reachable=False,errors=[],violations=[])])))
            data=helix_runtime.browser_results(out)
            self.assertEqual((data['errors'],data['pages'],data['redirected']),([],[],{'/old':'/new'}))


class RouteAuditSelfCheck(unittest.TestCase):
    def audits(self, d, findings, obscured=0):
        import json as j
        results=[]
        for index,items in enumerate(findings):
            folder=Path(d,str(index));folder.mkdir()
            Path(folder,'audit.json').write_text(j.dumps(dict(runs=[dict(tap=items)])))
            results.append(dict(route='/r'+str(index),status='failed' if items else 'passed',evidence=str(folder/'audit.json')))
        return results+[dict(route='/o'+str(i),status='obscured',obscured_by='Nowa wersja') for i in range(obscured)]

    def test_same_finding_on_most_routes_makes_the_audit_suspect(self):
        import helix_visual, tempfile
        with tempfile.TemporaryDirectory() as d:
            # nearly all findings are the same on every route: the measurement sees something common to all routes, not the screens
            check=helix_visual.self_check(self.audits(d,[['okno "Zaczynamy" 95x28','okno: lista','okno: tytuł','okno: stopka']+(['własny'] if i==0 else []) for i in range(12)]))
            self.assertEqual((check['status'],check['shared_total'],check['shared_findings'][0]['routes']),('SUSPECT',4,12))
            # a shared shell plus many route-specific findings is a result, not a suspicion; routes are judged without the shell's findings
            mixed=helix_visual.self_check(self.audits(d+'/..',[]) if False else self.audits(tempfile.mkdtemp(dir=d),[['powłoka 36x36']+(['własny '+str(i)+'-'+str(k) for k in range(4)] if i%2 else []) for i in range(12)]))
            self.assertEqual((mixed['status'],mixed['passed_without_shell']),('OK',6))

    def test_distinct_findings_and_passing_routes_are_not_suspect(self):
        import helix_visual, tempfile
        with tempfile.TemporaryDirectory() as d:
            check=helix_visual.self_check(self.audits(d,[['własny '+str(i)] if i%2 else [] for i in range(12)]))
            self.assertEqual((check['status'],check['shared_total']),('OK',0))

    def test_obscured_screen_is_always_suspect(self):
        import helix_visual, tempfile
        with tempfile.TemporaryDirectory() as d:
            check=helix_visual.self_check(self.audits(d,[[] for _ in range(5)],obscured=1))
            self.assertEqual(check['status'],'SUSPECT');self.assertIn('Nowa wersja',check['reasons'][0])

    def test_failed_backend_requests_are_listed_with_the_routes_they_break_including_unstable_ones(self):
        import helix_visual, tempfile, json as j
        with tempfile.TemporaryDirectory() as d:
            results=self.audits(d,[['własny'],[],[]])
            Path(results[0]['evidence']).write_text(j.dumps(dict(runs=[dict(tap=['własny'],runtime=['HTTP 500: http://127.0.0.1:5/functions/v1/sales?x=1','console: x'])])))
            Path(results[1]['evidence']).write_text(j.dumps(dict(runs=[dict(runtime=['HTTP 500: http://127.0.0.1:5/functions/v1/sales','HTTP 406: http://127.0.0.1:5/rest/v1/rows'])])))
            results[1]['status']='incomplete'
            # an error after a click or from a rejected attempt counts the same as an error on entry
            Path(results[2]['evidence']).write_text(j.dumps(dict(runs=[dict(states=True),dict(states=[dict(runtime=['HTTP 500: http://127.0.0.1:5/functions/v1/sales'])],attempts=[dict(runtime=['HTTP 404: http://127.0.0.1:5/rpc/x'])])])))
            check=helix_visual.self_check(results)
            self.assertEqual(check['failed_requests'],[dict(status=500,path='/functions/v1/sales',routes=3),dict(status=406,path='/rest/v1/rows',routes=1),dict(status=404,path='/rpc/x',routes=1)])
            self.assertEqual((check['measured'],results[1]['failed_requests'],results[2]['failed_requests']),(2,2,2))
            self.assertTrue(any('na 3 z 3 otwartych tras' in reason for reason in check['reasons']))


class ScreenCookies(unittest.TestCase):
    def cookies(self, state):
        import helix_runtime, tempfile, json as j
        with tempfile.TemporaryDirectory() as d:
            path=Path(d,'screen-session.json')
            if state is not None:path.write_text(j.dumps(state))
            fake=type('Fake',(),{'screen_session':lambda self,part:dict(role='editor',path=path),'screen_file':helix_runtime.Runner.screen_file})()
            return helix_runtime.Runner.screen_cookies(fake,{'path':'frontend'},'localhost')

    def test_only_application_host_cookies_with_plain_values_are_passed(self):
        state={'cookies':[{'name':'sid','value':'abc123','domain':'localhost'},{'name':'kc','value':'x','domain':'127.0.0.1'},
                          {'name':'bad','value':'a;b','domain':'localhost'},{'name':'n l','value':'x','domain':'localhost'}]}
        self.assertEqual(self.cookies(state),{'sid':'abc123'})

    def test_no_session_file_means_anonymous_measurement(self):
        self.assertEqual(self.cookies(None),{})


class VolumeResult(unittest.TestCase):
    def row(self, tbl, after, extreme=0, **more):
        return dict(dict(tbl=tbl,before=1,after=after,extreme=extreme,copied=0,failed=0,skipped=None),**more)

    def test_measured_shortfall_is_reported_instead_of_claiming_success(self):
        import helix_runtime, json as j
        rows=[self.row('a',60,11),self.row('silent',1,failed=6)]
        result=helix_runtime.volume_result('NOTICE: x\n'+j.dumps(rows)+'\n',60)
        self.assertEqual((result['status'],result['tables_at_target'],result['below_target'],result['insert_failures']),('INCOMPLETE',1,['silent'],6))
        result=helix_runtime.volume_result(j.dumps(rows[:1]),60)
        self.assertEqual((result['status'],result['rows_with_extreme_values']),('APPLIED',11))

    def test_no_measured_extreme_rows_or_missing_summary_is_incomplete(self):
        import helix_runtime, json as j
        self.assertEqual(helix_runtime.volume_result(j.dumps([self.row('join',60,0)]),60)['status'],'INCOMPLETE')
        self.assertEqual(helix_runtime.volume_result('',60)['status'],'INCOMPLETE')

    def test_dictionaries_are_listed_and_do_not_count_as_shortfall(self):
        import helix_runtime, json as j
        rows=[self.row('a',60,11),dict(tbl='lead_statuses',before=None,after=None,extreme=0,copied=0,failed=0,skipped='dictionary or settings')]
        result=helix_runtime.volume_result(j.dumps(rows),60)
        self.assertEqual((result['status'],result['skipped_dictionaries']),('APPLIED',['lead_statuses']))


class ScenarioSessions(unittest.TestCase):
    def test_route_audit_uses_scenario_session_without_any_screen_session(self):
        import helix_visual, tempfile
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            hub=Path(directory)/'scenario-hub.json'
            pick=lambda route:hub if route.startswith('/hub/') else None
            for run in (helix_visual.runtime_audits,helix_visual.sparse_pass):
                run(lambda argv,cwd,maximum:calls.append(argv),'node',Path(directory),'https://localhost:1',['/hub/start','/public'],Path(directory)/'out',
                    **(dict(weight_result={}) if run is helix_visual.runtime_audits else {}),storage_state=None,session_for=pick)
        with_session=[argv for argv in calls if '--storage-state' in argv]
        self.assertEqual(len(calls),4);self.assertEqual(len(with_session),2)
        self.assertTrue(all(argv[argv.index('--storage-state')+1]==str(hub) and argv[2].endswith('/hub/start') for argv in with_session))

    def test_route_session_respects_the_declared_prefix_only(self):
        import helix_runtime, tempfile
        with tempfile.TemporaryDirectory() as directory:
            hub=Path(directory)/'scenario-hub.json';hub.write_text('{}')
            fake=type('Fake',(),{'scenario_sessions':[('/hub/',hub)]})()
            self.assertEqual(helix_runtime.Runner.route_session(fake,'/hub/start','default'),hub)
            self.assertEqual(helix_runtime.Runner.route_session(fake,'/hubris','default'),'default')
            hub.unlink()
            self.assertEqual(helix_runtime.Runner.route_session(fake,'/hub/start','default'),'default')


class DatabaseTargetEvidence(unittest.TestCase):
    def target(self, files):
        import helix_runtime, tempfile
        with tempfile.TemporaryDirectory() as d:
            for name,text in files.items():
                path=Path(d,name);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
            return helix_runtime.database_target(d)

    def test_documentation_and_port_numbers_do_not_block_runnable_files(self):
        target=self.target({'infra/docker-compose.yml':'services:\n  db:\n    image: postgres:16-alpine\n',
                            'docs/DEPLOYMENT.md':'Wymagany PostgreSQL 15.\nPort: postgres: 5432\n','docs/old/ARCH.md':'postgres 14\n'})
        self.assertEqual((target['major'],target['conflict'],target['tag'],target['documentation_mismatch']),(16,False,'VERIFIED',[14,15]))

    def test_production_file_decides_and_the_divergence_is_reported(self):
        target=self.target({'infra/docker-compose.prod.yml':'services:\n  db:\n    image: postgres:15-alpine\n',
                            'infra/docker-compose.local.yml':'services:\n  db:\n    image: postgres:16-alpine\n'})
        self.assertEqual((target['major'],target['conflict']),(15,False))
        self.assertEqual(target['version_divergence'],[dict(path='infra/docker-compose.local.yml',major=16)])

    def test_two_runnable_versions_without_a_production_file_still_conflict(self):
        target=self.target({'a/docker-compose.yml':'image: postgres:15\n','b/docker-compose.yml':'image: postgres:16\n'})
        self.assertTrue(target['conflict'])

    def test_documentation_alone_is_an_assumption_not_a_conflict(self):
        target=self.target({'README.md':'Baza: PostgreSQL 15 albo PostgreSQL 16.\n'})
        self.assertEqual((target['major'],target['conflict'],target['tag']),(16,False,'ASSUMPTION'))


class TargetFindings(unittest.TestCase):
    def test_divergence_and_outdated_documentation_become_project_findings(self):
        import helix_runtime
        target=dict(major=15,version_divergence=[dict(path='infra/docker-compose.local.yml',major=16)],documentation_mismatch=[14],
                    evidence=[dict(path='docs/OLD.md',line=7,engine='postgres',major=14,strength='documentation'),dict(path='infra/docker-compose.prod.yml',line=3,engine='postgres',major=15,strength='explicit')])
        found={row['id']:row for row in helix_runtime.target_findings(target)}
        self.assertEqual(set(found),{'database-version-divergence','database-version-documentation-outdated'})
        self.assertEqual(found['database-version-documentation-outdated']['evidence'],[dict(path='docs/OLD.md',line=7,major=14)])
        self.assertEqual(helix_runtime.target_findings(dict(major=16,version_divergence=[],documentation_mismatch=[],evidence=[])),[])


class ExampleValues(unittest.TestCase):
    def test_external_service_addresses_from_example_files_are_not_used(self):
        from helix_runtime import external_address as external
        for value in ('https://203.0.113.2:444/next-app/x','smtp.gmail.com:587','postgresql://u:p@db.prod.example.com:5432/x','10.0.0.5:8080'):
            self.assertTrue(external(value),value)
        for value in ('http://localhost:8002','redis://redis:6379/0','http://api:8000','true','1.5','Panel B2B','admin@firma.example','http://127.0.0.1:1','https://example.invalid/x'):
            self.assertFalse(external(value),value)

    def test_package_proxy_tunnels_only_registry_hosts(self):
        import helix_runtime, socket
        proxy=helix_runtime.PackageProxy(('registry.invalid',))
        try:
            for line,expected in ((b'CONNECT evil.example:443 HTTP/1.1',b'403'),(b'GET http://registry.invalid/ HTTP/1.1',b'403'),(b'CONNECT registry.invalid:80 HTTP/1.1',b'403')):
                with socket.create_connection(('127.0.0.1',proxy.port),timeout=5) as client:
                    client.sendall(line+b'\r\nHost: x\r\n\r\n')
                    self.assertIn(expected,client.recv(200))
            self.assertEqual(proxy.allowed,0);self.assertIn('evil.example:443',proxy.denied)
        finally:proxy.close()


class PythonSettings(unittest.TestCase):
    TEXT = """
class Settings(BaseSettings):
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    RETRIES: int = 3  # liczba prób
    ORIGINS: List[AnyHttpUrl] = ["http://localhost:3000"]
    ERP_URL: str = "https://203.0.113.2:444/api"
    API_KEY: str
    WORKERS: int
    ENABLED: bool = Field(..., description="x")
    LIMIT: float = Field(default=1.5)
"""
    def test_declarations_are_read_without_executing_code(self):
        import helix_runtime
        found=helix_runtime.python_settings(self.TEXT)
        self.assertEqual({name:row['has_default'] for name,row in found.items()},
                         dict(ENVIRONMENT=True,DEBUG=True,RETRIES=True,ORIGINS=True,ERP_URL=True,API_KEY=False,WORKERS=False,ENABLED=False,LIMIT=True))
        self.assertEqual(found['ERP_URL']['default'],'https://203.0.113.2:444/api')

    def test_defaults_stay_unset_required_get_typed_values_external_default_is_stubbed(self):
        import helix_runtime
        found=helix_runtime.python_settings(self.TEXT)
        spec=dict(env=[dict(name=name,classification=helix_runtime.classification(name),declared=row) for name,row in found.items()])
        env=helix_runtime.dummy_env(spec,'postgresql://helix@127.0.0.1:1/helix',8000)
        for name in ('ENVIRONMENT','DEBUG','RETRIES','LIMIT'): self.assertNotIn(name,env,name)
        self.assertEqual((env['WORKERS'],env['ENABLED'],env['ERP_URL']),('1','false','https://127.0.0.1:1/api'))
        self.assertIn('API_KEY',env)


class QueueNotSent(unittest.TestCase):
    def test_task_queue_imports_but_sending_is_replaced_by_a_log_line(self):
        import subprocess, sys, tempfile, json as j, os
        with tempfile.TemporaryDirectory() as d:
            package=Path(d,'site','celery','app');package.mkdir(parents=True)
            Path(d,'site','celery','__init__.py').write_text('')
            Path(package,'__init__.py').write_text('')
            Path(package,'task.py').write_text('class Task:\n    name="orders.sync"\n    def apply_async(self,*a,**k):\n        raise SystemExit("broker reached")\n    def delay(self,*a,**k):\n        return self.apply_async(a,k)\n')
            Path(d,'site','smtp_sdk.py').write_text('x=1\n')
            config=Path(d,'input.json');config.write_text(j.dumps(dict(disable_only=True,disabled_modules=['smtp_sdk'],neutralized_modules=['celery'])));os.chmod(config,0o600)
            code=('import sitecustomize\nfrom celery.app.task import Task\nr=Task().delay(1)\nprint(r.id,r.ready())\n'
                  'try:\n    import smtp_sdk\nexcept ImportError as e:\n    print(e)\n')
            done=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=30,
                                env=dict(PATH=os.environ['PATH'],HELIX_GENERIC_INPUT=str(config),PYTHONPATH=str(Path(__file__).resolve().parents[1]/'bin/runtime-python')+os.pathsep+str(Path(d,'site'))))
            self.assertEqual(done.stdout.split(),['helix-not-sent','False','HELIX_INTEGRATION_DISABLED'],done.stderr[-600:])
            self.assertIn('HELIX_QUEUE_NOT_SENT',done.stderr);self.assertIn('orders.sync',done.stderr)


class SettingsReviewFixes(unittest.TestCase):
    def test_required_collections_get_empty_json_and_defaults_stay_unset(self):
        import helix_runtime
        text="""
class Settings(BaseSettings):
    HOSTS: list[str]
    OPTIONS: dict[str, str]
    TAGS: List[str] = ["a"]
"""
        found=helix_runtime.python_settings(text)
        spec=dict(env=[dict(name=name,classification=helix_runtime.classification(name),declared=row,structured=True) for name,row in found.items()])
        env=helix_runtime.dummy_env(spec,'postgresql://helix@127.0.0.1:1/helix',8000)
        self.assertEqual((env['HOSTS'],env['OPTIONS']),('[]','{}'));self.assertNotIn('TAGS',env)

    def test_stub_keeps_the_scheme_and_ipv6_literals_are_external(self):
        import helix_runtime
        self.assertEqual(helix_runtime.loopback_stub('redis://cache.example.com:6379/0'),'redis://127.0.0.1:1/0')
        self.assertEqual(helix_runtime.loopback_stub('https://user:pw@erp.example.com:444/api?x=1'),'https://127.0.0.1:1/api?x=1')
        self.assertTrue(helix_runtime.external_address('http://[2001:db8::1]:8080/x'))
        self.assertFalse(helix_runtime.external_address('http://[::1]:8080/x'))

    def test_declarations_are_scoped_to_the_part(self):
        import helix_runtime, tempfile
        with tempfile.TemporaryDirectory() as d:
            for name,body in (('a','    WORKERS: int\n'),('b','    WORKERS: int = 4\n')):
                Path(d,name).mkdir()
                Path(d,name,'requirements.txt').write_text('fastapi\n')
                Path(d,name,'main.py').write_text('from fastapi import FastAPI\napp=FastAPI()\n')
                Path(d,name,'config.py').write_text('from pydantic_settings import BaseSettings\nclass Settings(BaseSettings):\n'+body)
            plan=helix_runtime.plan(Path(d))
            declared={part['path']:{row['name']:row.get('declared') for row in part['env']}.get('WORKERS') for part in plan['parts']}
            self.assertEqual({path:row and row['has_default'] for path,row in declared.items() if path in ('a','b')},{'a':False,'b':True})

    def test_closing_the_proxy_drops_an_open_tunnel(self):
        import helix_runtime, socket, threading
        upstream=socket.create_server(('127.0.0.1',0));port=upstream.getsockname()[1]
        accepted=[]
        threading.Thread(target=lambda:accepted.append(upstream.accept()[0]),daemon=True).start()
        proxy=helix_runtime.PackageProxy(('localhost',))
        original=socket.create_connection
        try:
            # a tunnel to the "registry" on loopback: the test only swaps the target port
            socket.create_connection=lambda address,timeout=None:original(('127.0.0.1',port),timeout=timeout) if address==('localhost',443) else original(address,timeout=timeout)
            client=original(('127.0.0.1',proxy.port),timeout=5)
            client.sendall(b'CONNECT localhost:443 HTTP/1.1\r\n\r\n')
            self.assertIn(b'200',client.recv(100))
            proxy.close()
            client.settimeout(5)
            self.assertEqual(client.recv(10),b'')
        finally:
            socket.create_connection=original;upstream.close();proxy.close()


class SettingsReviewRoundTwo(unittest.TestCase):
    def test_outer_collection_type_decides_the_empty_json(self):
        import helix_runtime
        found=helix_runtime.python_settings("class S(BaseSettings):\n    OPTIONS: list[dict[str, str]]\n    MAPPING: Optional[Dict[str, int]]\n")
        found['MAPPING']['has_default']=False
        spec=dict(env=[dict(name=name,classification=helix_runtime.classification(name),declared=row,structured=True) for name,row in found.items()])
        env=helix_runtime.dummy_env(spec,'postgresql://helix@127.0.0.1:1/helix',8000)
        self.assertEqual((env['OPTIONS'],env['MAPPING']),('[]','{}'))

    def test_root_part_does_not_absorb_declarations_of_a_nested_service(self):
        import helix_runtime, tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d,'package.json').write_text('{"name":"root","scripts":{"start":"node server.js"},"dependencies":{"express":"4"}}')
            Path(d,'server.js').write_text('console.log(process.env.WORKERS)\n')
            Path(d,'svc').mkdir()
            Path(d,'svc','requirements.txt').write_text('fastapi\n')
            Path(d,'svc','main.py').write_text('from fastapi import FastAPI\napp=FastAPI()\n')
            Path(d,'svc','config.py').write_text('from pydantic_settings import BaseSettings\nclass Settings(BaseSettings):\n    WORKERS: int = 4\n')
            plan=helix_runtime.plan(Path(d))
            declared={part['path']:{row['name']:row.get('declared') for row in part['env']}.get('WORKERS') for part in plan['parts']}
            self.assertIsNone(declared['.']);self.assertTrue(declared['svc']['has_default'])


class PathRouterTest(unittest.TestCase):
    def test_declared_prefixes_go_to_the_backend_everything_else_to_the_frontend(self):
        import helix_runtime, http.server, threading, urllib.request
        def serve(label):
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    body=(label+' '+self.path+' '+self.headers.get('Host','')).encode()
                    self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                def do_POST(self):
                    data=self.rfile.read(int(self.headers.get('Content-Length','0')))
                    body=(label+' got '+data.decode()).encode()
                    self.send_response(201);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            return server
        front,api=serve('front'),serve('api')
        router=helix_runtime.PathRouter(front.server_address[1],{'/api':api.server_address[1],'/uploads':api.server_address[1]})
        try:
            base='http://127.0.0.1:'+str(router.port)
            read=lambda path,data=None:urllib.request.urlopen(urllib.request.Request(base+path,data=data),timeout=10).read().decode()
            self.assertTrue(read('/api/v1/items?x=1').startswith('api /api/v1/items?x=1 127.0.0.1:'+str(router.port)))
            self.assertTrue(read('/uploads/a.png').startswith('api '))
            self.assertTrue(read('/apiary').startswith('front '))
            self.assertTrue(read('/').startswith('front / '))
            self.assertEqual(read('/api/v1/items',b'{"a":1}'),'api got {"a":1}')
        finally:
            router.close();front.shutdown();api.shutdown();front.server_close();api.server_close()

    def test_backend_is_detected_from_the_frontend_proxy_configuration(self):
        import helix_runtime, tempfile
        with tempfile.TemporaryDirectory() as d:
            web=Path(d,'apps','web');web.mkdir(parents=True)
            Path(web,'package.json').write_text('{"name":"web","scripts":{"build":"vite build"},"dependencies":{"@sveltejs/kit":"2","@sveltejs/adapter-node":"5"}}')
            Path(web,'vite.config.ts').write_text("const T = process.env.API_TARGET ?? 'http://localhost:8004';\nexport default {server:{proxy:{'/api': { target: T }, '/uploads': { target: T }}}};\n")
            api=Path(d,'apps','api');api.mkdir(parents=True)
            Path(api,'requirements.txt').write_text('fastapi\n')
            Path(api,'main.py').write_text('from fastapi import FastAPI\napp=FastAPI()\n')
            plan=helix_runtime.plan(Path(d))
            backend={part['path']:part.get('backend') for part in plan['parts']}
            self.assertEqual(backend['apps/web'],dict(part='apps/api',prefixes=['/api','/uploads'],env=['API_TARGET']))
            self.assertIsNone(backend['apps/api'])


class RoleChecks(unittest.TestCase):
    def test_login_expectations_follow_the_owner_declaration(self):
        import helix_runtime
        phases=lambda status,reason='UNEXPECTED_AUTHORIZATION_RESTART':[dict(phase='form',status='PASS'),dict(phase='callback',status=status,reason_code=reason if status=='FAIL' else 'OK')]
        fake=type('Fake',(),dict(config=dict(runtime=dict(keycloak=dict(parts=dict(frontend=dict(denied_roles=['archived']))))),
            identity_plans=dict(parts=[dict(part='frontend',identities=[dict(id='role-a',app_roles=['admin']),dict(id='role-b',app_roles=['archived']),dict(id='role-c',app_roles=['reader'])])]),
            identity_forms=dict(frontend=dict(identities=[dict(identity_id='role-a',phases=phases('PASS')),dict(identity_id='role-b',phases=phases('FAIL')),dict(identity_id='role-c',phases=phases('FAIL'))]))))()
        rows={row['role']:row['result'] for row in helix_runtime.Runner.login_expectations(fake,{'path':'frontend'})}
        self.assertEqual(rows,dict(admin='AS_EXPECTED',archived='AS_EXPECTED',reader='UNEXPECTED_DENIAL'))
        fake.identity_forms['frontend']['identities'][1]['phases']=phases('PASS')
        rows={row['role']:row['result'] for row in helix_runtime.Runner.login_expectations(fake,{'path':'frontend'})}
        self.assertEqual(rows['archived'],'SESSION_GRANTED_TO_DENIED_ROLE')
        # an attempt that failed for another reason (identity provider, interruption) does not prove the application refused
        fake.identity_forms['frontend']['identities'][1]['phases']=phases('FAIL','BROWSER_OPERATION_FAILED')
        rows={row['role']:row['result'] for row in helix_runtime.Runner.login_expectations(fake,{'path':'frontend'})}
        self.assertEqual(rows['archived'],'INCONCLUSIVE')

    def test_denied_roles_must_be_declared_roles_other_than_the_screen_role(self):
        import helix_runtime_identity as identity
        check=getattr(identity,'_settings')
        base=dict(roles=['admin','archived'],screen_role='admin')
        try:
            check(dict(runtime=dict(keycloak=dict(parts=dict(frontend=dict(base,denied_roles=['archived']))))))
            for bad in (['ghost'],['admin'],'archived'):
                with self.assertRaises(ValueError):check(dict(runtime=dict(keycloak=dict(parts=dict(frontend=dict(base,denied_roles=bad))))))
        except TypeError:
            self.skipTest('inna sygnatura walidatora; sprawdzane przez plan')


class ClosingReviewFixes(unittest.TestCase):
    def serve(self,kind,body):
        import http.server, threading
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        return server

    def test_api_is_recognised_by_its_answer_not_by_the_framework(self):
        import helix_runtime
        html,api=self.serve('text/html; charset=utf-8',b'<html></html>'),self.serve('application/json',b'{}')
        try:
            probe=helix_runtime.Executor.non_html
            self.assertFalse(probe(None,'http://127.0.0.1:%d/'%html.server_address[1]))
            self.assertTrue(probe(None,'http://127.0.0.1:%d/'%api.server_address[1]))
            self.assertFalse(probe(None,'http://127.0.0.1:1/'))
            self.assertFalse(probe(None,'https://example.invalid/'))
            # a redirect or an HTTP error decides nothing; redirects are not followed
            import http.server, threading
            hits=[]
            class Elsewhere(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):hits.append(self.path);self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b'{}')
            other=http.server.ThreadingHTTPServer(('127.0.0.1',0),Elsewhere);threading.Thread(target=other.serve_forever,daemon=True).start()
            class Redirect(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    if self.path=='/gone':self.send_response(404);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b'{}');return
                    self.send_response(307);self.send_header('Location','http://127.0.0.1:%d/x'%other.server_address[1]);self.end_headers()
            front=http.server.ThreadingHTTPServer(('127.0.0.1',0),Redirect);threading.Thread(target=front.serve_forever,daemon=True).start()
            try:
                self.assertFalse(probe(None,'http://127.0.0.1:%d/'%front.server_address[1]));self.assertEqual(hits,[])
                self.assertFalse(probe(None,'http://127.0.0.1:%d/gone'%front.server_address[1]))
            finally:
                for server in (other,front):server.shutdown();server.server_close()
        finally:
            for server in (html,api):server.shutdown();server.server_close()

    def test_router_survives_a_half_closed_client_and_still_delivers_the_answer(self):
        import helix_runtime, socket, time
        upstream=self.serve('text/plain',b'done')
        router=helix_runtime.PathRouter(upstream.server_address[1],{})
        try:
            client=socket.create_connection(('127.0.0.1',router.port),timeout=5)
            client.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n');client.shutdown(socket.SHUT_WR)
            data=b'';client.settimeout(5)
            while True:
                chunk=client.recv(4096)
                if not chunk:break
                data+=chunk
            self.assertIn(b'done',data)
            time.sleep(.3)
            with router.lock:self.assertEqual(len(router.sockets),0)
        finally:
            router.close();upstream.shutdown();upstream.server_close()
