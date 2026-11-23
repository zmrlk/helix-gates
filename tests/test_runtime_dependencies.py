"""Zależności Node bez sieci w izolacji i samodzielne przygotowania Helixa (dane syntetyczne, bez npm i bez sieci)."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime as runtime
from test_runtime import FakeExecutor, TOOLS

def entry(name, version, **extra):
    return dict(version=version, resolved=f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz', integrity='sha512-' + 'A' * 86 + '==', **extra)


LOCK = {'packages': {'': {'name': 'synthetic'}, 'node_modules/alpha': entry('alpha', '1.2.3'),
                     'node_modules/beta': entry('beta', '2.0.0', dev=True),
                     'node_modules/native-linux': entry('native-linux', '9.9.9', optional=True)}}
INSTALLED = {'packages': {'node_modules/alpha': {'version': '1.2.3'}, 'node_modules/beta': {'version': '2.0.0'}}}


def write_modules(directory, installed=INSTALLED):
    directory.mkdir(parents=True)
    (directory / '.package-lock.json').write_text(json.dumps(installed))
    for name, row in installed['packages'].items() if isinstance(installed, dict) and isinstance(installed.get('packages'), dict) else ():
        package = directory.parent / name; package.mkdir(parents=True, exist_ok=True)
        (package / 'package.json').write_text(json.dumps(dict(name=Path(name).name, version=row.get('version'))))
    (directory / 'alpha').mkdir(exist_ok=True); (directory / 'alpha' / 'index.js').write_text('module.exports = 1\n')


class Match(unittest.TestCase):
    def check(self, installed):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base); (root / 'package-lock.json').write_text(json.dumps(LOCK))
            if installed is not None: write_modules(root / 'node_modules', installed)
            return runtime.node_modules_match(root / 'package-lock.json', root / 'node_modules')

    def test_same_versions_with_only_optional_packages_missing_match(self):
        self.assertTrue(self.check(INSTALLED))

    def test_missing_required_other_version_extra_package_or_no_install_do_not_match(self):
        cases = [None, {'packages': {}}, {'packages': {'node_modules/alpha': {'version': '1.2.3'}}},
                 {'packages': {'node_modules/alpha': {'version': '1.2.4'}, 'node_modules/beta': {'version': '2.0.0'}}},
                 {'packages': dict(INSTALLED['packages'], **{'node_modules/gamma': {'version': '1.0.0'}})}, {'packages': []}, []]
        for installed in cases:
            with self.subTest(installed=installed): self.assertFalse(self.check(installed))


    def test_package_missing_or_changed_on_disk_does_not_match_even_with_clean_metadata(self):
        for damage in ('remove', 'version', 'symlink'):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as base:
                root = Path(base); (root / 'package-lock.json').write_text(json.dumps(LOCK)); write_modules(root / 'node_modules')
                manifest = root / 'node_modules' / 'beta' / 'package.json'
                if damage == 'remove': manifest.unlink()
                elif damage == 'version': manifest.write_text(json.dumps(dict(name='beta', version='2.0.1')))
                else:
                    outside = root / 'outside.json'; outside.write_text(json.dumps(dict(name='beta', version='2.0.0'))); manifest.unlink(); manifest.symlink_to(outside)
                self.assertFalse(runtime.node_modules_match(root / 'package-lock.json', root / 'node_modules'))

    def test_extra_or_unclassifiable_entries_on_disk_do_not_match(self):
        def damage_extra(m): (m / 'gamma').mkdir(); (m / 'gamma' / 'package.json').write_text(json.dumps(dict(name='gamma', version='1.0.0')))
        def damage_scoped(m): (m / '@scope' / 'inner').mkdir(parents=True)
        def damage_nested(m): (m / 'alpha' / 'node_modules' / 'hidden').mkdir(parents=True)
        def damage_file(m): (m / 'stray.js').write_text('x')
        def damage_link(m): (m / 'linked').symlink_to(m / 'alpha')
        for damage in (damage_extra, damage_scoped, damage_nested, damage_file, damage_link):
            with self.subTest(damage=damage.__name__), tempfile.TemporaryDirectory() as base:
                root = Path(base); (root / 'package-lock.json').write_text(json.dumps(LOCK)); write_modules(root / 'node_modules')
                self.assertTrue(runtime.node_modules_match(root / 'package-lock.json', root / 'node_modules'))
                damage(root / 'node_modules')
                self.assertFalse(runtime.node_modules_match(root / 'package-lock.json', root / 'node_modules'))

    def test_tool_caches_in_dot_directories_are_tolerated_but_not_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); runner, project, part = Install().runner(base)
            modules = project / 'app' / 'node_modules'; write_modules(modules)
            (modules / '.vite').mkdir(); (modules / '.vite' / 'cache.bin').write_text('x'); (modules / '.bin').mkdir()
            runner.install(part)
            copied = runner.work / 'app' / 'node_modules'
            self.assertTrue((copied / '.bin').is_dir()); self.assertTrue((copied / '.package-lock.json').is_file())
            self.assertFalse((copied / '.vite').exists())

    def test_link_entries_never_match(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base); lock = json.loads(json.dumps(LOCK)); lock['packages']['node_modules/local'] = dict(link=True, resolved='packages/local')
            (root / 'package-lock.json').write_text(json.dumps(lock)); write_modules(root / 'node_modules')
            self.assertFalse(runtime.node_modules_match(root / 'package-lock.json', root / 'node_modules'))

    def test_only_public_registry_entries_with_integrity_are_downloadable(self):
        def check(change):
            with tempfile.TemporaryDirectory() as base:
                lock = json.loads(json.dumps(LOCK)); change(lock['packages'])
                path = Path(base) / 'package-lock.json'; path.write_text(json.dumps(lock))
                return runtime.lockfile_downloadable(path)
        self.assertTrue(check(lambda packages: None))
        # archiwum spoza rejestru: tylko z hosta znanego Helixowi albo dopuszczonego przez właściciela, zawsze ze skrótem sha512
        sheet = lambda p: p['node_modules/alpha'].update(resolved='https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz')
        self.assertTrue(check(sheet))
        other = lambda p: p['node_modules/alpha'].update(resolved='https://registry.example.invalid/alpha/-/alpha-1.2.3.tgz')
        with tempfile.TemporaryDirectory() as base:
            lock = json.loads(json.dumps(LOCK)); other(lock['packages']); path = Path(base) / 'package-lock.json'; path.write_text(json.dumps(lock))
            self.assertTrue(runtime.lockfile_downloadable(path, ['registry.example.invalid'])); self.assertFalse(runtime.lockfile_downloadable(path))
            self.assertEqual(runtime.lockfile_foreign_hosts(path), ['registry.example.invalid'])
        self.assertTrue(check(lambda p: p.update({'node_modules/alpha/node_modules/inner': dict(inBundle=True, optional=True, version='1.0.0')})))
        for change in (lambda p: p.update({'node_modules/top': dict(inBundle=True, version='1.0.0')}),
                       lambda p: p.update({'node_modules/ghost/node_modules/inner': dict(inBundle=True, version='1.0.0')}),
                       lambda p: (p['node_modules/alpha'].update(resolved='git+ssh://git@example.invalid/a.git#abc'), p.update({'node_modules/alpha/node_modules/inner': dict(inBundle=True, version='1.0.0')})),
                       lambda p: p.update({'node_modules/alpha/node_modules/inner': dict(inBundle=True, version='https://example.invalid/x.tgz')}),
                       lambda p: p.update({'node_modules/alpha/node_modules/inner': dict(inBundle=True, link=True, version='1.0.0')}),
                       lambda p: p['node_modules/beta'].update(version='github:owner/repo')):
            with self.subTest(bundle=change): self.assertFalse(check(change))
        for change in (lambda p: p['node_modules/alpha'].update(resolved='git+ssh://git@example.invalid/a.git#abc'),
                       lambda p: p['node_modules/alpha'].update(resolved='https://registry.example.invalid/alpha/-/alpha-1.2.3.tgz'),
                       lambda p: p['node_modules/alpha'].update(resolved='http://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz'),
                       lambda p: p['node_modules/alpha'].update(resolved='file:../alpha'),
                       lambda p: p['node_modules/alpha'].pop('integrity'),
                       lambda p: p['node_modules/alpha'].update(integrity='sha1-AAAA'),
                       lambda p: p.update({'node_modules/local': dict(link=True, resolved='packages/local')}),
                       lambda p: [p.pop(k) for k in list(p) if k]):
            with self.subTest(change=change): self.assertFalse(check(change))

    def test_fallback_install_is_allowed_only_for_plain_registry_ranges_and_operator_settings_come_from_the_operator(self):
        with tempfile.TemporaryDirectory() as base:
            path = Path(base) / 'package.json'
            write = lambda **fields: path.write_text(json.dumps(fields))
            write(dependencies={'a': '^1.2.3', 'b': '~2.0.0', 'x': 'https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz'}, devDependencies={'c': '>=1 <3', 'd': 'latest'})
            self.assertTrue(runtime.package_specs_downloadable(path))
            for spec in ('github:owner/repo', 'git+https://example.invalid/a.git', 'file:../a', 'npm:other@1', 'https://example.invalid/a.tgz', 'http://cdn.sheetjs.com/a.tgz'):
                write(dependencies={'a': spec})
                with self.subTest(spec=spec): self.assertFalse(runtime.package_specs_downloadable(path))
            write(dependencies={'a': '1.0.0'}, overrides={'a': 'github:x/y'}); self.assertFalse(runtime.package_specs_downloadable(path))
            # adres spoza dozwolonych źródeł w package.json: Helix nie uruchamia npm poza izolacją ani razu
            write(dependencies={'a': 'https://example.invalid/a.tgz'}); (Path(base) / 'package-lock.json').write_text(json.dumps(LOCK))
            calls = []
            runner = type('Fake', (), dict(project=Path(base), config={}, cache_root=Path(base) / 'cache', operator_setting=runtime.Runner.operator_setting,
                                           executor=type('E', (), dict(run=lambda self, *a: calls.append(a) or (0, '')))()))()
            self.assertIsNone(runtime.Runner.prepare_node_modules(runner, Path(base) / 'package-lock.json', Path(base), 'npm')); self.assertEqual(calls, [])
            # ustawienie dopuszczające hosty zapisane w helix.json samego projektu jest odrzucane
            fake = type('Fake', (), dict(project=Path(base), config=dict(runtime=dict(dependency_hosts=['example.invalid'], supabase=dict(schema='/etc/passwd')))))()
            for name in ('dependency_hosts', 'supabase.schema'):
                with self.assertRaises(runtime.Blocked): runtime.Runner.operator_setting(fake, name)
            self.assertEqual(runtime.Runner.operator_setting(type('Fake', (), dict(project=Path(base), config={}))(), 'dependency_hosts', []), [])

    def test_links_must_stay_inside_the_tree(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / 'node_modules'; (root / '.bin').mkdir(parents=True); (root / 'alpha').mkdir()
            (root / 'alpha' / 'cli.js').write_text('x'); (root / '.bin' / 'alpha').symlink_to('../alpha/cli.js')
            self.assertTrue(runtime.links_stay_inside(root))
            outside = Path(base) / 'outside.txt'; outside.write_text('x'); (root / 'alpha' / 'leak').symlink_to(outside)
            self.assertFalse(runtime.links_stay_inside(root))


class Install(unittest.TestCase):
    def runner(self, base, executor=None, cache_root=None):
        project = base / 'project'; (project / 'app').mkdir(parents=True)
        (project / 'app' / 'package.json').write_text(json.dumps(dict(name='synthetic')))
        (project / 'app' / 'package-lock.json').write_text(json.dumps(LOCK))
        runner = runtime.Runner(project, base / 'out', engine='native', executor=executor or FakeExecutor(), tools={'tools': dict(TOOLS)}, port_factory=lambda: 31234, cache_root=cache_root)
        runner.tmp = base / 'scratch'; runner.tmp.mkdir(); runner.work = runner.tmp / 'project'
        (runner.out / 'logs').mkdir(parents=True)
        runtime.copy_project(project, runner.work)
        return runner, project, dict(path='app', workspace='app', package_manager='npm', lockfile='package-lock.json')

    def test_matching_project_dependencies_are_copied_and_nothing_is_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); runner, project, part = self.runner(base)
            write_modules(project / 'app' / 'node_modules')
            runner.install(part)
            self.assertEqual((runner.work / 'app' / 'node_modules' / 'alpha' / 'index.js').read_text(), 'module.exports = 1\n')
            self.assertEqual(runner.dependency_sources, {'app': 'project'})
            self.assertFalse(any('ci' in call[0] or 'install' in call[0] or 'rebuild' in call[0] for call in runner.executor.calls))

    def test_missing_dependencies_are_downloaded_by_helix_without_package_scripts_then_rebuilt_in_isolation(self):
        class Downloading(FakeExecutor):
            def run(self, argv, cwd, env, timeout):
                if '--ignore-scripts' in argv:
                    self.calls.append((argv, cwd, env, timeout)); write_modules(Path(cwd) / 'node_modules')
                    return 0, 'added 2 packages'
                return super().run(argv, cwd, env, timeout)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); home = base / 'home'; home.mkdir()
            runner, project, part = self.runner(base, Downloading(), home / '.cache' / 'helix')
            rebuilt = []
            with patch.object(runner, 'project_command', side_effect=lambda argv, cwd=None, maximum=120, *, phase: rebuilt.append((argv, phase))):
                runner.install(part)
            download = next(call for call in runner.executor.calls if '--ignore-scripts' in call[0])
            self.assertTrue(str(download[1]).startswith(str(home / '.cache' / 'helix' / 'node-deps')))
            self.assertNotEqual(Path(download[1]), runner.work / 'app')
            self.assertNotIn('NODE_OPTIONS', download[2])
            self.assertTrue((runner.work / 'app' / 'node_modules' / 'alpha' / 'index.js').exists())
            self.assertEqual(rebuilt, [([TOOLS['npm'], 'rebuild'], 'install')])
            self.assertEqual(runner.dependency_sources, {'app': 'helix-prepared'})
            self.assertEqual(download[0][-2:], ['--registry', 'https://registry.npmjs.org/'])

    def test_failed_rebuild_blocks_instead_of_reporting_ready_dependencies(self):
        class Downloading(FakeExecutor):
            def run(self, argv, cwd, env, timeout):
                if '--ignore-scripts' in argv:
                    write_modules(Path(cwd) / 'node_modules'); return 0, 'added 2 packages'
                return super().run(argv, cwd, env, timeout)
        def refuse(argv, cwd=None, maximum=120, *, phase): raise runtime.Blocked('exit 1: synthetic rebuild failure')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); home = base / 'home'; home.mkdir()
            runner, project, part = self.runner(base, Downloading(), home / '.cache' / 'helix')
            with patch.object(runner, 'project_command', side_effect=refuse), self.assertRaises(runtime.Blocked):
                runner.install(part)

    def test_lockfile_outside_the_public_registry_is_never_downloaded_by_helix(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); home = base / 'home'; home.mkdir()
            runner, project, part = self.runner(base, None, home / '.cache' / 'helix')
            lock = json.loads(json.dumps(LOCK)); lock['packages']['node_modules/alpha']['resolved'] = 'git+ssh://git@example.invalid/a.git#abc'
            (runner.work / 'app' / 'package-lock.json').write_text(json.dumps(lock))
            commands = []
            with patch.object(runner, 'project_command', side_effect=lambda argv, cwd=None, maximum=120, *, phase: commands.append(argv)):
                runner.install(part)
            self.assertFalse(any('--ignore-scripts' in call[0] for call in runner.executor.calls))
            self.assertEqual(commands, [[TOOLS['npm'], 'ci', '--include=dev']])

    def test_failed_download_falls_back_to_the_isolated_install(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); home = base / 'home'; home.mkdir()
            runner, project, part = self.runner(base, None, home / '.cache' / 'helix')
            commands = []
            with patch.object(runner, 'project_command', side_effect=lambda argv, cwd=None, maximum=120, *, phase: commands.append(argv)):
                runner.install(part)
            self.assertEqual(commands, [[TOOLS['npm'], 'ci', '--include=dev']])
            self.assertFalse((runner.work / 'app' / 'node_modules').exists())


class RuntimeTools(unittest.TestCase):
    def runner(self, base, executor):
        runner, _, _ = Install().runner(base, executor, base / 'home' / '.cache' / 'helix')
        return runner

    def test_tools_are_downloaded_once_outside_the_project_copy_without_scripts(self):
        class Downloading(FakeExecutor):
            def run(self, argv, cwd, env, timeout):
                if '--ignore-scripts' in argv:
                    self.calls.append((argv, cwd, env, timeout))
                    for name in runtime.RUNTIME_TOOL_PACKAGES:
                        (Path(cwd) / 'node_modules' / name).mkdir(parents=True); (Path(cwd) / 'node_modules' / name / 'package.json').write_text('{}')
                    return 0, 'added'
                return super().run(argv, cwd, env, timeout)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); home = base / 'home'; home.mkdir()
            runner = self.runner(base, Downloading())
            first = runner.prepare_runtime_tools(); second = runner.prepare_runtime_tools()
            self.assertEqual(first, home / '.cache' / 'helix' / 'runtime-tools' / sys.platform / 'node_modules'); self.assertEqual(second, first)
            downloads = [call for call in runner.executor.calls if '--ignore-scripts' in call[0]]
            self.assertEqual(len(downloads), 1)
            self.assertEqual(downloads[0][0][-4:], ['--registry', 'https://registry.npmjs.org/', 'axe-core', 'playwright'])
            self.assertFalse(str(downloads[0][1]).startswith(str(runner.work))); self.assertNotIn('NODE_OPTIONS', downloads[0][2])

    def test_failed_or_interrupted_download_is_never_reused_as_cache(self):
        class Partial(FakeExecutor):
            attempts = 0
            def run(self, argv, cwd, env, timeout):
                if '--ignore-scripts' in argv:
                    Partial.attempts += 1; self.calls.append((argv, cwd, env, timeout))
                    for name in runtime.RUNTIME_TOOL_PACKAGES:
                        (Path(cwd) / 'node_modules' / name).mkdir(parents=True); (Path(cwd) / 'node_modules' / name / 'package.json').write_text('{}')
                    return (1, 'npm error network') if Partial.attempts == 1 else (0, 'added')
                return super().run(argv, cwd, env, timeout)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); (base / 'home').mkdir()
            runner = self.runner(base, Partial())
            self.assertIsNone(runner.prepare_runtime_tools())
            stage = base / 'home' / '.cache' / 'helix' / 'runtime-tools' / sys.platform
            self.assertFalse((stage / runtime.CACHE_COMPLETE).exists())
            self.assertEqual(runner.prepare_runtime_tools(), stage / 'node_modules')
            self.assertEqual(Partial.attempts, 2)
            self.assertTrue((stage / runtime.CACHE_COMPLETE).is_file())
            self.assertEqual(runner.prepare_runtime_tools(), stage / 'node_modules'); self.assertEqual(Partial.attempts, 2)

    def test_failed_download_returns_none_so_the_isolated_install_remains(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); home = base / 'home'; home.mkdir()
            runner = self.runner(base, FakeExecutor())
            self.assertIsNone(runner.prepare_runtime_tools())


    def test_synthetic_runner_without_cache_root_downloads_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, project, part = Install().runner(Path(directory).resolve())
            self.assertIsNone(runner.cache_root); self.assertIsNone(runner.prepare_runtime_tools())
            self.assertIsNone(runner.prepare_node_modules(runner.work / 'app' / 'package-lock.json', runner.work / 'app', TOOLS['npm']))
            self.assertEqual(runner.executor.calls, [])


class AutoPrepare(unittest.TestCase):
    def test_only_blockers_with_a_known_command_are_executed(self):
        calls = []
        def run(argv, **options):
            calls.append(argv); return type('Done', (), {'returncode': 0 if argv[0] == '/synthetic/docker' else 1})()
        lines = []
        done = runtime.auto_prepare([dict(area='identity', reason='r', fix='f', auto=['/synthetic/docker', 'pull', 'example.invalid/idp:1']),
                                     dict(area='worker', reason='r', fix='f'),
                                     dict(area='database', reason='r', fix='f', auto=['/synthetic/brew', 'install', 'postgresql@99'])], run=run, report=lines.append)
        self.assertEqual(calls, [['/synthetic/docker', 'pull', 'example.invalid/idp:1'], ['/synthetic/brew', 'install', 'postgresql@99']])
        self.assertEqual([(row['area'], row['ok']) for row in done], [('identity', True), ('database', False)])
        self.assertEqual(len(lines), 2)

    def test_preflight_attaches_commands_for_image_and_database(self):
        spec = dict(parts=[], database_target=dict(engine='postgres', major=99),
                    identity_plan=dict(parts=[dict(part='app', status='READY', strategy='container', image=runtime.SUPPORTED_KEYCLOAK_IMAGE, gaps=[]),
                                              dict(part='other', status='READY', strategy='container', image='example.invalid/idp:1 --privileged', gaps=[]),
                                              dict(part='blocked', status='BLOCKED', strategy='container', image=runtime.SUPPORTED_KEYCLOAK_IMAGE, gaps=[])]))
        import helix_runtime_isolation as isolation
        with patch.object(runtime, 'plan', return_value=spec), patch.object(runtime, 'locate', side_effect=lambda name: '/synthetic/' + name), \
                patch.object(runtime.subprocess, 'run', return_value=type('Done', (), {'returncode': 1})()), patch.object(runtime.sys, 'platform', 'darwin'), \
                patch.object(isolation.SeatbeltBackend, 'admit', return_value=dict(enforcement='enforced')), patch.object(runtime, 'sysv_segments', return_value=[]):
            found = runtime.preflight('/synthetic/project')
        self.assertEqual([row.get('auto') for row in found if row['area'] == 'identity' and 'obrazu' in row['reason']],
                         [['/synthetic/docker', 'pull', runtime.SUPPORTED_KEYCLOAK_IMAGE], None, None])
        self.assertIsNone(next(row for row in found if row['area'] == 'database').get('auto'))
        spec['database_target']['major'] = 16
        with patch.object(runtime, 'plan', return_value=spec), patch.object(runtime, 'locate', side_effect=lambda name: '/synthetic/' + name), \
                patch.object(runtime, 'native_postgres', return_value=None), \
                patch.object(runtime.subprocess, 'run', return_value=type('Done', (), {'returncode': 1})()), patch.object(runtime.sys, 'platform', 'darwin'), \
                patch.object(isolation.SeatbeltBackend, 'admit', return_value=dict(enforcement='enforced')), patch.object(runtime, 'sysv_segments', return_value=[]):
            found = runtime.preflight('/synthetic/project')
        self.assertEqual(next(row for row in found if row['area'] == 'database')['auto'], ['/synthetic/brew', 'install', 'postgresql@16'])


if __name__ == '__main__':
    unittest.main()
