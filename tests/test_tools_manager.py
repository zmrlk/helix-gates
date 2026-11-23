"""Offline orchestration tests. No package manager or installed tool is run."""
import base64
import fcntl
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
import zipfile

MODULE = Path(__file__).resolve().parents[1] / 'bin/helix_tools_manager.py'
sys.path.insert(0, str(MODULE.parent))
spec = importlib.util.spec_from_file_location('staged_tools_manager', MODULE)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class FakeExecutor:
    def __init__(self, root, *, fault=None):
        self.root, self.fault, self.calls = Path(root), fault, []
        self.pins = self.root / 'pins'
        self.pins.mkdir()
        self.runtime = self.root / 'runtimes'
        self.runtime.mkdir()
        self.runtime_paths = {}
        self.identities = {}
        for name in ('node', 'npm', 'python3', 'python3.12'):
            (self.runtime / name).write_text('synthetic ' + name)
            self.runtime_paths[name] = self.runtime / name
            if name.startswith('python'):
                self.identities[name] = dict(implementation='CPython', version=[3, 12, 8], releaselevel='final')

    @staticmethod
    def wheel(name, version):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            info = zipfile.ZipInfo(name.replace('-', '_') + '-' + version + '.dist-info/METADATA')
            archive.writestr(info, 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: ' + version + '\n')
        return out.getvalue()

    def prepare_pins(self):
        for name, spec in M.CATALOG.items():
            key = 'darwin-arm64' + ('/cp312' if spec['channel'] == 'wheel' else '')
            directory = self.pins / key
            directory.mkdir(parents=True, exist_ok=True)
            pin = dict(schema_version=1, tool=name, version=spec['version'], platform=key)
            if spec['channel'] == 'npm':
                package, version = spec['package'], spec['version']
                item = dict(version=version, resolved='https://registry.npmjs.org/' + package + '/-/package-' + version + '.tgz',
                            integrity='sha512-' + base64.b64encode(hashlib.sha512(b'synthetic tarball').digest()).decode())
                lock = dict(lockfileVersion=3, packages={'': dict(dependencies={package: version}), 'node_modules/' + package: item})
                if name == 'ast-grep':
                    lock['packages']['node_modules/@ast-grep/cli-darwin-arm64'] = dict(item, optional=True)
                    pin['native'] = dict(path='node_modules/@ast-grep/cli-darwin-arm64/ast-grep', sha256=hashlib.sha256(b'synthetic native executable').hexdigest())
                raw = json.dumps(lock).encode()
                (directory / (name + '.package-lock.json')).write_bytes(raw)
                pin['lock_sha256'] = hashlib.sha256(raw).hexdigest()
            else:
                pin['wheels'] = [dict(name=package, version=version, filename=package.replace('-', '_') + '-' + version + '-py3-none-any.whl',
                                     sha256=hashlib.sha256(self.wheel(package, version)).hexdigest())
                                 for package, version in [(spec['package'], spec['version']), ('fixture-dependency', '1.0.0')]]
            (directory / (name + '.json')).write_text(json.dumps(pin))
            if spec['channel'] == 'wheel':
                for abi in ('cp310', 'cp311', 'cp313'):
                    other = self.pins / 'darwin-arm64' / abi
                    other.mkdir(parents=True, exist_ok=True)
                    (other / (name + '.json')).write_text(json.dumps(dict(pin, platform='darwin-arm64/' + abi)))

    def fetch(self, url):
        return b'synthetic tarball' if self.fault != 'bad_tarball' else b'replaced tarball'

    def locate(self, name):
        value = self.runtime_paths.get(name)
        return str(value) if value and value.exists() else None

    def run(self, argv, *, cwd, env, timeout):
        cwd = Path(cwd)
        self.calls.append(dict(argv=list(argv), cwd=str(cwd), env=dict(env), timeout=timeout))
        argv = [arg for arg in argv if arg != '-B']
        if self.fault == 'interrupt' and 'ci' in argv:
            raise KeyboardInterrupt()
        if self.fault == 'timeout':
            raise subprocess.TimeoutExpired(['secret-canary'], timeout, output='secret-canary')
        if self.fault == 'command_error':
            return subprocess.CompletedProcess(argv, 2, 'secret-canary', 'secret-canary')
        result = lambda value='', rc=0: subprocess.CompletedProcess(argv, rc, value, '')
        if argv[1:] == ['-I', '-c', M.PYTHON_IDENTITY_SCRIPT]:
            return result(json.dumps(self.identities[Path(argv[0]).name]))
        if argv[1:] == ['-I', '-c', "from importlib.metadata import version; print(version('mutmut'))"]:
            return result('0.0.1' if self.fault == 'wrong_version' else M.CATALOG['mutmut']['version'])
        if argv[-1:] == ['--version']:
            if 'pip' in argv:
                return result('pip 25.3 from own venv (python 3.12)')
            if argv == [self.locate('node'), self.locate('npm'), '--version']:
                if env['npm_config_userconfig'] == env['npm_config_globalconfig']:
                    return subprocess.CompletedProcess(argv, 1, '', 'Error: double-loading config "/dev/null" as "global", previously loaded as "user"')
                return result('10.9.0')
            runtime = Path(argv[0]).name
            if len(argv) == 2 and Path(argv[0]).parent == self.runtime:
                return result({'node': 'v22.12.0', 'npm': '10.9.0', 'python3': 'Python 3.12.8', 'python3.12': 'Python 3.12.8'}[runtime])
            tool = 'knip' if any(str(value).endswith('/knip.js') for value in argv) else runtime
            return result('0.0.1' if self.fault == 'wrong_version' else M.CATALOG[tool]['version'])
        if 'cache' in argv and 'add' in argv:
            return result()
        if '--package-lock-only' in argv:
            root = json.loads((cwd / 'package.json').read_text())
            package, version = next(iter(root['dependencies'].items()))
            item = dict(version=version, resolved='https://registry.npmjs.org/' + package + '/-/package-' + version + '.tgz', integrity='sha512-' + base64.b64encode(b'x' * 64).decode())
            if self.fault == 'foreign_registry':
                item['resolved'] = 'https://token:secret-canary@example.invalid/file.tgz'
            if self.fault == 'no_hash':
                item.pop('integrity')
            lock = dict(lockfileVersion=3, packages={'': dict(dependencies=root['dependencies']), 'node_modules/' + package: item})
            if package == '@ast-grep/cli':
                lock['packages']['node_modules/@ast-grep/cli-darwin-arm64'] = dict(item, optional=True)
            (cwd / 'package-lock.json').write_text(json.dumps(lock))
            return result()
        if 'ci' in argv:
            lock = json.loads((cwd / 'package-lock.json').read_text())
            for location, item in lock['packages'].items():
                if not location:
                    continue
                package = cwd / location
                package.mkdir(parents=True)
                data = dict(version=item['version'])
                if location == 'node_modules/@ast-grep/cli':
                    data['scripts'] = {'postinstall': 'node postinstall.js'}
                    (package / 'postinstall.js').write_text('synthetic script')
                if location == 'node_modules/knip':
                    (package / 'bin').mkdir()
                    (package / 'bin/knip.js').write_text('synthetic knip')
                if location == 'node_modules/@ast-grep/cli-darwin-arm64':
                    (package / 'ast-grep').write_text('synthetic native executable')
                (package / 'package.json').write_text(json.dumps(data))
                (package / 'dependency.js').write_text('synthetic dependency')
            if self.fault == 'lock_changed':
                (cwd / 'package-lock.json').write_text('{}')
            if self.fault == 'evil_postinstall':
                package = cwd / 'node_modules/@ast-grep/cli/package.json'
                data = json.loads(package.read_text())
                data['scripts']['postinstall'] = 'curl secret-canary'
                package.write_text(json.dumps(data))
            return result()
        if str(argv[-1]).endswith('/postinstall.js'):
            (cwd / 'ast-grep').write_text('synthetic native executable')
            return result()
        if argv[1:4] == ['-I', '-m', 'venv']:
            venv = Path(argv[-1])
            (venv / 'bin').mkdir(parents=True)
            (venv / 'bin/python').symlink_to(argv[0])
            return result()
        if 'download' in argv:
            wheels = Path(argv[argv.index('--dest') + 1])
            for line in Path(argv[-1]).read_text().splitlines():
                name, pin = line.split()[0].split('==')
                filename = name.replace('-', '_') + '-' + pin + '-py3-none-any.whl'
                (wheels / filename).write_bytes(self.wheel(name, pin))
            if self.fault == 'sdist':
                (wheels / 'source.tar.gz').write_bytes(b'bad')
            return result()
        if 'install' in argv and '--require-hashes' in argv:
            name = cwd.parent.parent.name
            (cwd / 'venv/bin' / name).write_text('#!' + str(cwd / 'venv/bin/python') + '\n# synthetic entrypoint\n')
            return result()
        if argv[-1] == 'check':
            return result()
        if self.fault == 'smoke_empty':
            return result('[]')
        if '--pattern' in argv:
            has = (cwd / 'input.js').read_text().startswith('console.log')
            return result(json.dumps([{'range': {'start': {'line': 0}}}] if has else []))
        if any(str(value).endswith('/knip.js') for value in argv):
            # Pinned Knip 6 removed root.files, including for the clean result.
            issues = [dict(file='unused.js', files=[dict(name='unused.js')], exports=[], dependencies=[])] if (cwd / 'unused.js').exists() else []
            return result(json.dumps(dict(issues=issues)), rc=1 if issues else 0)
        if '--output' in argv:
            out = Path(argv[argv.index('--output') + 1])
            has = (cwd / 'b.js').exists()
            value = dict(statistics={'total': {'sources': 2 if has else 1}}, duplicates=[dict(firstFile=dict(name='a.js', startLoc={'line': 1}), secondFile=dict(name='b.js', startLoc={'line': 1}))] if has else [])
            (out / 'jscpd-report.json').write_text(json.dumps(value))
            return result()
        if '--reporter' in argv and 'migration.sql' in argv:
            sql = (cwd / 'migration.sql').read_text()
            rows = [dict(rule_name='prefer-text-field', line=0)] if 'varchar' in sql else []
            if 'PRIMARY KEY' not in sql:
                rows.append(dict(rule_name='require-primary-key', line=0))
            if 'IF NOT EXISTS' not in sql:
                rows.append(dict(rule_name='prefer-robust-stmts', line=0))
            return result(json.dumps(rows), rc=1 if rows else 0)
        if Path(argv[0]).name == 'mutmut':
            if not (cwd / 'pyproject.toml').is_file() or not (cwd / 'src/helix_smoke/example.py').is_file():
                return subprocess.CompletedProcess(argv, 1, '', 'FileNotFoundError: Could not figure out where the code to mutate is.')
        if argv[-1] == '--help':
            return result('Usage: mutmut [OPTIONS] COMMAND [ARGS]...\nCommands:\n  run\n  export-cicd-stats\n')
        if argv[-3:] == ['run', '--max-children', '1']:
            return result()
        if argv[-1] == 'export-cicd-stats':
            out = cwd / 'mutants'
            out.mkdir()
            value = dict(total=2, killed=2, survived=0, no_tests=0, skipped=0, suspicious=0, timeout=0, check_was_interrupted_by_user=0, segfault=0)
            (out / 'mutmut-cicd-stats.json').write_text(json.dumps(value))
            return result()
        raise AssertionError('unexpected fake invocation: ' + str(argv))


class ToolsManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'tools'
        self.executor = FakeExecutor(self.base)
        self.executor.prepare_pins()
        pins = patch.object(M, 'PIN_ROOT', self.executor.pins)
        pins.start()
        self.addCleanup(pins.stop)
        self.platform = patch.multiple(M.platform, system=lambda: 'Darwin', machine=lambda: 'arm64')
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.network = patch.object(subprocess, 'Popen', side_effect=AssertionError('real subprocess forbidden'))
        self.network.start()
        self.addCleanup(self.network.stop)

    def install(self, names, **kwargs):
        return M.install(names, yes=True, tools_root=self.root, executor=self.executor, **kwargs)

    def test_plan_is_read_only_and_has_correct_exact_pins(self):
        result = M.plan(tools_root=self.root)
        self.assertFalse(self.root.exists())
        self.assertEqual(result['execution']['commands'], 0)
        self.assertEqual({row['name']: row['version'] for row in result['tools']}, {'ast-grep': '0.51.0', 'knip': '6.43.0', 'jscpd': '5.4.2', 'squawk': '2.70.0', 'mutmut': '3.8.0'})
        self.assertEqual(next(row for row in result['tools'] if row['name'] == 'squawk')['license'], 'Apache-2.0 OR MIT')
        self.assertEqual(result['excluded'][0]['name'], 'stryker')

    def test_runtime_version_parser_does_not_accept_prerelease_as_pinned(self):
        self.assertEqual(M._version('pip 25.3 from owned venv'), '25.3')
        for text in ('knip 6.43.0-beta', 'ast-grep 0.51.0+modified', 'Python 3.15.0rc1'):
            with self.subTest(text=text), self.assertRaises(M.InstallError):
                M._version(text)

    def test_yes_required_before_any_mutation(self):
        result = M.install(['knip'], tools_root=self.root, executor=self.executor)
        self.assertEqual(result['reason_code'], 'EXPLICIT_YES_REQUIRED')
        self.assertFalse(self.root.exists())
        self.assertEqual(self.executor.calls, [])

    def test_offline_missing_never_creates_or_resolves_packages(self):
        result = self.install(['knip'], offline=True)
        self.assertEqual(result['reason_code'], 'OFFLINE_PACKAGES_MISSING')
        self.assertFalse(self.root.exists())
        self.assertEqual(self.executor.calls, [])

    def test_unknown_duplicate_and_arbitrary_package_refused(self):
        for names in (['stryker'], ['knip@latest'], ['knip', 'knip'], []):
            with self.subTest(names=names), self.assertRaises(M.InstallError):
                self.install(names)
        self.assertFalse(self.root.exists())

    def test_custom_root_requires_injected_executor(self):
        with self.assertRaisesRegex(M.InstallError, 'ROOT_OVERRIDE_TEST_ONLY'):
            M.install(['knip'], yes=True, tools_root=self.root)

    def test_five_installations_have_semantic_smoke_and_synthetic_proof(self):
        result = self.install(list(M.CATALOG))
        self.assertEqual(result['status'], 'COMPLETE', result)
        self.assertEqual(len(result['tools']), 5)
        for name in M.CATALOG:
            installed = M.resolve_installed(name, tools_root=self.root)
            self.assertIsNotNone(installed, name)
            self.assertFalse(installed['usable'])
            receipt = json.loads(Path(installed['receipt']).read_text())
            self.assertEqual(receipt['smoke']['status'], 'PASS')
            self.assertEqual(receipt['proof_kind'], 'synthetic_test')
            self.assertFalse(receipt['smoke']['target_execution'])
            self.assertGreater(len(receipt['dependencies']), 0)
            self.assertEqual(receipt['adapter_status'], 'UNVERIFIED')
        self.assertTrue(all(row['managed_install_status'] == 'SYNTHETIC_ONLY' for row in M.plan(tools_root=self.root)['tools']))

    def test_npm_lock_and_scripts_are_restricted(self):
        result = self.install(['ast-grep', 'knip'])
        self.assertEqual(result['status'], 'COMPLETE', result)
        install = [row for row in self.executor.calls if '--package-lock-only' in row['argv'] or 'ci' in row['argv']]
        self.assertEqual(len(install), 2)
        self.assertTrue(all('--ignore-scripts' in row['argv'] for row in install))
        post = [row for row in self.executor.calls if row['argv'][-1].endswith('/postinstall.js')]
        self.assertEqual(post, [])
        self.assertFalse(any('--package-lock-only' in row['argv'] for row in self.executor.calls))

    def test_npm_cli_outside_node_bin_uses_explicit_node_and_distinct_configs(self):
        npm = self.base / 'npm/lib/node_modules/npm/bin/npm-cli.js'
        npm.parent.mkdir(parents=True)
        npm.write_text('#!/usr/bin/env node\n// synthetic npm CLI\n')
        self.executor.runtime_paths['npm'] = npm
        result = self.install(['ast-grep', 'knip'])
        self.assertEqual(result['status'], 'COMPLETE', result)
        calls = [row for row in self.executor.calls if str(npm) in row['argv']]
        self.assertGreaterEqual(len(calls), 6)
        for row in calls:
            self.assertEqual(row['argv'][:2], [self.executor.locate('node'), str(npm)])
            self.assertEqual(row['env']['PATH'].split(os.pathsep)[0], str(Path(self.executor.locate('node')).parent))
            first, second = (Path(row['env'][key]) for key in ('npm_config_userconfig', 'npm_config_globalconfig'))
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_bytes(), b'')
            self.assertEqual(second.read_bytes(), b'')
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            self.assertEqual(second.stat().st_mode & 0o777, 0o600)

    def test_npm_failure_diagnostic_uses_owner_home_without_changing_process_home(self):
        npm = self.base / 'npm/lib/npm-cli.js'
        npm.parent.mkdir(parents=True)
        npm.write_text('#!/usr/bin/env node\n')
        self.executor.runtime_paths['npm'] = npm
        original = self.executor.run
        def fail_probe(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv == [self.executor.locate('node'), str(npm), '--version']:
                return subprocess.CompletedProcess(argv, 1, '', 'env: node: No such file or directory')
            return result
        self.executor.run = fail_probe
        with patch.object(M.Path, 'home', return_value=self.base):
            row = self.install(['knip'])['tools'][0]
        self.assertEqual(row['reason_code'], 'RUNTIME_PROBE_FAILED')
        self.assertIn('~/npm/lib/npm-cli.js', row['diagnostic']['command'])
        self.assertNotIn(str(self.base), json.dumps(row['diagnostic']))
        for call in self.executor.calls:
            self.assertNotEqual(call['env']['HOME'], str(self.base))
            self.assertTrue(Path(call['env']['HOME']).is_relative_to(self.root))

    def test_mutmut_prefers_existing_cpython312_over_default315(self):
        self.executor.identities['python3']['version'] = [3, 15, 0]
        result = self.install(['mutmut'])
        self.assertEqual(result['status'], 'COMPLETE', result)
        selection = result['tools'][0]['runtime_selection']
        self.assertEqual(selection['candidate_order'], ['python3.12', 'python3.13', 'python3.11', 'python3.10', 'python3'])
        self.assertEqual(selection['selected']['candidate'], 'python3.12')
        self.assertEqual(selection['selected']['version'], '3.12.8')
        self.assertEqual(selection['selected']['implementation'], 'CPython')
        self.assertFalse(selection['retry_after_resolution'])
        self.assertEqual([row['candidate'] for row in selection['candidates']], ['python3.12'])
        venv = next(row for row in self.executor.calls if row['argv'][1:4] == ['-I', '-m', 'venv'])
        self.assertEqual(venv['argv'][0], self.executor.locate('python3.12'))
        active = M.resolve_installed('mutmut', tools_root=self.root)
        self.assertEqual(active['runtime_selection'], selection)
        receipt = json.loads(Path(active['receipt']).read_text())
        self.assertEqual(receipt['runtimes'][0]['version'], '3.12.8')

    def test_mutmut_uses_declared_second_choice_only_when_first_missing(self):
        self.executor.runtime_paths['python3.12'].unlink()
        path = self.executor.runtime / 'python3.13'
        path.write_text('synthetic CPython 3.13')
        self.executor.runtime_paths['python3.13'] = path
        self.executor.identities['python3.13'] = dict(implementation='CPython', version=[3, 13, 7], releaselevel='final')
        result = self.install(['mutmut'])
        self.assertEqual(result['status'], 'COMPLETE', result)
        selection = result['tools'][0]['runtime_selection']
        self.assertEqual(selection['selected']['candidate'], 'python3.13')
        self.assertEqual(selection['candidates'][0]['status'], 'not_found')
        self.assertEqual(selection['candidates'][1]['status'], 'selected')

    def test_mutmut_only315_refused_before_package_resolution(self):
        self.executor.runtime_paths['python3.12'].unlink()
        self.executor.identities['python3']['version'] = [3, 15, 0]
        result = self.install(['mutmut'])
        row = result['tools'][0]
        self.assertEqual(row['reason_code'], 'MUTMUT_INTERPRETER_UNSUPPORTED')
        self.assertIsNone(row['runtime_selection']['selected'])
        self.assertEqual(row['runtime_selection']['candidates'][-1]['version'], '3.15.0')
        self.assertFalse(any('download' in call['argv'] or 'venv' in call['argv'] for call in self.executor.calls))

    def test_mutmut_requires_final_cpython_and_consistent_alias(self):
        self.executor.runtime_paths['python3'].unlink()
        for value, expected in ((dict(implementation='PyPy', version=[3, 12, 8], releaselevel='final'), 'MUTMUT_INTERPRETER_UNSUPPORTED'),
                                (dict(implementation='CPython', version=[3, 12, 0], releaselevel='beta'), 'MUTMUT_INTERPRETER_UNSUPPORTED'),
                                (dict(implementation='CPython', version=[3, 11, 9], releaselevel='final'), 'INTERPRETER_ALIAS_MISMATCH')):
            with self.subTest(value=value):
                self.executor.identities['python3.12'] = value
                result = self.install(['mutmut'])
                selection = result['tools'][0]['runtime_selection']
                self.assertIsNone(selection['selected'])
                self.assertEqual(selection['candidates'][0]['reason_code'], expected)
        self.assertFalse(any('download' in call['argv'] or 'venv' in call['argv'] for call in self.executor.calls))

    def test_mutmut_wheel_failure_never_retries_another_interpreter_and_keeps_diagnostic(self):
        path = self.executor.runtime / 'python3.13'
        path.write_text('synthetic CPython 3.13')
        self.executor.runtime_paths['python3.13'] = path
        self.executor.identities['python3.13'] = dict(implementation='CPython', version=[3, 13, 7], releaselevel='final')
        original = self.executor.run
        def unavailable(argv, **kwargs):
            result = original(argv, **kwargs)
            if 'download' in argv:
                return subprocess.CompletedProcess(argv, 1, 'secret-canary', 'ERROR: No matching distribution found for libcst\nPRIVATE_TOKEN=secret-canary')
            return result
        self.executor.run = unavailable
        result = self.install(['mutmut'])
        row = result['tools'][0]
        self.assertEqual(row['reason_code'], 'WHEEL_RESOLUTION_FAILED')
        self.assertEqual(row['runtime_selection']['selected']['candidate'], 'python3.12')
        self.assertEqual(len(row['runtime_selection']['candidates']), 1)
        probes = [call for call in self.executor.calls if '-c' in call['argv']]
        self.assertEqual(len(probes), 1)
        self.assertEqual(row['diagnostic']['phase'], 'dependency_resolution')
        self.assertEqual(row['diagnostic']['returncode'], 1)
        self.assertIn('libcst', json.dumps(row['diagnostic']))
        self.assertNotIn('secret-canary', json.dumps(result))

    def test_squawk_controls_have_primary_key_and_only_type_differs(self):
        original, snapshots = self.executor.run, []
        def capture(argv, **kwargs):
            if '--reporter' in argv and 'migration.sql' in argv:
                snapshots.append((Path(kwargs['cwd']) / 'migration.sql').read_text())
            return original(argv, **kwargs)
        self.executor.run = capture
        self.assertEqual(self.install(['squawk'])['status'], 'COMPLETE')
        self.assertEqual(len(snapshots), 2)
        self.assertEqual(snapshots[0].replace('varchar(255)', 'text'), snapshots[1])
        self.assertTrue(all('id bigint PRIMARY KEY' in text for text in snapshots))
        self.assertTrue(all('CREATE TABLE IF NOT EXISTS public.helix_smoke' in text for text in snapshots))

    def test_knip_v6_grouped_files_and_empty_issues_are_required(self):
        result = self.install(['knip'])
        self.assertEqual(result['status'], 'COMPLETE', result)
        receipt = json.loads(Path(result['tools'][0]['receipt']).read_text())
        self.assertEqual(receipt['smoke']['id'], 'knip-synthetic-v2')
        calls = [row for row in self.executor.calls if '--reporter' in row['argv']]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]['cwd'], calls[1]['cwd'])

    def test_knip_old_schema_empty_or_wrong_file_cannot_activate(self):
        original = self.executor.run
        cases = ({'files': ['unused.js'], 'issues': []}, {'issues': []},
                 {'issues': [{'file': 'other/unused.js', 'files': [{'name': 'other/unused.js'}]}]},
                 {'issues': [{'file': 'unused.js', 'files': ['unused.js']}]})
        for index, payload in enumerate(cases):
            with self.subTest(payload=payload):
                def output(argv, **kwargs):
                    value = original(argv, **kwargs)
                    if '--reporter' in argv:
                        return subprocess.CompletedProcess(argv, 1, json.dumps(payload), '')
                    return value
                self.executor.run = output
                result = M.install(['knip'], yes=True, tools_root=self.base / str(index), executor=self.executor)
                self.assertEqual(result['tools'][0]['reason_code'], 'SMOKE_EXPECTED_FINDING_MISSING')
                self.assertIn('Smoke Knip:', result['tools'][0]['diagnostic']['hints'][0])
                self.assertIsNone(M.resolve_installed('knip', tools_root=self.base / str(index)))

    def test_knip_negative_rejects_unexpected_issues_without_leaking_names(self):
        original = self.executor.run
        def output(argv, **kwargs):
            value = original(argv, **kwargs)
            if '--reporter' in argv and not (Path(kwargs['cwd']) / 'unused.js').exists():
                return subprocess.CompletedProcess(argv, 0, json.dumps({'issues': [{'file': 'secret-canary.js', 'files': [], 'exports': [{'name': 'secret-canary'}]}]}), '')
            return value
        self.executor.run = output
        row = self.install(['knip'])['tools'][0]
        self.assertEqual(row['reason_code'], 'SMOKE_NEGATIVE_FAILED')
        self.assertIn('grupy 1', row['diagnostic']['hints'][0])
        self.assertNotIn('secret-canary', json.dumps(row))

    def test_mutmut_version_uses_distribution_then_help_in_valid_fixture(self):
        original, configured = self.executor.run, []
        def capture(argv, **kwargs):
            if Path(argv[0]).name == 'mutmut':
                self.assertNotIn('--version', argv)
                root = Path(kwargs['cwd'])
                config = (root / 'pyproject.toml').read_text()
                self.assertIn('source_paths = ["src/"]', config)
                self.assertIn('pytest_add_cli_args_test_selection = ["tests/"]', config)
                self.assertNotIn('pythonpath', config)
                self.assertIn('from helix_smoke.example import increment', (root / 'tests/test_example.py').read_text())
                configured.append(argv[1:])
            return original(argv, **kwargs)
        self.executor.run = capture
        result = self.install(['mutmut'])
        self.assertEqual(result['status'], 'COMPLETE', result)
        self.assertEqual(configured, [['--help'], ['run', '--max-children', '1'], ['export-cicd-stats']])
        metadata = next(row for row in self.executor.calls if 'importlib.metadata' in row['argv'][-1])
        self.assertEqual(metadata['argv'][1:4], ['-I', '-B', '-c'])
        self.assertTrue(metadata['argv'][0].endswith('/venv/bin/python'))
        receipt = json.loads(Path(result['tools'][0]['receipt']).read_text())
        self.assertEqual(receipt['version_probe'], {'method': 'distribution_metadata', 'distribution': 'mutmut', 'version': '3.8.0'})

    def test_mutmut_metadata_mismatch_refuses_before_help_or_run(self):
        self.executor.fault = 'wrong_version'
        row = self.install(['mutmut'])['tools'][0]
        self.assertEqual(row['reason_code'], 'VERSION_MISMATCH')
        self.assertFalse(any(Path(call['argv'][0]).name == 'mutmut' for call in self.executor.calls))

    def test_mutmut_help_without_required_commands_is_not_smoke(self):
        original = self.executor.run
        def output(argv, **kwargs):
            value = original(argv, **kwargs)
            if argv[-1] == '--help':
                return subprocess.CompletedProcess(argv, 0, 'secret-canary', '')
            return value
        self.executor.run = output
        row = self.install(['mutmut'])['tools'][0]
        self.assertEqual(row['reason_code'], 'SMOKE_EXPECTED_FINDING_MISSING')
        self.assertIn('help', row['diagnostic']['hints'][0])
        self.assertNotIn('secret-canary', json.dumps(row))
        self.assertFalse(any('run' in call['argv'][1:] for call in self.executor.calls))

    def test_mutmut_zero_untested_surviving_and_incomplete_stats_refuse_activation(self):
        original = self.executor.run
        cases = ({'total': 0, 'killed': 0}, {'killed': 1, 'survived': 1},
                 {'killed': 1, 'no_tests': 1}, {'killed': 1, 'skipped': 1},
                 {'total': True}, {'total': 3})
        for index, delta in enumerate(cases):
            with self.subTest(delta=delta):
                def output(argv, **kwargs):
                    value = original(argv, **kwargs)
                    if argv[-1] == 'export-cicd-stats':
                        path = Path(kwargs['cwd']) / 'mutants/mutmut-cicd-stats.json'
                        stats = json.loads(path.read_text())
                        stats.update(delta)
                        path.write_text(json.dumps(stats))
                    return value
                self.executor.run = output
                root = self.base / str(index)
                row = M.install(['mutmut'], yes=True, tools_root=root, executor=self.executor)['tools'][0]
                self.assertEqual(row['reason_code'], 'SMOKE_MUTATION_INCOMPLETE')
                self.assertIn('Smoke mutmut:', row['diagnostic']['hints'][0])
                self.assertIsNone(M.resolve_installed('mutmut', tools_root=root))

    def test_mutmut_rc_zero_without_valid_stats_never_activates(self):
        original = self.executor.run
        for index, malformed in enumerate((None, '{"incomplete"', '{"source":"secret-canary"}')):
            with self.subTest(malformed=malformed):
                def output(argv, **kwargs):
                    value = original(argv, **kwargs)
                    if argv[-1] == 'export-cicd-stats':
                        path = Path(kwargs['cwd']) / 'mutants/mutmut-cicd-stats.json'
                        if malformed is None:
                            path.unlink()
                        else:
                            path.write_text(malformed)
                    return value
                self.executor.run = output
                root = self.base / str(index)
                row = M.install(['mutmut'], yes=True, tools_root=root, executor=self.executor)['tools'][0]
                self.assertEqual(row['reason_code'], 'SMOKE_MUTATION_INCOMPLETE')
                self.assertIn('mutation_stats', row['diagnostic']['hints'][0])
                self.assertNotIn('secret-canary', json.dumps(row))
                self.assertIsNone(M.resolve_installed('mutmut', tools_root=root))

    def test_squawk_negative_failure_keeps_bounded_semantic_reason(self):
        original = self.executor.run
        def wrong_negative(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--reporter' in argv and 'migration.sql' in argv and 'varchar' not in (Path(kwargs['cwd']) / 'migration.sql').read_text():
                return subprocess.CompletedProcess(argv, 0, json.dumps([dict(rule_name='require-primary-key', line=0, message='secret-canary', file='/private/secret-canary.sql')]), '')
            return result
        self.executor.run = wrong_negative
        row = self.install(['squawk'])['tools'][0]
        self.assertEqual(row['reason_code'], 'SMOKE_NEGATIVE_FAILED')
        self.assertEqual(row['diagnostic']['phase'], 'smoke')
        self.assertEqual(row['diagnostic']['returncode'], 0)
        self.assertIn('require-primary-key', json.dumps(row['diagnostic']))
        self.assertNotIn('secret-canary', json.dumps(row))

    def test_wheels_hash_lock_install_no_index_and_no_relocation(self):
        result = self.install(['mutmut'])
        self.assertEqual(result['status'], 'COMPLETE', result)
        active = M.resolve_installed('mutmut', tools_root=self.root)
        receipt = json.loads(Path(active['receipt']).read_text())
        venv_call = next(row for row in self.executor.calls if row['argv'][1:4] == ['-I', '-m', 'venv'])
        directory = Path(active['receipt']).parent
        self.assertEqual(venv_call['argv'][-1], str(directory / 'venv'))
        install = next(row['argv'] for row in self.executor.calls if 'install' in row['argv'] and '--require-hashes' in row['argv'])
        for flag in ('--no-index', '--no-deps', '--no-compile', '--only-binary=:all:'):
            self.assertIn(flag, install)
        self.assertEqual(len(receipt['dependencies']), 2)
        for row in receipt['dependencies']:
            self.assertIn(row['sha256'], (directory / 'requirements.lock').read_text())

    def test_environment_has_no_caller_credentials_or_loaders(self):
        with patch.dict(os.environ, {'SECRET_KEY': 'secret-canary', 'NODE_OPTIONS': '--require secret-canary', 'PYTHONPATH': 'secret-canary', 'HTTP_PROXY': 'secret-canary', 'NPM_CONFIG_REGISTRY': 'secret-canary'}):
            self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        for row in self.executor.calls:
            self.assertNotIn('secret-canary', json.dumps(row))
            self.assertTrue(Path(row['cwd']).is_relative_to(self.root))
            self.assertNotEqual(row['env']['npm_config_userconfig'], row['env']['npm_config_globalconfig'])
            for key in ('npm_config_userconfig', 'npm_config_globalconfig'):
                self.assertTrue(Path(row['env'][key]).is_relative_to(Path(row['env']['HOME'])))
                self.assertEqual(Path(row['env'][key]).read_bytes(), b'')
            self.assertEqual(row['env']['PIP_CONFIG_FILE'], os.devnull)
            if '--reporter' in row['argv']:
                self.assertEqual(row['env']['npm_config_offline'], 'true')
                self.assertEqual(row['env']['PIP_NO_INDEX'], '1')

    def test_npm_bad_source_integrity_lock_and_postinstall_do_not_activate(self):
        for fault in ('bad_tarball', 'lock_changed'):
            with self.subTest(fault=fault):
                self.executor.fault = fault
                result = self.install(['ast-grep'])
                self.assertEqual(result['status'], 'INCOMPLETE', result)
                self.assertIsNone(M.resolve_installed('ast-grep', tools_root=self.root))
                self.assertNotIn('secret-canary', json.dumps(result))

    def test_sdist_wrong_version_empty_smoke_refuse_activation(self):
        for fault, tool in (('sdist', 'mutmut'), ('wrong_version', 'knip'), ('smoke_empty', 'ast-grep')):
            with self.subTest(fault=fault):
                self.executor.fault = fault
                result = self.install([tool])
                self.assertEqual(result['status'], 'INCOMPLETE', result)
                self.assertIsNone(M.resolve_installed(tool, tools_root=self.root))

    def test_known_wheel_hash_mismatch_refused(self):
        wheels = self.base / 'wheels'
        wheels.mkdir()
        path = wheels / next(iter(M.WHEEL_HASHES))
        path.write_bytes(b'wrong')
        with self.assertRaisesRegex(M.InstallError, 'PACKAGE_HASH_MISMATCH'):
            M._wheels(wheels, M.CATALOG['jscpd'])

    def test_interruption_and_failure_preserve_other_active_installation(self):
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        previous = (self.root / 'active.json').read_bytes()
        self.executor.fault = 'interrupt'
        with self.assertRaises(KeyboardInterrupt):
            self.install(['ast-grep'])
        self.assertEqual((self.root / 'active.json').read_bytes(), previous)
        self.assertEqual(list((self.root / 'ast-grep/0.51.0').iterdir()), [])
        self.executor.fault = 'command_error'
        result = self.install(['ast-grep'])
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual((self.root / 'active.json').read_bytes(), previous)
        self.assertNotIn('secret-canary', json.dumps(result))

    def test_timeout_is_redacted_and_does_not_activate(self):
        self.executor.fault = 'timeout'
        result = self.install(['knip'])
        self.assertEqual(result['tools'][0]['reason_code'], 'INSTALL_TIMEOUT')
        self.assertNotIn('secret-canary', json.dumps(result))
        self.assertFalse((self.root / 'active.json').exists())

    def test_repeat_and_offline_reuse_do_not_execute_commands(self):
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        self.executor.calls.clear()
        self.assertEqual(self.install(['knip'])['tools'][0]['status'], 'REUSED')
        self.assertEqual(self.install(['knip'], offline=True)['status'], 'REUSED')
        self.assertEqual(self.executor.calls, [])

    def test_mutated_dependency_and_added_loader_invalidate_resolution(self):
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        receipt = Path(M.resolve_installed('knip', tools_root=self.root)['receipt'])
        dep = receipt.parent / 'node_modules/knip/dependency.js'
        original = dep.read_text()
        dep.write_text('changed')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))
        dep.write_text(original)
        self.assertIsNotNone(M.resolve_installed('knip', tools_root=self.root))
        (dep.parent / 'new-loader.js').write_text('added')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))

    def test_tampered_receipt_and_runtime_invalidate_resolution(self):
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        receipt = Path(M.resolve_installed('knip', tools_root=self.root)['receipt'])
        raw = receipt.read_bytes()
        receipt.write_bytes(raw + b' ')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))
        receipt.write_bytes(raw)
        (self.executor.runtime / 'node').write_text('replaced runtime')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))

    def test_changed_file_permissions_invalidate_resolution(self):
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        active = M.resolve_installed('knip', tools_root=self.root)
        path = Path(active['argv_prefix'][-1])
        path.chmod(0o700)
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))

    def test_symlink_root_and_active_manifest_are_refused(self):
        target = self.base / 'outside'
        target.mkdir()
        self.root.symlink_to(target, target_is_directory=True)
        result = self.install(['knip'])
        self.assertEqual(result['reason_code'], 'UNSAFE_PATH')
        self.assertEqual(list(target.iterdir()), [])
        self.root.unlink()
        self.root.mkdir(mode=0o700)
        (self.root / 'active.json').symlink_to(target / 'foreign.json')
        result = self.install(['knip'])
        self.assertEqual(result['status'], 'INCOMPLETE', result)
        self.assertFalse((target / 'foreign.json').exists())

    def test_install_lock_prevents_lost_update(self):
        self.root.mkdir(mode=0o700)
        with (self.root / '.install.lock').open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.install(['knip'])
        self.assertEqual(result['reason_code'], 'INSTALL_BUSY')
        self.assertEqual(self.executor.calls, [])

    def test_world_writable_installation_root_is_not_trusted(self):
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        self.root.chmod(0o777)
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))
        self.assertEqual(self.install(['ast-grep'])['reason_code'], 'UNSAFE_ROOT')

    def test_malformed_active_manifest_is_not_a_ready_installation(self):
        self.root.mkdir(mode=0o700)
        for value in (None, [], True, {'schema_version': True, 'tools': {}}):
            with self.subTest(value=value):
                (self.root / 'active.json').write_text(json.dumps(value))
                self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))
                result = self.install(['knip'])
                self.assertEqual(result['status'], 'INCOMPLETE')
                self.assertEqual(json.loads((self.root / 'active.json').read_text()), value)

    def test_node_package_tree_escape_is_rejected_before_smoke(self):
        original = self.executor.run
        def introduce_link(argv, **kwargs):
            result = original(argv, **kwargs)
            if 'ci' in argv:
                path = Path(kwargs['cwd']) / 'node_modules/knip/dependency.js'
                path.unlink()
                path.symlink_to(self.executor.runtime / 'python3')
            return result
        self.executor.run = introduce_link
        result = self.install(['knip'])
        self.assertEqual(result['status'], 'INCOMPLETE', result)
        self.assertEqual(result['tools'][0]['reason_code'], 'INSTALLED_SYMLINK_ESCAPE')
        self.assertFalse(any('--reporter' in row['argv'] for row in self.executor.calls))

    def test_link_to_unhashed_installation_home_is_rejected(self):
        original = self.executor.run
        def introduce_link(argv, **kwargs):
            result = original(argv, **kwargs)
            if 'ci' in argv:
                directory = Path(kwargs['cwd'])
                target = directory / 'home/unhashed-dependency.js'
                target.write_text('unhashed dependency')
                link = directory / 'node_modules/knip/dependency.js'
                link.unlink()
                link.symlink_to(target)
            return result
        self.executor.run = introduce_link
        result = self.install(['knip'])
        self.assertEqual(result['tools'][0]['reason_code'], 'INSTALLED_SYMLINK_ESCAPE')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))
        self.assertFalse(any('--reporter' in row['argv'] for row in self.executor.calls))

    def test_internal_symlink_target_is_hashed_and_change_invalidates(self):
        original = self.executor.run
        def introduce_link(argv, **kwargs):
            result = original(argv, **kwargs)
            if 'ci' in argv:
                package = Path(kwargs['cwd']) / 'node_modules/knip'
                (package / 'target.js').write_text('hashed target')
                link = package / 'dependency.js'
                link.unlink()
                link.symlink_to('target.js')
            return result
        self.executor.run = introduce_link
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        receipt = Path(M.resolve_installed('knip', tools_root=self.root)['receipt'])
        (receipt.parent / 'node_modules/knip/target.js').write_text('changed target')
        self.assertIsNone(M.resolve_installed('knip', tools_root=self.root))

    def test_parent_swap_does_not_redirect_file_read_or_write(self):
        original = M.os.open
        for operation in ('read', 'write'):
            with self.subTest(operation=operation):
                parent = self.base / ('parent-' + operation)
                retained = self.base / ('retained-' + operation)
                outside = self.base / ('outside-' + operation)
                parent.mkdir(); outside.mkdir()
                if operation == 'read':
                    (parent / 'value.txt').write_text('owned')
                    (outside / 'value.txt').write_text('outside-canary')
                swapped = []
                def swap(name, flags, *args, **kwargs):
                    if name == 'value.txt' and kwargs.get('dir_fd') is not None and not swapped:
                        parent.rename(retained)
                        parent.symlink_to(outside, target_is_directory=True)
                        swapped.append(True)
                    return original(name, flags, *args, **kwargs)
                with patch.object(M.os, 'open', side_effect=swap):
                    if operation == 'read':
                        self.assertEqual(M._read(parent / 'value.txt'), b'owned')
                    else:
                        M._write(parent / 'value.txt', b'owned')
                self.assertEqual(swapped, [True])
                self.assertEqual((retained / 'value.txt').read_text(), 'owned')
                if operation == 'write':
                    self.assertFalse((outside / 'value.txt').exists())

    def test_parent_swap_does_not_redirect_atomic_publication(self):
        parent, retained, outside = (self.base / name for name in ('publish', 'retained', 'outside'))
        parent.mkdir(); outside.mkdir()
        (parent / 'active.json').write_text('{"old":true}')
        (outside / 'active.json').write_text('{"outside":true}')
        original = M.os.replace
        def swap(source, destination, **kwargs):
            parent.rename(retained)
            parent.symlink_to(outside, target_is_directory=True)
            self.assertIsNotNone(kwargs.get('src_dir_fd'))
            self.assertEqual(kwargs['src_dir_fd'], kwargs.get('dst_dir_fd'))
            return original(source, destination, **kwargs)
        with patch.object(M.os, 'replace', side_effect=swap):
            M._atomic(parent / 'active.json', {'new': True})
        self.assertEqual(json.loads((retained / 'active.json').read_text()), {'new': True})
        self.assertEqual(json.loads((outside / 'active.json').read_text()), {'outside': True})

    def test_parent_swap_does_not_redirect_directory_creation(self):
        parent, retained, outside = (self.base / name for name in ('mkdir', 'retained', 'outside'))
        parent.mkdir(); outside.mkdir()
        original = M.os.mkdir
        def swap(name, *args, **kwargs):
            if name == 'child':
                parent.rename(retained)
                parent.symlink_to(outside, target_is_directory=True)
                self.assertIsNotNone(kwargs.get('dir_fd'))
            return original(name, *args, **kwargs)
        with patch.object(M.os, 'mkdir', side_effect=swap):
            M._mkdir(parent / 'child')
        self.assertTrue((retained / 'child').is_dir())
        self.assertFalse((outside / 'child').exists())

    def test_atomic_publication_failure_keeps_previous_selection(self):
        self.assertEqual(self.install(['knip'])['status'], 'COMPLETE')
        original = (self.root / 'active.json').read_bytes()
        with patch.object(M.os, 'replace', side_effect=OSError('secret-canary')):
            result = self.install(['squawk'])
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual((self.root / 'active.json').read_bytes(), original)
        self.assertNotIn('secret-canary', json.dumps(result))
        self.assertEqual(list((self.root / 'squawk/2.70.0').iterdir()), [])

    def test_real_executor_contract_closes_owned_group_on_interrupt(self):
        process = Mock(pid=123, returncode=0)
        process.wait.side_effect = [KeyboardInterrupt(), 0]
        with patch.object(M.subprocess, 'Popen', return_value=process) as popen, patch.object(M.os, 'killpg') as kill:
            with self.assertRaises(KeyboardInterrupt):
                M.Executor().run(['/synthetic'], cwd=self.base, env={}, timeout=1)
        self.assertEqual(kill.call_args.args[0], 123)
        options = popen.call_args.kwargs
        self.assertTrue(options['close_fds'])
        self.assertEqual(options['pass_fds'], ())
        self.assertEqual(options['stdin'], subprocess.DEVNULL)
        self.assertTrue(options['start_new_session'])

    def test_real_executor_closes_group_after_successful_launcher_exit(self):
        process = Mock(pid=123, returncode=0)
        process.wait.return_value = 0
        with patch.object(M.subprocess, 'Popen', return_value=process), patch.object(M.os, 'killpg') as kill:
            result = M.Executor().run(['/synthetic'], cwd=self.base, env={}, timeout=1)
        self.assertEqual(result.returncode, 0)
        kill.assert_called_once_with(123, M.signal.SIGKILL)

    def test_real_executor_preserves_bounded_stderr_tail(self):
        process = Mock(pid=123, returncode=1)
        process.wait.return_value = 1
        def popen(argv, **kwargs):
            kwargs['stderr'].write(b'x' * 200 + b'known diagnostic tail')
            return process
        with patch.object(M.subprocess, 'Popen', side_effect=popen), patch.object(M.os, 'killpg'), patch.object(M, 'MAX_OUTPUT', 64):
            result = M.Executor().run(['/synthetic'], cwd=self.base, env={}, timeout=1)
        self.assertEqual(len(result.stderr.encode()), 64)
        self.assertTrue(result.stderr.endswith('known diagnostic tail'))

    def test_lock_path_fifo_is_not_opened_for_blocking_read(self):
        self.root.mkdir(mode=0o700)
        os.mkfifo(self.root / '.install.lock')
        self.assertEqual(self.install(['knip'])['reason_code'], 'UNSAFE_LOCK')
        self.assertEqual(self.executor.calls, [])

    def test_unsupported_platform_and_old_node_refused_without_packages(self):
        with patch.object(M.platform, 'system', return_value='Windows'):
            result = self.install(['knip'])
        self.assertEqual(result['tools'][0]['reason_code'], 'UNSUPPORTED_PLATFORM')
        self.assertEqual(self.executor.calls, [])
        original = self.executor.run
        def old_node(argv, **kwargs):
            if argv == [str(self.executor.runtime / 'node'), '--version']:
                return subprocess.CompletedProcess(argv, 0, 'v21.1.0', '')
            return original(argv, **kwargs)
        self.executor.run = old_node
        result = self.install(['knip'])
        self.assertEqual(result['tools'][0]['reason_code'], 'RUNTIME_VERSION_UNSUPPORTED')
        self.assertFalse(any('--package-lock-only' in row['argv'] for row in self.executor.calls))


if __name__ == '__main__':
    unittest.main()
