"""Independent PostgreSQL extension parsing and admission; fake processes only."""
import builtins
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_runtime import FakeExecutor, FIX, TOOLS
import helix_runtime as runtime
import helix_runtime_extensions as extensions


CANARY = 'PRIVATE_EXTENSION_CATALOG_CANARY'


class ExtensionExecutor(FakeExecutor):
    def __init__(self, respond=None):
        super().__init__()
        self.respond = respond
        self.catalog_calls = []

    def run(self, argv, cwd, env, timeout):
        if argv[-1] == extensions.AVAILABLE_EXTENSIONS_SQL:
            self.catalog_calls.append(argv[1])
            if self.respond is not None:
                self.calls.append((argv, Path(cwd), dict(env), timeout))
                return self.respond(argv, len(self.catalog_calls))
        return super().run(argv, cwd, env, timeout)


def catalog(*names):
    return json.dumps([dict(name=name, default_version='1.0', installed_version=None) for name in names])


class RuntimeExtensionsAdversarial(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.number = 0

    def make_runner(self, *, respond=None, fixture='sveltekit-pg'):
        self.number += 1
        project = self.base / ('project-' + str(self.number)); shutil.copytree(FIX / fixture, project)
        executor = ExtensionExecutor(respond)
        runner = runtime.Runner(project, self.base / ('out-' + str(self.number)), engine='native',
            executor=executor, tools={'tools': dict(TOOLS)}, port_factory=lambda: 31234)
        return runner, project

    def manual(self, respond=None):
        runner, project = self.make_runner(respond=lambda *_: (0, catalog(*extensions.COMMON_EXTENSIONS)))
        runner.work = project; runner.tmp = self.base / ('scratch-' + str(self.number)); runner.tmp.mkdir(mode=0o700)
        (runner.tmp / 'home').mkdir(mode=0o700); (runner.out / 'logs').mkdir(parents=True)
        runner.env = dict(PATH='/fake', HOME=str(runner.tmp / 'home'), CI='1')
        with self.offline(): runner.database()
        runner.executor.respond = respond
        def cleanup():
            with self.offline():
                for action in reversed(runner.database_cleanup + runner.cleanup_actions): action()
        self.addCleanup(cleanup)
        return runner, project

    def migration(self, project, path, name):
        source = project / path; source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('CREATE EXTENSION IF NOT EXISTS "' + name + '";\nCREATE TABLE synthetic_items(id integer);\n')
        return dict(kind='sql', path=path)

    def saved_checks(self, runner):
        return json.loads((runner.out / 'database-fidelity.json').read_text())['extension_checks']

    @contextlib.contextmanager
    def offline(self):
        with contextlib.redirect_stderr(io.StringIO()), \
             patch.object(socket, 'socket', side_effect=AssertionError('unexpected network')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected process')), \
             patch('helix_environment._git_ref', return_value={
                 'head': None, 'dirty': None, 'status': 'unknown', 'reason': 'synthetic fixture'}):
            yield

    def test_only_literal_active_up_declarations_preserve_original_lines(self):
        lines = [
            '-- migrate:up',
            '-- CREATE EXTENSION pgcrypto;',
            '/* CREATE EXTENSION fuzzystrmatch;',
            ' /* CREATE EXTENSION postgis; */ */',
            "SELECT 'CREATE EXTENSION vector;';",
            'DO $body$',
            'BEGIN',
            '-- migrate:down',
            "  EXECUTE 'CREATE EXTENSION pgcrypto';",
            'END $body$;',
            'CrEaTe',
            ' EXTENSION IF NOT EXISTS "pg_trgm";',
            'CREATE EXTENSION btree_gist;',
            '-- migrate:down',
            'CREATE EXTENSION fuzzystrmatch;',
        ]
        with patch.object(builtins, 'open', side_effect=AssertionError('pure parser I/O')):
            parsed = extensions.sql_extensions('\n'.join(lines), path='db/migrations/001.sql')
        self.assertEqual(parsed['declarations'], [
            dict(name='pg_trgm', path='db/migrations/001.sql', line=11, declared_version=None),
            dict(name='btree_gist', path='db/migrations/001.sql', line=13, declared_version=None)])
        self.assertEqual(parsed['gaps'], [dict(path='db/migrations/001.sql', line=6,
            reason_code='dynamic_sql_requirements_unresolved')])

    def test_catalog_is_strict_and_available_does_not_mean_installed(self):
        result = extensions.parse_available_extensions(catalog('pg_trgm'))
        self.assertEqual(result, {'pg_trgm': {'default_version': '1.0', 'installed_version': None}})
        bad = ['not-json ' + CANARY, '{}', 'null', '[true]',
            json.dumps([dict(name='pg_trgm', default_version=1, installed_version=None)]),
            json.dumps([dict(name='pg_trgm', default_version='1', installed_version=False)]),
            json.dumps([dict(name='pg_trgm', default_version='1', installed_version=None, private=CANARY)]),
            json.dumps([dict(name='pg_trgm', default_version='1', installed_version=None)] * 2)]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError) as caught:
                extensions.parse_available_extensions(value)
            self.assertNotIn(CANARY, str(caught.exception))

    def test_special_image_profiles_do_not_conflict_with_common_extensions(self):
        for names, image, conflict in [
            (('vector', 'pg_trgm'), 'pgvector/pgvector:pg16', False),
            (('postgis', 'btree_gist'), 'postgis/postgis:16-3.5', False),
            (('pgcrypto', 'fuzzystrmatch'), 'postgres:16-alpine', False),
            (('vector', 'postgis'), None, True),
        ]:
            with self.subTest(names=names):
                self.number += 1; project = self.base / ('profile-' + str(self.number)); project.mkdir()
                (project / 'compose.yml').write_text('services:\n  db:\n    image: postgres:16\n')
                (project / 'schema.sql').write_text('\n'.join('CREATE EXTENSION ' + name + ';' for name in names))
                target = runtime.database_target(project)
                self.assertEqual(set(target['extensions']), set(names))
                if image is not None: self.assertEqual(target['image'], image)
                self.assertEqual(target['extension_profile_conflict'], conflict)

    def test_missing_required_extension_blocks_before_sql_and_project_runner(self):
        runner, project = self.manual(lambda *_: (0, catalog('pg_trgm')))
        sql = self.migration(project, 'db/migrations/required.sql', 'pgcrypto')
        script = project / 'migrate.sh'; script.write_text('#!/bin/sh\nexit 0\n')
        project_runner = dict(kind='runner', path='migrate.sh', argv=['bash', 'migrate.sh'], env={})
        before = len(runner.executor.calls)
        with self.offline(), self.assertRaises(runtime.Blocked):
            runner.migrate(dict(migrations=[project_runner, sql]), seed=False)
        later = [call[0] for call in runner.executor.calls[before:]]
        self.assertFalse(any(command[0] == 'bash' or '-f' in command for command in later))
        self.assertEqual(runner.applied, set())
        row = self.saved_checks(runner)[-1]
        self.assertEqual(row['status'], 'blocked')
        self.assertEqual(row['missing'], ['pgcrypto'])
        self.assertEqual(row['declarations'], [dict(name='pgcrypto', path=sql['path'], line=1, declared_version=None)])
        self.assertEqual(row['version_check'], 'not_checked')
        self.assertTrue((runner.out / row['log']).is_file())

    def test_invalid_query_results_never_become_ready_even_with_exit_zero(self):
        cases = [lambda *_: (0, 'not-json ' + CANARY), lambda *_: (0, '{}'),
                 lambda *_: (0, catalog('pg_trgm', 'pg_trgm')), lambda *_: (2, 'synthetic catalog failure')]
        def timeout(argv, _): raise subprocess.TimeoutExpired(argv, 1)
        def pause(*_): raise runtime.ResourcePaused('synthetic admission pause')
        cases.extend([timeout, pause])
        for responder in cases:
            with self.subTest(responder=responder):
                runner, project = self.manual(responder)
                sql = self.migration(project, 'db/migrations/required.sql', 'pg_trgm')
                with self.offline(), self.assertRaises((runtime.Blocked, runtime.ResourcePaused)):
                    runner.extension_preflight(dict(migrations=[sql]), part='frontend')
                row = self.saved_checks(runner)[-1]
                self.assertEqual(row['status'], 'incomplete')
                self.assertNotIn(CANARY, json.dumps(row))
                self.assertEqual(runner.applied, set())

    def test_trial_databases_have_separate_preflight_cleanup_and_candidate_scope(self):
        runner, project = self.manual(lambda *_: (0, catalog('pg_trgm')))
        missing = self.migration(project, 'db/a.sql', 'pgcrypto')
        available = self.migration(project, 'db/b.sql', 'pg_trgm')
        part = dict(path='.', env=[], migrations=[missing, available], schema_selection={}, schema_strategies=[
            dict(root='db', strategy='needs-crypto', trial_required=True, candidates=[
                dict(strategy='needs-crypto', migrations=[missing]), dict(strategy='needs-trgm', migrations=[available])])])
        original = runner.db
        with self.offline(): runner.select_schema(part)
        self.assertEqual(runner.db, original)
        rows = [r for r in self.saved_checks(runner) if r['scope'] == 'trial']
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({r['database'] for r in rows}), 2)
        self.assertEqual([(r['candidate'], r['required'], r['status']) for r in rows],
            [('needs-crypto', ['pgcrypto'], 'blocked'), ('needs-trgm', ['pg_trgm'], 'ready')])
        group = part['schema_strategies'][0]
        self.assertEqual(group['strategy'], 'needs-trgm')
        self.assertEqual([r['status'] for r in group['results']], ['failed', 'applied'])
        commands = [c[0] for c in runner.executor.calls]
        drops = [c[-1] for c in commands if c[-1].startswith('DROP DATABASE IF EXISTS helix_trial_')]
        for row in rows: self.assertIn('DROP DATABASE IF EXISTS ' + row['database'] + ' WITH (FORCE)', drops)
        blocked_database = rows[0]['database']
        self.assertFalse(any('-f' in c and c[1].endswith('/' + blocked_database) for c in commands))
        self.assertEqual(sum(url.endswith('/' + rows[1]['database']) for url in runner.executor.catalog_calls), 1)

    def test_restore_checks_its_own_catalog_before_restore_and_preserves_source_evidence(self):
        runner, project = self.manual(lambda argv, _: (0, catalog() if 'helix_restore_' in argv[1] else catalog('pgcrypto')))
        sql = self.migration(project, 'db/migrations/required.sql', 'pgcrypto')
        with self.offline(): runner.migrate(dict(migrations=[sql]), seed=False)
        source = copy.deepcopy(self.saved_checks(runner)[-1])
        self.assertEqual(source['status'], 'ready')
        with self.offline(), self.assertRaises(runtime.Blocked): runner.backup()
        rows = self.saved_checks(runner)
        restore = rows[-1]
        self.assertEqual(restore['scope'], 'restore')
        self.assertEqual(restore['status'], 'blocked')
        self.assertEqual(restore['missing'], ['pgcrypto'])
        self.assertTrue(restore['database'].startswith('helix_restore_'))
        self.assertIn(source, rows)
        commands = [c[0] for c in runner.executor.calls]
        self.assertFalse(any(c[0].endswith('pg_restore') or 'pg_restore' in c for c in commands))
        self.assertTrue(runner.database_cleanup)
        with self.offline():
            for action in runner.database_cleanup: action()
        self.assertTrue(any('DROP DATABASE IF EXISTS ' + restore['database'] in c[0][-1] for c in runner.executor.calls))
        runner.database_cleanup.clear()

    def test_scoped_new_requirements_and_constant_query_do_not_reuse_false_readiness(self):
        runner, project = self.manual(lambda *_: (0, catalog('pg_trgm')))
        first = self.migration(project, 'frontend/db/first.sql', 'pg_trgm')
        second = self.migration(project, 'backend/db/second.sql', 'pgcrypto')
        with self.offline():
            ready = runner.extension_preflight(dict(migrations=[first]), part='frontend')
        self.assertEqual(ready['status'], 'ready')
        observed = next(row for row in ready['observed'] if row['name'] == 'pg_trgm')
        self.assertTrue(observed['available']); self.assertIsNone(observed['installed_version'])
        self.assertEqual(ready['missing'], [])
        with self.offline(), self.assertRaises(runtime.Blocked):
            runner.extension_preflight(dict(migrations=[second]), part='backend')
        after = self.saved_checks(runner)[-1]
        self.assertEqual(after['part'], 'backend'); self.assertEqual(after['required'], ['pgcrypto'])
        self.assertEqual(after['declarations'][0]['path'], 'backend/db/second.sql')
        self.assertNotEqual(ready['log'], after['log'])
        custom = self.migration(project, 'frontend/db/custom.sql', 'custom_plugin')
        with self.offline(), self.assertRaises(runtime.Blocked):
            runner.extension_preflight(dict(migrations=[custom]), part='frontend')
        queries = [c[0][-1] for c in runner.executor.calls if c[0][-1] == extensions.AVAILABLE_EXTENSIONS_SQL]
        self.assertGreaterEqual(len(queries), 4)
        self.assertEqual(set(queries), {extensions.AVAILABLE_EXTENSIONS_SQL})
        self.assertNotIn('custom_plugin', extensions.AVAILABLE_EXTENSIONS_SQL)
        commands = [c[0] for c in runner.executor.calls]
        self.assertFalse(any('CREATE EXTENSION' in c[-1] for c in commands))
        self.assertFalse(any(Path(c[0]).name in ('apt', 'apt-get', 'brew', 'pip', 'npm') for c in commands))
        self.assertFalse(any(c[1:2] == ['build'] for c in commands))


if __name__ == '__main__':
    unittest.main()

