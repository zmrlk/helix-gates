"""Opt-in, owned Unix-socket PostgreSQL only; no app/production database access."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'bin'))
from helix_runtime_adapters import CHECKSUM_SQL, checksum_rows, settings_sql


@unittest.skipUnless(os.environ.get('HELIX_RUNTIME_PG_TESTS') == '1', 'opt-in disposable PostgreSQL integration')
class PostgreSQLBackupTests(unittest.TestCase):
    def test_dump_restore_and_changed_value_detection_with_real_postgres(self):
        tools = {name: shutil.which(name) for name in ('initdb', 'pg_ctl', 'psql', 'pg_dump', 'pg_restore')}
        if not all(tools.values()): self.skipTest('PostgreSQL binaries unavailable')
        # macOS socket paths are short. No TCP listener or inherited PG credentials.
        with tempfile.TemporaryDirectory(prefix='hxpg-', dir='/tmp') as directory:
            root = Path(directory); data = root/'data'
            env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
            env.update(PGHOST=directory, PGPORT='54329', PGUSER='helix', PGDATABASE='postgres', LC_ALL='C')
            def command(name, *args):
                result = subprocess.run([tools[name], *map(str, args)], env=env, capture_output=True, text=True, timeout=40)
                self.assertEqual(result.returncode, 0, name+': '+result.stderr[-2000:])
                return result.stdout
            def sql(database, text):
                return command('psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', text)
            command('initdb', '-D', data, '-U', 'helix', '--auth-local=trust', '--auth-host=reject', '--no-locale', '-E', 'UTF8')
            started = False
            try:
                command('pg_ctl', '-D', data, '-l', root/'server.log', '-o', "-k " + directory + " -p 54329 -c listen_addresses=''", '-w', 'start')
                started = True
                sql('postgres', 'CREATE DATABASE source'); sql('postgres', 'CREATE DATABASE restored')
                sql('source', "CREATE TABLE items(id int, value jsonb, at timestamptz); INSERT INTO items VALUES (1, '{\"a\":1}', '2026-10-25T01:30:00Z'),(1, '{\"a\":1}', '2026-10-25T01:30:00Z'); CREATE TABLE empty(id int);")
                sql('source', "CREATE TABLE preferences(label text, enabled bool, options jsonb);")
                sql('source', settings_sql({'runtime':{'adapters':{'synthetic_rows':[{'synthetic':True,'table':'public.preferences','values':{'label':"Synthetic O'Reilly",'enabled':False,'options':{'mode':'fixture'}}}]}}}))
                self.assertEqual(sql('source', 'SELECT count(*) FROM preferences WHERE NOT enabled').strip(), '1')
                script = root/'counts.sql'; script.write_text(CHECKSUM_SQL)
                def digest(database): return checksum_rows(command('psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-d', database, '-f', script))
                before = digest('source')
                command('pg_dump', '--format=custom', '--file', root/'dump', 'source')
                command('pg_restore', '--exit-on-error', '--no-owner', '--dbname', 'restored', root/'dump')
                self.assertEqual(before, digest('restored'))
                sql('restored', "UPDATE items SET value='{\"a\":2}'")
                after = digest('restored')
                self.assertEqual([r['rows'] for r in before], [r['rows'] for r in after])
                self.assertNotEqual(before, after)
            finally:
                if started: command('pg_ctl', '-D', data, '-m', 'immediate', '-w', 'stop')


if __name__ == '__main__': unittest.main()
