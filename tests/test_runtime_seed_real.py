"""Zasiew syntetyczny na prawdziwym PostgreSQL: kolumny o ograniczonej długości i tabele odrzucające wiersz."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
PG = next((found for found in (runtime.native_postgres(major) for major in (16, 17, 15, 14)) if found), None)


@unittest.skipUnless(PG, 'wymaga lokalnego PostgreSQL')
class SeedOnRealPostgres(unittest.TestCase):
    def setUp(self):
        self.base = runtime.runtime_tmpdir(); self.data = self.base / 'data'; self.port = str(runtime.free_port())
        self.env = dict(os.environ, LC_ALL='C')
        subprocess.run([PG / 'initdb', '-D', self.data, '-U', 'helix', '--auth-local=trust', '--auth-host=trust', '--no-locale'], check=True, capture_output=True, env=self.env)
        subprocess.run([PG / 'pg_ctl', '-D', self.data, '-l', self.base / 'log', '-o', f'-h 127.0.0.1 -p {self.port} -k {self.base}', '-w', 'start'],
                       check=True, capture_output=True, env=self.env)

    def tearDown(self):
        subprocess.run([PG / 'pg_ctl', '-D', self.data, '-m', 'fast', '-w', 'stop'], capture_output=True, env=self.env)
        shutil.rmtree(self.base, ignore_errors=True)

    def sql(self, text):
        done = subprocess.run([PG / 'psql', f'postgresql://helix@127.0.0.1:{self.port}/postgres', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', text],
                              capture_output=True, text=True, env=self.env)
        self.assertEqual(done.returncode, 0, done.stderr[-600:])
        return done.stdout.strip()

    def test_bounded_text_is_trimmed_and_a_refusing_table_does_not_abort_the_seed(self):
        self.sql("""
            CREATE TABLE exchange_rates (currency char(3) NOT NULL, rate_date date NOT NULL, mid numeric NOT NULL);
            CREATE TABLE short_codes (code varchar(5) NOT NULL, label text NOT NULL);
            CREATE TABLE refusing (name text NOT NULL);
            CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'synthetic refusal'; END $f$;
            CREATE TRIGGER refuse_insert BEFORE INSERT ON refusing FOR EACH ROW EXECUTE FUNCTION refuse();
            CREATE TABLE zz_after_refusal (title text NOT NULL);
        """)
        self.sql((ROOT / 'templates' / 'runtime-seed.sql').read_text())
        self.assertEqual(self.sql("SELECT currency||'|'||length(currency) FROM exchange_rates"), 'syn|3')
        self.assertEqual(self.sql('SELECT code FROM short_codes'), 'synth')
        self.assertEqual(self.sql('SELECT label FROM short_codes'), 'synthetic-item')
        self.assertEqual(self.sql('SELECT count(*) FROM refusing'), '0')
        self.assertEqual(self.sql('SELECT title FROM zz_after_refusal'), 'synthetic-item')


if __name__ == '__main__':
    unittest.main()
