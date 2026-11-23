"""Zasiew przepełniony na prawdziwym PostgreSQL. Uruchamiany na życzenie: HELIX_RUNTIME_IT=1 python3 tests/integration/test_seed_volume_it.py"""
import json, os, shutil, socket, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'bin'))
import helix_runtime  # noqa: E402

SCHEMA = """
CREATE TABLE customers(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, code varchar(8) NOT NULL UNIQUE, city text,
  email text CHECK (email LIKE '%@%'), balance numeric(12,2) NOT NULL DEFAULT 0, status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','old')));
CREATE TABLE tags(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), label text NOT NULL);
CREATE TABLE customer_tags(customer_id uuid NOT NULL REFERENCES customers(id), tag_id uuid NOT NULL REFERENCES tags(id), PRIMARY KEY(customer_id,tag_id));
CREATE TABLE picky(id uuid PRIMARY KEY, label text NOT NULL CHECK (label='synthetic-item'), qty int NOT NULL CHECK (qty=1));
CREATE TABLE owner_listed(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL);
CREATE TABLE lead_statuses(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL);
CREATE TABLE quotes(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), title text NOT NULL, public_token text NOT NULL UNIQUE, total real NOT NULL, net numeric(10,1) NOT NULL);
CREATE TABLE profiles(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL, keycloak_id text);
CREATE TABLE employees(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), first_name text NOT NULL, pin_hash text);
CREATE TABLE vault(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), password_hash text NOT NULL);
CREATE TABLE silent(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL);
CREATE FUNCTION drop_more() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN IF (SELECT count(*) FROM silent)>=1 THEN RETURN NULL; END IF; RETURN NEW; END $f$;
CREATE TRIGGER silent_t BEFORE INSERT ON silent FOR EACH ROW EXECUTE FUNCTION drop_more();
"""


def tool(name):
    found = shutil.which(name)
    if found: return found
    for base in sorted(Path('/opt/homebrew/Cellar').glob('postgresql@*/*/bin'), reverse=True):
        if (base/name).is_file(): return str(base/name)
    return None


@unittest.skipUnless(os.environ.get('HELIX_RUNTIME_IT') == '1' and all(tool(n) for n in ('initdb', 'pg_ctl', 'psql')), 'ustaw HELIX_RUNTIME_IT=1; wymaga initdb, pg_ctl i psql')
class SeedVolume(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='helix-seed-')
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); cls.port = s.getsockname()[1]
        subprocess.run([tool('initdb'), '-D', cls.dir+'/data', '-U', 'helix', '-A', 'trust'], check=True, capture_output=True)
        subprocess.run([tool('pg_ctl'), '-D', cls.dir+'/data', '-o', f"-p {cls.port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=''",
                        '-l', cls.dir+'/log', '-w', 'start'], check=True, capture_output=True)
        cls.sql(SCHEMA)
        cls.sql((ROOT/'templates/runtime-seed.sql').read_text())
        cls.sql("INSERT INTO customer_tags SELECT (SELECT id FROM customers LIMIT 1),(SELECT id FROM tags LIMIT 1) ON CONFLICT DO NOTHING; UPDATE employees SET pin_hash='scrypt-x'")
        cls.output = cls.sql((ROOT/'templates/runtime-seed-volume.sql').read_text().replace(':rows', '60').replace('/*:skip*/', "|| '|^(owner_listed)$'"))
        cls.tables = {row['tbl']: row for row in json.loads(cls.output.strip().splitlines()[-1])}

    @classmethod
    def tearDownClass(cls):
        subprocess.run([tool('pg_ctl'), '-D', cls.dir+'/data', '-m', 'fast', 'stop'], capture_output=True)
        shutil.rmtree(cls.dir, ignore_errors=True)

    @classmethod
    def sql(cls, text):
        done = subprocess.run([tool('psql'), '-h', '127.0.0.1', '-p', str(cls.port), '-U', 'helix', '-d', 'postgres', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-c', text],
                              capture_output=True, text=True)
        if done.returncode: raise AssertionError(done.stderr[-800:])
        return done.stdout

    def count(self, query): return int(self.sql('SELECT '+query).strip())

    def test_work_tables_reach_the_target_with_measured_extreme_rows(self):
        for name in ('customers', 'quotes', 'employees'):
            self.assertEqual((self.tables[name]['after'], self.count(f'count(*) FROM {name}')), (60, 60), name)
            self.assertGreater(self.tables[name]['extreme'], 0, name)
        # znacznik zaokrąglany przez real i numeric(10,1) nadal jest liczony
        self.assertEqual(self.tables['quotes']['extreme'], self.count('count(*) FROM quotes WHERE total>=987654 OR net>=987654 OR length(title)>100'))
        self.assertEqual(self.count('count(DISTINCT public_token) FROM quotes'), 60)

    def test_optional_fields_are_filled_but_formal_ones_and_some_rows_stay_empty(self):
        filled, long_values, emails, zero = [self.count(q+' FROM customers') for q in
            ('count(city)', "count(*) FILTER (WHERE length(city)>100)", 'count(email)', 'count(*) FILTER (WHERE balance=0)')]
        self.assertTrue(40 <= filled < 60 and long_values >= 5, (filled, long_values))
        self.assertEqual(emails, 0); self.assertTrue(0 < zero < 60, zero)
        self.assertEqual(self.count("count(*) FROM customers WHERE status<>'new'"), 0)

    def test_join_table_gets_rotating_parents_in_the_second_pass(self):
        self.assertEqual((self.tables['customer_tags']['after'], self.count('count(*) FROM customer_tags')), (60, 60))

    def test_restrictive_checks_fall_back_to_copies_and_silent_trigger_is_reported(self):
        self.assertEqual((self.tables['picky']['after'], self.tables['picky']['copied'], self.tables['picky']['extreme']), (60, 59, 0))
        self.assertEqual((self.tables['silent']['after'], self.count('count(*) FROM silent')), (1, 1))
        self.assertGreater(self.tables['silent']['failed'], 0)

    def test_login_data_dictionaries_and_owner_listed_tables_are_skipped_and_named(self):
        self.assertEqual({name: self.tables[name]['skipped'] for name in ('profiles', 'vault', 'lead_statuses', 'owner_listed')},
                         dict(profiles='login data', vault='login data', lead_statuses='dictionary or settings', owner_listed='dictionary or settings'))
        for name in ('profiles', 'vault', 'lead_statuses', 'owner_listed'): self.assertEqual(self.count(f'count(*) FROM {name}'), 1, name)
        # opcjonalna kolumna logowania w tabeli roboczej: kopie jej nie niosą
        self.assertEqual(self.count('count(pin_hash) FROM employees'), 1)

    def test_summary_is_incomplete_because_one_table_stayed_below_target(self):
        result = helix_runtime.volume_result(self.output, 60)
        self.assertEqual((result['status'], result['below_target']), ('INCOMPLETE', ['silent']))
        self.assertEqual(result['skipped_login_data'], ['profiles', 'vault'])


if __name__ == '__main__':
    unittest.main()
