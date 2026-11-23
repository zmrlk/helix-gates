"""Projekt na Supabase: zaślepianie adresów w migracjach, kolejność plików, odtwarzanie tabel z typów aplikacji."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime_supabase as supabase

TYPES = '''export type Database = {
  __InternalSupabase: { PostgrestVersion: "12" }
  public: {
    Tables: {
      profiles: {
        Row: {
          created_at: string
          id: string
          region_id: string | null
          role: Database["public"]["Enums"]["user_role"]
          tags: string[] | null
          meta: Json | null
          points: number
        }
        Insert: {
          created_at?: string
          id: string
          region_id?: string | null
          role?: Database["public"]["Enums"]["user_role"]
          tags?: string[] | null
          meta?: Json | null
          points: number
        }
        Update: { id?: string }
        Relationships: [
          {
            foreignKeyName: "profiles_region_id_fkey"
            columns: ["region_id"]
            isOneToOne: false
            referencedRelation: "regions"
            referencedColumns: ["id"]
          },
        ]
      }
      orders: {
        Row: { id: string; name: string }
        Insert: { id?: string; name: string }
        Update: { id?: string }
        Relationships: []
      }
    }
    Views: { [_ in never]: never }
    Functions: { [_ in never]: never }
    Enums: {
      user_role:
        | "admin"
        | "advisor"
      order_kind: "a" | "b"
    }
  }
}
'''


class Supabase(unittest.TestCase):
    def test_external_addresses_and_tokens_in_migrations_are_blinded_local_ones_stay(self):
        # token składany w teście z części: w repozytorium nie ma napisu wyglądającego na prawdziwy klucz
        import base64, json
        part = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        token = part(dict(alg='HS256')) + '.' + part(dict(role='service_role', ref='abc')) + '.' + part('podpis-testowy-nie-jest-kluczem')
        sql = "select net.http_post(url:='https://abc.supabase.co/functions/v1/send', headers:='{\"Authorization\":\"Bearer " + token + "\"}'); select 'http://localhost:54321/x', 'http://kong:8000/y';"
        text, urls, tokens = supabase.blind(sql)
        self.assertEqual((urls, tokens), (1, 1))
        self.assertIn(supabase.BLOCKED + '/functions/v1/send', text); self.assertNotIn('supabase.co', text); self.assertNotIn('eyJ', text)
        self.assertIn('http://localhost:54321/x', text); self.assertIn('http://kong:8000/y', text)

    def test_migrations_run_in_timestamp_order_whatever_the_file_name_format(self):
        names = ['20250601000000-a1b2.sql', '20250101000000_bucket.sql', 'readme.md', '20250701000000.sql', 'zz.sql']
        self.assertEqual(supabase.ordered(names), ['20250101000000_bucket.sql', '20250601000000-a1b2.sql', '20250701000000.sql', 'zz.sql'])

    def test_tables_and_enums_no_migration_creates_are_rebuilt_from_the_application_types(self):
        sql, tables, enums = supabase.bootstrap(TYPES, 'CREATE TABLE public.orders (id uuid); create type public.order_kind as enum (\'a\');')
        self.assertEqual((tables, enums), (['profiles'], ['user_role']))
        self.assertIn('CREATE TYPE public."user_role" AS ENUM (\'admin\', \'advisor\');', sql)
        for line in ('"id" uuid PRIMARY KEY', '"created_at" timestamptz DEFAULT now() NOT NULL', '"region_id" uuid', '"role" public."user_role" DEFAULT \'admin\' NOT NULL',
                     '"tags" text[]', '"meta" jsonb', '"points" numeric NOT NULL'):
            self.assertIn(line, sql)
        self.assertNotIn('"orders"', sql)

    def test_project_address_and_keys_in_the_working_copy_point_to_the_local_stack(self):
        import base64, json, tempfile
        token = lambda role, ref: '.'.join(base64.urlsafe_b64encode(json.dumps(part).encode()).decode().rstrip('=') for part in (dict(alg='HS256', typ='JWT'), dict(role=role, ref=ref, iss='supabase'))) + '.c2lnbmF0dXJlc2lnbmF0dXJl'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); client = root/'src'/'integrations'/'supabase'/'client.ts'; client.parent.mkdir(parents=True)
            client.write_text('const URL = "https://abcdefgh.supabase.co"; const KEY = "%s"; const OTHER = "%s";' % (token('anon', 'abcdefgh'), token('anon', 'zzzzzzzz')))
            (root/'supabase'/'functions').mkdir(parents=True); (root/'supabase'/'functions'/'a.ts').write_text('fetch("https://abcdefgh.supabase.co/x")')
            (root/'node_modules'/'x').mkdir(parents=True); (root/'node_modules'/'x'/'i.js').write_text('"https://abcdefgh.supabase.co"')
            (root/'README.md').write_text('https://abcdefgh.supabase.co')
            changed, left = supabase.localize_tree(root, 'abcdefgh', 'http://127.0.0.1:5', 'LOCAL')
            text = client.read_text()
            self.assertEqual((changed, left), (1, [])); self.assertIn('"http://127.0.0.1:5"', text); self.assertIn('"LOCAL"', text); self.assertIn(token('anon', 'zzzzzzzz'), text)
            self.assertIn('abcdefgh', (root/'supabase'/'functions'/'a.ts').read_text()); self.assertIn('abcdefgh', (root/'node_modules'/'x'/'i.js').read_text())

    def test_synthetic_profile_takes_the_account_id_consents_and_owner_values(self):
        columns = [('id', 'uuid'), ('email', 'text'), ('is_approved', 'boolean'), ('role', 'USER-DEFINED'), ('password_changed_at', 'timestamp'), ('phone', 'text')]
        sql = supabase.profile_sql(columns, 'u-1', {'role': "it'x"})
        self.assertIn('("email", "id", "is_approved", "password_changed_at", "role")', sql); self.assertIn("'u-1', true, now(), 'it''x'", sql)
        with self.assertRaises(ValueError): supabase.profile_sql(columns, 'u-1', {'nope': 'x'})
        self.assertIsNone(supabase.profile_sql([('name', 'text')], 'u-1', None))

    def test_migration_errors_are_attributed_to_files(self):
        rows = supabase.apply_report('@@ a.sql\npsql:/x:3: ERROR:  relation "p" does not exist\nLINE 1\n@@ b.sql\n@@ c.sql\npsql: ERROR:  one\npsql: ERROR:  two\n', ['a.sql', 'b.sql', 'c.sql'])
        self.assertEqual([(row['file'], row['errors']) for row in rows], [('a.sql', 1), ('b.sql', 0), ('c.sql', 2)]); self.assertEqual(rows[0]['first'], 'relation "p" does not exist')


if __name__ == '__main__':
    unittest.main()
