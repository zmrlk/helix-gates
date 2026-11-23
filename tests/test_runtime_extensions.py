"""Offline synthetic SQL/catalog tests; no database, files or subprocesses."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_extensions as ext


class RuntimeExtensions(unittest.TestCase):
    def detect(self, sql):
        return ext.sql_extensions(sql, path='database/migrations/001.sql')

    def test_common_multiline_declarations_preserve_locations(self):
        result = self.detect('''-- comment
CREATE EXTENSION IF NOT EXISTS pg_trgm;
create extension
  "btree_gist";
CrEaTe ExTeNsIoN FUZZYSTRMATCH;
CREATE EXTENSION pgcrypto;
''')
        self.assertEqual([d['name'] for d in result['declarations']], list(ext.COMMON_EXTENSIONS))
        self.assertEqual([d['line'] for d in result['declarations']], [2, 3, 5, 6])
        self.assertTrue(all(d['path'] == 'database/migrations/001.sql' for d in result['declarations']))
        self.assertEqual(result['gaps'], [])

    def test_comments_nested_comments_and_literals_are_not_requirements(self):
        result = self.detect('''-- CREATE EXTENSION vector;
/* outer
 /* CREATE EXTENSION postgis; */
 CREATE EXTENSION pgcrypto; */
SELECT 'CREATE EXTENSION pg_trgm;', E'it\\\'s CREATE EXTENSION fuzzystrmatch;';
SELECT "CREATE EXTENSION btree_gist;";
CREATE EXTENSION pgcrypto;
''')
        self.assertEqual([(x['name'], x['line']) for x in result['declarations']], [('pgcrypto', 7)])
        self.assertEqual(result['gaps'], [])

    def test_dollar_body_marker_does_not_hide_following_up_declaration(self):
        result = self.detect('''-- migrate:up
DO $body$
BEGIN
-- migrate:down
RAISE NOTICE 'CREATE EXTENSION vector;';
END
$body$;
CREATE EXTENSION pg_trgm;
-- migrate:down
CREATE EXTENSION postgis;
''')
        self.assertEqual([(x['name'], x['line']) for x in result['declarations']], [('pg_trgm', 8)])
        self.assertEqual(result['gaps'], [dict(path='database/migrations/001.sql', line=2,
                                               reason_code='dynamic_sql_requirements_unresolved')])

    def test_real_up_marker_ignores_preamble_and_preserves_lines(self):
        result = self.detect('''CREATE EXTENSION postgis;
-- migrate:up

CREATE EXTENSION pgcrypto;
-- migrate:down
CREATE EXTENSION vector;
''')
        self.assertEqual([(x['name'], x['line']) for x in result['declarations']], [('pgcrypto', 4)])
        self.assertEqual(self.detect('-- migrate:down\nCREATE EXTENSION vector;')['declarations'], [])

    def test_quoted_names_preserve_case_and_unknown_extensions(self):
        result = self.detect('CREATE EXTENSION "Example_Ext"; CREATE EXTENSION "uuid-ossp";')
        self.assertEqual([x['name'] for x in result['declarations']], ['Example_Ext', 'uuid-ossp'])
        self.assertEqual(result['gaps'], [])

    def test_version_is_a_declaration_separate_from_catalog(self):
        result = self.detect('CREATE EXTENSION pg_trgm WiTh SCHEMA public VERSION \'1.99\' CASCADE;')
        self.assertEqual(result['declarations'][0]['declared_version'], '1.99')
        catalog = ext.parse_available_extensions(json.dumps([
            dict(name='pg_trgm', default_version='1.6', installed_version=None)
        ]))
        self.assertEqual(catalog['pg_trgm'], dict(default_version='1.6', installed_version=None))
        self.assertNotIn('version_check', result['declarations'][0])
        self.assertEqual(result['gaps'], [])

    def test_dynamic_execution_keeps_unknown_scope_without_literal_requirements(self):
        result = self.detect("EXECUTE 'CREATE EXTENSION vector';\nCALL prepare_database();")
        self.assertEqual(result['declarations'], [])
        self.assertEqual([(g['line'], g['reason_code']) for g in result['gaps']], [
            (1, 'dynamic_sql_requirements_unresolved'), (2, 'dynamic_sql_requirements_unresolved')])

    def test_function_definition_alone_is_not_an_executed_dynamic_requirement(self):
        result = self.detect("CREATE FUNCTION f() RETURNS void AS $$ BEGIN CREATE EXTENSION vector; END; $$ LANGUAGE plpgsql;\nCREATE EXTENSION pgcrypto;")
        self.assertEqual([x['name'] for x in result['declarations']], ['pgcrypto'])
        self.assertEqual(result['gaps'], [])

    def test_schema_named_version_is_not_a_version_clause(self):
        result = self.detect('CREATE EXTENSION pgcrypto SCHEMA version;')
        self.assertIsNone(result['declarations'][0]['declared_version'])
        self.assertEqual(result['gaps'], [])

    def test_unresolved_name_is_a_location_not_an_echo(self):
        result = self.detect('CREATE EXTENSION :"PRIVATE_CANARY";')
        self.assertEqual(result['declarations'], [])
        self.assertEqual(result['gaps'], [dict(path='database/migrations/001.sql', line=1,
                                               reason_code='extension_name_unresolved')])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_unresolved_version_keeps_required_name_without_invented_version(self):
        for sql in ('CREATE EXTENSION pgcrypto VERSION :version;',
                    "CREATE EXTENSION pgcrypto VERSION E'1\\x32';",
                    "CREATE EXTENSION pgcrypto VERSION '1' VERSION '2';"):
            with self.subTest(sql=sql):
                result = self.detect(sql)
                self.assertEqual(result['declarations'][0]['name'], 'pgcrypto')
                self.assertIsNone(result['declarations'][0]['declared_version'])
                self.assertEqual(result['gaps'][0]['reason_code'], 'extension_version_unresolved')

    def test_unsupported_identifier_and_options_fail_closed(self):
        for sql in ('CREATE EXTENSION schema.pgcrypto;', 'CREATE EXTENSION "PRIVATE CANARY";'):
            result = self.detect(sql)
            self.assertEqual(result['declarations'], [])
            self.assertEqual(result['gaps'][0]['reason_code'], 'extension_name_unresolved')
            self.assertNotIn('PRIVATE', json.dumps(result))
        result = self.detect('CREATE EXTENSION pgcrypto UNKNOWN_OPTION;')
        self.assertEqual(result['gaps'][0]['reason_code'], 'extension_options_unresolved')
        self.assertEqual(result['declarations'][0]['name'], 'pgcrypto')

    def test_invalid_helper_input_uses_fixed_errors(self):
        for path in ('/PRIVATE_CANARY.sql', '../PRIVATE_CANARY.sql', 'x\nPRIVATE_CANARY.sql'):
            with self.assertRaisesRegex(ValueError, '^invalid extension source path$'):
                ext.sql_extensions('', path=path)
        with self.assertRaisesRegex(ValueError, '^invalid extension source SQL$'):
            ext.sql_extensions(None, path='migration.sql')

    def test_available_catalog_preserves_observed_versions_and_sorts_names(self):
        catalog = ext.parse_available_extensions(json.dumps([
            dict(name='pgcrypto', default_version='1.3', installed_version=None),
            dict(name='btree_gist', default_version=None, installed_version='1.6')
        ]))
        self.assertEqual(list(catalog), ['btree_gist', 'pgcrypto'])
        self.assertEqual(catalog['pgcrypto']['installed_version'], None)
        self.assertEqual(catalog['btree_gist']['default_version'], None)
        self.assertEqual(ext.parse_available_extensions('[]'), {})

    def test_catalog_rejects_duplicates_in_rows_and_json_keys(self):
        row = dict(name='pgcrypto', default_version='1.3', installed_version=None)
        for output in (json.dumps([row, row]),
                       '[{"name":"pgcrypto","name":"vector","default_version":null,"installed_version":null}]'):
            with self.assertRaisesRegex(ValueError, '^invalid available extensions catalog$'):
                ext.parse_available_extensions(output)

    def test_catalog_rejects_wrong_shape_types_and_unknown_fields(self):
        row = dict(name='pgcrypto', default_version='1.3', installed_version=None)
        bad = [None, True, {}, [None], [dict(row, comment='PRIVATE_CANARY')],
               [dict(row, default_version=True)], [dict(row, installed_version=1)],
               [dict(row, name='')], [dict(row, default_version='')],
               [dict(row, name='PRIVATE\nCANARY')], [dict(row, installed_version={})]]
        for value in bad:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^invalid available extensions catalog$'):
                ext.parse_available_extensions(json.dumps(value))

    def test_catalog_bad_json_and_psql_noise_never_become_success_or_echo(self):
        for output in ('PRIVATE_CANARY', 'WARNING: PRIVATE_CANARY\n[]', '[NaN]', '', None):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, '^invalid available extensions catalog$'):
                ext.parse_available_extensions(output)

    def test_query_is_constant_read_only_and_has_no_project_interpolation(self):
        self.assertIn('FROM pg_available_extensions', ext.AVAILABLE_EXTENSIONS_SQL)
        self.assertNotRegex(ext.AVAILABLE_EXTENSIONS_SQL, r'(?i)\b(?:CREATE|INSTALL|ALTER|DROP)\b')
        self.assertEqual(set(ext.COMMON_EXTENSIONS), {'pg_trgm', 'btree_gist', 'fuzzystrmatch', 'pgcrypto'})


if __name__ == '__main__':
    unittest.main()
