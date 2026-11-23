"""Guard spelling alone cannot suppress authorization findings."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_guard_contracts as contracts
import helix_ast_scope_helpers as helpers
import helix_security_ast_rules as rules
import helix_static_security as security
from test_ast_scope_helpers import record, helper, client, function, stmt, await_, call, ret, query


class GuardContractTests(unittest.TestCase):
    def test_renamed_record_guard_requires_the_same_explicit_contract(self):
        for guard in ('requireCan', 'verifyAssetAccess'):
            with self.subTest(guard=guard):
                raw, facts = record(helper(name='gate', guard_name=guard), client(name='gate'))
                snapshots, records = {'route.ts': raw}, {'route.ts': facts}
                fn = next(n for n in facts['facts'] if n['kind'] == 'function_declaration' and rules.text(n, 'name') == 'GET')
                scope = rules.Scope(raw, facts['facts'], fn)
                effect = next(n for n in scope.calls if rules.name(n) == 'db.documents.findUnique')
                self.assertIsNone(helpers.build(snapshots, records).guard_reason('route.ts', scope, effect))
                index = helpers.build(snapshots, records, record_guards=[guard])
                self.assertEqual(index.guard_reason('route.ts', scope, effect), 'local_same_id_row_guard_candidate')

    def test_identity_guard_name_has_no_default_meaning(self):
        for guard in ('requireAuth', 'needIdentity'):
            raw, facts = record(function('GET', '{locals,params}', stmt(call(guard, 'locals')), ret(query('params.id')), export=True))
            default = rules.analyze_file('route.ts', raw, facts)
            route = next(s for s in default['scopes'] if s.function)
            self.assertIsNone(rules.auth_candidate(route))
            declared = rules.analyze_file('route.ts', raw, facts, identity_guards=[guard])
            route = next(s for s in declared['scopes'] if s.function)
            self.assertEqual(rules.auth_candidate(route)['reason'], 'configured_permission_helper_candidate')

    def test_lexical_scope_uses_project_config_and_rejects_malformed_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / 'route.ts'
            config = root / 'helix.json'
            for guard in ('checkOwnership', 'enforceInvoiceScope'):
                source.write_text('export const GET = ({params,locals}) => { ' + guard + '(params.id, locals.user); return db.findUnique({id:params.id}); };')
                config.write_text('{}')
                self.assertTrue(any(r['id'] == 'SEC-IDOR' for r in security.analyze(root)['findings']))
                config.write_text(json.dumps({'static_security': {'scope_guards': [guard]}}))
                self.assertFalse(any(r['id'] == 'SEC-IDOR' for r in security.analyze(root)['findings']))
            config.write_text('{"static_security":{"scope_guards":"guess"}}')
            with self.assertRaises(ValueError):
                contracts.load(root)


if __name__ == '__main__':
    unittest.main()
