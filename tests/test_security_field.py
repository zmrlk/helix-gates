"""Small synthetic patterns from field review; target application is never copied/run."""
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_static_security as security


class FieldSecurityTests(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory() as directory:
            for name, source in files.items():
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            with patch('helix_guard_contracts.project_config', return_value={'static_security': {'record_context_guards': ['requireCan'], 'scope_guards': ['checkOwnership']}}):
                return security.analyze(directory)

    def hits(self, files, code):
        return [f for f in self.scan(files)['findings'] if f['id'] == code]

    def test_destructured_typed_handlers_keep_body_and_boundaries(self):
        source = '''export const GET: Handler = async ({params}) => {
  return sql`UPDATE counters SET views = views + 1 WHERE id = ${params.id}`;
};
export const POST: Handler = async ({params, locals}) => {
  checkOwnership(params.id, locals.user.id);
  return sql`UPDATE counters SET views = views + 1 WHERE id = ${params.id}`;
};'''
        hits = self.hits({'src/routes/items/[id]/+server.ts': source}, 'SEC-IDOR')
        self.assertEqual([f['line'] for f in hits], [2])
        self.assertTrue(self.hits({'src/routes/items/[id]/+server.ts': source}, 'SEC-PUBLIC-COUNTER'))

    def test_typed_delegated_guard_is_candidate_not_execution_proof(self):
        data = self.scan({
            'src/guard.ts': '''export async function requireFeature(locals: Context, feature: string): Promise<void> {
 const user = locals.user;
 if (!user) throw error(401);
 if (!user.permissions.has(feature)) throw error(403);
}''',
            'src/routes/invoices/+page.server.ts': "export const load: Loader = async ({locals}) => { await requireFeature(locals, 'invoices'); return db.findMany(); };"})
        self.assertTrue(data['endpoints'][0]['guard_candidate'])
        self.assertEqual(data['endpoints'][0]['auth_status'], 'unknown')
        self.assertFalse([f for f in data['findings'] if f['id'] == 'SEC-AUTH'])

    def test_icon_pin_and_schema_comment_are_not_authentication(self):
        files = {'view.svelte': '<Icon name="pin" />{#if addresses.length === 0}<p>Empty</p>{/if}',
                 'schema.sql': '-- PIN = 4 digits; application verifies it\nCREATE TABLE devices (id int);'}
        self.assertFalse(self.hits(files, 'SEC-OTP'))
        self.assertTrue(self.hits({'auth.ts': 'const otp = Math.random().toString().slice(2, 6); if (otp === input) signIn();'}, 'SEC-OTP'))

    def test_hash_update_is_not_mass_assignment_but_orm_stays_flagged(self):
        files = {'digest.ts': "const checksum = createHash('sha256').update(JSON.stringify({...data})).digest('hex');\nconst h = crypto.createHash('sha256'); h.update(req.body);",
                 'data.ts': 'db.users.update({...data});'}
        self.assertEqual([f['file'] for f in self.hits(files, 'SEC-MASS')], ['data.ts'])
        self.assertTrue(self.hits({'data.ts': 'const h = crypto.createHash("sha256"); h = db.users; h.update(req.body);'}, 'SEC-MASS'))

    def test_form_fields_and_signature_checked_upload(self):
        files = {'fields.ts': "export const POST = async ({request}) => { const form = await request.formData(); return saveDate(form.get('date')); };",
                 'upload.ts': '''export const POST = async ({request}) => {
 const form = await request.formData(); const image = form.get('image');
 if (!(image instanceof File)) throw error(400);
 if (image.size > 2048) throw error(413);
 const kind = sniffImage(Buffer.from(await image.arrayBuffer()));
 if (!kind) throw error(415);
 await writeFile('image.bin', image);
};'''}
        self.assertFalse(self.hits(files, 'SEC-UPLOAD'))
        files['upload.ts'] = files['upload.ts'].replace('if (!kind) throw error(415);', '')
        self.assertEqual([f['file'] for f in self.hits(files, 'SEC-UPLOAD')], ['upload.ts'])

    def test_upload_validation_cannot_leak_from_neighbour_handler(self):
        source = '''export const POST = async ({request}) => {
 const form = await request.formData(); const file = form.get('image');
 if (!(file instanceof File)) throw error(400);
 if (file.size > 2048) throw error(413);
 if (!allowedTypes.includes(file.type)) throw error(415);
};
export const PUT = async ({request}) => {
 const form = await request.formData(); const file = form.get('image');
 if (!(file instanceof File)) throw error(400);
 await writeFile('image.bin', await file.arrayBuffer());
};'''
        hits = self.hits({'route.ts': source}, 'SEC-UPLOAD')
        self.assertEqual([f['line'] for f in hits], [8])

    def test_optional_scope_fail_open_is_a_hypothesis(self):
        source = '''export async function canReadAttachment(user: User, parent: Scope | null): Promise<boolean> {
 if (!parent) return true;
 return canUser(user, 'view', parent.module, {record: parent.row});
}'''
        hits = self.hits({'access.ts': source}, 'SEC-SCOPE-FAILOPEN')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['line'], 2)
        self.assertEqual(hits[0]['confidence'], 'possible')
        self.assertFalse(self.hits({'access.ts': source.replace('return true', 'return false')}, 'SEC-SCOPE-FAILOPEN'))

    def test_global_authentication_throttle_before_verification(self):
        source = '''export async function signIn(pin: string): Promise<User> {
 if (rateLimitExhausted('login:global', 100)) throw error(429);
 const user = await verifyPin(pin);
 if (!user) { rateLimit('login:global', 100, 60000); throw error(401); }
 return user;
}'''
        hits = self.hits({'auth.ts': source}, 'SEC-GLOBAL-LOCKOUT')
        self.assertEqual([f['line'] for f in hits], [2])
        self.assertFalse(self.hits({'auth.ts': source.replace("'login:global'", '`login:${pin}`')}, 'SEC-GLOBAL-LOCKOUT'))
        safe = source.replace(" if (rateLimitExhausted('login:global', 100)) throw error(429);", '')
        self.assertFalse(self.hits({'auth.ts': safe}, 'SEC-GLOBAL-LOCKOUT'))

    def test_email_link_requires_verified_claim_before_lookup(self):
        source = '''async function linkIdentity(user: Identity): Promise<void> {
 const [account] = await sql`SELECT id FROM accounts WHERE email = ${user.email} AND identity_id IS NULL`;
 if (account) await sql`UPDATE accounts SET identity_id = ${user.id}, email = CASE WHEN ${user.emailVerified} THEN ${user.email} ELSE email END WHERE id = ${account.id}`;
}'''
        hits = self.hits({'hooks.server.ts': source}, 'SEC-EMAIL-LINK')
        self.assertEqual([f['line'] for f in hits], [2])
        safe = source.replace(' const [account]', ' if (user.emailVerified !== true) throw error(403);\n const [account]')
        self.assertFalse(self.hits({'hooks.server.ts': safe}, 'SEC-EMAIL-LINK'))
        weak = source.replace(' const [account]', ' if (user.emailVerified === false) throw error(403);\n const [account]')
        self.assertTrue(self.hits({'hooks.server.ts': weak}, 'SEC-EMAIL-LINK'))
        guarded = source.replace(' const [account]', ' if (user.emailVerified === true) {\n const [account]').replace('\n}', '\n}\n}')
        self.assertFalse(self.hits({'hooks.server.ts': guarded}, 'SEC-EMAIL-LINK'))
        unrelated = source.replace(' const [account]', ' if (user.emailVerified === true) { logVerified(); }\n const [account]')
        self.assertTrue(self.hits({'hooks.server.ts': unrelated}, 'SEC-EMAIL-LINK'))

    def test_row_permission_is_distinct_from_module_permission(self):
        files = {'route.ts': '''export const GET = async ({params, locals}) => {
 const row = await db.findUnique({id: params.id});
 await requireCan(locals, 'view', 'items', {itemRow: row});
 return row;
};'''}
        self.assertFalse(self.hits(files, 'SEC-IDOR'))
        files['route.ts'] = files['route.ts'].replace(", {itemRow: row}", '')
        self.assertTrue(self.hits(files, 'SEC-IDOR'))

    def test_delegated_record_guard_needs_actual_implementation(self):
        guard = '''async function requireThingAccess(locals: Locals, thingId: string): Promise<void> {
 const [thing] = await sql`SELECT * FROM things WHERE id = ${thingId}`;
 await requireCan(locals, 'view', 'things', {thingRow: thing});
}'''
        route = '''export const GET = async ({locals, params}) => {
 await requireThingAccess(locals, params.id);
 return await sql`SELECT * FROM things WHERE id = ${params.id}`;
};'''
        self.assertFalse(self.hits({'guard.ts': guard, 'route.ts': route}, 'SEC-IDOR'))
        self.assertTrue(self.hits({'route.ts': route}, 'SEC-IDOR'))

    def test_unrelated_scoped_read_is_not_a_record_guard(self):
        source = '''function loadDashboard(user) { return db.query(`SELECT id FROM items WHERE owner_id = ${user.id}`); }
export const GET = async ({locals, params}) => {
 await loadDashboard(locals.user);
 return db.findUnique({id: params.id});
};'''
        self.assertTrue(self.hits({'route.ts': source}, 'SEC-IDOR'))
