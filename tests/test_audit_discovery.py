"""Synthetic, stack-independent discovery and evidence regressions."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_audit_context import inventory, parts
from helix_new import audit
from helix_pro import assess, usable_evidence


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'project'
        self.root.mkdir()

    def put(self, path, content):
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
        return dest

    def control(self, ident, report=None):
        report = report or assess(self.root, 'L')
        return next(c for a in report['areas'].values() for c in a['requirements'] if c['id'] == ident)

    def test_three_framework_monorepos_and_outputs(self):
        for stack, deps, layout in [
            ('kit', {'svelte':'1','@sveltejs/kit':'1'}, 'frontend'),
            ('next', {'react':'1','next':'1'}, 'apps/web'),
            ('nuxt', {'vue':'1','nuxt':'1'}, 'apps/web')]:
            with self.subTest(stack=stack), tempfile.TemporaryDirectory() as work:
                self.root = Path(work) / 'source'; self.root.mkdir()
                self.put(layout + '/package.json', json.dumps({'dependencies':deps}))
                self.put(layout + '/src/main.ts', 'export const value = 42;')
                self.put('database/migrations/001.sql', 'CREATE TABLE records (id integer PRIMARY KEY);')
                self.put('worker/task.py', 'def task(): return 42')
                self.put('infra/main.tf', 'resource "example" "main" {}')
                self.put('ops/maintenance.sh', '#!/bin/sh\nprintf ready')
                self.put('packages/core/package.json', '{"name":"core"}')
                self.put('package.json', '{"workspaces":["apps/*","packages/*"]}')
                self.put('turbo.json', '{"tasks":{"build":{}}}')
                self.put('nx.json', '{"targetDefaults":{"build":{}}}')
                before = {p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
                out = Path(work) / 'audit'
                audit(self.root, out)
                data = json.loads((out / 'audit.json').read_text())
                self.assertEqual({p['path'] for p in data['maturity']['parts']}, {layout,'database','worker','infra','ops','packages/core'})
                self.assertEqual({p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}, before)
                self.assertTrue(any(o['kind']=='framework-declaration' for o in data['observations']))
                self.assertEqual({v['path'] for v in data['inventory']}, set(inventory(self.root)))
                self.assertEqual(data['scope']['profile'], 'M')  # parts alone do not establish tenancy/scale

    def test_recursive_case_and_variant_documents(self):
        self.put('docs/technical/02-SYSTEM-DESIGN.md', '# Design\nService owns orders and storage.\n```mermaid\nflowchart LR\n A --> B\n```')
        self.put('docs/contracts/v2.OPENAPI.yml', 'openapi: 3.0.3\npaths:\n  /records:\n    get:\n      responses:\n        "200":\n          description: records returned\n')
        self.assertTrue(self.control('docs-architecture')['satisfied'])
        self.assertTrue(self.control('docs-api')['satisfied'])
        self.assertTrue(self.control('docs-api')['evidence'][0].startswith('docs/contracts/'))

    def test_deployment_architecture_diagram_variants(self):
        for deps in ({'svelte': '1'}, {'react': '1', 'next': '1'}, {'vue': '1'}):
            with self.subTest(deps=deps):
                self.put('app/package.json', json.dumps({'dependencies': deps}))
                self.put('docs/PRODUCTION-DEPLOY.md', '# Deployment\nService architecture connects application and storage.\n```\n┌── application ──┐\n│       ▼         │\n└── database ─────┘\n```')
                self.assertTrue(self.control('docs-architecture')['satisfied'])
                self.put('docs/PRODUCTION-DEPLOY.md', '# Deployment\nApplication connects to storage; diagram pending.')
                self.assertFalse(self.control('docs-architecture')['satisfied'])

    def test_unfinished_section_does_not_hide_completed_diagram(self):
        self.put('docs/architecture.md', '# Architecture\nService owns records and storage.\n```mermaid\nflowchart LR\n A --> B\n```\n## Future work\nTODO add capacity plan')
        c = self.control('docs-architecture')
        self.assertTrue(c['satisfied'])
        self.assertEqual(c['evidence'], ['docs/architecture.md:3'])
        self.put('docs/architecture.md', '# Architecture\nTODO mermaid A --> B\nService owns records and storage.')
        self.assertFalse(self.control('docs-architecture')['satisfied'])

    def test_generated_starter_and_explicit_draft_are_not_evidence(self):
        self.put('README.md', "# App\nThis project was bootstrapped with a framework. Install dependencies and run start.")
        self.assertFalse(self.control('docs-quickstart')['satisfied'])
        self.put('docs/architecture.md', '# Architecture\nASSUMPTION: draft; owner review required.\nService owns records.\n```mermaid\n A --> B\n```')
        self.assertFalse(self.control('docs-architecture')['satisfied'])

    def test_api_prose_and_empty_spec_are_insufficient(self):
        self.put('docs/contracts/openapi.yaml', '{}')
        self.assertFalse(self.control('docs-api')['satisfied'])
        self.assertEqual(self.control('docs-api')['status'], 'insufficient-evidence')
        self.put('docs/contracts/openapi.yaml', 'openapi: 3.0.3\n# paths TBD')
        self.assertFalse(self.control('docs-api')['satisfied'])

    def test_security_and_ops_aliases(self):
        for path in ['docs/security/THREAT_MODEL-v2.md','docs/security/ASVS-4.0.md',
                     'ops/readiness/production-readiness-review.md','ops/recovery/backup-plan.md']:
            self.put(path, '# Review\nOwner operations reviewed assets, trust boundaries, abuse cases and ASVS 4.0 controls. Negative authorization tests documented. SLO alerts rollback restore reviewed.')
        for ident in ['threat-model','asvs','prr','backup-policy']:
            self.assertTrue(self.control(ident)['satisfied'], ident)
        self.put('ops/budgets/service-SLO.yml', 'p95_ms: 250\nerror_rate: 0.01\nowner: operations\nwindow: 30d\ntarget: 0.999\nerror_budget_action: freeze\nalert_owner: operations')
        self.assertTrue(self.control('slo')['satisfied'])
        self.assertTrue(self.control('ops-slo')['satisfied'])

    def test_sql_schema_prisma_and_alembic_parts(self):
        self.put('storage/schema/001.sql', 'CREATE TABLE records (id integer PRIMARY KEY, parent integer REFERENCES parents(id), CHECK (id > 0));')
        self.put('api/prisma/schema.prisma', 'model Record { id Int @id }')
        self.put('services/jobs/alembic/versions/001.py', 'def upgrade(): pass')
        self.assertEqual({p['path'] for p in parts(self.root,{})}, {'storage','api','services/jobs'})
        self.assertTrue(self.control('data-model')['satisfied'])

    def test_ci_runtime_is_never_execution_proof(self):
        self.put('.github/workflows/tests.yaml', 'jobs:\n  tests:\n    steps:\n      - run: npx playwright test\n      - run: k6 run perf/load.js\n')
        self.put('apps/web/playwright.config.ts', 'export default {testDir:"tests"}')
        report=assess(self.root,'L')
        for ident in ['playwright-ci','k6-ci']:
            item=self.control(ident, report)
            self.assertTrue(item['satisfied'])
            self.assertEqual(item['status'],'needs-runtime')
            self.assertEqual(item['points'], 0)
            self.assertIn('unverified', item['threshold'])
        # Command presence is preparation only; execution remains unverified.
        self.assertEqual(self.control('load',report)['status'], 'needs-runtime')

    def test_shell_and_yaml_inventory_shared(self):
        self.put('infra/backup-nightly.sh', '#!/bin/sh\necho backup restore')
        self.put('.github/workflows/restore.yml', 'jobs:\n  restore:\n    steps:\n      - run: echo restore')
        self.assertTrue(self.control('restore')['satisfied'])
        self.assertEqual(self.control('restore')['status'], 'needs-runtime')

    def test_runbook_name_does_not_establish_threshold(self):
        self.put('ops/runbooks/service.md', '# Runbook\nProcedures will be added later.')
        c=self.control('docs-runbook')
        self.assertFalse(c['satisfied'])
        self.assertTrue(c['candidate_evidence'])
        self.put('ops/runbooks/service.md', '# Runbook\nAlert on incident. Contact owner on-call. Recover using rollback procedure.')
        self.assertTrue(self.control('docs-runbook')['satisfied'])

    def test_headings_and_drafts_fail_but_html_is_content(self):
        for content in ['# threat model\n## assets\n## boundaries', 'TODO add assets', '', '{}']:
            self.put('docs/threat-model.md',content)
            self.assertFalse(self.control('threat-model')['satisfied'])
        self.put('docs/threat-model.md', '<details><summary>Review</summary>Owner reviewed trust boundaries and assets, abuse cases and ASVS 4.0 controls.</details>')
        self.assertTrue(self.control('threat-model')['satisfied'])

    def test_deny_first_symlinks_fifo_and_size(self):
        for path in ['Secrets/config.json','nested/PRIVATE/guide.md','docs/memory.md',
                     'docs/EMAIL.md','.env.json','nested/credentials.yml','infra/klucze-realm.py','keys/passwords.json','node_modules/pkg/index.ts',
                     'build/main.js','.git/config.json','.codex/state.json']:
            self.put(path,'private must never be read')
        self.put('oversize.md','x'*1_000_001)
        self.put('docs/public.md','Safe public documentation.')
        self.put('docs/public.md.link','ignored')
        (self.root/'escape.md').symlink_to(self.root/'docs/public.md')
        (self.root/'docs/loop').symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.root/'pipe.md')
        self.assertEqual(set(inventory(self.root)), {'docs/public.md', 'docs/public.md.link', 'oversize.md', 'node_modules/pkg/index.ts', 'build/main.js'})

    def test_manifest_variants_pnpm_and_workspace_exclusions(self):
        self.put('pnpm-workspace.yaml', 'packages:\n - "apps/*"\n - "!apps/archive"')
        self.put('apps/web/project.json','{"name":"web"}')
        self.put('apps/web/src/main.ts','export const value=1')
        self.put('apps/archive/package.json','{}')
        self.put('worker/requirements.txt','queue-lib==1')
        self.assertEqual({p['path'] for p in parts(self.root,{})}, {'apps/web','worker'})

    def test_malformed_manifest_and_explicit_part_escape(self):
        self.put('package.json','{broken')
        self.put('worker/job.py','print(42)')
        self.assertEqual(parts(self.root,{}),[{'path':'worker'}])
        with self.assertRaises(ValueError): parts(self.root,{'parts':[{'path':'../outside'}]})

    def test_category_palette_line_provenance(self):
        self.put('frontend/package.json','{"dependencies":{"react":"1"}}')
        self.put('frontend/style.css','/* palette */\n:root { --accent: #123456; }')
        self.put('api/alembic/versions/001.py','def upgrade(): pass')
        self.put('infra/Dockerfile.worker','FROM python:3')
        out=Path(self.temp.name)/'audit'; audit(self.root,out,'M')
        report=json.loads((out/'audit.json').read_text())
        paths={p['path']:p for p in report['inventory']}
        self.assertIn('migrations',paths['api/alembic/versions/001.py']['categories'])
        self.assertIn('docker',paths['infra/Dockerfile.worker']['categories'])
        self.assertTrue(any(o.get('value')=='#123456' and o['evidence']=='frontend/style.css:2' for o in report['observations']))

    def test_slo_types_owners_and_parser_gap(self):
        from unittest.mock import patch
        self.put('ops/slo.yaml', 'p95: nope\nerror_rate: nope')
        self.assertFalse(self.control('slo')['satisfied'])
        self.assertFalse(self.control('ops-slo')['satisfied'])
        with patch.dict(sys.modules, {'yaml': None}):
            item=self.control('slo')
            self.assertFalse(item['satisfied'])
            self.assertEqual(item['status'],'assessment-gap')
            self.assertEqual(item['checks'][0]['candidates'][0]['reason'],'parser-missing')
        for bad in ['{"p95_ms":true,"error_rate":0.1,"owner":"ops","window":"30d"}',
                    '{"p95_ms":250,"error_rate":2,"owner":"ops","window":"30d"}',
                    '{"p95_ms":250,"error_rate":0.1}']:
            self.put('ops/slo.yaml', bad)
            self.assertFalse(self.control('slo')['satisfied'])

    def test_external_sensitive_docs_and_safe_descriptor_read(self):
        from helix_audit_context import documents, safe_read
        from unittest.mock import patch
        ext=Path(self.temp.name).resolve()/'external';ext.mkdir()
        (ext/'API-TOKEN.json').write_text('never read')
        (ext/'notes.md').write_text('Public architecture notes only.')
        self.assertEqual(set(documents(self.root,[ext])), {str(ext/'notes.md')})
        link=ext/'changed.md';link.symlink_to(ext/'notes.md')
        with self.assertRaises(OSError): safe_read(link)
        # Replacing pathname reads cannot influence descriptor-owned content.
        with patch.object(Path,'read_text',side_effect=AssertionError('unsafe pathname read')):
            self.assertEqual(safe_read(ext/'notes.md'), 'Public architecture notes only.')

    def test_business_rules_are_not_custom_gates(self):
        self.put('database/migrations/001_business_reguly.sql', 'CREATE TABLE rules (id integer);')
        self.put('src/MacierzRoles.svelte', '<p>Role matrix</p>')
        self.put('docs/test-matrix.md', 'Gate command and testing matrix are documented here.')
        gates=assess(self.root, 'M')['custom_gates']
        self.assertEqual([g['name'] for g in gates], ['docs/test-matrix.md'])

    def test_diagnostics_include_absent_selector_and_near_miss(self):
        self.put('docs/architecture-notes.md','# Design\nService owns records but has no diagram.')
        c=self.control('docs-architecture')
        self.assertFalse(c['satisfied'])
        self.assertEqual(c['checks'][0]['candidates'][0]['reason'],'content-predicate-not-met')
        self.assertFalse(self.control('docs-api')['checks'][0]['candidates'])
