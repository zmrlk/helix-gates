"""Synthetic integration declarations and receipts. No project/service execution."""
import copy
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_integrations as integrations


class RuntimeIntegrationsTests(unittest.TestCase):
    def inventory(self, sources, parts=None, config=None):
        return integrations.inventory(sources, parts or [dict(path='app')], config)

    def entry(self, report, provider, area='active', part=None):
        rows = [e for e in report['integrations'] if e['provider'] == provider and e['area'] == area and
                (part is None or e['parts'] == [part])]
        self.assertEqual(len(rows), 1, rows)
        return rows[0]

    def route_plan(self, provider='resend', package='resend'):
        return self.inventory({'app/src/routes/api/send/+server.ts':
            f"import client from '{package}';\nexport const POST = () => client.send();"})

    def reconcile(self, plan, receipts=None, **kwargs):
        return integrations.reconcile(plan, receipts, run_id=kwargs.get('run_id', 'run-one'))

    def receipt(self, entry, **changes):
        return dict(integration_id=entry['id'], plan_id=entry['plan_id'], run_id='run-one', strategy=entry['strategy']['selected'],
                    status='completed', readiness='ready', actual_version='1.2.3', logs=['logs/service.json'], **changes)

    def route_receipt(self, route='/api/send', method='POST', **changes):
        return dict(route=route, method=method, status='PASS', evidence='logs/operation.json',
                    integration_exercised=True, **changes)

    def test_all_project_a_categories_from_small_synthetic_patterns(self):
        packages = ['pg', 'openid-client', 'ioredis', 'resend', 'nodemailer', 'web-push',
                    'whatsapp-web.js', 'puppeteer', 'playwright', 'sharp', 'satori', 'node-cron',
                    'openai', '@simplewebauthn/server', 'celery']
        names = ['SERWERSMS_TOKEN', 'PLAY_SMS_KEY', 'META_ACCESS_TOKEN', 'TIKTOK_TOKEN', 'SUBIEKT_URL']
        source = '\n'.join(f"import p{i} from '{name}';" for i, name in enumerate(packages))
        source += '\n' + '\n'.join(f'consume(process.env.{name});' for name in names)
        report = self.inventory({'app/src/clients.ts': source})
        expected = {'postgres', 'oidc', 'redis', 'resend', 'smtp', 'web-push', 'whatsapp',
                    'puppeteer', 'playwright', 'sharp', 'satori', 'cron', 'ai', 'webauthn',
                    'worker', 'serwersms', 'play-sms', 'meta', 'tiktok', 'subiekt'}
        self.assertEqual({e['provider'] for e in report['integrations']}, expected)
        self.assertTrue(all(e['coverage']['status'] == 'not_checked' for e in report['integrations']))
        self.assertTrue(all(e['execution']['status'] == 'not_run' for e in report['integrations']))

    def test_monorepo_shared_import_does_not_attach_sibling_dependency(self):
        sources = {'apps/one/src/routes/mail/+server.ts': "import {send} from '../../../../../shared/mail';\nexport const POST=send;",
                   'apps/two/src/routes/cache/+server.ts': "import Redis from 'ioredis';\nexport const GET=()=>new Redis();",
                   'shared/mail.ts': "import {Resend} from 'resend';\nexport const send=()=>new Resend();"}
        report = self.inventory(sources, [dict(path='apps/one'), dict(path='apps/two')])
        resend = self.entry(report, 'resend', part='apps/one')
        self.assertEqual(resend['affected_routes'][0]['path'], '/mail')
        self.assertEqual(resend['affected_routes'][0]['relation'], 'import_chain')
        self.assertEqual(self.entry(report, 'redis')['parts'], ['apps/two'])
        self.assertFalse(any(e['provider'] == 'resend' and e['parts'] == ['apps/two'] for e in report['integrations']))

    def test_comments_and_string_examples_do_not_create_active_connections(self):
        source = """// import fake from 'resend';
/* fetch('https://api.serwersms.pl/send'); */
const example = "import x from 'whatsapp-web.js'; process.env.REDIS_URL";
const also = 'fetch("https://api.resend.com/send")';
import client from 'pg';
"""
        report = self.inventory({'app/src/main.ts': source})
        self.assertEqual([e['provider'] for e in report['integrations']], ['postgres'])

    def test_docs_legacy_examples_and_tests_are_separate(self):
        report = self.inventory({name: "import {Resend} from 'resend';" for name in
            ['app/src/mail.ts', 'app/legacy/mail.ts', 'app/docs/guide.md', 'app/tests/mail.test.ts', 'app/examples/mail.ts']})
        self.assertEqual({e['area'] for e in report['integrations']}, {'active', 'legacy', 'docs', 'tests', 'examples'})
        result = self.reconcile(report)
        self.assertTrue(all(e['coverage']['status'] == 'not_applicable' for e in result['integrations'] if e['area'] != 'active'))

    def test_env_aliases_are_names_only_and_real_env_is_ignored(self):
        secret = 'PRIVATE_VALUE_DO_NOT_RETAIN'
        report = self.inventory({'app/src/mail.ts': "import {env as privateEnv} from '$env/dynamic/private';\nconst a=privateEnv.RESEND_API_KEY;\nconst b=process.env.RESEND_TOKEN;",
            'app/.env.example': f'RESEND_API_KEY={secret}\n# REDIS_URL={secret}\n',
            'app/.env.production': f'REDIS_URL={secret}', 'app/.env': f'OPENAI_API_KEY={secret}'})
        self.assertEqual(self.entry(report, 'resend')['env_names'], ['RESEND_API_KEY', 'RESEND_TOKEN'])
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn('redis', {e['provider'] for e in report['integrations']})
        self.assertEqual(len(report['discovery']['excluded']), 2)

    def test_images_ci_and_package_declarations_retain_locations_and_versions(self):
        report = self.inventory({'app/compose.yml': 'services:\n  data:\n    image: "postgres:16.4"\n    environment:\n      REDIS_URL: never-retain-me\n',
            'app/.github/workflows/check.yml': 'services:\n  cache:\n    image: redis:7.2\n',
            'app/package.json': json.dumps({'dependencies': {'resend': '^4.2.0', 'openai': 'https://SECRET@private/package'}})})
        postgres = self.entry(report, 'postgres')
        self.assertEqual(postgres['declared_versions'], ['16.4'])
        self.assertEqual(postgres['evidence'][0]['line'], 3)
        self.assertEqual(self.entry(report, 'resend')['declared_versions'], ['^4.2.0'])
        self.assertEqual(self.entry(report, 'ai')['declared_versions'], [])
        self.assertNotIn('never-retain-me', json.dumps(report)); self.assertNotIn('SECRET', json.dumps(report))

    def test_known_keycloak_does_not_get_generic_oidc_emulator_fallback(self):
        report = self.inventory({'app/auth.ts': "import {Issuer} from 'openid-client';\nconst realm=process.env.KEYCLOAK_REALM;"})
        self.assertEqual([e['provider'] for e in report['integrations']], ['keycloak'])
        keycloak = self.entry(report, 'keycloak')
        self.assertEqual(keycloak['strategy']['selected'], 'container')
        self.assertTrue(keycloak['strategy']['implemented'])
        self.assertEqual(keycloak['execution']['status'], 'not_run')
        self.assertEqual(keycloak['coverage']['status'], 'not_checked')
        self.assertEqual(len(keycloak['evidence']), 2)

    def test_dynamic_route_and_unknown_alias_stay_explicit_gaps(self):
        report = self.inventory({'app/src/routes/items/[id]/+server.ts': "import {Resend} from 'resend';\nimport auth from '@/hidden';\nexport const GET=()=>new Resend();"})
        entry = self.entry(report, 'resend')
        self.assertEqual(entry['affected_routes'][0]['path'], '/items/:id')
        reasons = [r['reason'] for r in entry['unresolved_paths']]
        self.assertTrue(any('dynamiczna' in reason for reason in reasons))
        self.assertTrue(any('nierozwiązany import' in reason for reason in reasons))
        result = self.reconcile(report, [self.receipt(entry, tested_routes=[self.route_receipt('/items/:id', 'GET')])])
        self.assertEqual(self.entry(result, 'resend')['coverage']['status'], 'partial')

    def test_literal_api_routes_not_only_browser_part_routes(self):
        report = self.inventory({'app/server.ts': "import pg from 'pg';\napp.post('/api/save', handler);\napp.get('/health', ready);"},
                                [dict(path='app', routes=['/'])])
        self.assertEqual({r['path'] for r in self.entry(report, 'postgres')['affected_routes']}, {'/api/save', '/health'})
        self.assertTrue(all(r['relation'] == 'direct_file' for r in self.entry(report, 'postgres')['affected_routes']))

    def test_python_and_fastify_explicit_routes(self):
        report = self.inventory({'app/views.py': 'import smtplib\n@app.post("/mail")\ndef send(): pass\n',
            'app/cache.ts': "import Redis from 'ioredis';\nfastify.route({url: '/cache', method: 'GET', handler});"})
        self.assertEqual(self.entry(report, 'smtp')['affected_routes'][0]['path'], '/mail')
        self.assertEqual(self.entry(report, 'redis')['affected_routes'][0]['path'], '/cache')

    def test_unknown_http_and_known_hosts_without_retaining_url_or_credentials(self):
        report = self.inventory({'app/api.ts': "fetch('https://user:SECRET@api.resend.com/path?token=SECRET');\nfetch(endpoint);\nfetch('/api/local');"})
        self.assertEqual({e['provider'] for e in report['integrations']}, {'resend', 'unknown-http'})
        unknown = self.entry(report, 'unknown-http')
        self.assertIsNone(unknown['strategy']['selected'])
        self.assertNotIn('SECRET', json.dumps(report)); self.assertNotIn('api.resend.com', json.dumps(report))

    def test_only_local_http_does_not_invent_external_integration(self):
        self.assertEqual(self.inventory({'app/client.ts': "fetch('/api/local');"})['integrations'], [])

    def test_sms_v2_and_tiktok_content_hosts_keep_scopes_and_locations(self):
        sources = {'app/sms.ts': "fetch('https://api2.serwersms.pl/messages/send_sms');",
                   'app/social.ts': "\nfetch('https://open.tiktokapis.com/v2/post/publish/content/init/');",
                   'other/docs/example.md': "fetch('https://open.tiktokapis.com/v2/example');"}
        report = self.inventory(sources, [dict(path='app'), dict(path='other')])
        sms = self.entry(report, 'serwersms', part='app')
        social = self.entry(report, 'tiktok', part='app')
        self.assertEqual(sms['evidence'][0]['path'], 'app/sms.ts')
        self.assertEqual(social['evidence'][0]['line'], 2)
        self.assertEqual(self.entry(report, 'tiktok', 'docs')['parts'], ['other'])
        self.assertNotIn('unknown-http', {entry['provider'] for entry in report['integrations']})

    def test_route_registration_inside_literal_is_not_an_affected_route(self):
        report = self.inventory({'app/server.ts': '''import pg from 'pg';
const example = "fastify.route({url: '/fake', method: 'GET'});";
'''})
        self.assertEqual(self.entry(report, 'postgres')['affected_routes'], [])

    def test_explicit_strategy_is_preserved_and_invalid_configuration_fails_cleanly(self):
        config = {'runtime': {'integrations': {'resend': {'strategy': 'replay', 'required_for_startup': True}}}}
        before = copy.deepcopy(config)
        report = self.inventory({'app/mail.ts': "import x from 'resend';"}, config=config)
        entry = self.entry(report, 'resend')
        self.assertEqual(entry['strategy']['selected'], 'replay'); self.assertEqual(entry['strategy']['requested'], 'replay')
        self.assertTrue(entry['required_for_startup']); self.assertEqual(config, before)
        for bad in [[], {'integrations': []}, {'integrations': {'resend': {'strategy': 'native'}}},
                    {'integrations': {'resend': {'strategy': 'disabled', 'required_for_startup': 'yes'}}}]:
            with self.subTest(bad=bad), self.assertRaises(ValueError): self.inventory({}, config=bad)

    def test_ready_database_and_oidc_do_not_prove_routes(self):
        for provider, package in [('postgres', 'pg'), ('oidc', 'openid-client')]:
            with self.subTest(provider=provider):
                plan = self.route_plan(provider, package); entry = self.entry(plan, provider)
                receipt = self.receipt(entry); receipt['status'] = 'ready'
                result = self.reconcile(plan, [receipt]); actual = self.entry(result, provider)
                self.assertEqual(actual['execution']['readiness'], 'ready')
                self.assertEqual(actual['coverage']['status'], 'not_checked')
                self.assertEqual(result['status'], 'INCOMPLETE')

    def test_exercised_route_receipt_counts_without_claiming_pass(self):
        plan = self.route_plan(); entry = self.entry(plan, 'resend'); before = copy.deepcopy(plan)
        result = self.reconcile(plan, [self.receipt(entry, tested_routes=[self.route_receipt()])])
        self.assertEqual(self.entry(result, 'resend')['coverage']['status'], 'tested')
        self.assertEqual(result['status'], 'RECORDED'); self.assertEqual(plan, before)
        failed = self.route_receipt(); failed['status'] = 'FAIL'
        result = self.reconcile(plan, [self.receipt(entry, tested_routes=[failed])])
        self.assertEqual(self.entry(result, 'resend')['coverage']['tested_routes'][0]['status'], 'FAIL')
        self.assertNotIn('pass', result)

    def test_browser_route_without_dependency_evidence_does_not_count(self):
        plan = self.route_plan(); entry = self.entry(plan, 'resend'); test = self.route_receipt(); test.pop('integration_exercised')
        result = self.reconcile(plan, [self.receipt(entry, tested_routes=[test])])
        self.assertEqual(self.entry(result, 'resend')['coverage']['tested_routes'], [])
        self.assertTrue(result['receipt_errors'])

    def test_disabled_requires_enforcement_receipt_but_still_is_untested(self):
        plan = self.inventory({'app/a.ts': "import Client from 'whatsapp-web.js';"}); entry = self.entry(plan, 'whatsapp')
        first = self.reconcile(plan); second = self.reconcile(plan, [self.receipt(entry, disabled_verified=True)])
        self.assertIn('bez dowodu', ' '.join(self.entry(first, 'whatsapp')['coverage']['untested_because']))
        self.assertIn('nie było testowane', ' '.join(self.entry(second, 'whatsapp')['coverage']['untested_because']))
        self.assertEqual(second['status'], 'INCOMPLETE')

    def test_reconcile_resets_previous_attempt_and_sanitizes_unknown_fields(self):
        plan = self.route_plan(); entry = self.entry(plan, 'resend')
        receipt = self.receipt(entry, tested_routes=[self.route_receipt()], stdout='SECRET', env={'TOKEN': 'SECRET'})
        result = self.reconcile(plan, [receipt])
        self.assertNotIn('SECRET', json.dumps(result))
        again = self.reconcile(result)
        self.assertEqual(self.entry(again, 'resend')['execution']['status'], 'not_run')
        self.assertEqual(self.entry(again, 'resend')['coverage']['tested_routes'], [])

    def test_invalid_receipts_and_paths_are_explicit_errors_not_tracebacks(self):
        plan = self.route_plan(); entry = self.entry(plan, 'resend')
        invalid = [None, {'integration_id': {}}, self.receipt(entry)]
        invalid[-1]['logs'] = ['../../secret']
        for field, value in [('strategy', 'native'), ('actual_version', 'token=SECRET'), ('readiness', True)]:
            receipt = self.receipt(entry); receipt[field] = value; invalid.append(receipt)
        test = self.route_receipt(); test['route'] = {}; invalid.append(self.receipt(entry, tested_routes=[test]))
        result = self.reconcile(plan, invalid)
        self.assertEqual(len(result['receipt_errors']), len(invalid))
        self.assertNotIn('SECRET', json.dumps(result)); self.assertEqual(result['status'], 'INCOMPLETE')

    def test_missing_old_report_and_empty_source_are_not_completed_coverage(self):
        self.assertEqual(self.reconcile(None)['status'], 'NOT_RECORDED')
        self.assertEqual(self.inventory({})['status'], 'INCOMPLETE')
        report = self.inventory({'../bad.ts': 'secret', 'app/package.json': '{bad'})
        self.assertEqual(report['status'], 'INCOMPLETE'); self.assertEqual(len(report['discovery']['errors']), 2)

    def test_malformed_plan_and_unmatched_explicit_strategy_are_not_silently_accepted(self):
        plan = self.route_plan()
        for changed in [{}, {'schema_version': 1, 'integrations': [None]},
                        {'schema_version': 1, 'integrations': [{'provider': {}}]}]:
            with self.subTest(changed=changed), self.assertRaises(ValueError): self.reconcile(changed)
        duplicate = copy.deepcopy(plan); duplicate['integrations'] *= 2
        with self.assertRaises(ValueError): self.reconcile(duplicate)
        result = self.inventory({'app/main.ts': 'const value = 1;'}, config={'integrations': {'resend': {'strategy': 'replay'}}})
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIn('jawnych strategii', result['discovery']['errors'][0]['reason'])

    def test_unresolved_import_inside_shared_helper_stays_with_importing_part(self):
        report = self.inventory({'app/src/routes/mail/+server.ts': "import send from '../../../../shared/mail';\nexport const POST=send;",
            'shared/mail.ts': "import {Resend} from 'resend';\nimport template from '@/unknown';"})
        self.assertTrue(any('nierozwiązany import' in row['reason'] for row in self.entry(report, 'resend')['unresolved_paths']))

    def test_old_source_or_other_run_receipt_never_confirms_current_coverage(self):
        old = self.route_plan(); entry = self.entry(old, 'resend')
        receipt = self.receipt(entry, tested_routes=[self.route_receipt()])
        changed = self.inventory({'app/src/routes/api/send/+server.ts':
            "import client from 'resend';\nexport const POST = () => client.send({changed: true});"})
        self.assertEqual(entry['id'], self.entry(changed, 'resend')['id'])
        self.assertNotEqual(old['plan_id'], changed['plan_id'])
        for plan, run_id in [(changed, 'run-one'), (old, 'run-two'), (old, None)]:
            with self.subTest(run_id=run_id, plan_id=plan['plan_id']):
                result = self.reconcile(plan, [receipt], run_id=run_id)
                self.assertEqual(result['status'], 'INCOMPLETE')
                self.assertEqual(self.entry(result, 'resend')['coverage']['tested_routes'], [])
                self.assertTrue(result['receipt_errors'])

    def test_example_values_do_not_enter_plan_binding_but_names_do(self):
        a = self.inventory({'app/.env.example': 'RESEND_TOKEN=first-secret'})
        b = self.inventory({'app/.env.example': 'RESEND_TOKEN=second-secret'})
        c = self.inventory({'app/.env.example': 'RESEND_API_KEY=second-secret'})
        self.assertEqual(a['plan_id'], b['plan_id']); self.assertNotEqual(a['plan_id'], c['plan_id'])

    def test_play_oauth_names_and_business_endpoint_are_integration_declarations(self):
        sources={'app/src/lib/phone.ts': "const base=process.env.PLAY_BASE_URL;\nconst client=process.env.PLAY_CLIENT_ID;\nconst secret=process.env.PLAY_CLIENT_SECRET;",
                 'app/src/routes/calls/+server.ts': "import '../../../lib/phone';\nexport const GET=()=>fetch('https://uslugidlafirm.play.pl/example?token=PRIVATE');"}
        report=self.inventory(sources);row=self.entry(report,'play-sms')
        self.assertEqual(row['env_names'],['PLAY_BASE_URL','PLAY_CLIENT_ID','PLAY_CLIENT_SECRET'])
        self.assertEqual(row['coverage']['status'],'not_checked')
        self.assertIn('http_call',{e['kind'] for e in row['evidence']})
        self.assertNotIn('PRIVATE',json.dumps(report))

    def test_named_erp_protocol_keeps_affected_routes_without_inventing_a_connection(self):
        for field in ('accounting_system','system_ksiegowy','erpProvider'):
            with self.subTest(field=field):
                sources={'app/src/lib/external-ledger.ts':f"export function accepts(row) {{ return row.{field} === 'nexo'; }}",
                         'app/src/routes/ledger/+server.ts':"import {accepts} from '../../lib/external-ledger';\nexport function GET(){return accepts({});}"}
                row=self.entry(self.inventory(sources),'subiekt')
                self.assertEqual(row['evidence'][0]['kind'],'erp_protocol_declaration')
                self.assertEqual(row['strategy']['selected'],'replay');self.assertFalse(row['strategy']['implemented'])
                self.assertEqual(row['execution']['status'],'not_run')
                self.assertEqual(row['affected_routes'][0]['path'],'/ledger')

    def test_comments_and_product_labels_do_not_invent_redis_or_erp_runtime(self):
        text="// Redis: configure REDIS_URL and redis:// later\nconst label='Subiekt';\nconst example=\"row.accounting_system === 'nexo'\";\nconst info='PLAY_CLIENT_ID';"
        self.assertEqual(self.inventory({'app/view.ts':text})['integrations'],[])

    def test_large_string_heavy_source_reads_all_locations_without_quadratic_prefix_search(self):
        # Count regex input work rather than wall time, so host pressure cannot
        # make this regression flaky. Before the fix each literal rescanned its
        # entire preceding source twice, despite having no import/HTTP prefix.
        rows=[f"const value{i}='synthetic-{i}';" for i in range(4000)]
        rows += ["import client /* retained comment */ from 'resend';",
                 "const reply=fetch(/* comment */ 'https://api.resend.com/synthetic');"]
        source='\n'.join(rows);original=integrations.re.search;searched=[0]
        def counted(pattern,string,*args,**kwargs):
            searched[0]+=len(string)
            return original(pattern,string,*args,**kwargs)
        with patch.object(integrations.re,'search',side_effect=counted):
            report=self.inventory({'app/large.ts':source})
        row=self.entry(report,'resend')
        self.assertEqual({e['line'] for e in row['evidence']},{4001,4002})
        self.assertEqual(report['discovery']['files'],1)
        self.assertLess(searched[0],len(source)*100)

    def test_import_and_http_introducers_keep_multiline_comments_and_ignore_quoted_examples(self):
        source="const example=\"require('redis'); fetch('https://api.openai.com')\";\nimport\n value from /* gap */ 'pg';\nconst other=require(\n/* gap */ 'resend');\nfetch(\n/* gap */ 'https://api.serwersms.pl/synthetic');"
        report=self.inventory({'app/client.ts':source})
        self.assertEqual({row['provider'] for row in report['integrations']},{'postgres','resend','serwersms'})
        self.assertEqual(self.entry(report,'postgres')['evidence'][0]['line'],3)
        self.assertEqual(self.entry(report,'resend')['evidence'][0]['line'],5)
        self.assertEqual(self.entry(report,'serwersms')['evidence'][0]['line'],7)

    def test_pure_inventory_never_opens_files_spawns_or_connects(self):
        sources = {'app/db.ts': "import pg from 'pg';"}; original = copy.deepcopy(sources)
        with patch('builtins.open', side_effect=AssertionError('file I/O')), \
             patch.object(Path, 'read_text', side_effect=AssertionError('read')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network')):
            report = self.inventory(sources); self.reconcile(report)
        self.assertEqual(sources, original)


if __name__ == '__main__': unittest.main()
