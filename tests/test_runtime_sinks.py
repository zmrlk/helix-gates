"""Pure local-send contracts. No sockets, commands or target application code."""
import builtins
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
import helix_runtime_sinks as sinks


def fixture_report(state='pending', *, sibling=False, config=None):
    sources = {'frontend/src/send.ts': "import x from 'resend';\nfetch('https://api2.serwersms.pl/messages/send_sms');\n"
               "consume(process.env.PLAY_BASE_URL);\nfetch('https://graph.facebook.com/v23.0/123/feed');\n"
               "fetch('https://open.tiktokapis.com/v2/post/publish/content/init/');\nimport w from 'web-push';",
               'frontend/docs/mail.md': "import x from 'resend';",
               'frontend/legacy/send.ts': "import x from 'resend';"}
    parts = [{'path':'frontend'}] + ([{'path':'other'}] if sibling else [])
    inventory = integrations.inventory(sources, parts, config)
    plan = sinks.sink_plan(inventory, parts)
    report = dict(run_id='runtime-synthetic', parts=parts, integrations=inventory, sink_plan=plan, sink_observations=[])
    if state != 'pending':
        snapshot = dict(schema_version=1, binding=dict(run_id=report['run_id'],plan_id=plan['plan_id'],
            integration_plan_id=inventory['plan_id'],part='frontend',attempt_id='sink-'+'a'*32),
            status='ready' if state=='ready' else 'partial' if state=='partial' else 'closed',
            cleanup='unknown' if state in ('ready','partial') else 'closed', observations=[], gaps=[])
        if state in ('captured','partial','rejected'):
            snapshot['observations']=[dict(sequence=1,operation_id='resend.send',provider='resend',
                http_status=400 if state=='rejected' else 200,outcome='rejected_local' if state=='rejected' else 'captured_local')]
        if state=='partial': snapshot['gaps']=['SINK_WRITE_FAILED']
        report['sink_observations']=[snapshot]
    return report


def fixture_input():
    report=fixture_report()
    value=sinks.build_sink_input(report['sink_plan'],run_id=report['run_id'],part='frontend',attempt_id='sink-'+'a'*32,
        origin='http://127.0.0.1:32123',mailbox_path='/tmp/helix-synthetic/mailbox',bearer_token='b'*64,
        public_path='/tmp/helix-synthetic/public.json',deadline_unix_ms=4000000000000,
        own_origins=['http://127.0.0.1:32124'],synthetic_domains=['helix-mail.invalid'])
    return report,value


class RuntimeSinks(unittest.TestCase):
    def test_six_channels_preserve_locations_and_separate_docs_legacy(self):
        report=fixture_report();view=sinks.project_sinks(report)
        self.assertEqual({p['provider'] for p in view['parts'][0]['providers']},set(sinks.PROVIDERS))
        self.assertEqual({p['area'] for p in view['excluded_declarations']},{'docs','legacy'})
        sms=next(p for p in view['parts'][0]['providers'] if p['provider']=='serwersms')
        self.assertEqual(sms['evidence'][0]['path'],'frontend/src/send.ts');self.assertEqual(sms['evidence'][0]['line'],2)
        self.assertEqual(view['counts']['captured_local'],0);self.assertEqual(view['execution_status'],'NOT_RUN')

    def test_readiness_and_capture_never_prove_delivery_or_routes(self):
        for state,count in [('pending',0),('ready',0),('captured',1),('partial',1),('rejected',0)]:
            with self.subTest(state=state):
                view=sinks.project_sinks(fixture_report(state))
                self.assertEqual(view['counts']['captured_local'],count)
                self.assertEqual(view['counts']['external_deliveries_verified'],0)
                self.assertEqual(view['counts']['application_routes_verified'],0)
                self.assertEqual(view['external_delivery'],'NOT_RUN');self.assertEqual(view['coverage_status'],'INCOMPLETE')
        self.assertEqual(sinks.project_sinks(fixture_report('rejected'))['counts']['rejected_local'],1)

    def test_partial_preserves_prior_capture_and_known_gap(self):
        view=sinks.project_sinks(fixture_report('partial'))
        self.assertEqual(view['execution_status'],'PARTIAL');self.assertEqual(view['counts']['captured_local'],1)
        self.assertIn('SINK_WRITE_FAILED',view['parts'][0]['gaps']);self.assertIn('CLEANUP_UNKNOWN',view['parts'][0]['gaps'])

    def test_legacy_counts_unknown_and_missing_half_contract_rejected(self):
        self.assertTrue(all(v is None for v in sinks.project_sinks({})['counts'].values()))
        for report in ({'sink_plan':{}},{'sink_observations':[]}):
            with self.assertRaisesRegex(ValueError,'invalid or unbound'):sinks.project_sinks(report)

    def test_sibling_filter_does_not_invent_dependency(self):
        report=fixture_report('captured',sibling=True)
        view=sinks.project_sinks(report,['other'])
        self.assertEqual(view['plan_status'],'NOT_DETECTED');self.assertEqual(view['coverage_status'],'NOT_DETECTED')
        self.assertEqual(view['counts']['captured_local'],0)
        report['sink_observations'][0]['observations'][0]['provider']='tiktok'
        with self.assertRaises(ValueError):sinks.project_sinks(report,['other'])

    def test_current_run_inventory_and_plan_are_required(self):
        for key,value in [('run_id','old-run'),('plan_id','f'*64),('integration_plan_id','f'*64),('part','other'),('attempt_id','sink-old')]:
            report=fixture_report('captured');report['sink_observations'][0]['binding'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):sinks.project_sinks(report)

    def test_rehashed_omission_or_disabled_operation_is_rejected(self):
        report=fixture_report('captured');report['sink_plan']['parts']=[]
        report['sink_plan']['plan_id']=sinks._digest({k:v for k,v in report['sink_plan'].items() if k!='plan_id'})
        with self.assertRaises(ValueError):sinks.project_sinks(report)
        cfg={'runtime':{'integrations':{'resend':{'strategy':'disabled'}}}}
        report=fixture_report('captured',config=cfg)
        self.assertIn('STRATEGY_DISABLED',report['sink_plan']['parts'][0]['gaps'])
        with self.assertRaises(ValueError):sinks.project_sinks(report)

    def test_control_token_response_is_not_a_captured_message(self):
        report=fixture_report('captured');row=report['sink_observations'][0]['observations'][0]
        row.update(operation_id='play.token',provider='play-sms')
        self.assertEqual(sinks.project_sinks(report)['counts']['captured_local'],0)

    def test_all_disabled_providers_remain_blocked_without_adapter_start(self):
        config={'runtime':{'integrations':{name:{'strategy':'disabled'} for name in sinks.PROVIDERS}}}
        report=fixture_report(config=config)
        self.assertEqual(report['sink_plan']['status'],'BLOCKED')
        view=sinks.project_sinks(report)
        self.assertEqual(view['plan_status'],'BLOCKED');self.assertEqual(view['execution_status'],'NOT_RUN')
        self.assertEqual(report['sink_plan']['parts'][0]['operation_ids'],[])

    def test_durable_shape_rejects_duplicate_sequence_and_invented_success(self):
        for mutate in (lambda s:s['observations'].append(copy.deepcopy(s['observations'][0])),
                       lambda s:s['observations'][0].update(sequence=True),
                       lambda s:s['observations'][0].update(outcome='delivered'),
                       lambda s:s['observations'][0].update(http_status=202),
                       lambda s:s.update(status='not_run'),lambda s:s.update(cleanup='unknown')):
            report=fixture_report('captured');mutate(report['sink_observations'][0])
            with self.assertRaises(ValueError):sinks.project_sinks(report)

    def test_public_unknown_fields_and_raw_secrets_are_not_echoed(self):
        canary='PRIVATE_RECIPIENT_TOKEN'
        for target in ('snapshot','binding','observation'):
            report=fixture_report('captured');snapshot=report['sink_observations'][0]
            row={'snapshot':snapshot,'binding':snapshot['binding'],'observation':snapshot['observations'][0]}[target]
            row['raw_body']=canary
            with self.assertRaises(ValueError) as error:sinks.project_sinks(report)
            self.assertNotIn(canary,str(error.exception))
        report,value=fixture_input();self.assertNotIn(value['bearer_token'],json.dumps(sinks.project_sinks(report)))
        self.assertNotIn(value['mailbox_path'],json.dumps(sinks.project_sinks(report)))

    def test_dynamic_inventory_execution_does_not_invalidate_static_plan(self):
        report=fixture_report('captured')
        for entry in report['integrations']['integrations']:entry['execution']['status']='ready'
        self.assertEqual(sinks.project_sinks(report)['counts']['captured_local'],1)

    def test_private_table_exact_origins_and_domains_only(self):
        report,value=fixture_input()
        self.assertEqual(value['operations'],list(sinks.OPERATIONS))
        self.assertEqual(value['webpush_endpoint'],'http://127.0.0.1:32123/web-push/helix-synthetic')
        self.assertEqual(value['limits']['max_body_bytes'],1048576)
        base=dict(run_id=report['run_id'],part='frontend',attempt_id='sink-'+'a'*32,origin=value['origin'],
                  mailbox_path=value['mailbox_path'],bearer_token=value['bearer_token'],public_path=value['public_path'],
                  deadline_unix_ms=value['deadline_unix_ms'])
        for changes in ({'origin':'http://localhost:32123'},{'origin':'https://api.resend.com'},
                        {'synthetic_domains':['evil.invalid']},{'synthetic_domains':['*.invalid']},
                        {'own_origins':['http://localhost:32123@evil.test:80']},{'mailbox_path':'/tmp/../etc'},
                        {'deadline_unix_ms':True},{'bearer_token':'PRIVATE_CANARY'}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):sinks.build_sink_input(report['sink_plan'],**dict(base,**changes))

    def test_mutated_catalog_or_extra_private_plan_data_rejected(self):
        report,value=fixture_input()
        base=dict(run_id=report['run_id'],part='frontend',attempt_id=value['binding']['attempt_id'],origin=value['origin'],
                  mailbox_path=value['mailbox_path'],bearer_token=value['bearer_token'],public_path=value['public_path'],
                  deadline_unix_ms=value['deadline_unix_ms'])
        for mutate in (lambda p:p.update(catalog_hash='f'*64),lambda p:p.update(catalog_version=True),
                       lambda p:p.update(raw_credentials='CANARY'),lambda p:p['parts'][0]['operation_ids'].append('unknown.send')):
            plan=copy.deepcopy(report['sink_plan']);mutate(plan);plan['plan_id']=sinks._digest({k:v for k,v in plan.items() if k!='plan_id'})
            with self.assertRaises(ValueError):sinks.build_sink_input(plan,**base)

    def test_plan_and_projection_no_io_or_mutation(self):
        report=fixture_report('captured');before=copy.deepcopy(report)
        with patch.object(builtins,'open',side_effect=AssertionError('read')),patch.object(socket,'socket',side_effect=AssertionError('network')),\
             patch.object(subprocess,'run',side_effect=AssertionError('command')):
            sinks.sink_plan(report['integrations'],report['parts']);sinks.project_sinks(report)
        self.assertEqual(before,report)

    def test_source_gap_and_unscoped_dependency_never_disappear(self):
        inventory=integrations.inventory({'shared/mail.ts':"import x from 'resend';"},[{'path':'frontend'}])
        report=dict(integrations=inventory,sink_plan=sinks.sink_plan(inventory,[{'path':'frontend'}]),sink_observations=[])
        view=sinks.project_sinks(report,['frontend'])
        self.assertEqual(view['coverage_status'],'INCOMPLETE');self.assertTrue(view['unscoped_declarations'])
        self.assertIn('INTEGRATION_SCOPE_UNRESOLVED',view['gaps'])


if __name__=='__main__':unittest.main()
