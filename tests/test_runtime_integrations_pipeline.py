"""Inventory reaches runtime, importer and owner without inventing route proof."""
import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from test_runtime import FakeExecutor, FIX, TOOLS
import helix_config
import helix_owner_report as owner
import helix_pro
import helix_runtime as runtime
import helix_runtime_integrations as integrations


class IntegrationPipeline(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.project=self.base/'project'
        shutil.copytree(FIX/'sveltekit-pg',self.project)
        self.out=self.base/'out'

    def run_fake(self,**kwargs):
        runner=runtime.Runner(self.project,self.out,executor=kwargs.pop('executor',FakeExecutor()),
                              tools={'tools':dict(TOOLS)},port_factory=lambda:31234,**kwargs)
        return runner,runner.run()

    def entry(self,report,provider):
        return next(e for e in report['integrations']['integrations'] if e['provider']==provider and e['area']=='active')

    def dispatch(self,report):
        parser=argparse.ArgumentParser();runtime.parsers(parser.add_subparsers())
        args=parser.parse_args(['runtime','run','--project',str(self.project),'--out',str(self.out)])
        with patch.object(runtime,'Runner') as runner,contextlib.redirect_stdout(io.StringIO()):
            runner.return_value.run.return_value=report
            return runtime.dispatch(args)

    def save(self,report):
        path=self.out/'runtime-report.json';path.write_text(json.dumps(report));return path

    def test_plan_reuses_sources_and_external_config_without_execution(self):
        cfg=self.base/'config.json';cfg.write_text(json.dumps({'runtime':{'integrations':{'postgres':{'strategy':'replay'}}}}))
        helix_config.configure(self.project,cfg)
        before={p.relative_to(self.project):p.read_bytes() for p in self.project.rglob('*') if p.is_file()}
        with patch.object(runtime,'Executor') as executor,patch.object(integrations,'inventory',wraps=integrations.inventory) as build:
            spec=runtime.plan(self.project)
        executor.assert_not_called();build.assert_called_once()
        self.assertEqual(self.entry(spec,'postgres')['strategy']['requested'],'replay')
        self.assertIn('package.json',build.call_args.args[0])
        self.assertEqual(before,{p.relative_to(self.project):p.read_bytes() for p in self.project.rglob('*') if p.is_file()})
        self.assertFalse((self.project/'helix.json').exists())

    def test_real_adapter_readiness_never_promotes_route_coverage_or_exit(self):
        runner,report=self.run_fake();row=self.entry(report,'postgres')
        self.assertEqual(row['execution']['readiness'],'ready')
        self.assertEqual(row['execution']['actual_version'],'16.4')
        self.assertEqual(row['coverage']['tested_routes'],[])
        self.assertEqual(row['coverage']['status'],'not_checked')
        self.assertTrue(all(c['status']=='PASS' for c in report['parts'][0]['checks'].values()))
        self.assertEqual(report['measurement_status'],'PASS');self.assertEqual(report['status'],'INCOMPLETE')
        self.assertEqual(self.dispatch(report),3);runtime.validate_report(report)
        receipt=report['integration_receipts'][0]
        self.assertEqual(receipt['run_id'],report['run_id']);self.assertEqual(receipt['plan_id'],report['integrations']['plan_id'])
        self.assertTrue((runner.out/receipt['logs'][0]).is_file())
        self.assertIn('Gotowość usługi nie potwierdza', (runner.out/'runtime.md').read_text())

    def test_native_backend_is_not_mislabeled_as_container_execution(self):
        _,report=self.run_fake(engine='native')
        self.assertEqual(report['database_fidelity']['backend'],'native')
        self.assertEqual(self.entry(report,'postgres')['execution']['status'],'not_run')
        self.assertEqual(report['integration_receipts'],[])
        self.assertEqual(self.dispatch(report),3)

    def test_explicit_unimplemented_strategy_blocks_without_silent_adapter(self):
        cfg=self.base/'config.json';cfg.write_text(json.dumps({'runtime':{'integrations':{'postgres':{'strategy':'disabled'}}}}))
        helix_config.configure(self.project,cfg)
        runner,report=self.run_fake()
        self.assertEqual(runner.executor.calls,[]);self.assertEqual(report['status'],'BLOCKED')
        self.assertIn('no fallback',report['parts'][0]['startup']['reason'])
        self.assertEqual(report['integration_receipts'],[])
        self.assertEqual(self.entry(report,'postgres')['strategy']['selected'],'disabled')

    def test_explicit_container_strategy_never_falls_back_to_native(self):
        (self.project/'helix.json').write_text(json.dumps({'runtime':{'integrations':{'postgres':{'strategy':'container'}}}}))
        executor=FakeExecutor(fail=lambda argv:argv[0].endswith(('podman','docker')) and 'run' in argv)
        runner,report=self.run_fake(executor=executor)
        self.assertFalse(any('initdb' in argv[0] for argv,*_ in executor.calls))
        self.assertIsNone(report['engine']);self.assertEqual(self.dispatch(report),3)

    def test_implemented_adapters_keep_unexecuted_integrations_visible(self):
        route=self.project/'src/routes/+server.ts'
        route.parent.mkdir(parents=True,exist_ok=True)
        route.write_text("import Keycloak from 'keycloak-connect';\nimport Redis from 'ioredis';\nimport {Resend} from 'resend';\nexport function GET(){ return process.env.KEYCLOAK_ISSUER; }")
        spec=runtime.plan(self.project)
        for provider in ('keycloak','redis','resend'):
            row=self.entry(spec,provider)
            self.assertTrue(row['strategy']['implemented']);self.assertTrue(row['evidence'])
            self.assertEqual(row['coverage']['status'],'not_checked')
            self.assertTrue(row['affected_routes']);self.assertEqual(row['execution']['status'],'not_run')
        self.assertNotIn('oidc',{e['provider'] for e in spec['integrations']['integrations']})

    def test_monorepo_routes_and_receipts_remain_part_scoped(self):
        shutil.rmtree(self.project);self.project.mkdir()
        for name,dependency in (('a','pg'),('b','redis')):
            app=self.project/'apps'/name;app.mkdir(parents=True)
            (app/'package.json').write_text(json.dumps({'dependencies':{'express':'1',dependency:'1'},'scripts':{'start':'node server.js'}}))
            (app/'server.js').write_text("import client from '"+dependency+"';\napp.get('/"+name+"', ()=>client.query());")
        _,report=self.run_fake()
        postgres=self.entry(report,'postgres');redis=self.entry(report,'redis')
        self.assertEqual(postgres['parts'],['apps/a']);self.assertEqual(redis['parts'],['apps/b'])
        self.assertEqual(postgres['execution']['readiness'],'ready');self.assertEqual(redis['execution']['readiness'],'unknown')
        self.assertEqual([r['path'] for r in postgres['affected_routes']],['/a'])
        maturity=helix_pro.assess(self.project,'XL');runtime.import_evidence(maturity,self.out/'runtime-report.json',self.project)
        for part in maturity['parts']:
            if 'maturity' in part:
                self.assertTrue(all(part['path'] in gap['parts'] for gap in part['maturity']['runtime_integration_gaps']))

    def test_import_keeps_measurements_but_adds_global_coverage_blocker(self):
        _,report=self.run_fake();maturity=helix_pro.assess(self.project,'XL')
        runtime.import_evidence(maturity,self.out/'runtime-report.json',self.project)
        rows={i['id']:i for area in maturity['areas'].values() for i in area['requirements']}
        self.assertEqual(rows['cwv']['status'],'PASS');self.assertTrue(rows['cwv']['metrics'])
        self.assertEqual(maturity['runtime_coverage'],'INCOMPLETE')
        self.assertTrue(any(item.startswith('runtime-integrations:') for item in maturity['blocking']))
        self.assertEqual(maturity['runtime_integrations'],report['integrations'])

    def test_legacy_inventory_is_not_recorded_and_never_invented(self):
        _,report=self.run_fake()
        for key in ('integrations','integration_receipts','coverage_status','run_id','measurement_status',
                    'webauthn_plan','webauthn_receipts','webauthn_executions','webauthn_coverage','network_isolation','sink_plan','sink_observations'):report.pop(key,None)
        report['status']='PASS';runtime.validate_report(report)
        maturity=helix_pro.assess(self.project,'XL');runtime.import_evidence(maturity,self.save(report),self.project)
        self.assertEqual(maturity['runtime_coverage'],'NOT_RECORDED')
        self.assertEqual(maturity['runtime_network_isolation']['status'],'NOT_RECORDED')
        self.assertEqual(maturity['runtime_integrations']['integrations'],[])
        result=owner.aggregate(self.project,[self.out]);summary=result['groups'][0]['runtime_integrations'][0]
        self.assertEqual(summary['status'],'NOT_RECORDED');self.assertIsNone(summary['tested'])
        self.assertIn('Brak inwentarza',owner.markdown(result))

    def test_owner_retains_all_locations_routes_and_coverage_gaps(self):
        _,report=self.run_fake();result=owner.aggregate(self.project,[self.out])
        summary=result['groups'][0]['runtime_integrations'][0];row=summary['entries'][0]
        source=report['integrations']['integrations'][0]
        self.assertEqual(len(row['locations']),len(source['evidence']))
        self.assertEqual(len(row['affected_routes']),len(source['affected_routes']))
        self.assertEqual(row['untested_because'],source['coverage']['untested_because'])
        markdown=owner.markdown(result)
        self.assertIn('INCOMPLETE',markdown);self.assertIn('Gotowość usługi',markdown)
        self.assertTrue(any('Niepełne pokrycie integracji' in g['reason'] for g in result['gaps']))

    def test_owner_audit_import_has_pending_integration_with_source_lines(self):
        _,report=self.run_fake();maturity=helix_pro.assess(self.project,'XL')
        runtime.import_evidence(maturity,self.out/'runtime-report.json',self.project)
        audit=dict(maturity=maturity,quality={'domains':{'checks':[]},'findings':[]},source_coverage={},scope={'profile':'XL'})
        with patch('helix_lenses.report',return_value={'findings':[],'lenses':{}}):
            owner.audit_report(self.project,self.out,audit,{})
        result=json.loads((self.out/'owner-current.json').read_text())
        gap=next(g for g in result['gaps'] if g['id'].startswith('runtime-integration:'))
        self.assertTrue(gap['evidence']);self.assertTrue(all(':' in place for place in gap['evidence']))
        self.assertEqual(result['runtime_integrations']['status'],'INCOMPLETE')
        self.assertIn('Gotowość usługi',(self.out/'owner-current.md').read_text())

    def completed_route_report(self,route_status='PASS'):
        _,report=self.run_fake()
        from helix_runtime_identity import identity_plan
        from helix_runtime_identity_policy import policy_plan
        from helix_runtime_transport import transport_plan
        from helix_runtime_webauthn import webauthn_plan
        from helix_runtime_sinks import sink_plan
        sources={'server.js':"import pg from 'pg';\napp.get('/rows',()=>pg.query('SELECT 1'));"}
        parts=[{'path':'.'}];plan=integrations.inventory(sources,parts)
        # This fixture replaces the discovery snapshot. Its dependent plans
        # must bind the same synthetic snapshot, rather than the original app.
        identities=identity_plan(sources,parts)
        policies=policy_plan(sources,parts,identities,plan)
        transport=transport_plan(sources,parts,plan)
        report.update(identity_plan=identities,identity_policy_plan=policies,transport_plan=transport,
                      webauthn_plan=webauthn_plan(sources,parts,plan,identities,transport,policies),sink_plan=sink_plan(plan,parts))
        row=plan['integrations'][0]
        (self.out/'logs/route-proof.json').write_text('{"synthetic_trace":"query was observed"}')
        receipt=dict(integration_id=row['id'],plan_id=plan['plan_id'],run_id=report['run_id'],strategy='container',
                     status='completed',readiness='ready',actual_version='16.4',logs=['database-fidelity.json'],
                     tested_routes=[dict(route='/rows',method='GET',status=route_status,integration_exercised=True,evidence='logs/route-proof.json')])
        report.update(integrations=integrations.execution_inventory(plan,[receipt],run_id=report['run_id']),
                      integration_receipts=[receipt],coverage_status='RECORDED',status='INCOMPLETE')
        return report

    def test_bound_explicit_route_receipt_is_required_and_artifact_checked(self):
        report=self.completed_route_report()
        runtime.validate_report(report);self.assertEqual(self.dispatch(report),3)
        self.assertEqual(report['measurement_status'],'PASS')
        self.assertEqual(report['network_isolation']['status'],'SIMULATED')
        maturity=helix_pro.assess(self.project,'XL');runtime.import_evidence(maturity,self.save(report),self.project)
        self.assertEqual(maturity['runtime_coverage'],'RECORDED')
        (self.out/'logs/route-proof.json').unlink()
        with self.assertRaises(ValueError):runtime.import_evidence(maturity,self.save(report),self.project)

    def test_failed_route_is_executed_coverage_but_blocks_success_everywhere(self):
        report=self.completed_route_report('FAIL')
        # Deliberately forge the complete-success claim under test. The
        # synthetic isolation result itself remains unchanged.
        report['status']='PASS'
        with self.assertRaises(ValueError):runtime.validate_report(report)
        self.assertEqual(self.dispatch(report),2)
        report['status']='FAIL';runtime.validate_report(report)
        maturity=helix_pro.assess(self.project,'XL');runtime.import_evidence(maturity,self.save(report),self.project)
        self.assertEqual(maturity['runtime_coverage'],'RECORDED')
        self.assertEqual(maturity['runtime_integration_failures'][0]['route'],'/rows')
        self.assertTrue(any(item.startswith('runtime-integration-failed:') for item in maturity['blocking']))
        owner_report=owner.aggregate(self.project,[self.out]);summary=owner_report['groups'][0]['runtime_integrations'][0]
        self.assertEqual(summary['failed_routes'],1);self.assertIn('FAIL postgres: GET /rows',owner.markdown(owner_report))
        audit=dict(maturity=maturity,quality={'domains':{'checks':[]},'findings':[]},source_coverage={},scope={'profile':'XL'})
        with patch('helix_lenses.report',return_value={'findings':[],'lenses':{}}):owner.audit_report(self.project,self.out,audit,{})
        pending=json.loads((self.out/'owner-current.json').read_text())['gaps']
        self.assertTrue(any('FAIL GET /rows' in item['why'] for item in pending))

    def test_raw_receipt_unknown_route_and_missing_exercise_flag_cannot_import(self):
        _,report=self.run_fake()
        for test in (dict(route='/not-observed',method='GET',status='PASS',integration_exercised=True,evidence='logs/route.json'),
                     dict(route='/',method='GET',status='PASS',evidence='logs/route.json')):
            with self.subTest(receipt=test):
                bad=copy.deepcopy(report);bad['integration_receipts'][0]['tested_routes']=[test]
                with self.assertRaises(ValueError):runtime.validate_report(bad)

    def test_schema_rejects_malformed_receipts_paths_and_recomputed_coverage(self):
        _,report=self.run_fake()
        def receipt(r):return r['integration_receipts'][0]
        mutations=[lambda r:receipt(r).update(logs=['../escape']),lambda r:receipt(r).update(logs=['/absolute']),
                   lambda r:receipt(r).update(logs=['logs\\escape']),lambda r:receipt(r).update(logs=[]),
                   lambda r:receipt(r).update(secret='DO_NOT_PUBLISH'),lambda r:receipt(r).update(run_id='old-run'),
                   lambda r:receipt(r).update(plan_id='0'*64),lambda r:r['integrations']['integrations'][0]['coverage'].update(status='tested'),
                   lambda r:r.update(status='PASS'),lambda r:r.update(coverage_status='RECORDED'),
                   lambda r:r['integrations']['integrations'][0]['evidence'][0].update(line=True)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                bad=copy.deepcopy(report);mutate(bad)
                with self.assertRaises(ValueError):runtime.validate_report(bad)

    def test_import_rejects_receipt_artifact_symlink_missing_and_empty(self):
        _,report=self.run_fake();relative=report['integration_receipts'][0]['logs'][0];artifact=self.out/relative
        original=artifact.read_bytes();outside=self.base/'outside';outside.write_text('not this run')
        for variant in ('missing','empty','symlink'):
            with self.subTest(variant=variant):
                if artifact.exists() or artifact.is_symlink():artifact.unlink()
                if variant=='empty':artifact.write_text('')
                elif variant=='symlink':artifact.symlink_to(outside)
                with self.assertRaises(ValueError):runtime.import_evidence(helix_pro.assess(self.project,'XL'),self.out/'runtime-report.json',self.project)
        artifact.unlink();artifact.write_bytes(original)

    def test_no_detected_active_integrations_does_not_invent_a_blocker(self):
        shutil.rmtree(self.project);self.project.mkdir()
        (self.project/'package.json').write_text(json.dumps({'scripts':{'start':'node server.js'}}))
        (self.project/'server.js').write_text('console.log("synthetic");')
        _,report=self.run_fake()
        self.assertEqual(report['integrations']['integrations'],[])
        self.assertEqual(report['coverage_status'],'RECORDED');self.assertEqual(self.dispatch(report),3)
        self.assertEqual(report['measurement_status'],'PASS')
        self.assertEqual(report['network_isolation']['status'],'SIMULATED')
        self.assertIn('brak wykrycia',str(report['integrations']['discovery']['limitations']))


if __name__=='__main__':unittest.main()
