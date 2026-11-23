"""WebAuthn planning wiring only: synthetic sources, no browser or service."""
import builtins
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import helix_config
import helix_pro
import helix_project_proposal as proposal
import helix_runtime as runtime
# Loaded before the no-IO block: inventory() imports it lazily, and the first import of
# zoneinfo reads an OS file on macOS framework Pythons (sysconfig), which is not inventory IO.
import helix_runtime_adapters  # noqa: F401
import helix_runtime_integrations as integrations
import helix_runtime_transport as transport
import helix_runtime_webauthn as webauthn
import test_runtime_keycloak_pipeline as fixtures


class RuntimeWebAuthnPlanning(unittest.TestCase):
    def make_fixture(self):
        fixture=fixtures.RuntimeKeycloakPipeline();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.app(configured=False,identity_source=False,names=[]);fixture.configure()
        return fixture

    def test_runtime_plan_reuses_exact_source_and_dependency_plans(self):
        fixture=self.make_fixture()
        manifest=fixture.project/'frontend/package.json';value=json.loads(manifest.read_text())
        value['dependencies']={'@simplewebauthn/browser':'13.3.0'};manifest.write_text(json.dumps(value))
        before=fixture.snapshot()
        with patch.object(webauthn,'webauthn_plan',wraps=webauthn.webauthn_plan) as compile_plan, \
             patch.object(integrations,'inventory',wraps=integrations.inventory) as inventory, \
             patch.object(transport,'transport_plan',wraps=transport.transport_plan) as transport_plan, \
             patch.object(runtime,'Executor',side_effect=AssertionError('executor')), \
             patch.object(subprocess,'run',side_effect=AssertionError('process')), \
             patch.object(socket,'socket',side_effect=AssertionError('network')):
            planned=runtime.plan(fixture.project)
        compile_plan.assert_called_once();inventory.assert_called_once();transport_plan.assert_called_once()
        args=compile_plan.call_args.args
        self.assertIs(args[0],inventory.call_args.args[0]);self.assertIs(args[1],planned['parts'])
        for index,key in [(2,'integrations'),(3,'identity_plan'),(4,'transport_plan'),(5,'identity_policy_plan')]:
            self.assertIs(args[index],planned[key])
        self.assertEqual(planned['webauthn_receipts'],[])
        self.assertEqual(planned['webauthn_plan']['status'],'BLOCKED')
        self.assertEqual(before,fixture.snapshot())

    def test_disabled_known_scope_keeps_measurements_and_requires_incomplete_exit(self):
        for disabled in (False,True):
            with self.subTest(disabled=disabled):
                fixture=self.make_fixture();config=fixture.configure()
                if disabled:
                    config['runtime']['webauthn']={'schema_version':1,'parts':{'frontend':{'enabled':False}}}
                    fixture.config_path.write_text(json.dumps(config));helix_config.configure(fixture.project,fixture.config_path)
                report=fixture.run_pipeline(allow_plain_oidc=True)
                self.assertEqual(report['measurement_status'],'PASS')
                self.assertEqual(report['status'],'INCOMPLETE')
                self.assertEqual(report['network_isolation']['status'],'SIMULATED')
                self.assertEqual(report['webauthn_coverage'],'INCOMPLETE' if disabled else 'NOT_DETECTED')
                self.assertEqual(report['webauthn_receipts'],[])
                projected=webauthn.project_webauthn_plan(report)
                self.assertEqual(projected['counts']['ceremonies_executed'],0)
                args=SimpleNamespace(runtime_action='run',project=fixture.project,out=fixture.out,engine='auto',budget_min=1,
                    part=None,skip='',keep=False,no_oidc_stub=True,allow_version_mismatch=False)
                with patch.object(runtime,'Runner') as constructor,contextlib.redirect_stdout(io.StringIO()):
                    constructor.return_value.run.return_value=report
                    self.assertEqual(runtime.dispatch(args),3)
                if disabled:
                    forged=copy.deepcopy(report);forged['status']='PASS'
                    with self.assertRaisesRegex(ValueError,'unexecuted WebAuthn'):runtime.validate_report(forged)
                    self.assertFalse(helix_config.load(fixture.project)['runtime']['webauthn']['parts']['frontend']['enabled'])

    def test_import_retains_unexecuted_webauthn_gap_without_ceremony_points(self):
        fixture=self.make_fixture();config=fixture.configure()
        config['runtime']['webauthn']={'schema_version':1,'parts':{'frontend':{'enabled':False}}}
        fixture.config_path.write_text(json.dumps(config));helix_config.configure(fixture.project,fixture.config_path)
        report=fixture.run_pipeline(allow_plain_oidc=True)
        maturity=helix_pro.assess(fixture.project,'XL')
        runtime.import_evidence(maturity,fixture.out/'runtime-report.json',fixture.project)
        view=maturity['runtime_webauthn']
        self.assertEqual(view,webauthn.project_webauthn_plan(report,['frontend']))
        self.assertEqual(view['execution_status'],'NOT_RUN');self.assertEqual(view['counts']['registration_pass'],0)
        self.assertTrue(any(row.startswith('runtime-webauthn: INCOMPLETE') for row in maturity['blocking']))


class WebAuthnProposalSnapshot(unittest.TestCase):
    def sources(self):
        return {'frontend/package.json':json.dumps({'dependencies':{'@simplewebauthn/browser':'13.3.0'}}),
                'frontend/app.js':'export const value=1;'}

    def propose(self,explicit=None):
        sources=self.sources();explicit={} if explicit is None else explicit;config=copy.deepcopy(explicit)
        context=proposal._source_context(sources,None,None,explicit)
        tls=proposal.propose_transport(sources,None,None,explicit,config,{'status':'COMPLETE'},_context=context)
        result=proposal.propose_webauthn(sources,context,tls,explicit,config,{'status':'COMPLETE'})
        return result,config

    def test_shared_inventory_is_compiled_once_without_io_and_no_invented_flow(self):
        with patch.object(integrations,'inventory',wraps=integrations.inventory) as inventory, \
             patch.object(runtime,'plan',side_effect=AssertionError('runtime plan called')), \
             patch.object(builtins,'open',side_effect=AssertionError('file opened')), \
             patch.object(subprocess,'run',side_effect=AssertionError('process')), \
             patch.object(socket,'socket',side_effect=AssertionError('network')):
            result,config=self.propose()
        inventory.assert_called_once()
        self.assertEqual(result['status'],'INCOMPLETE');self.assertEqual(result['projection']['execution_status'],'NOT_RUN')
        self.assertNotIn('webauthn',config.get('runtime',{}));self.assertFalse(result['proposal_applied'])
        self.assertTrue(config['runtime']['https']['enabled'])
        self.assertTrue(all(part['registration'] is None for part in result['proposed']['parts']))
        self.assertIn('frontend/package.json:1','\n'.join(proposal.webauthn_markdown(result)))

    def test_explicit_false_and_partial_true_survive_without_guessed_paths(self):
        for enabled in (False,True):
            explicit={'runtime':{'webauthn':{'schema_version':1,'parts':{'frontend':{'enabled':enabled}}}}}
            original=copy.deepcopy(explicit)
            result,config=self.propose(explicit)
            self.assertEqual(explicit,original);self.assertEqual(config['runtime']['webauthn'],explicit['runtime']['webauthn'])
            self.assertEqual(result['status'],'INCOMPLETE')
            self.assertEqual(result['projection']['counts']['ceremonies_executed'],0)
            self.assertIsNone(result['proposed']['parts'][0]['registration'])

    def test_missing_snapshot_is_unknown_without_scan(self):
        with patch.object(integrations,'inventory',side_effect=AssertionError('inventory')), \
             patch.object(runtime,'plan',side_effect=AssertionError('runtime')):
            result=proposal.propose_webauthn(None,None,{}, {}, {})
        self.assertEqual(result['status'],'NOT_RECORDED');self.assertIsNone(result['projection'])

    def test_unresolved_identity_scope_is_a_gap_without_hiding_explicit_contract_errors(self):
        sources={'backend/main.py':'print("synthetic application")'}
        explicit={'runtime':{'keycloak':{'parts':{'backend':{'client_id':'synthetic-client'}}}}}
        before=copy.deepcopy(explicit);config=copy.deepcopy(explicit)
        context=proposal._source_context(sources,None,None,explicit)
        tls=proposal.propose_transport(sources,None,None,explicit,config,{'status':'COMPLETE'},_context=context)
        result=proposal.propose_webauthn(sources,context,tls,explicit,config,{'status':'COMPLETE'})
        self.assertEqual(result['status'],'INCOMPLETE')
        self.assertEqual((result['stage'],result['reason_code']),('identity_scope','SOURCE_SCOPE_UNRESOLVED'))
        for key in ('observed','proposed','projection'):self.assertIsNone(result[key])
        self.assertNotIn('synthetic-client',json.dumps(result));self.assertEqual(explicit,before)
        # Explicit WebAuthn must not be hidden by an unresolved dependency, and
        # confirmed source scopes retain the normal fail-closed contract.
        configured=copy.deepcopy(explicit);configured['runtime']['webauthn']={'schema_version':True}
        with self.assertRaises(ValueError):
            proposal.propose_webauthn(sources,context,tls,configured,configured,{'status':'COMPLETE'})
        known=copy.deepcopy(context);known['parts_basis']='provided_source_scopes'
        with self.assertRaisesRegex(ValueError,'nieznaną część'):
            proposal.propose_webauthn(sources,known,tls,explicit,config,{'status':'COMPLETE'})


if __name__=='__main__':unittest.main()
