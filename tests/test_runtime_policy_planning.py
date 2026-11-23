"""Unexecuted policy scope cannot reuse successful unrelated measurements."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_config
import helix_runtime as runtime
import test_runtime_keycloak_pipeline as runner_fixture
import test_runtime_identity_policy as policy_fixture


class RuntimePolicyPlanning(unittest.TestCase):
    def test_explicit_unexecuted_scope_keeps_measurements_but_requires_incomplete_exit(self):
        for configured in (False,True):
            with self.subTest(configured=configured):
                fixture=runner_fixture.RuntimeKeycloakPipeline();fixture.setUp()
                try:
                    fixture.app(configured=False,identity_source=False,names=[])
                    config=fixture.configure()
                    if configured:
                        policy=policy_fixture.RuntimeIdentityPolicy();policy.setUp()
                        config['runtime']['identity_policy']=policy.config['runtime']['identity_policy']
                        fixture.config_path.write_text(json.dumps(config));helix_config.configure(fixture.project,fixture.config_path)
                    report=fixture.run_pipeline(allow_plain_oidc=True)
                    self.assertEqual(report['identity_coverage'],'NOT_DETECTED')
                    self.assertEqual(report['measurement_status'],'PASS')
                    self.assertEqual(report['status'],'INCOMPLETE')
                    self.assertEqual(report['network_isolation']['status'],'SIMULATED')
                    self.assertEqual(report['identity_policy_receipts'],[])
                    args=SimpleNamespace(runtime_action='run',project=fixture.project,out=fixture.out,engine='auto',budget_min=1,
                        part=None,skip='',keep=False,no_oidc_stub=True,allow_version_mismatch=False)
                    with patch.object(runtime,'Runner') as constructor,contextlib.redirect_stdout(io.StringIO()):
                        constructor.return_value.run.return_value=report
                        self.assertEqual(runtime.dispatch(args),3)
                    if configured:
                        forged=copy.deepcopy(report);forged['status']='PASS'
                        with self.assertRaisesRegex(ValueError,'unexecuted identity policy'):runtime.validate_report(forged)
                finally:fixture.doCleanups()


if __name__=='__main__':unittest.main()
