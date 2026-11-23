"""Shared safe transport reporting, independent of measurement status."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(os.environ.get('HELIX_SOURCE_ROOT', ROOT)) / 'bin'))
sys.path.insert(0, str(ROOT / 'bin'))
import helix_runtime_transport as transport


class RuntimeTransportProjection(unittest.TestCase):
    def report(self, needed=False):
        sources = {'app/server.js': 'cookies.set("sid", value, {secure:true});' if needed else 'const ready=true;'}
        plan = transport.transport_plan(sources, [{'path':'app'}], {'integrations':[]}, {})
        declaration = plan['parts'][0]
        part = dict(path='app', name='display name', transport=dict(selected='http', status='not_checked',
                    cleanup='not_needed', gaps=declaration['gaps'], limits=declaration['limits']))
        return dict(parts=[part], transport_plan=plan, transport_coverage=transport.derive_transport_coverage(plan,[part]))

    def test_legacy_absent_is_not_recorded(self):
        result = transport.project_transport({'parts':[]})
        self.assertEqual(result['status'],'NOT_RECORDED');self.assertEqual(result['parts'],[])

    def test_gap_survives_without_claiming_session_or_replacing_measurement(self):
        report = self.report(needed=True);report['parts'][0]['checks']={'a11y':{'status':'PASS'}}
        before = copy.deepcopy(report);result = transport.project_transport(report)
        self.assertEqual(result['status'],'INCOMPLETE')
        self.assertEqual(result['parts'][0]['part'],'app')
        self.assertIn({'kind':'https_not_enabled'},result['parts'][0]['gaps'])
        self.assertEqual(result['parts'][0]['requirements'],[{'kind':'secure_cookie','path':'app/server.js','line':1}])
        self.assertEqual(report,before);self.assertNotIn('checks',result)
        self.assertNotIn('session',result)

    def test_unknown_private_fields_and_freeform_reason_are_not_projected(self):
        report = self.report(needed=True)
        marker='PRIVATE_PASSWORD_TOKEN_SHOULD_NOT_APPEAR'
        report['parts'][0]['transport'].update(password=marker,reason=marker,public_origin='https://'+marker)
        report['transport_plan']['parts'][0]['gaps'][0].update(reason=marker,headers={'Authorization':marker})
        report['material']={'password':marker}
        result=transport.project_transport(report)
        self.assertNotIn(marker,json.dumps(result));self.assertNotIn('public_origin',result['parts'][0])

    def test_forged_status_and_missing_fields_are_rejected(self):
        report=self.report(needed=True);report['transport_coverage']='RECORDED'
        with self.assertRaisesRegex(ValueError,'coverage'):transport.project_transport(report)
        for field in ('transport_plan','transport_coverage'):
            report=self.report();report.pop(field)
            with self.subTest(field=field),self.assertRaises(ValueError):transport.project_transport(report)

    def test_selected_part_projection_and_empty_execution_are_explicit(self):
        report=self.report()
        self.assertEqual(transport.project_transport(report,['app'])['parts'][0]['part'],'app')
        self.assertEqual(transport.project_transport(report,[])['status'],'INCOMPLETE')
        with self.assertRaises(ValueError):transport.project_transport(report,['display name'])
        with self.assertRaises(ValueError):transport.project_transport(report,['app','app'])


if __name__=='__main__':unittest.main()
