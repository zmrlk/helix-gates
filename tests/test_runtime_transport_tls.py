"""Actual HTTPS health handler behavior with injected stdlib transport, no socket."""
import json
import copy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime as runtime


class RuntimeTransportTLS(unittest.TestCase):
    def response(self,url):
        response=Mock(status=200)
        response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.geturl.return_value=url
        return response

    def test_exact_ca_and_redirect_admission_happen_before_any_new_request(self):
        origin='https://localhost:44100';response=self.response(origin+'/ready')
        opener=Mock();opener.open.return_value=response;context=object()
        with patch.object(runtime.ssl,'create_default_context',return_value=context) as tls, \
             patch.object(runtime.urllib.request,'build_opener',return_value=opener) as build:
            executor=runtime.Executor();self.assertEqual(executor.health(origin+'/ready',.1,ca_file='/private/own-ca.pem'),origin+'/ready')
        tls.assert_called_once_with(cafile='/private/own-ca.pem')
        handlers=build.call_args.args
        self.assertEqual(handlers[0].proxies,{})
        self.assertIs(handlers[2]._context,context)
        redirects=handlers[1];request=urllib.request.Request(origin+'/ready')
        for target in ('https://remote.invalid/SECRET','http://localhost:44100/','http://127.0.0.1:44099/',
                       'https://localhost:44101/','https://operator:SECRET@localhost:44100/'):
            with self.subTest(target=target):
                self.assertIsNone(redirects.redirect_request(request,None,302,'',{},target))
        accepted=redirects.redirect_request(request,None,302,'',{},origin+'/next')
        self.assertEqual(accepted.full_url,origin+'/next')
        opener.open.assert_called_once()

    def test_rejected_external_redirect_is_an_http_response_not_a_followup(self):
        origin='https://localhost:44100'
        error=urllib.error.HTTPError(origin+'/',302,'redirect',{'Location':'https://remote.invalid/SECRET'},None)
        opener=Mock();opener.open.side_effect=error
        with patch.object(runtime.ssl,'create_default_context',return_value=object()), \
             patch.object(runtime.urllib.request,'build_opener',return_value=opener):
            executor=runtime.Executor();result=executor.health(origin+'/',.1,ca_file='/private/ca.pem')
        self.assertEqual(result,origin+'/');self.assertEqual(executor.last_health['status'],302)
        opener.open.assert_called_once()
        self.assertNotIn('SECRET',json.dumps(executor.last_health))

    def test_proxy_generated_failure_never_credits_application_readiness(self):
        origin='https://localhost:44100';clock=[0.]
        error=urllib.error.HTTPError(origin+'/',502,'proxy unavailable',{'X-Helix-Runtime-Proxy-Error':'1'},None)
        opener=Mock();opener.open.side_effect=error
        def sleep(delay):clock[0]+=delay
        with patch.object(runtime.ssl,'create_default_context',return_value=object()), \
             patch.object(runtime.urllib.request,'build_opener',return_value=opener), \
             patch.object(runtime.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(runtime.time,'sleep',side_effect=sleep):
            executor=runtime.Executor()
            with self.assertRaisesRegex(runtime.Blocked,'proxy-unavailable'):
                executor.health(origin+'/',.1,ca_file='/private/ca.pem')
        self.assertEqual(executor.last_health['state'],'proxy-unavailable')
        self.assertEqual(opener.open.call_count,1)

    def test_actual_backend_500_remains_observed_application_response(self):
        origin='https://localhost:44100';opener=Mock()
        opener.open.side_effect=urllib.error.HTTPError(origin+'/',500,'app error',{},None)
        with patch.object(runtime.ssl,'create_default_context',return_value=object()), \
             patch.object(runtime.urllib.request,'build_opener',return_value=opener):
            executor=runtime.Executor();self.assertEqual(executor.health(origin+'/',.1,ca_file='/private/ca.pem'),origin+'/')
        self.assertEqual(executor.last_health['state'],'http');self.assertEqual(executor.last_health['status'],500)

    def test_budget_rejects_overflow_before_proxy_deadline_conversion(self):
        for value in (float('inf'),float('nan'),-1,0):
            with self.subTest(value=value),self.assertRaises(ValueError):runtime.Budget(value)
        with self.assertRaises(ValueError):runtime.Budget(1e308,clock=lambda:1e308)

    def test_forged_transport_pass_cannot_hide_plan_gaps_or_missing_metadata(self):
        import test_runtime_transport_pipeline as fixture
        case=fixture.RuntimeTransportPipeline();case.setUp()
        try:
            case.application();case.configure(enabled=False);report=case.run_pipeline()
            forged=copy.deepcopy(report);forged.update(status='PASS',transport_coverage='RECORDED')
            with self.assertRaisesRegex(ValueError,'transport coverage'):runtime.validate_report(forged)
            for field in ('transport_plan','transport_coverage'):
                broken=copy.deepcopy(report);broken.pop(field)
                with self.subTest(missing=field),self.assertRaises(ValueError):runtime.validate_report(broken)
            malformed=copy.deepcopy(report);malformed['transport_plan']['parts'][0]['gaps']={}
            with self.assertRaises(ValueError):runtime.validate_report(malformed)
        finally:case.doCleanups()

    def test_https_ready_requires_bound_origin_and_probe_receipt(self):
        import test_runtime_transport_pipeline as fixture
        case=fixture.RuntimeTransportPipeline();case.setUp()
        try:
            case.application();case.configure(enabled=True);report=case.run_pipeline()
            runtime.validate_report(report)
            for mutation in (lambda r:r['parts'][0]['transport'].pop('tls_health'),
                             lambda r:r['parts'][0]['transport'].update(public_origin='https://localhost:49999'),
                             lambda r:r['parts'][0]['transport'].update(cleanup='unknown')):
                broken=copy.deepcopy(report);mutation(broken)
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):runtime.validate_report(broken)
        finally:case.doCleanups()

    def test_empty_execution_never_establishes_transport_coverage(self):
        from helix_runtime_transport import derive_transport_coverage, transport_plan
        plan=transport_plan({'src/server.js':'export const ready=true;'},[{'path':'.'}],{'integrations':[]},{})
        self.assertTrue(plan['parts']);self.assertEqual(plan['gaps'],[])
        self.assertEqual(derive_transport_coverage(plan,[]),'INCOMPLETE')

    def test_http_legacy_has_no_hidden_tls_probe(self):
        opener=Mock();opener.open.return_value=self.response('http://127.0.0.1:44100/')
        with patch.object(runtime.ssl,'create_default_context',side_effect=AssertionError('unexpected TLS')), \
             patch.object(runtime.urllib.request,'build_opener',return_value=opener) as build:
            self.assertEqual(runtime.Executor().health('http://127.0.0.1:44100/',.1),'http://127.0.0.1:44100/')
        self.assertEqual(len(build.call_args.args),2)


if __name__=='__main__':unittest.main()
