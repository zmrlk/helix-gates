"""Accounting contracts exercised without model calls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_usage as U
import helix_owner_report as O


class ModelUsage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.ctx = SimpleNamespace(repo=self.root)

    def invoke(self, caller):
        with patch('helix_environment.provenance', return_value={'target_head': 'a' * 40}):
            return U.measured('fixture')(caller)(self.ctx, 'fake', 'PRIVATE_PROMPT', None, None, False, self.root, 5)

    def receipts(self):
        return [json.loads(p.read_text()) for p in self.root.glob('model-call-*.json')]

    def test_unknown_is_null_not_zero_and_response_is_compatible(self):
        response = self.invoke(lambda *args: '{"verdict":"approve","usage":{"total_tokens":999}}')
        self.assertEqual(json.loads(response)['verdict'], 'approve')
        row = self.receipts()[0]
        self.assertIsNone(row['usage']['total_tokens'])  # model-written data is not billing
        self.assertIsNone(row['usage']['cost_usd'])
        self.assertGreaterEqual(row['elapsed_seconds'], 0)
        self.assertNotIn('PRIVATE_PROMPT', json.dumps(row))
        self.assertNotIn('verdict', json.dumps(row))
        self.assertIn('nieznane', U.describe(row))

    def test_outer_telemetry_preserves_real_zero_and_partial_unknown(self):
        self.invoke(lambda *args: U.Response('{}', {'usage': {'input_tokens': 12, 'output_tokens': 0}, 'total_cost_usd': 0}))
        row = self.receipts()[0]
        self.assertEqual(row['usage']['input_tokens'], 12)
        self.assertEqual(row['usage']['output_tokens'], 0)
        self.assertEqual(row['usage']['cost_usd'], 0)
        self.assertIsNone(row['usage']['total_tokens'])

    def test_invalid_numbers_are_unknown(self):
        for value in (-1, True, '100', float('nan'), float('inf')):
            self.assertIsNone(U.usage({'usage': {'input_tokens': value, 'cost_usd': value}})['input_tokens'])
            self.assertIsNone(U.usage({'usage': {'cost_usd': value}})['cost_usd'])

    def test_failed_and_retried_calls_have_distinct_receipts(self):
        def fail(*args):
            raise subprocess.TimeoutExpired('private-command', 5)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.invoke(fail)
        self.invoke(lambda *args: '{}')
        rows = self.receipts()
        self.assertEqual({r['status'] for r in rows}, {'error', 'complete'})
        self.assertEqual(len({r['call_id'] for r in rows}), 2)
        self.assertNotIn('private-command', json.dumps(rows))

    def test_not_admitted_is_not_a_measured_model_call(self):
        def reject(*args):
            error = ValueError('denied')
            error.admission_code = 'OFFLINE'
            raise error
        with self.assertRaises(ValueError):
            self.invoke(reject)
        self.assertEqual(self.receipts(), [])

    def test_owner_projects_per_call_time_tokens_and_unknown_cost(self):
        self.invoke(lambda *args: U.Response('{}', {'usage': {'input_tokens': 15}}))
        with patch('subprocess.run', side_effect=AssertionError('no command in aggregation')):
            report = O.aggregate(self.root, [self.root])
        calls = [c for group in report['groups'] for c in group['cost'] if c.get('call_id')]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['usage']['input_tokens'], 15)
        self.assertIsNone(calls[0]['measured'])
        text = O.markdown(report)
        self.assertIn('15/nieznane/nieznane', text)
        self.assertIn('koszt USD: nieznane', text)

    def test_agy_receipt_uses_provider_from_admitted_probe(self):
        def call_agy(*args):
            return '{}'
        with patch('helix_model_admission.probe_provider', return_value='claude-via-agy'):
            self.invoke(call_agy)
        self.assertEqual(self.receipts()[0]['provider'], 'claude-via-agy')
