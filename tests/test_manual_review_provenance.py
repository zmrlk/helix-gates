"""A declared manual model must not become a claimed CLI execution on import."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_environment as environment
import helix_owner_report as owner


class ManualProvenance(unittest.TestCase):
    def receipt(self):
        return dict(provider='grok', model='grok-synthetic', method='manual_handoff',
                    request_id='a' * 64, reviewer='reviewer-A', round=1, role='reviewer', family='xai',
                    prompt='PRIVATE PROMPT', private_context='PRIVATE DATA')

    def test_manual_declaration_remains_distinct_and_idempotent(self):
        rows = environment.normalize_models([self.receipt()])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'declared')
        self.assertEqual(rows[0]['method'], 'manual_handoff')
        self.assertFalse(rows[0]['call_invoked'])
        self.assertEqual(rows[0]['evidence_kind'], 'manual_receipt')
        self.assertEqual(rows[0]['request_id'], 'a' * 64)
        self.assertEqual(environment.normalize_models(rows), rows)
        self.assertNotIn('PRIVATE', json.dumps(rows))

    def test_owner_projection_never_upgrades_manual_receipt_to_cli_execution(self):
        source = dict(models=[self.receipt()], target_head='b' * 40)
        data = owner.projected_provenance(source)
        model = data['models'][0]
        self.assertEqual(model['status'], 'declared')
        self.assertFalse(model['call_invoked'])
        self.assertEqual(owner.projected_provenance(data), data)
        self.assertNotIn('PRIVATE', json.dumps(data))

    def test_cli_receipt_keeps_existing_execution_semantics(self):
        rows = environment.normalize_models([dict(provider='grok-cli', model='grok-synthetic', status='completed')])
        self.assertEqual(rows[0]['status'], 'recorded')
        self.assertNotIn('manual_receipt', json.dumps(rows))
