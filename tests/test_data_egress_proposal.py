"""A project proposal never turns an old path list into provider consent; without a declaration all providers apply."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_project_proposal import egress_declaration


class DataEgressProposal(unittest.TestCase):
    def test_missing_policy_means_all_providers_without_a_question_or_processes(self):
        # Decyzja właściciela 15.11.2026: bez deklaracji Helix wysyła do wszystkich dostawców; propozycja niczego nie dopisuje.
        from helix_model_admission import effective_policy
        from helix_data_egress import policy_sha256
        config = {}
        with patch.object(subprocess, 'run', side_effect=AssertionError('proposal is not a model call')):
            result, pending = egress_declaration(config)
        self.assertEqual(config, {})
        self.assertEqual(result['status'], 'DEFAULT_ALL_PROVIDERS')
        self.assertIn('codex', result['allowed_providers']); self.assertIn('gemini', result['allowed_providers'])
        self.assertEqual(result['delivery'], 'NOT_SENT')
        self.assertEqual(result['policy_sha256'], policy_sha256(effective_policy(None)))
        self.assertEqual(pending, [])

    def test_legacy_path_allowlist_stays_unchanged_and_never_approves_a_provider(self):
        config = {'data_egress': {'allowlist': ['frontend/src'], 'approved_by': 'synthetic owner'}}
        before = copy.deepcopy(config)
        result, pending = egress_declaration(config)
        self.assertEqual(config, before)
        self.assertEqual(result['allowed_providers'], [])
        self.assertEqual(result['status'], 'PENDING_OWNER')
        self.assertEqual(len(pending), 1)

    def test_explicit_approved_declaration_is_preserved_without_claiming_delivery(self):
        config = {'data_egress': {'status': 'approved', 'allowed_providers': ['codex', 'grok-cli'],
                                  'exclude_paths': ['private-reports/**'], 'approved_by': 'owner@example.invalid'}}
        before = copy.deepcopy(config)
        result, pending = egress_declaration(config)
        self.assertEqual(config, before)
        self.assertEqual(result['status'], 'APPROVED_DECLARATION')
        self.assertEqual(set(result['allowed_providers']), {'codex', 'grok-cli'})
        self.assertEqual(result['delivery'], 'NOT_SENT')
        self.assertRegex(result['policy_sha256'], r'^[0-9a-f]{64}$')
        self.assertNotIn('owner@example.invalid', json.dumps(result))
        self.assertEqual(pending, [])

    def test_pending_or_invalid_policy_does_not_silently_become_approved(self):
        config = {'data_egress': {'status': 'pending_owner', 'allowed_providers': ['codex']}}
        result, pending = egress_declaration(config)
        self.assertEqual((result['status'], pending), ('DEFAULT_ALL_PROVIDERS', []))
        for value in ({'status': 'approved', 'allowed_providers': ['*']},
                      {'status': 'approved', 'allowed_providers': ['openai']},
                      {'status': 'approved', 'allowed_providers': ['codex'], 'api_key': 'PRIVATE_POLICY_CANARY'}):
            with self.subTest(policy=list(value)):
                config = {'data_egress': value}
                before = copy.deepcopy(config)
                result, pending = egress_declaration(config)
                self.assertEqual(config, before)
                self.assertEqual(result['status'], 'PENDING_OWNER')
                self.assertEqual(result['allowed_providers'], [])
                self.assertEqual(result['delivery'], 'NOT_SENT')
                self.assertEqual(len(pending), 1)
                self.assertNotIn('PRIVATE_POLICY_CANARY', json.dumps([result, pending]))


if __name__ == '__main__':
    unittest.main()
