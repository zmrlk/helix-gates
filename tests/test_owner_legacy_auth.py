"""Historical emulator claims remain evidence gaps, never session proof."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))

import helix_owner_report as owner
import helix_pro
import helix_runtime as runtime
import test_owner_runtime_projection as fixture_module


class OwnerLegacyAuth(unittest.TestCase):
    def historical(self):
        fixture = fixture_module.OwnerRuntimeProjection()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        report = fixture.run_fake(cookie=False)
        control = copy.deepcopy(report['parts'][0]['checks']['e2e'])
        control.update(status='PASS', reason='PRIVATE_LEGACY_COOKIE_CANARY')
        report['parts'][0]['checks']['auth-flow'] = control
        path = fixture.save(report)
        return fixture, path

    def test_owner_preserves_historical_source_hash_and_explains_unverified_claim(self):
        fixture, path = self.historical()
        original = path.read_bytes()
        result = owner.aggregate(fixture.project, [fixture.out])
        group = result['groups'][0]
        for key in ('runtime_integrations', 'runtime_transport', 'runtime_identity', 'runtime_identity_policy', 'runtime_webauthn'):
            self.assertEqual(group[key], [])
        self.assertTrue(any('Historyczny auth-flow PASS nie ma dowodu tożsamości' in gap['reason']
                            for gap in result['gaps']))
        artifact = next(row for row in group['artifacts'] if row['path'] == str(path))
        self.assertEqual(artifact['sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(path.read_bytes(), original)
        self.assertNotIn('PRIVATE_LEGACY_COOKIE_CANARY', json.dumps(result))
        text = owner.markdown(result)
        self.assertIn('wymagany jest powiązany test jawnej polityki', text)
        self.assertNotIn('PRIVATE_LEGACY_COOKIE_CANARY', text)

    def test_pro_import_rejects_historical_auth_claim_before_changing_points(self):
        fixture, path = self.historical()
        maturity = helix_pro.assess(fixture.project, 'XL')
        before = copy.deepcopy(maturity)
        original = path.read_bytes()
        with self.assertRaisesRegex(ValueError, '^legacy_auth_claim_unverified$'):
            runtime.import_evidence(maturity, path, fixture.project)
        self.assertEqual(maturity, before)
        self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
