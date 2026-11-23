"""Both owner-report APIs survive the project-A/master integration."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_owner_report as owner
import helix_config


class OwnerReportMerge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'project'
        self.repo.mkdir()
        self.out = self.base / 'evidence'
        self.out.mkdir()

    def finding(self, file='src/view.ts', **changes):
        return dict(dict(id='R1', file=file, line=3, severity='high', confidence='possible',
                         lens='security', why='Missing object scope', fix='Add ownership check',
                         evidence=[file + ':3']), **changes)

    def test_contract_mode_keeps_weighted_api_without_displaying_fake_zero(self):
        rows = [self.finding('docs/example.ts'), self.finding('legacy/example.ts'), self.finding()]
        data = {'findings': rows, 'assessment': {'controls': [{'id': 'security', 'status': 'not-run'}]}}
        result = owner.build(data, {'status': 'INCOMPLETE'}, {'status': 'NOT_CONFIGURED'}, 'details.json')
        self.assertEqual(result['assessment']['score'], 0)
        self.assertEqual(result['assessment']['counts']['not-run'], 1)
        self.assertEqual(result['summary']['by_area'], {'active': 1, 'docs': 1, 'legacy': 1})
        text = owner.markdown(result)
        self.assertNotIn('0/100', text)
        self.assertIn('Brak pomiaru wykonania', text)
        self.assertLess(text.index('src/view.ts:3'), text.index('docs/example.ts:3'))

    def test_verified_execution_is_still_weighted_and_blockers_still_visible(self):
        (self.repo / 'log').write_text('1 test passed\n')
        sha = 'a' * 40
        run = dict(status='passed', exit=0, who='runner', where='temporary copy', sha=sha, command='unittest', log='log')
        data = dict(sha=sha, assessment={'controls': [dict(id='security', status='PASS', score=100, run=run)]})
        with patch('helix_release.git', return_value=sha):
            result = owner.build(data, {'status': 'PASS'}, {}, 'details.json', self.repo)
        self.assertEqual(result['assessment']['score'], 100)
        self.assertIn('100.0/100', owner.markdown(result))
        with patch('helix_release.git', return_value=sha):
            failed = owner.build(data, {'status': 'FAIL'}, {}, 'details.json', self.repo)
        self.assertEqual(failed['assessment']['readiness'], 'BLOCKED')
        self.assertIn('validation: FAIL', failed['assessment']['blockers'])
        data['sha'] = 'b' * 40
        with patch('helix_release.git', return_value=sha):
            old = owner.build(data, {'status': 'PASS'}, {}, 'details.json', self.repo)
        self.assertEqual(old['assessment']['readiness'], 'BLOCKED')
        self.assertNotIn('/100', owner.markdown(old))

    def test_audit_projection_is_aggregated_with_source_identity_and_full_locations(self):
        locations = [f'src/view.ts:{line}' for line in range(1, 12)]
        row = self.finding(locations=locations)
        audit = {'maturity': {'areas': {}}, 'quality': {'domains': {'checks': []}, 'findings': []},
                 'scope': {'profile': 'M'}, 'source_coverage': {'status': 'COMPLETE', 'files_read': 1, 'files_total': 1}}
        with patch('helix_lenses.report', return_value={'findings': [row], 'lenses': {}}), \
             patch('helix_continuity.Continuity.report', side_effect=AssertionError('no continuity policy configured')), \
             patch('helix_release.git', return_value='a' * 40):
            owner.audit_report(self.repo, self.out, audit, {})
        with patch.object(subprocess, 'run', side_effect=AssertionError('aggregation must remain non-executing')):
            combined = owner.aggregate(self.repo, [self.out])
        group = combined['groups'][0]
        self.assertEqual(combined['artifact_count'], 1)
        self.assertEqual(group['identity_status'], 'declared')
        self.assertTrue(group['applies_to_requested_repo'])
        self.assertEqual(group['source_shas'], ['a' * 40])
        self.assertEqual(group['assessments'][0]['readiness'], 'BLOCKED')
        self.assertEqual(group['findings'][0]['verdict'], 'candidate')
        self.assertEqual(len(group['findings'][0]['locations']), 11)
        self.assertIn('Ocena wykonania wg artefaktu', owner.markdown(combined))

    def test_audit_projection_respects_external_owner_configuration(self):
        config = self.base / 'external.json'
        config.write_text(json.dumps({'owner_report': {'gap_assignments': {'R1': {'owner': 'Review team'}}}}))
        helix_config.configure(self.repo, config)
        self.addCleanup(helix_config._overrides.pop, self.repo.resolve(), None)
        audit = {'maturity': {'areas': {}}, 'quality': {'domains': {'checks': []}, 'findings': []},
                 'scope': {'profile': 'M'}, 'source_coverage': {'status': 'COMPLETE'}}
        with patch('helix_lenses.report', return_value={'findings': [self.finding()], 'lenses': {}}), \
             patch('helix_release.git', return_value='a' * 40):
            owner.audit_report(self.repo, self.out, audit, {})
        result = json.loads((self.out / 'owner-current.json').read_text())
        self.assertEqual(result['gaps'][0]['owner'], 'Review team')
        self.assertEqual(list(self.repo.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
