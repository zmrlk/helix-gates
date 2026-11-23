"""Owner projections retain debt locations without awarding quality credit."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_owner_report as owner
from helix_ponytail_debt import debt, project_debt

STAMP = '2026-10-26T01:00:00+00:00'
HEAD = 'a' * 40


def snapshot(sources=None):
    sources = sources if sources is not None else {
        'src/cache.py': '# ponytail: ceiling: 50 rows; upgrade: indexed cache\n',
        'legacy/cache.py': '# ponytail: ceiling: 20 rows; upgrade: shared helper\n',
        'tests/cache.py': '# ponytail: ceiling: 10 rows; upgrade: parameterized fixture\n',
        'docs/example.py': '# ponytail: ceiling: one example; upgrade: generated examples\n',
    }
    coverage = dict(status='COMPLETE', files_total=len(sources), files_read=len(sources),
                    files=[dict(file=name, status='read', sha256=hashlib.sha256(text.encode()).hexdigest())
                           for name, text in sources.items()])
    return debt(sources, coverage, observed_at=STAMP)


class OwnerPonytailDebt(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / 'project'
        self.repo.mkdir()
        self.out = self.root / 'audit'
        self.out.mkdir()
        self.meta = dict(target=str(self.repo), head=HEAD,
                         provenance={'target_ref': {'head': HEAD, 'dirty': False}})

    def write(self, name, data):
        (self.out / name).write_text(json.dumps(data))

    def aggregate(self):
        with patch.object(subprocess, 'run', side_effect=AssertionError('owner must only project evidence')):
            return owner.aggregate(self.repo, [self.out])

    def test_all_locations_and_areas_survive_without_age_or_quality_invention(self):
        report = snapshot()
        before = copy.deepcopy(report)
        text = '\n'.join(owner.ponytail_debt_markdown(project_debt(report)))
        for row in report['rows']:
            self.assertIn(row['file'] + ':' + str(row['line']), text)
            self.assertIn(row['source_area'], text)
        self.assertEqual(len(report['rows']), 4)
        self.assertIn('nieznane', text)
        self.assertIn('nie przyznaje punktów', text)
        self.assertNotIn('/100', text)
        self.assertEqual(report, before)

    def test_missing_history_is_distinct_from_a_complete_empty_scan(self):
        legacy = project_debt(None)
        empty = snapshot({})
        self.assertIsNone(legacy['counts']['markers'])
        self.assertEqual(empty['counts']['markers'], 0)
        self.assertIn('komentarze: nieznane', '\n'.join(owner.ponytail_debt_markdown(legacy)))
        self.assertIn('komentarze: 0', '\n'.join(owner.ponytail_debt_markdown(empty)))

    def test_identical_audit_quality_and_owner_snapshots_are_not_counted_three_times(self):
        result = snapshot()
        self.write('audit.json', dict(self.meta, quality={'ponytail_debt': result}))
        self.write('quality.json', dict(self.meta, ponytail_debt=result))
        self.write('owner-current.json', dict(self.meta, ponytail_debt=project_debt(result)))
        report = self.aggregate()
        group = report['groups'][0]
        self.assertEqual(len(group['ponytail_debt']), 1)
        self.assertEqual(len(group['ponytail_debt'][0]['artifacts']), 3)
        self.assertEqual(group['ponytail_debt'][0]['counts']['markers'], 4)
        self.assertEqual(group['findings'], [])
        text = owner.markdown(report)
        self.assertEqual(text.count('`src/cache.py:1`'), 1)
        self.assertIn('aktualność źródeł', text)

    def test_different_snapshots_or_revisions_are_not_silently_coalesced(self):
        self.write('audit.json', dict(self.meta, quality={'ponytail_debt': snapshot()}))
        self.write('quality.json', dict(self.meta, ponytail_debt=snapshot({'src/other.py': '# ponytail: ceiling: 5 rows; upgrade: helper\n'})))
        alternate = dict(self.meta, head='b' * 40)
        self.write('owner-current.json', dict(alternate, ponytail_debt=snapshot()))
        group = self.aggregate()['groups'][0]
        self.assertEqual(len(group['ponytail_debt']), 3)
        self.assertEqual(group['identity_status'], 'conflict')

    def test_unbound_quality_and_tampered_counts_remain_explicit_gaps(self):
        self.write('quality.json', {'ponytail_debt': snapshot()})
        bad = snapshot()
        bad['counts']['markers'] = 999
        self.write('audit.json', dict(self.meta, quality={'ponytail_debt': bad}))
        report = self.aggregate()
        self.assertEqual(report['groups'][0]['ponytail_debt'], [])
        reasons = ' '.join(gap['reason'] for gap in report['gaps'])
        self.assertIn('tożsamości repo', reasons)
        self.assertIn('Nieprawidłowy rejestr', reasons)

    def test_owner_current_projects_registry_without_creating_scored_controls(self):
        audit = dict(maturity={'areas': {}}, quality={'domains': {'checks': []}, 'findings': [],
                    'ponytail_debt': snapshot()}, source_coverage={}, scope={'profile': 'M'})
        with patch('helix_lenses.report', return_value={'findings': [], 'lenses': {}}), \
             patch('helix_release.git', return_value=HEAD):
            owner.audit_report(self.repo, self.out, audit, {})
        result = json.loads((self.out / 'owner-current.json').read_text())
        self.assertEqual(result['target'], str(self.repo))
        self.assertEqual(result['ponytail_debt']['counts']['markers'], 4)
        self.assertEqual(result['controls'], [])
        self.assertEqual(result['assessment']['counts']['executed'], 0)
        text = (self.out / 'owner-current.md').read_text()
        self.assertIn('src/cache.py:1', text)
        self.assertIn('nieznane', text)


if __name__ == '__main__':
    unittest.main()
