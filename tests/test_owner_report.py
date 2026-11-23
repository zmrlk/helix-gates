"""Owner evidence aggregation, source separation and redaction without network."""
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


class OwnerReport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'project'
        self.repo.mkdir()
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()

    def write(self, name, data):
        p = self.evidence / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data))
        return p

    def report(self):
        with patch.object(subprocess, 'run', side_effect=AssertionError('aggregation must not execute commands')):
            return owner.aggregate(self.repo, [self.evidence])

    def test_attention_section_is_readable_for_many_route_audits(self):
        # Przebieg projektu B: 130 tras dawało 260 linii tej samej uwagi, a audit.json trasy liczył się jako brak rejestru długu.
        for n in range(3):
            self.write(f'runtime/visual/1/{n}/audit.json', {'url': f'http://127.0.0.1/r{n}', 'runs': [], 'summary': {'status': 'failed'}})
        self.write('deep/findings.json', [{'id': 'R', 'severity': 'high', 'file': 'src/a.ts', 'line': 1, 'title': 'T', 'verdict': 'needs_validation'}])
        text = owner.evidence_markdown(self.report())
        attention = text.split('## Co wymaga uwagi')[1].split('## Wyniki')[0]
        self.assertIn('(4 miejsc, np. `', attention)   # trzy trasy i katalog deep, wszystkie bez rewizji
        self.assertEqual(attention.count('Brak jednoznacznej rewizji'), 1)
        self.assertNotIn('Dług Ponytail', attention)
        self.assertIn('Ustalenia: 1; weryfikacja: {"needs_validation": 1}', attention)

    def test_aggregates_scan_gate_coverage_tools_and_unknown_cost(self):
        self.write('scan/run.json', {'target': str(self.repo), 'head': 'a' * 40, 'status': 'error', 'tools': [{'tool': 'semgrep', 'status': 'error', 'error_category': 'certificate', 'duration': .2}]})
        self.write('scan/gate.json', {'gate': 'security', 'status': 'ERROR', 'pass': False})
        self.write('scan/findings.json', [{'id': 'RULE', 'severity': 'high', 'file': 'src/a.ts', 'line': 4, 'title': 'Scope missing', 'verdict': 'needs_validation'}])
        self.write('scan/coverage-ledger.json', [{'unit': 'semgrep', 'status': 'error', 'reason': 'certificate'}])
        report = self.report()
        group = report['groups'][0]
        self.assertEqual(group['counts']['verification'], {'needs_validation': 1})
        self.assertEqual(group['gates'][0]['status'], 'ERROR')
        self.assertEqual(group['source_shas'], ['a' * 40])
        self.assertEqual(group['tools'][0]['reason'], 'certificate')
        self.assertEqual(group['coverage'][0]['summary']['states'], {'error': 1})
        text = owner.markdown(report)
        self.assertIn('**nieznany**', text)
        self.assertNotIn('0 USD', text)
        self.assertNotIn('0/100:', text)
        self.assertIn('source', json.dumps(report))

    def test_revisions_and_unknown_identity_remain_separate(self):
        for directory, sha in [('old', 'a' * 40), ('new', 'b' * 40)]:
            self.write(directory + '/run.json', {'head': sha, 'target': str(self.repo)})
            self.write(directory + '/findings.json', [{'id': 'SAME', 'file': 'src/a.ts', 'line': 1, 'severity': 'high'}])
        self.write('loose/verified-auth.json', [{'id': 'SAME', 'file': 'src/a.ts', 'line': 1, 'verdict': 'confirmed'}])
        report = self.report()
        self.assertEqual(len(report['groups']), 3)
        unknown = next(g for g in report['groups'] if g['identity_status'] == 'unknown')
        self.assertEqual(unknown['counts']['verification'], {'confirmed': 1})
        for g in report['groups']:
            if g is not unknown: self.assertEqual(g['counts']['verification'], {'candidate': 1})
        self.assertTrue(any('rewizji' in g['reason'] for g in report['gaps']))

    def test_separates_docs_legacy_tests_and_keeps_all_locations(self):
        self.write('findings.json', [{'id': 'A', 'file': f, 'line': 1} for f in ['src/a.ts', 'docs/example.ts', 'legacy/a.ts', 'tests/a.ts']])
        self.write('report.json', {'findings': [{'rule': 'raw-element', 'where': [f'src/Form.tsx:{n}' for n in range(1, 100)], 'count': 99, 'confidence': 'VERIFIED', 'severity': 'high'}]})
        group = self.report()['groups'][0]
        self.assertEqual(group['counts']['areas'], {'active': 2, 'docs': 1, 'legacy': 1, 'tests/examples': 1})
        row = next(f for f in group['findings'] if f['id'] == 'raw-element')
        self.assertEqual(len(row['locations']), 99)
        self.assertEqual(row['verdict'], 'candidate')

    def test_does_not_read_arbitrary_files_or_follow_links(self):
        self.write('credentials.json', {'password': 'SHOULD_NOT_BE_OPENED'})
        outside = self.root / 'outside.json'; outside.write_text('{"password":"SHOULD_NOT_BE_OPENED"}')
        (self.evidence / 'findings.json').symlink_to(outside)
        (self.evidence / 'linked').symlink_to(self.root, target_is_directory=True)
        report = self.report()
        self.assertEqual(report['artifact_count'], 0)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertNotIn('SHOULD_NOT_BE_OPENED', json.dumps(report))
        self.assertTrue(any('dowiązanie' in g['reason'] for g in report['gaps']))

    def test_invalid_json_and_conflicting_identity_are_explicit(self):
        (self.evidence / 'findings.json').write_text('{broken')
        self.write('run.json', {'head': 'a' * 40})
        self.write('run-metadata.json', {'source_ref': {'head': 'b' * 40}})
        report = self.report()
        self.assertEqual(report['groups'][0]['identity_status'], 'conflict')
        self.assertTrue(any('Nieprawidłowy' in g['reason'] for g in report['gaps']))

    def test_malformed_nested_report_is_a_gap_not_a_crash(self):
        self.write('broken/run.json', {'tools': 42})
        self.write('good/findings.json', [])
        report = self.report()
        self.assertEqual(report['artifact_count'], 1)
        self.assertTrue(any('Nieprawidłowy' in g['reason'] for g in report['gaps']))

    def test_redacts_secret_assignments_and_does_not_copy_raw_payloads(self):
        self.write('findings.json', [{'id': 'RULE', 'file': 'src/a.ts', 'title': 'password=placeholder-secret api_key=placeholder-key', 'code': 'PRIVATE SOURCE SHOULD NOT APPEAR', 'secret': 'PRIVATE SECRET SHOULD NOT APPEAR'}])
        serialized = json.dumps(self.report())
        self.assertNotIn('placeholder-secret', serialized)
        self.assertNotIn('placeholder-key', serialized)
        self.assertNotIn('PRIVATE SOURCE', serialized)
        self.assertNotIn('PRIVATE SECRET', serialized)

    def test_empty_evidence_writes_readable_incomplete_output(self):
        out = self.root / 'report.md'
        result = owner.dispatch(argparse.Namespace(repo=str(self.repo), out=str(out), evidence=[str(self.evidence)], state_dir=None))
        self.assertEqual(result, 2)
        self.assertIn('INCOMPLETE', out.read_text())
        self.assertTrue(out.with_suffix('.json').exists())

    def test_cli_requires_no_owner_contract_or_repo_pin(self):
        self.write('scan/findings.json', [])
        self.write('scan/run.json', {'head': 'a' * 40, 'target': str(self.repo)})
        out = self.root / 'report.md'
        run = subprocess.run([sys.executable, str(ROOT / 'bin/helix'), '--repo', str(self.repo), 'owner-report', '--evidence', str(self.evidence), '--out', str(out)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        self.assertTrue(out.is_file())
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_readonly_output_cannot_write_to_target(self):
        with self.assertRaises(ValueError):
            owner.dispatch(argparse.Namespace(repo=str(self.repo), out=str(self.repo / 'report.md'), evidence=[str(self.evidence)], state_dir=str(self.root / 'state')))

    def test_deep_raw_and_mapped_findings_are_counted_once_and_cost_is_projected(self):
        self.write('findings.json', [{'fingerprint': 'FP', 'title': 'Observed', 'evidence': [{'file': 'src/a.ts', 'line': 4}],
                                     'severity': {'overall_severity': 'high'}, 'verdict': 'confirmed'}])
        self.write('helix-findings.json', [{'id': 'FP', 'title': 'Observed', 'file': 'src/a.ts', 'line': 4,
                                           'severity': 'high', 'verdict': 'confirmed'}])
        self.write('run-metadata.json', {'source_ref': {'head': 'a' * 40}, 'target': str(self.repo),
                                        'usage': {'elapsed_seconds': 2, 'cost_usd': None}, 'provider_attempts': [{}, {}],
                                        'budget': {'calls': 3, 'prompt': 'PRIVATE PAYLOAD'},
                                        'plan': {'batches': 8, 'calls_min': 8, 'calls_max': 24, 'secret': 'PRIVATE PAYLOAD'}})
        group = self.report()['groups'][0]
        self.assertEqual(len(group['findings']), 1)
        self.assertEqual(group['findings'][0]['severity'], 'high')
        self.assertEqual(group['cost'][0]['provider_calls'], 2)
        self.assertEqual(group['cost'][0]['plan']['calls_min'], 8)
        self.assertIsNone(group['cost'][0]['measured'])
        self.assertNotIn('PRIVATE PAYLOAD', json.dumps(group))

    def test_mapped_deep_findings_with_other_ids_are_not_added_twice(self):
        # Projekt B: helix-findings.json ma inne id i miejsca niż findings.json obok, więc raport liczył 454 zamiast 240.
        self.write('deep/findings.json', [{'fingerprint': 'pg:a', 'title': 'A', 'evidence': [{'file': 'm.sql', 'line': 3}], 'verdict': 'needs_validation'},
                                          {'fingerprint': 'pg:b', 'title': 'B', 'evidence': [{'file': 'n.sql', 'line': 9}], 'verdict': 'rejected'}])
        self.write('deep/helix-findings.json', [{'id': 'helix:pg:a', 'title': 'A', 'file': 'supabase/m.sql', 'line': 17,
                                                 'severity': 'info', 'verdict': 'needs_validation'}])
        group = self.report()['groups'][0]
        self.assertEqual(group['counts']['verification'], {'needs_validation': 1, 'rejected': 1})

    def test_ux_report_is_listed_with_cells_and_judge_issues(self):
        # Projekt B: raport dla właściciela nie czytał ux-report.json, więc wynik sędziego i skanu urządzeń znikał.
        self.write('ux/1/report/ux-report.json', {'pass': False, 'blocking': 3, 'run_status': 'partial', 'targets': [{}, {}], 'pages': ['a', 'b', 'c'],
                                                   'counts': {'pass': 1, 'warn': 2, 'fail': 3},
                                                   'judge_issues': [{'severity': 'high'}, {'severity': 'high'}, {'severity': 'low'}],
                                                   'explore': [{'status': 'not_checked'}, {'status': 'fail'}]})
        attention = owner.evidence_markdown(self.report()).split('## Co wymaga uwagi')[1].split('## Wyniki')[0]
        self.assertIn('ux (2 urządzeń × 3 stron; komórki {"pass": 1, "warn": 2, "fail": 3}; uwagi sędziego {"high": 2, "low": 1}; '
                      'eksplorator 2 zadań, 1 sprawdzonych; przebieg partial): FAIL', attention)


if __name__ == '__main__':
    unittest.main()
