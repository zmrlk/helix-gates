"""Generation metadata never rewrites the provenance of imported owner evidence."""
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
import helix_new


def metadata(target, helix='d', version='0.1.0-beta'):
    return dict(schema_version=1, helix_version=version,
                source_ref=dict(head=helix * 40, dirty=False, status='recorded'),
                target_ref=dict(head=target * 40, dirty=True, status='recorded'),
                source_head=helix * 40, target_head=target * 40, source_dirty=False, target_dirty=True,
                python='3.11.1', generated_at='2026-10-25T10:00:00+00:00',
                models=[], tools={'python': {'version': '3.11.1', 'status': 'recorded', 'used': True}})


class ProvenanceOwner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'project'; self.repo.mkdir()
        self.evidence = self.base / 'evidence'; self.evidence.mkdir()

    def write(self, name, data):
        path = self.evidence / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    def test_aggregate_preserves_source_refs_and_does_not_execute_commands(self):
        original = metadata('a')
        self.write('run.json', {'target': str(self.repo), 'provenance': original})
        self.write('findings.json', [])
        with patch.object(subprocess, 'run', side_effect=AssertionError('pure aggregation must not execute commands')):
            data = owner.aggregate(self.repo, [self.evidence], generation_provenance=metadata('b', 'e', '0.9.3-beta'))
        self.assertEqual(data['generation_provenance']['target_head'], 'b' * 40)
        self.assertEqual(data['generation_provenance']['source_head'], 'e' * 40)
        self.assertEqual(data['groups'][0]['source_shas'], ['a' * 40])
        source = next(row for row in data['groups'][0]['artifacts'] if row['path'].endswith('run.json'))['source_provenance']
        self.assertEqual(source['target_head'], 'a' * 40)
        self.assertEqual(source['source_head'], 'd' * 40)
        self.assertEqual(source['helix_version'], '0.1.0-beta')
        self.assertEqual(source['tools']['python']['version'], '3.11.1')
        self.assertTrue(source['target_dirty'])
        text = owner.markdown(data)
        self.assertIn('bieżący cel ' + 'b' * 40, text)
        self.assertIn('źródłowy target HEAD ' + 'a' * 40, text)

    def test_unknown_source_does_not_inherit_current_models_or_tools(self):
        self.write('findings.json', [])
        current = metadata('b')
        current['models'] = [{'provider': 'codex', 'model': 'observed-model', 'status': 'recorded'}]
        data = owner.aggregate(self.repo, [self.evidence], generation_provenance=current)
        source = data['groups'][0]['artifacts'][0]['source_provenance']
        self.assertEqual(source['status'], 'not_recorded')
        self.assertEqual(source['models'], [])
        self.assertIsNone(source['tools']['python']['version'])
        self.assertEqual(data['groups'][0]['source_shas'], [])
        self.assertIsNone(source['target_head'])
        pure = owner.aggregate(self.repo, [self.evidence])
        self.assertEqual(pure['generation_provenance']['status'], 'not_recorded')

    def test_imported_provenance_projects_receipts_and_drops_private_payloads(self):
        source = metadata('a')
        source['models'] = [dict(provider='codex', model='configured-only', status='planned'),
                            dict(provider='gemini', model='answered-model', status='recorded', prompt='PRIVATE PROMPT'),
                            dict(provider='claude', model=None, status='recorded')]
        source['tools']['semgrep'] = dict(version='1.2.3', status='recorded', used=True, stderr='PRIVATE STDERR')
        source['environment_values'] = {'TOKEN': 'PRIVATE VALUE'}
        self.write('run.json', {'target': str(self.repo), 'provenance': source})
        data = owner.aggregate(self.repo, [self.evidence])
        projected = data['groups'][0]['artifacts'][0]['source_provenance']
        self.assertEqual({row['provider'] for row in projected['models']}, {'gemini', 'claude'})
        self.assertEqual(next(row for row in projected['models'] if row['provider'] == 'claude')['status'], 'unknown')
        self.assertEqual(projected['tools']['semgrep']['version'], '1.2.3')
        self.assertNotIn('PRIVATE', json.dumps(data))
        self.assertEqual(owner.projected_provenance(projected), projected)

    def test_nested_imported_runtime_keeps_its_revision_and_runtime_python(self):
        old = metadata('a')
        old['runtime_python'] = {'version': '3.10.2', 'status': 'recorded', 'used': True}
        self.write('owner-current.json', {'provenance': metadata('b'), 'target': str(self.repo),
                                         'source_reports': [{'kind': 'runtime', 'artifact': '/audit/runtime-report.json',
                                                             'provenance': old, 'head_relation': 'different'}]})
        result = owner.aggregate(self.repo, [self.evidence], generation_provenance=metadata('c'))
        artifact = result['groups'][0]['artifacts'][0]
        self.assertEqual(artifact['source_provenance']['target_head'], 'b' * 40)
        self.assertEqual(artifact['source_reports'][0]['provenance']['target_head'], 'a' * 40)
        self.assertEqual(artifact['source_reports'][0]['provenance']['runtime_python']['version'], '3.10.2')
        self.assertEqual(artifact['source_reports'][0]['head_relation'], 'different')
        self.assertEqual(artifact['source_reports'][0]['snapshot_equivalence'], 'not_established')

    def test_legacy_source_keeps_declared_engine_without_filling_unknown_tools(self):
        self.write('run-metadata.json', {'target': str(self.repo), 'source_ref': {'head': 'a' * 40}, 'helix_version': '0.6.0'})
        data = owner.aggregate(self.repo, [self.evidence], generation_provenance=metadata('b'))
        source = data['groups'][0]['artifacts'][0]['source_provenance']
        self.assertEqual(source['status'], 'legacy')
        self.assertEqual(source['helix_version'], '0.6.0')
        self.assertEqual(source['target_head'], 'a' * 40)
        self.assertIsNone(source['source_head'])
        self.assertIsNone(source['tools']['semgrep']['version'])

    def test_dispatch_collects_current_metadata_before_pure_projection(self):
        self.write('findings.json', [])
        args = argparse.Namespace(repo=str(self.repo), out=str(self.base / 'owner.md'), evidence=[str(self.evidence)], state_dir=None)
        with patch.object(owner, 'generation_metadata', return_value=metadata('b')) as capture:
            self.assertEqual(owner.dispatch(args), 0)
        capture.assert_called_once_with(self.repo)
        result = json.loads((self.base / 'owner.json').read_text())
        self.assertEqual(result['provenance']['target_head'], 'b' * 40)

    def test_new_audit_and_owner_keep_source_metadata_without_probes(self):
        (self.repo / 'app.py').write_text('def run():\n    return 1\n')
        out = self.base / 'audit'
        source = metadata('a')
        def readonly_inventory(command, **kwargs):
            self.assertEqual(command[0], 'git')
            self.assertIn('ls-files', command)
            self.assertIn('core.fsmonitor=false', command)
            self.assertEqual(Path(kwargs['cwd']), self.repo)
            self.assertEqual(kwargs['env']['GIT_OPTIONAL_LOCKS'], '0')
            # The synthetic project is not Git-backed; exercise walk fallback.
            if kwargs.get('check'): raise subprocess.CalledProcessError(128, command)
            return subprocess.CompletedProcess(command, 128, b'', b'')
        with patch('helix_environment.provenance', return_value=source), \
             patch('helix_environment.local_tool', side_effect=AssertionError('no version probes')), \
             patch('helix_release.git', return_value='a' * 40), \
             patch.object(subprocess, 'run', side_effect=readonly_inventory):
            helix_new.audit(self.repo, out, 'S')
        audit = json.loads((out / 'audit.json').read_text())
        report = json.loads((out / 'owner-current.json').read_text())
        self.assertEqual(audit['provenance'], source)
        self.assertEqual(report['source_provenance']['target_head'], 'a' * 40)
        self.assertEqual(report['source_provenance']['models'], [])
        self.assertEqual({row['kind'] for row in report['source_reports']}, {'audit', 'review'})
        self.assertIn('Generowanie raportu:', (out / 'audit.md').read_text())
        self.assertEqual(list(self.repo.iterdir()), [self.repo / 'app.py'])


if __name__ == '__main__':
    unittest.main()
