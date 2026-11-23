"""Synthetic external proposal contracts; no providers, application or network."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_config
import helix_project_proposal as proposal
from helix_contracts import VERSION


class ProjectProposalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'project'
        self.repo.mkdir()
        self.out = self.base / 'results'
        self.state = self.base / 'state'
        self.state.mkdir()
        self.addCleanup(helix_config._overrides.clear)

    def put(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def config(self, value):
        path = self.base / 'external-config.json'
        path.write_text(json.dumps(value))
        helix_config.configure(self.repo, path)
        return path

    def cache(self, age=0, rows=None):
        when = (datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat()
        records = rows if rows is not None else [dict(provider=p, model=m, family=f, status='available', method='short_call', checked_at=when)
                                                for p, m, f in [('codex', 'model-openai', 'openai'), ('gemini', 'model-google', 'google'), ('claude', 'model-anthropic', 'anthropic')]]
        path = self.state / 'provider-availability.json'
        path.write_text(json.dumps({'models': records}))
        return path

    def run_proposal(self, **kwargs):
        with mock.patch('helix_security_deep.ask', side_effect=AssertionError('model called')), \
             mock.patch('helix_environment.local_tool', side_effect=AssertionError('version probe called')):
            return proposal.generate(self.repo, self.out, state_dir=self.state, **kwargs)

    def test_missing_cache_is_limited_no_login_claim_or_target_write(self):
        self.put('frontend/src/app.svelte', '<button>Save</button>')
        self.put('.env', 'PASSWORD=must-not-leak')
        before = sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob('*'))
        data = self.run_proposal()
        self.assertEqual(data['status'], 'LIMITED')
        self.assertEqual(data['execution']['models'], 0)
        self.assertEqual(data['ui_paths'], ['frontend/src'])
        self.assertEqual(data['history']['status'], 'missing')
        self.assertEqual(data['availability']['status'], 'missing')
        self.assertEqual(sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob('*')), before)
        self.assertFalse((self.repo / 'helix.json').exists())
        config = json.loads((self.out / 'helix.proposed.json').read_text())
        self.assertEqual(config['helix_version'], VERSION)
        # Decyzja właściciela 15.11.2026: propozycja nie dopisuje pytania o wysyłkę; obowiązuje domyślna (wszyscy dostawcy).
        self.assertNotIn('data_egress', config)
        self.assertEqual(data['data_egress']['status'], 'DEFAULT_ALL_PROVIDERS')
        self.assertEqual(data['data_egress']['delivery'], 'NOT_SENT')
        self.assertNotIn('data_egress', [item['id'] for item in data['pending_owner']])
        combined = ''.join(p.read_text() for p in self.out.glob('*') if p.is_file())
        self.assertNotIn('must-not-leak', combined)
        self.assertIn('nie potwierdza zalogowania', combined)
        self.assertEqual(data['provenance']['models'], [])

    def test_fresh_real_cache_assigns_families_and_records_cache_hash(self):
        cache = self.cache()
        data = self.run_proposal()
        plan = data['provider_plan']
        self.assertEqual(data['availability']['status'], 'recorded_fresh')
        self.assertEqual(plan['status'], 'READY')
        self.assertNotEqual(plan['roles']['hunter']['family'], plan['roles']['verifier']['family'])
        self.assertEqual(data['availability']['sha256'], hashlib.sha256(cache.read_bytes()).hexdigest())
        self.assertEqual(data['execution']['models'], 0)
        self.assertEqual(data['provenance']['models'], [])  # Previous probes are not this run's calls.
        self.assertEqual(plan['roles']['hunter']['model'], 'model-openai')
        config = json.loads((self.out / 'helix.proposed.json').read_text())
        self.assertEqual(config['models']['codex'][0], 'model-openai')
        from helix_provider_plan import plan as plan_again
        self.assertEqual(plan_again(config, proposal.availability(cache)[0], config)['status'], 'READY')

    def test_stale_or_path_only_cache_does_not_claim_availability(self):
        self.cache(age=3600)
        data = self.run_proposal()
        self.assertEqual(data['provider_plan']['status'], 'LIMITED')
        self.assertEqual(data['availability']['status'], 'recorded_unavailable_or_stale')
        path = self.state / 'provider-availability.json'
        data = json.loads(path.read_text())
        for row in data['models']:
            row.update(checked_at=datetime.now(timezone.utc).isoformat(), method='which')
        path.write_text(json.dumps(data))
        clean, evidence = proposal.availability(path)
        self.assertFalse(any(row['fresh_available'] for row in clean['models']))

    def test_cache_projection_rejects_wrong_types_and_drops_raw_responses(self):
        path = self.cache(rows=[{'provider': ['invalid']}, {'provider': 'codex', 'model': {'wrong': True}},
                               {'provider': 'codex', 'model': None, 'status': float('nan'),
                                'stdout': 'private response', 'prompt': 'private prompt'}])
        clean, evidence = proposal.availability(path)
        self.assertEqual(len(clean['models']), 1)
        self.assertNotIn('stdout', clean['models'][0])
        self.assertNotIn('prompt', clean['models'][0])
        self.assertNotIn('status', clean['models'][0])
        data = self.run_proposal()
        self.assertEqual(data['provider_plan']['status'], 'LIMITED')

    def test_complete_history_requires_matching_receipt(self):
        from helix_security_deep import digest
        cursor = self.state / 'security-audit/completed' / digest(str(self.repo)) / 'last-complete.json'
        cursor.parent.mkdir(parents=True)
        run = self.base / 'old-run'
        run.mkdir()
        head = 'a' * 40
        cursor.write_text(json.dumps(dict(target=str(self.repo), run_status='complete', head=head, run=str(run))))
        (run / 'run-metadata.json').write_text(json.dumps(dict(run_status='complete', source_ref={'head': head})))
        _, history = proposal.schedule(self.state, self.repo)
        self.assertEqual(history['status'], 'recorded_complete')
        (run / 'run-metadata.json').write_text('[]')
        self.assertEqual(proposal.schedule(self.state, self.repo)[1]['status'], 'invalid_or_unreadable')

    def test_config_user_fields_roles_models_and_paths_are_preserved(self):
        given = dict(helix_version='0.0.1', profile='XL', mode='autonomous', custom={'answer': 42},
                     providers={'hunter': 'claude', 'verifier': 'claude'}, models={'claude': ['explicit-model', 'fallback']},
                     consistency={'runtime': {'pages': ['/admin']}, 'static': {'paths': ['custom/ui'], 'exclude': ['cache']}},
                     packs={'security': {'deep': {'jobs': 7, 'max_candidates': 2}}, 'perf': {'enabled': False}},
                     runtime={'custom': True, 'database': {'engine': 'postgres', 'major': 17}},
                     data_egress={'allowlist': ['frontend/src'], 'approved_by': 'fixture owner'})
        self.config(given)
        self.cache()
        original = copy.deepcopy(given)
        data = self.run_proposal()
        result = json.loads((self.out / 'helix.proposed.json').read_text())
        for field in ('custom', 'providers', 'consistency', 'packs', 'runtime', 'data_egress'):
            if field == 'providers':
                for key, value in given[field].items(): self.assertEqual(result[field][key], value)
            else: self.assertEqual(result[field], given[field])
        self.assertEqual(result['models']['claude'], given['models']['claude'])
        self.assertEqual(result['helix_version'], VERSION)
        self.assertEqual(helix_config.load(self.repo), original)
        self.assertEqual([row['id'] for row in data['pending_owner']], ['data_egress'])
        self.assertEqual(data['data_egress']['status'], 'PENDING_OWNER')
        self.assertTrue(data['provider_plan']['proposals'])

    def test_monorepo_ui_roots_exclude_linked_dependencies_and_legacy(self):
        self.put('apps/store/src/a.ts', 'export const a = 1')
        self.put('packages/ui/src/box.ts', 'export const box = 1')
        self.put('legacy/src/a.ts', 'old code')
        self.put('node_modules/dependency/src/a.ts', 'dependency')
        (self.repo / 'linked').symlink_to(self.repo / 'apps', target_is_directory=True)
        self.assertEqual(self.run_proposal()['ui_paths'], ['apps/store/src', 'packages/ui/src'])

    def test_plan_schedule_unlimited_full_daily_release_30_minutes(self):
        data = self.run_proposal()
        self.assertEqual([row['budget_seconds'] for row in data['schedule']], [None, None, 1800])
        self.assertTrue(all(row['history_status'] == 'missing' for row in data['schedule']))
        self.assertTrue(any('COMPLETE' in gap and '--since REF' in gap for gap in data['gaps']))
        self.assertNotIn('--budget', data['schedule'][0]['invocation'])
        self.assertNotIn('--budget', data['schedule'][1]['invocation'])
        self.assertEqual(data['schedule'][2]['invocation'][-2:], ['--budget', 'time=30m'])

    def test_database_mismatch_is_explicit_installed_binary_not_production(self):
        self.put('compose.yaml', 'services:\n  db:\n    image: postgres:17\n')
        def local(name):
            return dict(status='available', version='14.2', scope='server_binary_not_running_server' if name == 'postgres' else 'local_binary')
        with mock.patch('helix_environment.local_tool', side_effect=local):
            data = proposal.generate(self.repo, self.out, state_dir=self.state, probe=True)
        self.assertEqual(data['database']['target']['major'], 17)
        self.assertFalse(data['database']['local']['compatible'])
        self.assertTrue(any('WARNING' in gap for gap in data['gaps']))
        self.assertEqual(data['database']['local']['scope'], 'server_binary_not_running_server')
        env = json.loads((self.out / 'environment.json').read_text())
        self.assertTrue(all(row['production']['status'] == 'unknown' for row in env['components']))

    def test_explicit_write_creates_config_once_and_never_replaces(self):
        self.run_proposal(write=True)
        original = (self.repo / 'helix.json').read_bytes()
        other = self.base / 'other-output'
        with self.assertRaisesRegex(ValueError, 'nie nadpisuje'):
            proposal.generate(self.repo, other, write=True)
        self.assertFalse(other.exists())
        self.assertEqual((self.repo / 'helix.json').read_bytes(), original)

    def test_refuses_output_state_and_cache_symlinks_or_inside_target(self):
        for output in (self.repo / 'results', self.base):
            with self.assertRaises(ValueError): proposal.generate(self.repo, output)
        linked = self.base / 'linked'
        linked.symlink_to(self.out, target_is_directory=True)
        with self.assertRaises(ValueError): proposal.generate(self.repo, linked)
        with self.assertRaises(ValueError): proposal.generate(self.repo, self.out, state_dir=self.repo / '.helix')
        cache = self.cache()
        alias = self.base / 'cache-alias.json'
        alias.symlink_to(cache)
        self.assertEqual(proposal.availability(alias)[1]['status'], 'invalid_or_unreadable')
        self.run_proposal()
        with self.assertRaises(ValueError): proposal.generate(self.repo, self.out)

    def test_real_git_deep_plan_uses_jobs3_and_never_calls_model(self):
        self.put('src/api.ts', 'export async function GET(request) { return {ok: true}; }\n')
        for command in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'fixture']):
            subprocess.run(['git', '-C', str(self.repo), *command], check=True, capture_output=True)
        self.cache()
        data = self.run_proposal()
        self.assertEqual(data['deep']['status'], 'plan_only', data['gaps'])
        self.assertGreater(data['deep']['plan']['batches'], 0)
        self.assertEqual(data['deep']['plan']['jobs'], 3)
        self.assertGreater(data['deep']['plan']['source_bytes'], 0)
        self.assertEqual(json.loads((self.out / 'deep-plan/checkpoint.json').read_text())['meta']['usage']['calls'], 0)
        self.assertFalse((self.repo / '.helix').exists())
        self.assertTrue((self.out / 'deep-plan/cost-plan.json').is_file())

    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'bin/helix'), *map(str, args)], capture_output=True, text=True)

    def test_cli_init_is_external_without_write_and_honors_nested_config(self):
        target = self.base / 'new-project'
        cfg = self.config({'custom': {'keep': True}})
        result = self.cli('new', 'init', '--dir', target, '--out', self.out, '--mode', 'greenfield', '--profile', 'S', '--risk', 'low', '--config', cfg, '--offline', '--no-probe')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(target.exists())
        self.assertTrue((self.out / 'proposed/PROJECT.md').is_file())
        self.assertTrue((self.out / 'NEW-REPORT.md').is_file())
        self.assertEqual(json.loads((self.out / 'helix.proposed.json').read_text())['custom'], {'keep': True})
        self.assertEqual(json.loads((self.out / 'proposed/helix.json').read_text()),
                         json.loads((self.out / 'helix.proposed.json').read_text()))

    def test_cli_init_write_refuses_any_existing_draft_before_config_write(self):
        self.put('PROJECT.md', 'existing owner document')
        result = self.cli('new', 'init', '--dir', self.repo, '--out', self.out, '--mode', 'greenfield', '--profile', 'S', '--risk', 'low', '--write', '--offline', '--no-probe')
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual((self.repo / 'PROJECT.md').read_text(), 'existing owner document')
        self.assertFalse((self.repo / 'helix.json').exists())
        self.assertFalse(self.out.exists())

    def test_cli_audit_honors_global_target_and_external_state(self):
        self.put('frontend/src/app.ts', 'export const app = 1;')
        result = self.cli('--repo', self.repo, '--offline', 'new', 'audit', '--out', self.out, '--state-dir', self.state, '--profile', 'S', '--no-probe')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads((self.out / 'project-proposal.json').read_text())
        self.assertEqual(data['target'], str(self.repo))
        self.assertEqual(data['execution']['models'], 0)
        self.assertTrue((self.out / 'audit.json').is_file())
        self.assertFalse((self.repo / 'helix.json').exists())
        self.assertFalse((self.repo / '.helix').exists())
        self.assertIn('Pokrycie odczytu:', result.stdout)
        self.assertNotIn('/100', result.stdout)

    def test_explicit_refresh_uses_only_owner_config_and_counts_current_attempts(self):
        owner = {'models': {'claude': [None]}, 'custom': {'keep': True}}
        self.config(owner)
        called = []
        def refresh(*, config, cache_path, jobs, offline):
            called.append((copy.deepcopy(config), cache_path, jobs, offline))
            self.assertEqual(config, owner)
            self.assertFalse(self.out.exists())
            when = datetime.now(timezone.utc).isoformat()
            records = [dict(provider='codex', model='gpt-synthetic', family='openai', status='available',
                            method='short_call', checked_at=when, call_invoked=True),
                       dict(provider='claude', model=None, family='anthropic', status='unavailable',
                            method='short_call', checked_at=when, call_invoked=True),
                       dict(provider='grok', model=None, family='xai', status='unavailable',
                            method='short_call', checked_at=when, call_invoked=False)]
            result = {'status': 'complete', 'models': records}
            cache_path.write_text(json.dumps(result))
            config['custom']['keep'] = False
            return result
        data = self.run_proposal(refresh_providers=True, provider_refresh=refresh, jobs=2)
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0][1:], (self.state / 'provider-availability.json', 2, False))
        self.assertEqual(helix_config.load(self.repo), owner)
        self.assertEqual(data['execution']['models'], 2)
        self.assertEqual(data['execution']['availability_probe_calls'], 2)
        self.assertEqual(data['execution']['source_review_calls'], 0)
        self.assertEqual([row['provider'] for row in data['provenance']['models']], ['codex', 'claude'])
        self.assertTrue(all(row['role'] == 'availability_probe' for row in data['provenance']['models']))
        self.assertEqual(data['provenance']['models'][1]['status'], 'unknown')
        self.assertEqual(data['status'], 'LIMITED')
        config = json.loads((self.out / 'helix.proposed.json').read_text())
        self.assertNotIn('data_egress', config)
        self.assertEqual(data['data_egress']['delivery'], 'NOT_SENT')
        text = (self.out / 'NEW-REPORT.md').read_text()
        self.assertIn('Sondy dostępności w tym poleceniu: 2', text)
        self.assertIn('Przegląd kodu przez modele: 0', text)
        self.assertNotIn('modele i baza nie zostały uruchomione', text)
        self.assertNotIn('żaden model nie został wywołany', text)

    def test_cached_probe_receipts_never_count_as_current_calls(self):
        cache = self.cache()
        saved = json.loads(cache.read_text())
        for row in saved['models']: row['call_invoked'] = True
        cache.write_text(json.dumps(saved))
        callback = mock.Mock(side_effect=AssertionError('implicit refresh'))
        data = self.run_proposal(provider_refresh=callback)
        callback.assert_not_called()
        self.assertEqual(data['execution']['availability_probe_calls'], 0)
        self.assertEqual(data['provider_refresh']['status'], 'not_requested')
        self.assertEqual(data['provenance']['models'], [])

    def test_refresh_offline_bad_jobs_and_target_cache_refuse_before_callback(self):
        callback = mock.Mock(side_effect=AssertionError('must not call'))
        for kwargs in ({'offline': True}, {'jobs': 0}, {'jobs': True},
                       {'provider_cache': self.repo / 'provider-availability.json'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.run_proposal(refresh_providers=True, provider_refresh=callback, **kwargs)
        callback.assert_not_called()
        self.assertFalse(self.out.exists())
        self.assertFalse((self.repo / 'provider-availability.json').exists())

    def test_audit_current_probe_provenance_is_written_before_owner_aggregation(self):
        from helix_new import audit
        self.put('src/app.py', 'print("fixture")')
        callback = mock.Mock()
        def refresh(**kwargs):
            records = dict(status='complete', models=[dict(provider='codex', model='gpt-synthetic', family='openai',
                           status='unavailable', call_invoked=True)])
            kwargs['cache_path'].write_text(json.dumps(records))
            return records
        callback.side_effect = refresh
        with mock.patch('helix_security_deep.ask', side_effect=AssertionError('source review called')):
            lines = audit(self.repo, self.out, profile='S', state_dir=self.state, refresh_providers=True,
                          provider_refresh=callback, jobs=2)
        callback.assert_called_once()
        data = json.loads((self.out / 'audit.json').read_text())
        self.assertEqual(data['execution']['models'], 1)
        self.assertEqual(data['provenance']['models'][0]['role'], 'availability_probe')
        generated = json.loads((self.out / 'project-proposal.json').read_text())
        self.assertEqual(generated['execution']['availability_probe_calls'], 1)
        self.assertEqual(generated['execution']['source_review_calls'], 0)
        self.assertIn('Sondy dostępności: 1; przegląd kodu przez modele: 0', '\n'.join(lines))
        self.assertIn('Sondy dostępności w tym poleceniu: 1', (self.out / 'audit.md').read_text())
        self.assertFalse((self.repo / '.helix').exists())

    def test_refresh_audit_collision_refuses_before_any_probe(self):
        from helix_new import audit
        self.out.mkdir()
        (self.out / 'audit.json').write_text('existing owner evidence')
        callback = mock.Mock(side_effect=AssertionError('must not call'))
        with self.assertRaisesRegex(ValueError, 'existing artifacts'):
            audit(self.repo, self.out, profile='S', state_dir=self.state,
                  refresh_providers=True, provider_refresh=callback)
        callback.assert_not_called()
        self.assertEqual((self.out / 'audit.json').read_text(), 'existing owner evidence')

    def test_console_evidence_counts_keep_execution_and_declarations_separate(self):
        from helix_new import audit_summary, evidence_counts
        rows = [dict(id='declared', satisfied=True, runtime=True, status='needs-runtime'),
                dict(id='measured-pass', satisfied=True, runtime=False, status='PASS', execution_status='PASS'),
                dict(id='measured-fail', satisfied=False, runtime=False, status='FAIL', execution_status='FAIL'),
                dict(id='missing', satisfied=False, runtime=True, status='missing'),
                dict(id='excepted', satisfied=False, runtime=False, status='missing', exception={'reason': 'fixture'})]
        maturity = dict(score=0, areas={'UX': dict(score=0, preparation_score=100, requirements=rows, top_gaps=rows[2:])},
                        parts=[dict(path='legacy', status='excluded')])
        report = dict(scope={'profile': 'M'}, maturity=maturity,
                      source_coverage=dict(files_read=2, files_total=3, lines_read=10, status='INCOMPLETE'))
        original = copy.deepcopy(report)
        with mock.patch('subprocess.run', side_effect=AssertionError('pure summary executed a process')):
            text = '\n'.join(audit_summary(report))
        self.assertEqual(evidence_counts(maturity), dict(requirements=5, declarations=1, passed=1, failed=1, runtime_pending=2, missing=1, exceptions=1))
        self.assertIn('wykonane PASS 1, FAIL 1', text)
        self.assertIn('dopasowane deklaracje 1', text)
        self.assertIn('INCOMPLETE', text)
        self.assertIn('legacy: wyłączona', text)
        self.assertNotIn('/100', text)
        self.assertEqual(report, original)

    def test_console_empty_catalog_has_no_perfect_or_failed_quality_score(self):
        from helix_new import audit_summary
        report = dict(scope={'profile': 'S'}, maturity=dict(score=100, areas={'UX': dict(requirements=[], top_gaps=[])}))
        text = '\n'.join(audit_summary(report))
        self.assertIn('wymagania 0', text)
        self.assertIn('bez nowego wykonania aplikacji', text)
        self.assertNotIn('/100', text)


if __name__ == '__main__':
    unittest.main()
