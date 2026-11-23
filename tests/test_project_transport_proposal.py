"""HTTPS proposals from supplied snapshots, without runtime or target writes."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_config
import helix_new
import helix_project_proposal as proposal
import helix_runtime_integrations as integrations_module
import helix_runtime_transport as transport_module
import helix_source_coverage


class ProjectTransportProposalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'target'
        self.repo.mkdir()
        self.out = self.base / 'out'
        self.addCleanup(helix_config._overrides.clear)

    def sources(self, body="cookies.set('sid', value, {secure: true});"):
        return {'app/package.json': '{"scripts":{"start":"node app.js"}}', 'app/src/auth.ts': body}

    def pure(self, sources, explicit=None, **kwargs):
        explicit = explicit or {}
        config = copy.deepcopy(explicit)
        result = proposal.propose_transport(sources, kwargs.pop('parts', None), kwargs.pop('integrations', None),
                                             explicit, config, kwargs.pop('source_coverage', {'status': 'COMPLETE'}))
        self.assertFalse(kwargs)
        return result, config

    def put(self, sources):
        for name, content in sources.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def test_secure_cookie_adds_external_proposal_and_keeps_observed_http(self):
        result, config = self.pure(self.sources())
        self.assertEqual(config['runtime']['https'], {'enabled': True})
        self.assertTrue(result['proposal_applied'])
        self.assertEqual(result['observed']['parts'][0]['selected'], 'http')
        self.assertEqual(result['proposed']['parts'][0]['selected'], 'https')
        self.assertEqual(result['observed']['parts'][0]['requirements'][0]['path'], 'app/src/auth.ts')
        self.assertEqual(result['observed']['parts'][0]['requirements'][0]['line'], 1)
        self.assertNotEqual(result['observed']['plan_id'], result['proposed']['plan_id'])
        self.assertEqual(result['execution'], 'not_run')
        self.assertEqual(result['proposed']['parts'][0]['execution'], 'not_run')
        self.assertEqual(result['proposed']['execution']['application'], False)

    def test_explicit_false_true_and_host_are_preserved_without_mutation(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                explicit = {'runtime': {'https': {'enabled': enabled, 'public_host': '127.0.0.1'}, 'custom': 7}, 'custom': True}
                original = copy.deepcopy(explicit)
                result, config = self.pure(self.sources(), explicit)
                self.assertEqual(config, original)
                self.assertEqual(explicit, original)
                self.assertFalse(result['proposal_applied'])
                self.assertEqual(result['observed'], result['proposed'])
                self.assertEqual(result['observed']['parts'][0]['selection'], 'explicit')
                self.assertEqual(result['status'], 'PLANNED' if enabled else 'INCOMPLETE')

    def test_existing_host_preserved_when_enabled_is_missing(self):
        explicit = {'runtime': {'https': {'public_host': '127.0.0.1'}}}
        result, config = self.pure(self.sources('navigator.credentials.create({publicKey: options});'), explicit)
        self.assertEqual(config['runtime']['https'], {'public_host': '127.0.0.1', 'enabled': True})
        self.assertEqual(explicit['runtime']['https'], {'public_host': '127.0.0.1'})
        self.assertIn('webauthn_rp_host', [gap['kind'] for gap in result['proposed']['parts'][0]['gaps']])
        self.assertEqual(result['status'], 'INCOMPLETE')

    def test_no_requirement_or_only_dynamic_candidates_does_not_enable_https(self):
        for body in ("const options={secure:true};", "cookies.set('sid', token, options);", "res.cookie('sid',token,{secure:true});"):
            with self.subTest(body=body):
                result, config = self.pure(self.sources(body))
                self.assertNotIn('runtime', config)
                self.assertFalse(result['proposal_applied'])
                self.assertFalse(result['observed']['parts'][0]['https_needed'])
        result, _ = self.pure(self.sources("cookies.set('sid', token, options);"))
        self.assertEqual(result['status'], 'INCOMPLETE')

    def test_docs_tests_legacy_real_env_and_literals_do_not_enable_https(self):
        sources = self.sources('const text="cookies.set(\'sid\', token, {secure:true})";')
        sources.update({'docs/auth.md': 'navigator.credentials.create({publicKey: options});',
                        'app/legacy/old.ts': "import Keycloak from 'keycloak-js';",
                        'app/tests/auth.ts': "cookies.set('sid', token, {secure:true});",
                        'app/.env': 'KEYCLOAK_SECRET=PRIVATE_CANARY'})
        result, config = self.pure(sources)
        self.assertFalse(result['proposal_applied']); self.assertNotIn('runtime', config)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        self.assertEqual(len(result['observed']['parts']), 1)

    def test_monorepo_scopes_and_locations_survive_global_https_proposal(self):
        sources = {'apps/console/package.json': '{}', 'apps/store/package.json': '{}',
                   'apps/console/auth.ts': "\nimport Keycloak from 'keycloak-js';",
                   'apps/store/main.ts': 'export const value=1;'}
        result, _ = self.pure(sources)
        parts = {part['part']: part for part in result['observed']['parts']}
        self.assertTrue(parts['apps/console']['https_needed'])
        self.assertFalse(parts['apps/store']['https_needed'])
        self.assertEqual(parts['apps/console']['requirements'][0]['line'], 2)
        self.assertEqual({part['selected'] for part in result['proposed']['parts']}, {'https'})
        self.assertEqual(result['parts_basis'], 'manifest_source_scopes')

    def test_supplied_snapshots_reused_without_scans_processes_or_mutation(self):
        sources = self.sources()
        parts = [{'path': 'app'}]
        inventory = integrations_module.inventory(sources, parts)
        original = copy.deepcopy((sources, parts, inventory))
        with mock.patch('helix_runtime_integrations.inventory', side_effect=AssertionError('recomputed supplied inventory')), \
             mock.patch('helix_runtime.plan', side_effect=AssertionError('runtime plan called')), \
             mock.patch('helix_source_coverage.scan', side_effect=AssertionError('source scan called')), \
             mock.patch('builtins.open', side_effect=AssertionError('file opened')), \
             mock.patch('subprocess.run', side_effect=AssertionError('process called')), \
             mock.patch('socket.socket', side_effect=AssertionError('network called')), \
             mock.patch.object(transport_module, 'transport_plan', wraps=transport_module.transport_plan) as planner:
            result, _ = self.pure(sources, parts=parts, integrations=inventory)
        self.assertEqual(planner.call_count, 2)
        for call in planner.call_args_list:
            self.assertIs(call.args[0], sources); self.assertIs(call.args[1], parts); self.assertIs(call.args[2], inventory)
        self.assertEqual((sources, parts, inventory), original)
        self.assertEqual(result['parts_basis'], 'provided_source_scopes')

    def test_missing_snapshot_is_not_recorded_and_does_not_scan(self):
        with mock.patch('helix_source_coverage.scan', side_effect=AssertionError('scan called')), \
             mock.patch('helix_runtime.plan', side_effect=AssertionError('runtime plan called')):
            result, config = self.pure(None, {'runtime': {'https': {'enabled': False}}})
        self.assertEqual(result['status'], 'NOT_RECORDED')
        self.assertIsNone(result['observed']); self.assertIsNone(result['proposed'])
        self.assertFalse(config['runtime']['https']['enabled'])
        self.assertIn('nie zostały sprawdzone', '\n'.join(proposal.transport_markdown(result)))

    def test_missing_manifest_and_incomplete_coverage_are_explicit_gaps(self):
        result, config = self.pure({'src/auth.py': 'SESSION_COOKIE_SECURE = True'}, source_coverage={'status': 'INCOMPLETE'})
        self.assertTrue(config['runtime']['https']['enabled'])
        self.assertEqual(result['parts_basis'], 'repository_source_scope_assumption')
        self.assertEqual(result['source_coverage_status'], 'INCOMPLETE')
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertTrue(any('manifestów' in gap for gap in result['gaps']))
        self.assertTrue(any('odczytu' in gap for gap in result['gaps']))

    def test_markdown_polish_distinguishes_requirement_proposal_and_no_execution(self):
        result, _ = self.pure(self.sources())
        text = '\n'.join(proposal.transport_markdown(result))
        for term in ('Obecny wybór', 'Proponowany wybór', 'app/src/auth.ts:1', 'runtime.https.enabled=true',
                     'nie zaliczają logowania', 'nie uruchomiono', 'SameSite', 'WebSocket'):
            self.assertIn(term, text)
        self.assertNotIn('/100', text); self.assertNotIn('PASS', text)

    def test_generate_external_config_and_reports_preserve_target(self):
        sources = self.sources("cookies.set('__Host-secret-name', 'PRIVATE_CANARY', {secure: true});")
        self.put(sources)
        explicit = {'runtime': {'database': {'engine': 'postgres', 'major': 16}}, 'custom': {'owner': True}}
        cfg = self.base / 'config.json'; cfg.write_text(json.dumps(explicit))
        helix_config.configure(self.repo, cfg)
        before = {str(path.relative_to(self.repo)): path.read_bytes() for path in self.repo.rglob('*') if path.is_file()}
        with mock.patch('helix_runtime.plan', side_effect=AssertionError('runtime plan called')), \
             mock.patch('helix_runtime.Runner.run', side_effect=AssertionError('runtime called')), \
             mock.patch('helix_security_deep.ask', side_effect=AssertionError('model called')), \
             mock.patch('helix_environment.local_tool', side_effect=AssertionError('probe called')):
            data = proposal.generate(self.repo, self.out, sources=sources, source_coverage={'status': 'COMPLETE'}, offline=True)
        config = json.loads((self.out / 'helix.proposed.json').read_text())
        self.assertTrue(config['runtime']['https']['enabled'])
        self.assertEqual(config['runtime']['database'], explicit['runtime']['database'])
        self.assertEqual(helix_config.load(self.repo), explicit)
        self.assertEqual(before, {str(path.relative_to(self.repo)): path.read_bytes() for path in self.repo.rglob('*') if path.is_file()})
        self.assertFalse(data['execution']['application']); self.assertEqual(data['execution']['models'], 0)
        self.assertEqual(data['provenance']['models'], [])
        outputs = (self.out / 'NEW-REPORT.md').read_text() + (self.out / 'project-proposal.json').read_text()
        self.assertNotIn('PRIVATE_CANARY', outputs); self.assertNotIn('__Host-secret-name', outputs)

    def test_new_audit_passes_already_read_sources_and_coverage(self):
        self.put(self.sources())
        scans = []
        original_scan, original_generate = helix_source_coverage.scan, proposal.generate
        def scan_sources(*args, **kwargs):
            value = original_scan(*args, **kwargs)
            scans.append(value)
            return value
        def from_snapshot(*args, **kwargs):
            self.assertIs(kwargs['sources'], scans[0][0])
            self.assertIs(kwargs['source_coverage'], scans[0][1])
            # Older audit assessments still own their reads; this added proposal
            # must not repeat any of them or build another runtime source map.
            with mock.patch('helix_source_coverage.scan', side_effect=AssertionError('proposal reread sources')):
                return original_generate(*args, **kwargs)
        with mock.patch('helix_source_coverage.scan', side_effect=scan_sources), \
             mock.patch.object(proposal, 'generate', side_effect=from_snapshot) as generate, \
             mock.patch('helix_runtime.plan', side_effect=AssertionError('runtime plan called')), \
             mock.patch('helix_runtime.Runner.run', side_effect=AssertionError('runtime called')), \
             mock.patch('helix_security_deep.ask', side_effect=AssertionError('model called')):
            helix_new.audit(self.repo, self.out, profile='S', offline=True, probe=False)
        self.assertEqual(generate.call_count, 1)
        self.assertEqual(generate.call_args.kwargs['sources'], self.sources())
        self.assertIn('status', generate.call_args.kwargs['source_coverage'])
        data = json.loads((self.out / 'project-proposal.json').read_text())
        self.assertTrue(data['transport']['proposal_applied'])
        self.assertFalse((self.repo / 'helix.json').exists())


if __name__ == '__main__':
    unittest.main()
