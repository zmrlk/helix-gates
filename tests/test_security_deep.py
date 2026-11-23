"""Offline source-only orchestration using real vendored CLI validators."""
import shutil
import copy, importlib.machinery, importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
loader = importlib.machinery.SourceFileLoader('helix_deep_test_cli', str(ROOT / 'bin/helix'))
spec = importlib.util.spec_from_loader(loader.name, loader)
H = importlib.util.module_from_spec(spec); sys.modules[loader.name] = H; loader.exec_module(H)
import helix_security_deep as D
import helix_packs as P


def availability(cfg):
    from datetime import datetime, timezone
    import helix_provider_plan as routing
    return {'models': [dict(provider=p, model=m, family=routing.family(p), status='available',
                            method='short_call', checked_at=datetime.now(timezone.utc).isoformat())
                       for p, m in routing.configured_models(cfg) if p in routing.JSON_PROVIDERS]}


class NormalResources:
    """No machine sampling or waits in source-review unit fixtures."""
    policy = {'max_pause_s': 300}
    history = []
    def decision(self, force=False):
        return dict(state='normal', requested_jobs=64, effective_jobs=64, reason='synthetic', sample={}, thresholds={})
    def wait(self, stop=None):
        if stop: stop()
        return self.decision()


def ledger():
    refs = dict(surface='src/app.py#update', boundary='src/app.py#owner', subsystem='api', attack_class='ATTACK-CLASSES.md#Access control')
    coverage_id = '::'.join(quote(v, safe="~()*!'._-") for v in refs.values())
    return [dict(coverage_id=coverage_id, canonical_refs=refs, surface='Update route', boundary='Ownership', subsystem='API',
        attack_class='Access control', starting_paths=['src/app.py'], ordinary_attack_class_block=refs['attack_class'],
        selected_companion_blocks=[], excluded_blocks=[], prior_status='new', attempts=[], wave=1, status='planned',
        agent_id=None, reviewed_paths=[], local_checks=[], result_fingerprints=[], unresolved=[])]


def record(verdict='needs_validation', fp='app-owner'):
    r = dict(verdict=verdict, fingerprint=fp, title='Ownership', description='Ownership check requires review',
        claimed_root_cause='Update may lack an owner check',
        trace=[dict(kind='entrypoint', file='src/app.py', line=1, scope='update', description='Input enters update')],
        evidence=[dict(file='src/app.py', line=1, description='Update accepts an identifier')])
    if verdict == 'needs_validation': r.update(blockers=['Deployed ownership middleware is unknown'], validation_plan={'local': 'Inspect middleware'})
    elif verdict == 'rejected': r['reason'] = 'Owner check precedes update'
    else:
        r.pop('claimed_root_cause'); r.update(root_cause='Missing owner check', intended_behavior='Only owner can update',
            conditions=[], execution=dict(attacker_perspective='Account owner', payloads=['other id'],
                instructions=['Trace the input through update'], observed_result='Source path has no owner check'),
            remediation={'strategy': 'Require ownership before update'},
            severity=dict(likelihood={'score': 'high', 'reason': 'Reachable'}, impact={'score': 'high', 'reason': 'Other account changes'}, overall_severity='high'),
            confidence={'score': 'high', 'reason': 'Source trace is complete'})
        r['trace'].append(dict(kind='sink', file='src/app.py', line=2, scope='update', description='Object mutation'))
    return r


@unittest.skipUnless(shutil.which("node"), "Node validators unavailable")
class Deep(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / 'target'; self.repo.mkdir()
        (self.repo / 'src').mkdir(); (self.repo / 'src/app.py').write_text('def update():\n    pass\n')
        for cmd in (['git', 'init', '-q'], ['git', 'add', '.'],
                    ['git', '-c', 'user.name=test', '-c', 'user.email=test@test', 'commit', '-qm', 'fixture']):
            subprocess.run(cmd, cwd=self.repo, check=True, capture_output=True)
        self.ctx = SimpleNamespace(repo=self.repo, cfg=copy.deepcopy(H.DEFAULT_CFG))
        self.ctx.cfg['data_egress'] = dict(status='approved', allowed_providers=list(__import__('helix_provider_plan').JSON_PROVIDERS), exclude_paths=[])
        self.ctx.availability = availability(self.ctx.cfg)
        self.ctx.resource_governor = NormalResources()
        self.runs = self.root / 'runs'
        self.addCleanup(patch.stopall)
        patch.object(D, 'H', H).start(); patch.object(D, 'run_root', return_value=self.runs).start()
        self.hunt = dict(architecture_md='# API', coverage_ledger=ledger(), candidates=[record()])
        self.prompts = []

    def args(self, **kw):
        return SimpleNamespace(**(dict(hunter='codex', verifier='grok-cli', profile='quick', scope=None, out=None, max_candidates=8) | kw))

    def providers(self, hunts=None, records=None, fail_grok=False):
        hunts = iter(hunts or [self.hunt]); records = iter(records or [record()])
        def hunter(ctx, model, prompt, images, schema, write, out, timeout):
            self.assertFalse(write); self.prompts.append(('hunter', prompt)); return json.dumps(next(hunts))
        def verifier(ctx, model, prompt, images, schema, write, out, timeout, **kwargs):
            self.assertFalse(write); self.prompts.append(('verifier', prompt)); return json.dumps(next(records))
        patch.object(H, 'call_codex', side_effect=hunter).start()
        patch.object(H, 'call_grok_cli', side_effect=H.ProviderError('offline') if fail_grok else verifier).start()
        patch.object(H, 'call_agy', side_effect=verifier).start()

    def test_real_fixtures_and_mapping(self):
        path = self.root / 'ledger.json'; P.write_json(path, ledger())
        self.assertEqual(D.validate('validate-coverage-ledger.cjs', path), '')
        all_records = [record(v, v) for v in ('confirmed', 'needs_validation', 'rejected')]
        P.write_json(path, all_records); self.assertEqual(D.validate('validate-findings.cjs', path), '')
        mapped = D.map_findings(all_records)
        self.assertEqual([(f['verdict'], f['tag'], f['severity']) for f in mapped],
                         [('confirmed', 'VERIFIED', 'high'), ('needs_validation', 'ASSUMPTION', 'info')])

    def test_output_validators_and_prior_runs(self):
        self.providers(hunts=[self.hunt, self.hunt], records=[record(), record()])
        with patch.object(D, 'validate', wraps=D.validate) as validator:
            first, meta = D.run(self.ctx, self.args())
            second, next_meta = D.run(self.ctx, self.args())
        self.assertFalse(first.is_relative_to(self.repo)); self.assertEqual(first.name, 'run-1'); self.assertEqual(second.name, 'run-2')
        self.assertEqual(next_meta['prior_runs'], [str(first)])
        self.assertIn(str(first), self.prompts[2][1])
        self.assertTrue(any(c.args[0] == 'validate-coverage-ledger.cjs' for c in validator.call_args_list))
        self.assertTrue(any(c.args[0] == 'validate-findings.cjs' for c in validator.call_args_list))
        self.assertEqual(meta['run_status'], 'partial'); self.assertIn('source_ref', meta)
        self.assertIn('scoped/quick = partial coverage', (first / 'REPORT.md').read_text())
        self.assertIn('Deployed ownership middleware is unknown', (first / 'NEEDS-VALIDATION.md').read_text())

    def test_custom_output_index_is_additive(self):
        self.providers(hunts=[self.hunt, self.hunt, self.hunt], records=[record(), record(), record()])
        first, _ = D.run(self.ctx, self.args(out=str(self.root / 'custom-a' / 'audit')))
        second, meta = D.run(self.ctx, self.args(out=str(self.root / 'custom-b' / 'audit')))
        third, meta = D.run(self.ctx, self.args())
        self.assertEqual(set(meta['prior_runs']), {str(first), str(second)})
        self.assertEqual(set(D.prior_runs(self.repo, self.runs)), {first, second, third})

    def test_same_provider_and_inside_output_refused(self):
        _, limited = D.run(self.ctx, self.args(verifier='codex'))
        self.assertEqual(limited['run_status'], 'limited')
        self.assertFalse(limited['provider_attempts'])
        with self.assertRaisesRegex(ValueError, 'poza target'): D.run(self.ctx, self.args(out=str(self.repo / 'out')))
        link = self.root / 'link'; link.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(ValueError): D.output_dir(self.repo, link / 'out')
        self.assertFalse((self.repo / 'out').exists())

    def test_invalid_ledger_reprompt_once(self):
        bad = dict(self.hunt, coverage_ledger={})
        self.providers(hunts=[bad, self.hunt])
        out, meta = D.run(self.ctx, self.args())
        self.assertEqual(sum(role == 'hunter' for role, _ in self.prompts), 2)
        self.assertIn('expected a top-level array', self.prompts[1][1])
        self.assertEqual(P.read_json(out / 'coverage-ledger.json'), ledger())
        self.assertFalse(meta['errors'])

    def test_still_invalid_ledger_keeps_candidates_partial(self):
        bad = dict(self.hunt, coverage_ledger={})
        self.providers(hunts=[bad, bad])
        out, meta = D.run(self.ctx, self.args(profile='standard'))
        self.assertEqual(meta['run_status'], 'partial'); self.assertTrue(meta['errors'])
        self.assertEqual(len(P.read_json(out / 'findings.json')), 1)

    def test_invalid_record_downgrade_and_drop(self):
        bad = record('confirmed'); bad.pop('confidence')
        self.providers(records=[bad, bad])
        out, meta = D.run(self.ctx, self.args())
        result = P.read_json(out / 'findings.json')[0]
        self.assertEqual(result['verdict'], 'needs_validation'); self.assertEqual(result['blockers'], ['schema invalid'])
        self.assertEqual(D.validate('validate-findings.cjs', out / 'findings.json'), '')
        self.assertIn('downgraded', ' '.join(meta['errors']))
        self.providers(records=[{}, {}])
        out, meta = D.run(self.ctx, self.args())
        self.assertEqual(P.read_json(out / 'findings.json'), []); self.assertIn('dropped', ' '.join(meta['errors']))

    def test_failed_verifier_never_silently_changes_provider(self):
        self.providers(hunts=[self.hunt, self.hunt], fail_grok=True)
        out, meta = D.run(self.ctx, self.args())
        self.assertEqual([p['provider'] for p in meta['providers']], ['codex'])
        self.assertEqual(meta['run_status'], 'error')
        with patch.object(H, 'call_grok_cli', side_effect=H.ProviderError('offline')), patch.object(H, 'call_agy', side_effect=H.ProviderError('offline')):
            out, meta = D.run(self.ctx, self.args())
        self.assertIn('no automatic fallback', ' '.join(meta['errors']))
        self.assertEqual(sum(role == 'hunter' for role, _ in self.prompts), 2)

    def test_cap_and_severity_priority(self):
        self.hunt['candidates'] = [record(), record('confirmed')]
        self.providers(records=[record('confirmed')])
        out, meta = D.run(self.ctx, self.args(max_candidates=1))
        self.assertIn('"overall_severity": "high"', self.prompts[1][1])
        self.assertEqual(meta['counts']['confirmed'], 1); self.assertTrue(meta['errors'])

    def test_source_scope_and_credentials_are_not_opened(self):
        (self.repo / '.env').write_text('do not open')
        (self.repo / 'credentials.json').write_text('do not open')
        (self.repo / 'external.py').symlink_to(self.root / 'outside')
        subprocess.run(['git', 'add', '.'], cwd=self.repo, check=True)
        original = Path.read_bytes
        def guarded(path):
            self.assertNotIn(path.name, ('.env', 'credentials.json')); return original(path)
        with patch.object(Path, 'read_bytes', guarded):
            text, omitted = D.source_context(self.repo, ['src'], 'quick')
            self.assertIn('src/app.py', text); self.assertNotIn('do not open', text)
            text, omitted = D.source_context(self.repo, ['.'], 'quick')
            self.assertNotIn('do not open', text)
        with self.assertRaises(ValueError): D.run(self.ctx, self.args(scope=['../outside']))

    def test_pack_verdict_defaults_and_gate(self):
        for tool in ('semgrep', 'trivy', 'osv-scanner', 'bandit'):
            f = P.finding('security', tool, 'hit', 'high', 'Hit')
            self.assertEqual((f['verdict'], f['tag']), ('needs_validation', 'ASSUMPTION'))
        f = P.finding('security', 'gitleaks', 'secret', 'high', 'Secret')
        self.assertEqual(f['verdict'], 'needs_validation')
        cfg = dict(fail_on=['high'], mode='blocking')
        self.assertEqual(P.evaluate('security', [dict(f, verdict='rejected')], cfg, [], False)['exit_code'], 0)
        self.assertEqual(P.evaluate('security', [dict(f, verdict='needs_validation')], cfg, [], False)['exit_code'], 2)

    def test_deep_required_gate(self):
        self.hunt['coverage_ledger'][0].update(status='covered', agent_id='hunter-1', reviewed_paths=['src/app.py'],
            local_checks=[dict(agent_id='hunter-1', reviewed_paths=['src/app.py'], invariant='Ownership required', method='source', result='Source reviewed', artifact=None)])
        self.providers(records=[record('confirmed')])
        out, meta = D.run(self.ctx, self.args(profile='standard'))
        (self.repo / 'helix.json').write_text(json.dumps({'packs': {'security': {'tools': [], 'deep_required': True}}}))
        args = SimpleNamespace(which='security', checkpoint=None, out=str(self.root / 'gate'), trusted_base=False)
        with self.assertRaises(SystemExit) as result: P.gate_pack(self.ctx, args)
        self.assertEqual(result.exception.code, 2)
        self.assertEqual(P.read_json(self.root / 'gate/gate.json')['status'], 'FAIL')
        self.assertIn('**FAIL**', (self.root / 'gate/report.md').read_text())
        (self.repo / 'helix.json').write_text(json.dumps({'packs': {'security': {'tools': []}}}))
        with self.assertRaises(SystemExit) as result: P.gate_pack(self.ctx, args)
        self.assertEqual(result.exception.code, 0)
        (self.repo / 'helix.json').write_text(json.dumps({'packs': {'security': {'tools': [], 'deep_required': True}}}))
        (out / 'helix-findings.json').unlink()
        with self.assertRaises(SystemExit) as result: P.gate_pack(self.ctx, args)
        self.assertEqual(result.exception.code, 3)


if __name__ == '__main__': unittest.main()
