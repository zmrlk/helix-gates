"""Cheap enforceable CI invariants, also used by pre-push."""
from pathlib import Path
import re
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class CIContract(unittest.TestCase):
    def test_every_ci_platform_has_approved_pins_and_no_privileged_trigger(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        triggers = workflow.get('on', workflow.get(True))
        self.assertEqual(set(triggers), {'push', 'pull_request', 'workflow_dispatch'})
        self.assertEqual(workflow['permissions'], {})
        job = workflow['jobs']['tests']
        # A runner without an approved wheel lock is always red; only pinned platforms belong in the matrix.
        pins = {'macos-latest': 'darwin-arm64', 'ubuntu-latest': 'linux-x86_64'}
        matrix = job['strategy']['matrix']['os']
        self.assertIn('macos-latest', matrix)
        for runner in matrix:
            self.assertTrue((ROOT / 'data/tool-pins' / pins[runner]).is_dir(), runner)
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertLessEqual(job['timeout-minutes'], 15)
        for step in job['steps']:
            if 'uses' in step:
                self.assertRegex(step['uses'], r'^[\w/-]+@[0-9a-f]{40}$')
            if step.get('uses', '').startswith('actions/checkout@'):
                self.assertIs(step['with']['persist-credentials'], False)
            self.assertNotIn('${{', step.get('run', ''))
        commands = '\n'.join(s.get('run', '') for s in job['steps'])
        for command in ('zizmor --offline --pedantic', 'semgrep --test', 'run_tests_parallel.py', 'requirements check', 'new audit'):
            self.assertIn(command, commands)

    def test_rules_focus_dangerous_argument_and_do_not_claim_sanitizers(self):
        rules = yaml.safe_load((ROOT / 'config/tools/semgrep.yml').read_text())['rules']
        taint = [r for r in rules if r.get('mode') == 'taint']
        self.assertEqual({r['id'] for r in taint}, {'helix-sveltekit-taint-' + s for s in ('sql', 'fetch', 'fs')})
        for rule in taint:
            self.assertNotIn('pattern-sanitizers', rule)
            for sink in rule['pattern-sinks']:
                self.assertIn({'focus-metavariable': '$SINK'}, sink['patterns'])

    def test_hook_runs_bounded_gate_without_installing_itself(self):
        hook = ROOT / '.githooks/pre-push'
        self.assertTrue(hook.stat().st_mode & 0o111)
        self.assertIn('exec python3 scripts/check_fast.py', hook.read_text())
        script = (ROOT / 'scripts/check_fast.py').read_text()
        self.assertNotIn('run_tests_parallel.py', script)
        self.assertNotIn('pip install', script)
