"""Offline neutral field contract regression tests."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_contracts import VERSION, validate

class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'proof').write_text('retained test output / tree / screenshot')
        self.run = dict(status='passed', exit=0, who='host', where='local', sha='source-revision', command='unittest', log='proof', tree='proof')
        self.data = dict(helix_version=VERSION,
            decisions=[dict(number=1, executors=['worker'], acknowledged=['worker'], test='test_rule', run=self.run)],
            merge=dict(conflicts=[], resolutions=[]), runs=[self.run], rule_changes=[],
            budget=dict(rules=[], shards=1), registry=[dict(id='C1', prefix='C', type='component', reserved_by='worker')],
            domain=dict(mechanisms={'M1':['P1']}, patterns={'P1':['C1']}, components={'C1':['I1']}, industries={'I1':[]}),
            catalog=[], modules=[], comparisons=[],
            owner_report=dict(state='review', current='proof', obsolete=[], gates={}, decisions=[]),
            documentation=[dict(owner='maintainer', path='proof', reviewed='2000-01-01', code=[])])
    def result(self, **kw):
        return validate(self.root, dict(self.data, **kw))
    def fails(self, **kw): self.assertEqual(self.result(**kw)['status'], 'FAIL')
    def passes(self, **kw): self.assertEqual(self.result(**kw)['status'], 'PASS')
    def test_decisions(self):
        d = dict(number=1, executors=['worker'], acknowledged=['worker'], test='test_rule', run=self.run)
        self.passes(decisions=[d])
        self.fails(decisions=[dict(d, test='')])
        self.fails(decisions=[dict(d, acknowledged=[])])
        self.fails(decisions=[d, d])
    def test_merge(self):
        r = dict(conflict='file:1', choice='ours', reason='preserve validated behavior', reviewer='reviewer', ui=True, before='proof', after='proof')
        self.passes(merge=dict(conflicts=['file:1'], resolutions=[r]))
        self.fails(merge=dict(conflicts=['file:1'], resolutions=[]))
        self.fails(merge=dict(conflicts=['file:1'], resolutions=[dict(r, reason='')]))
        self.fails(merge=dict(conflicts=['file:1'], resolutions=[dict(r, before='missing')]))
    def test_host_execution(self):
        self.passes(runs=[self.run])
        r = dict(self.run, status='unexecuted')
        self.assertEqual(self.result(runs=[r])['points'], 0)
        self.fails(runs=[dict(self.run, tree='missing')])
        self.fails(runs=[dict(self.run, who='')])
    def test_rule_changes(self):
        r = dict(id='R1', reason='correct measurement', bad_case='regression fixture', self_test=self.run)
        self.passes(rule_changes=[r])
        self.fails(rule_changes=[dict(r, reason='')])
        self.fails(rule_changes=[dict(r, self_test={})])
    def test_budget(self):
        rules = [dict(id='R1', component='button', seconds=3, limit=2), dict(id='R2', component='panel', seconds=1, limit=2)]
        r = self.result(budget=dict(rules=rules, components={'button':2}, shards=2, fast=True, affected=['button']))
        self.assertEqual(len(r['warnings']), 2)
        self.assertEqual(r['batches'], [[rules[0]], []])
        self.fails(budget=dict(shards=0))
    def test_registry(self):
        r = dict(id='C1', prefix='C', type='component', reserved_by='worker')
        self.passes(registry=[r])
        self.fails(registry=[r, r])
        self.fails(registry=[r, dict(r, id='C2', type='pattern')])
    def test_domain(self):
        d = dict(mechanisms={'M1':['P1','P2']}, patterns={'P1':['C1'], 'P2':['C1']}, components={'C1':['I1']}, industries={'I1':[]})
        self.passes(domain=d)
        self.fails(domain=dict(d, patterns={'P1':[], 'P2':['C2']}))
    def test_configurable_product(self):
        axes = dict(theme=['light','dark'], radius=[0], shape=['round'], density=['compact'])
        cases = [dict(config=dict(theme=t, radius=0, shape='round', density='compact'), run=self.run, contrast_passed=True) for t in axes['theme']]
        self.passes(product=dict(axes=axes, cases=cases))
        self.fails(product=dict(axes=axes, cases=cases[:1]))
        self.fails(product=dict(axes=axes, cases=[dict(c, contrast_passed=False) for c in cases]))
    def test_ai_modules(self):
        m = dict(components=['button'], gates={g:self.run for g in ('contract','tests','permissions','appearance')})
        self.passes(catalog=['button'], modules=[m])
        self.fails(catalog=[], modules=[m])
        self.fails(catalog=['button'], modules=[dict(m, gates={})])
    def test_owner_report(self):
        r = dict(state='review', current='proof', obsolete=['old'], screenshots=['proof'], gates={}, decisions=[])
        self.passes(owner_report=r)
        self.fails(owner_report=dict(r, current=['proof','old']))
        self.fails(owner_report=dict(r, obsolete=['proof']))
    def test_version(self):
        self.passes(comparisons=[dict(before_version=VERSION, after_version=VERSION)])
        self.fails(comparisons=[dict(before_version='old', after_version=VERSION)])
        self.assertEqual(validate(self.root, {})['status'], 'FAIL')
    def test_documentation(self):
        d = dict(owner='maintainer', path='proof', reviewed='2000-01-01', code=['proof'])
        self.assertTrue(self.result(documentation=[d])['warnings'])
        self.fails(documentation=[dict(d, owner='')])
        self.fails(documentation=[dict(d, reviewed='invalid')])
    def test_cli_offline_and_project_pin(self):
        import subprocess
        cli = Path(__file__).resolve().parents[1] / 'bin/helix'
        (self.root / 'helix-contracts.json').write_text(json.dumps(self.data))
        cmd = [sys.executable, str(cli), '--repo', str(self.root), 'contracts', '--out', str(self.root / 'report.json')]
        self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)
        (self.root / 'helix.json').write_text(json.dumps(self.data))
        self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(cmd + ['--profile', 'configurable-product'], capture_output=True).returncode, 2)
        merge = dict(self.data, merge=dict(conflicts=['file:1'], resolutions=[dict(conflict='file:1', choice='manual', reviewer='reviewer', reason='retain behavior')]))
        (self.root / 'helix-contracts.json').write_text(json.dumps(merge))
        self.assertEqual(subprocess.run([*cmd[:4], 'merge-audit', *cmd[5:]], capture_output=True).returncode, 0)
        owner = dict(self.data, owner_report=dict(state='review', current='proof', gates={}, decisions=[], obsolete=['old']))
        (self.root / 'helix-contracts.json').write_text(json.dumps(owner))
        self.assertEqual(subprocess.run([*cmd[:4], 'owner-report', '--input', 'helix-contracts.json', *cmd[5:]], capture_output=True).returncode, 0)
        self.assertIn('Obsolete', (self.root / 'report.json').read_text())
