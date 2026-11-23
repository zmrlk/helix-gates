"""Kontrakty ledgeru, runnera i historii; wszystkie dane syntetyczne/offline."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_requirements as req

FIX = ROOT / 'tests/fixtures/requirements'


class RequirementsLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.ledger = self.repo / 'ledger.json'

    def write(self, data):
        self.ledger.write_text(json.dumps(data))
        return self.ledger

    def fixture(self, name='valid'):
        return req.load(FIX / (name + '.json'))

    def check(self, data=None, **kw):
        if data is not None:
            self.write(data)
        return req.check(ROOT, self.ledger, **kw)

    def cli(self, *args, repo=ROOT):
        return subprocess.run([sys.executable, str(ROOT / 'bin/helix'), '--repo', str(repo), 'requirements', *args, '--baseline', str(FIX / 'valid.json')], capture_output=True, text=True)

    def test_real_ledger(self):
        result = req.check(ROOT, ROOT / 'requirements/ledger.json', ROOT / 'requirements/baseline.json')
        self.assertTrue(result['pass'], result['errors'])
        data = req.load(ROOT / 'requirements/ledger.json')['requirements']
        self.assertGreaterEqual(len(data), 1)
        self.assertEqual(len({r['id'] for r in data}), len(data))
        self.assertEqual(result['execution_status'], 'not-run')

    def test_add_polish_long_quote_and_missing_field(self):
        self.write(self.fixture())
        quote = 'Senior team, critical: żółć, czytelność, dziewięć ról. ' * 120
        fields = ['--group', 'T', '--text', 'Zespół seniorów, krytyczny', '--source', 'statement:1', '--quote', quote, '--acceptance', 'Dziewięć ról ma dowody']
        result = self.cli('add', '--ledger', str(self.ledger), *fields)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(req.load(self.ledger)['requirements'][-1]['sources'][0]['quote'], quote)
        before = self.ledger.read_bytes()
        result = self.cli('add', '--ledger', str(self.ledger), *fields[:-2])
        self.assertEqual(result.returncode, 2)
        self.assertIn('--acceptance', result.stderr)
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_valid_fixture(self):
        result = self.check(self.fixture())
        self.assertTrue(result['pass'], result)
        self.assertEqual(result['covered'], 1)

    def test_negative_fixtures(self):
        for name in ('must-without-acceptance', 'done-without-test', 'nonexistent-test'):
            with self.subTest(name=name):
                self.assertFalse(self.check(self.fixture(name))['pass'])

    def test_schema_types_and_unknown_fields(self):
        for key, value in [('priority','HIGH'), ('status','PASS'), ('tests','bad'), ('sources',[]), ('group','AA'), ('text',''), ('unknown',1)]:
            data = self.fixture(); data['requirements'][0][key] = value
            with self.subTest(key=key):
                self.assertFalse(self.check(data)['pass'])

    def test_schema_version_bool_and_empty(self):
        for data in ({}, {'schema_version': True, 'requirements': []}, {'schema_version': 1, 'requirements': []}):
            self.assertFalse(self.check(data)['pass'])

    def test_duplicate_ids_and_group(self):
        data = self.fixture();data['requirements'] *= 2
        self.assertFalse(self.check(data)['pass'])
        data = self.fixture();data['requirements'][0]['group'] = 'B'
        self.assertFalse(self.check(data)['pass'])

    def test_pending_must_is_debt(self):
        data = self.fixture();item = data['requirements'][0]
        item.update(status='missing', tests=[])
        result = self.check(data)
        self.assertTrue(result['pass']); self.assertEqual(result['missing'], 1)
        self.assertEqual(result['debt'][0]['id'], item['id'])
        self.assertEqual(result['covered'], 0)

    def test_status_regression_fixture(self):
        result = self.check(self.fixture('regression'), baseline=FIX / 'valid.json')
        self.assertFalse(result['pass'])
        self.assertIn('regresja', result['errors'][0])

    def test_coverage_loss_even_when_status_same(self):
        data = self.fixture();data['requirements'][0].update(status='partial',tests=[])
        baseline = self.repo / 'base.json';old = self.fixture();old['requirements'][0]['status'] = 'partial'
        baseline.write_text(json.dumps(old))
        self.assertFalse(self.check(data, baseline=baseline)['pass'])

    def test_waiver_fixture(self):
        self.assertTrue(self.check(self.fixture('waiver'), baseline=FIX / 'valid.json')['pass'])

    def test_invalid_waiver_cannot_hide_regression(self):
        for waiver in ({'owner':'Agent','reason':'Owner pending','date':'2026-10-25'}, {'owner':'Owner','reason':'','date':'2026-10-25'}, {'owner':'Owner','reason':'Migration','date':'not-date'}, {'owner':'Owner','reason':'Migration','date':'2999-01-01'}):
            data = self.fixture('waiver');data['requirements'][0]['waiver'] = waiver
            self.assertFalse(self.check(data, baseline=FIX / 'valid.json')['pass'])

    def test_removed_id_requires_explicit_waiver(self):
        data = self.fixture(); data['requirements'][0]['id'] = 'REQ-A-02'
        self.assertFalse(self.check(data, baseline=FIX / 'valid.json')['pass'])
        data['waivers'] = {'REQ-A-01': {'owner':'Owner','reason':'Merged into REQ-A-02','date':'2026-10-25'}}
        self.assertTrue(self.check(data, baseline=FIX / 'valid.json')['pass'])

    def test_baseline_missing_is_error(self):
        self.assertFalse(self.check(self.fixture(), baseline=self.repo / 'absent.json')['pass'])

    def test_static_validation_never_imports(self):
        (self.repo / 'test_local.py').write_text("raise RuntimeError('must not import')\nclass Example:\n def test_ok(self): pass\n")
        req.target(self.repo, 'test_local.py::Example.test_ok')
        for mapping in ('test_local.py::Absent.test_ok', 'test_local.py::Example.test_absent', '../test_local.py::Example.test_ok'):
            with self.assertRaises((ValueError, OSError)):
                req.target(self.repo, mapping)

    def test_static_symlinks_rejected(self):
        (self.repo / 'real.py').write_text('class T:\n def test_ok(self): pass\n')
        (self.repo / 'link.py').symlink_to(self.repo / 'real.py')
        with self.assertRaises(ValueError): req.target(self.repo, 'link.py::T.test_ok')

    def runner_file(self, body):
        (self.repo / 'test_local.py').write_text('import unittest\nclass Local(unittest.TestCase):\n' + body)
        return 'test_local.py::Local.test_result'

    def test_runner_pass_fail_skip_expected_failure(self):
        for body, expected in [(' def test_result(self): self.assertEqual(2+2,4)\n',True), (' def test_result(self): self.fail()\n',False), (' @unittest.skip("synthetic")\n def test_result(self): pass\n',False), (' @unittest.expectedFailure\n def test_result(self): self.fail()\n',False)]:
            mapping = self.runner_file(body)
            self.assertEqual(req.run_test(self.repo, mapping)['passed'], expected)

    def test_runner_timeout(self):
        mapping = self.runner_file(' def test_result(self):\n  import time\n  time.sleep(2)\n')
        self.assertEqual(req.run_test(self.repo, mapping, timeout=.1)['reason'], 'timeout')

    def test_runner_zero_or_missing_result(self):
        mapping = self.runner_file(' def test_result(self): pass\n')
        fake = subprocess.CompletedProcess([],0,'Ran 0 tests\nOK','')
        with patch.object(req.subprocess, 'run', return_value=fake):
            self.assertFalse(req.run_test(self.repo,mapping)['passed'])

    def test_runner_no_credential_environment(self):
        mapping = self.runner_file(' def test_result(self):\n  import os\n  self.assertNotIn("SYNTHETIC_TOKEN",os.environ)\n')
        with patch.dict('os.environ', {'SYNTHETIC_TOKEN':'synthetic-value'}):
            self.assertTrue(req.run_test(self.repo,mapping)['passed'])

    def test_run_attributes_failure_to_requirement(self):
        data = self.fixture()
        with patch.object(req, 'run_test', return_value={'passed':False}):
            result = self.check(data,run=True)
        self.assertFalse(result['pass']);self.assertIn('REQ-A-01',result['errors'][0])

    def test_run_validates_before_execution(self):
        with patch.object(req, 'run_test') as run:
            result = self.check(self.fixture('nonexistent-test'),run=True)
        run.assert_not_called();self.assertFalse(result['pass'])

    def test_secret_values_rejected_without_echo(self):
        candidates = ['gh'+'p_'+'a'*30, 'sk-'+'b'*30, 'password='+'x'*16, 'https://person:synthetic@host.invalid', '{"api_key":"'+'z'*24+'"}']
        for secret in candidates:
            data = self.fixture();data['requirements'][0]['text'] = secret
            result = self.check(data)
            self.assertFalse(result['pass']); self.assertNotIn(secret, json.dumps(result))

    def test_cli_add_id_and_report_json(self):
        self.write(self.fixture())
        result = self.cli('add','--ledger',str(self.ledger),'--group','A','--text','Nowe wymaganie','--source','docs/owner-statements/001.md:1','--quote','Wymagane sprawdzenie','--acceptance','Brak dokumentu daje FAIL')
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('REQ-A-02',result.stdout)
        result = self.cli('report','--ledger',str(self.ledger),'--json')
        self.assertEqual(result.returncode,0,result.stdout)
        self.assertEqual(len(json.loads(result.stdout)['debt']),1)
        report = self.cli('report','--ledger',str(self.ledger))
        self.assertIn('| wynik |',report.stdout);self.assertIn('REQ-A-02',report.stdout)

    def test_add_secret_does_not_write(self):
        self.write(self.fixture());before = self.ledger.read_bytes()
        result = self.cli('add','--ledger',str(self.ledger),'--group','A','--text','password='+'x'*20,'--source','statement:1','--quote','Synthetic quote','--acceptance','Reject')
        self.assertEqual(result.returncode,2);self.assertEqual(before,self.ledger.read_bytes())

    def test_cli_json_and_bad_json(self):
        self.write(self.fixture())
        result = self.cli('check','--ledger',str(self.ledger))
        self.assertEqual(result.returncode,0,result.stdout)
        self.ledger.write_text('{bad')
        result = self.cli('check','--ledger',str(self.ledger),'--json')
        self.assertEqual(result.returncode,2);self.assertFalse(json.loads(result.stdout)['pass'])

    def git(self,*args):
        p = subprocess.run(['git',*args],cwd=self.repo,capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        return p.stdout.strip()

    def init_git(self):
        if not shutil.which('git'): self.skipTest('brak gita')
        self.git('init','-q');self.git('config','user.name','Fixture');self.git('config','user.email','fixture@example.test')
        self.write(self.fixture());self.git('add','.');self.git('commit','-qm','initial')
        return self.git('rev-parse','HEAD')

    def test_owner_statement_commit_requires_same_commit_ledger(self):
        base = self.init_git();docs = self.repo / 'docs/owner-statements';docs.mkdir(parents=True)
        (docs/'001.md').write_text('Synthetic requirement')
        self.git('add','.');self.git('commit','-qm','statement')
        with self.assertRaises(ValueError):req.touch_check(self.repo,base,self.ledger)
        self.ledger.write_text(self.ledger.read_text()+'\n');self.git('add','.');self.git('commit','-qm','late ledger')
        with self.assertRaises(ValueError):req.touch_check(self.repo,base,self.ledger)

    def test_owner_trailer_and_success(self):
        base = self.init_git();(self.repo/'file.txt').write_text('Synthetic')
        self.git('add','.');self.git('commit','-qm','change\n\nOwner-Statement: statement-001')
        with self.assertRaises(ValueError):req.touch_check(self.repo,base,self.ledger)
        base = self.git('rev-parse','HEAD')
        self.ledger.write_text(self.ledger.read_text()+'\n');self.git('add','.');self.git('commit','-qm','change\n\nOwner-Statement: statement-002')
        req.touch_check(self.repo,base,self.ledger)

    def test_worktree_statement_and_invalid_reference(self):
        base = self.init_git();doc = self.repo/'docs/owner-statements.md';doc.parent.mkdir();doc.write_text('Synthetic')
        with self.assertRaises(ValueError):req.touch_check(self.repo,base,self.ledger)
        self.ledger.write_text(self.ledger.read_text()+'\n')
        req.touch_check(self.repo,base,self.ledger)
        for since in (None,'--all','missing-ref'):
            with self.assertRaises(ValueError):req.touch_check(self.repo,since,self.ledger)

    def test_discovery_three_test_patterns(self):
        import helix_new
        for name in ('one.spec.ts','two.sprawdz.mjs','three.test.ts'):
            p = self.repo / 'tests' / name;p.parent.mkdir(exist_ok=True);p.write_text('assert(true);')
        # audit odmawia zapisu w target; output w osobnym tmp.
        with tempfile.TemporaryDirectory() as output:
            helix_new.audit(self.repo,Path(output),'S')
            inventory = req.load(Path(output)/'audit.json')['inventory']
        discovered = [r for r in inventory if 'tests' in r['categories']]
        self.assertEqual(len(discovered),3,inventory)


if __name__ == '__main__':
    unittest.main()
