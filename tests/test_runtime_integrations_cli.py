"""Offline inventory binds external configuration to --project, not caller cwd."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_provider_plan import load_helix
import helix_config
import helix_runtime


class RuntimeInventoryCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.project = self.root / 'target'; self.project.mkdir()
        self.config = self.root / 'proposal.json'
        self.config.write_text(json.dumps({'helix_version':'0.0.0', 'runtime':{'integration_fixture':'external'}}))
        self.cli = load_helix()

    def main(self, args):
        with patch.object(sys, 'argv', ['helix', '--offline', '--config', str(self.config), *args]), \
             patch.object(self.cli, 'Ctx', side_effect=AssertionError('runtime inventory must not create model context')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exit:
                self.cli.main()
        return exit.exception.code, output.getvalue()

    def test_offline_plan_binds_config_to_project_without_explicit_repo(self):
        observed = []
        def dispatch(args):
            observed.append((args.repo, args.project, helix_config.load(args.project)))
            return 0
        with patch.object(helix_runtime, 'dispatch', side_effect=dispatch):
            code, _ = self.main(['runtime','plan','--project',str(self.project),'--json'])
        self.assertEqual(code, 0)
        self.assertEqual(observed[0][:2], (str(self.project), str(self.project)))
        self.assertEqual(observed[0][2]['runtime']['integration_fixture'], 'external')
        self.assertEqual(list(self.project.iterdir()), [])

    def test_readonly_runtime_actions_are_available_offline(self):
        for args in (['runtime','doctor','--json'], ['runtime','ci-template']):
            with self.subTest(args=args), patch.object(helix_runtime,'dispatch',return_value=0) as dispatch:
                code, _ = self.main(args)
            self.assertEqual(code,0); dispatch.assert_called_once()

    def test_offline_still_blocks_code_execution_before_dispatch(self):
        cases = [['runtime','run','--project',str(self.project),'--out',str(self.root/'out')],
                 ['runtime','mutation','--project',str(self.project),'--tool','mutmut']]
        for args in cases:
            with self.subTest(args=args), patch.object(helix_runtime,'dispatch') as dispatch, contextlib.redirect_stderr(io.StringIO()):
                code, _ = self.main(args)
            self.assertEqual(code,2); dispatch.assert_not_called()
        self.assertFalse((self.root/'out').exists())
