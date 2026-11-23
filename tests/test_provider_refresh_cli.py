"""Provider refresh wiring uses fake callers; no real model or network traffic."""
import argparse
import contextlib
import copy
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_provider_plan import load_helix
import helix_new
import helix_provider_plan as routing


class ProviderRefreshCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.repo = self.root / 'target'; self.repo.mkdir()
        self.cache = self.root / 'state/provider-availability.json'
        self.H = load_helix()

    def test_preparation_callback_merges_defaults_without_overwriting_explicit_choices(self):
        explicit = {'models': {'gemini': ['synthetic-exact'], 'codex': [None]}, 'providers': {'hunter':'gemini'}}
        before, defaults = copy.deepcopy(explicit), copy.deepcopy(self.H.DEFAULT_CFG)
        def fake_refresh(ctx, callers, path, *, jobs):
            self.assertEqual(ctx.repo, self.repo)
            self.assertEqual(ctx.cfg['models']['gemini'], ['synthetic-exact'])
            self.assertEqual(ctx.cfg['models']['codex'], [None])
            self.assertEqual(ctx.cfg['models']['claude-via-agy'], defaults['models']['claude-via-agy'])
            self.assertEqual(ctx.cfg['providers']['hunter'], 'gemini')
            self.assertEqual(jobs, 2); self.assertIs(path, self.cache)
            ctx.cfg['models']['claude-via-agy'].append('mutation-is-local')
            return {'status':'complete', 'models':[]}
        with patch.object(routing, 'refresh', side_effect=fake_refresh), patch.object(self.H, 'Ctx') as context:
            result = self.H.refresh_new_providers(self.repo, explicit, self.cache, jobs=2)
        context.assert_not_called(); self.assertEqual(result['status'], 'complete')
        self.assertEqual(explicit, before); self.assertEqual(self.H.DEFAULT_CFG, defaults)
        self.assertFalse((self.repo / '.helix').exists())

    def test_providers_forwards_explicit_probe_jobs(self):
        ctx = SimpleNamespace(repo=self.repo, state_dir=self.root, cfg={'models':{'codex':['model']}, 'providers':{}}, explicit_cfg={})
        with patch.object(routing, 'refresh', return_value={'models':[]}) as refresh, contextlib.redirect_stdout(io.StringIO()):
            self.H.cmd_providers(ctx, argparse.Namespace(refresh=True, plan=False, jobs=2))
        self.assertEqual(refresh.call_args.kwargs['jobs'], 2)

    def test_new_cli_supplies_target_boundary_jobs_and_callback(self):
        def dispatch(args, provider_refresh=None):
            self.assertIsNotNone(provider_refresh)
            provider_refresh({}, self.cache, jobs=args.jobs, offline=args.offline)
            return 0
        argv = ['helix','new','init','--dir',str(self.repo),'--mode','greenfield','--profile','S','--risk','low','--refresh-providers','--jobs','2']
        with patch.object(sys,'argv',argv), patch.object(helix_new,'dispatch',side_effect=dispatch), patch.object(self.H,'refresh_new_providers',return_value={'models':[]}) as refresh:
            with self.assertRaises(SystemExit) as exit_code: self.H.main()
        self.assertEqual(exit_code.exception.code, 0)
        refresh.assert_called_once_with(str(self.repo), {}, self.cache, jobs=2, offline=False)

    def test_offline_or_zero_jobs_refuses_before_preparation_or_probes(self):
        for flags in (['--offline'], ['--jobs','0']):
            argv = ['helix','new','init','--dir',str(self.repo),'--mode','greenfield','--profile','S','--risk','low','--refresh-providers',*flags]
            with self.subTest(flags=flags), patch.object(sys,'argv',argv), patch.object(helix_new,'dispatch') as dispatch, patch.object(self.H,'refresh_new_providers') as refresh, contextlib.redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as exit_code: self.H.main()
            self.assertEqual(exit_code.exception.code,2)
            self.assertIn('offline' if flags == ['--offline'] else '--jobs musi', stderr.getvalue())
            refresh.assert_not_called(); dispatch.assert_not_called()
        self.assertEqual(list(self.repo.iterdir()), [])
