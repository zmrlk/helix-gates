"""CLI must propagate a partial UX result instead of claiming exit-zero success."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_provider_plan import load_helix
import helix_contracts
import helix_dependencies


class ResourceCLI(unittest.TestCase):
    def test_ux_partial_report_exits_nonzero_with_external_config(self):
        H = load_helix()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); repo = root / 'target'; repo.mkdir()
            config = root / 'helix.json'; config.write_text('{}')
            ctx = SimpleNamespace(repo=repo, state_dir=root / 'state', external_state=True)
            for status, expected in [('resource_paused', 3), ('partial', 3), ('complete', None)]:
                with self.subTest(status=status), patch.object(sys, 'argv', ['helix', '--repo', str(repo), '--config', str(config), 'ux', 'report', '--out', str(root / 'out')]), patch.object(helix_contracts, 'check_pin'), patch.object(H, 'Ctx', return_value=ctx), patch.object(helix_dependencies, 'STATE_ROOT', root / 'state'), patch.object(H.helix_ux, 'cmd_ux', return_value={'run_status':status, 'pass':status == 'complete'}):
                    if expected is None:
                        self.assertIsNone(H.main())
                    else:
                        with self.assertRaises(SystemExit) as error: H.main()
                        self.assertEqual(error.exception.code, expected)
