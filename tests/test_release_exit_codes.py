"""A printed failing result must be observable by shell scripts and CI."""
import sys
import unittest
from unittest.mock import patch

from test_provider_plan import load_helix
import helix_release
import helix_repo_hygiene


class ReleaseExitCodes(unittest.TestCase):
    def test_release_and_hygiene_propagate_dispatch_status(self):
        cli = load_helix()
        for module, command in ((helix_release, ['release','check']), (helix_repo_hygiene, ['repo-hygiene'])):
            for code in (0, 1, 2, 3):
                with self.subTest(command=command,code=code), patch.object(sys,'argv',['helix',*command]), patch.object(module,'dispatch',return_value=code) as dispatch, patch.object(cli,'Ctx') as ctx:
                    with self.assertRaises(SystemExit) as result: cli.main()
                self.assertEqual(result.exception.code,code)
                dispatch.assert_called_once(); ctx.assert_not_called()
