"""Synthetic mixed .NET manifests; no installed SDK is needed."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_dotnet as dotnet
import helix_environment as environment
from helix_audit_context import parts


class DotnetTests(unittest.TestCase):
    def test_sdk_runtime_framework_and_standard_are_distinct(self):
        sdk, errors = dotnet.declarations('global.json', '{"sdk":{"version":"8.0.402"}}')
        self.assertFalse(errors)
        self.assertEqual(sdk[0]['component'], 'dotnet-sdk')
        rows, errors = dotnet.declarations('service.csproj', '<Project><PropertyGroup><TargetFrameworks>net8.0;net9.0-windows;net48;netstandard2.0</TargetFrameworks></PropertyGroup></Project>')
        self.assertFalse(errors)
        self.assertEqual([(r['component'], r['version']) for r in rows], [('dotnet-runtime', '8.0'), ('dotnet-runtime', '9.0'), ('dotnet-framework', '4.8'), ('dotnet-standard', '2.0')])

    def test_legacy_namespaces_unknown_and_unexpanded_msbuild(self):
        rows, errors = dotnet.declarations('service.vbproj', '<Project xmlns="urn:msbuild"><PropertyGroup><TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion></PropertyGroup></Project>')
        self.assertFalse(errors)
        self.assertEqual(rows[0]['version'], '4.7.2')
        for text in ('<Project/>', '<Project><TargetFramework>$(SharedTarget)</TargetFramework></Project>', '<!DOCTYPE Project [<!ENTITY v "net8.0">]><Project/>'):
            rows, errors = dotnet.declarations('service.fsproj', text)
            self.assertFalse(rows)
            self.assertTrue(errors)

    def test_environment_and_parts_use_manifests_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name, text in {'global.json': '{"sdk":{"version":"8.0.402"}}', 'services/backend/App.csproj': '<Project><TargetFrameworks>net8.0;net9.0</TargetFrameworks></Project>', 'services/backend/App.cs': 'class App {}', 'tools/report/Report.fsproj': '<Project><TargetFramework>net8.0</TargetFramework></Project>'}.items():
                p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
            with patch.object(environment, '_run', side_effect=AssertionError('no SDK execution')), patch('helix_runtime.database_target', return_value={'evidence': []}):
                report = environment.report(root, probe=False)
            components = {r['name']: r for r in report['components']}
            self.assertEqual(set(components), {'dotnet-sdk', 'dotnet-runtime'})
            self.assertFalse(components['dotnet-runtime']['conflicts'])
            self.assertTrue(all(r['production']['status'] == 'unknown' for r in components.values()))
            self.assertEqual({r['path'] for r in parts(root, {})}, {'services/backend', 'tools/report'})
            self.assertFalse(report['provenance']['models'])


if __name__ == '__main__':
    unittest.main()
