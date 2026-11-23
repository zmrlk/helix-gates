"""Interrupted browser JSON keeps validated public checkpoints, never completion."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import helix_runtime as runtime
import test_runtime_identity_projection as fixture


class RuntimeLoginRecovery(unittest.TestCase):
    def test_truncated_final_recovers_suite_checkpoint_with_explicit_partial_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory).resolve()/'browser.json'
            suite=fixture.public_fixture()['identity_forms'][0]
            Path(str(output)+'.jsonl').write_text(json.dumps(suite)+'\n'+json.dumps({'type':'route','route':'/','status':'PASS','reachable':True})+'\n')
            output.write_text('{"identity_form":')
            result=runtime.browser_results(output)
        self.assertEqual(result['identity_form'],suite)
        self.assertEqual(result['execution_status'],'partial')
        self.assertEqual(result['artifact_gaps'],[{'kind':'browser_output_incomplete','source':'final_output'}])
        self.assertEqual(result['pages_tested'],1)

    def test_unsafe_final_symlink_is_not_treated_as_truncated_json(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory).resolve();target=base/'target.json';target.write_text('{}')
            output=base/'browser.json';output.symlink_to(target)
            with self.assertRaises(OSError):runtime.browser_results(output)


if __name__=='__main__':unittest.main()
