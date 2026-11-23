"""Round nine regressions. Added without executing the suite."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from test_runtime import FIX, TOOLS, FakeExecutor
from test_runtime_round8 import BootstrapExecutor
import helix_runtime as rt


class RoundNineTests(unittest.TestCase):
    def test_refusal_suggestion_is_tried_on_fresh_database(self):
        with tempfile.TemporaryDirectory() as directory:
            project=Path(directory)/'project'
            shutil.copytree(FIX/'bootstrap-runner',project)
            # Construct the hint dynamically so only the refusal reveals the command.
            (project/'migrate.sh').write_text('''#!/bin/sh
if [ "${ALLOW_EMPTY:-0}" != 1 ]; then
 printf '%s=%s %s %s\\n' ALLOW_EMPTY 1 ./migrate.sh up
 exit 2
fi
exit 0
''')
            runner=rt.Runner(project,Path(directory)/'out',executor=BootstrapExecutor(),tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
            part=runner.run()['parts'][0]
            group=part['database']['strategies'][0]
            modes=[c for c in group['candidates'] if c['migrations'][0].get('env',{}).get('ALLOW_EMPTY')=='1']
            self.assertEqual(len(modes),1)
            self.assertTrue(any(r['strategy']==modes[0]['strategy'] for r in group['results']))
            creates=[c for c in runner.executor.calls if any('CREATE DATABASE helix_trial_' in str(a) for a in c[0])]
            self.assertGreaterEqual(len(creates),2)

    def test_documented_command_preserves_args_and_deduplicates(self):
        runners=rt.project_runners({'migrate.sh':'case "$1" in up) ;; esac', 'README.md':'fresh: ALLOW_EMPTY=true ./migrate.sh up --empty\nfresh: ALLOW_EMPTY=true ./migrate.sh up --empty'})
        modes=[r for r in runners if r.get('env',{}).get('ALLOW_EMPTY')=='true']
        self.assertEqual(len(modes),1)
        self.assertEqual(modes[0]['argv'],['bash','migrate.sh','up','--empty'])

    def test_adoption_baseline_is_skipped(self):
        runners=rt.project_runners({'migrate.sh':'echo refuse','README.md':'new: ./migrate.sh baseline --adopt'})
        mode=next(r for r in runners if 'baseline' in r['argv'])
        self.assertIn('without SQL',mode['skip_reason'])

    def test_composed_issuer_dependencies(self):
        sources={'config.ts':'''import { env } from '$env/dynamic/private';
const base = env.IDENTITY_BASE_URL;
const realm = env.IDENTITY_REALM;
const issuer = `${base}/realms/${realm}`;
export const configuration = discovery(new URL(issuer));
const unrelated = env.OTHER_API_URL;
'''}
        self.assertEqual(rt.oidc_dependencies(sources),['IDENTITY_BASE_URL','IDENTITY_REALM'])

    def test_app_plan_discovers_base_url_and_realm(self):
        with tempfile.TemporaryDirectory() as directory:
            app=Path(directory)
            (app/'package.json').write_text(json.dumps({'scripts':{'start':'node server.cjs'}}))
            (app/'server.cjs').write_text("const base = process.env.LOGIN_BASE_URL;\nconst realm = process.env.LOGIN_REALM;\nconst issuer = `${base}/realms/${realm}`;\nconst config = discovery(new URL(issuer));\n")
            part=rt.plan(app)['parts'][0]
            self.assertEqual(part['oidc_dependencies'],['LOGIN_BASE_URL','LOGIN_REALM'])
            self.assertTrue({'LOGIN_BASE_URL','LOGIN_REALM'} <= {e['name'] for e in part['env']})

    def test_helper_composed_issuer_dependencies(self):
        sources={'config.ts':'''get issuer() { return `${required('LOGIN_BASE_URL')}/realms/${required('LOGIN_REALM')}`; }'''}
        self.assertEqual(rt.oidc_dependencies(sources),['LOGIN_BASE_URL','LOGIN_REALM'])

    def test_oidc_sets_base_and_realm_and_probes_native_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            runner=rt.Runner(FIX/'bootstrap-runner',Path(directory)/'out',executor=FakeExecutor(),tools={'tools':dict(TOOLS)},port_factory=lambda:31234)
            runner.tmp=Path(directory)/'tmp';runner.tmp.mkdir()
            runner.work=FIX/'bootstrap-runner';runner.env={}
            (runner.out/'logs').mkdir(parents=True)
            part={'env':[{'name':n} for n in ('IDENTITY_BASE_URL','IDENTITY_REALM')],'oidc_dependencies':['IDENTITY_BASE_URL','IDENTITY_REALM']}
            runner.oidc(part)
            self.assertEqual(runner.env['IDENTITY_BASE_URL'],'https://127.0.0.1:31234')
            self.assertEqual(runner.env['IDENTITY_REALM'],'synthetic')
            self.assertIn('NODE_EXTRA_CA_CERTS',runner.env)
            self.assertTrue(any('-e' in c[0] and 'fetch(' in ' '.join(c[0]) for c in runner.executor.calls))
            self.assertNotIn('NODE_TLS_REJECT_UNAUTHORIZED',runner.env)


class ReservedEnvNotClobberedTest(__import__('unittest').TestCase):
    def test_path_and_system_vars_are_never_oidc_targets(self):
        import sys, pathlib
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'bin'))
        import helix_runtime as h
        for name in ('PATH', 'HOME', 'NODE_PATH', 'PYTHONPATH', 'LD_LIBRARY_PATH'):
            self.assertFalse(h.oidc_path_var(name), name)
        self.assertTrue(h.oidc_path_var('AUTH_REALM'))
