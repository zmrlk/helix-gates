"""Execute the actual browser script against a local module fake, no browser/network."""
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node unavailable')
class KeycloakReadinessBrowser(unittest.TestCase):
    def test_readiness_skips_stub_login_but_keeps_issuer_allowlist_and_tls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); project = root / 'project'
            module = project / 'node_modules/playwright'; module.mkdir(parents=True)
            (project / 'package.json').write_text('{}')
            (module / 'package.json').write_text('{"name":"playwright","main":"index.cjs"}')
            (module / 'index.cjs').write_text('''
const fs=require('fs');const records=[];
exports.chromium={launch:async options=>{records.push({launch:options});return {
 newContext:async options=>{records.push({context:options});return {
  route:async(pattern,handler)=>{for(const url of ['http://127.0.0.1:3100/public','https://127.0.0.1:4400/realms/fixture','https://outside.invalid/path']){
   await handler({request:()=>({url:()=>url}),continue:()=>records.push({url,allowed:true}),abort:()=>records.push({url,allowed:false})});}},
  newPage:async()=>{let current='';return {on:()=>{},goto:async url=>{records.push({goto:url});current=url;if(url.endsWith('/login'))throw Error('stub login invoked');return{status:()=>200}},url:()=>current};},
  close:async()=>records.push({contextClosed:true})};},
 close:async()=>{records.push({browserClosed:true});fs.writeFileSync(process.env.FIXTURE_RECORDS,JSON.stringify(records))}
}}};
''')
            script = Path(__file__).resolve().parents[1] / 'bin/runtime-browser.cjs'
            for readiness in (True, False):
                output = root / ('readiness.json' if readiness else 'stub.json')
                records = root / ('readiness-records.json' if readiness else 'stub-records.json')
                env = dict(os.environ, FIXTURE_RECORDS=str(records), HELIX_RUNTIME_OIDC_ISSUER='https://127.0.0.1:4400/realms/fixture',
                           HELIX_RUNTIME_OIDC_SPKI='A'*43+'=', HELIX_RUNTIME_BROWSER_BUDGETS='{"workers":1}')
                for name in ['HELIX_RESOURCE_FILE', 'HELIX_RUNTIME_NODE_MODULES', 'HELIX_RUNTIME_IDENTITY_MODE']:
                    env.pop(name, None)
                decision = root / 'resource-current.json'
                decision.write_text(json.dumps(dict(updated_at=datetime.now(timezone.utc).isoformat(), state='normal',
                    effective_jobs=1, max_pause_s=.1, poll_s=.001, stale_after_s=15)))
                env['HELIX_RESOURCE_FILE'] = str(decision)
                if readiness:
                    env['HELIX_RUNTIME_IDENTITY_MODE'] = 'keycloak-readiness'
                    env['HELIX_RUNTIME_TLS_SPKI_LIST'] = 'A'*43+'='+','+'B'*43+'='
                else:env.pop('HELIX_RUNTIME_TLS_SPKI_LIST',None)
                done = subprocess.run(['node', str(script), 'http://127.0.0.1:3100/', str(output), 'e2e', '["/public"]', str(project)],
                                      env=env, text=True, capture_output=True, timeout=5)
                self.assertEqual(done.returncode, 0, done.stderr)
                data = json.loads(output.read_text()); events = json.loads(records.read_text())
                if readiness:
                    self.assertIsNone(data['auth_flow']); self.assertIn('NOT_RUN', data['auth_coverage'])
                    self.assertIn('protected routes not covered', data['auth_coverage'])
                    self.assertFalse(any(event.get('goto', '').endswith('/login') for event in events))
                else:
                    self.assertEqual(data['auth_flow']['status'], 'BLOCKED')
                    self.assertEqual(data['auth_flow']['reason_code'], 'NO_EXPLICIT_IDENTITY_POLICY')
                    self.assertTrue(any(event.get('goto', '').endswith('/login') for event in events))
                self.assertEqual(data['routes'][0]['route'], '/public')
                self.assertEqual(data['routes'][0]['status'], 'PASS')
                decisions = {event['url']: event['allowed'] for event in events if 'allowed' in event}
                self.assertEqual(decisions, {'http://127.0.0.1:3100/public': True,
                                            'https://127.0.0.1:4400/realms/fixture': True,
                                            'https://outside.invalid/path': False})
                keys=env.get('HELIX_RUNTIME_TLS_SPKI_LIST',env['HELIX_RUNTIME_OIDC_SPKI'])
                self.assertEqual(events[0]['launch']['args'],['--ignore-certificate-errors-spki-list='+keys])
                self.assertTrue(all(event['context']['serviceWorkers']=='block' for event in events if 'context' in event))
                self.assertNotIn('ignoreHTTPSErrors',json.dumps(events))
                self.assertTrue(events[-1]['browserClosed'])


if __name__ == '__main__': unittest.main()
