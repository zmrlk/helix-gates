"""Opt-in real loopback capture server + Node transport; never calls provider APIs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'bin'))
from helix_runtime_generic import start_http


@unittest.skipUnless(os.environ.get('HELIX_RUNTIME_ADAPTER_TESTS')=='1' and shutil.which('node'),'opt-in loopback transport')
class CaptureTests(unittest.TestCase):
    def test_node_fetch_and_http_reach_shared_engine_and_persist_shapes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);preloads=[]
            def write(value,path):
                path.write_text(json.dumps(value));path.chmod(0o600)
            runner=SimpleNamespace(out=root,run_id='integration',integration_plan={'plan_id':'f'*64},env={'PORT':'32123'},private_values=set(),network_connect_ports=set(),cleanup_actions=[],active_transport=None,project_temporary=lambda:root,write_sink_input=write,add_owned_preload=preloads.append)
            rule={'provider':'acme','hosts':['api.acme.invalid'],'strategy':'http-sink','response':{'status':201,'body':{'synthetic':True}},'packages':{}}
            handle=start_http(runner,{'path':'.','package_manager':'npm'},[rule],{'runtime':{'integrations':{'learning':True}}},ROOT)
            try:
                program="""const http=require('node:https');(async()=>{let r=await fetch('https://api.acme.invalid/send',{method:'POST',body:JSON.stringify({token:'PRIVATE_VALUE'})});if(r.status!==201)throw Error('sink');await new Promise((resolve,reject)=>{http.get('https://other.invalid/private/123?token=PRIVATE_VALUE',res=>{if(res.statusCode!==503)reject(Error('learning'));res.resume();res.on('end',resolve)}).on('error',reject)});})().catch(e=>{console.error(e);process.exitCode=1});"""
                result=subprocess.run(['node','--require',str(preloads[0]),'-e',program],env={**os.environ,**runner.env},capture_output=True,text=True,timeout=20)
                self.assertEqual(result.returncode,0,result.stderr)
                handle['capture']();raw=handle['public'].read_text();receipt=json.loads(raw)
                self.assertEqual(len(receipt['observations']),2);self.assertNotIn('PRIVATE_VALUE',raw);self.assertNotIn('123',raw)
                self.assertEqual(receipt['coverage'],'not_checked');self.assertFalse(receipt['observations'][1]['proposal']['accepted'])
            finally:handle['cleanup']()


if __name__=='__main__':unittest.main()
