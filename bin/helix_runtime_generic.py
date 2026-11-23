"""One data-driven HTTP engine and disposable service launcher; no provider branches."""
import fnmatch
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import threading
from urllib.parse import urlsplit, parse_qs

from helix_runtime_registry import load_registry

ALIASES={'emulator':'http-sink','replay':'record-replay','disabled':'disable'}


def compile_rules(inventory,part,config):
    registry=load_registry(config); definitions={r['provider']:r for r in registry['providers']}
    settings=config.get('runtime',{}).get('integrations',{})
    rules=[]
    for entry in inventory['integrations']:
        if entry['area']!='active' or part not in entry['parts']:continue
        definition=definitions[entry['provider']]; setting=settings.get(entry['id'],settings.get(entry['provider'],{}))
        strategy=entry['strategy']['selected']
        if strategy=='disabled':strategy='disable'
        # Existing protocol adapters remain supported explicitly, without guessing
        # their readiness. New canonical strategies always use this engine.
        if strategy not in ('http-sink','record-replay','container','disable'):continue
        row=dict(provider=entry['provider'],family=definition['family'],hosts=definition['hosts'],strategy=strategy,
                 packages=definition['packages'],env_names=entry['env_names'],integration_id=entry['id'],required=entry.get('required_for_startup') is True or entry['strategy']['resolution']=='explicit')
        if strategy=='http-sink':
            response=setting.get('response')
            if response is not None and (not isinstance(response,dict) or type(response.get('status')) is not int or not 200<=response['status']<=599):
                raise ValueError('http-sink: invalid configured response')
            row['response']=response
        if strategy=='record-replay':
            cases=setting.get('recordings',[])
            if not isinstance(cases,list) or len(cases)>50:raise ValueError('record-replay: invalid cases')
            for case in cases:
                if case.get('synthetic') is not True or not isinstance(case.get('request'),dict) or not isinstance(case.get('response'),dict):raise ValueError('record-replay: synthetic request/response required')
                if type(case['response'].get('status')) is not int or not 200<=case['response']['status']<=599:raise ValueError('record-replay: invalid status')
                parsed=urlsplit(case['request'].get('url',''))
                if parsed.scheme not in ('http','https') or parsed.username or parsed.password or parsed.fragment:raise ValueError('record-replay: invalid URL')
            row['recordings']=cases
        if strategy=='container':
            preset=setting.get('preset',definition.get('container'))
            if preset in registry['containers']:row['container']=registry['containers'][preset]
            else:continue  # database/identity own protocol adapters
        rules.append(row)
    if len(json.dumps(rules).encode())>4_000_000:raise ValueError('generic adapters: configuration too large')
    return rules


def _fields(value):
    if isinstance(value,dict):
        return sorted({key for key in value if isinstance(key,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}',key)})
    return []


def request_shape(request):
    url=urlsplit(request['url'])
    # Unknown path components may be customer IDs/names/tokens. Keep only shape.
    return dict(host=url.hostname,method=request.get('method','GET').upper(),
                path='/'+'/'.join('{segment}' for p in url.path.split('/') if p),
                query_fields=_fields(parse_qs(url.query)),body_fields=_fields(request.get('body')),
                header_fields=_fields(request.get('headers',{})))


class Engine:
    def __init__(self,rules,learning=False,binding=None):
        self.rules=rules;self.learning=learning;self.binding=binding or {};self.observations=[];self.lock=threading.Lock()

    def handle(self,request):
        if not isinstance(request,dict) or not isinstance(request.get('url'),str):raise ValueError('invalid request')
        url=urlsplit(request['url']);method=request.get('method','GET').upper()
        if url.scheme not in ('http','https') or not url.hostname or url.username or url.password or not re.fullmatch(r'[A-Z]{3,12}',method):raise ValueError('invalid URL/method')
        rules=[r for r in self.rules if any(fnmatch.fnmatchcase(url.hostname,h) for h in r['hosts'])]
        if len({r['provider'] for r in rules})>1:return dict(status=409,body={'error':'AMBIGUOUS_PROVIDER'})
        row=rules[0] if rules else None; shape=request_shape(request)
        observation=dict(shape=shape,coverage='not_checked',provider=row['provider'] if row else 'unknown-http')
        if row and row['strategy']=='http-sink':
            response=row.get('response') or {'status':200,'body':{}}
            observation['outcome']='configured' if row.get('response') else 'zaślepione'
        elif row and row['strategy']=='record-replay':
            normalized={'url':request['url'],'method':method,'body':request.get('body')}
            case=next((r for r in row.get('recordings',[]) if r['request']==normalized),None)
            response=case['response'] if case else {'status':502,'body':{'error':'REPLAY_UNMATCHED'}}
            observation['outcome']='replayed' if case else 'unmatched'
        else:
            response={'status':503,'body':{'error':'INTEGRATION_DISABLED' if row else 'UNKNOWN_HTTP'}}
            observation['outcome']='disabled' if row else 'nietestowane'
            if not row and self.learning:
                ident='learned-'+hashlib.sha256(url.hostname.encode()).hexdigest()[:12]
                observation['proposal']={'provider':ident,'family':'chat','packages':{},'hosts':[url.hostname],
                                         'env_patterns':[],'default_strategy':'http-sink','accepted':False}
        with self.lock:
            if len(self.observations)>=1000:return {'status':429,'body':{'error':'CAPTURE_LIMIT'}}
            self.observations.append(observation)
        return response

    def snapshot(self):
        with self.lock:
            return dict(binding=self.binding,status='nietestowane',observations=list(self.observations),
                        external_delivery='NOT_RUN',coverage='not_checked')


QUEUE_MODULES=frozenset({'celery','rq'})


def start_http(runner,part,rules,config,home):
    settings=config.get('runtime',{}).get('integrations',{})
    learning=settings.get('learning',False)
    if type(learning) is not bool:raise ValueError('integrations.learning must be boolean')
    engine=Engine(rules,learning,binding=dict(run_id=runner.run_id,plan_id=runner.integration_plan['plan_id'],part=part['path']))
    token=secrets.token_hex(32);runner.private_values.add(token)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            if self.path!='/capture' or self.headers.get('Authorization')!='Bearer '+token:
                self.send_error(403);return
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=1048576:raise ValueError()
                response=engine.handle(json.loads(self.rfile.read(length)))
                capture()
                status=response['status'];body=b'' if status in (204,205,304) else json.dumps(response.get('body')).encode()
            except (ValueError,TypeError,KeyError):status=400;body=b'{}'
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    # Loopback only; the server never forwards a request to the original host.
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    port=server.server_address[1];runner.network_connect_ports.add(port)
    public=runner.out/('generic-'+hashlib.sha256(part['path'].encode()).hexdigest()[:10]+'.json')
    capture_lock=threading.Lock()
    def capture():
        with capture_lock:runner.write_sink_input(engine.snapshot(),public)
    def cleanup():
        server.shutdown();server.server_close();thread.join(timeout=2);capture()
    runner.cleanup_actions.append(cleanup)
    try:
        private=runner.project_temporary()/('generic-'+str(port)+'.json')
        own=['http://127.0.0.1:'+str(runner.env['PORT']),'http://localhost:'+str(runner.env['PORT'])]
        if runner.active_transport:own.append(runner.active_transport['public_origin'])
        disabled=sorted({p for r in rules if r['strategy']=='disable' for p in r['packages'].get('npm',[])})
        payload=dict(origin='http://127.0.0.1:'+str(port),token=token,own_origins=own,disabled_packages=disabled,
                     # Kolejka zadań w Pythonie bywa importowana przy starcie całej aplikacji: zamiast blokować import (aplikacja by nie wstała),
                     # zadania nie są wysyłane do brokera (sitecustomize podmienia wysyłkę i zostawia ślad w logu startu).
                     disabled_modules=sorted({p.replace('-','_') for r in rules if r['strategy']=='disable' for p in r['packages'].get('pypi',[])}-QUEUE_MODULES),
                     neutralized_modules=sorted({p.replace('-','_') for r in rules if r['strategy']=='disable' for p in r['packages'].get('pypi',[])}&QUEUE_MODULES))
        runner.write_sink_input(payload,private)
        runner.env['HELIX_GENERIC_INPUT']=str(private)
        if part['package_manager']=='pip':
            runner.owned_pythonpath=str(home/'bin/runtime-python')
            runner.env['PYTHONPATH']=runner.owned_pythonpath
        else:runner.add_owned_preload(home/'bin/runtime-generic.cjs')
        capture()
        return dict(engine=engine,public=public,capture=capture,cleanup=cleanup,input=payload,config=private,origin=payload['origin'])
    except BaseException:
        cleanup();raise


def start_containers(runner,rules):
    """One preset interpreter: local cached digest, private internal network, tmpfs."""
    from helix_runtime import Blocked
    tool=runner.tools.get('docker')
    results=[]
    for row in rules:
        if row['strategy']!='container':continue
        spec=row['container']; result=dict(provider=row['provider'],image=spec['image'],status='BLOCKED',coverage='not_checked',required=row.get('required',False))
        results.append(result)
        if not tool:result['reason']='docker unavailable';continue
        name='helix-svc-'+secrets.token_hex(8);network=name+'-net';created=False;net=False
        def cleanup(n=name,nw=network):
            runner.command([tool,'rm','-f',n],cleanup=True)
            runner.command([tool,'network','rm',nw],cleanup=True)
        try:
            if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}',spec['image']):raise ValueError('unpinned service image')
            runner.command([tool,'image','inspect',spec['image']],maximum=10)
            runner.command([tool,'network','create','--internal',network],maximum=10);net=True
            port=runner.port_factory();argv=[tool,'run','--detach','--pull=never','--name',name,'--network',network,
                '--label','io.helix.runtime.owner='+name,'--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
                '--pids-limit=128','--memory=256m','--cpus=1','-p',f'127.0.0.1:{port}:{spec["port"]}']
            for path in spec['tmpfs']:argv+=['--tmpfs',path+':rw,nosuid,nodev,size=64m']
            for key,value in spec['environment'].items():argv+=['-e',key+'='+value]
            argv+=[spec['image'],*spec['command']]
            created=True;runner.command(argv,maximum=20)
            internal=runner.command([tool,'network','inspect','--format','{{.Internal}}',network]).strip()
            running=runner.command([tool,'inspect','--format','{{.State.Running}}',name]).strip()
            if internal!='true' or running!='true':raise Blocked('service isolation/start not verified')
            runner.network_connect_ports.add(port)
            for key,value in spec['env_bindings'].items():runner.env[key]=value.replace('{port}',str(port))
            runner.cleanup_actions.append(cleanup)
            result.update(status='RUNNING',readiness='not_checked',reason='process and internal network verified; protocol not exercised')
        except (Blocked,OSError,ValueError):
            result['reason']='cached pinned image or isolated container unavailable; no pull/fallback'
            if created:runner.command([tool,'rm','-f',name],cleanup=True)
            if net:runner.command([tool,'network','rm',network],cleanup=True)
    return results


def prepare_generic(runner,part,declaration,config,home):
    rules=compile_rules(runner.integration_plan,part['path'],config)
    services=start_containers(runner,rules)
    declaration['integrations']={'services':services,'coverage':'not_checked','status':'nietestowane'}
    active=[r for r in rules if r['strategy']!='container']
    declaration['integrations']['disabled']=[r['provider'] for r in active if r['strategy']=='disable']
    if any(r['strategy']!='disable' or r['hosts'] for r in active) or config.get('runtime',{}).get('integrations',{}).get('learning'):
        handle=start_http(runner,part,active,config,home)
        runner.active_generic=handle
        declaration['integrations']['capture']=handle['public'].relative_to(runner.out).as_posix()
    elif part['package_manager']=='pip' and active:
        private=runner.project_temporary()/'generic-disabled.json'
        modules={p.replace('-','_') for r in active for p in r['packages'].get('pypi',[])}
        runner.write_sink_input(dict(disable_only=True,disabled_modules=sorted(modules-QUEUE_MODULES),neutralized_modules=sorted(modules&QUEUE_MODULES)),private)
        runner.env['HELIX_GENERIC_INPUT']=str(private)
        runner.owned_pythonpath=str(home/'bin/runtime-python');runner.env['PYTHONPATH']=runner.owned_pythonpath
    if any(r['status']=='BLOCKED' and r['required'] for r in services):
        from helix_runtime import Blocked
        raise Blocked('generic container strategy unavailable; no fallback')


def refresh_generic(runner):
    handle=getattr(runner,'active_generic',None)
    if not handle:return
    origins={scheme+'://'+host+':'+str(port) for port in runner.network_connect_ports for scheme in ('http','https') for host in ('localhost','127.0.0.1')}
    handle['input']['own_origins']=sorted(origins)
    runner.write_sink_input(handle['input'],handle['config'])
    if runner.active_sink:
        runner.active_sink['input']['own_origins']=sorted(set(runner.active_sink['input']['own_origins'])|{handle['origin']})
