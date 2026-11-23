"""Owned requests/import adapter. Provider strategy logic lives in the shared engine."""
import json
import os
import sys
from urllib.parse import urlsplit, parse_qs

if os.environ.get('HELIX_GENERIC_INPUT'):
    try:
        path=os.environ['HELIX_GENERIC_INPUT']
        st=os.lstat(path)
        if os.path.islink(path) or st.st_size>1048576 or st.st_mode & 0o077:raise ValueError()
        with open(path) as stream:_cfg=json.load(stream)
        class _DisabledImports:
            def find_spec(self,fullname,path=None,target=None):
                if any(fullname==name or fullname.startswith(name+'.') for name in _cfg.get('disabled_modules',[])):
                    raise ImportError('HELIX_INTEGRATION_DISABLED')
                return None
        sys.meta_path.insert(0,_DisabledImports())
        # Kolejka zadań: import działa (aplikacja wstaje), ale wysyłka zadania do brokera jest zastąpiona śladem w logu.
        _QUEUE={'celery.app.task':(('Task','apply_async'),),'celery.app.base':(('Celery','send_task'),),'rq.queue':(('Queue','enqueue_call'),)}
        if any(name.split('.')[0] in _cfg.get('neutralized_modules',[]) for name in _QUEUE):
            import importlib.abc,importlib.util
            class _NotSent:
                id='helix-not-sent';task_id='helix-not-sent';state='PENDING';status='PENDING'
                def get(self,*args,**kwargs):raise RuntimeError('HELIX_QUEUE_NOT_SENT')
                def ready(self):return False
                def successful(self):return False
                def failed(self):return False
            def _stub(label):
                def send(*args,**kwargs):
                    target=args[1] if label.endswith('send_task') and len(args)>1 else getattr(args[0],'name',None) if args else None
                    sys.stderr.write('HELIX_QUEUE_NOT_SENT '+json.dumps(dict(via=label,task=str(target)[:120]))+'\n')
                    return _NotSent()
                return send
            class _Patching(importlib.abc.Loader):
                def __init__(self,loader,fullname):self.loader=loader;self.fullname=fullname
                def create_module(self,spec):return self.loader.create_module(spec)
                def exec_module(self,module):
                    self.loader.exec_module(module)
                    for owner,method in _QUEUE[self.fullname]:
                        target=getattr(module,owner,None)
                        if target is not None:setattr(target,method,_stub(owner+'.'+method))
            class _QueueImports:
                active=False
                def find_spec(self,fullname,path=None,target=None):
                    if fullname not in _QUEUE or fullname.split('.')[0] not in _cfg.get('neutralized_modules',[]) or _QueueImports.active:return None
                    _QueueImports.active=True
                    try:spec=importlib.util.find_spec(fullname)
                    finally:_QueueImports.active=False
                    if spec is None or spec.loader is None:return None
                    spec.loader=_Patching(spec.loader,fullname)
                    return spec
            sys.meta_path.insert(0,_QueueImports())
        if not _cfg.get('disable_only'):
            try:import requests
            except ImportError:requests=None
            if requests is not None:
                _original=requests.sessions.Session.request
                def _capture(self,method,url,**kwargs):
                    url=requests.Request(method,url,params=kwargs.get('params')).prepare().url
                    parsed=urlsplit(url);origin=parsed.scheme+'://'+parsed.netloc
                    if origin in _cfg['own_origins']:
                        kwargs.pop('params',None);kwargs['allow_redirects']=False
                        return _original(self,method,url,**kwargs)
                    body=kwargs.get('json',kwargs.get('data'))
                    if isinstance(body,(str,bytes)):
                        try:body=json.loads(body)
                        except (ValueError,UnicodeError):body={k:None for k in parse_qs(body.decode() if isinstance(body,bytes) else body)}
                    headers={**dict(self.headers),**kwargs.get('headers',{})}
                    payload=json.dumps(dict(url=url,method=method.upper(),headers=headers,body=body)).encode()
                    if len(payload)>65536:raise RuntimeError('HELIX_CAPTURE_LIMIT')
                    session=requests.Session();session.trust_env=False
                    return _original(session,'POST',_cfg['origin']+'/capture',headers={'Authorization':'Bearer '+_cfg['token'],'Content-Type':'application/json'},data=payload,timeout=15,allow_redirects=False)
                requests.sessions.Session.request=_capture
    except Exception:
        raise RuntimeError('HELIX_PYTHON_ADAPTER_INVALID') from None
