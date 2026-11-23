"""Integration declarations are data. Loading never imports project code."""
import copy
import fnmatch
import hashlib
import json
from pathlib import Path
import re

DATA = Path(__file__).resolve().parents[1] / 'data/integrations.json'
FAMILIES = {'payments','storage','email','sms','push','ai','identity','queue','scheduler','erp','observability','chat'}
STRATEGIES = {'http-sink','record-replay','container','disable','emulator','replay','disabled'}
ECOSYSTEMS = {'npm','pypi','go','composer','gem'}
IDENT = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
_BASE = json.loads(DATA.read_text())


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _patterns(values):
    if not isinstance(values,list) or len(values)>30: raise ValueError('registry: invalid patterns')
    for pattern in values:
        if not isinstance(pattern,str) or len(pattern)>400 or re.search(r'\\[1-9]|\(\?[=!<]|[+*][^)]*\)[+*{]',pattern):
            raise ValueError('registry: unsupported pattern')
        try: re.compile(pattern)
        except re.error: raise ValueError('registry: invalid regex') from None


def load_registry(config=None):
    registry=copy.deepcopy(_BASE)
    runtime=(config or {}).get('runtime',config or {})
    custom=runtime.get('integrations',{}).get('custom',[])
    if not isinstance(custom,list) or len(custom)>100: raise ValueError('registry: custom must be a list, max 100')
    known={row['provider'] for row in registry['providers']}
    for row in custom:
        if not isinstance(row,dict) or row.get('provider') in known: raise ValueError('registry: duplicate custom provider; configure existing provider by id')
        if row.get('accepted') is False:continue
        known.add(row.get('provider')); registry['providers'].append(copy.deepcopy(row))
    for row in registry['providers']:
        if not isinstance(row.get('provider'),str) or not IDENT.fullmatch(row['provider']) or row.get('family') not in FAMILIES or row.get('default_strategy') not in STRATEGIES | {None}:
            raise ValueError('registry: invalid provider, family or strategy')
        packages=row.setdefault('packages',{})
        if not isinstance(packages,dict) or set(packages)-ECOSYSTEMS: raise ValueError('registry: unknown package ecosystem')
        for values in packages.values():
            if not isinstance(values,list) or any(not isinstance(v,str) or not v or len(v)>200 for v in values): raise ValueError('registry: invalid package name')
        hosts=row.setdefault('hosts',[])
        if not isinstance(hosts,list) or any(not isinstance(h,str) or not re.fullmatch(r'[a-z0-9*.-]{1,253}',h) or h.startswith('.') for h in hosts):
            raise ValueError('registry: host patterns only, no URL/credentials')
        for name in ('env_patterns','code_patterns'): _patterns(row.setdefault(name,[]))
        if row.get('container') and row['container'] not in registry['containers']: raise ValueError('registry: unknown container preset')
    registry['sha256']=digest(registry)
    return registry


def indexes(registry):
    providers={}; packages={}; hosts={}; env={}
    for row in registry['providers']:
        ident=row['provider']; providers[ident]=(row.get('legacy_kind',row['family']),row['default_strategy'],row.get('legacy_implemented',False))
        for values in row['packages'].values():
            for value in values: packages.setdefault(value,ident)
        for host in row['hosts']: hosts.setdefault(host,ident)
        if row['env_patterns']:env[ident]='(?:'+'|'.join(row['env_patterns'])+')'
    return providers,packages,hosts,env


def host_provider(host,hosts):
    if host in hosts:return hosts[host]
    return next((provider for pattern,provider in hosts.items() if '*' in pattern and fnmatch.fnmatchcase(host,pattern)),'unknown-http')


def manifest_signals(path,text,registry):
    base=Path(path).name
    ecosystem=('npm' if base=='package.json' else 'composer' if base=='composer.json' else 'pypi' if base.startswith('requirements') or base=='pyproject.toml' else 'go' if base=='go.mod' else 'gem' if base=='Gemfile' else None)
    if not ecosystem:return []
    result=[]
    if ecosystem in ('npm','composer'):
        try: manifest=json.loads(text)
        except ValueError:return []
        names={name for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies','require','require-dev')
               for name in (manifest.get(section,{}) if isinstance(manifest.get(section,{}),dict) else {})}
        for row in registry['providers']:
            for package in row['packages'].get(ecosystem,[]):
                if package in names:result.append((row['provider'],text[:max(0,text.find(json.dumps(package)))].count('\n')+1))
    else:
        for number,line in enumerate(text.splitlines(),1):
            line=line.split('#',1)[0][:4096]
            for row in registry['providers']:
                for package in row['packages'].get(ecosystem,[]):
                    suffix=r'(?:/v[0-9]+)?' if ecosystem=='go' else ''
                    if re.search(r'(?<![\w/-])'+re.escape(package)+suffix+r'(?=[\s\["\'~<>=!,]|$)',line,re.I):result.append((row['provider'],number))
    return sorted(set(result))


def source_signals(path,clean,code,registry):
    result=[]
    for row in registry['providers']:
        if any(fnmatch.fnmatchcase(path,pattern) or fnmatch.fnmatchcase(Path(path).name,pattern) for pattern in row.get('file_patterns',[])):
            result.append((row['provider'],1,'scheduler_declaration'))
        for number,(line,masked) in enumerate(zip(clean.splitlines(),code.splitlines()),1):
            if not masked.strip():continue
            for pattern in row['code_patterns']:
                match=re.search(pattern,line[:4096])
                if match and not masked[match.start()].isspace(): result.append((row['provider'],number,row.get('evidence_kind','protocol_declaration')))
    return sorted(set(result))
