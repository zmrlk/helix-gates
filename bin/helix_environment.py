"""Read-only environment declarations and provenance; never load actual dotenv files."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

import helix_dotnet
from helix_source_policy import AGENT_STATE_DIRECTORIES
from helix_contracts import VERSION
from helix_audit_context import safe_read, system_path

EXCLUDE = {'.git', '.helix', 'helix-evidence', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', '.nuxt', '.svelte-kit', 'vendor', '.aws', '.ssh', 'credentials', 'secrets'} | AGENT_STATE_DIRECTORIES
SOURCES = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.svelte', '.vue', '.py', '.sh'}
ENV_EXAMPLES = {'.env.example', '.env.sample', '.env.template'}
TOOLS = {'dotnet-sdk': ['dotnet', '--version'], 'node': ['node', '--version'], 'python': [sys.executable, '--version'], 'npm': ['npm', '--version'], 'pnpm': ['pnpm', '--version'], 'yarn': ['yarn', '--version'], 'bun': ['bun', '--version'], 'postgres': ['postgres', '--version'], 'postgres-client': ['psql', '--version'], 'pg_ctl': ['pg_ctl', '--version'], 'nginx': ['nginx', '-v'], 'playwright': ['playwright', '--version'], 'chromium': ['chromium', '--version'], 'docker': ['docker', '--version'], 'redis': ['redis-server', '--version'], 'mysql': ['mysql', '--version']}
NAME = r'[A-Z_][A-Z0-9_]*'


def _run(command, cwd=None):
    environment={k:v for k,v in os.environ.items() if k in ('PATH', 'LANG', 'SYSTEMROOT')}
    environment.update(GIT_OPTIONAL_LOCKS='0',COREPACK_ENABLE_NETWORK='0',COREPACK_ENABLE_DOWNLOAD_PROMPT='0',npm_config_offline='true',PIP_NO_INDEX='1',UV_OFFLINE='1')
    return subprocess.run(command, cwd=cwd or Path(__file__).parent, capture_output=True, text=True, timeout=5, env=environment)


STANDARD_TOOLS=('gitleaks','semgrep','trivy','playwright','chromium','node','python')


def _identifier(value):
    return value if isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,159}',value) else None


def _observed_version(value):
    if not isinstance(value,str):return None
    match=re.search(r'(?<![\w.])v?(\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?)(?![\w.])',value)
    return match[1] if match else None


def _records(value, kind):
    if isinstance(value,list):return [v for v in value if isinstance(v,dict)]
    if not isinstance(value,dict):return []
    if kind in value:return [value]
    records=[]
    for name,item in value.items():
        if isinstance(item,dict):records.append(dict(item,**({kind:name} if kind not in item else {})))
        elif kind=='tool' and isinstance(item,str):records.append(dict(tool=name,version=item,status='unknown',used=None))
    return records


def normalize_tools(records=None):
    """Project only metadata fields, never argv, paths, stderr or credentials."""
    result={name:dict(status='not_used',version=None,used=False,reason='Brak dowodu wykonania w tym raporcie') for name in STANDARD_TOOLS}
    for item in _records(records,'tool'):
        name=_identifier(item.get('tool') or item.get('name'))
        if not name:continue
        raw_status=str(item.get('status','unknown')).lower()
        version=_observed_version(item.get('version'))
        if raw_status in ('planned','configured','selected','requested'):version=None
        explicit=item.get('used')
        used=explicit if isinstance(explicit,bool) else raw_status in ('ok','complete','completed','executed','pass','fail','error','failed','recorded')
        if raw_status in ('not_used','not_run','planned','configured','selected','requested','skipped','unavailable','missing','not_probed'):used=False
        status='not_used' if not used and raw_status in ('not_used','not_run','planned','configured','selected','requested','skipped','not_probed') else 'recorded' if version else 'unknown'
        row=dict(status=status,version=version,used=used,reason='Wersja z danych wykonawcy' if version else 'Wykonanie zgłoszone; brak zaobserwowanej wersji' if used else 'Brak dowodu wykonania w tym raporcie')
        for field in ('scope','evidence_kind'):
            if label:=_identifier(item.get(field)):row[field]=label
        if isinstance(item.get('calls'),int) and not isinstance(item.get('calls'),bool) and item['calls']>=0:row['calls']=item['calls']
        result[name]=row
    return result


def normalize_models(records=None):
    """Only caller-supplied execution receipts; availability and plans are excluded."""
    result=[]
    for item in _records(records,'provider'):
        provider=_identifier(item.get('provider'))
        status=str(item.get('status','recorded')).lower()
        if not provider or item.get('used') is False or status in ('available','unavailable','planned','configured','selected','requested','not_used','not_run','not_checked','pending'):continue
        if 'requested_model' in item and 'model' not in item and 'status' not in item:continue
        model=_identifier(item.get('model'))
        if model in ('default','unknown','orchestrator'):model=None
        row=dict(provider=provider,model=model,status='recorded' if model else 'unknown',reason='Identyfikator z wywołania modelu' if model else 'Wywołanie z domyślnym modelem; konkretna wersja nie została zwrócona')
        if item.get('method') == 'manual_handoff':
            row.update(status='declared' if model else 'unknown', method='manual_handoff',
                       evidence_kind='manual_receipt', call_invoked=False,
                       reason='Model zadeklarowany w ręcznym receipt; bez wywołania CLI przez Helixa')
            for field in ('request_id', 'reviewer'):
                if value:=_identifier(item.get(field)):row[field]=value
            if isinstance(item.get('round'),int) and not isinstance(item.get('round'),bool) and item['round']>0:
                row['round']=item['round']
        for field in ('role','family'):
            if value:=_identifier(item.get(field)):row[field]=value
        if isinstance(item.get('batch_index'),int) and not isinstance(item.get('batch_index'),bool):row['batch_index']=item['batch_index']
        if row not in result:result.append(row)
    return result


def _git_ref(repo):
    from helix_git_readonly import read_ref
    return read_ref(repo)


def provenance(repo, models=None, tools=None):
    """Read-only Git snapshot plus supplied receipts; no tool/model availability probes."""
    source=_git_ref(Path(__file__).resolve().parents[1]);target=_git_ref(repo)
    observed=normalize_tools(tools)
    observed['python']=dict(status='recorded',version=platform.python_version(),used=True,scope='report_interpreter',reason='Wersja z danych wykonawcy')
    return dict(schema_version=1,helix_version=VERSION,source_ref=source,target_ref=target,
                source_head=source['head'],source_dirty=source['dirty'],helix_head=source['head'],helix_dirty=source['dirty'],target_head=target['head'],target_dirty=target['dirty'],
                python=platform.python_version(),generated_at=datetime.now(timezone.utc).isoformat(),
                tools=observed,models=normalize_models(models),
                reproducibility='Git refs and dirty flags; dirty worktrees require the retained source snapshot to reproduce',
                scope='Local execution metadata; no production claim')


def _root(value):
    path=system_path(Path(value).expanduser().absolute())
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('env: ścieżka nie może zawierać dowiązania')
    if not path.is_dir(): raise ValueError('env: nie ma katalogu projektu')
    return path.resolve()


def _files(root, coverage):
    def skip(path, reason, gap=False):
        coverage['excluded'].append(dict(path=path.relative_to(root).as_posix(),reason=reason,gap=gap))
    for base, dirs, names in os.walk(root, followlinks=False, onerror=lambda error:coverage['errors'].append(dict(reason='Nie można odczytać katalogu'))):
        kept=[]
        for name in sorted(dirs):
            path=Path(base)/name
            if name in EXCLUDE: skip(path,'dependency, output or private directory')
            elif path.is_symlink():skip(path,'symlink directory not followed',True)
            else:kept.append(name)
        dirs[:]=kept
        for name in sorted(names):
            path=Path(base)/name
            if (name.startswith('.env') or name.endswith('.env')) and name not in ENV_EXAMPLES:
                skip(path,'actual environment file not opened');continue
            if name.endswith(('.pem','.key','.p12','.pfx')) or name in EXCLUDE:
                skip(path,'private file not opened');continue
            if path.is_symlink():skip(path,'symlink file not followed',True);continue
            if not path.is_file():skip(path,'not a regular file',True);continue
            yield path


def _version(value):
    """Validate separate atoms without ambiguous nested regex repetitions."""
    if not isinstance(value,(str,int,float)) or isinstance(value,bool):return None
    value=str(value).strip().strip('"\'')
    value=re.sub(r'(>=|<=|>|<|==|=|~=|~|\^)\s+',r'\1',value)
    value=re.sub(r'(?<=[\dxX*])(?=[<>=~^])',' ',value)
    if value=='*' or re.fullmatch(r'(?:lts|latest|stable)(?:/[\w*.-]+)?',value):return value
    atoms=re.split(r'(?:\s*\|\|\s*|\s*,\s*|\s+)',value)
    if not atoms or any(not atom for atom in atoms):return None
    for index,atom in enumerate(atoms):
        if atom=='-' and len(atoms)==3 and index==1:continue
        if not re.fullmatch(r'(?:>=|<=|>|<|==|=|~=|~|\^)?[vV]?\d+(?:\.(?:\d+|[xX*]))*(?:[-+][a-zA-Z0-9.-]+)?',atom):return None
        if any(len(n)>5 for n in re.findall(r'\d+',atom)):return None
    return value


def _bounds(spec, component):
    """Inclusive numeric bounds; unresolved/prerelease selectors are not guessed."""
    if not spec or '||' in spec:return None
    base=100000;maximum=base**3-1
    def parse(value):
        if re.search(r'[-+]',value):return None
        pieces=value.lstrip('vV').split('.')
        numeric=[]
        for part in pieces:
            if part in ('x','X','*'):break
            if not part.isdigit() or int(part)>=base:return None
            numeric.append(int(part))
        if not 1<=len(numeric)<=3:return None
        full=numeric+[0]*(3-len(numeric))
        lower=full[0]*base**2+full[1]*base+full[2]
        return numeric,lower,lower+base**(3-len(numeric))-1
    hyphen=re.fullmatch(r'\s*(v?\d+(?:\.\d+)*)\s+-\s+(v?\d+(?:\.\d+)*)\s*',spec)
    if hyphen:
        first,second=parse(hyphen[1]),parse(hyphen[2])
        return (first[1],second[2]) if first and second else None
    lo,hi=0,maximum;position=0;found=False
    token=re.compile(r'\s*[, ]*\s*(>=|<=|>|<|\^|~=|~|==|=)?\s*([vV]?\d+(?:\.(?:\d+|[xX*]))*(?:[-+][\w.-]+)?)')
    while position<len(spec):
        match=token.match(spec,position)
        if not match:return None
        parsed=parse(match[2])
        if not parsed:return None
        numbers,value,upper=parsed;op=match[1];found=True
        if op=='>=':lo=max(lo,value)
        elif op=='>':lo=max(lo,upper+1)
        elif op=='<':hi=min(hi,value-1)
        elif op=='<=':hi=min(hi,upper)
        elif op=='^':
            bump=next((i for i,n in enumerate(numbers) if n),len(numbers)-1)
            ceiling=value-value%(base**(2-bump))+base**(2-bump)
            lo=max(lo,value);hi=min(hi,ceiling-1)
        elif op in ('~','~='):
            bump=max(0,len(numbers)-2) if op=='~=' else min(1,len(numbers)-1)
            ceiling=value-value%(base**(2-bump))+base**(2-bump)
            lo=max(lo,value);hi=min(hi,ceiling-1)
        else:lo=max(lo,value);hi=min(hi,upper)
        position=match.end()
    return (lo,hi) if found else None


def local_tool(component):
    command = TOOLS.get(component)
    if not command: return dict(status='not_probed', version=None, reason='Brak sondy dla tego komponentu')
    executable=shutil.which(command[0])
    if not executable and component=='chromium':
        executable=next((p for name in ('chromium-browser','google-chrome') if (p:=shutil.which(name))),None)
        if not executable:
            candidates=[]
            for cache in (Path.home()/'Library/Caches/ms-playwright',Path.home()/'.cache/ms-playwright'):
                for pattern in ('chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium','chromium-*/chrome-linux*/chrome','chromium_headless_shell-*/chrome-*/headless_shell'):
                    candidates.extend(sorted(cache.glob(pattern),reverse=True))
            candidates.extend([Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'),Path('/Applications/Chromium.app/Contents/MacOS/Chromium')])
            executable=next((str(path) for path in candidates if path.is_file() and not path.is_symlink()),None)
    if not executable:return dict(status='missing',version=None,reason='Brak lokalnego narzędzia; nic nie instalowano')
    command=[executable,*command[1:]]
    try:
        result = _run(command)
        match = re.search(r'\b(?:v)?(\d+\.\d+(?:\.\d+){0,2})\b', result.stdout+'\n'+result.stderr)
        if result.returncode == 0 and match:
            return dict(status='available', version=match[1], tag='VERIFIED', evidence=' '.join(command), scope='client' if component in ('postgres-client','mysql') else 'server_binary_not_running_server' if component in ('postgres','pg_ctl') else 'local_binary')
        return dict(status='error',version=None,reason='Polecenie wersji nie zwróciło poprawnej odpowiedzi')
    except (OSError, subprocess.SubprocessError) as error:
        return dict(status='error',version=None,reason=type(error).__name__)


def _prod(path):
    if path is None: return {}
    path = system_path(Path(path).expanduser().absolute())
    if any(p.is_symlink() for p in (path,*path.parents)) or path.name.startswith('.env'): raise ValueError('prod-evidence wymaga zwykłego pliku JSON, nie pliku środowiska')
    try:data=json.loads(safe_read(path))
    except (ValueError,OSError):raise ValueError('prod-evidence: nieczytelny lub niepoprawny JSON')
    if isinstance(data,dict) and isinstance(data.get('claims'),list):
        claims={}
        for item in data['claims']:
            if isinstance(item,dict) and item.get('component') and item.get('version') and item.get('tag')=='VERIFIED' and item.get('source_status')=='FOUND':
                claims[item['component']]=dict(item,checked_at=item.get('checked_at') or item.get('retrieved_at'))
        if not claims:raise ValueError('prod-evidence: brak datowanych claimów G0 z jawnym component/version')
        data=dict(components=claims)
    if not isinstance(data,dict) or not isinstance(data.get('components'),dict):raise ValueError('prod-evidence wymaga components lub jawnych claimów G0 z wersjami i datą')
    result={}
    for name, item in data['components'].items():
        if not isinstance(item,dict): raise ValueError('prod-evidence: komponent musi mieć version, checked_at i evidence')
        try: stamp=datetime.fromisoformat(item.get('checked_at',data.get('checked_at','')))
        except (TypeError,ValueError): raise ValueError('prod-evidence: wymagane checked_at ISO ze strefą czasową')
        if stamp.tzinfo is None or stamp.timestamp()>datetime.now(timezone.utc).timestamp()+60: raise ValueError('prod-evidence: data musi mieć strefę i nie może być z przyszłości')
        version=_version(item.get('version',''))
        evidence=item.get('evidence')
        if isinstance(evidence,list):evidence=';'.join(x for x in evidence if isinstance(x,str))
        # Do not reflect arbitrary evidence content, which might contain credentials.
        if not version or not re.fullmatch(r'v?\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9.-]+)?',version) or not isinstance(evidence,str) or not evidence.strip():raise ValueError('prod-evidence: wymagana konkretna wersja, nie zakres, oraz niepuste evidence')
        result[name]=dict(version=version,checked_at=stamp.isoformat(),status='provided',tag='VERIFIED',evidence='jawny plik '+path.name,scope='owner provided; no remote readback')
    return result


def _source_env(text, suffix):
    """Lex tokens so strings, comments and renamed imports do not invent names."""
    comment=r'#[^\n]*' if suffix in ('.py','.sh') else r'//[^\n]*|/\*[\s\S]*?\*/|<!--[\s\S]*?-->'
    pattern=re.compile(r'(?P<string>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|(?P<comment>'+comment+r')|(?P<identifier>[A-Za-z_$][\w$]*)|(?P<punct>[^\s])')
    def template(match):
        value=match.group();masked=list(re.sub(r'[^\n]',' ',value))
        for expression in re.finditer(r'\$\{([^}]*)\}',value,re.S):masked[expression.start(1):expression.end(1)]=expression[1]
        return ''.join(masked)
    lexed=re.sub(r'`(?:\\.|[^`\\])*`',template,text) if suffix not in ('.py','.sh') else text
    tokens=[(m.lastgroup,m.group(),m.start()) for m in pattern.finditer(lexed) if m.lastgroup!='comment']
    values=[t[1] for t in tokens];aliases=set();os_aliases={'os'};result=[]
    def emit(value,index):
        if re.fullmatch(NAME,value):result.append((value,text.count('\n',0,tokens[index][2])+1))
    def string(index):
        return values[index][1:-1] if index<len(tokens) and tokens[index][0]=='string' else None
    for i,value in enumerate(values):
        if value=='import' and i+1<len(values) and values[i+1]=='{':
            end=next((j for j in range(i+2,len(values)) if values[j]=='}'),len(values))
            if end+2<len(values) and values[end+1]=='from' and (module:=string(end+2)) and module.startswith('$env/'):
                j=i+2
                while j<end:
                    source=values[j];binding=values[j+2] if j+2<end and values[j+1]=='as' else source
                    if source=='env' and '/dynamic/' in module:aliases.add(binding)
                    elif '/static/' in module:emit(source,j)
                    j=next((k+1 for k in range(j+1,end) if values[k]==','),end)
        if values[i:i+3]==['import','os','as'] and i+3<len(values):os_aliases.add(values[i+3])
        if values[i:i+4]==['from','os','import','environ']:
            aliases.add(values[i+5] if i+5<len(values) and values[i+4]=='as' else 'environ')
    for i,value in enumerate(values):
        if tokens[i][0]!='identifier':continue
        end=None
        if values[i:i+3]==['process','.','env']:end=i+3
        elif values[i:i+5]==['import','.','meta','.','env']:end=i+5
        elif value in os_aliases and values[i+1:i+3]==['.','environ']:end=i+3
        elif value in aliases:end=i+1
        if end is not None:
            if end+1<len(values) and values[end]=='.' and values[end+1]!='get':emit(values[end+1],end+1)
            elif end+1<len(values) and values[end]=='[' and string(end+1):emit(string(end+1),end+1)
            elif values[end:end+3]==['.','get','('] and string(end+3):emit(string(end+3),end+3)
        if value in os_aliases and values[i+1:i+4]==['.','getenv','('] and string(i+4):emit(string(i+4),i+4)
        if value in ('const','let','var') and values[i+1:i+2]==['{']:
            end=next((j for j in range(i+2,len(values)) if values[j]=='}'),len(values))
            if values[end+1:end+5]==['=','process','.','env'] or values[end+1:end+7]==['=','import','.','meta','.','env']:
                j=i+2
                while j<end:
                    emit(values[j],j);j=next((k+1 for k in range(j+1,end) if values[k]==','),end)
        if value in ('const','let','var') and values[i+2:i+6]==['=','process','.','env']:aliases.add(values[i+1])
    return sorted(set(result),key=lambda item:(item[1],item[0]))


def _ci_versions(lines, path, add):
    """Resolve inline/multiline/include matrix values within the current CI job."""
    matrices=[]
    for index,line in enumerate(lines):
        match=re.match(r'(\s*)matrix:\s*(.*)',line)
        if not match:continue
        indent=len(match[1]);end=index+1
        while end<len(lines) and (not lines[end].strip() or len(lines[end])-len(lines[end].lstrip())>indent):end+=1
        block=lines[index+1:end];rows={}
        if match[2].strip():block=[match[2].strip().strip('{}')]+block
        for offset,entry in enumerate(block):
            field=re.match(r'\s*(?:-\s*)?([\w-]+):\s*(.*)',entry)
            if not field or field[1] in ('include','exclude'):continue
            raw=field[2].strip();choices=[]
            if raw.startswith('['):
                remaining='\n'.join([raw,*block[offset+1:]])
                choices=[x.strip().strip('"\'') for x in remaining.split(']',1)[0].lstrip('[').split(',')]
            elif raw:choices=[raw.strip('"\'')]
            else:
                level=len(entry)-len(entry.lstrip())
                for following in block[offset+1:]:
                    if following.strip() and len(following)-len(following.lstrip())<=level:break
                    choice=re.match(r'\s*-\s*([^:#]+)\s*$',following)
                    if choice:choices.append(choice[1].strip().strip('"\''))
            for choice in choices:
                if _version(choice) is not None:rows.setdefault(field[1],[]).append(choice)
        matrices.append((index,end,rows))
    for index,line in enumerate(lines):
        if line.lstrip().startswith('#'):continue
        setup=re.search(r'uses:\s*["\']?actions/setup-(node|python)@',line)
        if not setup:continue
        indent=len(line)-len(line.lstrip());job_start=max((n for n in range(index) if re.match(r'^  [\w-]+:\s*$',lines[n])),default=0)
        options=next((rows for start,end,rows in reversed(matrices) if job_start<=start<index),{})
        for number in range(index+1,len(lines)):
            current=lines[number]
            if current.strip() and len(current)-len(current.lstrip())<=indent:break
            value=re.match(r'\s*(node-version|python-version):\s*(.*?)\s*(?:#.*)?$',current)
            if not value:continue
            raw=value[2].strip().strip('"\'');reference=re.fullmatch(r'\$\{\{\s*matrix\.([\w-]+)\s*\}\}',raw)
            choices=options.get(reference[1],[]) if reference else [raw]
            for choice in dict.fromkeys(choices):add(setup[1],choice,path,number+1,'ci_matrix' if reference else 'ci')


def _yaml_env_names(lines):
    """Read keys only; quoted/list/flow values are never interpreted."""
    level=None
    def name(chunk, mapping):
        pattern=r'\s*["\']?('+NAME+r')["\']?\s*:' if mapping else r'\s*["\']?('+NAME+r')(?==|["\']?\s*$)'
        match=re.match(pattern,chunk)
        return match[1] if match else None
    for number,line in enumerate(lines,1):
        indent=len(line)-len(line.lstrip())
        if level is not None and line.strip() and indent<=level:level=None
        header=re.match(r'\s*(?:environment|env):\s*(.*)',line)
        if header:
            level=indent;raw=header[1].strip()
            if raw.startswith(('{','[')):
                mapping=raw[0]=='{';quote=None;escaped=False;start=1
                for index,char in enumerate(raw[1:],1):
                    if quote:
                        if escaped:escaped=False
                        elif char=='\\':escaped=True
                        elif char==quote:quote=None
                    elif char in ('"',"'"):quote=char
                    elif char in ',}]':
                        if key:=name(raw[start:index],mapping):yield key,number
                        start=index+1
            continue
        if level is None:continue
        content=line.lstrip()
        key=name(content[1:].lstrip(),False) if content.startswith('-') else name(content,True)
        if key:yield key,number


def report(repo, prod_evidence=None, probe=True):
    root=_root(repo)
    declarations={};usage={};declared={};errors=[];files_scanned=0
    coverage=dict(files=[],excluded=[],errors=[],bytes_read=0,lines_read=0,status='COMPLETE')
    def add(component,version,path,line,kind='pin'):
        value=_version(version)
        if value is None:
            errors.append(dict(path=path,line=line,component=component,reason='Nieobsługiwana lub niepoprawna deklaracja wersji'));return
        item=dict(path=path,line=line,version=value,kind=kind,tag='VERIFIED',scope='deklaracja w pliku')
        if item not in declarations.setdefault(component,[]): declarations[component].append(item)
    def env(target,name,path,line):
        if re.fullmatch(NAME,name):
            location=dict(path=path,line=line)
            if location not in target.setdefault(name,[]): target[name].append(location)
    for path in _files(root,coverage):
        rel=path.relative_to(root).as_posix();name=path.name
        relevant=helix_dotnet.relevant(path) or path.suffix in SOURCES or name in ENV_EXAMPLES or name in ('package.json','.nvmrc','.node-version','.python-version','.tool-versions','.mise.toml','mise.toml','pyproject.toml','package-lock.json','pnpm-lock.yaml','yarn.lock','nginx.conf') or name.startswith('Dockerfile') or path.suffix in ('.yaml','.yml')
        if not relevant:continue
        try:text=safe_read(path,errors='strict')
        except (OSError,UnicodeError):errors.append(dict(path=rel,reason='Nie można bezpiecznie odczytać całego pliku'));continue
        if '\0' in text:errors.append(dict(path=rel,reason='Oczekiwano pliku tekstowego'));continue
        files_scanned+=1;lines=text.splitlines()
        coverage['files'].append(dict(path=rel,lines_read=len(lines),status='read'))
        coverage['bytes_read']+=len(text.encode());coverage['lines_read']+=len(lines)
        if name in ENV_EXAMPLES:
            # Only names are parsed; example values are discarded without interpretation.
            for number,line in enumerate(lines,1):
                match=re.match(r'^\s*(?:export\s+)?('+NAME+r')\s*=',line)
                if match:env(declared,match[1],rel,number)
            continue
        if helix_dotnet.relevant(path):
            dotnet_rows, dotnet_errors = helix_dotnet.declarations(rel, text)
            errors.extend(dotnet_errors)
            for row in dotnet_rows:
                add(row['component'], row['version'], rel, row['line'], row['kind'])
        if name=='package.json':
            try: pkg=json.loads(text)
            except ValueError: errors.append(dict(path=rel,reason='Niepoprawny package.json'));continue
            if not isinstance(pkg,dict): errors.append(dict(path=rel,reason='package.json nie jest obiektem'));continue
            for component,value in (pkg.get('engines',{}) if isinstance(pkg.get('engines'),dict) else {}).items():
                if component in TOOLS: add(component,value,rel,next((i for i,l in enumerate(lines,1) if '"'+component+'"' in l),1),'constraint')
            dependencies={}
            for field in ('dependencies','devDependencies'):
                if isinstance(pkg.get(field,{}),dict):dependencies.update(pkg.get(field,{}))
                else:errors.append(dict(path=rel,reason='Niepoprawna sekcja zależności package.json'))
            for dependency,value in dependencies.items():
                if dependency in ('playwright','@playwright/test','playwright-core'):
                    add('playwright',value,rel,next((i for i,l in enumerate(lines,1) if dependency in l),1),'constraint')
                    declarations.setdefault('chromium',[])
            manager=pkg.get('packageManager','')
            if isinstance(manager,str) and '@' in manager:
                component,value=manager.split('@',1)
                if component in TOOLS: add(component,value.split('+sha')[0],rel,next((i for i,l in enumerate(lines,1) if 'packageManager' in l),1))
        if name in ('.nvmrc','.node-version','.python-version'):
            for number,line in enumerate(lines,1):
                if line.strip() and not line.lstrip().startswith('#'): add('python' if name=='.python-version' else 'node',line,rel,number);break
        if name=='.tool-versions':
            for number,line in enumerate(lines,1):
                match=re.match(r'\s*(nodejs|node|python|postgres|postgresql|npm|pnpm|yarn|bun|redis|nginx)\s+(\S+)',line)
                if match: add({'nodejs':'node','postgresql':'postgres'}.get(match[1],match[1]),match[2],rel,number)
        if name in ('.mise.toml','mise.toml','pyproject.toml'):
            for number,line in enumerate(lines,1):
                match=re.match(r'\s*(node|python|postgres|npm|pnpm|yarn|bun|nginx|requires-python)\s*=\s*["\']([^"\']+)',line)
                if match: add('python' if match[1]=='requires-python' else match[1],match[2],rel,number,'constraint' if match[1]=='requires-python' else 'pin')
        if name=='package-lock.json':
            match=re.search(r'"lockfileVersion"\s*:\s*(\d+)',text)
            if match: add('package-lock-format',match[1],rel,text[:match.start()].count('\n')+1,'lockfile_format')
        if name=='pnpm-lock.yaml':
            match=re.search(r'^lockfileVersion:\s*["\']?([\d.]+)',text,re.M)
            if match: add('pnpm-lock-format',match[1],rel,text[:match.start()].count('\n')+1,'lockfile_format')
        if name=='yarn.lock':
            match=re.search(r'^# yarn lockfile v(\d+)|^  version:\s*(\d+)',text,re.M)
            if match: add('yarn-lock-format',match[1] or match[2],rel,text[:match.start()].count('\n')+1,'lockfile_format')
        if name=='nginx.conf':declarations.setdefault('nginx',[])
        matrix={};setup=None;setup_indent=-1;env_indent=None
        if path.suffix in ('.yml','.yaml'):
            _ci_versions(lines,rel,add)
            for key,number in _yaml_env_names(lines):env(declared,key,rel,number)
        is_config=path.suffix in ('.yml','.yaml')
        for number,line in enumerate(lines,1):
            clean=line.split('#',1)[0];indent=len(line)-len(line.lstrip())
            if name.startswith('Dockerfile'):
                match=re.match(r'^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)',line,re.I)
                image=match[1] if match else None
            elif is_config:
                match=re.match(r'\s*image:\s*["\']?([^\s"\']+)',line);image=match[1] if match else None
            else:image=None
            if image:
                match=re.search(r'(?:^|/)(node|python|postgres|postgresql|redis|mysql|mariadb|bun|nginx|playwright):(?:pg)?(\d+(?:\.\d+)*)',image)
                if match: add({'postgresql':'postgres'}.get(match[1],match[1]),match[2],rel,number,'container_image')
            if is_config:
                for var in re.findall(r'\$\{('+NAME+r')(?::[^}]*)?\}',line):env(usage,var,rel,number)
        if path.suffix in SOURCES:
            for variable,line in _source_env(text,path.suffix):env(usage,variable,rel,line)
    # Reuse actual runtime detector, but only its evidence; its default PG16 is not a declaration.
    from helix_runtime import database_target
    try:database=database_target(root)
    except (OSError,UnicodeError):database={'evidence':[]};errors.append(dict(reason='Niepełny odczyt deklaracji bazy'))
    for item in database['evidence']:
        if item.get('major') is not None and (item['path'].endswith('.sql') or item['strength']=='minimum'):
            add(item['engine'],('>=' if item['strength']=='minimum' else '')+str(item['major']),item['path'],item['line'],'migration_minimum' if item['strength']=='minimum' else 'database')
    if 'postgres' in declarations:
        declarations.setdefault('postgres-client',[]);declarations.setdefault('pg_ctl',[])
    production=_prod(prod_evidence);components=[];probed={}
    for name in sorted(set(declarations)|set(production)):
        entries=declarations.get(name,[]);local=local_tool(name) if probe and name in TOOLS else dict(status='not_probed',version=None)
        if name in TOOLS:probed[name]=local
        prod=production.get(name,dict(status='unknown',version=None,tag='ASSUMPTION',reason='Brak jawnego dowodu wersji produkcyjnej z datą'))
        conflicts=[];unresolved=[]
        # Target frameworks are build alternatives, not runtime environment pins.
        comparable=[(e,_bounds(e['version'],name)) for e in entries if e['kind'] not in ('lockfile_format','target_framework')]
        # CI matrix versions are alternatives, not mutually exclusive environment pins.
        for index,(entry,bounds) in enumerate(comparable):
            if bounds is None:
                unresolved.append(dict(path=entry['path'],line=entry['line'],reason='Nierozpoznany selektor wersji; zgodność nieustalona'));continue
            for other,second in comparable[index+1:]:
                if second is None or entry['kind']=='ci_matrix' or other['kind']=='ci_matrix':continue
                one=Path(entry['path']).parent;two=Path(other['path']).parent
                if not one.is_relative_to(two) and not two.is_relative_to(one) and '.github' not in one.parts and '.github' not in two.parts:continue
                if max(bounds[0],second[0])>min(bounds[1],second[1]):conflicts.append(dict(kind='declaration_conflict',sources=[entry,other],effect='Deklaracje wymagają różnych wersji; wybierz świadomie środowisko testu'))
            for label,actual in (('local',local),('production',prod)):
                actual_bounds=_bounds(actual.get('version'),name)
                if actual_bounds and (actual_bounds[0]<bounds[0] or actual_bounds[1]>bounds[1]):
                    if entry['kind']=='ci_matrix':continue
                    conflicts.append(dict(kind=label+'_mismatch',source=entry,actual_version=actual['version'],effect='Wynik z tego środowiska nie potwierdza zgodności z deklarowanym środowiskiem'))
        matrix_groups={}
        for entry,bounds in comparable:
            if entry['kind']=='ci_matrix' and bounds is not None:matrix_groups.setdefault((entry['path'],entry['line']),[]).append((entry,bounds))
        for alternatives in matrix_groups.values():
            for entry,bounds in comparable:
                if bounds is None or entry['kind']=='ci_matrix':continue
                if not any(max(bounds[0],candidate[0])<=min(bounds[1],candidate[1]) for _,candidate in alternatives):
                    conflicts.append(dict(kind='ci_matrix_conflict',source=entry,alternatives=[item for item,_ in alternatives],effect='Żaden wariant macierzy CI nie pokrywa deklarowanej wersji'))
        components.append(dict(name=name,declarations=entries,local=local,production=prod,conflicts=conflicts,unresolved=unresolved,effect='Wymaga wyjaśnienia różnic' if conflicts else 'Zgodność nieustalona dla części selektorów' if unresolved else 'Nie stwierdzono sprzecznych rozpoznanych deklaracji; nie jest to test zgodności'))
    server=next((c for c in components if c['name']=='postgres'),None)
    client=next((c for c in components if c['name']=='postgres-client'),None)
    if server and client and server['local'].get('version') and client['local'].get('version') and server['local']['version'].split('.')[0]!=client['local']['version'].split('.')[0]:
        client['conflicts'].append(dict(kind='client_server_major_difference',server_version=server['local']['version'],client_version=client['local']['version'],effect='Binaria serwera i klienta mają różne wersje główne; działający serwer nie był sondowany'))
        client['effect']='Różne lokalne wersje główne klienta i binariów serwera'
    missing=sorted(set(usage)-set(declared));unused=sorted(set(declared)-set(usage))
    errors+=coverage['errors']
    gaps=[e for e in coverage['excluded'] if e['gap']]
    coverage['status']='INCOMPLETE' if errors or gaps or not files_scanned else 'COMPLETE'
    result=dict(schema_version=1,status='INCOMPLETE' if coverage['status']=='INCOMPLETE' else 'WARN' if missing or any(c['conflicts'] or c['unresolved'] or probe and c['local']['status'] in ('missing','error') for c in components) else 'OK',scope='Analiza deklaracji i lokalnych wersji; bez uruchamiania projektu i bez odczytu produkcji',components=components,files_scanned=files_scanned,errors=errors,env_names=dict(used=usage,declared=declared,missing_from_examples=missing,unused_declared=unused,values_parsed=False,values_retained=False,real_env_read=False,scope='Zbiorcze porównanie statycznych nazw w repo; dynamiczne klucze i per-service injection wymagają osobnej weryfikacji'),coverage=coverage,provenance=provenance(root,tools=probed))
    result['markdown']=markdown(result)
    return result


def markdown(data):
    lines=['# Środowisko projektu','', 'Status: '+data['status']+'. '+data['scope'], '', '| Komponent | Deklaracje | Lokalnie | Produkcja | Skutek |','|---|---|---|---|---|']
    escape=lambda value:str(value).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('|','\\|').replace('\n',' ')
    for item in data['components']:
        sources='<br>'.join(escape(e['version'])+' ('+escape(e['path'])+':'+str(e['line'])+')' for e in item['declarations']) or 'brak'
        local=item['local'];prod=item['production']
        lines.append('| '+ ' | '.join((escape(item['name']),sources,local.get('version') or local['status'],(prod.get('version') or 'nieznana')+' ['+prod['tag']+']'+(' '+prod['checked_at'] if prod.get('checked_at') else ''),item['effect']))+' |')
    lines+=['','Deklaracja w repo jest potwierdzonym wpisem w pliku, nie dowodem wersji działającej na produkcji. postgres i pg_ctl oznaczają wersje lokalnych binariów serwera, postgres-client oznacza klienta psql. Żadna z tych sond nie potwierdza wersji działającego serwera.','', '## Zmienne środowiskowe','', 'Sprawdzono wyłącznie nazwy. Wartości nie są częścią raportu; rzeczywiste pliki .env są pomijane.','', 'Użyte bez deklaracji w przykładach/Compose/CI: '+(', '.join(data['env_names']['missing_from_examples']) or 'brak')+'.', '', 'Zadeklarowane bez rozpoznanego użycia: '+(', '.join(data['env_names']['unused_declared']) or 'brak')+'.']
    return '\n'.join(lines)+'\n'


def parsers(sp):
    parser=sp.add_parser('env',help='Deklaracje i różnice środowisk, bez odczytu .env')
    parser.add_argument('--prod-evidence');parser.add_argument('--out');parser.add_argument('--json',action='store_true');parser.add_argument('--no-probe',action='store_true')


def _write_outputs(value, root, data):
    out=system_path(Path(value).expanduser().absolute())
    if any(p.is_symlink() for p in (out,*out.parents)):raise ValueError('env --out musi być poza repo celu, bez dowiązań')
    out=out.resolve()
    if out==root or root in out.parents:raise ValueError('env --out musi być poza repo celu')
    fd=os.open(out.anchor,os.O_RDONLY|os.O_DIRECTORY)
    try:
        for component in out.parts[1:]:
            try:os.mkdir(component,dir_fd=fd)
            except FileExistsError:pass
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        artifacts={'environment.json':json.dumps(data,ensure_ascii=False,indent=2)+'\n','environment.md':data['markdown']}
        for name in artifacts:
            try:os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:continue
            raise ValueError('env --out zawiera istniejący artefakt; wybierz nowy katalog')
        for name,content in artifacts.items():
            target=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(target,'w') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)


def dispatch(args):
    try:
        data=report(args.repo,getattr(args,'prod_evidence',None),not getattr(args,'no_probe',False))
        if getattr(args,'out',None):_write_outputs(args.out,_root(args.repo),data)
        print(json.dumps(data,ensure_ascii=False,indent=2) if getattr(args,'json',False) else data['markdown'])
        return 3 if data['status']=='INCOMPLETE' else 0
    except ValueError as error:
        print('Helix env ERROR: '+str(error),file=sys.stderr);return 3
    except (OSError,TypeError,KeyError):
        print('Helix env ERROR: nieczytelna konfiguracja lub dowód, niedozwolona ścieżka albo istniejący wynik; szczegóły wartości nie są ujawniane',file=sys.stderr);return 3
