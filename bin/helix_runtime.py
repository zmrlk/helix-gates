"""Synthetic, disposable application runtime. Detection never executes project code."""
import argparse
import base64
import hashlib
import json
from helix_contracts import VERSION
from helix_resources import Governor, ResourcePaused
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import sys
import ssl
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse, unquote

HOME = Path(__file__).resolve().parent.parent
CHECKS = ('schema-apply', 'e2e', 'a11y', 'lighthouse', 'load', 'backup')
EXCLUDE = {'.git', '.helix', 'helix-evidence', '.aws', '.ssh', '.codex', '.agents', '.usage', 'secrets', 'credentials', 'node_modules', '.helix-runtime-tools', '.next', '.nuxt', '.svelte-kit', 'dist', 'build', '__pycache__', '.venv', 'venv', '.npmrc', '.yarnrc', '.yarnrc.yml', '.pnpmfile.cjs'}
FRAMEWORKS = [('@sveltejs/kit','sveltekit'), ('next','next'), ('nuxt','nuxt'), ('@angular/core','angular'), ('@remix-run/node','remix'), ('astro','astro'), ('@nestjs/core','nest'), ('fastify','fastify'), ('express','express'), ('vue','vue'), ('svelte','svelte'), ('react','react')]
SOURCE = {'.js','.mjs','.cjs','.ts','.tsx','.jsx','.svelte','.vue','.py','.json','.sql','.toml','.yaml','.yml','.prisma','.ini','.md','.sh','.plan','.conf','.go','.php','.rb','.timer','.service','.cron'}

def database_target(root):
    """Repository evidence only: explicit pins outrank syntax lower bounds."""
    from helix_runtime_extensions import sql_extensions
    evidence=[]; extensions=set(); extension_declarations=[]
    for path in files(Path(root)):
        rel=path.relative_to(root).as_posix()
        if path.suffix.lower() not in {'.tf','.sql','.toml','.yaml','.yml','.prisma','.ini','.md','.conf'} and not path.name.startswith('Dockerfile') and path.name!='.tool-versions': continue
        text=read(path)
        if path.suffix.lower()=='.sql' and not (set(Path(rel.lower()).parts[:-1]) & {'archive','archived','old','legacy','deprecated','backup','_unused','examples'}) and not rel.endswith(('.down.sql','.undo.sql')):
            declarations=sql_extensions(text,path=rel)['declarations']
            extension_declarations.extend(declarations)
            extensions.update(row['name'] for row in declarations)
        # Split Helm repository/tag and Azure version declarations need local context.
        context_engine='postgres' if re.search(r'postgres|postgis|pgvector',text,re.I) else 'mysql' if re.search(r'mysql',text,re.I) else None
        for number,line in enumerate(text.splitlines(),1):
            matches=[]
            for engine,pattern in [('postgres',r'(?:postgres(?:ql)?|pgvector/pgvector|postgis/postgis)[:@ /="\t-]+(?:pg)?(\d+)(?:[.\s"\x27_-]|$)'),('postgres',r'POSTGRES[_:](\d+)'),('mysql',r'mysql[: /="\t]+(\d+)'),('mariadb',r'mariadb[: /="\t]+(\d+)')]:
                matches.extend((engine,int(m.group(1))) for m in re.finditer(pattern,line,re.I))
            if context_engine and (re.search(r'(^|\s)(?:tag|version)\s*[:=]',line) and (path.suffix in ('.yaml','.yml','.tf') or path.name=='.mise.toml')):
                m=re.search(r'(?:tag|version)\s*[:=]\s*["\x27]?(\d+)',line)
                if m: matches.append((context_engine,int(m[1])))
            if re.search(r'engine_version|major_version|database_version',line):
                m=re.search(r'(?:engine_version|major_version|database_version)\s*[:=]\s*["\x27]?(?:POSTGRES[_:]?)?(\d+)',line,re.I)
                if m and (context_engine or 'supabase' in rel):
                    engine='mysql' if re.search(r'mysql|MYSQL',text) else 'postgres'
                    matches.append((engine,int(m.group(1))))
            if re.search(r'provider\s*=\s*["\x27]postgresql|jdbc:postgresql|engine\s*=\s*["\x27]postgres',line,re.I): matches.append(('postgres',None))
            if re.search(r'provider\s*=\s*["\x27]mysql|jdbc:mysql',line,re.I): matches.append(('mysql',None))
            for engine,major in matches:
                # Liczba spoza zakresu wersji to nie wersja (np. port 5432 w opisie wdrożenia). Dokumentacja opisuje, pliki
                # uruchomieniowe (compose, CI, Dockerfile, infrastruktura) rozstrzygają: wzmianka w .md nie blokuje przebiegu.
                if major is not None and not 5<=major<=30: continue
                evidence.append(dict(path=rel,line=number,engine=engine,major=major,strength='documentation' if path.suffix.lower()=='.md' else 'explicit'))
            if path.suffix=='.sql' and re.search(r'\bMERGE\s+INTO\b|NULLS\s+NOT\s+DISTINCT',sql_without_comments(line),re.I):
                evidence.append(dict(path=rel,line=number,engine='postgres',major=15,strength='minimum'))
    pins={(e['engine'],e['major']) for e in evidence if e['major'] and e['strength']=='explicit'}
    described={(e['engine'],e['major']) for e in evidence if e['major'] and e['strength']=='documentation'}
    # Gdy pliki uruchomieniowe różnią się wersją, rozstrzyga plik produkcyjny: przebieg ma odtwarzać produkcję, a rozjazd
    # między produkcją a środowiskiem testów trafia do raportu jako ustalenie o projekcie, nie blokada.
    divergence=[]
    if len(pins)>1:
        production={(e['engine'],e['major']) for e in evidence if e['major'] and e['strength']=='explicit' and re.search(r'prod(uction)?\b|prod[._-]',Path(e['path']).name,re.I)}
        if len(production)==1:
            divergence=sorted({(e['path'],e['major']) for e in evidence if e['major'] and e['strength']=='explicit' and (e['engine'],e['major']) not in production})
            divergence=[dict(path=path,major=major) for path,major in divergence][:20]
            pins=production
    # Silnik: pliki uruchomieniowe przed dokumentacją (stare opisy bywają o innym silniku albo wersji).
    engines={e['engine'] for e in evidence if e['strength']!='documentation'} or {e['engine'] for e in evidence}
    conflict=len(pins)>1 or len(engines)>1
    engine=next(iter(engines),'postgres') if len(engines)<=1 else 'conflict'
    major=next(iter(pins))[1] if len(pins)==1 else max((e['major'] for e in evidence if e['major'] and (not pins or e['strength']=='explicit')),default=16)
    mismatch=sorted({m for _,m in described if m!=major})
    minimum=max((e['major'] for e in evidence if e['strength']=='minimum'),default=0)
    conflict=conflict or bool(pins and major<minimum)
    image=f'postgres:{major}-alpine'
    if 'vector' in extensions: image=f'pgvector/pgvector:pg{major}'
    elif 'postgis' in extensions: image=f'postgis/postgis:{major}-3.5'
    return dict(engine=engine,major=major,image=image,evidence=evidence,conflict=conflict,extensions=sorted(extensions),extension_declarations=extension_declarations,extension_profile_conflict={'vector','postgis'}<=extensions,
                tag='VERIFIED' if pins else 'ASSUMPTION',documentation_mismatch=mismatch,version_divergence=divergence,
                assumption=None if pins else f'No version pin in runnable files; PostgreSQL {major} taken from documentation' if described else f'No exact version pin; PostgreSQL {major} default/minimum assumed')


def native_postgres(major):
    """Kompletny lokalny zestaw narzędzi PostgreSQL danej wersji albo None."""
    for directory in (Path('/usr/lib/postgresql')/str(major)/'bin',Path('/opt/homebrew/opt')/f'postgresql@{major}'/'bin',
                      Path('/usr/local/opt')/f'postgresql@{major}'/'bin',Path('/Applications/Postgres.app/Contents/Versions')/str(major)/'bin'):
        if (directory/'postgres').is_file(): return directory
    return None


def backend_instruction(tools,major,system=None,failures=()):
    """Podpowiedź tylko dla przyczyn, które faktycznie wystąpiły."""
    system=system or sys.platform
    actions=[]
    # Kontener nie pomoże, gdy zaplecze odmówiło z powodu izolacji albo zawiodła lokalna baza.
    container_useless=any('isolation unsupported' in f or f.startswith('native:') for f in failures)
    if tools.get('podman') and not container_useless: actions.append('podman machine start' if system=='darwin' else 'start Podman service')
    if (tools.get('docker') or system=='darwin') and not container_useless: actions.append('uruchom Docker Desktop' if system=='darwin' else 'start Docker daemon')
    if not native_postgres(major):
        actions.append(f'brew install postgresql@{major}' if system=='darwin' else f'install/start PostgreSQL {major} using your distribution packages')
    elif any(f.startswith('native:') for f in failures): actions.append('lokalny PostgreSQL jest dostępny; przyczyna w opisie zaplecza native powyżej')
    return '; '.join(actions)


NPM_REGISTRY='https://registry.npmjs.org/'
NODE_MODULES_DOT_ENTRIES=('.bin','.package-lock.json')
RUNTIME_TOOL_PACKAGES=('axe-core','playwright')
CACHE_COMPLETE='.helix-complete'


def installed_packages(modules,prefix='node_modules'):
    """Katalogi paczek faktycznie obecne w drzewie node_modules, także zagnieżdżone; None przy wpisie, którego nie da się zaklasyfikować."""
    found=set()
    try: entries=sorted(Path(modules).iterdir())
    except OSError: return None
    for entry in entries:
        if entry.name.startswith('.'):
            if prefix=='node_modules' or entry.name=='.bin': continue
            return None
        if entry.is_symlink() or not entry.is_dir(): return None
        packages=[entry] if not entry.name.startswith('@') else None
        if packages is None:
            try: packages=sorted(entry.iterdir())
            except OSError: return None
        for package in packages:
            if package.is_symlink() or not package.is_dir(): return None
            name=prefix+'/'+package.relative_to(modules).as_posix(); found.add(name)
            nested=package/'node_modules'
            if nested.is_symlink(): return None
            if nested.is_dir():
                inner=installed_packages(nested,name+'/node_modules')
                if inner is None: return None
                found|=inner
    return found


def node_modules_match(lockfile,modules):
    """Zainstalowane paczki zgodne z plikiem blokady: każda jest na dysku w tej samej wersji, brakować mogą tylko opcjonalne.

    Sprawdzane są pliki package.json paczek, nie sam ukryty plik blokady. Wpisy link (workspace, file:) są odrzucane.
    Treść plików paczek nie jest porównywana z integrity: npm nie zapisuje skrótów rozpakowanych plików.
    """
    try:
        wanted=json.loads(Path(lockfile).read_text())['packages']
        have=json.loads((Path(modules)/'.package-lock.json').read_text())['packages']
    except (OSError,ValueError,KeyError,TypeError): return False
    if not isinstance(wanted,dict) or not isinstance(have,dict) or not have: return False
    if any(isinstance(row,dict) and row.get('link') for row in list(wanted.values())+list(have.values())): return False
    base=Path(modules).resolve().parent
    for name,row in have.items():
        if not isinstance(row,dict) or not isinstance(wanted.get(name),dict) or wanted[name].get('version')!=row.get('version'): return False
        if not name.startswith('node_modules/') or '..' in Path(name).parts: return False
        manifest=base/name/'package.json'
        try:
            if manifest.is_symlink() or (base/name).is_symlink() or json.loads(manifest.read_text()).get('version')!=row.get('version'): return False
        except (OSError,ValueError,AttributeError): return False
    # Paczka na dysku spoza pliku blokady (dołożona ręcznie albo pozostałość) też dyskwalifikuje drzewo.
    if installed_packages(modules)!=set(have): return False
    return all(name in have or row.get('optional') for name,row in wanted.items() if name and isinstance(row,dict))


# Oficjalne miejsca wydań paczek, które opuściły rejestr npm. Inne hosty dopisuje właściciel w runtime.dependency_hosts.
DEPENDENCY_HOSTS=('cdn.sheetjs.com',)


def lockfile_foreign_hosts(lockfile):
    """Hosty archiwów https spoza rejestru npm wskazane w pliku blokady (do komunikatu dla właściciela)."""
    try: rows=json.loads(Path(lockfile).read_text())['packages'].values()
    except (OSError,ValueError,KeyError,TypeError,AttributeError): return []
    return sorted({urlparse(row['resolved']).hostname or '' for row in rows if isinstance(row,dict) and isinstance(row.get('resolved'),str)
                   and row['resolved'].startswith('https://') and not row['resolved'].startswith(NPM_REGISTRY)}-{''})


def package_specs_downloadable(package_json,hosts=()):
    """Czy każda zależność z package.json to zwykły zakres wersji z rejestru albo archiwum https z dozwolonego hosta.
    Instalacja, która sama rozwiązuje zależności (npm install), sięga pod adresy z tego pliku, zanim powstanie plik blokady."""
    try: data=json.loads(Path(package_json).read_text())
    except (OSError,ValueError): return False
    allowed=set(DEPENDENCY_HOSTS)|set(hosts)
    for field in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
        specs=data.get(field,{})
        if not isinstance(specs,dict): return False
        for spec in specs.values():
            if not isinstance(spec,str): return False
            if re.fullmatch(r'[\^~<>=|\s\d.xX*-]+(?:-[0-9A-Za-z.-]+)?|latest',spec): continue
            if re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9._/@+-]+\.t(?:ar\.)?gz',spec) and urlparse(spec).hostname in allowed: continue
            return False
    # Nadpisania wersji: te same zasady co zależności (zakres wersji albo odwołanie $nazwa do zależności głównej).
    def plain(value):
        if isinstance(value,dict): return all(plain(item) for item in value.values())
        return isinstance(value,str) and bool(re.fullmatch(r'[\^~<>=|\s\d.xX*-]+(?:-[0-9A-Za-z.-]+)?|latest|\$[A-Za-z0-9@/._-]+',value))
    return plain(data.get('overrides',{})) and not data.get('workspaces')


def lockfile_downloadable(lockfile,hosts=()):
    """Samodzielne pobranie tylko dla paczek z publicznego rejestru npm albo archiwum https z dozwolonego hosta, zawsze z integrity
    sha512 (npm sprawdza skrót pobranego archiwum, a skrypty paczek przy pobraniu się nie wykonują); bez git, file i link."""
    allowed=set(DEPENDENCY_HOSTS)|set(hosts)
    try: wanted=json.loads(Path(lockfile).read_text())['packages']
    except (OSError,ValueError,KeyError,TypeError): return False
    if not isinstance(wanted,dict): return False
    rows={name:row for name,row in wanted.items() if name}
    if not rows: return False
    def from_registry(row):
        return (isinstance(row.get('resolved'),str) and (row['resolved'].startswith(NPM_REGISTRY) or bool(re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9._/@+-]+\.t(?:ar\.)?gz',row['resolved'])) and urlparse(row['resolved']).hostname in allowed)
                and isinstance(row.get('integrity'),str) and row['integrity'].startswith('sha512-'))
    for name,row in rows.items():
        # Każdy wpis, także pomijany niżej: słownik, bez link, wersja jako zwykły semver (nie adres ani specyfikacja).
        if not isinstance(row,dict) or row.get('link') or not isinstance(row.get('version'),str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?',row['version']): return False
        if from_registry(row): continue
        # Bez własnego adresu przechodzi tylko paczka wbudowana w archiwum rodzica, który sam pochodzi z rejestru z integrity.
        parent=name.rsplit('/node_modules/',1)[0] if '/node_modules/' in name else None
        if row.get('inBundle') is True and 'resolved' not in row and parent and isinstance(rows.get(parent),dict) and from_registry(rows[parent]): continue
        return False
    return True


def links_stay_inside(root):
    """Każde dowiązanie w drzewie wskazuje do środka tego drzewa."""
    root=Path(root).resolve()
    for directory,names,files in os.walk(root):
        for name in names+files:
            path=Path(directory)/name
            if path.is_symlink():
                target=(path.parent/os.readlink(path)).resolve()
                if target!=root and root not in target.parents: return False
    return True


SUPPORTED_KEYCLOAK_IMAGE='quay.io/keycloak/keycloak:26.8.1'


def auto_prepare(blockers,run=subprocess.run,report=None):
    """Wykonaj przygotowania, które Helix umie zrobić sam (pobranie obrazu, instalacja lokalnej bazy); zwróć wykonane."""
    done=[]
    for row in blockers:
        argv=row.get('auto')
        if not argv: continue
        if report: report(f"[helix runtime] przygotowuję sam: {' '.join(argv)} ({row['area']})")
        try: ok=run(argv,capture_output=True,text=True,timeout=1800).returncode==0
        except (OSError,subprocess.SubprocessError): ok=False
        done.append(dict(area=row['area'],command=argv,ok=ok))
    return done


def sysv_segments():
    """Identyfikatory istniejących segmentów pamięci SysV tego użytkownika; None, gdy nie da się ich odczytać."""
    try: done=subprocess.run(['/usr/bin/ipcs','-m'],capture_output=True,text=True,timeout=10)
    except (OSError,subprocess.SubprocessError): return None
    if done.returncode!=0: return None
    return [fields[1] for fields in (line.split() for line in done.stdout.splitlines()) if len(fields)>1 and fields[0]=='m']


def runtime_tmpdir():
    """Katalog przebiegu z krótką ścieżką: gniazdo AF_UNIX ma limit 104 znaków, a domyślny TMPDIR macOS go przekracza."""
    base=Path(tempfile.gettempdir()).resolve()
    if len(str(base))>40:
        for short in (Path('/private/tmp'),Path('/tmp')):
            if short.is_dir() and os.access(short,os.W_OK): base=short.resolve();break
    return Path(tempfile.mkdtemp(prefix='helix-rt-',dir=base)).resolve()


def preflight(project,config=None,only=None):
    """Wszystkie znane przeszkody uruchomienia naraz, bez startu kodu projektu i bez sieci."""
    spec=plan(project,config) if config is not None else plan(project); found=[]
    def add(area,reason,fix): found.append(dict(area=area,reason=reason,fix=fix))
    # Przy --part przeszkody innych części nie dotyczą tego przebiegu.
    for part in (spec.get('identity_plan') or {}).get('parts',[]):
        if only is not None and part.get('part')!=only:continue
        if part.get('status')=='BLOCKED':
            gaps=sorted({g['field']+' ('+g['reason']+')' for g in part.get('gaps',[])})
            add('identity',part['part']+': '+', '.join(gaps),'uzupełnij runtime.keycloak.parts.'+part['part']+' w zewnętrznym --config')
        image=part.get('image'); engine=locate('docker') or locate('podman')
        if part.get('strategy')=='container' and image:
            try: present=bool(engine) and subprocess.run([engine,'image','inspect',image],capture_output=True,timeout=15).returncode==0
            except (OSError,subprocess.SubprocessError): present=False
            if not present:
                add('identity','brak lokalnego obrazu '+image,'docker pull '+image)
                # Sam pobieram wyłącznie przypięty, wspierany obraz gotowego planu; nazwa z projektu nie trafia do polecenia.
                if engine and image==SUPPORTED_KEYCLOAK_IMAGE and part.get('status')=='READY': found[-1]['auto']=[engine,'pull',SUPPORTED_KEYCLOAK_IMAGE]
    target=spec.get('database_target') or {}
    if target.get('engine')=='postgres' and not native_postgres(target['major']):
        add('database',f"brak lokalnego PostgreSQL {target['major']}; serwer bazy w Dockerze i Podmanie nie jest obsługiwany (brak izolacji serwera)",
            f"brew install postgresql@{target['major']}" if sys.platform=='darwin' else f"zainstaluj PostgreSQL {target['major']}")
        brew=locate('brew') if sys.platform=='darwin' else None
        if brew and type(target['major']) is int and 12<=target['major']<=18: found[-1]['auto']=[brew,'install',f"postgresql@{target['major']}"]
    if sys.platform=='darwin':
        from helix_runtime_isolation import SeatbeltBackend,KEYS
        root=runtime_tmpdir()
        try:
            control=root/'control';control.mkdir(mode=0o700);work=root/'work';work.mkdir()
            policy={key:[] for key in KEYS};policy.update(scope='database_server',writable_roots=[str(work)],listen_tcp=[55432],unix_sockets=[str(work/'.s.PGSQL.55432')])
            result=SeatbeltBackend(control).admit(policy,20)
            if result.get('enforcement')!='enforced':
                add('isolation','sonda izolacji procesu: '+str(result.get('reason_code')),'sprawdź wersję systemu i profil Seatbelt; bez przejścia sondy nic się nie uruchomi')
        finally: shutil.rmtree(root,ignore_errors=True)
        foreign=sysv_segments()
        if foreign is None or foreign:
            add('isolation',('nie można policzyć segmentów pamięci SysV' if foreign is None else f'{len(foreign)} segmentów pamięci SysV innych programów na tym koncie')+'; serwer bazy mógłby do nich sięgnąć',
                'zatrzymaj inne lokalne bazy (ipcs -m) albo świadomie dopuść: runtime run --allow-sysv-exposure')
    else:
        add('isolation','izolacja procesów jest dostępna tylko na macOS (Seatbelt); na tym systemie kod projektu i serwer bazy nie zostaną uruchomione','uruchom przebieg na macOS; brak niechronionego trybu zastępczego')
    return found


RESERVED_ENV=frozenset({'PATH','HOME','SHELL','USER','LANG','TMPDIR','PWD','NODE_PATH','PYTHONPATH','LD_LIBRARY_PATH','CI','HOST','HOSTNAME','PORT'})
def oidc_path_var(name):
    """Issuer-building component (realm/tenant/path) — never a process/system variable."""
    return name not in RESERVED_ENV and bool(re.search(r'(?:^|_)(?:REALM|TENANT)(?:$|_)|.+_PATH$',name))

def url_role(name):
    """Classify destinations before following dependencies of issuer expressions."""
    if name in RESERVED_ENV or classification(name)=='random-secret': return None
    if (name in ('ORIGIN','NEXTAUTH_URL','AUTH_URL','BASE_URL','PUBLIC_URL','SITE_URL') or
        re.search(r'REDIRECT_URI|CALLBACK_URL',name) or
        # lista adresów, którym aplikacja pozwala się wywoływać (CORS), to w kopii testowej jej własny adres
        re.search(r'(?:^|_)(?:CORS(?:_ALLOWED)?_ORIGINS?|ALLOWED_ORIGINS?|TRUSTED_ORIGINS?)$',name) or
        (re.search(r'(?:^|_)(?:APP|PUBLIC|SITE)(?:_BASE)?_URL$',name) and
         not re.search(r'AUTH|OIDC|KC|ISSUER|IDP|KEYCLOAK',name))): return 'app-url'
    if oidc_path_var(name) and classification(name)!='loopback': return 'idp-path'
    return 'issuer'


def app_url(name, port, previous='', public_origin=None):
    path=urlparse(previous).path if re.search(r'REDIRECT_URI|CALLBACK_URL',name) else ''
    return (public_origin or 'http://127.0.0.1:'+str(port))+path


def stub_404_reason(requests, roles):
    if not any(r.get('status')==404 and r.get('source')=='stub' for r in requests): return ''
    suspects=', '.join(name+' (assigned '+role+')' for name,role in sorted(roles.items()) if role=='app-url')
    return '; ASSUMPTION: callback reached stub; inspect '+(suspects or 'issuer URL dependencies (assigned issuer)')


def qualify_image(image):
    """Fully qualify short image names (podman refuses unqualified short names without registries.conf)."""
    first=image.split('/')[0]
    if '.' in first or ':' in first.split('@')[0] and '/' in image or first=='localhost': return image
    return ('docker.io/library/'+image) if '/' not in image else 'docker.io/'+image

class Blocked(Exception):
    pass


class Interrupted(BaseException):
    """Sygnał zatrzymania. Nie jest zwykłym błędem pomiaru: przechodzi przez pętle, które takie błędy łapią i idą dalej
    (sprawdzenia, przegląd tras), aż do sprzątania przebiegu."""


def safe_name(name):
    return Path(name).suffix.lower() not in {'.csv','.dump','.backup','.sqlite','.sqlite3','.db','.parquet','.xlsx'} and name not in EXCLUDE and (not name.startswith('.env') or name in ('.env.example', '.env.sample')) and not re.search(r'(?i)(?:\.pem$|\.key$|credentials(?:\.(?:json|ya?ml|toml|ini|txt|xml|cfg|conf|properties|bak))?$|secrets?\.json$|^id_rsa)', name)


def files(root):
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if safe_name(d) and not (Path(base)/d).is_symlink())
        for name in sorted(names):
            p = Path(base)/name
            if safe_name(name) and not p.is_symlink() and p.is_file():
                yield p


def read(p):
    from helix_audit_context import safe_read
    return safe_read(p)


def env_names(text):
    result = set(re.findall(r'(?:process\.env\.|import\.meta\.env\.|os\.environ\.)([A-Z][A-Z0-9_]*)', text))
    result.update(re.findall(r'(?:process\.env|import\.meta\.env|os\.environ)\s*\[\s*[\'\"]([A-Z][A-Z0-9_]*)', text))
    result.update(re.findall(r'(?:os\.getenv|os\.environ\.get)\(\s*[\'\"]([A-Z][A-Z0-9_]*)', text))
    for group in re.findall(r'import\s*\{([^}]+)\}\s*from\s*[\'\"]\$env/(?:static|dynamic)/(?:private|public)[\'\"]', text):
        result.update(re.findall(r'\b[A-Z][A-Z0-9_]+\b', group))
    result.update(re.findall(r'\benv\.([A-Z][A-Z0-9_]*)', text))
    for alias in re.findall(r'import\s*\{\s*env\s+as\s+(\w+)\s*\}\s*from\s*[\'\"]\$env/dynamic/private',text):
        result.update(re.findall(r'\b'+re.escape(alias)+r'\.([A-Z][A-Z0-9_]*)',text))
    result.update(re.findall(r'\benv\s*\[\s*[\'\"]([A-Z][A-Z0-9_]*)',text))
    result.update(re.findall(r'\b([A-Z0-9_]*(?:ISSUER|OIDC|KEYCLOAK|AUTH0|OKTA|COGNITO|AUTH_URL|REALM|DISCOVERY)[A-Z0-9_]*)\s*[:=]',text))
    result.update(re.findall(r'(?:^|\n)\s*(?:-\s*)?([A-Z][A-Z0-9_]+)\s*[:=]',text))
    result.update(re.findall(r'\bname:\s*([A-Z][A-Z0-9_]+)\b',text))
    result.update(re.findall(r'\$\{([A-Z][A-Z0-9_]+)',text))
    for group in re.findall(r'\{([^}]+)\}\s*=\s*(?:process\.env|import\.meta\.env)',text):
        result.update(re.findall(r'\b[A-Z][A-Z0-9_]+\b',group))
    return result


def first_error(output):
    lines=[line.strip() for line in output.splitlines() if line.strip() and not line.lstrip().startswith(('$ ','exit='))]
    return next((line for line in lines if re.search(r'error|exception|fatal|failed|not HTML',line,re.I)), next((line for line in lines if not line.startswith('$ ')), 'command returned no diagnostic'))[:600]


def runner_suggestions(runner, sources):
    """Parse data as argv, never as a shell program; only the known runner."""
    found=[]
    name=Path(runner['path']).name
    for path,text in sources.items():
        for number,line in enumerate(text.splitlines(),1):
            pattern=r'((?:[A-Z][A-Z0-9_]*=[\w./:-]+\s+)*(?:(?:bash|sh)\s+)?(?:\./)?'+re.escape(name)+r'(?:\s+[\w./:=+-]+)*)'
            for match in re.finditer(pattern,line):
                tokens=shlex.split(match[0]); env={}
                while tokens and re.fullmatch(r'[A-Z][A-Z0-9_]*=[\w./:-]+',tokens[0]):
                    key,value=tokens.pop(0).split('=',1)
                    if classification(key) in ('database','random-secret') or 'AUTH' in key: break
                    env[key]=value
                if tokens and tokens[0] in ('bash','sh'): tokens.pop(0)
                if not tokens or Path(tokens.pop(0)).name!=name: continue
                if not env and not any(t.startswith('--') or t=='baseline' for t in tokens): continue
                argv=(runner['argv'][:2] if runner['argv'][0] in ('bash','sh') else [runner['argv'][0]])+tokens
                skipped=bool(re.search(r'baseline', ' '.join(tokens)+' '+' '.join(env),re.I))
                found.append(dict(runner,argv=argv,env=env,fresh=True,
                    skip_reason='baseline adoption without SQL is forbidden' if skipped else None,
                    fresh_evidence=dict(path=path,line=number),
                    priority=0 if re.search(r'fresh|od zera|śwież|new|empty|bootstrap|guard',line,re.I) else 1))
    return sorted(found,key=lambda r:r['priority'])


def runner_key(runner):
    return (runner['path'],tuple(runner['argv']),tuple(sorted(runner.get('env',{}).items())))


def oidc_dependencies(sources):
    """Conservative static dependency slice of issuer/discovery expressions."""
    text='\n'.join(sources.values())
    assignments={}
    for match in re.finditer(r'(?:const|let|var)\s+(\w+)(?:\s*:[^=;\n]+)?\s*=\s*([^;]+)',text):
        assignments.setdefault(match[1],[]).append(match[2])
    expressions=[line for line in text.splitlines() if re.search(r'issuer|discovery|well-known/openid|new URL.*realms',line,re.I)]
    seen=set(); names=set()
    while expressions:
        expr=expressions.pop()
        names.update(env_names(expr))
        # Handles typed helper calls such as required('IDENTITY_BASE_URL').
        names.update(re.findall(r"['\"]([A-Z][A-Z0-9_]+)['\"]",expr))
        for ident in re.findall(r'\b[a-zA-Z_$][\w$]*\b',expr):
            if ident in assignments and ident not in seen:
                seen.add(ident); expressions.extend(assignments[ident])
    return sorted(n for n in names if classification(n)=='loopback' or oidc_path_var(n))


def project_runners(sources):
    runners=[]
    def add(path, argv, cwd=None):
        runners.append(dict(path=path,kind='runner',argv=argv,cwd=cwd or str(Path(path).parent)))
    for path,text in sources.items():
        name=Path(path).name
        if re.fullmatch(r'migrate[^/]*\.sh',name):
            args=['up'] if re.search(r'\bup\)',text) or re.search(r'\$\{?1[^\n]*up',text) else []
            add(path,['bash',name]+args)
        elif name=='Makefile':
            for target in re.findall(r'^(db-[\w-]+|migrate[\w-]*):',text,re.M):
                add(path,['make',target])
        elif name=='package.json':
            for script in json.loads(text).get('scripts',{}):
                if script in ('db:migrate','migrate'): add(path,['npm','run',script])
    conventions=[('supabase/config.toml',['supabase','db','reset','--db-url','{database}']),
                 ('flyway.conf',['flyway','-url={jdbc_database}','-user=helix','migrate']),('sqitch.plan',['sqitch','deploy','--target','{database}']),
                 ('schema.prisma',['npx','--no-install','prisma','migrate','deploy']),
                 ('drizzle.config.ts',['npx','--no-install','drizzle-kit','migrate']),
                 ('knexfile.js',['npx','--no-install','knex','migrate:latest']),
                 ('alembic.ini',['alembic','upgrade','head']),('manage.py',['python3','manage.py','migrate','--noinput'])]
    for path in sources:
        for marker,argv in conventions:
            if path.endswith(marker): add(path,argv)
    if any('-- migrate:up' in t for p,t in sources.items() if p.endswith('.sql')): add('dbmate',['dbmate','up'],'.')
    if any(p.endswith('.up.sql') for p in sources):
        directory=str(Path(next(p for p in sources if p.endswith('.up.sql'))).parent)
        add(directory,['migrate','-path',directory,'-database','{database}','up'],'.')
    if not any(r['argv'][0]=='flyway' for r in runners):
        flyway=next((p for p in sources if re.match(r'V\d+.*__.*\.sql$',Path(p).name)),None)
        if flyway: add(flyway,['flyway','-url={jdbc_database}','-user=helix','-locations=filesystem:.','migrate'])
    for path in sources:
        if re.fullmatch(r'knexfile\.(?:ts|cjs|mjs)',Path(path).name): add(path,['npx','--no-install','knex','migrate:latest','--knexfile',Path(path).name])
        if re.fullmatch(r'drizzle\.config\.(?:js|mjs|cjs|mts|cts)',Path(path).name): add(path,['npx','--no-install','drizzle-kit','migrate','--config',Path(path).name])
    for runner in runners:
        runner['documentation']=[dict(path=p,line=n) for p,t in sources.items() if Path(p).name.lower().startswith('readme') and ('migrat' in p.lower() or Path(p).parent==Path(runner['path']).parent) for n,line in enumerate(t.splitlines(),1) if re.search(r'migrat|deploy|reset',line,re.I)][:12]
    variants=[]
    for runner in runners:
        variants.append(runner)
        nearby={p:t for p,t in sources.items() if p==runner['path'] or Path(p).parent==Path(runner['path']).parent and Path(p).name.lower().startswith('readme')}
        modes=[]
        for path,text in nearby.items():
            lines=text.splitlines()
            for number,line in enumerate(lines,1):
                context=' '.join(lines[max(0,number-3):number+2])
                for name in re.findall(r'\b(?:[A-Z][A-Z0-9_]*)?(?:FRESH|BOOTSTRAP|FIRST_RUN|INIT)(?:[A-Z0-9_]*)\b',line):
                    # Thresholds are not switches. Require an assignment or a shell guard.
                    if re.search(r'\b'+name+r'=1\b',line) or ('if ' in line and re.search(r'\$\{?'+re.escape(name)+r'(?::-[^}]*)?\}?["\']?\s*!=\s*["\']?1\b',line)):
                        modes.append((dict(env={name:'1'}),dict(path=path,line=number)))
                if path==runner['path'] and re.search(r'if\s+\[.*-z\s+',line) and re.search(r'\bexit\b',' '.join(lines[number-1:number+8])) and re.search(r'fresh|bootstrap|baseline|first.run|śwież|pusta',context,re.I):
                    for name in re.findall(r'\$\{?([A-Z][A-Z0-9_]*)',line):
                        if classification(name) not in ('database','random-secret') and not re.search(r'AUTH',name):
                            modes.append((dict(env={name:'1'}),dict(path=path,line=number)))
                if re.search(r'fresh database|first run|bootstrap|śwież',context,re.I) or path==runner['path'] and re.search(r'--(?:fresh|init|baseline=0)\b',line):
                    for name,value in re.findall(r'\b([A-Z][A-Z0-9_]*)=(1|true)\b',line):
                        if classification(name) not in ('database','random-secret') and not re.search(r'AUTH',name):
                            modes.append((dict(env={name:value}),dict(path=path,line=number)))
                    for flag in re.findall(r'--(?:fresh|init|baseline=0)\b',line):
                        modes.append((dict(argv=runner['argv']+[flag]),dict(path=path,line=number)))
        seen=set()
        for mode,evidence in modes:
            key=str(mode)
            if key in seen: continue
            seen.add(key)
            variants.append(dict(runner,**mode,fresh=True,fresh_evidence=evidence))
    for runner in runners:
        nearby={p:t for p,t in sources.items() if p==runner['path'] or Path(p).name.lower().startswith('readme')}
        variants.extend(runner_suggestions(runner,nearby))
    unique={}
    for variant in variants:
        if re.search(r'baseline', ' '.join(variant['argv'])+' '+' '.join(variant.get('env',{})),re.I):
            variant['skip_reason']='baseline adoption without SQL is forbidden'
        unique.setdefault(runner_key(variant),variant)
    return sorted(unique.values(),key=lambda r: (bool(r.get('fresh')),r.get('priority',0)))


def classification(name):
    if re.search(r'DATABASE|POSTGRES|PGHOST|PGPORT|PGUSER|PGPASSWORD|PGDATABASE|^DB_(?:HOST|PORT|USER|PASSWORD|NAME|URL)$', name): return 'database'
    if re.search(r'URL|URI|HOST|ORIGIN|ENDPOINT|ISSUER|DSN|WEBHOOK', name): return 'loopback'
    if re.search(r'SECRET|TOKEN|PASSWORD|KEY|SALT', name): return 'random-secret'
    return 'dummy'


def sql_without_comments(text):
    """Preserve quoted SQL literals/identifiers while removing nested comments."""
    quoted=re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|(?P<tag>\$(?:[A-Za-z_]\w*)?\$).*?(?P=tag)",re.S)
    result=[]; index=0; depth=0
    while index<len(text):
        if text.startswith('/*',index):
            depth+=1; index+=2; result.append(' ')
        elif depth:
            if text.startswith('*/',index): depth-=1; index+=2
            else: index+=1
        elif text.startswith('--',index):
            end=text.find('\n',index)
            index=len(text) if end<0 else end
            result.append(' ')
        else:
            match=quoted.match(text,index)
            end=match.end() if match else index+1
            result.append(text[index:end]); index=end
    return ''.join(result)


def personal_emails(text):
    emails=set(re.findall(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',sql_without_comments(text).lower()))
    def synthetic(email):
        domain=email.split('@')[1]
        return (domain.split('.')[0]=='example' or '.example.' in domain
                or domain in {'test','local','localhost','invalid'}
                or domain.endswith(('.test','.local','.localhost','.invalid')))
    # A single explicitly named service account is configuration, not a user dataset.
    real=[e for e in emails if not synthetic(e)]
    return bool(real) and not (len(real)==1 and real[0].split('@')[0] in
                              {'admin','system','service','noreply','no-reply','bot','support'})


def table_events(text):
    plain=sql_without_comments(text)
    # Ignore SQL-looking text in literals and routine bodies.
    plain=re.sub(r"'(?:''|[^'])*'|(?P<tag>\$(?:[A-Za-z_]\w*)?\$).*?(?P=tag)",' ',plain,flags=re.S)
    ident=r'(?:"[^"]+"|[A-Za-z_][\w$]*)(?:\s*\.\s*(?:"[^"]+"|[A-Za-z_][\w$]*))?'
    for match in re.finditer(r'\b(CREATE\s+(?:(?:UNLOGGED|TEMPORARY|TEMP)\s+)?TABLE(?:\s+IF\s+NOT\s+EXISTS)?|ALTER\s+TABLE(?:\s+IF\s+EXISTS)?(?:\s+ONLY)?|REFERENCES)\s+('+ident+r')',plain,re.I):
        operation,name=match.groups()
        name=re.sub(r'\s*\.\s*','.',name.replace('"','').lower())
        # public is the default runtime search path.
        yield operation.upper().startswith('CREATE'),name.removeprefix('public.')


def initial_sql(text):
    created=set()
    for creating,name in table_events(text):
        if creating: created.add(name)
        elif name not in created: return False
    return bool(created)


def synthetic_sql(text):
    """Conservative PII/dump heuristic, not a proof of data provenance."""
    if not text or len(text.encode()) > 100_000: return False
    text=sql_without_comments(text)
    if personal_emails(text): return False
    if re.search(r'(?<!\w)(?:\+?\d[ ()-]*){9,15}(?!\w)|(?i:pg_dump|COPY\s+.*?FROM\s+stdin)',text): return False
    # Disallow SQL file/meta commands, dynamic code and network-capable statements.
    if re.search(r'\\|(?i:\b(?:DO|CALL|EXECUTE|COPY|CREATE|ALTER|DROP|dblink|postgres_fdw)\b)',text): return False
    scrubbed=re.sub(r"'(?:''|[^'])*'", '0',text)
    scrubbed=re.sub(r'--[^\n]*|/\*.*?\*/','',scrubbed,flags=re.S)
    ident=r'(?:[A-Za-z_][A-Za-z_0-9]*|"[A-Za-z_][A-Za-z_0-9]*")'
    literal=r'(?:[-+]?\d+(?:\.\d+)?|NULL|TRUE|FALSE|DEFAULT)'
    row=r'\(\s*'+literal+r'(?:\s*,\s*'+literal+r')*\s*\)'
    statement=r'INSERT\s+INTO\s+'+ident+r'(?:\.'+ident+r')?(?:\s*\(\s*'+ident+r'(?:\s*,\s*'+ident+r')*\s*\))?\s+VALUES\s*'+row+r'(?:\s*,\s*'+row+r')*'
    statements=[x.strip() for x in scrubbed.split(';') if x.strip()]
    return bool(statements) and all(re.fullmatch(statement,x,re.I) for x in statements)



def transactional_sql(sql):
    """Remove standalone transaction wrappers, preserving strings and routine bodies.

    psql --single-transaction owns the transaction. An embedded COMMIT must
    never make a failed file leave a partially committed schema behind.
    """
    tokens=re.compile(r"--[^\n]*|/\*.*?\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|(?P<dollar>\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$).*?(?P=dollar)|;",re.S)
    start=0; statements=[]
    for match in tokens.finditer(sql):
        if match.group()!=';': continue
        statement=sql[start:match.end()];start=match.end()
        plain=re.sub(r'--[^\n]*|/\*.*?\*/','',statement,flags=re.S).strip()
        if not re.fullmatch(r'(?:BEGIN(?:\s+(?:WORK|TRANSACTION))?|START\s+TRANSACTION|COMMIT(?:\s+WORK)?|END(?:\s+WORK)?|ROLLBACK(?:\s+WORK)?)\s*;',plain,re.I):
            statements.append(statement)
    statements.append(sql[start:])
    return ''.join(statements)


def up_sql(text):
    """dbmate directives are comments, so split before comment removal."""
    up=re.search(r'^\s*--\s*migrate:up\b.*$',text,re.M|re.I)
    if up:
        prefix='\n'*text[:up.end()].count('\n')
        text=prefix+text[up.end():]
        down=re.search(r'^\s*--\s*migrate:down\b',text,re.M|re.I)
        if down: text=text[:down.start()]
    return text


def error_summary(notes):
    groups={}
    for note in notes:
        reason=note['reason']
        errors=[line for line in reason.splitlines() if re.search(r'\b(?:ERROR|FATAL):',line)]
        if errors: reason=errors[0]
        category='fresh-database-guard' if re.search(r'fresh database|empty migration|schema_migrations.*(?:empty|pust)|bootstrap.*required',reason,re.I) else next((k for k in ('already exists','does not exist','syntax','extension') if k in reason.lower()),'other')
        entry=groups.setdefault(category,dict(category=category,count=0,examples=[]))
        entry['count']+=1
        if len(entry['examples'])<2:
            entry['examples'].append(dict(path=note['path'],line=note.get('line',1),error=reason[-400:]))
    return sorted(groups.values(),key=lambda x:-x['count'])[:5]


def migration_order(path):
    name=Path(path).name
    # Flyway repeatables follow all versioned files.
    prefix=2 if re.match(r'R__',name) else 1
    return [(1,prefix)]+[(1,int(x)) if x.isdigit() else (0,x) for x in re.split(r'(\d+)',path)]


def database_sources(part, items, parts):
    """App-local sources plus shared siblings; never borrow another app's DB."""
    prefix='' if part['path']=='.' else part['path']+'/'
    others=[p['path']+'/' for p in parts if p is not part and p['path']!='.']
    return [m for m in items if prefix and m['path'].startswith(prefix) or not any(m['path'].startswith(p) for p in others)]


def extension_requirements(migrations):
    """Merge already scoped declarations without reading or executing a project."""
    declarations={}; gaps={}; unknown=False
    for migration in migrations:
        snapshot=migration.get('extensions',{})
        for row in snapshot.get('declarations',[]):
            declarations[(row['path'],row['line'],row['name'],row.get('declared_version'))]=dict(row)
        for row in snapshot.get('gaps',[]):
            gaps[(row['path'],row['line'],row['reason_code'])]=dict(row)
        if snapshot.get('requirements_status')=='unknown' or migration['kind']!='sql':
            unknown=True
            row=dict(path=migration['path'],line=1,reason_code='DYNAMIC_RUNNER_REQUIREMENTS_UNKNOWN')
            gaps[(row['path'],row['line'],row['reason_code'])]=row
    return dict(declarations=sorted(declarations.values(),key=lambda r:(r['path'],r['line'],r['name'],r.get('declared_version') or '')),
                gaps=sorted(gaps.values(),key=lambda r:(r['path'],r['line'],r['reason_code'])),
                requirements_status='unknown' if unknown or gaps else 'recorded')


def manager(root, directory):
    for parent in (directory, *directory.parents):
        if not parent.is_relative_to(root): break
        for lock, pm in [('pnpm-lock.yaml','pnpm'),('yarn.lock','yarn'),('package-lock.json','npm'),('pnpm-workspace.yaml','pnpm')]:
            if (parent/lock).is_file(): return pm, parent.relative_to(root).as_posix(), lock
        pkg = parent/'package.json'
        if pkg.is_file():
            declared = json.loads(read(pkg)).get('packageManager','').split('@')[0]
            if declared in ('npm','pnpm','yarn'): return declared, parent.relative_to(root).as_posix(), None
    return 'npm', directory.relative_to(root).as_posix(), None


def react_router_paths(text, base=None, mounts=None):
    """Adresy z elementów <Route path="..."> (zagnieżdżone składane z rodzicem) i wpisów tablicy tras ({ path: '...', element });
    parametr :id jako [id]. Zwraca (adresy, liczba ścieżek względnych bez rodzica w tym pliku).

    base: plik jest modułem z własnymi <Routes>, zamontowanym pod `base/*` w innym pliku; w React Routerze 6 jego ścieżki
    (także zaczynające się od „/”) są względne wobec base. Projekt B: `<Route path="/types">` w Tasks.tsx to /tasks/types,
    a Helix sprawdzał nieistniejące /types (aplikacja przekierowała na start).
    mounts: lista, do której trafiają montowania (adres, nazwy komponentów w element) z tras `x/*` i `*`."""
    found=[];stack=[base] if base else [];unresolved=0;index=0
    def resolve(value,parent):
        if value.startswith('/') and base is None:return value
        return None if parent is None else parent.rstrip('/')+'/'+value.lstrip('/')
    while True:
        opening=text.find('<Route',index);closing=text.find('</Route>',index)
        if opening<0 and closing<0:break
        if closing>=0 and (opening<0 or closing<opening):
            if stack:stack.pop()
            index=closing+8;continue
        if text[opening+6:opening+7].isalnum() or text[opening+6:opening+7]=='s':index=opening+6;continue  # <Routes>, <RouteGuard>
        # koniec znacznika: pierwszy '>' poza nawiasami klamrowymi i napisami (atrybut element={<X />} zawiera własne '>')
        depth=0;quote=None;end=opening+6
        while end<len(text):
            char=text[end]
            if quote:
                if char==quote:quote=None
            elif char in '"\'`':quote=char
            elif char=='{':depth+=1
            elif char=='}':depth-=1
            elif char=='>' and depth==0:break
            end+=1
        tag=text[opening:end];selfclosing=tag.rstrip().endswith('/')
        match=re.search(r'\bpath=(?:["\']([^"\']*)["\']|\{["\'`]([^"\'`]*)["\'`]\})',tag)
        path=next((value for value in match.groups() if value is not None),None) if match else None
        parent=stack[-1] if stack else None
        mount=None
        if path is None:full=parent                       # trasa układu albo index: adres rodzica
        elif path=='*' or path.endswith('/*'):            # „wszystko pod”: bez własnego adresu, ale montuje moduł pod adresem
            full=None;head=path[:-1].rstrip('/')
            mount=parent if not head else resolve(head,parent)
            if mounts is not None and mount:mounts.append((mount,re.findall(r'<([A-Z][A-Za-z0-9_]*)',tag)))
        elif '*' in path:full=None                        # trasa „wszystko inne” nie ma własnego adresu
        else:
            full=resolve(path,parent)
            if full is None:unresolved+=1
        if full is not None and (path is not None or re.search(r'\bindex\b',tag)):found.append(full)
        if not selfclosing:stack.append(mount if mount else full)
        index=end+1
    listed=re.findall(r'\bpath:\s*["\']([^"\']+)["\']\s*,\s*(?:element|Component|lazy|children|loader)\b',text)
    # Wpis tablicy tras ze ścieżką względną (dziecko innego wpisu) nie ma pełnego adresu bez składania drzewa: liczony jako pominięty.
    unresolved+=sum(1 for path in listed if not path.startswith('/') and '*' not in path)
    found+=listed
    out=set()
    for path in found:
        if not path.startswith('/') or '*' in path or '?' in path: continue
        route='/'+'/'.join('['+x[1:]+']' if x.startswith(':') else x for x in path.split('/') if x)
        if re.fullmatch(r'/|(?:/(?:[A-Za-z0-9._~-]+|\[[A-Za-z0-9_]+\]))+',route): out.add(route)
    return out,unresolved


def component_files(sources, prefix=''):
    """Nazwa komponentu -> pliki, z których pochodzi: `X = lazy(() => import('...'))`, `import X from '...'` i plik o nazwie X."""
    import posixpath
    names={};known=set(sources)
    def target(spec,origin):
        if spec.startswith('@/'):stem=prefix+'src/'+spec[2:]
        elif spec.startswith('.'):stem=posixpath.normpath(posixpath.join(posixpath.dirname(origin),spec))
        else:return None
        return next((c for c in [stem]+[stem+e for e in ('.tsx','.ts','.jsx','.js')]+[stem+'/index'+e for e in ('.tsx','.ts','.jsx','.js')] if c in known),None)
    for origin,text in sources.items():
        pairs=re.findall(r'\b([A-Z][A-Za-z0-9_]*)\s*=\s*[\w.]*\(\s*\(\)\s*=>\s*import\(\s*["\']([^"\']+)["\']',text)
        pairs+=re.findall(r'^\s*import\s+([A-Z][A-Za-z0-9_]*)\s+from\s+["\']([^"\']+)["\']',text,re.M)
        for name,spec in pairs:
            found=target(spec,origin)
            if found:names.setdefault(name,set()).add(found)
        stem=Path(origin).stem
        if stem[:1].isupper():names.setdefault(stem,set()).add(origin)
    return names


def plan(project, config=None):
    root = Path(project).resolve()
    if not root.is_dir(): raise ValueError('project must be a directory')
    if config is None:
        from helix_config import load
        config=load(root)
    sources = {p.relative_to(root).as_posix(): read(p) for p in files(root) if p.suffix in SOURCE or p.name in ('.env.example','.env.sample','requirements.txt','Dockerfile','Makefile','go.mod','Gemfile','crontab') or p.name.startswith('Dockerfile.')}
    variables = set(); structured = set(); settings_declared = {}; encoded = set()
    for path, text in sources.items():
        # Ustawienie zadeklarowane w Pythonie jako lista, słownik albo zbiór czyta ze środowiska JSON, nie zwykły napis.
        if Path(path).suffix=='.py' and re.search(r'BaseSettings|pydantic_settings',text): settings_declared.update(python_settings(text))
        if Path(path).suffix=='.py': structured.update(re.findall(STRUCTURED_SETTING,text,re.M))
        if Path(path).name in ('.env.example','.env.sample'):
            variables.update(re.findall(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=', text, re.M))
        elif Path(path).suffix != '.sql':
            found=env_names(text); variables.update(found)
            # sekret, który kod czyta jako base64 (np. klucz szyfrowania), musi mieć taki format, inaczej aplikacja wyłącza funkcję
            encoded.update(n for n in found if classification(n)=='random-secret' and re.search(re.escape(n)+r'[\s\S]{0,600}base64|base64[\s\S]{0,600}'+re.escape(n),text))
        if Path(path).suffix in ('.yaml','.yml','.toml'):
            variables.update(re.findall(r'\b([A-Z0-9_]*(?:ISSUER|OIDC|KEYCLOAK|AUTH0|OKTA|COGNITO|AUTH_URL|REALM|DISCOVERY)[A-Z0-9_]*)\b',text))
    parts = []
    for path, text in sources.items():
        p = Path(path)
        if p.name != 'package.json': continue
        pkg = json.loads(text)
        deps = {**pkg.get('dependencies',{}), **pkg.get('devDependencies',{})}
        framework = next((label for dep,label in FRAMEWORKS if dep in deps), None)
        scripts = pkg.get('scripts',{})
        if not framework and not (scripts.get('start') or scripts.get('dev')): continue
        framework = framework or 'node'
        directory = root/p.parent
        pm, workspace, lock = manager(root, directory)
        start = 'start' if 'start' in scripts else 'preview' if 'preview' in scripts else 'dev' if 'dev' in scripts else None
        command = [pm, 'run', start] if start else ['node','build'] if framework == 'sveltekit' and '@sveltejs/adapter-node' in deps else None
        # adapter-node projects often expose preview only; run the production adapter after build.
        if framework == 'sveltekit' and not scripts.get('start') and '@sveltejs/adapter-node' in deps: command = ['node','build']
        routes = {'/'}; patterns = set(); router_unresolved = 0
        prefix = '' if str(p.parent)=='.' else p.parent.as_posix()+'/'
        for f in sources:
            if not f.startswith(prefix): continue
            rel = f[len(prefix):]
            m = re.search(r'(?:src/routes/(.*?)/?\+page\.|(?:src/)?app/(.*?)/?page\.|(?:src/)?pages/(.*?)\.(?:vue|tsx|jsx|astro))', rel)
            if m:
                route = next((v for v in m.groups() if v is not None), '')
                route = '/'+ '/'.join(x for x in route.split('/') if x and not x.startswith('('))
                if not re.search(r'[\[\]:*]', route): routes.add(route.removesuffix('/index') or '/')
                # Trasa z parametrem nie ma adresu z góry; konkretny adres odkrywa e2e z odnośników na obejrzanych ekranach.
                elif re.fullmatch(r'(?:/(?:[A-Za-z0-9._~-]+|\[[A-Za-z0-9_]+\]))+', route): patterns.add(route)
        # Aplikacja z React Routerem deklaruje adresy w elementach Route; katalog pages to wtedy zwykłe pliki komponentów, nie trasy.
        if ('react-router-dom' in deps or 'react-router' in deps) and 'next' not in deps:
            declared=set();loose=0;mounts=[]
            scripts_={f:text for f,text in sources.items() if f.startswith(prefix) and Path(f).suffix in ('.tsx','.jsx','.ts','.js')}
            for text in scripts_.values():react_router_paths(text,mounts=mounts)
            # Moduł z własnymi <Routes> zamontowany pod `x/*` (wprost albo przez lazy/import): jego ścieżki składane z x.
            components=component_files(scripts_,prefix);bases={}
            for mount,names_ in mounts:
                for name in names_:
                    for f in components.get(name,()):bases.setdefault(f,set()).add(mount)
            # Plik z własnymi <Routes>, którego nie renderuje router aplikacji (plik z BrowserRouter/RouterProvider i komponenty
            # użyte w nim) ani trasa `x/*`, ma trasy nieosiągalne: liczone jako pominięte, nie jako adresy główne
            # (projekt B: SettingsPage.tsx z dwiema trasami, nigdzie nie montowany).
            providers=[f for f,text in scripts_.items() if re.search(r'\b(?:BrowserRouter|HashRouter|MemoryRouter|createBrowserRouter|createHashRouter|RouterProvider)\b',text)]
            roots=set(providers)
            for f in providers:
                for name in re.findall(r'<([A-Z][A-Za-z0-9_]*)',scripts_[f]):roots.update(components.get(name,()))
            for f,text in scripts_.items():
                if providers and f not in roots and not bases.get(f) and '<Routes' in text:
                    loose+=len(react_router_paths(text)[0]);continue
                for base in sorted(bases.get(f) or [None],key=str):
                    paths,missing=react_router_paths(text,base=base);declared.update(paths);loose+=missing
            # Ścieżka względna, której rodzic jest w innym pliku, nie ma pełnego adresu z samego kodu: zakres pominięty jest jawny,
            # także wtedy, gdy żadnej trasy nie udało się odczytać.
            router_unresolved=loose
            if declared:
                routes={'/'}|{r for r in declared if not re.search(r'[\[\]]',r)}; patterns={r for r in declared if '[' in r}
        build=[pm,'run','build'] if 'build' in scripts else None
        defaults={
            'next':(['npx','--no-install','next','build'],['npx','--no-install','next','start']),
            'nuxt':(['npx','--no-install','nuxt','build'],['node','.output/server/index.mjs']),
            'astro':(['npx','--no-install','astro','build'],['npx','--no-install','astro','preview']),
        }
        if framework in defaults:
            build=build or defaults[framework][0]; command=command or defaults[framework][1]
        if 'vite' in deps:
            build=build or ['npx','--no-install','vite','build']
            command=command or ['npx','--no-install','vite','preview']
        main=pkg.get('main')
        if not command and isinstance(main,str) and (directory/main).is_file(): command=['node',main]
        port_match = re.search(r'(?:--port[ =]|PORT=|listen\(\s*)(\d{2,5})', ' '.join(str(v) for v in scripts.values()))
        parts.append(dict(name=p.parent.as_posix(), path=p.parent.as_posix(), framework=framework, package_manager=pm, workspace=workspace, lockfile=lock,
                          build=build, start=command,
                          port=int(port_match[1]) if port_match else 3000 if framework in ('next','nuxt','express','fastify','nest') else 4173,
                          routes=sorted(routes), route_patterns=sorted(patterns)))
        from helix_runtime_supabase import detect as supabase_detect
        found=supabase_detect(directory,deps)
        if found:parts[-1]['supabase']=found
        if router_unresolved:parts[-1]['routes_unresolved']=dict(count=router_unresolved,reason='relative React Router paths whose parent route is declared in another file, or routes of a module with its own <Routes> that the app router never mounts')
    for path,text in sources.items():
        if Path(path).name not in ('requirements.txt','pyproject.toml'): continue
        framework = 'django' if re.search(r'(?i)\bdjango\b',text) else 'fastapi' if re.search(r'(?i)\bfastapi\b',text) else None
        if not framework: continue
        parent = Path(path).parent.as_posix()
        module = next((Path(f).relative_to(Path(parent)).with_suffix('').as_posix().replace('/','.')+':app' for f,t in sources.items() if f.startswith('' if parent=='.' else parent+'/') and 'FastAPI(' in t), None)
        if any(p['path']==parent for p in parts): continue
        parts.append(dict(name=parent,path=parent,framework=framework,package_manager='pip',workspace=parent,lockfile=None,build=None,
                          start=['python','manage.py','runserver','127.0.0.1:{port}','--noreload'] if framework=='django' else ['python','-m','uvicorn',module,'--host','127.0.0.1','--port','{port}'] if module else None,port=8000,routes=['/']))
    from helix_runtime_adapters import worker_parts
    parts.extend(worker_parts(sources, parts))
    migrations=[]; seeds=[]
    for path,text in sources.items():
        low=path.lower()
        if set(Path(low).parts[:-1]) & {'archive','archived','old','legacy','deprecated','backup','_unused','examples'}: continue
        if path.endswith(('.down.sql', '.undo.sql')): continue
        if Path(path).suffix=='.sql' and ('migration' in low or 'supabase/' in low or '/drizzle/' in '/'+low or '/schema/' in '/'+low or Path(path).name=='schema.sql' or re.search(r'\b(?:CREATE|ALTER|DROP)\b',sql_without_comments(text),re.I)):
            migrations.append(dict(kind='sql',path=path))
        elif 'seed' in Path(path).stem.lower():
            safe=Path(path).suffix=='.sql' and synthetic_sql(text)
            seeds.append(dict(path=path,status='SYNTHETIC' if safe else 'BLOCKED',reason='SQL passed conservative synthetic heuristic' if safe else 'untrusted or personal seed; generated rows instead'))
        elif Path(path).name=='sqitch.plan': migrations.append(dict(kind='sqitch',path=path))
        elif Path(path).name=='schema.prisma': migrations.append(dict(kind='prisma',path=path))
        elif re.search(r'(drizzle|knexfile).*\.[cm]?[jt]s$',low): migrations.append(dict(kind='drizzle' if 'drizzle' in low else 'knex',path=path))
        elif Path(path).name=='alembic.ini': migrations.append(dict(kind='alembic',path=path))
        elif Path(path).name=='manage.py': migrations.append(dict(kind='django',path=path))
    from helix_runtime_extensions import sql_extensions
    for migration in migrations:
        if migration['kind']!='sqitch':continue
        deploy=Path(migration['path']).parent/'deploy'
        # Sqitch owns execution of these files. Preserve their literal deploy
        # requirements before removing duplicate direct SQL invocations.
        migration['extensions']=extension_requirements([
            dict(item,extensions=sql_extensions(sources[item['path']],path=item['path']))
            for item in migrations if item['kind']=='sql' and Path(item['path']).is_relative_to(deploy)
        ])
    sqitch_roots=[Path(m['path']).parent for m in migrations if m['kind']=='sqitch']
    migrations=[m for m in migrations if not (m['kind']=='sql' and any(Path(m['path']).is_relative_to(r/d) for r in sqitch_roots for d in ('deploy','revert','verify')))]
    # Flyway undo scripts are reverse operations, never part of a fresh deploy.
    flyway_dirs={Path(m['path']).parent for m in migrations if m['kind']=='sql' and re.match(r'V\d+.*__',Path(m['path']).name)}
    migrations=[m for m in migrations if not (m['kind']=='sql' and Path(m['path']).parent in flyway_dirs and re.match(r'U\d+.*__',Path(m['path']).name))]
    for path,text in sources.items():
        if Path(path).name=='package.json':
            pkg=json.loads(text)
            if 'node-pg-migrate' in {**pkg.get('dependencies',{}),**pkg.get('devDependencies',{})}:
                migrations.append(dict(kind='node-pg-migrate',path=path))
    for migration in migrations:
        if migration['kind']=='sql':
            snapshot=sql_extensions(sources[migration['path']],path=migration['path'])
            migration['extensions']=dict(snapshot,requirements_status='unknown' if snapshot['gaps'] else 'recorded')
    extension_sql=list(migrations)
    for part in parts:
        prefix='' if part['path']=='.' else part['path']+'/'
        names=set(); examples={}
        # Deklaracje ustawień tylko z plików tej części: ta sama nazwa w innej usłudze może mieć inny typ i inną wymagalność.
        part_declared={}; part_structured=set()
        # plik należący do części zagnieżdżonej (np. usługa w podkatalogu projektu głównego) nie liczy się do części nadrzędnej
        nested=[other['path']+'/' for other in parts if other is not part and other['path']!='.' and (other['path']+'/').startswith(prefix)]
        for path,text in sources.items():
            if path.startswith(prefix) and Path(path).suffix=='.py' and not any(path.startswith(inner) for inner in nested):
                if re.search(r'BaseSettings|pydantic_settings',text): part_declared.update(python_settings(text))
                part_structured.update(re.findall(STRUCTURED_SETTING,text,re.M))
        for path,text in sources.items():
            if path.startswith(prefix) or Path(path).parent==Path('.') and Path(path).name in ('.env.example','.env.sample') or Path(path).suffix in ('.yaml','.yml','.toml') and database_sources(part,[dict(path=path)],parts):
                names.update(env_names(text))
                if Path(path).name in ('.env.example','.env.sample'):
                    names.update(re.findall(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=',text,re.M))
                    for name,value in re.findall(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*([^\n]*)',text,re.M):
                        value=value.split(' #')[0].strip().strip('\"\'')
                        if classification(name) not in ('random-secret','database') and re.fullmatch(r'\d+(?:\.\d+)?(?:[kmg]b?)?|true|false|production|development|test|https?://(?:127\.0\.0\.1|localhost)(?::\d+)?/?',value,re.I): examples[name]=value
        part['oidc_dependencies']=oidc_dependencies({p:t for p,t in sources.items() if p.startswith(prefix)})
        names.update(part['oidc_dependencies'])
        part['env']=[dict(name=n,classification=classification(n),**({'example':examples[n]} if n in examples else {}),**({'structured':True} if n in part_structured else {}),**({'encoding':'base64'} if n in encoded else {}),**({'declared':part_declared[n]} if n in part_declared else {})) for n in sorted(names)]
    # Choose one SQL chain per database root. A creating first migration is
    # self-contained; incremental chains need a preceding schema baseline.
    groups={}
    for m in migrations:
        if m['kind']!='sql': continue
        path=Path(m['path']); components=path.parts
        marker=next((i for i,x in enumerate(components[:-1]) if x.lower() in ('migrations','schema')),None)
        key=Path(*components[:marker]).as_posix() if marker is not None else path.parent.as_posix()
        groups.setdefault(key,[]).append(m)
    selected=[]; strategies=[]
    for key,items in groups.items():
        chain=sorted([m for m in items if 'schema' not in Path(m['path']).parts and Path(m['path']).name!='schema.sql'],key=lambda m:migration_order(m['path']))
        baseline=sorted([m for m in items if m not in chain],key=lambda m:migration_order(m['path']))
        modular=[m for m in baseline if 'schema' in Path(m['path']).parts]
        if modular: baseline=modular
        initial=bool(chain and initial_sql(sources[chain[0]['path']]))
        # Even a creating first file can be followed by baseline-dependent ALTERs.
        if initial and baseline:
            baseline_tables={name for m in baseline for creating,name in table_events(sources[m['path']]) if creating}
            chain_events=[event for m in chain for event in table_events(sources[m['path']])]
            chain_tables={name for creating,name in chain_events if creating}
            referenced={name for creating,name in chain_events if not creating}
            if referenced & (baseline_tables-chain_tables): initial=False
        creators={}
        for m in baseline+chain:
            for creating,name in table_events(up_sql(sources[m['path']])):
                if creating: creators.setdefault(name,[]).append(m['path'])
        duplicates=[dict(object=name,sources=paths) for name,paths in creators.items() if len(set(paths))>1]
        candidates=[]
        if chain: candidates.append(dict(strategy='migrations',migrations=chain))
        if baseline and chain: candidates.append(dict(strategy='baseline+migrations',migrations=baseline+chain))
        if baseline: candidates.append(dict(strategy='snapshot',migrations=baseline))
        chosen='migrations' if initial else 'baseline+migrations' if chain and baseline else 'snapshot' if baseline else 'migrations'
        convention=next((name for name,pattern in (
            ('supabase',r'supabase/migrations/'),('flyway',r'/V\d+[^/]*__'),
            ('prisma',r'prisma/migrations/.*/migration.sql'),('drizzle',r'drizzle/'),
            ('golang-migrate',r'\.up.sql$')) if any(re.search(pattern,'/'+m['path']) for m in chain)),None)
        if not convention and any('-- migrate:up' in sources[m['path']] for m in chain): convention='dbmate'
        if not convention:
            convention=next((kind for kind,pattern in (('drizzle',r'meta/_journal\.json$'),('sqitch',r'sqitch\.plan$'),('knex',r'knexfile\.'),('alembic',r'alembic\.ini$'),('django',r'manage\.py$')) if any(re.search(pattern,p) for p in sources)),None)
        evidence=[]; declared_orders=[]
        for path,text in sources.items():
            if Path(path).suffix not in ('.md','.sh','.yml','.yaml') and 'Dockerfile' not in path: continue
            for number,line in enumerate(text.splitlines(),1):
                if re.search(r'(?:for\s+\w+\s+in|psql\b).*?(?:migrations|schema)/',line): evidence.append(dict(path=path,line=number))
            ordered=re.findall(r'(?:for\s+\w+\s+in|psql\b)[^\n]*?\b(schema|migrations)/',text)
            if ordered: declared_orders.append(ordered)
        # Conflicting or incomplete declarations require isolated runtime trials.
        explicit_baseline=any('schema' in order and 'migrations' in order and order.index('schema')<order.index('migrations') for order in declared_orders)
        if explicit_baseline and baseline and chain and not duplicates: chosen='baseline+migrations'
        ambiguous=bool(baseline and chain and (duplicates or not convention and not explicit_baseline))
        strategies.append(dict(root=key,strategy=chosen,tag='ASSUMPTION',convention=convention,
                               evidence=evidence[:5],duplicates=duplicates,candidates=candidates,trial_required=True))
        selected.extend(next(c['migrations'] for c in candidates if c['strategy']==chosen))

    # Jawna deklaracja właściciela wygrywa z heurystyką: projekt z migracjami zależnymi od stanu produkcji
    # (projekt A) ma jeden plik pełnego schematu, z którego stawiają bazę jego własne testy. Ścieżki muszą być
    # kluczami odczytanych źródeł repo, więc ścieżka bezwzględna, wyjście przez ../ i dowiązanie są odrzucane.
    declared=((config.get('runtime') or {}).get('database') or {}).get('schema_files') if isinstance(config,dict) else None
    declared_items=None
    if declared is not None:
        if not isinstance(declared,list) or not declared or any(not isinstance(x,str) or Path(x).suffix!='.sql' or x not in sources for x in declared):
            raise ValueError('runtime.database.schema_files: wymagana niepusta lista istniejących plików .sql w repo')
        declared_items=[]
        for path in declared:
            snapshot=sql_extensions(sources[path],path=path)
            declared_items.append(dict(kind='sql',path=path,extensions=dict(snapshot,requirements_status='unknown' if snapshot['gaps'] else 'recorded')))
    migrations=[m for m in migrations if m['kind']!='sql']+selected
    # SQL from prisma migrations is applied once, without also invoking prisma deploy.
    if any('/migrations/' in m['path'] and m['path'].endswith('migration.sql') for m in migrations): migrations=[m for m in migrations if m['kind']!='prisma']
    for part in parts:
        part['migrations']=database_sources(part,migrations,parts)
        part['schema_strategies']=[g for g in strategies if any(m in database_sources(part,[m],parts) for c in g['candidates'] for m in c['migrations'])]
        part['schema_selection']=dict(rule='per database root: creating initial migration preferred; otherwise schema directory (preferred over schema.sql) then all migrations without numeric cutoff',count=len(part['migrations']),examples=[m['path'] for m in part['migrations'][:5]])
        runners=database_sources(part,project_runners(sources),parts)
        for runner in runners:
            # A project runner can execute dynamic SQL. Nearby literal SQL is an
            # observation, never proof that the full runner requirements are known.
            nearby=[m for m in database_sources(part,extension_sql,parts) if m['kind']=='sql' and (runner['cwd']=='.' or m['path'].startswith(runner['cwd'].rstrip('/')+'/'))]
            runner['extensions']=extension_requirements(nearby)
            runner['extensions']['requirements_status']='unknown'
        if runners:
            fallback=part['schema_strategies']
            candidates=[dict(strategy='project-runner:'+r['path']+(':fresh' if r.get('fresh') else '')+(':'+str(i+1) if sum(x['path']==r['path'] for x in runners)>1 else ''),migrations=[r]) for i,r in enumerate(runners)]
            # One candidate describes the complete database, never concatenated rules.
            for strategy in ('migrations','baseline+migrations','snapshot'):
                items=[m for g in fallback for m in next((c['migrations'] for c in g['candidates'] if c['strategy']==strategy),next(c['migrations'] for c in g['candidates'] if c['strategy']==g['strategy']))]
                if items: candidates.append(dict(strategy=strategy,migrations=items))
            part['schema_strategies']=[dict(root='.',strategy=candidates[0]['strategy'],tag='ASSUMPTION',convention=next((g['convention'] for g in fallback if g['convention']), 'project runner'),evidence=list({(d['path'],d['line']):d for r in runners for d in r['documentation']}.values())[:5],evidence_count=len({(d['path'],d['line']) for r in runners for d in r['documentation']}),duplicates=[d for g in fallback for d in g['duplicates']],candidates=candidates,trial_required=True)]
        if declared_items is not None:
            part['schema_strategies']=[dict(root='.',strategy='declared-schema',tag='ASSUMPTION',convention='owner declaration: runtime.database.schema_files',
                                            evidence=[],duplicates=[],candidates=[dict(strategy='declared-schema',migrations=declared_items)],trial_required=True)]
            part['migrations']=[m for m in part['migrations'] if m['kind']!='sql']+declared_items
            part['schema_selection']=dict(rule='owner declaration: runtime.database.schema_files',count=len(declared_items),examples=[m['path'] for m in declared_items[:5]])
            runners=[]
        part['bootstrap_variables']=sorted({name for r in runners for name in r.get('env',{})})
        part['auth_bypass_variables']=[n for n in variables if re.search(r'AUTH.*BYPASS|BYPASS.*AUTH',n)]
        part['seeds']=database_sources(part,seeds,parts)
        part['database_association']='ASSUMPTION: app-local and shared repository sources; verified only when applied'
    # Katalog główny przestrzeni roboczej (pnpm-workspace, workspaces) tylko spina aplikacje z podkatalogów: sam nie jest częścią do uruchomienia.
    workspace_root=any(Path(path).name=='pnpm-workspace.yaml' and '/' not in path for path in sources) or bool(re.search(r'"workspaces"\s*:',sources.get('package.json','')))
    # To samo, gdy skrypty katalogu głównego tylko przekazują pracę do części z podkatalogu (npm --prefix apps/web run dev).
    # Liczą się wyłącznie skrypty uruchamiające aplikację: wszystkie obecne muszą delegować, inaczej katalog główny jest samodzielną aplikacją.
    try:root_scripts=json.loads(sources.get('package.json','') or '{}').get('scripts',{})
    except ValueError:root_scripts={}
    launchers=[str(root_scripts[name]) for name in ('dev','start','serve','preview') if isinstance(root_scripts,dict) and name in root_scripts]
    nested={part['path'] for part in parts if part['path']!='.'}
    # Skrypt deleguje wyłącznie wtedy, gdy cały jest jednym poleceniem przekazanym do podkatalogu; skrypt łączony (concurrently, &, |, ;)
    # albo o nierozpoznanej budowie zostawia katalog główny jako część.
    def delegates(text):
        match=re.fullmatch(r'\s*(?:(?:npm|pnpm|yarn|bun)\s+(?:--prefix|--cwd|-C)\s+([A-Za-z0-9._/-]+)\s+[^&|;"\'`$()\r\n]+|cd\s+([A-Za-z0-9._/-]+)\s*&&\s*[^&|;"\'`$()\r\n]+)\s*',text)
        return bool(match) and (match[1] or match[2]).strip('./') in nested
    workspace_root=workspace_root or (bool(launchers) and all(delegates(text) for text in launchers))
    if workspace_root and any(part['path']!='.' for part in parts):
        parts[:]=[part for part in parts if part['path']!='.']
    # Frontend z osobnym API: gdy konfiguracja frontendu przekazuje wskazane ścieżki (np. /api, /uploads) do drugiej usługi, a w projekcie
    # jest dokładnie jedna część serwerowa w Pythonie, Helix uruchamia ją jako zaplecze i spina obie tak, jak robi to serwer produkcyjny.
    servers=[p for p in parts if p['package_manager']=='pip' and p.get('start')]
    for part in parts:
        if part['package_manager']=='pip' or part['path']=='.' or len(servers)!=1: continue
        prefix=part['path']+'/'
        prefixes=[]; names=set()
        for path,text in sources.items():
            if not path.startswith(prefix) or not re.search(r'(?:vite|next|nuxt)\.config\.[a-z]+$',path): continue
            for route in re.findall(r'[\'"](/[A-Za-z0-9_-]+)[\'"]\s*:\s*\{\s*target\s*:',text):
                if route not in prefixes: prefixes.append(route)
            # cel proxy bywa podany wprost albo przez stałą: liczą się zmienne środowiska tego pliku wskazujące zaplecze
            names.update(name for name in re.findall(r'process\.env\.([A-Z][A-Z0-9_]*)',text) if re.search(r'API|BACKEND|TARGET',name))
        if not prefixes: continue
        names.update(row['name'] for row in part['env'] if re.fullmatch(r'(?:PUBLIC_|NEXT_PUBLIC_|VITE_|PRIVATE_)?(?:API|BACKEND)_(?:INTERNAL_)?(?:URL|TARGET|BASE_URL|ORIGIN)',row['name']))
        part['backend']=dict(part=servers[0]['path'],prefixes=prefixes[:10],env=sorted(names)[:10])
    from helix_runtime_integrations import inventory
    from helix_runtime_identity import identity_plan
    from helix_runtime_identity_policy import policy_plan
    from helix_runtime_transport import transport_plan
    from helix_runtime_webauthn import webauthn_plan
    integrations=inventory(sources,parts,config)
    identities=identity_plan(sources,parts,config)
    policies=policy_plan(sources,parts,identities,integrations,config)
    transport=transport_plan(sources,parts,integrations,config)
    webauthn=webauthn_plan(sources,parts,integrations,identities,transport,policies,config)
    from helix_runtime_sinks import sink_plan
    sinks=sink_plan(integrations,parts)
    from helix_runtime_adapters import adapter_plan
    adapters=adapter_plan(sources,parts,config)
    return dict(helix_version=VERSION,schema_version=1,project=str(root),tag='ASSUMPTION',scope='offline declarations; commands require runtime verification',parts=parts,database_target=database_target(root),
                env=[dict(name=n,classification=classification(n),**({'structured':True} if n in structured else {}),**({'encoding':'base64'} if n in encoded else {}),**({'declared':settings_declared[n]} if n in settings_declared else {})) for n in sorted(variables)],migrations=migrations,seeds=seeds,
                adapters=adapters,integrations=integrations,identity_plan=identities,transport_plan=transport,
                identity_policy_plan=policies,identity_policy_receipts=[],webauthn_plan=webauthn,webauthn_receipts=[],sink_plan=sinks,sink_observations=[])


def migration_command(migration):
    argv=migration.get('argv') or (['psql','<isolated-database>','-X','-v','ON_ERROR_STOP=1','-f',migration['path']] if migration['kind']=='sql' else [migration['kind'],migration['path']])
    sensitive=lambda n: bool(re.search(r'PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL',n,re.I))
    env={k:('[REDACTED]' if sensitive(k) else v) for k,v in migration.get('env',{}).items()}
    clean=[]; hide_next=False
    for value in argv:
        value=str(value)
        if hide_next:
            clean.append('[REDACTED]'); hide_next=False; continue
        if re.match(r'^--?(?:password|secret|token|api[-_]key|credential)$',value,re.I):
            clean.append(value); hide_next=True; continue
        value=re.sub(r'(?i)((?:password|secret|token|api_key)=)[^\s]+',r'\1[REDACTED]',value)
        value=re.sub(r'(://)[^/\s@]+@',r'\1[REDACTED]@',value)
        if '://' in value: value=value.split('?',1)[0].split('#',1)[0]
        clean.append(value)
    argv=clean
    return dict(argv=argv,env=env,evidence=migration.get('fresh_evidence'))


def synthetic_request(row):
    """Żądanie, którego adres kończy się wartością zastępczą Helixa (np. obraz o nazwie 'synthetic-item'): 404 jest skutkiem
    danych syntetycznych, nie błędem aplikacji."""
    return row.get('status')==404 and row.get('source','app')=='app' and bool(re.search(r'/(synthetic-item|bardzo długa nazwa pozycji testowej)[^/]*$',unquote(urlparse(str(row.get('url',''))).path)))


def lighthouse_failure(raw, issuer=''):
    requests=[]
    for row in raw.get('audits',{}).get('network-requests',{}).get('details',{}).get('items',[]):
        target=urlparse(row.get('url',''))
        requests.append(dict(method=row.get('requestMethod','GET'),url=target._replace(query='',fragment='').geturl(),status=row.get('statusCode',0),source='stub' if issuer and target.netloc==urlparse(issuer).netloc else 'app'))
    cause='; '.join('HTTP '+str(r['status'])+' from '+r['source']+' on '+r['url'] for r in requests if r['status']>=400 and not synthetic_request(r))
    return dict(requests=requests,cause=cause or raw.get('runtimeError',{}).get('message','Lighthouse runtime error; response URL unavailable'))


def database_variants(groups):
    """Public execution ledger, preserving every trial including refused runners."""
    variants=[]; findings=[]
    for group in groups:
        for result in group.get('results',[]):
            candidate=next(c for c in group['candidates'] if c['strategy']==result['strategy'])
            migrations=candidate['migrations']
            first=result.get('first_error') or ''
            # The runner log contains the SQL location, not the runner's own path.
            location=re.search(r'(?:psql:)?([^\s:]+\.sql):(\d+):',first)
            error_location=None
            if location:
                path=location[1].split('/project/')[-1]
                error_location=dict(path=path,line=int(location[2]))
            status={'applied':'PASS','failed':'FAIL','skipped':'SKIPPED'}.get(result['status'],result['status'])
            if status=='FAIL' and (result.get('category')=='fresh-database-guard' or re.search(r'guard|od zera|fresh database|empty migration',first,re.I) and not error_location): status='REFUSED'
            evidence=[e for m in migrations for e in ([m['fresh_evidence']] if m.get('fresh_evidence') else m.get('documentation',[]))]
            variant=dict(result,order=len(variants)+1,name=result['strategy'],status=status,
                         selected=result['strategy']==group['strategy'],selection_reason=group.get('selection_reason'),
                         suggestion=evidence,first_error_location=error_location,logs=result.get('logs',[]))
            variants.append(variant)
            if status=='FAIL' and error_location and any(m.get('fresh') for m in migrations) and evidence:
                findings.append(dict(id='fresh-install-broken',severity='high',category='data/ops',owner='project',tag='VERIFIED',
                                     verification='executed synthetic fresh database',recommendation=evidence,
                                     first_error=error_location,message=first,logs=result.get('logs',[])))
    return variants,findings


STRUCTURED_SETTING=r'^\s+([A-Z][A-Z0-9_]+)\s*:\s*(?:Optional\[\s*)?(?:typing\.)?(?:List|Dict|Set|Tuple|FrozenSet|list|dict|set|tuple|frozenset)\b'


def loopback_stub(value):
    """Zaślepka w miejsce adresu zewnętrznej usługi: ten sam schemat i ścieżka, host i port zamknięte na pętli zwrotnej."""
    match=re.match(r'^\s*([a-z][a-z0-9+.-]*)://[^/?#]*(.*)$',str(value),re.I)
    return (match[1]+'://127.0.0.1:1'+match[2]) if match else '127.0.0.1:1'


def python_settings(text):
    """Deklaracje ustawień z klasy ustawień w Pythonie: nazwa -> typ, czy ma wartość domyślną, domyślny napis (bez wykonywania kodu)."""
    found={}
    for name,kind,default in re.findall(r'^[ \t]+([A-Z][A-Z0-9_]+)[ \t]*:[ \t]*([^=\n#]+?)[ \t]*(?:=[ \t]*([^\n]*?))?[ \t]*(?:#.*)?$',text,re.M):
        literal=re.fullmatch(r'[rbu]?(["\'])(.*)\1',default.strip()) if default else None
        # Field(...) bez wartości domyślnej (wielokropek albo sam opis) oznacza ustawienie wymagane
        required=not default or bool(re.match(r'Field\(\s*(\.\.\.|[a-z_]+\s*=)',default.strip()) and not re.search(r'default(_factory)?\s*=',default))
        found[name]=dict(type=kind.strip()[:80],has_default=not required,**({'default':literal[2][:300]} if literal else {}))
    return found


def external_address(value):
    """Czy wartość z pliku przykładowego wskazuje adres poza tym komputerem (URL albo host:port z hostem innym niż pętla zwrotna)."""
    match=re.match(r'^\s*(?:[a-z][a-z0-9+.-]*://)?(?:[^@/\s]*@)?(\[[0-9a-f:]+\]|[A-Za-z0-9.-]+)(?::\d+)?(?:[/?#]|$)',str(value),re.I)
    # sam adres e-mail albo nazwa to nie adres usługi: wymagany schemat albo port
    if not match or not re.search(r'://|:\d+(?:[/?#]|$)',str(value)):return False
    host=match[1].strip('[]').lower()
    if ':' in host:return host not in ('::1','::')  # literał IPv6
    if host in ('localhost','127.0.0.1','::1','0.0.0.0') or host.endswith(('.localhost','.local','.test','.invalid','.example')):return False
    return bool(re.fullmatch(r'\d+\.\d+\.\d+\.\d+',host) or re.search(r'\.[a-z]{2,}$',host))


def typed_dummy(name):
    if re.search(r'_ENABLED$|^ENABLE_|^DISABLE_|^USE_|_DEBUG$',name): return 'false'
    if re.search(r'_SIZE|LIMIT|PORT$|TIMEOUT|_MAX|_MIN|COUNT|TTL|DEPTH',name): return '1'
    if name.endswith('_EMAIL'): return 'x@example.invalid'
    if name.endswith(('HOST', 'HOSTNAME', 'SERVER')): return '127.0.0.1'
    if re.search(r'_URL$|_URI$|ORIGIN$',name): return 'http://127.0.0.1:1'
    return secrets.token_hex(16)


def startup_failure(log,code):
    cause=first_error(log)
    category='env' if re.search(r'env|Invalid [A-Z_]+|numeric value|required.*[A-Z_]',cause,re.I) else 'missing-service' if re.search(r'ECONNREFUSED|ENOTFOUND|connection refused',log,re.I) else 'port' if re.search(r'EADDRINUSE|address already in use',log,re.I) else 'dependency' if re.search(r'module|package|dependency',log,re.I) else 'build'
    return dict(status='CRASHED',cause=cause,exit_code=code,category=category)


def dummy_env(spec, url, port, public_origin=None):
    env={'PATH':os.defpath, 'CI':'1','HOST':'127.0.0.1','HOSTNAME':'127.0.0.1','PORT':str(port),'DATABASE_URL':url,
         'PGHOST':'127.0.0.1','PGPORT':str(urlparse(url).port or 5432),'PGUSER':'helix','PGPASSWORD':'','PGDATABASE':urlparse(url).path.lstrip('/')}
    for item in spec['env']:
        name,kind=item['name'],item['classification']
        if name in spec.get('bootstrap_variables',[]): continue
        if item.get('structured'):
            # Wartość musi być JSON-em: adres aplikacji idzie jako lista, pozostałe zostają na wartości domyślnej z kodu.
            example=item.get('example','')
            if url_role(name)=='app-url': env[name]=json.dumps([app_url(name,port,'',public_origin)])
            elif example.strip().startswith(('[','{')) and not external_address(example.strip('[]{}"\' ')): env[name]=example
            # wymagana kolekcja bez przykładu: pusty JSON zgodny z typem; z wartością domyślną zostaje nieustawiona
            elif item.get('declared') and not item['declared']['has_default']: env[name]='{}' if re.match(r'\s*(?:Optional\[\s*)?(?:typing\.)?dict\b',item['declared']['type'],re.I) else '[]'  # liczy się typ zewnętrzny: list[dict] to lista
            continue
        if url_role(name)=='app-url':
            env[name]=app_url(name,port,item.get('example',''),public_origin); continue
        decl=item.get('declared')
        # Nazwa z „TOKEN” albo „SECRET” bywa liczbą (czas ważności tokenu): typ z deklaracji wygrywa z klasyfikacją po nazwie.
        if decl and 'example' not in item and kind!='database' and (kind!='random-secret' or re.search(r'\b(int|bool|float)\b',decl['type'].lower())) and name not in env:
            # Ustawienie zadeklarowane w kodzie: wartość domyślna aplikacji jest lepsza niż losowy napis (liczba, tak/nie, nazwa trybu).
            # Wyjątek: domyślny adres zewnętrznej usługi zastępuje zaślepka. Ustawienie wymagane dostaje wartość zgodną z typem.
            if decl['has_default']:
                if external_address(decl.get('default','')): env[name]=loopback_stub(decl['default'])
                continue
            kind_of=decl['type'].lower()
            if re.search(r'\bbool\b',kind_of): env[name]='false'; continue
            if re.search(r'\bint\b',kind_of): env[name]='1'; continue
            if re.search(r'\bfloat\b|decimal',kind_of): env[name]='1.0'; continue
        if name in env or re.search(r'AUTH.*BYPASS|BYPASS.*AUTH|FRESH',name): continue
        reserved={'BODY_SIZE_LIMIT','ORIGIN','PROTOCOL_HEADER','HOST_HEADER','XFF_DEPTH','SHUTDOWN_TIMEOUT','IDLE_TIMEOUT','NODE_ENV'}
        if name in reserved and 'example' not in item: continue
        if 'example' in item and kind not in ('database','random-secret'):
            # Plik przykładowy bywa kopią produkcji: adres zewnętrznej usługi (np. serwer klienta) nie trafia do kopii testowej.
            env[name]=loopback_stub(item['example']) if external_address(item['example']) else item['example']; continue
        database_values={'DB_HOST':'127.0.0.1','DB_PORT':str(urlparse(url).port or 5432),'DB_USER':'helix','DB_PASSWORD':'','DB_NAME':urlparse(url).path.lstrip('/'),'POSTGRES_USER':'helix','POSTGRES_PASSWORD':'','POSTGRES_DB':urlparse(url).path.lstrip('/')}
        if name in database_values: env[name]=database_values[name]; continue
        if kind!='database' and re.search(r'_ENABLED$|^ENABLE_|^DISABLE_|^USE_|_DEBUG$|_SIZE|LIMIT|PORT$|TIMEOUT|_MAX|_MIN|COUNT|TTL|DEPTH',name):
            env[name]=typed_dummy(name); continue
        env[name]= url if kind=='database' else (base64.b64encode(secrets.token_bytes(32)).decode() if item.get('encoding')=='base64' else secrets.token_hex(32)) if kind=='random-secret' else (typed_dummy(name) if name.endswith('_HOST') else '127.0.0.1' if name.endswith(('HOST','HOSTNAME','SERVER')) else ('smtp://127.0.0.1:1' if 'SMTP' in name else 'http://127.0.0.1:1')) if kind in ('loopback','external-required') else '1' if name.endswith('_PORT') else 'us-east-1' if name.endswith('_REGION') else typed_dummy(name)
    if 'AZURE_STORAGE_CONNECTION_STRING' in env:
        env['AZURE_STORAGE_CONNECTION_STRING']='DefaultEndpointsProtocol=http;AccountName=synthetic;AccountKey='+'YQ=='+';BlobEndpoint=http://127.0.0.1:1/synthetic;'
    for name in env:
        if 'STRIPE' in name and name.endswith(('KEY','TOKEN')): env[name]=('pk_test_' if 'PUBLIC' in name or 'PUBLISHABLE' in name else 'sk_test_')+secrets.token_hex(16)
        if 'SENTRY' in name and name.endswith('DSN'): env[name]='http://dummy@127.0.0.1:1/1'
    if public_origin: env['ORIGIN']=public_origin
    env.update(AWS_EC2_METADATA_DISABLED='true', AWS_ENDPOINT_URL='http://127.0.0.1:1')
    return env


def locate(name):
    found=shutil.which(name)
    if found: return found
    for path in (Path('/usr/lib/postgresql/17/bin')/name,Path.home()/'.local/bin'/name):
        if path.is_file(): return str(path)
    return None


def doctor():
    tools={name:locate(name) for name in ('podman','docker','postgres','pg_config','initdb','pg_ctl','pg_dump','pg_restore','psql','pg_isready','node','npm','pnpm','yarn','k6','lighthouse','playwright')}
    from helix_runtime_adapters import chromium_path
    tools['playwright_chromium']=chromium_path()
    return dict(tools=tools,engine=next((e for e in ('podman','docker','native') if tools.get('initdb' if e=='native' else e)),None))


class Budget:
    def __init__(self, seconds, clock=time.monotonic):
        if not math.isfinite(seconds) or seconds<=0:raise ValueError('runtime budget must be finite and positive')
        self.clock=clock; self.end=clock()+seconds
        if not math.isfinite(self.end):raise ValueError('runtime deadline must be finite')
    def remaining(self, maximum):
        value=min(maximum,self.end-self.clock())
        if value<=0: raise Blocked('global runtime budget exhausted')
        return value


class Executor:
    def run(self, argv, cwd, env, timeout):
        p=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True,close_fds=True,pass_fds=())
        try:
            output,_=p.communicate(timeout=timeout)
        except BaseException:
            self.stop(p)
            raise
        return p.returncode,output
    def spawn(self, argv,cwd,env,log):
        handle=open(log,'w')
        try: return subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=handle,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True,pass_fds=())
        finally: handle.close()
    def stop(self,p):
        try: os.killpg(p.pid,signal.SIGTERM)
        except ProcessLookupError: return
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        finally:
            # The launcher may exit while descendants still own the process group.
            # macOS odpowiada EPERM, gdy w grupie zostały już tylko procesy zakończone, czekające na odebranie: nie ma czego zabijać.
            try: os.killpg(p.pid,signal.SIGKILL)
            except (ProcessLookupError,PermissionError): pass
            p.wait(timeout=3)
    def non_html(self,url,timeout=5):
        """Czy adres na pętli zwrotnej odpowiada poprawnie (2xx) czymś innym niż strona HTML. Przekierowań nie śledzi i nie używa
        pośredników systemu: odesłanie, błąd HTTP albo brak odpowiedzi niczego nie rozstrzygają (wynik False)."""
        import urllib.request,urllib.error
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        try:
            if urlparse(url).hostname not in ('127.0.0.1','localhost') or urlparse(url).scheme!='http':return False
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
            with opener.open(urllib.request.Request(url,headers={'Accept':'text/html,*/*'}),timeout=timeout) as response:
                kind=(response.headers.get('Content-Type') or '').lower()
                return 200<=response.status<300 and bool(kind) and 'html' not in kind
        except (OSError,ValueError):return False
    def port_ready(self,port,timeout):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.5):return
            except OSError:time.sleep(.1)
        raise Blocked('measurement browser did not open its control port')
    def oidc_ready(self,issuer,cert,timeout):
        context=ssl.create_default_context(cafile=str(cert)); end=time.monotonic()+timeout
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        while time.monotonic()<end:
            try:
                with opener.open(issuer+'/.well-known/openid-configuration',timeout=min(1,max(.01,end-time.monotonic()))) as response:
                    if json.load(response).get('issuer')==issuer: return
            except (OSError,ValueError): pass
            time.sleep(.05)
        raise Blocked('synthetic HTTPS OIDC discovery did not become ready')

    def health(self,url,timeout,ca_file=None):
        end=time.monotonic()+timeout
        class LocalRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if (urlparse(newurl).scheme,urlparse(newurl).netloc) != (urlparse(url).scheme,urlparse(url).netloc):
                    return None  # HTTP redirect proves that the app answered; do not contact the provider.
                return super().redirect_request(req,fp,code,msg,headers,newurl)
        handlers=[urllib.request.ProxyHandler({}),LocalRedirect()]
        if ca_file is not None:handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_file))))
        opener=urllib.request.build_opener(*handlers)
        while time.monotonic()<end:
            try:
                with opener.open(url,timeout=min(2,max(.01,end-time.monotonic()))) as response:
                    self.last_health=dict(state='http',status=response.status,url=response.geturl())
                    return response.geturl()
            except urllib.error.HTTPError as error:
                try:
                    if ca_file is not None and error.headers and error.headers.get('X-Helix-Runtime-Proxy-Error')=='1':
                        self.last_health=dict(state='proxy-unavailable',status=error.code,url=url)
                    else:
                        self.last_health=dict(state='http',status=error.code,url=url)
                        return url
                finally:error.close()
            except (OSError,ValueError) as error:
                self.last_health=dict(state='timeout' if isinstance(getattr(error,'reason',error),(TimeoutError,socket.timeout)) else 'no-listener',reason=str(error))
            time.sleep(min(.2,max(0,end-time.monotonic())))
        raise Blocked('HTTP healthcheck '+getattr(self,'last_health',{}).get('state','timeout'))


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]


def copy_project(project,target):
    target.mkdir()
    for p in files(project):
        rel=p.relative_to(project)
        dest=target/rel; dest.parent.mkdir(parents=True,exist_ok=True)
        if p.name in ('.env.example','.env.sample'):
            dest.write_text(''.join(n+'=\n' for n in re.findall(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=',read(p),re.M)))
        else: shutil.copyfile(p,dest)


def validate_extension_checks(fidelity):
    """Validate catalog observations, without treating readiness as execution."""
    if 'extension_checks' not in fidelity:return
    from helix_runtime_extensions import COMMON_EXTENSIONS, parse_available_extensions
    def invalid():raise ValueError('invalid database extension checks')
    def path(value):
        return isinstance(value,str) and 0<len(value)<=1000 and not Path(value).is_absolute() and '..' not in Path(value).parts and not any(c in value for c in '\\:\x00\r\n')
    checks=fidelity['extension_checks']
    if not isinstance(checks,list):invalid()
    keys={'scope','database','part','candidate','status','reason_code','requirements_status','required','declarations','gaps','observed','missing','version_check','log'}
    for row in checks:
        if not isinstance(row,dict) or set(row)!=keys:invalid()
        if row['scope'] not in ('base','trial','restore') or not isinstance(row['database'],str) or not re.fullmatch(r'helix(?:_[A-Za-z0-9_]+)?',row['database']):invalid()
        if row['part'] is not None and not path(row['part']):invalid()
        if row['candidate'] is not None and (not isinstance(row['candidate'],str) or not re.fullmatch(r'[A-Za-z0-9_./:+ -]{1,1000}',row['candidate'])):invalid()
        if row['version_check']!='not_checked' or row['requirements_status'] not in ('recorded','unknown'):invalid()
        if row['log'] is not None and (not isinstance(row['log'],str) or not re.fullmatch(r'logs/[0-9]+\.log',row['log'])):invalid()
        for key in ('declarations','gaps','required','missing','observed'):
            if not isinstance(row[key],list):invalid()
        if any(not isinstance(x,str) for x in row['required']+row['missing']):invalid()
        for item in row['declarations']:
            if not isinstance(item,dict) or set(item)!={'name','path','line','declared_version'} or not path(item['path']) or type(item['line']) is not int or item['line']<1:invalid()
            parse_available_extensions(json.dumps([dict(name=item['name'],default_version=item['declared_version'],installed_version=None)]))
        for gap in row['gaps']:
            if not isinstance(gap,dict) or set(gap)!={'path','line','reason_code'} or not path(gap['path']) or type(gap['line']) is not int or gap['line']<1 or gap['reason_code'] not in ('DYNAMIC_RUNNER_REQUIREMENTS_UNKNOWN','dynamic_sql_requirements_unresolved','extension_name_unresolved','extension_version_unresolved','extension_options_unresolved'):invalid()
        if row['requirements_status']!=('unknown' if row['gaps'] else 'recorded'):invalid()
        if row['required']!=sorted({item['name'] for item in row['declarations']}):invalid()
        names=[]; available=[]
        for item in row['observed']:
            if not isinstance(item,dict) or set(item)!={'name','available','default_version','installed_version'} or type(item['available']) is not bool:invalid()
            parse_available_extensions(json.dumps([{key:item[key] for key in ('name','default_version','installed_version')}]))
            if not item['available'] and (item['default_version'] is not None or item['installed_version'] is not None):invalid()
            names.append(item['name'])
            if item['available']:available.append(item['name'])
        if row['status'] in ('ready','blocked'):
            if names!=sorted(set(COMMON_EXTENSIONS)|set(row['required'])) or row['log'] is None:invalid()
            missing=sorted(set(row['required'])-set(available))
            if row['missing']!=missing:invalid()
            expected=('blocked','REQUIRED_EXTENSION_UNAVAILABLE') if missing else ('ready','CATALOG_OBSERVED')
            if (row['status'],row['reason_code'])!=expected:invalid()
        elif row['status'] in ('checking','incomplete'):
            reasons={'CHECK_PENDING'} if row['status']=='checking' else {'CATALOG_QUERY_FAILED','CATALOG_INVALID','RESOURCE_PAUSED','INTERRUPTED'}
            if row['reason_code'] not in reasons or row['observed'] or row['missing']:invalid()
        else:invalid()


ISOLATION_PHASES=('install','migration','build','application','measurement','database_server')
ISOLATION_REASONS={'LOCAL_PROBE_PASSED','UNSUPPORTED_PLATFORM','SANDBOX_EXEC_UNAVAILABLE','INVALID_POLICY','CONTROL_PATH_UNSAFE',
                   'BUDGET_EXHAUSTED','PROBE_DENIED','PROBE_INCOMPLETE','PROBE_FAILED','PROFILE_PUBLICATION_FAILED',
                   'DATABASE_SERVER_UNSUPPORTED','WRAPPER_REJECTED','ADMISSION_ERROR','SYNTHETIC_TEST'}


def network_isolation_record(records):
    invoked=[row for row in records if row.get('command_invoked')]
    status='BLOCKED' if any(row['enforcement']=='blocked' for row in records) else ('SIMULATED' if any(row['enforcement']=='simulated' for row in invoked) else 'ENFORCED') if invoked else 'NOT_RUN'
    return dict(schema_version=1,scope='project_processes_and_owned_database',status=status,records=[dict(row) for row in records])


def project_network_isolation(report):
    """Pure projection of current process admission; no imported grant is usable."""
    keys=('admitted','blocked','enforced','simulated','invoked')
    if 'network_isolation' not in report:
        return dict(schema_version=1,scope='project_processes_and_owned_database',status='NOT_RECORDED',coverage_status='NOT_RECORDED',counts={key:None for key in keys},records=[])
    def invalid():raise ValueError('invalid runtime network isolation evidence')
    source=report['network_isolation']
    if not isinstance(source,dict) or set(source)!={'schema_version','scope','status','records'} or type(source['schema_version']) is not int or source['schema_version']!=1 or source['scope']!='project_processes_and_owned_database' or not isinstance(source['records'],list):invalid()
    fields={'enforcement','proof_kind','backend','reason_code','policy_hash','scope','phase','command_invoked'}
    for row in source['records']:
        if not isinstance(row,dict) or set(row)!=fields or row['phase'] not in ISOLATION_PHASES or type(row['command_invoked']) is not bool:invalid()
        if row['scope']!=({'database_server':'database_server','measurement':'measurement'}.get(row['phase'],'project')) or row['reason_code'] not in ISOLATION_REASONS:invalid()
        if not isinstance(row['backend'],str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}',row['backend']):invalid()
        if row['policy_hash'] is not None and (not isinstance(row['policy_hash'],str) or not re.fullmatch(r'[0-9a-f]{64}',row['policy_hash'])):invalid()
        pair=(row['enforcement'],row['proof_kind'])
        if pair==('enforced','execution'):
            if row['reason_code']!='LOCAL_PROBE_PASSED' or row['backend']!='macos-seatbelt' or row['policy_hash'] is None:invalid()
        elif pair==('simulated','synthetic_test'):
            if row['reason_code']!='SYNTHETIC_TEST' or row['policy_hash'] is None:invalid()
        elif pair==('blocked','none'):
            if row['command_invoked'] or row['reason_code'] in ('LOCAL_PROBE_PASSED','SYNTHETIC_TEST'):invalid()
        else:invalid()
    expected=network_isolation_record(source['records'])
    if source!=expected:invalid()
    rows=expected['records']
    counts=dict(admitted=sum(r['enforcement']!='blocked' for r in rows),blocked=sum(r['enforcement']=='blocked' for r in rows),
                enforced=sum(r['command_invoked'] and r['enforcement']=='enforced' for r in rows),
                simulated=sum(r['command_invoked'] and r['enforcement']=='simulated' for r in rows),invoked=sum(r['command_invoked'] for r in rows))
    coverage='RECORDED' if expected['status']=='ENFORCED' else 'NOT_RUN' if expected['status']=='NOT_RUN' else 'INCOMPLETE'
    return dict(expected,coverage_status=coverage,counts=counts)


def validate_report(report):
    schema=json.loads((HOME/'schemas/runtime-report.json').read_text())
    def validate(value, rule, where='$'):
        if '$ref' in rule:
            ref=rule['$ref']
            if not ref.startswith('#/$defs/'):raise ValueError('unsupported runtime schema reference')
            return validate(value,schema['$defs'][ref.removeprefix('#/$defs/')],where)
        types={'object':dict,'array':list,'string':str,'integer':int,'boolean':bool,'null':type(None),'number':(int,float)}
        expected=rule.get('type'); kinds=expected if isinstance(expected,list) else [expected] if expected else []
        if kinds and not any(isinstance(value,types[k]) and not (k in ('integer','number') and isinstance(value,bool)) for k in kinds):
            raise ValueError(f'invalid runtime report type at {where}: expected {rule["type"]}, got {type(value).__name__}')
        if 'const' in rule and (value!=rule['const'] or isinstance(value,bool)!=isinstance(rule['const'],bool)): raise ValueError(f'invalid runtime schema version at {where}')
        if 'enum' in rule and value not in rule['enum']: raise ValueError(f'invalid runtime enum at {where}: {value!r} not in {rule["enum"]}')
        if isinstance(value,str) and len(value)<rule.get('minLength',0): raise ValueError(f'empty runtime field at {where}')
        if isinstance(value,str) and ('pattern' in rule and not re.search(rule['pattern'],value) or len(value)>rule.get('maxLength',float('inf'))):raise ValueError(f'invalid runtime text at {where}')
        if type(value) in (int,float) and (not math.isfinite(value) or value<rule.get('minimum',-float('inf'))):raise ValueError(f'invalid runtime number at {where}')
        if isinstance(value,dict):
            missing=[k for k in rule.get('required',[]) if k not in value]
            if missing: raise ValueError(f'missing runtime field at {where}: {", ".join(missing)}')
            for k,v in value.items():
                child=rule.get('properties',{}).get(k,rule.get('additionalProperties',{}))
                if child is False:raise ValueError(f'unknown runtime field at {where}.{k}')
                if isinstance(child,dict): validate(v,child,f'{where}.{k}')
        if isinstance(value,list):
            for i,item in enumerate(value): validate(item,rule.get('items',{}),f'{where}[{i}]')
    validate(report,schema)
    if 'database_fidelity' in report:validate_extension_checks(report['database_fidelity'])
    if 'sink_plan' in report or 'sink_observations' in report:
        from helix_runtime_sinks import project_sinks
        project_sinks(report)
    if 'network_isolation' in report:
        isolation=project_network_isolation(report)
    # Historical cookie/redirect inference is not bound identity evidence.
    # Reject imported claims rather than modifying their source/provenance.
    for part in report['parts']:
        for name,check in part.get('checks',{}).items():
            metrics=check.get('metrics',{})
            flow=metrics.get('auth_flow') if isinstance(metrics,dict) else None
            if (name=='auth-flow' and (check.get('status')=='PASS' or legacy_auth_claim_unverified(metrics)) or
                    legacy_auth_claim_unverified(flow)):
                raise ValueError('legacy_auth_claim_unverified')
    if 'integrations' in report:
        from helix_runtime_integrations import execution_inventory
        if not all(key in report for key in ('run_id','integration_receipts','coverage_status')):
            raise ValueError('runtime integration evidence requires run, receipts and coverage status')
        inventory=report['integrations']
        if inventory['run_id']!=report['run_id']:raise ValueError('runtime integration run binding mismatch')
        declaration=dict(inventory,status='INCOMPLETE' if inventory['discovery']['errors'] or not inventory['discovery']['files'] else 'RECORDED')
        expected=execution_inventory(declaration,report['integration_receipts'],run_id=report['run_id'])
        if expected!=inventory:raise ValueError('runtime integration evidence disagrees with receipts')
        coverage='INCOMPLETE' if inventory['status']!='RECORDED' else 'RECORDED'
        if report['coverage_status']!=coverage:raise ValueError('runtime integration coverage mismatch')
        if coverage!='RECORDED' and report.get('status')=='PASS':raise ValueError('incomplete integrations cannot produce overall PASS')
        if integration_failures(inventory) and report.get('status')=='PASS':raise ValueError('failed integration route cannot produce overall PASS')
        for receipt in report['integration_receipts']:
            if receipt['status'] in ('ready','completed') and not receipt['logs']:raise ValueError('runtime integration execution requires an evidence artifact')
    elif 'integration_receipts' in report:raise ValueError('runtime receipts require an integration inventory')
    if any(key in report for key in ('transport_plan','transport_coverage')) or any('transport' in part for part in report['parts']):
        from helix_runtime_transport import derive_transport_coverage
        expected=derive_transport_coverage(report.get('transport_plan'),report['parts'])
        if report.get('transport_coverage')!=expected:raise ValueError('transport coverage disagrees with declarations and receipts')
        if expected=='INCOMPLETE' and report.get('status')=='PASS':raise ValueError('incomplete transport cannot produce overall PASS')
    if 'identity_plan' in report or 'identity_forms' in report:
        from helix_runtime_login import project_identity
        identity=project_identity(report)
        if report.get('identity_coverage')!=identity['status']:raise ValueError('identity coverage disagrees with phase observations')
        if 'identity_assessment' not in report and identity['status']=='INCOMPLETE' and report.get('status')=='PASS':raise ValueError('identity form observations cannot produce overall session or authorization PASS')
    if 'identity_policy_plan' in report or 'identity_policy_receipts' in report:
        from helix_runtime_policy_receipts import project_policy_plan
        policy=project_policy_plan(report)
        if 'identity_assessment' not in report and policy['parts'] and report.get('status')=='PASS':raise ValueError('unexecuted identity policy scope cannot produce overall PASS')
    if any(key in report for key in ('identity_policy_executions','identity_assessment')):
        from helix_runtime_identity_policy_run import derive_identity_assessment
        assessment=derive_identity_assessment(report)
        if report.get('identity_assessment')!=assessment:raise ValueError('identity assessment disagrees with bound policy observations')
        if report.get('status')=='PASS' and assessment['status'] not in ('PASS','NOT_DETECTED'):
            raise ValueError('unexecuted identity policy or failed observations cannot produce overall PASS')
        if assessment['outcome']=='FAIL' and assessment['coverage_status']=='RECORDED' and report.get('status') not in ('FAIL','INCOMPLETE','BLOCKED'):
            raise ValueError('failed identity policy outcome must remain visible')
    if any(key in report for key in ('webauthn_plan','webauthn_receipts','webauthn_coverage','webauthn_executions')):
        from helix_runtime_webauthn_run import project_webauthn_execution
        webauthn=project_webauthn_execution(report)
        expected=webauthn['coverage_status']
        if report.get('webauthn_coverage')!=expected:raise ValueError('WebAuthn coverage disagrees with declarations')
        if expected=='INCOMPLETE' and report.get('status')=='PASS':raise ValueError('unexecuted WebAuthn cannot produce overall PASS')
        if webauthn['outcome']=='FAIL' and report.get('status') not in ('FAIL','INCOMPLETE','BLOCKED'):raise ValueError('failed WebAuthn outcome must remain visible')
    if 'controls' in report:
        expected=[dict(result,id=name,part=part['name']) for part in report['parts'] for name,result in part['checks'].items()]
        if report['controls']!=expected: raise ValueError('controls disagree with part checks')
    seen=set()
    for part in report['parts']:
        if part['name'] in seen: raise ValueError('duplicate runtime part')
        seen.add(part['name'])
        if set(part['checks'])-{'auth-flow','timezone-utc','pdf-render','inbound-replay','worker-tests'} not in (set(CHECKS),set(CHECKS)-{'schema-apply'}): raise ValueError('incomplete runtime checks: '+', '.join(sorted(set(CHECKS)^set(part['checks']))))
        for check in part['checks'].values():
            log=Path(check['log'])
            if log.is_absolute() or '..' in log.parts: raise ValueError('unsafe log path')
            if check['status'] in ('PASS','FAIL') and not check['metrics']: raise ValueError('measured result requires metrics')
        backup=part['checks'].get('backup',{})
        metrics=backup.get('metrics',{})
        if metrics.get('comparison')=='row_counts_and_checksums':
            from helix_runtime_adapters import checksum_rows
            source=checksum_rows('\n'.join(json.dumps(row) for row in metrics.get('source_rows',[])))
            restored=checksum_rows('\n'.join(json.dumps(row) for row in metrics.get('restored_rows',[])))
            if backup.get('status')=='PASS' and (not source or source!=restored or metrics.get('tables')!=len(source) or
                    metrics.get('fresh_database') is not True or metrics.get('verification_completed') is not True or metrics.get('dump_bytes',0)<=0):
                raise ValueError('backup checksum evidence does not establish successful restore')
    if 'network_isolation' in report and isolation['status']!='ENFORCED' and report.get('status')=='PASS':
        raise ValueError('unverified network isolation cannot produce overall PASS')


def integration_failures(inventory):
    return [dict(integration_id=entry['id'],provider=entry['provider'],parts=entry['parts'],**route)
            for entry in (inventory or {}).get('integrations',[]) if entry['area']=='active'
            for route in entry['coverage']['tested_routes'] if route['status']=='FAIL']


class Runner:
    def __init__(self,project,out,engine='auto',budget_min=30,part=None,skip=(),keep=False,executor=None,tools=None,port_factory=free_port,oidc_stub=True,allow_version_mismatch=False,resource_governor=None,network_guard=None,allow_sysv_exposure=False,sysv_probe=None,cache_root=None,quick=0):
        self.project=Path(project).resolve(); self.out=Path(out).resolve()
        # Przebieg próbny: te same etapy co pełny, ale na kilku trasach każdej części. Służy do wykrycia błędów uruchomienia
        # i konfiguracji w kilka minut; jego wynik nie jest oceną projektu i raport to oznacza.
        self.quick=max(0,int(quick or 0))
        if self.out.is_relative_to(self.project) or self.project.is_relative_to(self.out): raise ValueError('output must be disjoint from project')
        if not math.isfinite(budget_min) or budget_min<=0: raise ValueError('budget must be positive')
        self.executor=executor or Executor(); self.tools=dict((tools or doctor())['tools']); self.engine=engine
        self.resources=resource_governor
        self.oidc_stub=oidc_stub
        self.allow_version_mismatch=allow_version_mismatch;self.allow_sysv_exposure=allow_sysv_exposure
        # Atrapa wykonawcy nie startuje procesów hosta, więc nie ma czego narażać; prawdziwy przebieg liczy segmenty przez ipcs.
        self.sysv_probe=sysv_probe or ((lambda:[]) if executor is not None else sysv_segments)
        # Samodzielne pobrania (zależności projektu, narzędzia pomiarowe) trafiają do pamięci podręcznej Helixa poza kopią projektu.
        # Przebieg z atrapą wykonawcy nie ma jej domyślnie, więc niczego nie pobiera i nie dotyka katalogu domowego.
        self.cache_root=Path(cache_root) if cache_root else (Path.home()/'.cache'/'helix' if executor is None else None)
        self.fidelity=dict(target=database_target(self.project),backend=None,artifact=None,server_version=None,compatible=None,warnings=[],attempts=[],selection_status='not_started',extension_checks=[])
        self.budget=Budget(budget_min*60); self.part=part; self.skip=set(skip); self.keep=keep; self.port_factory=port_factory
        if self.skip-(set(CHECKS)-{'schema-apply'})-{'route-review'}: raise ValueError('unknown skipped check')
        self.cleanup_actions=[]; self.database_cleanup=[]; self.steps=0; self.env={}; self.tmp=None; self.db=None; self.applied=set(); self.migration_notes=[]
        self.private_values=set();self.private_logs={}
        self.host_home=Path.home();self.container_endpoints={}
        self.active_transport=None;self.current_identity_tls=None
        self.extension_sources={};self.extension_context={}
        self.network_guard=network_guard;self.network_records=[]
        self.network_connect_ports=set();self.network_listen_ports=set();self.database_network=None
        self.database_network_ready=False;self.owned_node_options=None;self.owned_preloads=[];self.owned_pythonpath=None
        self.sink_observations={};self.active_sink=None;self.sink_handles=[]
    def integration_ready(self,provider,part,strategy,logs,version=None):
        """Record an actual matching adapter; readiness never proves a route."""
        if not hasattr(self,'integration_plan'):return
        from helix_environment import _observed_version
        for entry in self.integration_plan['integrations']:
            if entry['provider']!=provider or entry['area']!='active' or part['name'] not in entry['parts']:continue
            if entry['strategy']['selected']!=strategy:continue
            receipt=dict(integration_id=entry['id'],plan_id=self.integration_plan['plan_id'],run_id=self.run_id,
                         strategy=strategy,status='ready',readiness='ready',actual_version=_observed_version(version),
                         logs=logs,tested_routes=[])
            if receipt not in self.integration_receipts:self.integration_receipts.append(receipt)
    def require_integration_strategy(self,part):
        """An explicit unsupported strategy must not silently use existing adapters."""
        for entry in self.integration_plan['integrations']:
            if entry['area']!='active' or part['name'] not in entry['parts']:continue
            if entry['strategy']['resolution']=='explicit' and not entry['strategy']['implemented']:
                raise Blocked('integration '+entry['provider']+': explicit strategy '+str(entry['strategy']['selected'])+' is not implemented; no fallback')
            if entry['provider']=='postgres' and entry['strategy']['resolution']=='explicit' and entry['strategy']['selected']=='container':
                self.require_container_database=True
                if self.engine in ('native','service') or self.db is not None and getattr(self,'used_engine',None) not in ('docker','podman'):
                    raise Blocked('integration postgres: explicit container strategy conflicts with database backend; no fallback')
    def add_owned_preload(self,path):
        path=str(Path(path).resolve())
        allowed={str(HOME/'bin/runtime-fetch.cjs'),str(HOME/'bin/runtime-sinks-preload.cjs'),str(HOME/'bin/runtime-adapters.cjs'),str(HOME/'bin/runtime-generic.cjs')}
        if path not in allowed:raise ValueError('unknown owned Node preloader')
        if path not in self.owned_preloads:self.owned_preloads.append(path)
        self.owned_node_options=' '.join('--require '+json.dumps(item) for item in self.owned_preloads)
        self.env['NODE_OPTIONS']=self.owned_node_options

    def write_sink_input(self,value,path):
        fd,name=tempfile.mkstemp(prefix='.sink-input-',dir=path.parent)
        try:
            with os.fdopen(fd,'w') as stream:
                json.dump(value,stream,allow_nan=False);stream.flush();os.fsync(stream.fileno())
            os.replace(name,path)
        finally:
            if os.path.exists(name):os.unlink(name)

    def collect_sink(self,handle):
        from helix_audit_context import safe_read
        from helix_runtime_sinks import project_sinks
        try:
            snapshot=json.loads(safe_read(handle['public']))
            if snapshot.get('binding')!=handle['input']['binding']:raise ValueError('sink binding')
            sample=dict(run_id=self.run_id,integrations=self.integration_plan,sink_plan=self.sink_plans,sink_observations=[snapshot])
            project_sinks(sample)
            self.sink_observations[handle['part']]=snapshot
            return snapshot
        except (OSError,ValueError,TypeError,KeyError):
            snapshot=self.sink_observations[handle['part']]
            snapshot.update(status='partial',cleanup='unknown')
            if 'OBSERVATIONS_UNAVAILABLE' not in snapshot['gaps']:snapshot['gaps'].append('OBSERVATIONS_UNAVAILABLE')
            return snapshot

    def refresh_sink_input(self):
        from helix_runtime_generic import refresh_generic
        refresh_generic(self)
        handle=getattr(self,'active_sink',None)
        if handle is None:return
        value=handle['input']
        # Only origins already allocated by this run are admitted. No environment
        # supplied external URL becomes an adapter pass-through destination.
        origins=set(value['own_origins'])
        for key in ('HELIX_RUNTIME_OIDC_ISSUER',):
            issuer=self.env.get(key)
            if issuer:
                parsed=urlparse(issuer)
                if parsed.hostname in ('127.0.0.1','localhost','::1') and parsed.port in self.network_connect_ports:
                    origins.add(parsed.scheme+'://'+parsed.netloc)
        value['own_origins']=sorted(origins)
        control=getattr(self,'browser_control_port',None)
        value['browser_control_origins']=['http://127.0.0.1:'+str(control)] if type(control) is int and 1024<=control<=65535 else []
        self.write_sink_input(value,handle['config'])
        self.env['HELIX_RUNTIME_SINK_INPUT']=str(handle['config'])
        self.add_owned_preload(HOME/'bin/runtime-sinks-preload.cjs')

    def start_sinks(self,part,app_origin):
        from helix_audit_context import safe_read
        from helix_runtime_sinks import build_sink_input
        selected=next((row for row in self.sink_plans['parts'] if row['part']==part['path']),None)
        if selected is None or not selected['operation_ids']:return
        attempt='sink-'+secrets.token_hex(16);port=self.port_factory()
        if port in self.network_connect_ports or port in self.network_listen_ports:
            raise Blocked('runtime sink requires a distinct owned port')
        origin=f'http://127.0.0.1:{port}';private=self.tmp/'sink-control'/attempt
        private.mkdir(mode=0o700,parents=True)
        for parent in (self.out/'private',self.out/'private/sinks'):
            parent.mkdir(mode=0o700,exist_ok=True);parent.chmod(0o700)
        mailbox=self.out/'private/sinks'/attempt;mailbox.mkdir(mode=0o700)
        public=self.out/(attempt+'.json');config=private/'input.json'
        token=secrets.token_hex(32);self.private_values.add(token)
        domains=['helix-mail.invalid']
        if any('@example.invalid' in str(value) for value in self.env.values()) or self.keycloak_entry(part) is not None:domains.append('example.invalid')
        value=build_sink_input(self.sink_plans,run_id=self.run_id,part=part['path'],attempt_id=attempt,origin=origin,
            mailbox_path=str(mailbox),public_path=str(public),bearer_token=token,deadline_unix_ms=int(time.time()*1000+self.budget.remaining(86400)*1000),
            own_origins=[app_origin],synthetic_domains=domains)
        snapshot=dict(schema_version=1,binding=value['binding'],status='not_run',cleanup='not_needed',observations=[],gaps=[])
        self.sink_observations[part['path']]=snapshot
        handle=dict(input=value,config=config,public=public,mailbox=mailbox,part=part['path'],process=None)
        self.active_sink=handle;self.sink_handles.append(handle)
        self.write_sink_input(value,config)
        def cleanup():
            process=handle.get('process')
            if process is None:return
            try:self.executor.stop(process)
            finally:
                handle['process']=None;self.collect_sink(handle)
        self.cleanup_actions.append(cleanup)
        try:
            self.resource_wait();self.budget.remaining(1)
            argv=[self.tool('node'),HOME/'bin/runtime-sinks.cjs',config]
            safe={key:self.env[key] for key in ('PATH','HOME','CI') if key in self.env}
            self.note_tool(argv)
            handle['process']=self.executor.spawn(argv,private,safe,self.out/'logs'/(attempt+'.log'))
            deadline=time.monotonic()+self.budget.remaining(10)
            while time.monotonic()<deadline:
                self.budget.remaining(.001)
                if public.exists():
                    current=self.collect_sink(handle)
                    if current['status']=='ready':break
                    if current['status'] in ('partial','blocked','closed'):raise Blocked('runtime sink readiness failed')
                process=handle['process']
                if hasattr(process,'poll') and process.poll() is not None:raise Blocked('runtime sink exited before readiness')
                time.sleep(min(.02,max(0,deadline-time.monotonic())))
            else:raise Blocked('runtime sink readiness timeout')
            self.network_connect_ports.add(port)
            material=json.loads(safe_read(mailbox/'generated-material.json'))
            vapid=material['vapid']
            for key,size in (('public_key',65),('private_key',32)):
                raw=base64.urlsafe_b64decode(vapid[key]+'='*((-len(vapid[key]))%4))
                if len(raw)!=size:raise ValueError('synthetic material invalid')
            self.private_values.add(vapid['private_key'])
            env_names={name for row in selected['providers'] for name in row['env_names']}
            for name in env_names:
                if name=='PLAY_BASE_URL':self.env[name]=origin
                elif name.endswith('VAPID_PUBLIC_KEY'):self.env[name]=vapid['public_key']
                elif name.endswith('VAPID_PRIVATE_KEY'):self.env[name]=vapid['private_key']
                elif name.endswith('VAPID_SUBJECT'):self.env[name]=vapid['subject']
            self.refresh_sink_input()
            for provider in sorted({row['provider'] for row in selected['providers'] if row['strategy']=='emulator'}):
                self.integration_ready(provider,part,'emulator',[public.relative_to(self.out).as_posix()],VERSION)
        except BaseException as error:
            try:cleanup()
            except Exception:pass
            finally:
                snapshot=self.sink_observations[part['path']]
                snapshot.update(status='partial' if snapshot['observations'] else 'blocked')
                if 'SINK_START_FAILED' not in snapshot['gaps']:snapshot['gaps'].append('SINK_START_FAILED')
            if isinstance(error,(OSError,ValueError,KeyError,TypeError)):raise Blocked('runtime sink unavailable: SINK_START_FAILED') from None
            raise

    def resource_wait(self):
        resources=getattr(self,'resources',None)
        if resources is not None:
            if getattr(self,'resource_error',None) is not None:raise self.resource_error
            try:self.resource_last=resources.wait(stop=lambda:self.budget.remaining(3600))
            except ResourcePaused as error:
                self.resource_error=error
                raise
            return self.resource_last
    def note_tool(self, argv, output=None):
        """Retain actual tool identities, never command arguments or target values."""
        if not argv:return
        executable=str(argv[0]);base=Path(executable).name
        allowed={'node','npm','pnpm','yarn','python','python3','podman','docker','postgres','pg_ctl','initdb','pg_dump','pg_restore','psql','pg_isready','k6','lighthouse','openssl','bash','sh','playwright','chromium'}
        declared=next((key for key,path in self.tools.items() if path and str(path)==executable),None)
        name=declared or base
        if executable==sys.executable:name='python'
        name={'python3':'python','playwright_chromium':'chromium','psql':'postgres-client'}.get(name,name)
        if name not in allowed|{'postgres-client'}:return
        records=getattr(self,'execution_tools',{});self.execution_tools=records
        paths=getattr(self,'execution_paths',{});self.execution_paths=paths
        arguments=[str(arg) for arg in argv[1:]]
        only_version=arguments in (['--version'],['-V']) or name=='openssl' and arguments==['version']
        record=records.setdefault(name,dict(status='unknown',version=None,used=False,calls=0,evidence_kind='executor'))
        if output is None:
            record['used']=record['used'] or not only_version
            # Wpis mógł powstać z metadanych przeglądarki (bez licznika), zanim to samo narzędzie zostało uruchomione wprost.
            if not only_version:record['calls']=record.get('calls',0)+1
        elif only_version:
            from helix_environment import _observed_version
            if version:=_observed_version(output):record.update(version=version,status='recorded',evidence_kind='version_command')
        if declared:paths[name]=str(self.tools[declared])
        elif executable==sys.executable:paths[name]=executable
        elif base in self.tools and self.tools[base]:paths[name]=str(self.tools[base])

    def browser_metadata(self, data):
        if not any(data.get(key) for key in ('routes','auth_flow','identity_form','identity_policy','webauthn')):return
        from helix_audit_context import safe_read
        from helix_environment import _observed_version
        records=getattr(self,'execution_tools',{});self.execution_tools=records
        version=None
        try:
            metadata=Path(self.browser_module_dir)/'playwright/package.json'
            version=_observed_version(json.loads(safe_read(metadata)).get('version'))
        except (OSError,ValueError,TypeError):pass
        records['playwright']=dict(status='recorded' if version else 'unknown',version=version,used=True,evidence_kind='loaded_package_metadata')
        records.setdefault('chromium',dict(status='unknown',version=None,used=True,evidence_kind='browser_version_not_reported'))
        browser_version=data.get('webauthn',{}).get('capability',{}).get('browser_version') if isinstance(data.get('webauthn'),dict) else None
        if isinstance(browser_version,str) and re.fullmatch(r'\d+(?:\.\d+){1,3}',browser_version):
            records['chromium'].update(status='recorded',version=browser_version,used=True,evidence_kind='browser_version')
        if self.tools.get('playwright_chromium'):
            paths=getattr(self,'execution_paths',{});self.execution_paths=paths
            paths['chromium']=self.tools['playwright_chromium']

    def collect_tool_versions(self):
        """One bounded version call for each used executable; no target code or installs."""
        from helix_environment import _observed_version
        if getattr(self,'versions_collected',False):return
        self.versions_collected=True
        self.execution_tools=getattr(self,'execution_tools',{})
        for name,record in self.execution_tools.items():
            executable=getattr(self,'execution_paths',{}).get(name)
            if not record['used'] or record.get('version') or not executable:continue
            try:timeout=self.budget.remaining(5)
            except Blocked:record['evidence_kind']='version_not_probed_budget';continue
            args=[executable,'version'] if name=='openssl' else [executable,'--version']
            safe_env={'PATH':os.defpath,'GIT_OPTIONAL_LOCKS':'0','COREPACK_ENABLE_NETWORK':'0','COREPACK_ENABLE_DOWNLOAD_PROMPT':'0','npm_config_offline':'true','PIP_NO_INDEX':'1','UV_OFFLINE':'1'}
            version_home=None
            try:
                if name=='docker':
                    from helix_runtime_container import engine_environment
                    version_home=tempfile.TemporaryDirectory(prefix='.docker-client-version-',dir=self.out)
                    safe_env=engine_environment(dict(safe_env,HOME=version_home.name),engine='docker',require_endpoint=False)
                code,output=self.executor.run(args,self.out,safe_env,timeout)
                version=_observed_version(output) if code==0 else None
                if version:record.update(status='recorded',version=version,evidence_kind='version_command')
            except (OSError,subprocess.SubprocessError):record['evidence_kind']='version_command_failed'
            finally:
                if version_home is not None:version_home.cleanup()
        if self.fidelity.get('server_version'):
            self.execution_tools['postgres-server']=dict(status='recorded',version=self.fidelity['server_version'],used=True,scope='observed_running_server',evidence_kind='show_server_version')

    def redact_private(self,value):
        """Only redact this run's generated material; never inspect real env."""
        if isinstance(value,str):
            for secret in sorted(getattr(self,'private_values',()),key=len,reverse=True):
                value=value.replace(secret,'[REDACTED]')
            return value
        if isinstance(value,list):return [self.redact_private(item) for item in value]
        if isinstance(value,dict):return {self.redact_private(key):self.redact_private(item) for key,item in value.items()}
        return value

    def startup_text(self,public):
        from helix_audit_context import safe_read
        def unavailable(error):
            gaps=getattr(self,'startup_log_errors',{});self.startup_log_errors=gaps
            try:name=public.relative_to(self.out).as_posix()
            except ValueError:name='startup.log'
            gaps[name]=dict(log=name,status='not_read',reason='safe startup log read unavailable',error_type=type(error).__name__)
            return 'INCOMPLETE: startup log unavailable (safe read failed)\n'
        raw=getattr(self,'private_logs',{}).get(public)
        if raw is not None:
            try:text=self.redact_private(safe_read(raw))
            except OSError as error:text=unavailable(error)
            temporary=None
            try:
                fd,temporary=tempfile.mkstemp(prefix='.startup-',dir=public.parent)
                with os.fdopen(fd,'w') as stream:stream.write(text)
                os.replace(temporary,public)
            except OSError as error:return unavailable(error)
            finally:
                if temporary is not None and os.path.exists(temporary):os.unlink(temporary)
            return text
        try:return safe_read(public)
        except FileNotFoundError:return ''
        except OSError as error:return unavailable(error)

    def docker_endpoint(self,selector=None):
        from helix_runtime_container import local_docker_endpoint,validate_endpoint,public_endpoint
        if not hasattr(self,'_docker_endpoint_record'):
            selected=selector or getattr(self.executor,'docker_endpoint',None) or local_docker_endpoint
            self._docker_endpoint_record=validate_endpoint(selected(self.host_home))
            self.container_endpoints['docker']=public_endpoint(self._docker_endpoint_record)
        return dict(self._docker_endpoint_record) if self._docker_endpoint_record is not None else None

    def process_environment(self,environment,*,owned_preload=False):
        """Keep project loaders and host proxies out of trusted launchers."""
        denied={'NODE_OPTIONS','NODE_PATH','PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','PYTHONINSPECT','PYTHONUSERBASE',
                'BASH_ENV','ENV','ZDOTDIR','SHELLOPTS','SSH_AUTH_SOCK','DOCKER_HOST','DOCKER_CONTEXT','CONTAINER_HOST',
                'OPENSSL_CONF','OPENSSL_ENGINES','SSLKEYLOGFILE','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS'}
        result={key:value for key,value in environment.items() if key not in denied and not key.startswith(('DYLD_','LD_','GIT_CONFIG_KEY_','GIT_CONFIG_VALUE_')) and not key.upper().endswith('_PROXY')}
        if owned_preload and self.owned_node_options and environment.get('NODE_OPTIONS')==self.owned_node_options:
            result['NODE_OPTIONS']=self.owned_node_options
        if owned_preload and self.owned_pythonpath and environment.get('PYTHONPATH')==self.owned_pythonpath:
            result['PYTHONPATH']=self.owned_pythonpath
        return result

    def project_temporary(self):
        path=self.tmp/'project-tmp';path.mkdir(mode=0o700,exist_ok=True)
        return path

    def isolation_backend(self):
        if self.network_guard is None:
            control=self.tmp/'network-control'
            factory=getattr(self.executor,'network_guard',None)
            if factory is None:
                from helix_runtime_isolation import SeatbeltBackend
                factory=SeatbeltBackend
            self.network_guard=factory(control)
        return self.network_guard

    def isolation_policy(self,phase):
        if phase not in ('install','migration','build','application','measurement','database_server'):raise ValueError('unknown runtime process phase')
        control=self.tmp/'network-control';project_tmp=self.project_temporary()
        readonly={str(Path(path).resolve()) for path in ('/usr','/bin','/sbin','/System','/Library','/opt/homebrew','/private/etc','/dev') if Path(path).exists()}
        # Czcionki zainstalowane przez użytkownika system zgłasza przeglądarce po nazwie rodziny; bez odczytu ich plików tekst
        # w takiej czcionce rysuje się pustymi kwadratami i każdy pomiar wyglądu jest fałszywy. Same pliki czcionek, tylko do odczytu.
        user_fonts=getattr(self,'host_home',Path.home())/'Library'/'Fonts'
        if phase=='measurement' and user_fonts.is_dir():readonly.add(str(user_fonts.resolve()))
        for binary in self.tools.values():
            if binary:
                for directory in (Path(binary).parent.resolve(),Path(binary).resolve().parent.parent):
                    if directory!=Path('/') and directory.exists():readonly.add(str(directory))
                # Program z pakietu .app (Chrome) czyta też sam katalog pakietu; bez tego pada na blokadzie pojedynczej instancji.
                bundle=next((parent for parent in Path(binary).resolve().parents if parent.suffix=='.app'),None)
                if bundle is not None and bundle.is_dir():readonly.add(str(bundle))
        readonly.add(str(HOME));readonly.add(str(self.tmp))
        if phase=='database_server':
            if not self.database_network:raise Blocked('database network scope is not prepared')
            server=self.database_network
            writable=[str(server['data']),str(server['socket'].parent)];writefiles=[str(server['log'])]
            connect=[];listen=[server['port']];unix=[str(server['socket'])]
        else:
            writable=[str(self.work),str(project_tmp)]
            if phase=='measurement':
                visual=self.out/'visual';visual.mkdir(exist_ok=True);writable.append(str(visual))
            writefiles=[str(self.out/'logs/load-requests.jsonl')] if phase=='measurement' else []
            connect=sorted(self.network_connect_ports);listen=sorted(self.network_listen_ports);unix=[]
        policy=dict(scope={'database_server':'database_server','measurement':'measurement'}.get(phase,'project'),connect_tcp=connect,listen_tcp=listen,
                    unix_sockets=unix,writable_roots=writable,writable_files=writefiles,readonly_roots=sorted(readonly),
                    protected_roots=[str(self.project),str(control),str(HOME)])
        # Przeglądarka czyta stan monitora zasobów; bez tego uznaje monitor za martwy i przerywa pomiar po 15 s.
        monitor=getattr(getattr(self,'resources',None),'current_path',None)
        if phase=='measurement' and monitor is not None and Path(monitor).is_file():policy['readonly_files']=[str(monitor)]
        return policy

    def admit_process(self,phase,maximum):
        # Jedna bramka dla każdego procesu projektu (polecenie i proces w tle): ze starym wyjątkiem w straży nic nie startuje.
        if getattr(self,'guard_restore_failed',False):raise Blocked('sink guard input is stale; no further project process may start')
        self.resource_wait();remaining=self.budget.remaining(maximum)
        policy=self.isolation_policy(phase);backend=self.isolation_backend()
        try:grant=backend.admit(policy,remaining)
        except (OSError,ValueError,subprocess.TimeoutExpired):
            grant=dict(enforcement='blocked',proof_kind='none',backend='unavailable',reason_code='ADMISSION_ERROR',policy_hash=None,scope=policy['scope'])
        public={key:grant.get(key) for key in ('enforcement','proof_kind','backend','reason_code','policy_hash','scope')}
        public.update(phase=phase,command_invoked=False);self.network_records.append(public)
        self.save_network_isolation()
        if public['enforcement'] not in ('enforced','simulated') or (public['enforcement'],public['proof_kind']) not in (('enforced','execution'),('simulated','synthetic_test')):
            raise Blocked('runtime network isolation unavailable: '+str(public['reason_code']))
        return backend,grant,public

    def save_network_isolation(self):
        self.out.mkdir(parents=True,exist_ok=True)
        result=network_isolation_record(self.network_records)
        fd,name=tempfile.mkstemp(prefix='.network-isolation-',suffix='.json',dir=self.out)
        try:
            with os.fdopen(fd,'w') as stream:
                json.dump(result,stream,sort_keys=True,allow_nan=False);stream.write('\n');stream.flush();os.fsync(stream.fileno())
            os.replace(name,self.out/'network-isolation.json')
        finally:
            if os.path.exists(name):os.unlink(name)

    def project_command(self,argv,cwd=None,maximum=120,*,phase):
        if getattr(self,'guard_restore_failed',False):raise Blocked('sink guard input is stale; no further project process may start')
        if phase=='migration':self.require_database_network()
        backend,grant,record=self.admit_process(phase,maximum)
        try:wrapped=backend.wrap([str(item) for item in argv],grant)
        except ValueError:
            record.update(enforcement='blocked',proof_kind='none',reason_code='WRAPPER_REJECTED');self.save_network_isolation()
            raise Blocked('runtime network wrapper rejected current grant') from None
        original=self.env;self.env=self.process_environment(original,owned_preload=True)
        # macOS: postmaster pod izolacją z odziedziczonym locale kończy się „became multithreaded during startup”.
        if phase=='database_server':self.env['LC_ALL']='C'
        self.note_tool(argv)
        try:
            output=self.command(wrapped,cwd,maximum=maximum,_network_record=record)
            self.note_tool(argv,output)
            return output
        finally:self.env=original

    def screen_session(self,part):
        """Rola i plik sesji do oglądania ekranów chronionych; tylko z jawnej deklaracji właściciela dla tej części."""
        declared=(((getattr(self,'config',None) or {}).get('runtime') or {}).get('keycloak') or {}).get('parts') or {}
        role=(declared.get(part['path']) or {}).get('screen_role')
        if not isinstance(role,str) or not getattr(self,'private_keycloak',{}).get(part['path']):return None
        return dict(role=role,path=self.project_temporary()/'screen-session.json')

    def screen_cookies(self,part,host):
        """Ciasteczka sesji roli ekranów dla pomiaru szybkości i obciążenia (decyzja właściciela: Lighthouse i k6 dostają sesję).
        Tylko ciasteczka hosta aplikacji; bez zadeklarowanej roli albo bez udanego logowania wynik jest pusty."""
        path=self.screen_file(part)
        if path is None:return {}
        try:state=json.loads(path.read_text())
        except (OSError,ValueError):return {}
        return {c['name']:c['value'] for c in state.get('cookies',[]) if isinstance(c,dict) and isinstance(c.get('name'),str) and isinstance(c.get('value'),str)
                and str(c.get('domain','')).lstrip('.')==host and re.fullmatch(r'[!#-+\--:<-\[\]-~]+',c['name']) and re.fullmatch(r'[!#-+\--:<-\[\]-~]*',c['value'])}

    def measurement_command(self,argv,cwd=None,maximum=120,browser=None):
        # Serwer przeglądarki (Playwright) nasłuchuje na pętli zwrotnej; izolacja dopuszcza tylko port przydzielony temu poleceniu.
        port=self.port_factory();fresh_listen=port not in self.network_listen_ports;fresh_connect=port not in self.network_connect_ports
        missing=object();previous=self.env.get('HELIX_BROWSER_PORT',missing);previous_temp=self.env.get('MAC_CHROMIUM_TMPDIR',missing)
        # Straż skrzynek zostaje na każdym procesie Node. Dostaje jeden wyjątek (decyzja właściciela): połączenie sterujące
        # z własną przeglądarką na porcie tego polecenia. Wejście straży pisze Helix, nie projekt.
        # Błąd na dowolnym kroku cofa porty, środowisko i wejście straży; gdy wejścia nie da się cofnąć,
        # przebieg nie startuje kolejnych procesów projektu.
        failure=None;result=None;companion=None
        fill=lambda items:[item.replace('{port}',str(port)) if isinstance(item,str) else item for item in items]
        try:
            self.network_listen_ports.add(port);self.network_connect_ports.add(port)
            self.env['HELIX_BROWSER_PORT']=str(port)
            # Chrome bierze katalog tymczasowy z MAC_CHROMIUM_TMPDIR, nie z TMPDIR; kierujemy go do katalogu przebiegu,
            # żeby nie potrzebował uprawnień do systemowego katalogu tymczasowego użytkownika.
            self.env['MAC_CHROMIUM_TMPDIR']=str(self.project_temporary())
            self.browser_control_port=port;self.refresh_sink_input()
            if browser is not None:
                # Narzędzie, które samo startuje przeglądarkę poza katalogiem przebiegu (Lighthouse: mktemp ignoruje TMPDIR na macOS),
                # dostaje przeglądarkę uruchomioną przez Helix na porcie tego polecenia i tylko się do niej podłącza.
                companion=self.project_spawn(fill(browser),cwd or self.work,self.env,self.out/'logs'/('measurement-browser-'+str(port)+'.log'),phase='measurement')
                ready=getattr(self.executor,'port_ready',None)
                if ready is not None:ready(port,self.budget.remaining(20))
            result=self.project_command(fill(argv),cwd,maximum,phase='measurement')
        except BaseException as error:failure=error
        if companion is not None:
            try:self.executor.stop(companion)
            except BaseException as error:failure=failure or error
        self.browser_control_port=None
        try:self.refresh_sink_input()
        except Exception:
            self.guard_restore_failed=True
            handle=getattr(self,'active_sink',None)
            if handle is not None:handle['input']['browser_control_origins']=[]
        if previous is missing:self.env.pop('HELIX_BROWSER_PORT',None)
        else:self.env['HELIX_BROWSER_PORT']=previous
        if previous_temp is missing:self.env.pop('MAC_CHROMIUM_TMPDIR',None)
        else:self.env['MAC_CHROMIUM_TMPDIR']=previous_temp
        if fresh_listen:self.network_listen_ports.discard(port)
        if fresh_connect:self.network_connect_ports.discard(port)
        if failure is not None:raise failure
        if getattr(self,'guard_restore_failed',False):raise Blocked('sink guard input could not be restored after a measurement command')
        return result

    def project_spawn(self,argv,cwd,env,log,*,phase):
        backend,grant,record=self.admit_process(phase,120)
        try:wrapped=backend.wrap([str(item) for item in argv],grant)
        except ValueError:
            record.update(enforcement='blocked',proof_kind='none',reason_code='WRAPPER_REJECTED');self.save_network_isolation()
            raise Blocked('runtime network wrapper rejected current grant') from None
        self.note_tool(argv)
        process=self.executor.spawn(wrapped,cwd,self.process_environment(env,owned_preload=True),log)
        record['command_invoked']=True
        try:self.save_network_isolation()
        except BaseException:
            try:self.executor.stop(process)
            except BaseException:pass
            raise
        return process

    def require_database_network(self):
        if self.database_network_ready:return
        # Only a trusted executor fixture may represent a pre-existing synthetic
        # server. The real backend cannot attest a service or daemon-owned server.
        backend=self.isolation_backend()
        if getattr(backend,'synthetic_test',False):
            if self.database_network is None:
                port=urlparse(self.db or '').port or 5432
                self.database_network=dict(port=port,data=self.tmp/'pgdata',socket=self.tmp/'pg-socket'/('.s.PGSQL.'+str(port)),log=self.out/'logs/postgres.log')
            self.admit_process('database_server',15);self.database_network_ready=True;return
        raise Blocked('database server network isolation is not confirmed')

    def prepare_database_network(self,engine,port):
        self.database_network_ready=False
        self.database_network=dict(port=port,data=self.tmp/'pgdata',socket=self.tmp/'pg-socket'/('.s.PGSQL.'+str(port)),log=self.out/'logs/postgres.log')
        backend=self.isolation_backend()
        if engine!='native' and not getattr(backend,'synthetic_test',False):
            self.network_records.append(dict(enforcement='blocked',proof_kind='none',backend='unsupported',reason_code='DATABASE_SERVER_UNSUPPORTED',policy_hash=None,scope='database_server',phase='database_server',command_invoked=False))
            self.save_network_isolation()
            raise Blocked('database server network isolation unsupported for '+engine+'; no unprotected fallback')
        for directory in (self.database_network['data'],self.database_network['socket'].parent):directory.mkdir(mode=0o700,exist_ok=True)
        _,_,record=self.admit_process('database_server',30)
        self.network_connect_ports.add(port)
        return record

    def command(self,argv,cwd=None,maximum=120,cleanup=False,_network_record=None):
        if not cleanup:self.resource_wait()
        timeout=15 if cleanup else self.budget.remaining(maximum)
        if not cleanup and getattr(self,'trial_deadline',None):
            timeout=min(timeout,max(.01,self.trial_deadline-time.monotonic()))
        environment=self.process_environment(self.env,owned_preload=True)
        if argv and self.tools.get('docker') and str(argv[0])==str(self.tools['docker']):
            from helix_runtime_container import engine_environment
            version_only=list(argv[1:])==['--version']
            try:environment=engine_environment(environment,engine='docker',endpoint=None if version_only else self.docker_endpoint(),require_endpoint=not version_only)
            except ValueError as error:raise Blocked(str(error)) from None
        self.steps+=1; log=self.out/'logs'/f'{self.steps:03d}.log'
        self.note_tool(argv)
        try:
            rc,output=self.executor.run([str(x) for x in argv],cwd or self.work,environment,timeout)
            if _network_record is not None:_network_record['command_invoked']=True;self.save_network_isolation()
        except (OSError,subprocess.TimeoutExpired) as e:
            if _network_record is not None and isinstance(e,subprocess.TimeoutExpired):_network_record['command_invoked']=True;self.save_network_isolation()
            log.write_text(type(e).__name__+'\n'); raise Blocked(type(e).__name__+': '+str(e)[:400]) from e
        # Synthetic credentials are still private. Applications may echo them.
        output=self.redact_private(output)
        log.write_text(self.redact_private('$ '+ ' '.join(str(x) for x in argv)+'\n'+output+'\nexit='+str(rc)+'\n'))
        self.last_log=str(log.relative_to(self.out))
        if rc: raise Blocked('exit '+str(rc)+': '+first_error(output))
        self.note_tool(argv,output)
        return output
    def tool(self,name):
        value=self.tools.get(name)
        if not value: raise Blocked('missing tool: '+name)
        return value
    def save_fidelity(self, warning=None):
        """Persist database selection before application work or a later interruption."""
        if warning and warning not in self.fidelity['warnings']:
            self.fidelity['warnings'].append(warning)
            print('[helix runtime] '+warning, file=sys.stderr, flush=True)
        self.out.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.database-fidelity-', suffix='.json', dir=self.out)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(self.fidelity, stream, ensure_ascii=False, indent=2, allow_nan=False)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.out/'database-fidelity.json')
        finally:
            if os.path.exists(name): os.unlink(name)
    def extension_preflight(self,spec=None,*,database=None,scope='base',part=None,candidate=None):
        """Observe this owned database before project SQL, never activate extensions."""
        from helix_runtime_extensions import COMMON_EXTENSIONS, AVAILABLE_EXTENSIONS_SQL, parse_available_extensions, sql_extensions
        database=database or self.db
        if not database or scope not in ('base','trial','restore'):raise ValueError('invalid extension preflight scope')
        self.require_database_network()
        migrations=[]
        for original in (spec or {}).get('migrations',[]):
            migration=dict(original)
            if 'extensions' not in migration and migration['kind']=='sql':
                snapshot=sql_extensions(read(self.work/migration['path']),path=migration['path'])
                migration['extensions']=dict(snapshot,requirements_status='unknown' if snapshot['gaps'] else 'recorded')
            migrations.append(migration)
        snapshot=extension_requirements(migrations)
        required=sorted({row['name'] for row in snapshot['declarations']})
        database_name=urlparse(database).path.removeprefix('/')
        if not re.fullmatch(r'helix(?:_[A-Za-z0-9_]+)?',database_name):raise ValueError('extension preflight requires an owned database')
        row=dict(scope=scope,database=database_name,part=part,candidate=candidate,status='checking',reason_code='CHECK_PENDING',
                 **snapshot,required=required,observed=[],missing=[],version_check='not_checked',log=None)
        self.fidelity.setdefault('extension_checks',[]).append(row)
        self.save_fidelity()
        before=self.steps
        try:
            output=self.command([self.tool('psql'),database,'-X','-At','-v','ON_ERROR_STOP=1','-c',AVAILABLE_EXTENSIONS_SQL],maximum=15)
            try: catalog=parse_available_extensions(output)
            except ValueError:
                row.update(status='incomplete',reason_code='CATALOG_INVALID')
                raise Blocked('extension catalog returned invalid data; see database-fidelity.json') from None
            row['observed']=[dict(name=name,available=name in catalog,default_version=catalog.get(name,{}).get('default_version'),installed_version=catalog.get(name,{}).get('installed_version')) for name in sorted(set(COMMON_EXTENSIONS)|set(required))]
            row['missing']=sorted(name for name in required if name not in catalog)
            if row['missing']:
                row.update(status='blocked',reason_code='REQUIRED_EXTENSION_UNAVAILABLE')
                places=', '.join(f"{item['path']}:{item['line']}" for item in row['declarations'] if item['name'] in row['missing'])
                raise Blocked('required PostgreSQL extensions unavailable: '+', '.join(row['missing'])+' ('+scope+'; '+places+'); see database-fidelity.json')
            row.update(status='ready',reason_code='CATALOG_OBSERVED')
            # Restore only requirements admitted for this source DB, not unused
            # candidates from other databases or sibling application scopes.
            if scope!='restore':
                known=self.extension_sources.setdefault(database,{})
                for migration in migrations:known[migration['path']]=migration
            return row
        except ResourcePaused:
            row.update(status='incomplete',reason_code='RESOURCE_PAUSED');raise
        except (Blocked,OSError,subprocess.TimeoutExpired):
            if row['status']=='checking':row.update(status='incomplete',reason_code='CATALOG_QUERY_FAILED')
            raise
        finally:
            if row['status']=='checking':row.update(status='incomplete',reason_code='INTERRUPTED')
            if self.steps>before:row['log']='logs/'+f'{self.steps:03d}.log'
            self.save_fidelity()
    def database(self):
        target=self.fidelity['target']
        self.fidelity['selection_status']='selecting'
        self.save_fidelity('ASSUMPTION: '+target['assumption'] if target['assumption'] else None)
        if target['conflict'] or target['engine']!='postgres' or {'vector','postgis'}<=set(target['extensions']):
            self.fidelity['selection_status']='blocked'
            self.save_fidelity('WARN: conflicting or unsupported database target; resolve repository evidence')
            raise Blocked('database target conflict or unsupported engine; resolve repository evidence: '+json.dumps(target['evidence'][:5]))
        candidates=['podman','docker','native'] if self.engine=='auto' else [self.engine]
        if self.engine=='auto' and not getattr(self.isolation_backend(),'synthetic_test',False) and not getattr(self,'require_container_database',False):
            # This backend can attest a directly owned server, not a daemon's
            # descendants. Auto selects only supported candidates up front.
            candidates=['native']
        if getattr(self,'require_container_database',False):candidates=[engine for engine in candidates if engine in ('podman','docker')]
        failures=[]
        for engine in candidates:
            backend_attempt=dict(backend=engine,status='starting',reason=None)
            self.fidelity['attempts'].append(backend_attempt)
            if engine not in ('native','service') and not self.tools.get(engine):
                backend_attempt.update(status='unavailable',reason='missing tool: '+engine)
                failures.append(engine+': missing tool')
                self.save_fidelity()
                continue
            self.save_fidelity('WARN: backend fallback to '+engine+'; previous attempts: '+'; '.join(failures) if failures else None)
            mark=len(self.cleanup_actions)
            try:
                port=5432 if engine=='service' else self.port_factory()
                server_record=self.prepare_database_network(engine,port)
                database_name='helix_rt_'+secrets.token_hex(6) if engine=='service' else 'helix'
                url=f'postgresql://helix@127.0.0.1:{port}/{database_name}'
                if engine in ('podman','docker'):
                    name='helix-rt-'+secrets.token_hex(6); tool=self.tool(engine)
                    self.cleanup_actions.append(lambda t=tool,n=name:self.command([t,'rm','-f',n],cleanup=True))
                    self.command([tool,'run','--detach','--rm','--name',name,'-p',f'127.0.0.1:{port}:5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=helix','-e','POSTGRES_DB=helix',qualify_image(target['image'])],_network_record=server_record)
                    self.database_network_ready=True
                elif engine=='native':
                    # Select a complete toolchain belonging to the required major.
                    directories=[Path('/usr/lib/postgresql')/str(target['major'])/'bin',
                                 Path('/opt/homebrew/opt')/f"postgresql@{target['major']}"/'bin',
                                 Path('/usr/local/opt')/f"postgresql@{target['major']}"/'bin',
                                 Path('/Applications/Postgres.app/Contents/Versions')/str(target['major'])/'bin']
                    candidates_native=[str(d/'postgres') for d in directories if (d/'postgres').is_file()]
                    if self.tools.get('pg_config'):
                        try:
                            bindir=self.command([self.tools['pg_config'],'--bindir']).strip()
                            if Path(bindir).is_absolute(): candidates_native.append(str(Path(bindir)/'postgres'))
                        except Blocked: pass
                    candidates_native += [self.tools.get('postgres') or str(Path(self.tools.get('pg_ctl','/missing/pg_ctl')).parent/'postgres')]
                    selected=None
                    for binary in candidates_native:
                        try: version=self.command([binary,'--version'])
                        except Blocked: continue
                        match=re.search(r'(\d+)(?:\.\d+)',version)
                        if match and int(match[1])==target['major']: selected=Path(binary).parent; break
                    if selected:
                        for toolname in ('postgres','pg_ctl','initdb','pg_isready','psql','pg_dump','pg_restore'):
                            self.tools[toolname]=str(selected/toolname)
                    elif not self.allow_version_mismatch:
                        raise Blocked('native PostgreSQL major mismatch; '+backend_instruction(self.tools,target['major']))
                    data=self.tmp/'pgdata'; ctl=self.tool('pg_ctl')
                    # Seatbelt nie zawęża SysV do przebiegu: serwer wykonujący SQL projektu mógłby sięgnąć do cudzych segmentów
                    # tego użytkownika. Domyślnie odmowa, gdy takie istnieją albo nie da się ich policzyć; wybór należy do użytkownika.
                    foreign=self.sysv_probe()
                    exposure=dict(segments=None if foreign is None else len(foreign),accepted_by_user=bool(self.allow_sysv_exposure),
                                  scope='SysV shm i sem bez filtra po przebiegu; POSIX IPC zabronione')
                    self.fidelity['sysv_shared_memory']=exposure
                    if (foreign is None or foreign) and not self.allow_sysv_exposure:
                        raise Blocked(('nie można policzyć segmentów pamięci SysV' if foreign is None else f'na tym koncie istnieje {len(foreign)} segmentów pamięci SysV innych programów')
                                      +'; izolowany serwer bazy mógłby do nich sięgnąć. Zatrzymaj inne lokalne bazy (ipcs -m) albo świadomie dopuść: --allow-sysv-exposure')
                    # UTF8: bez tego klaster ma kodowanie SQL_ASCII i sterowniki aplikacji nie zapiszą znaków spoza ASCII (np. polskich w migracjach).
                    self.command([self.tool('initdb'),'-D',data,'-U','helix','--auth-local=trust','--auth-host=trust','--no-locale','--encoding=UTF8'])
                    self.cleanup_actions.append(lambda:self.command([ctl,'-D',data,'-m','immediate','-w','stop'],cleanup=True))
                    self.project_command([ctl,'-D',data,'-l',self.out/'logs/postgres.log','-o',f'-h 127.0.0.1 -p {port} -k {self.database_network["socket"].parent} -c dynamic_shared_memory_type=mmap','-w','start'],phase='database_server')
                    self.database_network_ready=True
                    self.command([self.tool('psql'),f'postgresql://helix@127.0.0.1:{port}/postgres','-X','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE helix'])
                else:
                    # A unique owned database prevents touching any pre-existing service data.
                    self.command([self.tool('psql'),f'postgresql://helix@127.0.0.1:{port}/postgres','-X','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE '+database_name],_network_record=server_record)
                    self.database_network_ready=True
                    self.cleanup_actions.append(lambda u=url,n=database_name:self.command([self.tool('psql'),u.rsplit('/',1)[0]+'/postgres','-X','-v','ON_ERROR_STOP=1','-c','DROP DATABASE '+n+' WITH (FORCE)'],cleanup=True))
                # Bound readiness polling through psql, also for detached containers.
                for attempt in range(20):
                    try:
                        readiness=[tool,'exec',name,'pg_isready','-h','127.0.0.1','-U','helix','-d','helix'] if engine in ('podman','docker') else [self.tool('pg_isready'),'-d',url]
                        self.command(readiness,maximum=3)
                        self.command([self.tool('psql'),url,'-X','-v','ON_ERROR_STOP=1','-c','SELECT 1'],maximum=3); break
                    except Blocked:
                        if attempt==19: raise
                        time.sleep(.15)
                actual=self.command([self.tool('psql'),url,'-X','-At','-v','ON_ERROR_STOP=1','-c','SHOW server_version']).strip()
                match=re.fullmatch(r'([1-9]\d*)(?:\.\d+)*(?:beta\d+|rc\d+|devel)?(?:\s+\([^()\r\n]+\))?',actual)
                compatible=bool(match and int(match[1])==target['major'])
                self.fidelity.update(backend=engine,artifact=target['image'] if engine in ('podman','docker') else self.tools.get('postgres') or self.tools.get('pg_ctl'),server_version=actual,compatible=compatible)
                backend_attempt.update(server_version=actual,compatible=compatible)
                self.save_fidelity('WARN: actual server version '+actual+' does not match target '+str(target['major']) if not compatible else None)
                if not match:
                    raise Blocked('actual PostgreSQL server version is unknown; cannot establish runtime compatibility')
                if not compatible and not self.allow_version_mismatch:
                    raise Blocked('actual PostgreSQL server major mismatch; use --allow-version-mismatch only for explicitly degraded evidence')
                self.extension_preflight(database=url,scope='base',part=getattr(self,'active_part',None))
                backend_attempt['status']='ready'
                self.fidelity['selection_status']='selected'
                self.save_fidelity()
                self.db=url; self.used_engine=engine
                self.container=name if engine in ('podman','docker') else None
                return
            except Blocked as e:
                self.database_network_ready=False
                failures.append(engine+': '+str(e))
                backend_attempt.update(status='failed',reason=str(e))
                self.save_fidelity()
                for action in reversed(self.cleanup_actions[mark:]):
                    try: action()
                    except Blocked: pass
                del self.cleanup_actions[mark:]
        self.fidelity['selection_status']='blocked'
        self.save_fidelity('WARN: no compatible backend; '+backend_instruction(self.tools,target['major'],failures=failures))
        raise Blocked('database engines unavailable: '+'; '.join(failures)+'; '+backend_instruction(self.tools,target['major'],failures=failures))
    def install(self,part):
        cwd=self.work/part['workspace']; pm=part['package_manager']
        if pm=='pip':
            venv=self.project_temporary()/'venv'
            # Interpreter w wersji, którą deklaruje projekt (Dockerfile, .python-version); paczki pobiera Helix poza izolacją jako gotowe
            # koła (bez wykonywania kodu paczek), a instalacja w izolacji idzie już bez sieci.
            python,version=project_python(cwd)
            notes=getattr(self,'dependency_sources',{}); self.dependency_sources=notes
            # Projekt bez zadeklarowanej wersji dostaje domyślny interpreter; gdy paczka nie ma jeszcze wydania dla tak nowej wersji,
            # Helix próbuje kolejno starszych zainstalowanych interpreterów, zamiast kończyć na braku paczki.
            older=[] if version else older_pythons(python)
            path_before=self.env['PATH']
            self.project_command([python,'-m','venv',venv],maximum=60,phase='install')
            self.env['PATH']=str(venv/'bin')+os.pathsep+path_before
            # Instalacja idzie w izolacji, a sieć ma tylko przez pośrednika Helixa, który przepuszcza wyłącznie rejestr paczek Pythona.
            # Paczki budowane ze źródeł wykonują więc swój kod w izolacji, nie poza nią.
            proxy=PackageProxy(PYTHON_REGISTRY_HOSTS)
            saved={'PIP_CONFIG_FILE':self.env.get('PIP_CONFIG_FILE')}
            try:
                self.network_connect_ports.add(proxy.port)
                # Zmienne *_PROXY są celowo usuwane ze środowiska procesów projektu, więc adres pośrednika idzie plikiem konfiguracji pip
                # (dziedziczą go także podprocesy budujące paczki ze źródeł).
                settings=self.project_temporary()/'pip.conf'
                def configure():
                    # W izolacji nie ma systemowego magazynu certyfikatów: pip weryfikuje rejestr własnym pakietem certyfikatów (certifi z venv).
                    # Ścieżka zależy od wersji interpretera, więc plik powstaje od nowa po każdym utworzeniu venv.
                    bundle=next(iter(sorted(venv.glob('lib/python*/site-packages/pip/_vendor/certifi/cacert.pem'))),None)
                    settings.write_text('[global]\nproxy = http://127.0.0.1:'+str(proxy.port)+'\nindex-url = https://pypi.org/simple\ndisable-pip-version-check = true\nno-input = true\n'
                                        +('use-deprecated = legacy-certs\ncert = '+str(bundle)+'\n' if bundle else ''))
                configure()
                self.env['PIP_CONFIG_FILE']=str(settings)
                command=['python','-m','pip','install','-r','requirements.txt'] if (cwd/'requirements.txt').exists() else ['python','-m','pip','install','.']
                while True:
                    try:self.project_command(command,cwd,maximum=600,phase='install');break
                    except Blocked as error:
                        if not older or not re.search(r'from versions: none|No matching distribution|Requires-Python',str(error)):raise
                        python=older.pop(0);shutil.rmtree(venv)
                        self.project_command([python,'-m','venv',venv],maximum=60,phase='install')
                        configure()
            finally:
                for name,value in saved.items():
                    if value is None:self.env.pop(name,None)
                    else:self.env[name]=value
                self.network_connect_ports.discard(proxy.port)
                proxy.close()
                (self.out/'logs'/('dependencies-'+re.sub(r'[^A-Za-z0-9]+','-',part['path']).strip('-')+'.log')).write_text(
                    'python: '+python+' (wersja projektu: '+(version or 'niezadeklarowana')+'); paczki: instalacja w izolacji przez pośrednika rejestru; połączenia dozwolone: '
                    +str(proxy.allowed)+', odmówione: '+(', '.join(sorted(proxy.denied)) or 'brak')+'\n')
            notes[part['path']]='registry-proxy'
            return
        executable=self.tool(pm)
        lock=part['lockfile']
        if pm=='npm' and lock=='package-lock.json' and self.reuse_node_modules(part,cwd,executable): return
        cmd=[executable,'ci'] if pm=='npm' and lock=='package-lock.json' else [executable,'install','--frozen-lockfile'] if pm in ('pnpm','yarn') and lock and lock.endswith(('yaml','.lock')) else [executable,'install']
        try: self.project_command(cmd+(['--include=dev'] if pm=='npm' else []),cwd,maximum=300,phase='install')
        except Blocked:
            if len(cmd)==2 and cmd[1]=='install': raise
            self.project_command([executable,'install']+(['--no-frozen-lockfile'] if pm=='pnpm' else []),cwd,maximum=300,phase='install')
    def operator_setting(self,name,default=None):
        """Ustawienie, które wolno podać tylko operatorowi (plik --config poza projektem): dopuszcza hosty albo pliki spoza
        projektu, więc wersja zapisana w helix.json samego projektu jest odrzucana, a nie po cichu pomijana."""
        runtime=(getattr(self,'config',None) or {}).get('runtime',{})
        value=(runtime.get('supabase') or {}).get(name.split('.',1)[1]) if name.startswith('supabase.') else runtime.get(name)
        if value is None:return default
        from helix_config import source
        if Path(source(self.project)).resolve()==Path(self.project).resolve()/'helix.json':
            raise Blocked('runtime.'+name+': to ustawienie przyjmuje tylko konfiguracja operatora (--config), nie helix.json projektu')
        return value

    def reuse_node_modules(self,part,cwd,npm):
        """Zależności bez sieci w izolacji: z projektu, gdy zgodne z plikiem blokady, inaczej pobrane przez Helix bez uruchamiania skryptów paczek."""
        lockfile=cwd/'package-lock.json'; source=self.project/part['workspace']/'node_modules'; origin='project'
        if not node_modules_match(lockfile,source):
            source=self.prepare_node_modules(lockfile,cwd,npm); origin='helix-prepared'
            if source is None: return False
        if not links_stay_inside(source):
            if origin=='project': return False
            raise Blocked('pobrane zależności zawierają dowiązanie poza własne drzewo')
        # Z katalogów z kropką na szczycie przechodzą tylko .bin i ukryty plik blokady; pamięci podręczne narzędzi zostają.
        root=source.resolve()
        shutil.copytree(root,cwd/'node_modules',symlinks=True,ignore=lambda directory,names:[n for n in names if Path(directory)==root and n.startswith('.') and n not in NODE_MODULES_DOT_ENTRIES])
        notes=getattr(self,'dependency_sources',{}); self.dependency_sources=notes; notes[part['path']]=origin
        (self.out/'logs'/('dependencies-'+re.sub(r'[^A-Za-z0-9]+','-',part['path']).strip('-')+'.log')).write_text('node_modules: '+origin+'; paczki na dysku zgodne z package-lock.json\n'
            +(getattr(self,'dependency_note','') if origin=='helix-prepared' else ''))
        if origin=='helix-prepared':
            # Skrypty paczek wykonują się dopiero tutaj, w izolacji i bez sieci. Nieudany rebuild to brak gotowych zależności.
            self.project_command([npm,'rebuild'],cwd,maximum=300,phase='install')
        return True

    def prepare_runtime_tools(self):
        """Własne narzędzia pomiarowe Helixa (axe-core, playwright) pobrane raz poza kopią projektu, bez skryptów paczek. None = instalacja w izolacji."""
        if self.cache_root is None: return None
        stage=self.cache_root/'runtime-tools'/sys.platform; modules=stage/'node_modules'
        marker=stage/CACHE_COMPLETE
        def ready(): return all((modules/name/'package.json').is_file() for name in RUNTIME_TOOL_PACKAGES) and links_stay_inside(modules)
        try:
            # Znacznik powstaje dopiero po udanym pobraniu; bez niego przerwane albo nieudane pobranie nie jest pamięcią podręczną.
            if marker.is_file() and ready(): return modules
            marker.unlink(missing_ok=True)
            if modules.exists(): shutil.rmtree(modules)
            npm=self.tools.get('npm')
            if not npm: return None
            (stage/'home').mkdir(parents=True,exist_ok=True); (stage/'package.json').write_text('{}')
            environment={'PATH':self.env.get('PATH') or os.environ.get('PATH',''),'HOME':str(stage/'home'),'npm_config_cache':str(stage/'cache'),'CI':'1'}
            self.steps+=1; log=self.out/'logs'/f'{self.steps:03d}.log'
            argv=[str(npm),'install','--prefix',str(stage),'--no-save','--package-lock=false','--ignore-scripts','--no-audit','--no-fund','--registry',NPM_REGISTRY,*RUNTIME_TOOL_PACKAGES]
            rc,output=self.executor.run(argv,stage,environment,self.budget.remaining(300))
            log.write_text('$ (narzędzia pomiarowe Helixa, poza kopią projektu, bez skryptów paczek) '+' '.join(argv)+'\n'+output[-4000:]+'\nexit='+str(rc)+'\n')
            if rc!=0 or not ready(): return None
            marker.write_text('ok\n'); return modules
        except (OSError,subprocess.SubprocessError): return None

    def prepare_node_modules(self,lockfile,cwd,npm):
        """Pobranie paczek poza kopią projektu, bez ich skryptów (--ignore-scripts). None = wróć do instalacji w izolacji."""
        hosts=self.operator_setting('dependency_hosts',[])
        if not isinstance(hosts,list) or len(hosts)>10 or not all(isinstance(h,str) and re.fullmatch(r'[a-z0-9.-]{3,100}',h) for h in hosts):
            raise Blocked('runtime.dependency_hosts: wymagana lista do 10 nazw hostów')
        if self.cache_root is None: return None
        # npm czyta package.json i buduje drzewo zależności, zanim porówna je z plikiem blokady: adres spoza dozwolonych źródeł
        # wpisany w package.json wywołałby żądanie mimo poprawnego pliku blokady. Dlatego oba pliki są sprawdzane przed npm.
        if not package_specs_downloadable(cwd/'package.json',hosts): return None
        if not lockfile_downloadable(lockfile,hosts):
            # Bez sieci w izolacji instalacja i tak by nie przeszła: lepszy od razu komunikat z nazwą hosta niż dwa limity czasu.
            foreign=[h for h in lockfile_foreign_hosts(lockfile) if h not in set(DEPENDENCY_HOSTS)|set(hosts)]
            if foreign: raise Blocked('zależności: plik blokady pobiera paczki z hostów spoza rejestru npm ('+', '.join(foreign[:5])+'); właściciel dopuszcza je w runtime.dependency_hosts')
            return None
        try: digest=hashlib.sha256(lockfile.read_bytes()+(cwd/'package.json').read_bytes()+sys.platform.encode()).hexdigest()[:32]
        except OSError: return None
        stage=self.cache_root/'node-deps'/digest
        if (stage/CACHE_COMPLETE).is_file() and ('USTALENIE' in (stage/CACHE_COMPLETE).read_text() or node_modules_match(lockfile,stage/'node_modules')):
            # Ustalenie z pobrania (np. konflikt w pliku blokady) dotyczy także przebiegów korzystających z gotowego katalogu.
            self.dependency_note=(stage/CACHE_COMPLETE).read_text().removeprefix('ok\n')
            return stage/'node_modules'
        try:
            if stage.exists(): shutil.rmtree(stage)
            (stage/'home').mkdir(parents=True)
            for name in ('package.json','package-lock.json'): shutil.copyfile(cwd/name,stage/name)
            environment={'PATH':self.env.get('PATH') or os.environ.get('PATH',''),'HOME':str(stage/'home'),'npm_config_cache':str(stage/'cache'),'CI':'1'}
            self.steps+=1; log=self.out/'logs'/f'{self.steps:03d}.log'
            argv=[str(npm),'ci','--ignore-scripts','--include=dev','--no-audit','--no-fund','--registry',NPM_REGISTRY]
            rc,output=self.executor.run(argv,stage,environment,self.budget.remaining(300))
            log.write_text('$ (pobranie zależności poza kopią projektu, bez skryptów paczek) '+' '.join(argv)+'\n'+output[-4000:]+'\nexit='+str(rc)+'\n')
            self.dependency_note='';other_lock=False
            if rc!=0 and 'ERESOLVE' in output and package_specs_downloadable(stage/'package.json',hosts):
                # npm ci pada na konflikcie zależności równorzędnych: plik blokady npm nie opisuje działającej instalacji.
                # Konflikt trafia do raportu jako ustalenie.
                self.steps+=1; log=self.out/'logs'/f'{self.steps:03d}.log'
                if (stage/'node_modules').exists(): shutil.rmtree(stage/'node_modules')
                # npm install --force trzyma wersje z pliku blokady i dokłada brakujące zależności równorzędne (zmienia tylko kopię pliku
                # w katalogu pobrania). Plik blokady po takiej instalacji przechodzi tę samą kontrolę źródeł co plik projektu.
                argv=[str(npm),'install','--force','--ignore-scripts','--include=dev','--no-audit','--no-fund','--registry',NPM_REGISTRY]
                rc,output=self.executor.run(argv,stage,environment,self.budget.remaining(300))
                log.write_text('$ (ponowienie po ERESOLVE, bez skryptów paczek) '+' '.join(argv)+'\n'+output[-4000:]+'\nexit='+str(rc)+'\n')
                # Wynik ponowienia z definicji różni się od package-lock.json projektu (dołożone paczki), więc nie jest z nim
                # porównywany; za to nowy plik blokady musi wskazywać wyłącznie dozwolone źródła i zgadzać się z dyskiem.
                other_lock=rc==0 and lockfile_downloadable(stage/'package-lock.json',hosts) and node_modules_match(stage/'package-lock.json',stage/'node_modules')
                if rc==0 and not other_lock:rc=1
                if rc==0: self.dependency_note='USTALENIE: npm ci na package-lock.json projektu kończy się ERESOLVE (konflikt zależności równorzędnych); paczki pobrane '+('przez npm install --force: wersje z pliku blokady plus brakujące zależności równorzędne')+'\n'
        except (OSError,subprocess.SubprocessError): return None
        if rc!=0 or not (other_lock or node_modules_match(lockfile,stage/'node_modules')): return None
        self.dependencies_from_other_lock=other_lock
        try: (stage/CACHE_COMPLETE).write_text('ok\n'+self.dependency_note)
        except OSError: return None
        return stage/'node_modules'

    def identity_tls(self, label='oidc', hosts=('127.0.0.1',)):
        """Private per-run TLS, shared by the existing emulator and Keycloak."""
        if label not in ('oidc','keycloak','app'):raise ValueError('invalid identity TLS label')
        if not isinstance(hosts,(list,tuple)) or not hosts or len(set(hosts))!=len(hosts) or any(host not in ('localhost','127.0.0.1','::1') for host in hosts):raise ValueError('invalid local TLS names')
        san=','.join(('DNS:' if host=='localhost' else 'IP:')+host for host in hosts)
        openssl=self.tools.get('openssl') or locate('openssl')
        if not openssl:raise Blocked('openssl missing for runtime identity TLS')
        directory=self.tmp/(label+'-'+secrets.token_hex(8));directory.mkdir(mode=0o700)
        cert=directory/'cert.pem';key=directory/'key.pem';public=directory/'public.der'
        self.command([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,
                      '-days','1','-subj','/CN='+hosts[0],'-addext','subjectAltName='+san])
        self.command([openssl,'pkey','-in',key,'-pubout','-outform','DER','-out',public])
        spki=base64.b64encode(hashlib.sha256(public.read_bytes()).digest()).decode() if public.exists() else None
        return dict(cert_path=cert,key_path=key,spki_sha256=spki)

    def prepare_https(self, settings, backend_port):
        """Private transport handle; plan policy and caller wiring are separate."""
        if settings is None: settings={}
        if not isinstance(settings,dict) or set(settings)-{'enabled','public_host'}:
            raise Blocked('invalid runtime HTTPS configuration')
        enabled=settings.get('enabled',False)
        if type(enabled) is not bool:raise Blocked('runtime HTTPS enabled must be boolean')
        if not enabled:return None
        host=settings.get('public_host','localhost')
        if host not in ('localhost','127.0.0.1'):raise Blocked('runtime HTTPS host must be local')
        if type(backend_port) is not int or not 1<=backend_port<=65535:raise Blocked('invalid backend port')
        public_port=self.port_factory()
        if type(public_port) is not int or not 1<=public_port<=65535 or public_port==backend_port:
            raise Blocked('runtime HTTPS public/backend ports must be distinct')
        previous=self.env
        self.env={key:previous[key] for key in ('PATH','HOME','CI') if key in previous}
        try:tls=self.identity_tls('app',hosts=(host,))
        finally:self.env=previous
        if not tls.get('spki_sha256'):raise Blocked('runtime HTTPS SPKI unavailable')
        # The private dict contains filesystem paths and must never be serialized.
        return dict(public_origin='https://'+host+':'+str(public_port),
                    backend_origin='http://127.0.0.1:'+str(backend_port),
                    public_port=public_port,backend_port=backend_port,tls=tls,process=None,
                    receipt=dict(status='not_checked',scope='local HTTPS front',
                                 limits=['localhost is not production cookie policy evidence',
                                         'WebSocket unsupported','login and cross-site SameSite not tested']))

    def apply_https_trust(self, transport, identity_tls=None):
        """Trust only certificates generated by this run, never target CA paths."""
        from helix_runtime_keycloak import _private_read
        materials=[transport['tls']]+([identity_tls] if identity_tls is not None else [])
        keys=[];certificates=[]
        for tls in materials:
            try:decoded=base64.b64decode(tls['spki_sha256'],validate=True)
            except (ValueError,TypeError):raise Blocked('invalid owned runtime TLS SPKI') from None
            if len(decoded)!=32:raise Blocked('invalid owned runtime TLS SPKI')
            certificates.append(_private_read(self.tmp,tls['cert_path']))
            if tls['spki_sha256'] not in keys:keys.append(tls['spki_sha256'])
        bundle=Path(transport['tls']['cert_path']).parent/'ca-bundle.pem'
        fd=os.open(bundle,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb',closefd=False) as stream:
                stream.write(b'\n'.join(certificates));stream.flush();os.fsync(stream.fileno())
        finally:os.close(fd)
        transport['ca_bundle']=bundle
        self.env.update(NODE_EXTRA_CA_CERTS=str(bundle),SSL_CERT_FILE=str(bundle),REQUESTS_CA_BUNDLE=str(bundle),
                        HELIX_RUNTIME_TLS_SPKI_LIST=','.join(keys))
        self.env.pop('NODE_TLS_REJECT_UNAUTHORIZED',None)
        transport['receipt']['trusted_key_count']=len(keys)

    def start_https(self, transport):
        """Launch the fixed-loopback proxy; readiness requires a separate probe."""
        self.resource_wait()
        now_ms=int(time.time()*1000)
        max_seconds=(9007199254740991-now_ms)/1000
        milliseconds=max(1,int(self.budget.remaining(max_seconds)*1000))
        cert=Path(transport['tls']['cert_path']).resolve();key=Path(transport['tls']['key_path']).resolve()
        config=cert.parent/'proxy.json'
        value=dict(schema_version=1,public_origin=transport['public_origin'],backend_origin=transport['backend_origin'],
                   cert_path=str(cert),key_path=str(key),deadline_unix_ms=min(9007199254740991,now_ms+milliseconds),
                   request_timeout_ms=min(30000,milliseconds))
        fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'w',closefd=False) as stream:
                json.dump(value,stream);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        finally:os.close(fd)
        holder={}
        def cleanup():
            if not holder:return
            try:self.executor.stop(holder['process'])
            except Exception:
                transport['receipt']['cleanup']='unknown';raise
            transport['receipt']['cleanup']='stopped'
            holder.clear()
        self.cleanup_actions.append(cleanup)
        argv=[self.tool('node'),HOME/'bin/runtime-https.cjs',config]
        safe={name:self.env[name] for name in ('PATH','HOME','CI') if name in self.env}
        self.note_tool(argv)
        log=self.out/'logs'/('https-'+str(transport['public_port'])+'.log')
        transport['receipt'].update(status='starting',log=str(log.relative_to(self.out)),cleanup='pending')
        proc=self.executor.spawn(argv,self.tmp,safe,log)
        holder['process']=proc;transport['process']=proc
        self.budget.remaining(.001)
        return proc

    def keycloak_entry(self,part):
        entries=[entry for entry in self.integration_plan['integrations'] if entry['provider']=='keycloak' and
                 entry['area']=='active' and (not entry['parts'] or part['path'] in entry['parts'])]
        if not entries:return None
        if len(entries)!=1 or not entries[0]['parts']:raise Blocked('Keycloak inventory binding is ambiguous; no fallback')
        return entries[0]

    def keycloak_contract(self,part,selected_plan,env_roles=None):
        from helix_runtime_identity import validate_env_roles
        entry=self.keycloak_entry(part)
        if entry is None:raise Blocked('Keycloak inventory binding missing; no fallback')
        if entry['strategy']['selected']!='container':raise Blocked('Keycloak requires container strategy; no fallback')
        if not isinstance(selected_plan,dict) or selected_plan.get('part')!=part['path'] or selected_plan.get('status')!='READY':
            raise Blocked('Keycloak identity plan incomplete; no fallback')
        try:roles=validate_env_roles(selected_plan.get('env_roles',{}) if env_roles is None else env_roles)
        except ValueError:raise Blocked('Keycloak environment role contract invalid; no fallback') from None
        values=set(roles.values())
        if 'client_id' not in values or not ('issuer' in values or {'idp_origin','realm'}<=values):
            raise Blocked('Keycloak environment role contract incomplete; no fallback')
        if any(row['name'] not in roles for row in selected_plan.get('env_bindings',[])):
            raise Blocked('Keycloak environment binding omitted by explicit contract; no fallback')
        if 'callback_uri' in values and len(selected_plan['client']['callback_paths'])!=1:
            raise Blocked('Keycloak callback mapping requires one exact path; no fallback')
        if selected_plan['client']['client_type']=='confidential' and 'client_secret' not in values:
            raise Blocked('Keycloak confidential client requires secret mapping; no fallback')
        return entry,roles

    def record_keycloak(self,part,raw,artifact=None):
        """Project a lifecycle receipt into the strict shared receipt contract."""
        from helix_environment import _observed_version
        entry=self.keycloak_entry(part)
        binding=dict(integration_id=entry['id'],plan_id=self.integration_plan['plan_id'],run_id=self.run_id)
        if not isinstance(raw,dict) or any(raw.get(key)!=value for key,value in binding.items()):
            raise Blocked('Keycloak lifecycle receipt binding mismatch')
        status={'ready':'ready','completed':'completed','blocked':'blocked','failed':'failed',
                'resource_paused':'incomplete','interrupted':'incomplete','starting':'not_run'}.get(raw.get('status'),'incomplete')
        cleanup=raw.get('cleanup',{})
        if isinstance(cleanup,dict) and cleanup.get('status') in ('refused','unknown'):status='incomplete'
        readiness=raw.get('readiness') if raw.get('readiness') in ('ready','failed') else 'unknown'
        logs=[value for value in raw.get('logs',[]) if isinstance(value,str) and re.fullmatch(r'logs/[A-Za-z0-9_.-]+',value)]
        if artifact is not None:
            candidate=Path(artifact)
            try:relative=candidate.relative_to(self.out).as_posix()
            except ValueError:raise Blocked('Keycloak receipt artifact outside output') from None
            if not re.fullmatch(r'helix-keycloak-[a-f0-9]{32}-status\.json',relative):raise Blocked('Keycloak receipt artifact invalid')
            logs.append(relative)
        summary_path='logs/keycloak-'+hashlib.sha256(part['path'].encode()).hexdigest()[:12]+'.json'
        logs.append(summary_path)
        normalized=dict(**binding,strategy='container',status=status,readiness=readiness,
                        actual_version=_observed_version(raw.get('actual_version')),logs=sorted(set(logs)),tested_routes=[])
        # The complete lifecycle artifact belongs to the adapter. This small
        # receipt also survives failures before a handle has been returned.
        summary=dict(normalized,cleanup_status=cleanup.get('status') if isinstance(cleanup,dict) and
                     cleanup.get('status') in ('removed','not_needed','refused','unknown') else 'pending',
                     login_status='NOT_RUN',coverage='readiness_only; login and routes not tested')
        fd,temporary=tempfile.mkstemp(prefix='.keycloak-',dir=self.out/'logs')
        try:
            with os.fdopen(fd,'w') as stream:json.dump(summary,stream,indent=2,sort_keys=True);stream.write('\n')
            os.replace(temporary,self.out/summary_path)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
        existing=next((receipt for receipt in self.integration_receipts if receipt['integration_id']==entry['id']),None)
        if existing is None:self.integration_receipts.append(normalized)
        else:existing.clear();existing.update(normalized)
        public=part.setdefault('keycloak',{})
        public.clear();public.update(summary)
        return normalized

    def start_planned_keycloak(self,part,selected_plan,env_roles=None):
        from helix_runtime_keycloak import private_material,start_keycloak,KeycloakBlocked
        entry,roles=self.keycloak_contract(part,selected_plan,env_roles)
        origin=self.active_transport['public_origin'] if self.active_transport else 'http://127.0.0.1:'+self.env['PORT']
        try:material=private_material(selected_plan,origin)
        except ValueError:raise Blocked('Keycloak identity plan or private material invalid; no fallback') from None
        secrets_used=list(material['user_passwords'].values())+[material.get('client_secret')]
        self.private_values=getattr(self,'private_values',set())|{value for value in secrets_used if isinstance(value,str) and value}
        binding=dict(integration_id=entry['id'],plan_id=self.integration_plan['plan_id'],run_id=self.run_id)
        holder={}
        # Adapter registers close after this callback, so reverse cleanup closes
        # its resource first and only then publishes its final receipt.
        def refresh():
            if holder:self.record_keycloak(part,holder['handle'].receipt(),holder['handle'].artifact)
        self.cleanup_actions.append(refresh)
        try:
            tls=self.identity_tls('keycloak');self.current_identity_tls=tls
            original_ports=self.port_factory
            def identity_port():
                value=original_ports()
                if self.active_transport and value in (self.active_transport['public_port'],self.active_transport['backend_port']):
                    raise Blocked('identity port conflicts with fixed application transport')
                return value
            self.port_factory=identity_port
            try:handle=start_keycloak(self,selected_plan,material,tls,binding=binding)
            finally:self.port_factory=original_ports
        except (KeycloakBlocked,ResourcePaused,Blocked,OSError,ValueError) as error:
            receipt=getattr(error,'receipt',None) or dict(**binding,status='resource_paused' if isinstance(error,ResourcePaused) else 'blocked',
                        readiness='unknown',actual_version=None,logs=[],tested_routes=[],cleanup=dict(status='not_needed'))
            self.record_keycloak(part,receipt,getattr(error,'artifact',None))
            if isinstance(error,ResourcePaused):raise
            raise Blocked(str(error) if isinstance(error,(KeycloakBlocked,Blocked)) else 'Keycloak preparation failed ('+type(error).__name__+')') from None
        holder['handle']=handle
        self.env.update(handle.environment)
        self.network_connect_ports.add(urlparse(handle.issuer).port or 443)
        self.env['HELIX_RUNTIME_IDENTITY_MODE']='keycloak-readiness'
        values=dict(issuer=handle.issuer,idp_origin=handle.issuer.split('/realms/',1)[0],realm=material['realm'],
                    app_origin=origin,client_id=selected_plan['client']['client_id'],client_secret=material.get('client_secret',''),
                    callback_uri=origin+selected_plan['client']['callback_paths'][0])
        self.env.update({name:values[role] for name,role in roles.items()})
        self.record_keycloak(part,handle.receipt(),handle.artifact)
        records=getattr(self,'execution_tools',{});self.execution_tools=records
        records['keycloak']=dict(status='recorded',used=True,version=handle.receipt()['actual_version'],
                                 calls=1+records.get('keycloak',{}).get('calls',0),evidence_kind='adapter_version_command')
        private=getattr(self,'private_keycloak',{});self.private_keycloak=private
        private[part['path']]=dict(handle=handle,material=material)
        return handle

    def oidc(self,part):
        if not self.oidc_stub: return
        names=[e['name'] for e in part.get('env',[]) if re.search(r'ISSUER|OIDC|KEYCLOAK|AUTH0|OKTA|COGNITO|AUTH_URL|REALM|DISCOVERY|(?:^|_)(?:KC|IDP)_(?:URL|HOST)|CLERK.*(?:URL|DOMAIN)$',e['name'])]
        names=sorted(set(names)|set(part.get('oidc_dependencies',[])))
        roles={name:url_role(name) for name in sorted(set(names)|{e['name'] for e in part.get('env',[]) if url_role(e['name'])=='app-url'}) if url_role(name)}
        part['url_roles']=roles
        if not names: return
        openssl=self.tools.get('openssl') or locate('openssl')
        if not openssl:
            part['oidc_stub']=dict(status='unavailable',reason='openssl missing'); return
        tls=self.identity_tls('oidc');self.current_identity_tls=tls
        cert=tls['cert_path'];key=tls['key_path'];port=self.port_factory()
        if self.active_transport and port in (self.active_transport['public_port'],self.active_transport['backend_port']):
            raise Blocked('OIDC port conflicts with fixed application transport')
        if tls['spki_sha256']:self.env['HELIX_RUNTIME_OIDC_SPKI']=tls['spki_sha256']
        self.resource_wait()
        self.note_tool([sys.executable])
        proc=self.executor.spawn([sys.executable,HOME/'bin/runtime-oidc.py',str(port),str(cert),str(key),openssl],self.tmp,self.process_environment(self.env),self.out/'logs/oidc.log')
        self.cleanup_actions.append(lambda p=proc:self.executor.stop(p))
        issuer='https://127.0.0.1:'+str(port)
        self.network_connect_ports.add(port)
        if hasattr(self.executor,'oidc_ready'): self.executor.oidc_ready(issuer,cert,self.budget.remaining(10))
        self.env['HELIX_RUNTIME_OIDC_ISSUER']=issuer
        for name in names:
            if classification(name)=='random-secret': continue
            if name in RESERVED_ENV: continue
            role=roles[name]
            self.env[name]=app_url(name,self.env['PORT'],self.env.get(name,''),self.active_transport['public_origin'] if self.active_transport else None) if role=='app-url' else 'synthetic' if role=='idp-path' else issuer
        self.env.update(NODE_EXTRA_CA_CERTS=str(cert),SSL_CERT_FILE=str(cert),REQUESTS_CA_BUNDLE=str(cert))
        self.refresh_sink_input()
        preload=HOME/'bin/runtime-fetch.cjs'
        self.add_owned_preload(preload)
        probe="fetch(process.argv[1]).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
        try:
            self.command([self.tools.get('node') or 'node','-e',probe,issuer+'/.well-known/openid-configuration'],maximum=10)
            tls_status='VERIFIED: native fetch accepted stub CA with NODE_EXTRA_CA_CERTS'
        except Blocked as error:
            tls_status='FAILED: native fetch CA probe: '+str(error)
            part['oidc_stub']=dict(status='unavailable',reason=tls_status)
            raise Blocked(tls_status)
        part['oidc_stub']=dict(browser_tls=dict(spki_sha256=self.env.get('HELIX_RUNTIME_OIDC_SPKI'),playwright='launch args',lighthouse='--chrome-flags',scope='stub public key only'),tls_probe=tls_status,status='synthetic',issuer=issuer,variable_roles=roles,variables=names,auth_bypass_variables=part.get('auth_bypass_variables',[]),
            capabilities=['discovery','authorization_code','signed_id_token','userinfo'],provider_fidelity='UNKNOWN',
            coverage='Emulator capabilities only; application session and authorization NOT_RUN',
            reason_code='NO_EXPLICIT_IDENTITY_POLICY',session_coverage='NOT_RUN',authorization_coverage='NOT_RUN')

    def select_schema(self,part):
        self.require_database_network()
        selected=[]
        for group in part.get('schema_strategies',[]):
            if group['trial_required']:
                results=[]; original=self.db; original_env=dict(self.env)
                saved_applied,saved_notes=self.applied,self.migration_notes
                trial_end=time.monotonic()+min(90,self.budget.remaining(90))
                try:
                    self.trial_deadline=trial_end
                    for candidate in group['candidates']:
                        skipped=next((m.get('skip_reason') for m in candidate['migrations'] if m.get('skip_reason')),None)
                        if skipped:
                            results.append(dict(strategy=candidate['strategy'],status='skipped',reason=skipped,selected=len(candidate['migrations']),failed=1,applied=0,incomplete=True,errors=[],category='adoption',first_error=skipped,seconds=0,commands=[migration_command(m) for m in candidate['migrations']]))
                            continue
                        if time.monotonic()>=trial_end:
                            results.append(dict(strategy=candidate['strategy'],selected=len(candidate['migrations']),failed=len(candidate['migrations']),applied=0,incomplete=True,errors=[],status='failed',category='budget',first_error='schema candidate trial budget exhausted',seconds=0,commands=[migration_command(m) for m in candidate['migrations']]))
                            continue
                        name='helix_trial_'+secrets.token_hex(4)
                        self.command([self.tool('psql'),original,'-X','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE '+name])
                        self.db=original.rsplit('/',1)[0]+'/'+name
                        trial_env=dummy_env(part,self.db,int(self.env.get('PORT','3000')),self.active_transport['public_origin'] if self.active_transport else None)
                        self.env.update({k:v for k,v in trial_env.items() if classification(k)=='database'})
                        self.applied=set(); self.migration_notes=[]; begin=self.steps; trial_started=time.monotonic()
                        try:
                            try:
                                self.migrate(dict(migrations=candidate['migrations']),seed=False,deadline=trial_end,extension_scope='trial',extension_part=part['path'],extension_candidate=candidate['strategy'])
                            except Blocked as error:
                                for migration in candidate['migrations']:
                                    if migration['path'] not in self.applied:
                                        self.migration_notes.append(dict(path=migration['path'],reason=str(error)))
                            results.append(dict(strategy=candidate['strategy'],selected=len(candidate['migrations']),logs=[f'logs/{i:03d}.log' for i in range(begin+1,self.steps+1)],count_unit='runner invocations' if any(m['kind']=='runner' for m in candidate['migrations']) else 'migration files',
                                                failed=len(self.migration_notes),applied=sum(m['path'] in self.applied and not any(n['path']==m['path'] for n in self.migration_notes) for m in candidate['migrations']),
                                                incomplete=any(m['path'] not in self.applied for m in candidate['migrations']),errors=error_summary(self.migration_notes),seconds=round(time.monotonic()-trial_started,3),commands=[migration_command(m) for m in candidate['migrations']],category=error_summary(self.migration_notes)[0]['category'] if self.migration_notes else None,first_error=first_error(self.migration_notes[0]['reason']) if self.migration_notes else None,status='failed' if self.migration_notes else 'applied'))
                            try:
                                count=self.command([self.tool('psql'),self.db,'-X','-At','-c',"SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','v','m')) + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema'))"])
                                results[-1]['objects']=int(count.strip())
                            except (Blocked,ValueError): results[-1]['objects']=0
                            for migration in candidate['migrations']:
                                if migration['kind']!='runner': continue
                                suggestions=runner_suggestions(migration,{n.get('log') or migration['path']:n['reason'] for n in self.migration_notes})
                                for suggestion in reversed(suggestions):
                                    if any(runner_key(suggestion)==runner_key(m) for c in group['candidates'] for m in c['migrations'] if m['kind']=='runner'): continue
                                    addition=dict(strategy='project-runner:'+suggestion['path']+':suggestion-'+str(len(group['candidates'])),migrations=[suggestion])
                                    group['candidates'].insert(group['candidates'].index(candidate)+1,addition)
                        finally:
                            self.db=original; self.env=dict(original_env)
                            self.command([self.tool('psql'),original,'-X','-v','ON_ERROR_STOP=1','-c','DROP DATABASE IF EXISTS '+name+' WITH (FORCE)'],cleanup=True)
                finally:
                    self.trial_deadline=None
                    self.db=original; self.applied,self.migration_notes=saved_applied,saved_notes
                    self.env=original_env
                eligible=[r for r in results if r['status']!='skipped']
                if not eligible: raise Blocked('all runner variants require forbidden baseline adoption')
                winner=migration_winner(eligible,group['strategy'])
                for candidate in group['candidates']:
                    result=next(r for r in results if r['strategy']==candidate['strategy'])
                    candidate.update({k:result[k] for k in ('status','applied','failed','first_error')})
                group.update(strategy=winner['strategy'],results=results,tag='ASSUMPTION',network_isolation='See runtime-report.json/network_isolation for current process admission and proof scope',selection_reason='maximum catalog objects, then applied files; tie: project recommended strategy',selection_counts={r['strategy']:dict(objects=r.get('objects',0),files=r.get('applied',0)) for r in results})
            selected.extend(next(c['migrations'] for c in group['candidates'] if c['strategy']==group['strategy']))
        if part.get('schema_strategies'):
            part['migrations']=[m for m in part['migrations'] if m['kind']!='sql' and not any(c['migrations'][0].get('kind')=='runner' for g in part['schema_strategies'] for c in g['candidates'])]+selected
            part['schema_selection'].update(rule='ASSUMPTION: selected database plan',selected=[dict(root=g['root'],strategy=g['strategy'],count=len(next(c['migrations'] for c in g['candidates'] if c['strategy']==g['strategy']))) for g in part['schema_strategies']],
                                            count=len(part['migrations']),examples=[m['path'] for m in part['migrations'][:5]])

    def migrate(self,spec,seed=True,_retry=False,deadline=None,extension_scope='base',extension_part=None,extension_candidate=None):
        if deadline is not None and time.monotonic()>=deadline:raise Blocked('schema candidate trial budget exhausted')
        # Lokalny stos Supabase zastosował migracje sam (z rejestrem błędów); ścieżka zwykłego PostgreSQL tu nie biegnie.
        if getattr(self,'supabase_stack',None):return
        self.extension_preflight(spec,scope=extension_scope,part=extension_part if extension_part is not None else getattr(self,'active_part',None),candidate=extension_candidate)
        for migration in spec['migrations']:
            if migration['path'] in self.applied: continue
            if deadline is not None and time.monotonic()>=deadline: raise Blocked('schema candidate trial budget exhausted')
            if migration.get('skip_reason'): raise Blocked(migration['skip_reason'])
            kind,path=migration['kind'],self.work/migration['path']
            cwd=path.parent
            begin=self.steps
            try:
                if kind=='runner':
                    argv=[str(a).replace('{database}',self.db).replace('{jdbc_database}','jdbc:postgresql://'+urlparse(self.db).netloc.split('@')[-1]+urlparse(self.db).path) for a in migration['argv']]
                    previous=dict(self.env)
                    try:
                        self.env.update(migration.get('env',{}))
                        output=self.project_command(argv,self.work/migration['cwd'],maximum=60,phase='migration')
                    finally: self.env=previous
                    if re.search(r'(?im)(?:^|:\s*)(?:ERROR|FATAL|Traceback)\b',output):
                        raise Blocked(first_error(output))
                    tables=self.command([self.tool('psql'),self.db,'-X','-At','-v','ON_ERROR_STOP=1','-c',"SELECT schemaname||'.'||tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')"])
                    if not tables.strip(): raise Blocked('project runner completed without creating application tables')
                elif kind=='sql':
                    sql=up_sql(read(path))
                    if re.search(r'(?im)^\s*\\(?:connect|c|!|include|i|ir|copy)\b|\b(?:dblink|postgres_fdw|COPY\s+.*?PROGRAM)\b',sql):
                        raise Blocked('SQL migration requests external connection or command: '+migration['path'])
                    if personal_emails(sql):
                        raise Blocked('migration may contain personal data: '+migration['path'])
                    normalized=transactional_sql(sql)
                    if normalized!=read(path):
                        path=self.tmp/'transactional'/migration['path']
                        path.parent.mkdir(parents=True,exist_ok=True); path.write_text(normalized)
                    self.project_command([self.tool('psql'),self.db,'-X','-v','ON_ERROR_STOP=1','--single-transaction','-f',path],phase='migration')
                elif kind=='prisma': self.project_command(['npx','--no-install','prisma','migrate','deploy','--schema',path],cwd,phase='migration')
                elif kind=='drizzle': self.project_command(['npx','--no-install','drizzle-kit','migrate','--config',path],cwd,phase='migration')
                elif kind=='knex': self.project_command(['npx','--no-install','knex','migrate:latest','--knexfile',path],cwd,phase='migration')
                elif kind=='alembic': self.project_command(['alembic','-c',path,'upgrade','head'],cwd,phase='migration')
                elif kind=='node-pg-migrate': self.project_command(['npx','--no-install','node-pg-migrate','up','--database-url-var','DATABASE_URL'],cwd,phase='migration')
                elif kind=='sqitch': self.project_command(['sqitch','deploy','--target',self.db],cwd,phase='migration')
                elif kind=='django': self.project_command(['python',path,'migrate','--noinput'],cwd,phase='migration')
            except (Blocked,OSError,subprocess.TimeoutExpired) as error:
                log=getattr(self,'last_log','') if self.steps>begin else ''
                output=(self.out/log).read_text(errors='replace') if log and (self.out/log).is_file() else str(error)
                self.migration_notes.append(dict(path=migration['path'],status='FAIL',line=int((re.search(r':(\d+):\s*(?:ERROR|FATAL)',output) or [None,1])[1]),duplicate=bool(re.search(r'(?:ERROR|FATAL):[^\n]*(?:already exists|duplicate)',output,re.I)),reason=output.strip() or str(error),log=log))
            self.applied.add(migration['path'])
        if not _retry:
            failed={n['path'] for n in self.migration_notes}
            retry=[m for m in spec['migrations'] if m['kind']=='sql' and m['path'] in failed]
            if retry:
                paths={m['path'] for m in retry}
                self.migration_notes=[n for n in self.migration_notes if n['path'] not in paths]
                self.applied.difference_update(paths)
                self.migrate(dict(spec,migrations=retry),seed=False,_retry=True,deadline=deadline,extension_scope=extension_scope,extension_part=extension_part,extension_candidate=extension_candidate)
        if not seed: return
        for seed in spec.get('seeds',[]):
            path=self.work/seed['path']
            if seed['status']=='SYNTHETIC' and seed['path'] not in self.applied and synthetic_sql(read(path)):
                self.project_command([self.tool('psql'),self.db,'-X','-v','ON_ERROR_STOP=1','--single-transaction','-f',path],phase='migration')
                self.applied.add(seed['path'])
        # Generate one synthetic row per table where defaults permit it. Unknown required
        # columns remain empty rather than importing an untrusted seed or inventing PII.
        seed=(HOME/'templates/runtime-seed.sql').read_text()
        self.command([self.tool('psql'),self.db,'-X','-v','ON_ERROR_STOP=1','-c',seed])
        from helix_runtime_adapters import settings_sql
        settings=settings_sql(self.config)
        if settings:self.command([self.tool('psql'),self.db,'-X','-v','ON_ERROR_STOP=1','--single-transaction','-c',settings])
    def setup_commands(self,part):
        """Polecenia przygotowujące zadeklarowane przez właściciela (runtime.setup_commands): własne skrypty projektu, które tworzą
        dane startowe (role, uprawnienia, ustawienia). Idą w izolacji, po migracjach, z dostępem tylko do jednorazowej bazy."""
        declared=self.config.get('runtime',{}).get('setup_commands',[]) if isinstance(getattr(self,'config',None),dict) else []
        if not isinstance(declared,list) or len(declared)>10:raise Blocked('runtime.setup_commands: wymagana lista do 10 poleceń')
        done=[]
        for row in declared:
            argv=row.get('argv') if isinstance(row,dict) else None
            if (not isinstance(row.get('part'),str) or not isinstance(argv,list) or not 1<=len(argv)<=12 or not all(isinstance(item,str) and 0<len(item)<=300 for item in argv)
                    or argv[0] not in ('python','python3','node','npm','pnpm','yarn')):
                raise Blocked('runtime.setup_commands: wymagane part oraz argv zaczynające się od python, node, npm, pnpm albo yarn')
            if row['part']!=part['path']:continue
            self.project_command(argv,self.work/part['path'],maximum=240,phase='migration')
            done.append(' '.join(argv))
        return done

    def worker_tests(self,part,base_env,log):
        """Własne testy części worker w izolacji, bez sieci poza rejestrem paczek przy instalacji. Demon workera nie jest uruchamiany."""
        cwd=self.work/part['path'];saved=self.env
        tests=sorted(path for path in cwd.rglob('test_*.py') if '.venv' not in path.parts and 'node_modules' not in path.parts)[:200]
        if not tests:
            log.write_text('worker: brak testów (test_*.py) w tej części; nic do uruchomienia\n')
            return 'SKIPPED','no tests (test_*.py) in the worker part'
        try:
            self.env=dict(base_env)
            self.install(part)
            # Sprawdzenie, czy jest pytest, też wykonuje kod zainstalowanych paczek: idzie w izolacji jak wszystko inne.
            try:self.project_command(['python','-c','import pytest'],cwd,maximum=30,phase='build');has_pytest=True
            except Blocked:has_pytest=False
            argv=['python','-m','pytest','-q','-x','--no-header','-p','no:cacheprovider'] if has_pytest else ['python','-m','unittest','discover','-p','test_*.py']
            try:
                output=str(self.project_command(argv,cwd,maximum=300,phase='build'))
                log.write_text(self.redact_private('$ '+' '.join(argv)+'\n'+output[-6000:]+'\n'))
                # Zaliczenie wymaga dowodu, że testy się wykonały: liczba z podsumowania runnera, nie liczba plików.
                match=re.search(r'(\d+) passed',output) if has_pytest else re.search(r'Ran (\d+) tests?',output)
                executed=int(match[1]) if match else 0
                # unittest wlicza testy pominięte do „Ran N tests”: wykonane to te, które nie zostały pominięte
                skipped=re.search(r'skipped=(\d+)',output)
                if not has_pytest and skipped:executed=max(0,executed-int(skipped[1]))
                if not executed:
                    return 'BLOCKED','no tests executed by '+('pytest' if has_pytest else 'unittest (pytest is not installed; pytest-style tests are not discovered)')
                return 'PASS',str(executed)+' tests executed by '+('pytest' if has_pytest else 'unittest')
            except Blocked as error:
                # Kod wyjścia 5 to udokumentowany wynik „nie zebrano żadnego testu” (pytest i unittest), nie porażka testów. Pliki test_*.py
                # bywają zwykłymi skryptami z asercjami; Helix uruchamia je wprost tylko wtedy, gdy właściciel je wskazał
                # (runtime.worker_scripts), bo sam kod wyjścia 0 nieznanego pliku nie dowodzi, że cokolwiek sprawdzono.
                if re.match(r'exit 5\b',str(error)):
                    declared=[name for name in ((self.config.get('runtime') or {}).get('worker_scripts') or [])
                              if isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_./-]{1,200}\.py',name) and '..' not in Path(name).parts and (cwd/name).is_file()][:20]
                    if not declared:
                        log.write_text(self.redact_private('$ '+' '.join(argv)+'\n'+str(error)[-2000:]+'\n'))
                        return 'BLOCKED','no test cases collected; if the test files are plain scripts, declare them in runtime.worker_scripts'
                    lines=[];failed=[]
                    for name in declared:
                        try:self.project_command(['python',name],cwd,maximum=120,phase='build');lines.append('$ python '+name+'\nexit 0')
                        except Blocked as broken:failed.append(name);lines.append('$ python '+name+'\n'+str(broken)[-1500:])
                    log.write_text(self.redact_private('\n'.join(lines)+'\n'))
                    if failed:return 'FAIL',str(len(failed))+' of '+str(len(declared))+' declared test scripts failed: '+', '.join(failed[:5])
                    return 'PASS',str(len(declared))+' owner-declared test scripts executed; exit code 0'
                log.write_text(self.redact_private('$ '+' '.join(argv)+'\n'+str(error)[-6000:]+'\n'))
                return 'FAIL',str(error)[-400:]
        except (Blocked,OSError,subprocess.SubprocessError) as error:
            log.write_text(self.redact_private('worker: instalacja zależności nie powiodła się\n'+str(error)[-4000:]+'\n'))
            return 'BLOCKED','dependency install failed: '+str(error)[-300:]
        finally:self.env=saved

    def start_backend(self,backend,port,public_origin,spec,base_env,index):
        """Zaplecze frontendu (osobna część API): instalacja, migracje na tej samej bazie i start na własnym porcie, zanim ruszy frontend."""
        saved=self.env
        try:
            backend_spec=dict(spec,env=backend.get('env',spec['env']),bootstrap_variables=backend.get('bootstrap_variables',[]))
            self.env=dict(dummy_env(backend_spec,self.db,port,public_origin));self.env.update(base_env)
            self.env['PATH']=saved.get('PATH',self.env.get('PATH',os.defpath))
            self.select_schema(backend)
            self.install(backend)
            self.migrate(dict(spec,migrations=backend['migrations'],seeds=backend['seeds']))
            self.setup_commands(backend)
            argv=[str(x).replace('{port}',str(port)) for x in backend['start']]
            log=self.out/'logs'/('backend-'+str(index)+'.log')
            private_dir=self.tmp/'private-startup';private_dir.mkdir(mode=0o700,exist_ok=True)
            raw_log=private_dir/log.name
            fd=os.open(raw_log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
            self.private_logs[log]=raw_log
            self.note_tool(argv)
            proc=self.project_spawn(argv,self.work/backend['path'],self.env,raw_log,phase='application')
            self.cleanup_actions.append(lambda p=proc:self.executor.stop(p))
            deadline=time.monotonic()+self.budget.remaining(60)
            while True:
                # port_ready zwraca bez wyniku, gdy port odpowiada, a po upływie czasu zgłasza błąd
                try:self.executor.port_ready(port,1);break
                except Blocked:
                    if hasattr(proc,'poll') and proc.poll() is not None:
                        raise Blocked('backend exited during startup: '+first_error(self.startup_text(log))) from None
                    if time.monotonic()>deadline:raise Blocked('backend did not open its port; startup log '+str(log.relative_to(self.out))) from None
        finally:self.env=saved

    def run_scenarios(self,part,url,screen,index):
        """Scenariusze właściciela (runtime.scenarios): zapis i formularz naprawdę wykonane w jednorazowej kopii oraz wejście
        tam, gdzie aplikacja ma własne logowanie. Sesja zapisana przez scenariusz służy tylko przeglądowi tras o wskazanym początku."""
        declared=self.declared_scenarios(part)
        if not declared:return dict(status='NOT_DECLARED',scenarios=[])
        if not self.tools.get('node'):return dict(status='BLOCKED',reason='missing Node.js',scenarios=[])
        out=self.out/'visual'/str(index)/'scenarios';out.mkdir(parents=True,exist_ok=True)
        # Pliki sesji scenariuszy są znane z góry (nazwa z identyfikatora): sprzątanie nie zależy od tego, czy scenariusze doszły do końca.
        named={row['id']:self.project_temporary()/('scenario-'+row['id']+'.json') for row in declared if isinstance(row.get('id'),str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}',row['id'])}
        self.scenario_files=list(named.values())
        for path in self.scenario_files:path.unlink(missing_ok=True)
        rows=[];missing=[]
        # Scenariusze idą po kolei, każdy osobnym wywołaniem: między nimi właściciel może wykonać krok w jednorazowej bazie (after_sql),
        # np. zatwierdzić konto założone poprzednim scenariuszem, tak jak zrobiłby to administrator.
        for row in declared:
            statements=row.get('after_sql',[])
            if not isinstance(statements,list) or len(statements)>10 or not all(isinstance(q,str) and 0<len(q)<=2000 for q in statements):
                raise Blocked('runtime.scenarios.after_sql: wymagana lista do 10 poleceń SQL')
            done=self.scenario(part,url,screen,out,row)
            if not done:missing.append(row.get('id'));continue
            rows.extend(done)
            if done[0].get('status')=='PASS':
                for statement in statements:
                    self.command([self.tool('psql'),self.db,'-X','-q','-v','ON_ERROR_STOP=1','-c',statement])
                done[0]['after_sql']=len(statements)
        (out/'scenarios.json').write_text(json.dumps(dict(scenarios=rows),indent=2)+'\n')
        # Sesję dostaje tylko trasa o początku zadeklarowanym w konfiguracji, i tylko po scenariuszu zakończonym sukcesem z zapisaną sesją.
        saved={row['id'] for row in rows if row.get('status')=='PASS' and row.get('session_saved') is True and row.get('id') in named and named[row['id']].is_file()}
        prefixes={row['id']:row['save_session'].get('routes_prefix') for row in declared if isinstance(row.get('save_session'),dict) and row.get('id') in named}
        self.scenario_sessions=[(prefixes[name],named[name]) for name in saved if prefixes.get(name)]
        # Scenariusz logowania aplikacji z własnym logowaniem może oddać sesję wszystkim sprawdzeniom (as_screen_session), gdy nie ma roli z Keycloaka.
        default=next((row['id'] for row in declared if isinstance(row.get('save_session'),dict) and row['save_session'].get('as_screen_session') is True and row.get('id') in saved),None)
        self.scenario_screen=named[default] if default and not screen else None
        return dict(status='PASS' if rows and not missing and all(row['status']=='PASS' for row in rows) else 'FAIL',scenarios=rows,not_run=missing,
                    screen_session='scenario '+default if self.scenario_screen else None)

    def declared_scenarios(self,part):
        """Scenariusze tej części. Scenariusz bez wskazanej części klika po ekranach, więc nie dotyczy części, która jest samym API."""
        return [row for row in (self.config.get('runtime',{}).get('scenarios') or []) if isinstance(row,dict)
                and (row['part']==part['path'] if 'part' in row else not part.get('api_only'))]

    def scenario(self,part,url,screen,out,row):
        """Jeden scenariusz jednym wywołaniem; zwraca jego wynik z pliku scenarios.json."""
        (out/'scenarios.json').unlink(missing_ok=True)
        private=self.project_temporary()/'scenarios-input.json';private.unlink(missing_ok=True)
        try:
            with os.fdopen(os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as handle:
                json.dump(dict(origin=f'{urlparse(url).scheme}://{urlparse(url).netloc}',out=str(out),session_dir=str(self.project_temporary()),
                               storage_state=str(screen['path']) if screen else None,
                               scenarios=[{key:value for key,value in row.items() if key not in ('part','after_sql','renewable')}]),handle)
            try:self.measurement_command([self.tool('node'),str(HOME/'scripts/scenarios.mjs'),str(private)],self.work/part['path'],maximum=240)
            except Blocked:
                if not (out/'scenarios.json').is_file():raise
        finally:private.unlink(missing_ok=True)
        return json.loads((out/'scenarios.json').read_text())['scenarios']

    def renew_sessions(self,part,url,screen,index,route):
        """Ponowne logowanie, gdy sesja aplikacji wygasła w trakcie przeglądu (token na kilkadziesiąt minut). Powtarzany jest wyłącznie
        scenariusz, którego sesji używała ta trasa, i tylko gdy właściciel oznaczył go jako powtarzalny (renewable: true): scenariusz
        może zapisywać dane, więc Helix nie powtarza go z własnej decyzji. Kroki w bazie (after_sql) nie są powtarzane."""
        used=self.route_session(route,self.screen_file(part))
        row=next((row for row in self.declared_scenarios(part) if row.get('renewable') is True and isinstance(row.get('save_session'),dict)
                  and self.project_temporary()/('scenario-'+str(row.get('id'))+'.json')==used),None)
        if row is None or used not in getattr(self,'scenario_files',[]) or not used.is_file():return False
        out=self.out/'visual'/str(index)/'scenarios'/'renew';out.mkdir(parents=True,exist_ok=True)
        previous=used.read_bytes();used.unlink()
        try:done=self.scenario(part,url,screen,out,row)
        except (Blocked,OSError,ValueError,KeyError,subprocess.SubprocessError):done=[]
        if done and done[0].get('status')=='PASS' and used.is_file():return True
        used.unlink(missing_ok=True)
        with os.fdopen(os.open(used,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as handle:handle.write(previous)
        return False

    def helix_cli(self):
        """Kontekst CLI Helixa (plan ról, dostępność modeli, wysyłka) dla kroków przebiegu, które pytają model."""
        if getattr(self,'_helix_cli',None) is None:
            import importlib.machinery, importlib.util
            loader=importlib.machinery.SourceFileLoader('helix_cli_for_runtime',str(HOME/'bin'/'helix'))
            module=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader))
            sys.modules[loader.name]=module; loader.exec_module(module)
            self._helix_cli=(module,module.Ctx(self.project,state_dir=self.cli.get('state_dir')))
        return self._helix_cli

    def seed_supabase(self,part):
        """Puste tabele, które czyta kod aplikacji, dostają dane syntetyczne napisane przez model (helix_runtime_seed)."""
        declared=((getattr(self,'config',None) or {}).get('runtime',{}).get('synthetic_data') or {})
        if declared.get('enabled') is False or (declared.get('enabled') is None and self.executor.__class__ is not Executor):
            return dict(status='SKIPPED',reason='wyłączone (runtime.synthetic_data.enabled=false) albo przebieg testowy')
        import helix_runtime_seed
        stack=self.supabase_stack; docker=self.tool('docker')
        psql=[docker,'exec',stack['database'],'psql','-U','supabase_admin','-d','postgres','-v','ON_ERROR_STOP=1']
        def sql(query):return self.command(psql+['-At','-F',helix_runtime_seed.SEP,'-c',query],maximum=300)
        def execute(statement):
            # Ten sam wykonawca co reszta przebiegu: sprawdzone lokalne gniazdo Dockera, budżet czasu, dziennik kroku.
            try:self.command(psql+['-q','-c','begin; set local session_replication_role = replica; '+statement+'; commit;'],maximum=300);return None
            except Blocked as error:return str(error)[:500]
        user=((stack.get('session') or {}).get('user') or {}).get('id') or ''
        provider=declared.get('provider') or 'gemini-flash'   # pomiar 15.11: 17 s na partię (Claude: 8 min)
        def ask(prompt):
            H,ctx=self.helix_cli()
            text,_=H.ask(ctx,provider,prompt,need_json=True,out_dir=self.out/'logs',substitute=True)
            return text
        try:
            report=helix_runtime_seed.seed(sql,execute,ask,self.work/part['path'],user,limit=declared.get('max_tables'),only=declared.get('tables'),log=lambda m:print('[helix runtime] '+m,file=sys.stderr))
        except Exception as error:   # błąd danych syntetycznych nie przerywa przebiegu; raport mówi, czego brakuje
            return dict(status='ERROR',reason=type(error).__name__+': '+str(error)[:300])
        (self.out/'logs'/'synthetic-data.json').write_text(json.dumps(report,ensure_ascii=False,indent=1))
        report['log']='logs/synthetic-data.json'
        return report

    def stub_functions(self,part):
        """Odpowiedzi funkcji serwerowych dla przeglądarki (helix_function_stubs): funkcje nie startują, bo wołają systemy
        zewnętrzne, więc model pisze ich przykładową poprawną odpowiedź z kodu funkcji i miejsc wywołania. Projekt B: bez tego
        20 ze 128 ekranów pokazywało błąd pobierania danych. Plik odpowiedzi czyta ux.cjs, runtime-browser.cjs i ui-audit.mjs."""
        runtime_cfg=(getattr(self,'config',None) or {}).get('runtime',{})
        declared=runtime_cfg.get('function_stubs') or {}
        if declared.get('enabled') is False or (declared.get('enabled') is None and self.executor.__class__ is not Executor):
            return dict(status='SKIPPED',reason='wyłączone (runtime.function_stubs.enabled=false) albo przebieg testowy')
        import helix_function_stubs
        provider=declared.get('provider') or (runtime_cfg.get('synthetic_data') or {}).get('provider') or 'gemini-flash'
        def ask(prompt):
            H,ctx=self.helix_cli()
            text,_=H.ask(ctx,provider,prompt,need_json=True,out_dir=self.out/'logs',substitute=True)
            return text
        cache=Path(self.cli.get('state_dir') or self.out)/'cache'/'function-stubs'
        try:stubs,report=helix_function_stubs.generate(self.work/part['path'],ask,cache,log=lambda m:print('[helix runtime] '+m,file=sys.stderr))
        except Exception as error:   # brak odpowiedzi funkcji nie przerywa przebiegu; ekrany pokażą błąd, a raport stan zrzutu
            return dict(status='ERROR',reason=type(error).__name__+': '+str(error)[:300])
        if stubs:
            path=self.project_temporary()/'function-stubs.json';path.write_text(json.dumps(stubs,ensure_ascii=False))
            self.env['HELIX_FUNCTION_STUBS']=str(path);os.environ['HELIX_FUNCTION_STUBS']=str(path)   # ux.cjs dziedziczy środowisko Helixa
            (self.out/'logs'/'function-stubs.json').write_text(json.dumps(stubs,ensure_ascii=False,indent=1))
        report.update(status='STUBBED' if stubs else 'FAILED',log='logs/function-stubs.json' if stubs else None)
        return report

    def ux_pack(self,part,url,entry,index):
        """Pakiet UX Helixa na żywej aplikacji tej części, póki działa: macierz urządzeń na wszystkich trasach, eksplorator
        udający użytkownika i sędzia zrzutów (modele z planu ról). Domyślnie włączony w prawdziwym przebiegu; ux.enabled=false
        go wyłącza. Wynik dołącza do raportu części; błąd pakietu nie przerywa pozostałych kontroli."""
        declared=(getattr(self,'config',None) or {}).get('ux',{}).get('enabled')
        if declared is False or (declared is None and getattr(self.executor,'__class__',None) is not Executor): return
        if entry.get('api_only') or not self.tools.get('node'):
            entry['ux']=dict(status='NOT_APPLICABLE',reason='część bez ekranów HTML' if entry.get('api_only') else 'brak Node.js');return
        from helix_config import source, load
        out=self.out/'ux'/str(index); out.mkdir(parents=True,exist_ok=True)
        origin=f'{urlparse(url).scheme}://{urlparse(url).netloc}'
        routes=[r for r in part.get('routes',[]) if isinstance(r,str) and r.startswith('/')] or ['/']
        if self.quick: routes=routes[:self.quick]
        config=load(self.project); ux=dict(config.get('ux') or {})
        ux.update(enabled=True,base_url=origin,start_cmd=None)
        if not ux.get('pages'): ux['pages']=[dict(name=re.sub(r'[^\w-]+','-',r.strip('/')) or 'start',path=r) for r in routes]
        state=self.screen_file(part)
        # Sesja tego przebiegu zawsze wygrywa: plik z konfiguracji pochodzi z innego, już zamkniętego środowiska.
        if state is not None: ux['storage_state']=str(state)
        elif ux.get('storage_state') and not Path(ux['storage_state']).is_file(): ux.pop('storage_state')
        explore=dict(ux.get('explore') or {}); explore['enabled']=True; ux['explore']=explore
        if not self.quick: ux['judge']=dict(ux.get('judge') or {},targets='all')   # pełny przebieg: każde urządzenie, każda strona
        if self.quick: ux.setdefault('matrix','quick')
        config['ux']=ux
        if not ux.get('flows'):
            # Bez zadeklarowanych ścieżek eksplorator dostaje jedno ogólne zadanie: zorientować się w aplikacji jak nowy użytkownik.
            flows=out/'explore.json'
            flows.write_text(json.dumps(dict(flows=[],explore=[dict(id='pierwsze-wejscie',persona='novice',start=routes[0] if routes[0]!='/' or len(routes)==1 else '/',
                goal='Zorientuj się, do czego służy aplikacja, i otwórz trzy najważniejsze funkcje dostępne z menu.',max_steps=8)]),ensure_ascii=False))
            ux['flows']=str(flows)
        settings=out/'config.json'; settings.write_text(json.dumps(config,ensure_ascii=False,indent=1))
        argv=[sys.executable,str(HOME/'bin'/'helix'),'--repo',str(self.project),'--config',str(settings)]
        if self.cli.get('state_dir'): argv+=['--state-dir',str(self.cli['state_dir'])]
        argv+=['ux','all','--base-url',origin,'--no-start','--explore','--out',str(out/'report')]
        log=self.out/'logs'/f'part-{index}-ux.log'
        try:
            # Zaufanie do certyfikatu tego przebiegu (HTTPS) dostaje też pakiet UX: sprawdzenie gotowości i przeglądarki.
            trust={k:v for k,v in (self.env or {}).items() if k in ('SSL_CERT_FILE','REQUESTS_CA_BUNDLE','NODE_EXTRA_CA_CERTS','CURL_CA_BUNDLE','HELIX_RUNTIME_TLS_SPKI_LIST')}
            done=subprocess.run(argv,cwd=str(HOME),capture_output=True,text=True,timeout=self.budget.remaining(24*3600),env=dict(os.environ,**trust))   # cały pozostały budżet przebiegu: skan i sędzia wszystkich stron
            log.write_text(self.redact_private(done.stdout+'\n'+done.stderr))
            data=json.loads((out/'report'/'ux-report.json').read_text())
        except (Blocked,subprocess.TimeoutExpired,OSError,ValueError) as error:
            entry['ux']=dict(status='ERROR',reason=str(error)[:300],log=str(log.relative_to(self.out)));return
        entry['ux']=dict(status='PASS' if data.get('pass') else 'FAIL' if data.get('run_status')=='complete' else 'INCOMPLETE',
            run_status=data.get('run_status'),pages=len(ux['pages']),report=str((out/'report'/'ux-report.md').relative_to(self.out)),
            log=str(log.relative_to(self.out)),exit_code=done.returncode,
            judge=dict(devices=len([k for k,v in (data.get('judge') or {}).items() if isinstance(v,dict) and v.get('scores')]),
                       issues=len(data.get('judge_issues') or []),
                       not_judged=sorted(k for k,v in (data.get('judge') or {}).items() if isinstance(v,dict) and v.get('error'))),
            explore=dict(tasks=len(data.get('explore') or []),reached=sum(1 for e in data.get('explore') or [] if e.get('verified_success') or (e.get('verified_success') is None and e.get('model_success'))),
                         friction=sum(len(e.get('friction') or []) for e in data.get('explore') or [])),
            findings=len(data.get('top_findings') or []))

    def screen_file(self,part):
        """Plik sesji, z którą sprawdzenia oglądają ekrany po zalogowaniu: rola z Keycloaka albo scenariusz logowania właściciela."""
        screen=self.screen_session(part)
        if screen and screen['path'].is_file():return screen['path']
        other=getattr(self,'scenario_screen',None)
        return other if other is not None and other.is_file() else None

    def route_session(self,route,default):
        """Sesja dla trasy: scenariusz właściciela dla tras o jego początku, w pozostałych sesja roli ekranów."""
        for prefix,path in getattr(self,'scenario_sessions',[]):
            if route.startswith(prefix) and path.is_file():return path
        return default

    def role_matrix(self,part,url,screen,budgets):
        """Co widzi każda rola: te same trasy oglądane z sesją każdej zalogowanej roli i porównane z rolą ekranów.
        Wynik to zestawienie różnic (rola nie wchodzi tam, gdzie wchodzi rola ekranów, albo odwrotnie), nie ocena wyglądu."""
        folder=self.project_temporary()/'role-sessions'
        files=sorted(folder.glob('role-*.json')) if folder.is_dir() else []
        base={row['route']:row for row in getattr(self,'e2e_result',{}).get('routes',[])}
        if not files or not base or not self.tools.get('node'):return dict(status='NOT_RUN',reason='no role sessions or no e2e result')
        outcome=lambda row:('reachable' if row.get('reachable') else 'redirected' if row.get('status')=='REDIRECTED' else 'denied' if type(row.get('code')) is int and row['code'] in (401,403) else 'error')
        cwd=self.work/part['path'];routes=[route for route in base if not base[route].get('pattern')];roles={};differences=[];maps={}
        allowed=('PATH','HOME','CI','TMPDIR','MAC_CHROMIUM_TMPDIR','CHROME_PATH','NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','HELIX_RUNTIME_NODE_MODULES',
                 'HELIX_RUNTIME_BROWSER_BUDGETS','HELIX_RESOURCE_FILE','HELIX_RUNTIME_OIDC_ISSUER','HELIX_RUNTIME_OIDC_SPKI','HELIX_RUNTIME_TLS_SPKI_LIST')
        for path in files:
            role=path.name[len('role-'):-len('.json')]
            if screen and role==screen['role']:continue
            output=self.project_temporary()/('roles-'+hashlib.sha256(role.encode()).hexdigest()[:12]+'.json')
            for stale in (output,Path(str(output)+'.jsonl')):stale.unlink(missing_ok=True)
            original=self.env
            self.env={key:original[key] for key in allowed if key in original}
            self.env.update(HELIX_RUNTIME_SCREEN_SESSION=str(path),HELIX_RUNTIME_IDENTITY_MODE='keycloak-form')
            try:self.project_command([self.tool('node'),HOME/'bin/runtime-browser.cjs',url,output,'e2e',json.dumps(routes),str(cwd)],cwd,maximum=budgets['browser_seconds'],phase='measurement')
            except (Blocked,subprocess.TimeoutExpired):pass
            finally:self.env=original
            seen={row['route']:row for row in browser_results(output).get('routes',[])}
            counts={}
            for route in routes:
                mine=outcome(seen[route]) if route in seen else 'not-run';theirs=outcome(base[route])
                counts[mine]=counts.get(mine,0)+1
                if mine!=theirs and mine!='not-run':
                    differences.append(dict(role=role,route=route,role_result=mine,screen_role_result=theirs,role_code=seen[route].get('code'),
                                            **({'redirected_to':seen[route]['redirected_to']} if seen[route].get('redirected_to') else {})))
            roles[role]=counts;maps[role]={route:outcome(seen[route]) for route in routes if route in seen}
        # Kilka ról o różnych uprawnieniach z identycznym wynikiem na każdej trasie i bez ani jednego ekranu więcej niż gość:
        # bardziej prawdopodobne, że sesje ról nie działały (wygasły), niż że role naprawdę niczym się nie różnią.
        same=len(maps)>1 and len({json.dumps(found,sort_keys=True) for found in maps.values()})==1
        return dict(status=('SUSPECT' if same else 'RECORDED') if roles else 'NOT_RUN',compared_with=screen['role'] if screen else None,roles=roles,
                    **({'reason':'all compared roles have identical results on every route: either role sessions were invalid or the disposable database has no permissions for these roles (see role_code in differences: 403 means the application answered with a valid session)'} if same else {}),
                    differences=differences[:400],differences_total=len(differences))

    def login_expectations(self,part):
        """Czy logowanie każdej roli skończyło się tak, jak zadeklarował właściciel: rola z listy denied_roles ma nie dostać sesji."""
        declared=(((self.config.get('runtime') or {}).get('keycloak') or {}).get('parts') or {}).get(part['path']) or {}
        denied=set(declared.get('denied_roles') or [])
        plan=next((row for row in (getattr(self,'identity_plans',None) or {}).get('parts',[]) if row.get('part')==part['path']),None)
        suite=getattr(self,'identity_forms',{}).get(part['path'])
        if not plan or not suite:return []
        role_of={row['id']:(row.get('app_roles') or [None])[0] for row in plan.get('identities',[])}
        rows=[]
        for identity in suite.get('identities',[]):
            role=role_of.get(identity.get('identity_id'))
            if role is None:continue
            phases={phase.get('phase'):phase for phase in identity.get('phases',[])}
            callback=phases.get('callback',{})
            # Odmowa aplikacji jest potwierdzona tylko wtedy, gdy formularz logowania przeszedł, a aplikacja po powrocie zaczęła
            # logowanie od nowa. Błąd dostawcy tożsamości, przerwana próba albo brak fazy niczego nie dowodzą.
            if callback.get('status')=='PASS':observed='session'
            elif phases.get('form',{}).get('status')=='PASS' and callback.get('status')=='FAIL' and callback.get('reason_code')=='UNEXPECTED_AUTHORIZATION_RESTART':observed='denied'
            else:observed='inconclusive'
            expected='denied' if role in denied else 'session'
            rows.append(dict(role=role,expected=expected,observed=observed,
                             result='AS_EXPECTED' if observed==expected else 'INCONCLUSIVE' if observed=='inconclusive'
                             else 'SESSION_GRANTED_TO_DENIED_ROLE' if observed=='session' else 'UNEXPECTED_DENIAL'))
        return rows

    def data_states(self,part,url,screen,index):
        result=dict(sparse=dict(status='NOT_RUN'),volume=dict(status='NOT_RUN'))
        if getattr(self,'scenarios_done',None) is not None:result['scenarios']=self.scenarios_done
        else:
            try:result['scenarios']=self.run_scenarios(part,url,screen,index)
            except (Blocked,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:result['scenarios']=dict(status='BLOCKED',reason=str(error)[:300],scenarios=[])
        try:
            if self.tools.get('node'):
                import helix_visual
                state=self.screen_file(part)
                result['sparse']=helix_visual.sparse_pass(self.measurement_command,self.tool('node'),self.work/part['path'],
                    f'{urlparse(url).scheme}://{urlparse(url).netloc}',part['routes'],self.out/'visual'/str(index)/'sparse',storage_state=state,
                    session_for=lambda route:self.route_session(route,state),ui_args=ui_audit_args(self.config),
                    renew=lambda route:self.renew_sessions(part,url,screen,index,route))
        except (Blocked,OSError,ValueError,subprocess.SubprocessError) as error:result['sparse']=dict(status='BLOCKED',reason=str(error)[:300])
        try:result['roles']=dict(self.role_matrix(part,url,screen,profile_budgets(self.config)),login=self.login_expectations(part))
        except (Blocked,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:result['roles']=dict(status='BLOCKED',reason=str(error)[:300])
        try:result['volume']=self.seed_volume()
        except (Blocked,OSError,subprocess.SubprocessError) as error:result['volume']=dict(status='BLOCKED',reason=str(error)[:300])
        return result

    def seed_volume(self):
        """Stan przepełniony: z jednego syntetycznego wiersza na tabelę robi wiele, w tym długie nazwy i duże kwoty."""
        rows=self.config.get('runtime',{}).get('seed_rows',60) if isinstance(getattr(self,'config',None),dict) else 60
        if type(rows) is not int or not 2<=rows<=500:raise Blocked('runtime.seed_rows: wymagana liczba całkowita od 2 do 500')
        skip=self.config.get('runtime',{}).get('seed_skip_tables',[]) if isinstance(getattr(self,'config',None),dict) else []
        if not isinstance(skip,list) or len(skip)>100 or not all(isinstance(name,str) and re.fullmatch(r'[a-z_][a-z0-9_]{0,62}',name) for name in skip):
            raise Blocked('runtime.seed_skip_tables: wymagana lista do 100 nazw tabel')
        sql=(HOME/'templates/runtime-seed-volume.sql').read_text().replace(':rows',str(rows)).replace('/*:skip*/',"|| '|^("+'|'.join(skip)+")$'" if skip else '')
        output=self.command([self.tool('psql'),self.db,'-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-c',sql])
        return volume_result(output,rows)

    def backup(self):
        self.require_database_network()
        dump=self.tmp/'synthetic.dump'; restored='helix_restore_'+secrets.token_hex(4)
        fresh=self.db.rsplit('/',1)[0]+'/'+restored
        container=getattr(self,'container',None)
        if container:
            # Use the server's own client tools: newer host clients can emit SQL
            # unsupported by an older container server, even for an empty database.
            tool=self.tool(self.used_engine)
            remote='/tmp/'+dump.name
            self.command([tool,'exec',container,'pg_dump','-U','helix','--format=custom','--file',remote,self.db.rsplit('/',1)[1]])
            self.command([tool,'cp',container+':'+remote,dump])
        else:
            self.command([self.tool('pg_dump'),'--format=custom','--file',dump,self.db])
        self.command([self.tool('psql'),self.db,'-X','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE '+restored])
        self.database_cleanup.append(lambda:self.command([self.tool('psql'),self.db,'-X','-v','ON_ERROR_STOP=1','-c','DROP DATABASE IF EXISTS '+restored+' WITH (FORCE)'],cleanup=True))
        self.extension_preflight(dict(migrations=list(self.extension_sources.get(self.db,{}).values())),database=fresh,scope='restore',part=getattr(self,'active_part',None))
        if container:
            self.command([tool,'exec',container,'pg_restore','-U','helix','--exit-on-error','--no-owner','--dbname',restored,remote])
        else:
            self.project_command([self.tool('pg_restore'),'--exit-on-error','--no-owner','--dbname',fresh,dump],phase='migration')
        # psql generates safely quoted SELECTs for every user table, then executes with gexec.
        from helix_runtime_adapters import CHECKSUM_SQL, checksum_rows
        query=CHECKSUM_SQL
        script=self.tmp/'counts.sql'; script.write_text(query)
        before=self.command([self.tool('psql'),self.db,'-X','-A','-t','-v','ON_ERROR_STOP=1','-f',script])
        after=self.command([self.tool('psql'),fresh,'-X','-A','-t','-v','ON_ERROR_STOP=1','-f',script])
        a,b=checksum_rows(before),checksum_rows(after)
        if not a and not b: return 'FAIL',dict(tables=0,source_rows=[],restored_rows=[],schema_apply_failed=len(self.migration_notes),cause='no application tables; see schema-apply')
        return ('PASS' if a==b else 'FAIL'),dict(partial=bool(self.migration_notes),schema_apply_failed=len(self.migration_notes),source_rows=a,restored_rows=b,tables=len(a),dump_bytes=dump.stat().st_size if dump.exists() else 0,
                                               verification_completed=True,comparison='row_counts_and_checksums',checksum_algorithm='md5-sorted-row-jsonb-md5',fresh_database=True)
    def prepare_identity_login(self,part,budgets):
        """Build private form input only for the current owned Keycloak handle."""
        from helix_runtime_login import build_login_input
        private=getattr(self,'private_keycloak',{}).get(part['path'])
        if private is None:return None
        plan=next((row for row in self.identity_plans['parts'] if row['part']==part['path']),None)
        handle=private['handle'];receipt=handle.receipt();entry=self.keycloak_entry(part)
        if (not self.active_transport or self.active_transport['receipt'].get('status')!='ready' or
                receipt.get('readiness')!='ready' or receipt.get('run_id')!=self.run_id or
                receipt.get('integration_id')!=entry['id'] or receipt.get('plan_id')!=self.integration_plan['plan_id']):
            raise Blocked('Keycloak form input requires current owned identity and HTTPS readiness')
        binding=dict(run_id=self.run_id,integration_id=entry['id'],integration_plan_id=self.integration_plan['plan_id'],
                     identity_plan_id=plan['plan_id'],attempt_id='login-'+secrets.token_hex(16),part=part['path'])
        remaining=self.budget.remaining(budgets['browser_seconds'])
        try:
            data=build_login_input(plan,private['material'],binding=binding,issuer=handle.issuer,
                                  deadline_unix_ms=int(time.time()*1000+remaining*1000),
                                  operation_timeout_ms=min(60000,max(1,int(budgets['navigation_ms']))))
        except ValueError:raise Blocked('Keycloak form input requires explicit exact login/callback and HTTPS contract') from None
        path=self.tmp/(binding['attempt_id']+'.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(data,stream,sort_keys=True,allow_nan=False);stream.write('\n')
        self.identity_login_bindings[part['path']]=binding
        return path

    def record_identity_suite(self,part,suite):
        """Validate the fresh attempt before publishing safe final form phases."""
        from helix_runtime_login import project_identity
        expected=self.identity_login_bindings.get(part['path'])
        if expected is None or not isinstance(suite,dict) or suite.get('binding')!=expected:
            raise ValueError('identity form receipt does not match current browser attempt')
        sample=dict(run_id=self.run_id,parts=[dict(path=part['path'])],identity_plan=self.identity_plans,
                    identity_forms=[suite],integrations=self.integration_plan)
        project_identity(sample)
        destination=self.out/'logs'/(expected['attempt_id']+'.json')
        fd,temporary=tempfile.mkstemp(prefix='.identity-',dir=destination.parent)
        try:
            with os.fdopen(fd,'w') as stream:json.dump(suite,stream,indent=2,allow_nan=False);stream.write('\n')
            os.replace(temporary,destination)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
        self.identity_forms[part['path']]=suite
        return destination.relative_to(self.out).as_posix()

    def prepare_identity_policy(self,part,login_input):
        from helix_audit_context import safe_read
        planned=next((row for row in self.identity_policy_plans['parts'] if row['part']==part['path']),None)
        if planned is None or planned['status']!='PLANNED':return None
        from helix_runtime_identity_policy_run import build_policy_input
        raw=self.runtime_config.get('runtime',{}).get('identity_policy',{}).get('parts',{}).get(part['path'])
        data=build_policy_input(self.identity_policy_plans,part['path'],self.identity_plans,raw,
                                json.loads(safe_read(login_input)),policy_attempt_id='policy-'+secrets.token_hex(16))
        path=self.tmp/(data['binding']['policy_attempt_id']+'.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(data,stream,sort_keys=True,allow_nan=False);stream.write('\n')
        self.identity_policy_bindings[part['path']]=data['binding']
        return path

    def record_identity_policy(self,part,suite):
        from helix_runtime_identity_policy_run import project_policy_execution
        expected=self.identity_policy_bindings.get(part['path'])
        if expected is None or not isinstance(suite,dict) or suite.get('binding')!=expected:
            raise ValueError('identity policy receipt does not match current browser attempt')
        sample=dict(run_id=self.run_id,parts=[dict(path=part['path'])],identity_plan=self.identity_plans,
                    identity_forms=[self.identity_forms[part['path']]] if part['path'] in self.identity_forms else [],integrations=self.integration_plan,
                    identity_policy_plan=self.identity_policy_plans,identity_policy_receipts=[],identity_policy_executions=[suite])
        project_policy_execution(sample)
        destination=self.out/'logs'/(expected['policy_attempt_id']+'.json')
        fd,temporary=tempfile.mkstemp(prefix='.policy-',dir=destination.parent)
        try:
            with os.fdopen(fd,'w') as stream:json.dump(suite,stream,indent=2,allow_nan=False);stream.write('\n')
            os.replace(temporary,destination)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
        self.identity_policy_executions[part['path']]=suite
        return destination.relative_to(self.out).as_posix()

    def webauthn_context(self,part):
        """Current part and owned transport, without sibling execution receipts."""
        return dict(run_id=self.run_id,parts=[dict(path=part['path'],name=part['path'],
                    transport=self.active_transport['receipt'] if self.active_transport else None)],
                    integrations=self.integration_plan,identity_plan=self.identity_plans,
                    identity_forms=[self.identity_forms[part['path']]] if part['path'] in self.identity_forms else [],
                    identity_policy_plan=self.identity_policy_plans,identity_policy_receipts=[],
                    identity_policy_executions=[self.identity_policy_executions[part['path']]] if part['path'] in self.identity_policy_executions else [],
                    transport_plan=self.transport_plans,webauthn_plan=self.webauthn_plans,webauthn_receipts=[])

    def prepare_webauthn(self,part,policy_input):
        from helix_audit_context import safe_read
        from helix_runtime_webauthn_run import build_webauthn_input
        planned=next((row for row in self.webauthn_plans['parts'] if row['part']==part['path']),None)
        if planned is None or planned['status']!='PLANNED':return None
        raw=self.runtime_config.get('runtime',{}).get('webauthn',{}).get('parts',{}).get(part['path'])
        data=build_webauthn_input(self.webauthn_context(part),part['path'],raw,json.loads(safe_read(policy_input)),
                                 webauthn_attempt_id='webauthn-'+secrets.token_hex(16))
        path=self.tmp/(data['binding']['webauthn_attempt_id']+'.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(data,stream,sort_keys=True,allow_nan=False);stream.write('\n')
        self.webauthn_bindings[part['path']]=data['binding']
        return path

    def record_webauthn(self,part,suite):
        from helix_runtime_webauthn_run import project_webauthn_execution
        expected=self.webauthn_bindings.get(part['path'])
        if expected is None or not isinstance(suite,dict) or suite.get('binding')!=expected:
            raise ValueError('WebAuthn receipt does not match current browser attempt')
        sample=self.webauthn_context(part);sample['webauthn_executions']=[suite]
        project_webauthn_execution(sample)
        destination=self.out/'logs'/(expected['webauthn_attempt_id']+'.json')
        fd,temporary=tempfile.mkstemp(prefix='.webauthn-',dir=destination.parent)
        try:
            with os.fdopen(fd,'w') as stream:json.dump(suite,stream,indent=2,allow_nan=False);stream.write('\n')
            os.replace(temporary,destination)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
        self.webauthn_executions[part['path']]=suite
        return destination.relative_to(self.out).as_posix()

    def scenario_pass(self,check,part,url,budgets,status,metrics):
        """Trasy z własną sesją scenariusza (save_session.routes_prefix) e2e i a11y oglądają drugi raz, z tą sesją.
        Sesja roli ekranów na nich nie działa (np. hala logowana PIN-em), więc pierwszy wynik to samo odesłanie na logowanie."""
        for prefix,path in getattr(self,'scenario_sessions',[]):
            rows=metrics.get('routes') if isinstance(metrics,dict) else None
            routes=[r['route'] for r in rows or [] if r['route'].startswith(prefix) and not r.get('pattern')]
            if status not in ('PASS','FAIL') or not routes or not path.is_file():continue
            output=self.project_temporary()/('routes-with-scenario-session.'+check+'.json')  # inna przestrzeń nazw niż pliki sesji scenario-<id>.json
            for stale in (output,Path(str(output)+'.jsonl'),Path(str(output)+'.session')):stale.unlink(missing_ok=True)
            saved=self.env
            self.env={key:saved[key] for key in ('PATH','HOME','CI','TMPDIR','MAC_CHROMIUM_TMPDIR','CHROME_PATH','NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','HELIX_RUNTIME_NODE_MODULES',
                      'HELIX_RUNTIME_BROWSER_BUDGETS','HELIX_RESOURCE_FILE','HELIX_RUNTIME_OIDC_ISSUER','HELIX_RUNTIME_OIDC_SPKI','HELIX_RUNTIME_TLS_SPKI_LIST') if key in saved}
            self.env.update(HELIX_RUNTIME_SCREEN_SESSION=str(path),HELIX_RUNTIME_IDENTITY_MODE='keycloak-form')
            try:self.project_command([self.tool('node'),HOME/'bin/runtime-browser.cjs',url,output,check,json.dumps(routes),str(self.work/part['path'])],self.work/part['path'],maximum=budgets['browser_seconds'],phase='measurement')
            except (Blocked,subprocess.TimeoutExpired):stopped=True
            else:stopped=False
            finally:self.env=saved
            # Brak końcowego pliku wyniku albo przerwany proces to pomiar nieukończony, także gdy dziennik ma wiersz dla każdej trasy.
            stopped=stopped or not output.exists()
            again=browser_results(output)
            for stale in (output,Path(str(output)+'.jsonl'),Path(str(output)+'.session')):stale.unlink(missing_ok=True)
            fresh={r['route']:r for r in again.get('routes',[]) if not r.get('pattern')}
            status,metrics=merge_scenario_routes(metrics,fresh,again.get('requests',[]),prefix,requested=routes,interrupted=bool(stopped or again.get('resource_paused') or again.get('artifact_gaps')))
        return status,metrics

    def measure(self,check,part,url,budgets):
        self.resource_wait()
        cwd=self.work/part['path']
        if check=='backup': return self.backup()
        if check in ('e2e','a11y'):
            output=self.project_temporary()/(check+'.json')
            if not getattr(self,'browser_tools',False):
                # Installing in the disposable copy is explicitly part of runtime, never Helix.
                tool_dir=self.work/'.helix-runtime-tools'; tool_dir.mkdir(exist_ok=True)
                (tool_dir/'package.json').write_text('{}')
                prepared=self.prepare_runtime_tools()
                if prepared is not None: shutil.copytree(prepared,tool_dir/'node_modules',symlinks=True)
                else: self.project_command([self.tool('npm'),'install','--prefix',tool_dir,'--no-save','--package-lock=false','axe-core','playwright'],tool_dir,maximum=180,phase='install')
                self.browser_module_dir=str(tool_dir/'node_modules')
                self.browser_tools=True
            self.env['HELIX_RUNTIME_NODE_MODULES']=self.browser_module_dir
            # Adres zwrotny OIDC wywołany bez parametrów zawsze odpowiada błędem; to nie jest ekran do oceny.
            selected=sample_routes(part['routes'],budgets['route_sample'])
            self.env['HELIX_RUNTIME_BROWSER_BUDGETS']=json.dumps(budgets)
            if getattr(self,'resources',None) is not None:
                self.env['HELIX_RESOURCE_FILE']=str(self.resources.current_path)
            output.unlink(missing_ok=True)
            Path(str(output)+'.session').unlink(missing_ok=True)
            Path(str(output)+'.jsonl').unlink(missing_ok=True)
            login_input=None;login_gap=None;policy_input=None;policy_gap=None;webauthn_input=None;webauthn_gap=None
            if check=='e2e' and getattr(self,'private_keycloak',{}).get(part['path']):
                try:login_input=self.prepare_identity_login(part,budgets)
                except Blocked as error:login_gap=str(error)
            if login_input:
                try:policy_input=self.prepare_identity_policy(part,login_input)
                except ValueError:policy_gap='Explicit identity policy could not bind to the current private form input'
            if policy_input:
                try:webauthn_input=self.prepare_webauthn(part,policy_input)
                except ValueError:webauthn_gap='Explicit WebAuthn could not bind to the current policy and owned transport'
            # Browser tooling only receives its own paths, trust anchors and
            # synthetic private input path. Application credentials stay out.
            original_environment=self.env
            allowed=('PATH','HOME','CI','TMPDIR','MAC_CHROMIUM_TMPDIR','CHROME_PATH','NODE_EXTRA_CA_CERTS','SSL_CERT_FILE',
                     'HELIX_RUNTIME_NODE_MODULES','HELIX_RUNTIME_BROWSER_BUDGETS','HELIX_RESOURCE_FILE',
                     'HELIX_RUNTIME_OIDC_ISSUER','HELIX_RUNTIME_OIDC_SPKI','HELIX_RUNTIME_TLS_SPKI_LIST','HELIX_RUNTIME_IDENTITY_MODE')
            self.env={key:original_environment[key] for key in allowed if key in original_environment}
            if login_input:
                self.env.update(HELIX_RUNTIME_IDENTITY_INPUT=str(login_input),HELIX_RUNTIME_PRIVATE_ROOT=str(self.tmp),
                                HELIX_RUNTIME_IDENTITY_MODE='keycloak-form')
            screen=self.screen_session(part)
            if check=='e2e' and part.get('route_patterns') and not self.quick:
                # Parametr o nazwie token, kod albo klucz to zwykle odnośnik-akcja (wypisanie, potwierdzenie): takich adresów e2e nie otwiera sam.
                self.env['HELIX_RUNTIME_ROUTE_PATTERNS']=json.dumps([p for p in part['route_patterns'] if not re.search(r'\[(token|code|kod|key|klucz|hash|secret|sig\w*)\]',p,re.I)][:200])
            if screen:
                # e2e zapisuje sesję wskazanej roli po udanym logowaniu; a11y tylko ją czyta.
                self.env['HELIX_RUNTIME_SCREEN_SESSION']=str(screen['path'])
                if check=='e2e' and login_input:
                    screen['path'].unlink(missing_ok=True);self.env['HELIX_RUNTIME_SCREEN_ROLE']=screen['role']
                    # sesje pozostałych ról: do sprawdzenia, co która rola widzi (prywatny katalog przebiegu, sprzątany po części)
                    roles=self.project_temporary()/'role-sessions'
                    if roles.exists():shutil.rmtree(roles)
                    roles.mkdir(mode=0o700);self.env['HELIX_RUNTIME_ROLE_SESSIONS']=str(roles)
            if not screen and getattr(self,'scenario_screen',None) is not None and self.scenario_screen.is_file():
                self.env['HELIX_RUNTIME_SCREEN_SESSION']=str(self.scenario_screen)
            if policy_input:self.env['HELIX_RUNTIME_POLICY_INPUT']=str(policy_input)
            if webauthn_input:self.env['HELIX_RUNTIME_WEBAUTHN_INPUT']=str(webauthn_input)
            try:
                self.project_command([self.tool('node'),HOME/'bin/runtime-browser.cjs',url,output,check,json.dumps(selected),str(cwd)],cwd,maximum=budgets['browser_seconds'],phase='measurement')
            except (Blocked,subprocess.TimeoutExpired): pass
            finally:
                self.env=original_environment
                if login_input:login_input.unlink(missing_ok=True)
                if policy_input:policy_input.unlink(missing_ok=True)
                if webauthn_input:webauthn_input.unlink(missing_ok=True)
            data=bare_callback_answers(browser_results(output),getattr(self,'identity_plans',None),part['path'])
            if check=='e2e' and login_input:
                if data.get('identity_form') is not None:
                    data['identity_form_log']=self.record_identity_suite(part,data['identity_form'])
                else:login_gap='Keycloak browser attempt did not publish a final form checkpoint'
            if login_gap:data['identity_form_gap']=login_gap
            if check=='e2e' and policy_input:
                if data.get('identity_policy') is not None:
                    data['identity_policy_log']=self.record_identity_policy(part,data['identity_policy'])
                else:policy_gap='Identity policy attempt did not publish a checkpoint'
            if policy_gap:data['identity_policy_gap']=policy_gap
            if check=='e2e' and webauthn_input:
                if data.get('webauthn') is not None:data['webauthn_log']=self.record_webauthn(part,data['webauthn'])
                else:webauthn_gap='WebAuthn attempt did not publish a checkpoint'
            if webauthn_gap:data['webauthn_gap']=webauthn_gap
            self.browser_metadata(data)
            journal=Path(str(output)+'.jsonl')
            if journal.exists():
                from helix_audit_context import safe_read
                destination=self.out/'logs'/('browser-'+str(self.steps)+'-'+check+'.jsonl')
                destination.parent.mkdir(parents=True,exist_ok=True)
                public_journal=self.redact_private(safe_read(journal))
                fd,temporary=tempfile.mkstemp(prefix='.browser-',dir=destination.parent)
                try:
                    with os.fdopen(fd,'w') as stream:stream.write(public_journal)
                    os.replace(temporary,destination)
                finally:
                    if os.path.exists(temporary):os.unlink(temporary)
                data['journal']=str(destination.relative_to(self.out))
            # Neither legacy navigation nor current form/policy observations
            # authorize export of credentials to a different measurement.
            Path(str(output)+'.session').unlink(missing_ok=True)
            if check=='e2e': self.session_cookies={}
            data['not_sampled']=dict(count=len(set(part['routes'])-set(selected)),reason='not sampled')
            data['not_completed']=max(0,len(selected)-sum(not r.get('pattern') for r in data.get('routes',[])))
            if check=='e2e' and part.get('route_patterns') and not self.quick:
                # Adresy odkryte z odnośników dołączają do tras części: a11y i przegląd tras oglądają je tak samo jak pozostałe.
                found=data.get('discovered',{})
                part['routes']=part['routes']+[route for route in found.values() if route not in part['routes']]
                data['unresolved_patterns']=[pattern for pattern in part['route_patterns'] if pattern not in found]
            if data.get('resource_paused'):
                paused=ResourcePaused('resource_paused: browser admission stopped; partial routes retained',data['resource_paused'].get('decision',{}))
                paused.metrics=data
                raise paused
            if data.get('artifact_gaps'):return 'BLOCKED',dict(data,cause='Browser final output incomplete; recovered journal observations only')
            if not data.get('routes'): return 'BLOCKED',dict(data,cause='No route produced a result')
            if check=='e2e': self.e2e_result=data
            # Goły adres zwrotny przeklasyfikowany wyżej nie jest przyczyną niepowodzenia; prawdziwy callback ocenia formularz logowania.
            data['cause']='; '.join('HTTP '+str(r['status'])+' from '+r['source']+' on '+r['url'] for r in data.get('requests',[]) if r['status']>=400 and not synthetic_request(r)
                                    and not (r['status']<500 and r['source']=='app' and urlparse(r['url']).path in data.get('bare_callbacks',())))
            data['cause']+=stub_404_reason(data.get('requests',[]),part.get('url_roles',{}))
            data['url_roles']=part.get('url_roles',{})
            # Same odesłania to nie wynik: bez choć jednego ekranu obejrzanego pod własnym adresem sprawdzenie nie przechodzi.
            if not data['errors'] and not data.get('pages'):data['cause']='No route was reachable under its own address'
            return ('FAIL' if data['errors'] or data['not_completed'] or not data.get('pages') else 'PASS'),data
        if check=='lighthouse':
            output=self.project_temporary()/'lighthouse.json'
            # Sesja roli ekranów trafia do przeglądarki pomiaru jako zwykłe ciasteczka (pomocnik runtime-lighthouse-session.cjs):
            # przeglądarka pilnuje ich zakresu, a wynik Lighthouse nie niesie wartości. Tylko na przeglądarce uruchomionej przez Helix.
            screen_path=self.screen_file(part)
            session=screen_path is not None and bool(self.screen_cookies(part,urlparse(url).hostname)) and sys.platform=='darwin' and bool(self.tools.get('playwright_chromium')) and bool(self.tools.get('node'))
            try:
                pins=self.env.get('HELIX_RUNTIME_TLS_SPKI_LIST') or self.env.get('HELIX_RUNTIME_OIDC_SPKI')
                chrome_flags=['--headless','--no-sandbox','--disable-dev-shm-usage']+(['--ignore-certificate-errors-spki-list='+pins] if pins else [])
                chrome=self.tools.get('playwright_chromium')
                if sys.platform=='darwin' and chrome:
                    profile=self.project_temporary()/'lighthouse-profile'
                    lighthouse=[self.tool('lighthouse'),url,'--output=json','--output-path='+str(output),'--hostname=127.0.0.1','--port={port}','--quiet']
                    if session:lighthouse=[self.tool('node'),str(HOME/'bin/runtime-lighthouse-session.cjs'),str(screen_path),urlparse(url).hostname,'{port}','--',*lighthouse,'--disable-storage-reset']
                    self.measurement_command(lighthouse,cwd,maximum=150,
                                             browser=[chrome,*chrome_flags,'--disable-gpu','--no-first-run','--no-default-browser-check','--remote-debugging-address=127.0.0.1',
                                                      '--remote-debugging-port={port}','--user-data-dir='+str(profile),'about:blank'])
                else:
                    self.project_command([self.tool('lighthouse'),url,'--output=json','--output-path='+str(output),'--chrome-flags='+' '.join(chrome_flags),'--quiet'],cwd,maximum=150,phase='measurement')
            except Blocked as error:
                if not output.is_file(): raise
                raw=json.loads(output.read_text())
                if not raw.get('runtimeError'): raise
                return 'FAIL',lighthouse_failure(raw,self.env.get('HELIX_RUNTIME_OIDC_ISSUER',''))
            raw=json.loads(output.read_text())
            if raw.get('runtimeError'): return 'FAIL',lighthouse_failure(raw,self.env.get('HELIX_RUNTIME_OIDC_ISSUER',''))
            # Bez sesji ekran chroniony odsyła do logowania u dostawcy tożsamości; wynik opisywałby jego stronę, nie aplikację.
            landed=urlparse(raw.get('finalDisplayedUrl') or raw.get('finalUrl') or url)
            if landed.netloc!=urlparse(url).netloc:
                return 'BLOCKED',dict(cause='Lighthouse landed on another origin (login at the identity provider), not on the application; the measured page is not the application screen',
                                      landed_on='identity provider' if self.env.get('HELIX_RUNTIME_OIDC_ISSUER') and landed.netloc==urlparse(self.env['HELIX_RUNTIME_OIDC_ISSUER']).netloc else 'other origin')
            audits=raw['audits']
            requests=[dict(method=r.get('requestMethod','GET'),url=urlparse(r.get('url',''))._replace(query='',fragment='').geturl(),status=r.get('statusCode',0),source='stub' if self.env.get('HELIX_RUNTIME_OIDC_ISSUER') and urlparse(r.get('url','')).netloc==urlparse(self.env['HELIX_RUNTIME_OIDC_ISSUER']).netloc else 'app') for r in audits.get('network-requests',{}).get('details',{}).get('items',[])]
            http_errors=[r for r in requests if r['status']>=400 and not synthetic_request(r)]
            if http_errors: return 'FAIL',dict(requests=requests,cause='; '.join('HTTP '+str(r['status'])+' from '+r['source']+' on '+r['url'] for r in http_errors))
            data=dict(lcp_ms=audits['largest-contentful-paint']['numericValue'],cls=audits['cumulative-layout-shift']['numericValue'],tbt_ms=audits['total-blocking-time']['numericValue'],performance=raw['categories']['performance']['score'])
            ok=data['lcp_ms']<=budgets['lcp_ms'] and data['cls']<=budgets['cls'] and data['tbt_ms']<=budgets['tbt_ms'] and data['performance']>=budgets['performance']
            return ('PASS' if ok else 'FAIL'),dict(data,budgets=budgets,measured_path=landed.path or '/',authentication_scope='session of the declared screen role' if session else 'anonymous')
        # k6 nie ma ścieżki zaufania do jednorazowego certyfikatu, a sprawdzania TLS nie wyłączamy. Gdy TLS kończy własna
        # warstwa przebiegu, obciążenie idzie wprost do aplikacji za nią, z tymi samymi nagłówkami przekazania co ta warstwa.
        load_base=url;forwarded={};transport=getattr(self,'active_transport',None)
        if urlparse(url).scheme=='https':
            if not transport or urlparse(url).port!=transport['public_port']:
                return 'BLOCKED',dict(cause='HTTPS load requires a verified per-process k6 CA trust path; no insecure TLS fallback')
            load_base=transport['backend_origin']
            forwarded={'X-Forwarded-Proto':'https','X-Forwarded-Host':urlparse(url).hostname,'X-Forwarded-Port':str(transport['public_port'])}
        elif getattr(self,'supabase_stack',None) and getattr(self,'direct_app_origin',None):load_base=self.direct_app_origin
        observed=getattr(self,'e2e_result',{})
        routes=observed.get('pages',[])
        excluded=[r for r in part['routes'] if r not in routes]
        if not routes: return 'BLOCKED',dict(cause='No routes verified reachable by e2e',excluded_routes=excluded)
        output=self.project_temporary()/'load.json'; output.unlink(missing_ok=True); script=self.project_temporary()/'load.js'
        targets=[urlparse(load_base)._replace(path=r,query='',fragment='').geturl() for r in routes]
        options=dict(vus=budgets['vus'],duration=budgets['duration'],thresholds={'http_req_duration':[f"p(95)<{budgets['p95_ms']}"],'http_req_failed':[f"rate<{budgets['error_rate']}"]})
        cookies=self.screen_cookies(part,urlparse(url).hostname)
        script.unlink(missing_ok=True)
        try:
            # Skrypt może nieść ciasteczka sesji: plik prywatny, a zapis i uruchomienie mają wspólne sprzątanie.
            with os.fdopen(os.open(script,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as handle:handle.write("import http from 'k6/http'; import {Counter} from 'k6/metrics'; const codes=new Counter('runtime_responses'); export const options="+json.dumps(options)+"; const urls="+json.dumps(targets)+"; export default function(){for(const url of urls){const r=http.get(url,{redirects:0,headers:"+json.dumps(forwarded)+",cookies:"+json.dumps(cookies)+",tags:{name:url}}); codes.add(1,{method:'GET',url:url,status:String(r.status),source:'app'});}}")
            try: self.project_command([self.tool('k6'),'run','--summary-export',output,'--out','json='+str(self.out/'logs/load-requests.jsonl'),script],cwd,maximum=90,phase='measurement')
            except Blocked:
                if not output.is_file(): raise
        finally:
            if cookies:script.unlink(missing_ok=True)  # skrypt niesie ciasteczka sesji
        raw=json.loads(output.read_text()); metrics=raw['metrics']
        values=lambda x:x.get('values',x)
        failed=values(metrics['http_req_failed'])
        # Legacy summary-export calls a rate metric's value "value".
        rate=failed['rate'] if 'rate' in failed else failed['value']
        data=dict(p95_ms=values(metrics['http_req_duration'])['p(95)'],error_rate=rate,excluded_routes=excluded,requests=[],status_by_url={})
        request_log=self.out/'logs/load-requests.jsonl'
        if request_log.exists():
            for line in request_log.read_text().splitlines():
                point=json.loads(line)
                if point.get('type')!='Point' or point.get('metric')!='runtime_responses': continue
                tags=point['data']['tags']; key=tags['url']
                row=dict(method=tags['method'],url=key,status=int(tags['status']),source=tags['source'])
                if row not in data['requests']: data['requests'].append(row)
                counts=data['status_by_url'].setdefault(key,{})
                counts[tags['status']]=counts.get(tags['status'],0)+point['data']['value']
        data['cause']='; '.join('HTTP '+str(r['status'])+' from '+r['source']+' on '+r['url'] for r in data['requests'] if r['status']>=400 and not synthetic_request(r))
        # Bez sesji ekran chroniony odpowiada odesłaniem: czas odesłań nie jest czasem aplikacji.
        moved=sum(1 for counts in data['status_by_url'].values() if counts and all(300<=int(code)<400 for code in counts))
        if data['status_by_url'] and moved*2>=len(data['status_by_url']):
            return 'BLOCKED',dict(data,budgets=budgets,cause='load measured mostly redirects: '+str(moved)+' of '+str(len(data['status_by_url']))+' sampled routes answer 3xx without a session')
        ok=data['p95_ms']<budgets['p95_ms'] and data['error_rate']<budgets['error_rate']
        return ('PASS' if ok else 'FAIL'),dict(data,budgets=budgets,authentication_scope='session of the declared screen role' if cookies else 'anonymous; no verified session transfer',
                                                 **({'transport':'application HTTP port behind the run-owned TLS layer; TLS handshake not included'} if forwarded else {}))
    def run(self,cli=None):
        # Konfiguracja i katalog stanu wywołania CLI: pakiet UX dostaje tych samych sprawdzonych dostawców modeli.
        self.cli=cli or {}
        from helix_config import load as load_config
        cfg=load_config(self.project)
        spec=plan(self.project,cfg)
        self.integration_plan=spec['integrations']; self.integration_receipts=[]; self.run_id='runtime-'+secrets.token_hex(16)
        self.identity_plans=spec['identity_plan']
        self.identity_forms={};self.identity_login_bindings={}
        self.identity_policy_plans=spec['identity_policy_plan'];self.runtime_config=cfg
        self.identity_policy_executions={};self.identity_policy_bindings={}
        self.transport_plans=spec['transport_plan']
        self.sink_plans=spec['sink_plan']
        self.adapter_plans=spec['adapters'];self.config=cfg
        self.webauthn_plans=spec['webauthn_plan'];self.webauthn_executions={};self.webauthn_bindings={}
        parts=[p for p in spec['parts'] if self.part is None or p['name']==self.part]
        if self.part is not None and not parts: raise ValueError('unknown project part')
        if self.out.exists() and any(self.out.iterdir()): raise ValueError('output must be empty')
        (self.out/'logs').mkdir(parents=True)
        self.tmp=runtime_tmpdir(); self.work=self.tmp/'project'
        from helix_environment import provenance, normalize_tools
        report=dict(helix_version=VERSION,schema_version=1,project=str(self.project),scope='synthetic disposable runtime; no production claims',parts=[],engine=None,provenance=provenance(self.project),run_id=self.run_id,transport_plan=self.transport_plans,identity_plan=self.identity_plans,identity_forms=[])
        report.update(identity_policy_plan=spec['identity_policy_plan'],identity_policy_receipts=[],identity_policy_executions=[])
        report.update(webauthn_plan=spec['webauthn_plan'],webauthn_receipts=[],webauthn_executions=[])
        report.update(sink_plan=self.sink_plans,sink_observations=[])
        old_handlers={}; resource_monitor=None
        def interrupt(signum,frame): raise Interrupted('runtime interrupted by signal '+str(signum))
        try:
            for sig in (signal.SIGINT,signal.SIGTERM):
                try: old_handlers[sig]=signal.signal(sig,interrupt)
                except ValueError: pass  # unit tests may execute in a worker thread
            budgets=profile_budgets(cfg)
            if self.resources is None:
                self.resources=Governor(snapshot_fn=getattr(self.executor,'resource_snapshot',None),policy=cfg.get('resources'),requested_jobs=budgets['workers'],out=self.out)
            resource_monitor=self.resources.monitor(); resource_monitor.__enter__()
            self.resource_wait()
            copy_project(self.project,self.work)
            # Fresh HOME prevents package managers loading caller credentials/configuration.
            sandbox_home=self.project_temporary()/'home'; sandbox_home.mkdir()
            safe_path=os.pathsep.join(dict.fromkeys([str(Path(x).parent) for x in self.tools.values() if x]+os.defpath.split(os.pathsep)))
            # Chrome na macOS bierze katalog tymczasowy z MAC_CHROMIUM_TMPDIR, nie z TMPDIR; dotyczy każdego startu przeglądarki (e2e, PDF, przegląd tras).
            self.env={'PATH':safe_path,'HOME':str(sandbox_home),'TMPDIR':str(self.project_temporary()),'MAC_CHROMIUM_TMPDIR':str(self.project_temporary()),'CI':'1'}
            base_env=dict(self.env)
            if self.tools.get('playwright_chromium'):
                base_env['CHROME_PATH']=self.tools['playwright_chromium']
            # Explicit module location is a tool path, never a credential source.
            if os.environ.get('HELIX_RUNTIME_NODE_MODULES'):
                base_env['HELIX_RUNTIME_NODE_MODULES']=os.environ['HELIX_RUNTIME_NODE_MODULES']
            for contract in ('slo.yaml','slo.yml','contracts/slo.yaml'):
                contract_path=self.work/contract
                if contract_path.is_file():
                    import yaml
                    content=yaml.safe_load(contract_path.read_text()) or {}
                    values=content.get('runtime',content.get('slo',content))
                    for key in ('p95_ms','error_rate'):
                        if key in values and isinstance(values[key],(int,float)) and values[key]>0: budgets[key]=values[key]
            for part in parts:
                self.active_part=part['path']
                if self.quick and part.get('routes'):
                    kept=quick_routes(part['routes'],self.quick,[row['save_session'].get('routes_prefix') for row in self.declared_scenarios(part) if isinstance(row.get('save_session'),dict)])
                    report.setdefault('quick',dict(routes_per_part=self.quick,scope='trial run on a few routes; not an assessment of the project',omitted={}))['omitted'][part['path']]=len(part['routes'])-len(kept)
                    part['routes']=kept
                entry=dict(name=part['name'],path=part['path'],checks={}); report['parts'].append(entry)
                entry['adapters']=next(row for row in self.adapter_plans['parts'] if row['part']==part['path'])
                if part['framework']=='python-worker':
                    # Worker nie ma ekranów ani adresu HTTP. Ograniczony kontrakt: zależności instalowane w izolacji i własne testy tej części.
                    log=self.out/'logs'/('worker-'+str(len(report['parts']))+'.log')
                    status,message=self.worker_tests(part,base_env,log)
                    entry['checks']={check:dict(status='SKIPPED',metrics={},log=log.relative_to(self.out).as_posix(),reason='worker part: screen and HTTP checks do not apply') for check in CHECKS}
                    entry['checks']['worker-tests']=dict(status=status,metrics=dict(summary=str(message)[:200]) if status in ('PASS','FAIL') else {},log=log.relative_to(self.out).as_posix(),reason=message)
                    continue
                # HTTP evidence belongs to this app only, even when its build fails
                # before a new health request can replace the previous response.
                self.executor.last_health={}
                self.e2e_result={}
                self.session_cookies={}
                self.active_transport=None;self.current_identity_tls=None
                self.owned_node_options=None;self.owned_preloads=[];self.owned_pythonpath=None;self.active_sink=None;self.active_generic=None;self.network_listen_ports=set()
                transport_declaration=next(row for row in self.transport_plans['parts'] if row['part']==part['path'])
                entry['transport']=dict(status='not_checked',selected=transport_declaration['selected'],
                                        gaps=transport_declaration['gaps'],limits=transport_declaration['limits'],cleanup='not_needed')
                startup_attempts=[]; reason=None; proc=None; start_log=None; url=None; executed_start=None; port=None
                weight_result=dict(status='needs-runtime', reason='Build not completed')
                try:
                    # Classification supplies dummy values; only execution can block an app.
                    self.budget.remaining(1)
                    self.require_integration_strategy(part)
                    selected_identity=None
                    if self.keycloak_entry(part) is not None:
                        selected_identity=next((p for p in self.identity_plans['parts'] if p['part']==part['path']),None)
                        self.keycloak_contract(part,selected_identity)
                    port=self.port_factory()
                    self.network_listen_ports.add(port);self.network_connect_ports.add(port)
                    self.env=dict(base_env)
                    self.active_transport=self.prepare_https(cfg.get('runtime',{}).get('https'),port)
                    if self.active_transport:self.network_connect_ports.add(self.active_transport['public_port'])
                    public_origin=self.active_transport['public_origin'] if self.active_transport else None
                    # Frontend z osobnym API: wspólny adres daje rozdzielacz ścieżek, a zaplecze dostaje własny port na pętli zwrotnej.
                    composed=None
                    backend_part=next((p for p in spec['parts'] if part.get('backend') and p['path']==part['backend']['part']),None)
                    if backend_part is not None and not self.active_transport:
                        backend_port=self.port_factory()
                        self.network_listen_ports.add(backend_port);self.network_connect_ports.add(backend_port)
                        router=PathRouter(port,{prefix:backend_port for prefix in part['backend']['prefixes']})
                        self.cleanup_actions.append(router.close)
                        self.network_connect_ports.add(router.port)
                        public_origin='http://127.0.0.1:'+str(router.port)
                        composed=dict(router=router,port=backend_port,part=backend_part)
                        entry['backend']=dict(part=backend_part['path'],prefixes=part['backend']['prefixes'],env=part['backend']['env'],status='PLANNED',origin=public_origin)
                    # Aplikacja na Supabase: lokalny stos pod tym samym adresem co ekrany (jak na serwerze za wspólną domeną).
                    supabase_ports=None
                    if part.get('supabase') and backend_part is None and not self.active_transport:
                        if not self.tools.get('docker'):raise Blocked('supabase: lokalny stos wymaga Dockera')
                        from helix_runtime_supabase import PREFIXES as supabase_prefixes
                        supabase_ports=(self.port_factory(),self.port_factory())
                        self.network_connect_ports.update(supabase_ports)
                        router=PathRouter(port,{prefix:supabase_ports[0] for prefix in supabase_prefixes})
                        self.cleanup_actions.append(router.close)
                        self.network_connect_ports.add(router.port)
                        public_origin='http://127.0.0.1:'+str(router.port)
                        composed=dict(router=router,port=None,part=None)
                        # Obciążenie idzie wprost do aplikacji: rozdzielacz otwiera nowe połączenie na każde żądanie i przy tempie
                        # próby obciążeniowej wyczerpuje porty systemu, co dawało 502 niebędące odpowiedzią aplikacji.
                        self.direct_app_origin='http://127.0.0.1:'+str(port);self.network_connect_ports.add(port)
                    if self.active_transport:
                        self.active_transport['receipt']=entry['transport']
                        entry['transport'].update(public_origin=public_origin,backend_origin=self.active_transport['backend_origin'],
                                                  public_port=self.active_transport['public_port'],backend_port=port)
                    # Zmienna opcjonalna, której sama obecność zmienia ekran (np. baner), zostaje nieustawiona na życzenie właściciela.
                    # Odfiltrowana ze spisu zmiennych, więc nie wróci przy żadnym późniejszym odtworzeniu środowiska.
                    unset=cfg.get('runtime',{}).get('env_unset',[])
                    if not isinstance(unset,list) or len(unset)>20 or not all(isinstance(n,str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}',n) for n in unset):
                        raise Blocked('runtime.env_unset: wymagana lista do 20 nazw zmiennych')
                    part_spec=dict(spec,env=[item for item in part.get('env',spec['env']) if item['name'] not in unset],bootstrap_variables=part.get('bootstrap_variables',[]))
                    app_env=dummy_env(part_spec,'postgresql://helix@127.0.0.1:1/helix',port,public_origin)
                    self.env=dict(app_env,**base_env)
                    execution_env=dict(base_env,PATH=self.env['PATH'])
                    self.supabase_stack=None
                    if supabase_ports:
                        import helix_runtime_supabase
                        self.supabase_stack=helix_runtime_supabase.start(self,part,supabase_ports[0],supabase_ports[1],Blocked)
                        self.db=self.supabase_stack['db_url'];self.used_engine='supabase'
                        # Serwer bazy stoi w sieci kontenerów bez wyjścia (dowód w entry['supabase'].egress), nie pod izolacją procesu.
                        self.database_network_ready=True
                        rewritten,left=helix_runtime_supabase.localize_tree(self.work/part['path'],part['supabase']['ref'],public_origin,self.supabase_stack['anon'])
                        entry['supabase']=dict(self.supabase_stack['report'],origin=public_origin,rewritten_files=rewritten)
                        entry['supabase']['synthetic_data']=self.seed_supabase(part)
                        entry['supabase']['function_stubs']=self.stub_functions(part)
                        # Aplikacja nie może wystartować z adresem produkcji w kodzie: ekrany wisiałyby na żądaniach, których Helix nie przepuszcza.
                        if left:raise Blocked('supabase: adres projektu produkcyjnego pozostał w kodzie kopii roboczej: '+', '.join(left[:5]))
                        # Migracje zastosował stos; strategie schematu dla zwykłego PostgreSQL tu nie mają zastosowania.
                        part=dict(part,migrations=[],seeds=[],schema_strategies=[])
                    if not self.db: self.database()
                    if getattr(self,'used_engine',None) in ('docker','podman'):
                        self.integration_ready('postgres',part,'container',['database-fidelity.json'],self.fidelity.get('server_version'))
                    self.env.update(dummy_env(part_spec,self.db,port,public_origin)); self.env.update(execution_env)
                    if self.supabase_stack:
                        # Klient czytający adres i klucz ze środowiska dostaje lokalny stos, nie zaślepki zmiennych.
                        for item in part_spec['env']:
                            if re.search(r'SUPABASE_URL$',item['name']):self.env[item['name']]=public_origin
                            elif re.search(r'SUPABASE_(?:ANON|PUBLISHABLE)(?:_KEY)?$|SUPABASE_KEY$',item['name']):self.env[item['name']]=self.supabase_stack['anon']
                    self.start_sinks(part,public_origin or f'http://127.0.0.1:{port}')
                    from helix_runtime_adapters import prepare as prepare_adapters
                    prepare_adapters(self,part,entry['adapters'],cfg,HOME)
                    self.select_schema(part)
                    if selected_identity is not None:self.start_planned_keycloak(part,selected_identity)
                    # Aplikacja na Supabase loguje przez lokalny stos; zaślepka OIDC i jej diagnostyczny wynik auth-flow tu nie dotyczą.
                    elif not self.supabase_stack:self.oidc(part)
                    self.refresh_sink_input()
                    if self.active_transport:self.apply_https_trust(self.active_transport,self.current_identity_tls)
                    if part.get('oidc_stub',{}).get('status')=='synthetic':
                        self.integration_ready('oidc',part,'emulator',['logs/oidc.log',self.last_log],VERSION)
                    database_spec=dict(spec,migrations=part['migrations'],seeds=part['seeds'])
                    self.migrate(dict(database_spec,migrations=[m for m in part['migrations'] if m['kind']=='sql']),seed=False)
                    self.install(part)
                    self.migrate(database_spec)
                    self.setup_commands(part)
                    # Migrations above must see the ephemeral database, too.
                    if part['build']: self.project_command(part['build'],self.work/part['path'],maximum=300,phase='build')
                    if self.tools.get('node'):
                        from helix_visual import runtime_weight
                        weight_result=runtime_weight(self.measurement_command,self.tool('node'),self.work/part['path'],
                            self.out/'visual'/str(len(report['parts']))/'weight')
                    if not part['start']: raise Blocked('start command not detected')
                    if composed and composed['part'] is not None:
                        self.start_backend(composed['part'],composed['port'],public_origin,spec,base_env,len(report['parts']))
                        for name in part['backend']['env']:self.env[name]='http://127.0.0.1:'+str(composed['port'])
                        entry['backend']['status']='RUNNING'
                    argv=[str(x).replace('{port}',str(port)) for x in part['start']]
                    if part['framework'] in ('react','vue','svelte','astro','nuxt','angular') and argv[:1]!=['node']:
                        argv+=(['--'] if part['package_manager']=='npm' else [])+['--port',str(port),'--host','127.0.0.1']
                    log=self.out/'logs'/('start-'+str(len(report['parts']))+'.log')
                    start_log=log
                    executed_start=argv
                    if self.active_transport:self.start_https(self.active_transport)
                    for attempt in range(2):
                        if attempt:
                            log=self.out/'logs'/('start-'+str(len(report['parts']))+'-retry.log'); start_log=log
                        try:
                            self.resource_wait()
                            self.note_tool(argv)
                            private_dir=self.tmp/'private-startup';private_dir.mkdir(mode=0o700,exist_ok=True)
                            raw_log=private_dir/log.name
                            fd=os.open(raw_log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
                            self.private_logs[log]=raw_log
                            proc=self.project_spawn(argv,self.work/part['path'],self.env,raw_log,phase='application')
                            self.cleanup_actions.append(lambda p=proc:self.executor.stop(p))
                            self.startup_text(log)
                            url=(public_origin or f'http://127.0.0.1:{port}')+'/'
                            health_errors=[]
                            # Retry a port explicitly advertised by the local server.
                            advertised=self.startup_text(log)
                            advertised_port=re.search(r'https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::\]):(\d+)',advertised)
                            if (selected_identity is not None or self.active_transport) and advertised_port and int(advertised_port[1])!=port:
                                raise Blocked('Keycloak callback port differs from application advertised port; no silent redirect rewrite')
                            if self.active_transport and re.search(r'https://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::\]):',advertised):
                                raise Blocked('HTTPS front requires the fixed HTTP backend scheme')
                            if advertised_port and not self.active_transport and not composed: url='http://127.0.0.1:'+advertised_port[1]+'/'
                            for route in part['routes'][:6]:
                                candidate=url.rstrip('/')+route
                                try:
                                    if self.active_transport:
                                        url=self.executor.health(candidate,self.budget.remaining(10),ca_file=self.active_transport['ca_bundle']) or candidate
                                        proxy=self.active_transport['process']
                                        if hasattr(proxy,'poll') and proxy.poll() is not None:raise Blocked('HTTPS front exited during healthcheck')
                                    else:url=self.executor.health(candidate,self.budget.remaining(10)) or candidate
                                    self.budget.remaining(.001)
                                    break
                                except Blocked as error:
                                    if hasattr(proc,'poll') and proc.poll() is not None: raise
                                    advertised=self.startup_text(log)
                                    match=re.search(r'https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::\]):(\d+)',advertised)
                                    if match and int(match[1])!=port:
                                        if selected_identity is not None or self.active_transport:
                                            raise Blocked('Keycloak callback port changed during healthcheck; no silent redirect rewrite')
                                        candidate='http://127.0.0.1:'+match[1]+route
                                        url=self.executor.health(candidate,self.budget.remaining(10)) or candidate
                                        break
                                    health_errors.append(route+': '+str(error))
                            else: raise Blocked('public route healthchecks failed: '+'; '.join(health_errors))
                            expected_origin=public_origin or f'http://127.0.0.1:{port}'
                            if (selected_identity is not None or self.active_transport) and (urlparse(url).scheme+'://'+urlparse(url).netloc!=expected_origin):
                                raise Blocked('Keycloak callback origin differs from application health result; no silent redirect rewrite')
                            if hasattr(proc,'poll') and proc.poll() is not None: raise Blocked('application exited during startup')
                            if self.active_transport:entry['transport'].update(status='ready',tls_health='verified_by_executor_ca_probe')
                            else:entry['transport'].update(status='ready')
                            startup_attempts.append(dict(status='RUNNING',log=str(log.relative_to(self.out))))
                            # Sprawdzenia ekranowe dotyczą tras, które Helix zna. Gdy jedyną znaną trasą części jest adres główny,
                            # a ten odpowiada poprawnie czymś innym niż HTML, nie ma ekranu do zmierzenia.
                            if part['routes']==['/'] and getattr(self.executor,'non_html',None) and self.executor.non_html(url):entry['api_only']=part['api_only']='non-HTML content'
                            break
                        except Blocked:
                            code=proc.poll() if hasattr(proc,'poll') else None
                            failure=startup_failure(self.startup_text(log),code)
                            if code is None and not re.search(r'error|exception|fatal|invalid|failed',self.startup_text(log),re.I):
                                failure.update(status='BLOCKED',cause='application did not become HTTP ready')
                            startup_attempts.append(dict(failure,log=str(log.relative_to(self.out))))
                            if failure['category']=='env' and attempt==0:
                                name=next((n for n in re.findall(r'\b[A-Z][A-Z0-9_]{2,}\b',failure['cause']) if n in self.env and n!='PORT'),None)
                                if name and name not in RESERVED_ENV and not (selected_identity is not None and name in selected_identity.get('env_roles',{})) and not (self.active_transport and (url_role(name)=='app-url' or name in ('NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','REQUESTS_CA_BUNDLE','HELIX_RUNTIME_TLS_SPKI_LIST'))):
                                    value=typed_dummy(name)
                                    if re.search(r'numeric|number|integer',failure['cause'],re.I): value='1'
                                    if value != self.env[name]:
                                        self.executor.stop(proc); self.env[name]=value
                                        continue
                            raise Blocked(f"{failure['status']} ({failure['category']}, exit={code}): {failure['cause']}")

                except (Blocked,OSError,subprocess.TimeoutExpired) as e:
                    reason=str(e)
                    if self.active_transport:entry['transport'].update(status='blocked',reason=self.redact_private(reason))
                    if start_log is not None and start_log.exists():
                        tail=self.startup_text(start_log)[-4000:]
                        reason+='; startup log '+str(start_log.relative_to(self.out))+': '+tail.strip()
                entry['startup']=dict(status=startup_attempts[-1]['status'] if startup_attempts else 'BLOCKED',attempts=startup_attempts,reason=reason,auth_bypass_variables=part.get('auth_bypass_variables',[]),url_roles=part.get('url_roles',{}),oidc=part.get('oidc_stub'),keycloak=part.get('keycloak'),build=part['build'],start=executed_start or part['start'],assigned_port=port,observed_port=urlparse(url).port if url else None,host='127.0.0.1',url=url,health=getattr(self.executor,'last_health',{}))
                if startup_attempts:
                    entry['startup'].update({key:startup_attempts[-1][key] for key in ('cause','exit_code','category') if key in startup_attempts[-1]})
                entry['database']=dict(strategies=part.get('schema_strategies',[]),selection=part['schema_selection'],association=part['database_association'],migrations=part['migrations'],seeds=part['seeds'],limitations=list(self.migration_notes))
                variants,findings=database_variants(part.get('schema_strategies',[]))
                entry['database'].update(variants=variants,selected=[g['strategy'] for g in part.get('schema_strategies',[])],selection_reason=[g.get('selection_reason') for g in part.get('schema_strategies',[])])
                entry['findings']=findings+target_findings(self.fidelity['target'])
                entry['coverage']=('Public routes only; Keycloak form/OIDC phases reported separately; session and protected routes NOT_RUN.' if part.get('keycloak') else
                                   'Public routes and synthetic OIDC login when configured; real identities and provider policies are not covered.')
                self.scenario_sessions=[];self.scenario_files=[];self.scenario_screen=None;self.scenarios_done=None
                if reason is None and getattr(self,'supabase_stack',None):
                    # Konto syntetyczne zalogowane w lokalnym Supabase: sesja w postaci, w jakiej trzyma ją klient w przeglądarce.
                    from helix_runtime_supabase import storage_state
                    state=self.project_temporary()/'supabase-session.json'
                    fd=os.open(state,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
                    with os.fdopen(fd,'w') as stream:json.dump(storage_state(entry['supabase']['origin'],self.supabase_stack['session']),stream)
                    self.scenario_screen=state
                screen=self.screen_session(part) if reason is None else None
                if reason is None and not screen and self.config.get('runtime',{}).get('scenarios'):
                    # Bez roli z Keycloaka scenariusze idą przed sprawdzeniami: logowanie własne aplikacji daje sesję także dla e2e.
                    try:self.scenarios_done=self.run_scenarios(part,url,None,len(report['parts']))
                    except (Blocked,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:self.scenarios_done=dict(status='BLOCKED',reason=str(error)[:300],scenarios=[])
                def route_audits():
                    if 'route-review' in self.skip:   # np. dokończenie pakietu UX, gdy trasy przejrzał wcześniejszy przebieg
                        entry['legacy_audits']=dict(status='SKIPPED',reason='explicit --skip',visual=[],weight=weight_result)
                    elif entry.get('api_only'):
                        entry['legacy_audits']=dict(status='not-applicable',reason='API part without HTML screens',visual=[],weight=weight_result)
                    elif reason is None and self.tools.get('node'):
                        import helix_visual
                        state=self.screen_file(part)
                        entry['legacy_audits'] = helix_visual.runtime_audits(
                            self.measurement_command, self.tool('node'), self.work/part['path'],
                            f'{urlparse(url).scheme}://{urlparse(url).netloc}', part['routes'], self.out/'visual'/str(len(report['parts'])), weight_result=weight_result, storage_state=state, throttled=throttled_paths(cfg),
                            session_for=lambda route:self.route_session(route,state), ui_args=ui_audit_args(cfg),
                            renew=lambda route:self.renew_sessions(part,url,screen,len(report['parts']),route), patterns=part.get('route_patterns') or ())
                    else:
                        entry['legacy_audits'] = dict(status='needs-runtime', reason=reason or 'missing Node.js', weight=weight_result)
                # Przegląd tras idzie po sprawdzeniach: ma wtedy sesję roli ekranów (jeśli zadeklarowana) i stan przepełniony danych.

                # Plik sesji znika także wtedy, gdy sprawdzenie albo przegląd tras przerwie wyjątek.
                try:
                    for check in CHECKS:
                        log=self.out/'logs'/f'part-{len(report["parts"])}-{check}.log'
                        status='BLOCKED'; metrics={}; message=reason or ''
                        if check in self.skip: status='SKIPPED'; message='explicit --skip'
                        elif check=='schema-apply' and getattr(self,'supabase_stack',None):
                            applied=entry['supabase']['migrations'];metrics=dict(applied=applied['files']-applied['with_errors'],failed=applied['with_errors'],selected=applied['files'],failed_statements=applied['failed_statements'],source=entry['supabase']['fidelity'])
                            status='FAIL' if applied['with_errors'] else 'PASS'
                            message=f"{metrics['applied']} applied / {metrics['failed']} failed"+(('; first error: '+str(applied['examples'][0]['error'])) if applied['examples'] else '')
                        elif check=='backup' and getattr(self,'supabase_stack',None): status='SKIPPED'; message='local Supabase stack: the database server is managed by Supabase; dump and restore of the project database are not part of this run'
                        elif check in ('a11y','lighthouse') and entry.get('api_only'): status='SKIPPED'; message='the only route known for this part (/) answers '+entry['api_only']+': no HTML screen to measure'
                        elif check=='schema-apply' and self.db is not None:
                            failures=[n for n in self.migration_notes if n['path'] in {m['path'] for m in part['migrations']}]
                            attempted=[m for m in part['migrations'] if m['path'] in self.applied]
                            metrics=dict(applied=len(attempted)-len(failures),failed=len(failures),selected=len(part['migrations']))
                            metrics.update(strategies=[dict(strategy=g['strategy'],tag=g['tag'],candidates=len(g['candidates']),results=g.get('results',[]),duplicates=g['duplicates']) for g in part.get('schema_strategies',[])],error_categories=error_summary(failures))
                            status='FAIL' if failures or len(attempted)<len(part['migrations']) else 'PASS'
                            metrics['findings']=[dict(path=n['path'],line=n.get('line',1),tag='ASSUMPTION',cause='Helix strategy error' if n.get('duplicate') else 'probable project dependency problem' if 'does not exist' in n['reason'] and not any(f.get('duplicate') for f in failures) else 'SQL application failure') for n in failures]
                            message=f"{metrics['applied']} applied / {metrics['failed']} failed"+(('; first error: '+first_error(failures[0]['reason'])) if failures else '')
                        elif reason is None and check in ('e2e','a11y','lighthouse') and getattr(self.executor,'last_health',{}).get('status',0)>=500:
                            status='FAIL'; metrics=dict(http_status=self.executor.last_health['status'])
                            message='HTTP '+str(self.executor.last_health['status'])+': '+(next((line.strip() for line in self.startup_text(start_log).splitlines() if re.search(r'Error|Exception|error:',line)), 'server error') if start_log and start_log.exists() else 'server error')
                        elif reason is None or check=='backup' and self.db is not None:
                            message=''
                            begin=self.steps
                            try:
                                status,metrics=self.measure(check,part,url,budgets)
                                if status=='FAIL':
                                    if metrics.get('cause'): message=metrics['cause']
                                    elif metrics.get('errors'): message='; '.join(e if isinstance(e,str) else str(e.get('route','/'))+': '+str(e.get('id',e)) for e in metrics['errors'][:5])
                                    elif 'budgets' in metrics: message='; '.join(f'{k}={metrics[k]} vs budget {v}' for k,v in metrics['budgets'].items() if k in metrics and (metrics[k]<v if k=='performance' else metrics[k]>v if check=='lighthouse' else metrics[k]>=v))
                                if check=='backup': message=('no application tables; see schema-apply' if metrics.get('tables')==0 else 'dump and restore row counts and checksums match' if status=='PASS' else 'dump and restore row counts or checksums differ')

                            except ResourcePaused as e:
                                metrics=getattr(e,'metrics',{})
                                log.write_text(self.redact_private(str(e)+'\n'+json.dumps(metrics)+'\n'))
                                entry['checks'][check]=dict(status='BLOCKED',metrics=metrics,log=log.relative_to(self.out).as_posix(),reason=str(e))
                                raise
                            except (Blocked,OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
                                message=str(e)
                                if check=='backup':
                                    status='FAIL'; metrics=dict(verification_completed=False,schema_apply_failed=len(self.migration_notes))
                            command_logs=[f'logs/{i:03d}.log' for i in range(begin+1,self.steps+1)]
                            log.write_text('\n'.join((self.out/p).read_text() for p in command_logs if (self.out/p).exists()))
                        if not log.exists(): log.write_text(self.redact_private(message+'\n'))
                        else:
                            with log.open('a') as f: f.write(self.redact_private('\n'+status+': '+message+'\n'+json.dumps(metrics)+'\n'))
                        if status=='FAIL' and start_log and start_log.exists() and any(r.get('source')=='app' and r.get('status',0)>=500 for r in metrics.get('requests',[])):
                            sql_error=next((line.strip() for line in self.startup_text(start_log).splitlines() if re.search(r'relation .+ does not exist',line)),None)
                            if sql_error: message+='; partial schema: '+sql_error+'; evidence: '+str(start_log.relative_to(self.out))
                        if check=='e2e' and metrics.get('auth_flow'):
                            metrics['auth_flow']=normalize_legacy_auth(metrics['auth_flow'])
                            entry['checks']['auth-flow']=dict(status='BLOCKED',metrics=metrics['auth_flow'],log=log.relative_to(self.out).as_posix(),reason='NO_EXPLICIT_IDENTITY_POLICY: legacy OIDC navigation is diagnostic; application session and authorization NOT_RUN')
                        if check=='e2e' and reason is None and self.db is not None and 'e2e' not in self.skip:
                            # Dwa stany danych w jednym przebiegu: najpierw zdjęcie każdego ekranu przy skąpych danych (jeden wiersz, puste listy),
                            # potem zasiew stanu przepełnionego, na którym idą a11y, szybkość, obciążenie i pełny przegląd tras.
                            entry['data_states']=self.data_states(part,url,screen,len(report['parts']))
                        if check in ('e2e','a11y') and reason is None and check not in self.skip and getattr(self,'scenario_sessions',None):
                            status,metrics=self.scenario_pass(check,part,url,budgets,status,metrics)
                            if status=='FAIL':message=metrics.get('cause') or '; '.join(str(e) for e in metrics.get('errors',[])[:5])
                            elif status=='PASS':message=''
                        entry['checks'][check]=dict(status=status,metrics=metrics,log=log.relative_to(self.out).as_posix(),reason=message or ('budgets met' if status=='PASS' else 'check failed: '+json.dumps(metrics)[:600]))
                    route_audits()
                    self.ux_pack(part,url,entry,len(report['parts']))
                finally:
                    if screen:
                        established=screen['path'].is_file()
                        entry['screen_session']=dict(role=screen['role'],status='USED' if established else 'NOT_ESTABLISHED',
                                                     scope='e2e, a11y, route audit, lighthouse and load of this part; never exported outside the run')
                        screen['path'].unlink(missing_ok=True)
                    for path in getattr(self,'scenario_files',[]):path.unlink(missing_ok=True)
                    shutil.rmtree(self.project_temporary()/'role-sessions',ignore_errors=True)
                    self.scenario_sessions=[];self.scenario_files=[];self.scenario_screen=None
                if reason is None:
                    from helix_runtime_adapters import pdf_probe, inbound_replay
                    if entry['adapters']['pdf']['required']:
                        entry['checks']['pdf-render']=pdf_probe(self,HOME)
                    if entry['adapters']['replay']['inbound_enabled']:
                        entry['checks']['inbound-replay']=inbound_replay(self,part,url,HOME,cfg)
                entry['fetch_failures']=[]
                if start_log is not None and start_log.exists():
                    for payload in re.findall(r'HELIX_FETCH_FAILURE (\{[^\n]+\})',read(start_log)):
                        try: diagnostic=json.loads(payload)
                        except ValueError: continue
                        if diagnostic not in entry['fetch_failures']: entry['fetch_failures'].append(diagnostic)
                if proc and not self.keep:
                    self.executor.stop(proc)
                    self.cleanup_actions.pop()
                    if reason is None:
                        from helix_runtime_adapters import utc_smoke
                        entry['checks']['timezone-utc']=utc_smoke(self,part,executed_start,url)
                elif proc:
                    entry['adapters']['timezone']['utc_status']='NOT_RUN_KEEP'
        except ResourcePaused as e:
            report.update(reason=str(e),run_status='resource_paused',partial=True,resource_pause=e.decision)
        except (Blocked,Interrupted) as e:
            report['reason']=str(e)
        finally:
            if resource_monitor is not None:resource_monitor.__exit__(None,None,None)
            if not self.keep:
                for action in list(reversed(self.database_cleanup))+list(reversed(self.cleanup_actions)):
                    try: action()
                    except (OSError,Blocked,subprocess.SubprocessError): pass
                for public in self.private_logs:self.startup_text(public)
                shutil.rmtree(self.tmp,ignore_errors=True)
            else:
                for handle in self.sink_handles:
                    if handle.get('process') is not None:self.collect_sink(handle)
                for public in self.private_logs:self.startup_text(public)
                report['kept_directory']=str(self.tmp)
            for sig,handler in old_handlers.items(): signal.signal(sig,handler)
            try:
                if report.get('run_status')!='resource_paused':self.collect_tool_versions()
            except Exception:report['provenance']['collection_status']='partial; version metadata unavailable'
            report['provenance']['tools']=normalize_tools(dict(python=report['provenance']['tools']['python'],**{k:v for k,v in getattr(self,'execution_tools',{}).items() if k!='python'}))
            if getattr(self,'execution_tools',{}).get('python'):report['provenance']['runtime_python']=normalize_tools({'python':self.execution_tools['python']})['python']
            if self.resources is not None:
                report['resources']=dict(requested_jobs=self.resources.requested_jobs,policy=self.resources.policy,decisions=self.resources.history,
                                         current=getattr(self,'resource_last',None),current_artifact='resource-current.json',history_artifact='resource-decisions.jsonl')
        # Admission can stop before the copy or before any app starts. Keep the
        # planned parts visible so every unexecuted control has a BLOCKED row.
        recorded_names={entry['name'] for entry in report['parts']}
        report['parts'].extend(dict(name=part['name'],path=part['path'],checks={}) for part in parts if part['name'] not in recorded_names)
        for entry in report['parts']:
            if 'transport' not in entry:
                declaration=next(row for row in self.transport_plans['parts'] if row['part']==entry['path'])
                entry['transport']=dict(selected=declaration['selected'],status='not_checked',gaps=declaration['gaps'],limits=declaration['limits'],cleanup='not_needed')
        for part_index,entry in enumerate(report['parts']):
            for check in CHECKS:
                if check not in entry['checks']:
                    log=self.out/'logs'/f'interrupted-{part_index}-{check}.log'
                    log.write_text(report.get('reason','runtime interrupted')+'\n')
                    entry['checks'][check]=dict(status='BLOCKED',metrics={},log=log.relative_to(self.out).as_posix(),reason=report.get('reason','runtime interrupted'))
        report={'database_fidelity':self.fidelity,**report}
        # Opting into an incompatible backend permits investigation, not credit
        # for verification against the project's required database version.
        if self.fidelity['compatible'] is False:
            for part in report['parts']:
                for check in ('schema-apply','backup','load'):
                    result=part['checks'].get(check)
                    if result and result['status'] in ('PASS','FAIL'):
                        result.update(status='DEGRADED',reason='WARN: database version mismatch; '+result['reason'])
                        with (self.out/result['log']).open('a') as log: log.write('\nDEGRADED: database version mismatch\n')
        report['engine']=getattr(self,'used_engine',None)
        for part in report['parts']:
            for name,result in part['checks'].items():
                # Every control must carry a concrete reason and log pointer, even partial ones (e.g. auth-flow).
                if not result.get('reason'):
                    m=result.get('metrics') or {}
                    result['reason']=('broken at '+str(m.get('break_at'))) if m.get('break_at') else (result.get('status','UNKNOWN').lower()+' without detailed reason')
                result.setdefault('log',f'logs/{name}.log')
        statuses={c['status'] for p in report['parts'] for c in p['checks'].values()}
        report['status']='BLOCKED' if not report['parts'] else next((s for s in ('FAIL','BLOCKED','DEGRADED','SKIPPED','PASS') if s in statuses))
        if report.get('run_status')=='resource_paused' and report['status']=='PASS':report['status']='BLOCKED'
        from helix_runtime_integrations import execution_inventory
        report['measurement_status']=report['status']
        if self.container_endpoints:report['container_endpoints']=dict(self.container_endpoints)
        from helix_runtime_transport import derive_transport_coverage
        report['transport_coverage']=derive_transport_coverage(self.transport_plans,report['parts'])
        if report['transport_coverage']=='INCOMPLETE' and report['status']=='PASS':report['status']='INCOMPLETE'
        if getattr(self,'startup_log_errors',None):
            report.update(partial=True,startup_log_gaps=list(self.startup_log_errors.values()))
            if report['status']=='PASS':report['status']='INCOMPLETE'
        report['sink_observations']=list(self.sink_observations.values())
        report['integration_receipts']=self.integration_receipts
        report['integrations']=execution_inventory(self.integration_plan,self.integration_receipts,run_id=self.run_id)
        report['identity_forms']=list(self.identity_forms.values())
        report['identity_policy_executions']=list(self.identity_policy_executions.values())
        report['webauthn_executions']=list(self.webauthn_executions.values())
        from helix_runtime_login import project_identity
        report['identity_coverage']=project_identity(report)['status']
        from helix_runtime_identity_policy_run import derive_identity_assessment
        report['identity_assessment']=derive_identity_assessment(report)
        assessment=report['identity_assessment']
        if assessment['status']=='INCOMPLETE' and report['status']=='PASS':report['status']='INCOMPLETE'
        if assessment['outcome']=='FAIL' and report['status'] not in ('BLOCKED','INCOMPLETE'):report['status']='FAIL'
        from helix_runtime_webauthn_run import project_webauthn_execution
        webauthn=project_webauthn_execution(report)
        report['webauthn_coverage']=webauthn['coverage_status']
        if report['webauthn_coverage']=='INCOMPLETE' and report['status']=='PASS':report['status']='INCOMPLETE'
        if webauthn['outcome']=='FAIL' and report['status'] not in ('BLOCKED','INCOMPLETE'):report['status']='FAIL'
        report['coverage_status']='INCOMPLETE' if report['integrations']['status']!='RECORDED' else 'RECORDED'
        if report['coverage_status']=='INCOMPLETE' and report['status']=='PASS':report['status']='INCOMPLETE'
        if integration_failures(report['integrations']):report['status']='FAIL'
        report['network_isolation']=network_isolation_record(self.network_records)
        if report['network_isolation']['status']!='ENFORCED' and report['status']=='PASS':report['status']='INCOMPLETE'
        self.save_network_isolation()
        report['controls']=[dict(result,id=name,part=part['name']) for part in report['parts'] for name,result in part['checks'].items()]
        report=self.redact_private(report)
        try: validate_report(report)
        except ValueError:
            # Keep the evidence for diagnosis; the run still fails loudly.
            (self.out/'runtime-report.invalid.json').write_text(json.dumps(report,indent=2,default=str)+'\n')
            raise
        (self.out/'runtime-report.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
        lines=['# Helix runtime','', 'VERIFIED: wyniki dotyczą wyłącznie kopii i danych syntetycznych.','', 'Metadane wykonania: Helix '+VERSION+'; target '+str(report['provenance']['target_head'])+'; dirty='+str(report['provenance']['target_dirty'])+'; pełne wersje: runtime-report.json/provenance.','']
        if report.get('resources'):
            lines += ['Zasoby: '+report.get('run_status','finished')+'; decyzje i progi: resource-decisions.jsonl. Parametry k6, SLO i lista tras zachowane.','']
        if report.get('run_status')=='resource_paused':lines += ['INCOMPLETE: '+report['reason']+'. Zachowano częściowe pomiary; ponów runtime z nowym katalogiem wyników po zwolnieniu zasobów.','']
        lines += ['Pokrycie integracji: '+report['coverage_status']+'; wynik wykonanych pomiarów: '+report['measurement_status']+'. Gotowość usługi nie potwierdza wykonania trasy.','']
        for integration in report['integrations']['integrations']:
            lines.append('- '+integration['provider']+' ['+integration['area']+']; części: '+(', '.join(integration['parts']) or 'nieustalone')+'; strategia: '+str(integration['strategy']['selected'])+'; adapter: '+('dostępny' if integration['strategy']['implemented'] else 'brak')+'; gotowość: '+integration['execution']['readiness']+'; pokrycie: '+integration['coverage']['status']+'. '+ '; '.join(integration['coverage']['untested_because']))
        for failure in integration_failures(report['integrations']):lines.append('- FAIL integracji '+failure['provider']+': '+failure['method']+' '+failure['route']+'; dowód: '+failure['evidence'])
        lines += ['Pełne miejsca path:line, trasy i luki: runtime-report.json/integrations.','']
        lines[2:2]=self.fidelity['warnings']+[self.fidelity['target']['tag']+': Database '+json.dumps({k:v for k,v in self.fidelity.items() if k!='target'})+'; target '+str(self.fidelity['target']['major']),self.fidelity['target']['assumption'] or '', 'Evidence: '+json.dumps(self.fidelity['target']['evidence'][:5])+'; full list: runtime-report.json/database_fidelity/target/evidence']
        lines += ['Transport: '+report['transport_coverage']+'. HTTPS i localhost nie potwierdzają loginu, cookies ani WebAuthn. Pełne deklaracje i luki: runtime-report.json/transport_plan.','']
        identity=project_identity(report)
        lines += ['Formularz i fazy OIDC: '+identity['form_status']+'. Dowód formularza jest odrębny od polityki sesji i tras. Szczegóły: runtime-report.json/identity_forms.','']
        from helix_runtime_policy_receipts import project_policy_plan
        policy=project_policy_plan(report)
        lines += ['Plan jawnej polityki: '+policy['plan_status']+'; przypadki: '+str(policy['counts']['required_cells'])+'. Wykonanie: '+assessment['policy_execution_status']+'; pokrycie: '+assessment['coverage_status']+'; wynik: '+assessment['outcome']+'. Szczegóły: runtime-report.json/identity_policy_executions.','']
        lines += ['WebAuthn: plan '+webauthn['plan_status']+'; wykonanie '+webauthn['execution_status']+'; pokrycie '+webauthn['coverage_status']+'. Deklaracja klucza nie potwierdza ceremonii. Szczegóły: runtime-report.json/webauthn_executions.','']
        for part in report['parts']:
            lines.append('Część: '+part['name'])
            if part.get('transport'):lines.append('Transport części: '+json.dumps(part['transport'],ensure_ascii=False))
            lines.append(part.get('coverage',''))
            if part.get('startup'): lines.append('Startup: '+json.dumps(part['startup'],ensure_ascii=False))
            if part.get('adapters'):
                adapters=part['adapters']
                lines.append('Adaptery: TZ '+adapters['timezone']['primary']+' (deklaracja, bez dowodu produkcji); WhatsApp disabled; crony disabled: '+', '.join(adapters['cron']['env_names']+adapters['cron']['routes']))
                lines.append('PDF: '+adapters['pdf']['status']+'; worker: '+adapters['worker']['status']+'; replay: '+adapters['replay']['status']+'. Konfiguracja nie zalicza wykonania.')
                if adapters['native']['packages']:lines.append('WARN native: '+', '.join(adapters['native']['packages'])+'; '+adapters['native']['warning'])
            selection=part.get('database',{}).get('selection',{})
            if selection: lines.append('Schema: '+selection['rule']+'; files: '+str(selection['count'])+'; examples: '+', '.join(selection['examples'])+'; full list: runtime-report.json/parts/database/migrations')
            if part.get('fetch_failures'): lines.append('VERIFIED: fetch failures: '+json.dumps(part['fetch_failures']))
            for group in part.get('database',{}).get('strategies',[]):
                lines.append('Schema candidates: '+str(len(group['candidates']))+'; selected: '+group['strategy'])
                if group.get('selection_reason'): lines.append('ASSUMPTION: '+group['selection_reason'])
                if group.get('network_isolation'): lines.append('Network isolation: '+group['network_isolation'])
                if group.get('results'): lines.append('ASSUMPTION: candidate trials: '+', '.join(c['strategy']+': '+str(c['applied'])+' applied / '+str(c['failed'])+' failed'+(' (incomplete)' if c.get('incomplete') else '') for c in group['results']))
                # Full variant detail is in the JSON ledger below.
                if group['duplicates']: lines.append('VERIFIED: duplicate table creators: '+str(len(group['duplicates']))+'; examples: '+', '.join(d['object'] for d in group['duplicates'][:5])+'; full list: runtime-report.json/parts/database/strategies')
            lines.extend(['| # | Variant | Status | Applied / failed | First error | Log | Seconds |','|---|---|---|---|---|---|---|'])
            for v in part.get('database',{}).get('variants',[])[:10]:
                lines.append('| '+ ' | '.join(str(x).replace('|','/').replace('\n',' ') for x in (v['order'],v['name'],v['status'],str(v['applied'])+' / '+str(v['failed']),v.get('first_error_location') or v.get('first_error'),', '.join(v.get('logs',[])),v['seconds']))+' |')
            lines.append('Full variants: runtime-report.json/parts/database/variants')
            for finding in part.get('findings',[]): lines.append('VERIFIED: project finding '+json.dumps(finding,ensure_ascii=False))
            for category in part['checks'].get('schema-apply',{}).get('metrics',{}).get('error_categories',[]):
                lines.append('SQL '+category['category']+': '+str(category['count'])+'; '+', '.join(e['path']+':'+str(e['line'])+' '+e['error'].splitlines()[-1][:160] for e in category['examples']))
            notes=part.get('database',{}).get('limitations',[])
            if notes: lines.append('Ograniczenia migracji: '+str(len(notes))+'; maks. 5 przykładów; pełna lista: runtime-report.json/parts/database/limitations')
            for note in notes[:5]:
                lines.append('Migracja pominięta: '+note['path']+' — '+note['reason'][-300:].replace('\n',' ')+'; '+note['log'])
            lines.append('Pełna lista migracji i decyzji seed: runtime-report.json/parts/database')
            for name,result in part['checks'].items(): lines.append(f"- {name}: {result['status']} — {result['reason']} ([log]({result['log']}))")
            seeded=(part.get('supabase') or {}).get('synthetic_data')
            if seeded: lines.append('Dane syntetyczne (model): '+str(seeded.get('status'))+'; tabel wypełnionych '+str(len(seeded.get('filled') or []))+' z '+str(seeded.get('empty_tables'))+' pustych, wierszy '+str(seeded.get('rows'))+', błędów '+str(len(seeded.get('errors') or []))+(' ('+seeded['log']+')' if seeded.get('log') else ''))
            ux=part.get('ux')
            if ux: lines.append('Pakiet UX: '+str(ux.get('status'))+(('; stron '+str(ux.get('pages'))+', sędzia: urządzeń '+str((ux.get('judge') or {}).get('devices'))+', uwag '+str((ux.get('judge') or {}).get('issues'))
                                 +'; eksplorator: zadań '+str((ux.get('explore') or {}).get('tasks'))+', osiągnięte '+str((ux.get('explore') or {}).get('reached'))+', tarcia '+str((ux.get('explore') or {}).get('friction'))
                                 +'; raport '+str(ux.get('report'))) if ux.get('report') else ('; '+str(ux.get('reason')))))
            check=part.get('legacy_audits',{}).get('self_check')
            if check:
                lines.append('Przegląd tras, kontrola własna: '+check['status']+('; '+'; '.join(check['reasons']) if check['reasons'] else ''))
                for row in check['shared_findings'][:5]: lines.append('  wspólne dla '+str(row['routes'])+' tras: '+row['finding'].replace('\n',' '))
                local=part.get('supabase')
                for row in check.get('failed_requests',[])[:8]:
                    cause=(' (funkcje serwerowe nie są uruchamiane lokalnie: brak w środowisku, nie usterka ekranu)' if local and row['path'].startswith('/functions/v1/')
                           else ' (lokalna baza nie ma danych projektu; brak wiersza może być skutkiem środowiska)' if local and row['status']==406 else '')
                    lines.append('  HTTP '+str(row['status'])+' na '+str(row['routes'])+' trasach: '+row['path']+cause)
        if not parts: lines.append('BLOCKED: nie wykryto części aplikacji.')
        (self.out/'runtime.md').write_text('\n'.join(lines)+'\n')
        return report


def route_category(route):
    value=route.casefold()
    groups={
        'auth': r'login|signin|callback|logout|logowanie|connexion|anmeld',
        'money': r'billing|payment|invoice|faktur|order|zamów|zamow|cart|checkout|quote|ofert|płat|plat|paiement|zahlung',
        'public': r'^/$|landing|docs|documentation',
    }
    return next((name for name,pattern in groups.items() if re.search(pattern,value)), 'crud')


def bare_callback_answers(data, identity_plans, part):
    """Adres zwrotny OIDC wywołany bez parametrów odpowiada 4xx z definicji; taka odpowiedź nie jest usterką ekranu.

    Trasa zostaje w próbie: gdy pod tym samym adresem jest zwykły ekran (odpowiedź spoza 4xx), jest oceniana jak każdy inny.
    """
    callbacks={path for row in (identity_plans or {}).get('parts',[]) if row.get('part')==part
               for path in (row.get('client') or {}).get('callback_paths',[])}
    bare=[row for row in data.get('routes',[]) if row.get('route') in callbacks and row.get('status')=='FAIL'
          and type(row.get('code')) is int and 400<=row['code']<500]
    if not bare:return data
    for row in bare:row.update(status='NOT_APPLICABLE',errors=[],reason='bare OIDC callback answered '+str(row['code']))
    skipped={row['route'] for row in bare}
    data['errors']=[r['route']+': '+str(r.get('errors',[])+r.get('violations',[])) for r in data['routes'] if r['status']=='FAIL']
    # Lista żądań zostaje nietknięta: zapis nie niesie parametrów, więc nie da się odróżnić gołego wywołania od prawdziwego callbacku.
    data['bare_callbacks']=sorted(skipped)
    return data


def ui_audit_args(cfg):
    """Ustawienia wyglądu projektu dla przeglądu tras (runtime.ui): drabinka pisma, cel dotyku, odstępy. Bez nich obowiązują domyślne,
    a uwagi mierzone cudzą miarą są fałszywe (np. cel dotyku 44 px w projekcie, który na komputerze przyjmuje 36)."""
    ui=cfg.get('runtime',{}).get('ui',{})
    if not isinstance(ui,dict) or set(ui)-{'ladder','tap','tap_desktop','space','lead_max'}:raise Blocked('runtime.ui: dozwolone pola ladder, tap, tap_desktop, space, lead_max')
    args=[]
    for key,flag in (('ladder','--ladder'),('space','--space')):
        if key in ui:
            if not isinstance(ui[key],list) or not ui[key] or len(ui[key])>30 or not all(type(n) in (int,float) and 0<n<=200 for n in ui[key]):raise Blocked('runtime.ui.'+key+': wymagana lista liczb')
            args+=[flag,','.join(str(n) for n in ui[key])]
    for key,flag in (('tap','--tap'),('tap_desktop','--tap-desktop'),('lead_max','--lead-max')):
        if key in ui:
            if type(ui[key]) not in (int,float) or not 0<ui[key]<=200:raise Blocked('runtime.ui.'+key+': wymagana liczba')
            args+=[flag,str(ui[key])]
    return args


def throttled_paths(cfg):
    """Ścieżki, na których aplikacja ogranicza liczbę zapytań jednego konta; 429 z nich nie obciąża ekranu w przeglądzie tras."""
    paths=cfg.get('runtime',{}).get('rate_limited_paths',[])
    if not isinstance(paths,list) or len(paths)>10 or not all(isinstance(p,str) and re.fullmatch(r'/[A-Za-z0-9._~/-]{1,200}',p) for p in paths):
        raise Blocked('runtime.rate_limited_paths: wymagana lista do 10 dokładnych ścieżek')
    return paths


class PathRouter:
    """Jeden adres dla frontendu i jego API, jak na serwerze produkcyjnym: żądania o wskazanych początkach ścieżki idą do zaplecza,
    pozostałe do frontendu. Tylko pętla zwrotna; każde połączenie obsługuje jedno żądanie (Connection: close)."""
    def __init__(self,default_port,routes):
        import socket,threading
        self.default=default_port;self.routes=dict(routes);self.closed=False;self.sockets=set();self.lock=threading.Lock();self.counts={}
        self.server=socket.create_server(('127.0.0.1',0),backlog=512);self.port=self.server.getsockname()[1]
        threading.Thread(target=self._accept,daemon=True).start()
    def _accept(self):
        import threading
        while not self.closed:
            try:client,_=self.server.accept()
            except OSError:return
            threading.Thread(target=self._serve,args=(client,),daemon=True).start()
    def target(self,path):
        for prefix,port in self.routes.items():
            if path==prefix or path.startswith(prefix+'/') or path.startswith(prefix+'?'):return port
        return self.default
    def _serve(self,client):
        import socket,select
        upstream=None
        try:
            with self.lock:self.sockets.add(client)
            client.settimeout(30);head=b''
            while b'\r\n\r\n' not in head and len(head)<65536:
                chunk=client.recv(8192)
                if not chunk:return
                head+=chunk
            if b'\r\n\r\n' not in head:return
            top,rest=head.split(b'\r\n\r\n',1);lines=top.split(b'\r\n')
            parts=lines[0].decode('latin-1').split(' ')
            if len(parts)<3 or not parts[1].startswith('/'):
                client.sendall(b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');return
            port=self.target(parts[1]);self.counts[port]=self.counts.get(port,0)+1
            headers=[line for line in lines[1:] if not line.lower().startswith((b'connection:',b'proxy-connection:',b'keep-alive:')) or b'upgrade' in line.lower()]
            if not any(line.lower().startswith(b'connection:') for line in headers):headers.append(b'Connection: close')
            # Ekran potrafi poprosić o setki plików naraz; serwer aplikacji z pełną kolejką zrywa wtedy część połączeń, zanim
            # cokolwiek odpowie. Przeglądarka sama by ponowiła odczyt, więc rozdzielacz ponawia żądania bez treści (GET, HEAD),
            # dopóki nie przyjdzie pierwszy bajt odpowiedzi; po wyczerpaniu prób odpowiada 502 zamiast zrywać połączenie.
            request=b'\r\n'.join([lines[0]]+headers)+b'\r\n\r\n'+rest
            repeatable=parts[0] in ('GET','HEAD') and not rest; first=b''
            for attempt in range(8 if repeatable else 1):
                try:
                    upstream=socket.create_connection(('127.0.0.1',port),timeout=30)
                    with self.lock:self.sockets.add(upstream)
                    upstream.sendall(request)
                    if not repeatable:break
                    upstream.settimeout(120);first=upstream.recv(65536)
                    if first:break
                    raise OSError('upstream closed before answering')
                except OSError:
                    if upstream is not None:
                        with self.lock:self.sockets.discard(upstream)
                        try:upstream.close()
                        except OSError:pass
                        upstream=None
                    if attempt==(7 if repeatable else 0) or self.closed:
                        self.refused=getattr(self,'refused',0)+1
                        client.sendall(b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');return
                    time.sleep(.05*(attempt+1))
            if first:client.sendall(first)
            client.settimeout(120);upstream.settimeout(120)
            watched=[client,upstream]
            while not self.closed:
                ready,_,_=select.select(watched,[],[],120)
                if not ready:return
                for source in ready:
                    data=source.recv(65536)
                    if not data:
                        if source is upstream:return
                        # klient skończył wysyłać: przestajemy go czytać i przekazujemy koniec dalej, odpowiedź płynie do końca
                        watched=[upstream]
                        try:upstream.shutdown(socket.SHUT_WR)
                        except OSError:pass
                        continue
                    (upstream if source is client else client).sendall(data)
        except OSError:pass
        finally:
            for sock in (client,upstream):
                with self.lock:self.sockets.discard(sock)
                try:
                    if sock:sock.close()
                except OSError:pass
    def close(self):
        import socket
        self.closed=True
        try:self.server.close()
        except OSError:pass
        with self.lock:active=list(self.sockets);self.sockets.clear()
        for sock in active:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:sock.close()
            except OSError:pass


PYTHON_REGISTRY_HOSTS=('pypi.org','files.pythonhosted.org')


class PackageProxy:
    """Pośrednik na pętli zwrotnej dla instalacji paczek w izolacji: zestawia tunel (CONNECT, port 443) wyłącznie do wskazanych
    hostów rejestru. Każde inne żądanie dostaje odmowę i trafia do spisu. Treści nie czyta: szyfrowanie zostaje między pip a rejestrem."""
    def __init__(self,hosts):
        import socket,threading
        self.hosts=frozenset(hosts);self.allowed=0;self.denied=set();self.closed=False;self.sockets=set();self.lock=threading.Lock()
        self.server=socket.create_server(('127.0.0.1',0));self.port=self.server.getsockname()[1]
        threading.Thread(target=self._accept,daemon=True).start()
    def _accept(self):
        import threading
        while not self.closed:
            try:client,_=self.server.accept()
            except OSError:return
            threading.Thread(target=self._serve,args=(client,),daemon=True).start()
    def _serve(self,client):
        import socket,select
        upstream=None
        try:
            with self.lock:self.sockets.add(client)
            client.settimeout(20);head=b''
            while b'\r\n\r\n' not in head and len(head)<8192:
                chunk=client.recv(4096)
                if not chunk:return
                head+=chunk
            line=head.split(b'\r\n',1)[0].decode('latin-1').split(' ')
            host,_,port=(line[1] if len(line)>1 else '').rpartition(':')
            if len(line)<3 or line[0]!='CONNECT' or port!='443' or host.lower() not in self.hosts:
                self.denied.add((line[1] if len(line)>1 else '?')[:80]);client.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return
            upstream=socket.create_connection((host,443),timeout=20)
            with self.lock:self.sockets.add(upstream)
            client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n');self.allowed+=1
            client.settimeout(30);upstream.settimeout(30)
            while not self.closed:
                ready,_,_=select.select([client,upstream],[],[],60)
                if not ready:return
                for source in ready:
                    data=source.recv(65536)
                    if not data:return
                    (upstream if source is client else client).sendall(data)
        except OSError:pass
        finally:
            for sock in (client,upstream):
                with self.lock:self.sockets.discard(sock)
                try:
                    if sock:sock.close()
                except OSError:pass
    def close(self):
        """Zamyka nasłuch i wszystkie otwarte tunele: po instalacji żaden proces nie ma już wyjścia przez pośrednika."""
        import socket
        self.closed=True
        try:self.server.close()
        except OSError:pass
        with self.lock:active=list(self.sockets);self.sockets.clear()
        for sock in active:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:sock.close()
            except OSError:pass


def project_python(cwd):
    """Interpreter Pythona w wersji deklarowanej przez projekt: (ścieżka, wersja). Bez deklaracji albo bez takiego interpretera: python3."""
    version=None
    for name in ('.python-version','Dockerfile.prod','Dockerfile','Dockerfile.dev'):
        try:text=(Path(cwd)/name).read_text()
        except OSError:continue
        match=re.search(r'^\s*(\d+\.\d+)',text,re.M) if name=='.python-version' else re.search(r'^\s*FROM\s+python:(\d+\.\d+)',text,re.M|re.I)
        if match:version=match[1];break
    if version:
        # Najpierw interpretery systemowe (czytelne dla izolacji); interpreter spod katalogu domowego użytkownika bywa dla niej niedostępny.
        found=next((str(path) for path in (Path(base)/('python'+version) for base in ('/opt/homebrew/bin','/usr/local/bin','/usr/bin')) if path.is_file()),None) or shutil.which('python'+version)
        if not found and shutil.which('uv'):
            try:
                done=subprocess.run(['uv','python','find',version],capture_output=True,text=True,timeout=60)
                if done.returncode==0 and Path(done.stdout.strip()).is_file():found=done.stdout.strip()
            except (OSError,subprocess.SubprocessError):pass
        if found:return found,version
    return shutil.which('python3') or 'python3',version


def older_pythons(current):
    """Starsze od bieżącego interpretery Pythona zainstalowane w systemie, od najnowszego. Wersja z nazwy pliku, bez uruchamiania."""
    try:match=re.search(r'python3\.(\d+)$',Path(current).resolve().name)
    except OSError:match=None
    if not match:return []
    found=[]
    for number in range(int(match[1])-1,max(int(match[1])-5,7),-1):
        path=next((str(path) for path in (Path(base)/('python3.'+str(number)) for base in ('/opt/homebrew/bin','/usr/local/bin','/usr/bin')) if path.is_file()),None)
        if path:found.append(path)
    return found


def target_findings(target):
    """Ustalenia o projekcie, które wyszły przy ustalaniu bazy: Helix na nich nie staje, ale właściciel ma je naprawić."""
    found=[]
    if target.get('version_divergence'):
        found.append(dict(id='database-version-divergence',severity='medium',category='data/ops',owner='project',tag='VERIFIED',
                          verification='repository files compared; not executed against production',
                          message='Pliki uruchomieniowe wskazują różne wersje bazy: produkcyjny '+str(target['major'])+', pozostałe '
                                  +', '.join(sorted({str(row['major']) for row in target['version_divergence']}))+'. Testy idą na innej wersji niż produkcja.',
                          recommendation='Ujednolić wersję bazy we wszystkich plikach compose i w CI z wersją produkcyjną.',
                          evidence=target['version_divergence'][:10]))
    if target.get('documentation_mismatch'):
        rows=[dict(path=e['path'],line=e['line'],major=e['major']) for e in target['evidence'] if e.get('strength')=='documentation' and e['major'] in target['documentation_mismatch']]
        found.append(dict(id='database-version-documentation-outdated',severity='low',category='docs',owner='project',tag='VERIFIED',
                          verification='repository files compared',
                          message='Dokumentacja podaje wersję bazy '+', '.join(str(m) for m in target['documentation_mismatch'])+', a pliki uruchomieniowe '+str(target['major'])+'.',
                          recommendation='Poprawić albo usunąć nieaktualne opisy wersji bazy.',evidence=rows[:10]))
    return found


def volume_result(output, rows):
    """Faktyczny stan po zasiewie przepełnionym: ile tabel doszło do zadanej liczby wierszy i ile wierszy ma wartości skrajne."""
    try:tables=json.loads(next(line for line in reversed(str(output).splitlines()) if line.strip().startswith('[')))
    except (StopIteration,ValueError):return dict(status='INCOMPLETE',rows_per_table=rows,reason='volume seed returned no table summary')
    work=[t for t in tables if not t.get('skipped')]
    stuck=sorted(t['tbl'] for t in work if t['after']<rows)
    extreme=sum(t['extreme'] for t in work)
    return dict(status='APPLIED' if work and extreme and not stuck else 'INCOMPLETE',rows_per_table=rows,tables=len(tables),
                tables_at_target=sum(t['after']>=rows for t in work),tables_below_target=len(stuck),below_target=stuck[:40],
                rows_with_extreme_values=extreme,rows_copied_unchanged=sum(t['copied'] for t in work),insert_failures=sum(t['failed'] for t in work),
                skipped_dictionaries=sorted(t['tbl'] for t in tables if t.get('skipped')=='dictionary or settings')[:80],
                skipped_login_data=sorted(t['tbl'] for t in tables if t.get('skipped')=='login data')[:80],
                skipped_empty=sum(t.get('skipped')=='empty' for t in tables),
                basis='measured after seeding; synthetic placeholders multiplied; no project or personal data')


def quick_routes(routes, maximum, prefixes=()):
    """Trasy przebiegu próbnego: przekrój kategorii jak w próbce oraz po jednej trasie na każdą sesję scenariusza (prefiks tras),
    żeby logowanie własne aplikacji też zostało sprawdzone."""
    kept=sample_routes(routes,maximum)
    for prefix in prefixes:
        if prefix and not any(route.startswith(prefix) for route in kept):
            kept+=[route for route in routes if route.startswith(prefix)][:1]
    return kept


def sample_routes(routes, maximum):
    # Brak limitu (domyślnie): wszystkie trasy. Próbka tylko przy jawnym runtime.budgets.route_sample.
    if maximum is None: return list(dict.fromkeys(routes))
    buckets={name:[] for name in ('auth','money','crud','public')}
    for route in dict.fromkeys(routes): buckets[route_category(route)].append(route)
    # Round robin preserves all risk categories and favors CRUD forms/details/lists.
    buckets['crud'].sort(key=lambda r: (0 if re.search(r'new|edit|create|nouveau|dodaj|nowy',r,re.I) else 1 if re.search(r'\[|:',r) else 3 if re.search(r'\d',r) else 2,r))
    selected=[]
    while any(buckets.values()) and len(selected)<maximum:
        for bucket in buckets.values():
            if bucket and len(selected)<maximum: selected.append(bucket.pop(0))
    return selected


def migration_winner(results, recommended):
    return max(results,key=lambda r:(r.get('objects',0),r.get('applied',0),r['strategy']==recommended))


def legacy_auth_claim_unverified(value):
    """One predicate for affirmative legacy claims at ingestion and import."""
    if not isinstance(value,dict):return False
    if value.get('status')=='PASS':return True
    if any(value.get(field) in ('PASS','COMPLETE','RECORDED') for field in ('session_coverage','authorization_coverage')):return True
    steps=value.get('steps',[])
    return isinstance(steps,list) and any(isinstance(row,dict) and row.get('step') in ('session','protected-route') and
        type(row.get('code')) is int and 200<=row['code']<300 for row in steps)


def normalize_legacy_auth(value):
    """Keep navigation observations, never infer identity from cookies/redirects."""
    value=value if isinstance(value,dict) else {}
    allowed={'login','authorize','callback','app','stub'}
    rows=value.get('steps',[]);rows=rows if isinstance(rows,list) else []
    steps=[];ignored=value.get('legacy_claims_ignored') is True or legacy_auth_claim_unverified(value)
    for row in rows:
        if not isinstance(row,dict):continue
        if not isinstance(row.get('step'),str) or row['step'] not in allowed:
            ignored|=row.get('step') in ('session','protected-route');continue
        code=row.get('code')
        item=dict(step=row['step'],code=code if type(code) is int and 100<=code<=599 else None)
        raw=row.get('url')
        if isinstance(raw,str) and len(raw)<=4096 and not re.search(r'[\x00-\x1f\x7f]',raw):
            try:
                parsed=urlparse(raw)
                if parsed.scheme in ('http','https') and parsed.hostname in ('localhost','127.0.0.1') and not parsed.username and not parsed.password:
                    port=parsed.port
                    if port is None or 1<=port<=65535:
                        item['url']=parsed.scheme+'://'+parsed.hostname+(':'+str(port) if port is not None else '')+parsed.path
            except ValueError:pass
        steps.append(item)
    result=dict(type='auth-flow',scope='legacy_oidc_observation',status='BLOCKED',reason_code='NO_EXPLICIT_IDENTITY_POLICY',
                session_coverage='NOT_RUN',authorization_coverage='NOT_RUN',steps=steps,
                break_at=value.get('break_at') if isinstance(value.get('break_at'),str) and value['break_at'] in allowed|{'identity-policy'} else None,
                cleanup=value.get('cleanup') if value.get('cleanup') in ('closed','not_needed','unknown') else 'unknown',
                legacy_claims_ignored=ignored)
    if value.get('observation_error')=='LEGACY_NAVIGATION_INCOMPLETE':result['observation_error']='LEGACY_NAVIGATION_INCOMPLETE'
    return result


def merge_scenario_routes(metrics,fresh,requests,prefix,requested=None,interrupted=False):
    """Wynik sprawdzenia po podmianie tras o danym początku na ich pomiar z sesją scenariusza; liczniki i status liczone od nowa."""
    # Trasa zlecona drugiemu pomiarowi, która nie dała wyniku (przerwany pomiar), zostaje z pierwszym wynikiem i liczy się jako nieukończona.
    missing=[route for route in (requested if requested is not None else fresh) if route not in fresh]
    routes=[fresh.get(r['route'],r) if not r.get('pattern') else r for r in metrics['routes']]
    inside=lambda r:urlparse(r.get('url','')).path.startswith(prefix)
    kept=[r for r in metrics.get('requests',[]) if not inside(r)]+[r for r in requests if inside(r)]
    data=dict(metrics,routes=routes,requests=kept,pages=[r['route'] for r in routes if r.get('reachable')],
              errors=[r['route']+': '+str(r.get('errors',[])+r.get('violations',[])) for r in routes if r['status']=='FAIL'],
              redirected={r['route']:r.get('redirected_to') for r in routes if r['status']=='REDIRECTED'})
    data['scenario_sessions']=metrics.get('scenario_sessions',[])+[dict(routes_prefix=prefix,routes=len(fresh),reachable=sum(bool(r.get('reachable')) for r in fresh.values()),not_completed=len(missing),interrupted=interrupted)]
    data['not_completed']=(metrics.get('not_completed') or 0)+len(missing)
    data['cause']='; '.join('HTTP '+str(r['status'])+' from '+r['source']+' on '+r['url'] for r in kept if r.get('status',0)>=400 and not synthetic_request(r)
                            and not (r['status']<500 and r.get('source')=='app' and urlparse(r['url']).path in data.get('bare_callbacks',())))
    if missing or interrupted:data['cause']=(data['cause']+'; ' if data['cause'] else '')+'measurement with the scenario session did not finish: '+str(len(missing))+' of '+str(len(missing)+len(fresh))+' routes without a result'
    if not data['errors'] and not data['pages']:data['cause']='No route was reachable under its own address'
    # Przerwanie przy którejkolwiek sesji zostaje w wyniku: kolejne scalanie nie może go zamienić na PASS.
    return ('FAIL' if data['errors'] or data['not_completed'] or any(row['interrupted'] for row in data['scenario_sessions']) or not data['pages'] else 'PASS'),data


def browser_results(output):
    from helix_audit_context import safe_read
    records=[]
    journal=Path(str(output)+'.jsonl')
    if journal.exists():
        for line in safe_read(journal).splitlines():
            try:
                record=json.loads(line)
                if isinstance(record,dict):records.append(record)
            except ValueError: pass  # A killed writer may leave its last line incomplete.
    try:
        data=json.loads(safe_read(output)) if output.exists() else {}
        if not isinstance(data,dict):raise ValueError('browser final output object required')
    except (ValueError,UnicodeError):
        data=dict(execution_status='partial',artifact_gaps=[dict(kind='browser_output_incomplete',source='final_output')])
    routes=[r for r in records if r.get('type')=='route'] or data.get('routes',[])
    if routes:
        data.update(routes=routes,pages=[r['route'] for r in routes if r.get('reachable')],pages_tested=len(routes),errors=[r['route']+': '+str(r.get('errors',[])+r.get('violations',[])) for r in routes if r['status']=='FAIL'],
                    redirected={r['route']:r.get('redirected_to') for r in routes if r['status']=='REDIRECTED'},
                    discovered={r['pattern']:r['route'] for r in routes if r.get('pattern')})
    auth=next((r for r in reversed(records) if r.get('type')=='auth-flow'),None)
    if auth is not None or data.get('auth_flow') is not None:
        data['auth_flow']=normalize_legacy_auth(auth if auth is not None else data['auth_flow'])
    identity=next((r for r in reversed(records) if r.get('type')=='identity-form-suite'),None)
    if identity:data['identity_form']=identity
    policy=next((r for r in reversed(records) if r.get('type')=='identity-policy-suite'),None)
    if policy:data['identity_policy']=policy
    webauthn=next((r for r in reversed(records) if r.get('type')=='webauthn-suite'),None)
    if webauthn:data['webauthn']=webauthn
    pause=next((r for r in reversed(records) if r.get('type')=='resource-paused'),None)
    if pause:data['resource_paused']=pause
    return data


def profile_budgets(cfg):
    scale={'S':1,'M':2,'L':3,'XL':4}.get(cfg.get('profile','S'),1)
    defaults=dict(lcp_ms=2500,cls=.1,tbt_ms=200,performance=.8,p95_ms=500,error_rate=.01,vus=scale*2,duration=str(5*scale)+'s',route_sample=None,navigation_ms=15000,axe_ms=10000,browser_seconds=120*scale,workers=max(1,min(4,(os.cpu_count() or 2)//2)))
    defaults.update(cfg.get('runtime',{}).get('budgets',{}))
    return defaults


def ci_template():
    return '''name: Helix runtime
on: [push, pull_request]
jobs:
  runtime:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: helix
          POSTGRES_HOST_AUTH_METHOD: trust
        ports: ['5432:5432']
        options: >-
          --health-cmd "pg_isready -U helix" --health-interval 5s
          --health-timeout 3s --health-retries 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: runtime-npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
      - run: npm install --prefix "$RUNNER_TEMP/runtime-tools" playwright axe-core lighthouse
      - run: npx --prefix "$RUNNER_TEMP/runtime-tools" playwright install --with-deps chromium
      - uses: grafana/setup-k6-action@v1
      - run: |
          export PATH="$RUNNER_TEMP/runtime-tools/node_modules/.bin:$PATH"
          export HELIX_RUNTIME_NODE_MODULES="$RUNNER_TEMP/runtime-tools/node_modules"
          bin/helix runtime run --project . --out "$RUNNER_TEMP/runtime-report" --engine service
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: runtime-report
          path: ${{ runner.temp }}/runtime-report
'''


def parsers(sp):
    p=sp.add_parser('runtime',help='Disposable synthetic application runtime')
    sub=p.add_subparsers(dest='runtime_action',required=True)
    d=sub.add_parser('doctor'); d.add_argument('--json',action='store_true'); d.add_argument('--project',help='Wypisz naraz wszystkie przeszkody uruchomienia tego projektu')
    p=sub.add_parser('plan'); p.add_argument('--project',required=True); p.add_argument('--json',action='store_true')
    r=sub.add_parser('run'); r.add_argument('--project',required=True); r.add_argument('--out',required=True)
    r.add_argument('--allow-version-mismatch',action='store_true')
    r.add_argument('--allow-sysv-exposure',action='store_true',help='Świadomie uruchom serwer bazy mimo cudzych segmentów pamięci SysV na tym koncie')
    r.add_argument('--engine',choices=['auto','podman','docker','native','service'],default='auto')
    r.add_argument('--budget-min',type=float,default=30); r.add_argument('--part'); r.add_argument('--skip',default=''); r.add_argument('--keep',action='store_true'); r.add_argument('--no-oidc-stub',action='store_true')
    r.add_argument('--quick',type=int,default=0,metavar='N',help='Przebieg próbny: wszystkie etapy na N trasach każdej części (kilka minut); wynik nie jest oceną projektu')
    m=sub.add_parser('mutation', help='Mutacje offline na kopii, wymagają izolacji sieci')
    m.add_argument('--project', required=True); m.add_argument('--tool', choices=['stryker','mutmut'], required=True)
    m.add_argument('--budget-seconds', type=float, default=60)
    c=sub.add_parser('ci-template'); c.add_argument('--out')


def dispatch(a):
    try:
        if a.runtime_action=='mutation':
            from helix_runtime_mutation import run
            print(json.dumps(run(a.project, a.tool, a.budget_seconds), ensure_ascii=False, indent=2))
        elif a.runtime_action=='doctor':
            report=doctor()
            if getattr(a,'project',None): report['blockers']=preflight(a.project)
            print(json.dumps(report,indent=2,ensure_ascii=False))
        elif a.runtime_action=='plan': print(json.dumps(plan(a.project),indent=2))
        elif a.runtime_action=='ci-template':
            if a.out: Path(a.out).write_text(ci_template())
            else: print(ci_template())
        else:
            try: blockers=preflight(a.project,only=a.part)
            except Exception: blockers=[]  # kontrola wstępna nie może zatrzymać przebiegu
            # Co Helix umie przygotować sam, robi sam; użytkownik dostaje tylko to, czego nie da się zrobić za niego.
            if any(row.get('auto') for row in blockers):
                auto_prepare(blockers,report=lambda line:print(line,file=sys.stderr))
                try: blockers=preflight(a.project,only=a.part)
                except Exception: blockers=[]
            if blockers:
                print(f'[helix runtime] przeszkody wykryte przed startem ({len(blockers)}), wszystkie naraz:',file=sys.stderr)
                for row in blockers: print(f"  - {row['area']}: {row['reason']} -> {row['fix']}",file=sys.stderr)
            report=Runner(a.project,a.out,a.engine,a.budget_min,a.part,filter(None,a.skip.split(',')),a.keep,oidc_stub=not a.no_oidc_stub,allow_version_mismatch=a.allow_version_mismatch,allow_sysv_exposure=getattr(a,'allow_sysv_exposure',False),quick=getattr(a,'quick',0)).run(cli=dict(config=getattr(a,'config',None),state_dir=getattr(a,'state_dir',None)))
            if report.get('quick'): print('PRZEBIEG PRÓBNY: '+str(report['quick']['routes_per_part'])+' tras na część; wynik nie jest oceną projektu')
            for part in report['parts']: print(part['name']+': '+', '.join(k+'='+v['status'] for k,v in part['checks'].items()))
            print(str(Path(a.out)/'runtime-report.json'))
            statuses={check['status'] for part in report['parts'] for check in part['checks'].values()}
            # A measured failure does not make unfinished controls complete.
            # Schema states BLOCKED/DEGRADED/SKIPPED all retain exit 3.
            if (report.get('partial') or report.get('run_status') not in (None,'complete') or
                report.get('coverage_status','NOT_RECORDED')!='RECORDED' or 'integrations' not in report or
                report.get('identity_assessment',{}).get('status') in ('INCOMPLETE','NOT_RECORDED') or
                report.get('webauthn_coverage')=='INCOMPLETE' or
                report.get('status') not in ('PASS','FAIL') or not statuses or statuses-{'PASS','FAIL'}):
                return 3
            return 2 if report['status']=='FAIL' or 'FAIL' in statuses or integration_failures(report.get('integrations')) else 0
        return 0
    except (OSError,ValueError,TypeError,KeyError) as e:
        # Miejsce błędu zostaje w katalogu wyniku: sam komunikat (np. „Operation not permitted”) nie mówi, który krok padł.
        try:
            import traceback
            target=Path(getattr(a,'out',None) or '.')/'logs';target.mkdir(parents=True,exist_ok=True)
            (target/'runtime-error.log').write_text(traceback.format_exc())
            print('Helix runtime ERROR: '+str(e)+' (ślad: '+str(target/'runtime-error.log')+')')
        except OSError:print('Helix runtime ERROR: '+str(e))
        return 3


def import_evidence(maturity, report_path, project):
    """Import measured controls only; policy/review/visual consistency are separate proofs."""
    from helix_audit_context import safe_read, system_path
    from helix_runtime_integrations import execution_inventory
    path=system_path(report_path); report=json.loads(safe_read(path)); validate_report(report)
    if Path(report['project']).resolve()!=Path(project).resolve(): raise ValueError('runtime report belongs to another project')
    integrations=report.get('integrations') or execution_inventory(None)
    for entry in integrations['integrations']:
        artifacts=entry['execution']['logs']+[row['evidence'] for row in entry['coverage']['tested_routes']]
        for relative in artifacts:
            try: content=safe_read(path.parent/relative)
            except OSError:raise ValueError('runtime integration evidence is missing, unsafe or not a regular file') from None
            if not content:raise ValueError('runtime integration evidence is empty')
    mapping={'load':'load','cwv':'lighthouse','a11y':'a11y','restore':'backup','backup-policy':'backup','ux-probes':'e2e'}
    def apply(target, entries):
        from helix_runtime_transport import project_transport
        from helix_runtime_login import project_identity
        from helix_runtime_policy_receipts import project_policy_plan
        from helix_runtime_identity_policy_run import project_policy_execution,derive_identity_assessment
        from helix_runtime_webauthn import project_webauthn_plan
        selected=[part.get('path',part['name']) for part in entries]
        target['runtime_transport']=project_transport(report,selected)
        target['runtime_identity']=project_identity(report,selected)
        target['runtime_identity_policy']=project_policy_plan(report,selected)
        target['runtime_identity_policy_execution']=project_policy_execution(report,selected)
        target['runtime_identity_assessment']=derive_identity_assessment(report,selected)
        target['runtime_webauthn']=project_webauthn_plan(report,selected)
        from helix_runtime_webauthn_run import project_webauthn_execution
        target['runtime_webauthn_execution']=project_webauthn_execution(report,selected)
        from helix_runtime_sinks import project_sinks
        target['runtime_sinks']=project_sinks(report,selected)
        for area in target['areas'].values():
            for item in area['requirements']:
                check=mapping.get(item['id'])
                if not check: continue
                results=[p['checks'][check] for p in entries]
                if check=='backup':
                    # Old count-only receipts do not prove data survived restore.
                    results=[dict(r,status='BLOCKED',reason='backup checksum verification NOT_RECORDED')
                             if r['status']=='PASS' and r['metrics'].get('comparison')!='row_counts_and_checksums' else r for r in results]
                    results=results+[p['checks']['schema-apply'] for p in entries if p['checks'].get('schema-apply',{}).get('status') in ('FAIL','BLOCKED','DEGRADED','SKIPPED')]
                if not results: continue
                for result in results:
                    try: content=safe_read(path.parent/result['log'])
                    except OSError:content=None
                    if not content:
                        raise ValueError('runtime log is missing or outside report directory')
                statuses={r['status'] for r in results}
                status=next((s for s in ('FAIL','BLOCKED','DEGRADED','SKIPPED','PASS') if s in statuses))
                item.update(status=status,execution_status=status,satisfied=status=='PASS',tag='VERIFIED',runtime=status not in ('PASS','FAIL'),
                            evidence=[str(path.parent/r['log']) for r in results],metrics=[r['metrics'] for r in results],assessment_reason='synthetic runtime evidence; '+str(path))
            items=area['requirements']; total=sum(i['weight'] for i in items)
            area['score']=round(100*sum(i['weight'] for i in items if i['satisfied'] and not i['runtime'] and not i.get('exception'))/total) if total else 100
            area['top_gaps']=sorted((i for i in items if not i['satisfied'] or i['runtime'] or i.get('exception')),key=lambda i:(-i['weight'],i['id']))[:3]
        passed={i['id'] for a in target['areas'].values() for i in a['requirements'] if i['status']=='PASS'}
        target['blocking']=[b for b in target.get('blocking',[]) if b.split(':',1)[0] not in passed]
        weights=target['area_weights']; target['score']=round(sum(a['score']*weights[n] for n,a in target['areas'].items())/sum(weights.values()))
        target['scope']='offline evidence plus imported synthetic runtime; production behavior unverified'
        names={p['name'] for p in entries}
        relevant=[entry for entry in integrations['integrations'] if entry['area']=='active' and (not entry['parts'] or names.intersection(entry['parts']))]
        gaps=[dict(id=entry['id'],provider=entry['provider'],parts=entry['parts'],paths=entry['affected_paths'],routes=entry['affected_routes'],
                   coverage=entry['coverage']['status'],untested_because=entry['coverage']['untested_because']) for entry in relevant if entry['coverage']['status']!='tested']
        incomplete=bool(gaps or integrations.get('receipt_errors') or integrations.get('discovery',{}).get('errors') or integrations.get('discovery',{}).get('files')==0)
        target['runtime_coverage']='NOT_RECORDED' if integrations['status']=='NOT_RECORDED' else 'INCOMPLETE' if incomplete else 'RECORDED'
        target['runtime_integration_gaps']=gaps
        failures=[failure for failure in integration_failures(integrations) if not failure['parts'] or names.intersection(failure['parts'])]
        target['runtime_integration_failures']=failures
        for failure in failures:
            message='runtime-integration-failed: '+failure['integration_id']+' '+failure['method']+' '+failure['route']
            if message not in target['blocking']:target['blocking'].append(message)
        if target['runtime_coverage']!='RECORDED':
            message='runtime-integrations: '+target['runtime_coverage']+'; measured controls do not establish complete business-flow coverage'
            if message not in target['blocking']:target['blocking'].append(message)
        for label,key in (('runtime-transport','runtime_transport'),('runtime-identity','runtime_identity')):
            if target[key]['status']=='INCOMPLETE':
                message=label+': INCOMPLETE; measured controls do not establish cookie, session or authorization coverage'
                if message not in target['blocking']:target['blocking'].append(message)
        if target['runtime_webauthn_execution']['coverage_status']=='INCOMPLETE':
            message='runtime-webauthn: INCOMPLETE; declarations and device profile do not establish executed ceremonies'
            if message not in target['blocking']:target['blocking'].append(message)
        if target['runtime_webauthn_execution']['outcome']=='FAIL':
            message='runtime-webauthn-failed: explicit flow observations failed'
            if message not in target['blocking']:target['blocking'].append(message)
    from helix_visual import compact_runtime
    maturity['legacy_audits'] = compact_runtime(report['parts'])
    for name in ('performance', 'UI', 'UX'):
        if name in maturity['areas']:
            maturity['areas'][name]['runtime_audits'] = maturity['legacy_audits']
    maturity['findings']=[dict(f,part=p['name']) for p in report['parts'] for f in p.get('findings',[])]
    maturity['database_fidelity']=report.get('database_fidelity',{})
    maturity['runtime_integrations']=integrations
    maturity['runtime_network_isolation']=project_network_isolation(report)
    apply(maturity,report['parts'])
    for part in maturity.get('parts',[]):
        if 'maturity' in part: apply(part['maturity'],[p for p in report['parts'] if p['name']==part['path']])
    return report.get('provenance')
