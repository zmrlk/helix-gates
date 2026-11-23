"""Consume sanitized local scanner metadata and exact-version advisories only.

Never starts scanners: raw secret/history access is explicitly outside this command.
"""
import json
from pathlib import Path
import re


def load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 5_000_000:
        raise ValueError('Metadane muszą być zwykłym plikiem do 5 MB')
    return json.loads(p.read_text(encoding='utf-8'))


def dependencies(root):
    """Return package, exact version, source location; no dependency resolution."""
    root = Path(root)
    rows = []
    supported = ('package-lock.json','pnpm-lock.yaml','yarn.lock','requirements.txt')
    for name in supported:
        p = root / name
        if p.is_symlink() or not p.is_file():
            continue
        from helix_audit_context import safe_read
        text = safe_read(p, errors='strict')
        if name == 'package-lock.json':
            data = json.loads(text)
            for key, entry in data.get('packages', {}).items():
                if not key or not isinstance(entry,dict) or not entry.get('version'):
                    continue
                package = entry.get('name') or key.split('node_modules/')[-1]
                position = text.find(json.dumps(key))
                rows.append((package,entry['version'],name,text.count('\n',0,max(0,position))+1))
            def nested(items):
                for package,entry in items.items():
                    if not isinstance(entry,dict):
                        raise ValueError('Nieprawidłowy wpis package-lock')
                    if entry.get('version'):
                        position = text.find(json.dumps(package))
                        rows.append((package,entry['version'],name,text.count('\n',0,max(0,position))+1))
                    nested(entry.get('dependencies',{}))
            nested(data.get('dependencies',{}))
        elif name == 'requirements.txt':
            for i,line in enumerate(text.splitlines(),1):
                m = re.match(r'\s*([\w.-]+)==([\w.+-]+)(?:\s|;|$)',line)
                if m:
                    rows.append((m[1],m[2],name,i))
        elif name == 'pnpm-lock.yaml':
            for i,line in enumerate(text.splitlines(),1):
                m = re.match(r"\s+['\"]?/?(@?[^\s:'\"]+?)(?:@|/)(\d[^\s:'\"(]*)(?:\([^)]*\))?['\"]?:",line)
                if m:
                    rows.append((m[1],m[2],name,i))
        else:
            package = None
            for i,line in enumerate(text.splitlines(),1):
                m = re.match(r'\s*["\']?(@?[^\s"\']+?)@[^:]+:',line)
                if m:
                    package = m[1]
                version = re.match(r'\s+version\s+["\']([^"\']+)',line)
                if package and version:
                    rows.append((package,version[1],name,i))
    return sorted(set(rows))


def apply(data, root, advisories=None, gitleaks_report=None):
    from helix_static_security import finding
    if advisories:
        db = load(advisories)
        if not isinstance(db,dict) or not isinstance(db.get('advisories'),list):
            raise ValueError('Baza wymaga listy advisories: package, versions, id, severity')
        packages = dependencies(root)
        for package,version,file,line in packages:
            for item in db['advisories']:
                if not isinstance(item,dict) or not isinstance(item.get('versions'),list):
                    raise ValueError('Advisory wymaga obiektu z listą versions')
                if item.get('package') == package and version in item.get('versions',[]):
                    severity = item.get('severity','high')
                    if severity not in {'critical','high','medium','low','info'}:
                        raise ValueError('Nieprawidłowa severity advisory')
                    row = finding('SEC-DEPENDENCY','Wersja zależności w lokalnej bazie',file,'\n'*(line-1),line-1,
                        'Dokładna wersja pasuje do dostarczonej bazy; exploitability wymaga przeglądu.',
                        'Zaktualizuj zależność do wersji spoza listy podatnych.',severity,'likely')
                    import hashlib
                    row['source_hash'] = hashlib.sha256((Path(root)/file).read_bytes()).hexdigest()
                    row['deterministic_evidence'] = 'exact-version-advisory'
                    # No arbitrary scanner text or package strings are echoed.
                    data['findings'].append(row)
        data['offline_audits']['dependencies'] = dict(status='checked' if packages else 'unknown',
            reason='Dopasowanie dokładnych wersji; zakresy i nieprzypięte wersje nie są rozwiązywane.',
            packages_checked=len(packages), advisory_count=len(db['advisories']))
    if gitleaks_report:
        metadata = load(gitleaks_report)
        if not isinstance(metadata,dict) or metadata.get('redacted') is not True or not isinstance(metadata.get('findings'),list):
            raise ValueError('Wymagane zredagowane metadane: redacted=true, findings=[{file,line,scope}]')
        accepted = 0
        for item in metadata['findings']:
            if not isinstance(item,dict):
                raise ValueError('Wskaźnik skanu musi być obiektem')
            file = item.get('file','')
            if not isinstance(file,str):
                raise ValueError('Ścieżka skanu musi być tekstem')
            path = Path(file)
            # Only ordinary repo-relative source names; never emit scanner strings or secrets.
            if (path.is_absolute() or '..' in path.parts or not re.fullmatch(r'[\w./@+ -]+',file)
                    or path.suffix not in {'.js','.ts','.py','.go','.sql','.json','.yaml','.yml'}
                    or any(x.startswith('.') for x in path.parts)):
                continue
            line = item.get('line',1)
            if not isinstance(line,int) or line < 1 or line > 1_000_000:
                continue
            row = finding('SEC-SECRET','Wskaźnik sekretu ze zredagowanego skanu',file,'',0,
                'Zewnętrzny skan zgłosił wskaźnik; wartość sekretu nie jest odczytywana ani ujawniana.',
                'Zweryfikuj wskaźnik i unieważnij potwierdzony sekret.','high','possible')
            row['line']=line;row['evidence']=[f'{file}:{line}']
            data['findings'].append(row);accepted+=1
        scopes = {x.get('scope') for x in metadata['findings'] if isinstance(x,dict)}
        data['offline_audits']['secrets'] = dict(status='imported', findings=accepted,
            directory='reported' if 'directory' in scopes else 'unknown', history='reported' if 'history' in scopes else 'unknown')
    return data
