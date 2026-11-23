"""Optional local Git line ages and exact, read-only debt status receipts."""
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import time

from helix_git_readonly import git as read_git, SHA
from helix_audit_context import safe_read, system_path


def _stamp(value):
    if not isinstance(value,str):raise ValueError('invalid debt timestamp')
    stamp=datetime.fromisoformat(value)
    if stamp.tzinfo is None:raise ValueError('invalid debt timestamp')
    return stamp.astimezone(timezone.utc)


def _relative(value):
    return (isinstance(value,str) and bool(value) and not PurePosixPath(value).is_absolute()
            and '..' not in PurePosixPath(value).parts and PurePosixPath(value).as_posix()==value
            and not any(c in value for c in '\\:\x00\r\n'))


def collect_line_ages(repo,debt_report,sources,source_ref,*,observed_at,budget_s=10):
    """One blame per marker file, only when the supplied text equals its HEAD blob.

    Source time is committer-time for the last change of a current HEAD line.
    Unknown history never becomes age zero, and no authors or raw Git output
    leave this function. All commands prohibit transport and replacement refs.
    """
    observed=_stamp(observed_at)
    if type(budget_s) not in (int,float) or not math.isfinite(budget_s) or budget_s<0:
        raise ValueError('invalid debt age budget')
    rows=[];seen=set();head=source_ref.get('head') if isinstance(source_ref,dict) else None
    head=head if isinstance(head,str) and SHA.fullmatch(head) else None
    for item in debt_report.get('rows',[]):
        name,line=item.get('file'),item.get('line')
        if not _relative(name) or type(line) is not int or line<=0 or not isinstance(sources.get(name),str):
            raise ValueError('invalid debt source reference')
        if (name,line) in seen:continue
        seen.add((name,line))
        rows.append(dict(file=name,line=line,source_sha256=hashlib.sha256(sources[name].encode()).hexdigest(),
                         head=head,status='unknown',changed_at=None,reason='GIT_UNAVAILABLE'))
    if not rows:return rows
    def unknown(reason):
        for row in rows:row.update(status='unknown',changed_at=None,reason=reason)
        return rows
    if head is None:return unknown('GIT_UNAVAILABLE')
    deadline=time.monotonic()+budget_s
    def run(*args,text=True,input_data=None):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError
        result=read_git(repo,*args,text=text,input_data=input_data,timeout=remaining,local_objects_only=True)
        if time.monotonic()>deadline:raise TimeoutError
        return result
    try:
        repo=Path(repo).resolve()
        top=run('rev-parse','--show-toplevel')
        current=run('rev-parse','--verify','HEAD^{commit}')
        if top.returncode or Path(top.stdout.strip()).resolve()!=repo:return unknown('GIT_UNAVAILABLE')
        if current.returncode or current.stdout.strip()!=head:return unknown('HEAD_CHANGED')
        partial=run('config','--null','--name-only','--get-regexp',r'^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$')
        if partial.returncode==0 and partial.stdout:return unknown('PARTIAL_CLONE')
        if partial.returncode not in (0,1):return unknown('CONFIG_UNSUPPORTED')
        config=run('config','--null','--name-only','--get-regexp',r'^(blame\.ignorerevsfile|mailmap\.(file|blob)|diff\..*\.textconv|filter\..*\.(clean|smudge|process|required))$')
        if config.returncode==0 and config.stdout or config.returncode not in (0,1):return unknown('CONFIG_UNSUPPORTED')
        shallow=run('rev-parse','--is-shallow-repository')
        if shallow.returncode or shallow.stdout.strip()!='false':return unknown('SHALLOW_HISTORY')
        tree=run('ls-tree','-r','-z',head,text=False)
        if tree.returncode:return unknown('HISTORY_UNAVAILABLE')
        wanted={row['file'] for row in rows};objects={}
        for entry in tree.stdout.split(b'\0'):
            if not entry:continue
            header,name=entry.split(b'\t',1);mode,kind,oid=header.decode('ascii').split()
            name=os.fsdecode(name)
            if name in wanted and mode in ('100644','100755') and kind=='blob' and SHA.fullmatch(oid):objects[name]=oid
        for row in rows:
            if row['file'] not in objects:row['reason']='UNTRACKED_OR_NONREGULAR'
        ordered=sorted(objects);blobs={}
        if ordered:
            result=run('cat-file','--batch',text=False,input_data=''.join(objects[name]+'\n' for name in ordered).encode())
            if result.returncode:return unknown('HISTORY_UNAVAILABLE')
            offset=0
            for name in ordered:
                end=result.stdout.index(b'\n',offset);oid,kind,size=result.stdout[offset:end].split();size=int(size)
                if oid.decode()!=objects[name] or kind!=b'blob' or size<0:raise ValueError('invalid blob')
                offset=end+1;blobs[name]=result.stdout[offset:offset+size];offset+=size
                if len(blobs[name])!=size or result.stdout[offset:offset+1]!=b'\n':raise ValueError('invalid blob')
                offset+=1
            if offset!=len(result.stdout):raise ValueError('invalid blob')
        for name in ordered:
            selected=[row for row in rows if row['file']==name]
            if blobs[name]!=sources[name].encode():
                for row in selected:row['reason']='BLOB_MISMATCH'
                continue
            result=run('blame','--line-porcelain','--no-textconv',head,'--',name,text=False)
            if result.returncode:
                for row in selected:row['reason']='HISTORY_UNAVAILABLE'
                continue
            lines={};line_number=None;timestamp=None
            for entry in result.stdout.split(b'\n'):
                header=re.fullmatch(rb'([0-9a-f]{40}(?:[0-9a-f]{24})?) ([0-9]+) ([0-9]+)(?: ([0-9]+))?',entry)
                if header:line_number=int(header[3]);timestamp=None
                elif entry.startswith(b'committer-time '):
                    number=entry.removeprefix(b'committer-time ')
                    if re.fullmatch(rb'[0-9]{1,12}',number):timestamp=int(number)
                elif entry.startswith(b'\t') and line_number is not None:
                    lines[line_number]=timestamp;line_number=None
            for row in selected:
                stamp=lines.get(row['line'])
                if stamp is None:row['reason']='HISTORY_UNAVAILABLE';continue
                try:changed=datetime.fromtimestamp(stamp,timezone.utc)
                except (OverflowError,OSError,ValueError):row['reason']='HISTORY_UNAVAILABLE';continue
                if changed>observed:row['reason']='FUTURE_TIMESTAMP';continue
                row.update(status='known',changed_at=changed.isoformat(),reason='HEAD_LINE_CHANGED')
        final=run('rev-parse','--verify','HEAD^{commit}')
        if final.returncode or final.stdout.strip()!=head:return unknown('HEAD_CHANGED')
    except (TimeoutError,subprocess.TimeoutExpired):return unknown('BUDGET_EXHAUSTED')
    except (OSError,ValueError,TypeError,UnicodeError,subprocess.SubprocessError):return unknown('GIT_UNAVAILABLE')
    return rows


def debt_summary_path(repo,state_dir):
    """A single named file, never a search through evidence directories."""
    if state_dir is None:return None
    identity=hashlib.sha256(str(Path(repo).resolve()).encode()).hexdigest()
    return Path(state_dir)/'quality'/'debt'/identity/'latest.json'


def _safe_path(value):
    path=system_path(Path(value).expanduser())
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('unsafe debt receipt path')
    return path.resolve()


def _outside(path,repo):
    return not path.is_relative_to(repo) and not repo.is_relative_to(path)


def write_debt_summary(repo,state_dir,quality_path):
    """Publish only an identity/hash pointer after the external quality artifact."""
    if state_dir is None:return None
    from helix_ponytail_debt import project_debt
    repo=_safe_path(repo);state=_safe_path(state_dir);artifact=_safe_path(quality_path)
    if not _outside(state,repo) or not _outside(artifact,repo):raise ValueError('debt evidence must be external')
    raw=safe_read(artifact,errors='strict');quality=json.loads(raw)
    if not isinstance(quality,dict) or quality.get('target')!=str(repo):raise ValueError('debt target mismatch')
    debt=project_debt(quality.get('ponytail_debt'))
    if quality.get('ponytail_debt') is None:raise ValueError('debt report missing')
    provenance=quality.get('provenance',{})
    if not isinstance(provenance,dict):raise ValueError('invalid debt provenance')
    head=provenance.get('target_head');dirty=provenance.get('target_dirty')
    data=dict(schema_version=1,kind='ponytail-debt-summary',target=str(repo),head=head if isinstance(head,str) and SHA.fullmatch(head) else None,
              dirty=dirty if type(dirty) is bool else None,artifact=str(artifact),artifact_sha256=hashlib.sha256(raw.encode()).hexdigest(),
              source_digest=debt.get('source_digest'),observed_at=debt.get('observed_at'))
    path=debt_summary_path(repo,state);path.parent.mkdir(parents=True,exist_ok=True)
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('unsafe debt receipt path')
    fd,temp=tempfile.mkstemp(prefix='.debt-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream,sort_keys=True,allow_nan=False);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)
    return data


def read_debt_summary(repo,state_dir,ref):
    """Existing ref plus two exact files. No Git, source scan, models or writes."""
    from helix_ponytail_debt import project_debt
    result=dict(status='NOT_RUN',reason='Brak zapisanego raportu długu w podanym state-dir',counts=None,
                last_observation=None,artifact=None,source_digest=None,observed_at=None,execution=dict(models=0,source_scans=0,git_blame=0,writes=0))
    if state_dir is None:return result
    try:
        repo=_safe_path(repo);state=_safe_path(state_dir)
        if not _outside(state,repo):raise ValueError('unsafe debt state')
        path=_safe_path(debt_summary_path(repo,state));summary=json.loads(safe_read(path,errors='strict'))
    except FileNotFoundError:return result
    except (OSError,ValueError,TypeError,UnicodeError):
        return dict(result,status='UNKNOWN',reason='Nie można potwierdzić zapisu długu')
    try:
        fields={'schema_version','kind','target','head','dirty','artifact','artifact_sha256','source_digest','observed_at'}
        if set(summary)!=fields or type(summary['schema_version']) is not int or summary['schema_version']!=1 or summary['kind']!='ponytail-debt-summary' or summary['target']!=str(repo):raise ValueError('invalid summary')
        artifact=_safe_path(summary['artifact'])
        if not _outside(artifact,repo):raise ValueError('invalid artifact')
        raw=safe_read(artifact,errors='strict')
        if hashlib.sha256(raw.encode()).hexdigest()!=summary['artifact_sha256']:raise ValueError('artifact hash mismatch')
        quality=json.loads(raw)
        if not isinstance(quality,dict) or quality.get('target')!=str(repo) or quality.get('ponytail_debt') is None:raise ValueError('target mismatch')
        debt=project_debt(quality['ponytail_debt']);provenance=quality.get('provenance',{})
        if not isinstance(provenance,dict):raise ValueError('invalid debt provenance')
        if any(summary[key]!=debt.get(key) for key in ('source_digest','observed_at')):raise ValueError('source mismatch')
        if summary['head']!=provenance.get('target_head') or summary['dirty']!=provenance.get('target_dirty'):raise ValueError('ref mismatch')
        result.update(last_observation=debt,artifact=str(artifact),source_digest=summary['source_digest'],observed_at=summary['observed_at'])
        head=ref.get('head') if isinstance(ref,dict) else None
        if not isinstance(head,str) or not SHA.fullmatch(head):result.update(status='UNKNOWN',reason='Nie potwierdzono rewizji długu')
        elif head!=summary['head']:result.update(status='STALE',reason='Raport długu dotyczy innej rewizji')
        elif ref.get('dirty') is True or summary['dirty'] is True:result.update(status='STALE',reason='Snapshot długu lub bieżące repo ma lokalne zmiany')
        elif ref.get('dirty') is not False or summary['dirty'] is not False:result.update(status='UNKNOWN',reason='Nie potwierdzono czystego snapshotu długu')
        elif debt.get('status')!='COMPLETE':result.update(status='INCOMPLETE',reason='Raport długu nie obejmuje pełnego odczytu komentarzy')
        else:result.update(status='CURRENT',reason='Zapisany dług dotyczy bieżącego czystego HEAD',counts=debt.get('counts'))
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        return dict(result,status='UNKNOWN',reason='Raport długu nie potwierdza tożsamości lub integralności',counts=None,last_observation=None)
    return result
