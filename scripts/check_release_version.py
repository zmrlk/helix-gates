#!/usr/bin/env python3
"""Offline release consistency and trusted-history check (no fetch)."""
import argparse
from pathlib import Path
import re
import subprocess


def git(root,*args):
    result=subprocess.run(['git','-C',str(root),*args],text=True,capture_output=True)
    if result.returncode: raise ValueError(result.stderr.strip())
    return result.stdout


def check(root,ref='origin/master',since=None,pre_push=False):
    root=Path(root)
    version=re.search(r"^VERSION\s*=\s*['\"]([^'\"]+)", (root/'bin/helix_contracts.py').read_text(),re.M)[1]
    headings=re.findall(r'^#\s+(\d+\.\d+\.\d+(?:-[\w.]+)?)\s+—', (root/'CHANGELOG.md').read_text(),re.M)
    errors=[]
    if len(headings)!=len(set(headings)): errors.append('duplicate CHANGELOG release')
    if not headings or headings[0]!=version or max(headings,key=lambda v:tuple(map(int,v.split('-')[0].split('.'))))!=version:
        errors.append('VERSION differs from highest CHANGELOG heading')
    try:
        if pre_push:
            remote_source=git(root,'show',ref+':bin/helix_contracts.py')
            remote_version=re.search(r"^VERSION\s*=\s*['\"]([^'\"]+)",remote_source,re.M)[1]
            if remote_version==version:
                errors.append('pre-push: VERSION already present on '+ref)
            remote_changelog=git(root,'show',ref+':CHANGELOG.md')
            if re.search(r'^#\s+'+re.escape(version)+r'\s+—',remote_changelog,re.M):
                errors.append('pre-push: release heading already present on '+ref)
        # Only commits in the current change range may repeat the release subject.
        allowed=set(git(root,'rev-list',f'{since}..HEAD').split()) if since else {git(root,'rev-parse','HEAD').strip()}
        history=git(root,'log','--format=%H%x09%s',ref)
        for line in history.splitlines():
            sha,subject=line.split('\t',1)
            if re.search(r'\bHelix '+re.escape(version)+r'(?![\w.-])',subject) and sha not in allowed:
                errors.append('version already released in history: '+sha)
    except ValueError as error:
        errors.append('release history unavailable: '+str(error))
    return errors


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--ref',default='origin/master')
    parser.add_argument('--since',help='trusted base before current change range')
    parser.add_argument('--pre-push',action='store_true',help='reject versions already present on locally recorded origin/master; no fetch')
    args=parser.parse_args()
    errors=check(args.repo,args.ref,args.since,args.pre_push)
    print('\n'.join(errors) if errors else 'release version: PASS')
    return bool(errors)

if __name__=='__main__': raise SystemExit(main())
