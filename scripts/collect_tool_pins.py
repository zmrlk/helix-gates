#!/usr/bin/env python3
"""Maintainer-only acquisition into an external candidate directory.

This never installs a tool, runs lifecycle scripts, approves pins or changes the
repository. Run on each supported OS/architecture and Python ABI, review the
result, then submit the approved files through the ordinary commit wrapper.
"""
import argparse
import base64
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import helix_tools_manager as M


def wheel_rows(directory):
    rows = []
    for path in sorted(directory.iterdir()):
        if path.suffix != '.whl': raise ValueError('source distributions forbidden')
        raw = path.read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = [n for n in archive.namelist() if n.endswith('.dist-info/METADATA')]
            if len(names) != 1: raise ValueError('ambiguous metadata')
            metadata = BytesParser().parsebytes(archive.read(names[0]))
        rows.append(dict(name=M._normalized(metadata['Name']), version=metadata['Version'],
                         filename=path.name, sha256=hashlib.sha256(raw).hexdigest()))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ci', action='store_true', help='also collect CI wheels (requires CPython 3.12)')
    parser.add_argument('--npm', action='store_true', help='also collect npm locks and native binary hash')
    parser.add_argument('--only-npm', action='store_true', help='reuse separately collected wheel candidates; only acquire npm')
    args = parser.parse_args()
    if args.only_npm and (not args.npm or args.ci): parser.error('--only-npm requires --npm and excludes --ci')
    out = args.out.resolve()
    if out.is_relative_to(ROOT) or out.exists(): parser.error('--out must be a new directory outside this repository')
    if platform.system() not in ('Darwin', 'Linux') or platform.machine() not in ('arm64', 'aarch64', 'x86_64'):
        parser.error('unsupported platform')
    if args.ci and sys.version_info[:2] != (3, 12): parser.error('CI pins require Python 3.12')
    out.mkdir(parents=True)
    system, machine = platform.system(), platform.machine()
    key = M._pin_key(system, machine, platform.python_version())
    target = out / key
    target.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='helix-pin-candidates-') as temporary:
        work = Path(temporary)
        home = work / 'home'; (home / 'tmp').mkdir(parents=True)
        for name in ('npm-user.config', 'npm-global.config'): (home / name).write_text('')
        executor = M.Executor()
        node = executor.locate('node') if args.npm else None
        npm = executor.locate('npm') if args.npm else None
        env = M._environment(home, [Path(sys.executable).parent] + ([Path(node).parent] if node else []))
        def run(argv, cwd):
            subprocess.run(argv, cwd=cwd, env=env, check=True, stdin=subprocess.DEVNULL, timeout=600)
        pip = [sys.executable, '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'download',
               '--only-binary=:all:', '--no-cache-dir', '--index-url', 'https://pypi.org/simple']
        for name, spec in M.CATALOG.items():
            if spec['channel'] != 'wheel' or args.only_npm: continue
            wheels = work / name; wheels.mkdir()
            run(pip + ['--dest', str(wheels), spec['package'] + '==' + spec['version']], work)
            rows = wheel_rows(wheels)
            pin = dict(schema_version=1, tool=name, version=spec['version'], platform=key, wheels=rows)
            (target / (name + '.json')).write_text(json.dumps(pin, indent=2) + '\n')
            # Retain bytes for an independent review/reproducibility check.
            import shutil
            shutil.copytree(wheels, out / 'downloads' / key / name)
        if args.ci:
            wheels = work / 'ci'; wheels.mkdir()
            run(pip + ['--dest', str(wheels), '-r', str(ROOT / 'requirements.txt'), 'zizmor==1.15.0', 'semgrep==1.181.0'], work)
            rows = wheel_rows(wheels)
            (target / 'ci.requirements.lock').write_bytes(M._requirements({r['filename']: r for r in rows}))
            (target / 'ci.wheels.json').write_text(json.dumps(rows, indent=2) + '\n')
            shutil.copytree(wheels, out / 'downloads' / key / 'ci')
        if args.npm:
            if not node or not npm: raise ValueError('trusted Node/npm required')
            npm_key = M._pin_key(system, machine); target = out / npm_key
            target.mkdir(parents=True, exist_ok=True)
            for name, spec in M.CATALOG.items():
                if spec['channel'] != 'npm': continue
                package = work / name; package.mkdir()
                (package / 'package.json').write_bytes(M._json(dict(name='helix-owned-' + name, private=True, dependencies={spec['package']: spec['version']})))
                run([node, npm, 'install', '--package-lock-only', '--ignore-scripts', '--include=optional',
                     '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/'], package)
                rows = M._npm_lock(package / 'package-lock.json', spec)
                raw = (package / 'package-lock.json').read_bytes()
                pin = dict(schema_version=1, tool=name, version=spec['version'], platform=npm_key, lock_sha256=M._sha(raw))
                archives = out / 'downloads' / npm_key / name; archives.mkdir(parents=True)
                suffix = ('darwin-' if system == 'Darwin' else 'linux-') + ('arm64' if machine in ('arm64','aarch64') else 'x64') + ('-gnu' if system == 'Linux' else '')
                native = 'node_modules/@ast-grep/cli-' + suffix
                for index, row in enumerate(rows):
                    data = executor.fetch(row['resolved']); algorithm, digest = row['integrity'].split('-', 1)
                    if hashlib.new(algorithm, data).digest() != base64.b64decode(digest): raise ValueError('registry integrity mismatch')
                    (archives / (str(index) + '.tgz')).write_bytes(data)
                    if name == 'ast-grep' and row['location'] == native:
                        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                            item = archive.getmember('package/ast-grep')
                            if not item.isfile() or item.size > 512 * 1024 * 1024: raise ValueError('unsafe native artifact')
                            pin['native'] = dict(path=native + '/ast-grep', sha256=M._sha(archive.extractfile(item).read()))
                if name == 'ast-grep' and 'native' not in pin: raise ValueError('native package not resolved')
                (target / (name + '.package-lock.json')).write_bytes(raw)
                (target / (name + '.json')).write_text(json.dumps(pin, indent=2) + '\n')
    (out / 'ACQUISITION.json').write_text(json.dumps(dict(status='CANDIDATE_NOT_APPROVED',
        python=sys.version, platform=key, source='PyPI/npm acquisition; requires independent review before repository adoption'), indent=2) + '\n')
    print(out)


if __name__ == '__main__': main()
