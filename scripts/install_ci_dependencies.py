#!/usr/bin/env python3
"""Install only the repository-reviewed CI wheel lock for this runner/ABI."""
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def command(root=ROOT):
    if sys.version_info[:2] != (3, 12): raise ValueError('CI requires CPython 3.12')
    system, machine = platform.system().lower(), platform.machine()
    if system not in ('darwin', 'linux') or machine not in ('arm64', 'aarch64', 'x86_64'):
        raise ValueError('CI wheel platform is not supported')
    architecture = 'arm64' if machine in ('arm64', 'aarch64') else 'x86_64'
    lock = root / 'data/tool-pins' / (system + '-' + architecture) / 'cp312/ci.requirements.lock'
    if not lock.is_file() or not lock.read_text().strip(): raise ValueError('approved CI wheel lock missing: ' + str(lock.relative_to(root)))
    return [sys.executable, '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install',
            '--require-hashes', '--only-binary=:all:', '--no-cache-dir', '--index-url', 'https://pypi.org/simple', '-r', str(lock)]


def main():
    try: argv = command()
    except ValueError as error:
        print(error, file=sys.stderr); return 2
    return subprocess.run(argv, check=False).returncode


if __name__ == '__main__': raise SystemExit(main())
