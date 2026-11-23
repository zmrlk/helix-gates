#!/usr/bin/env python3
"""Bounded local pre-push gate. No model, install, fetch or full test suite."""
import ast
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    for folder in ('bin', 'scripts', 'tests'):
        for path in sorted((ROOT / folder).glob('*.py')):
            ast.parse(path.read_bytes(), filename=str(path.relative_to(ROOT)))
    ast.parse((ROOT / 'bin/helix').read_bytes(), filename='bin/helix')
    for command in ([sys.executable, 'scripts/check_release_version.py'],
                    [sys.executable, 'bin/helix', '--offline', 'requirements', 'check'],
                    ['git', 'diff', '--check'], ['git', 'diff', '--cached', '--check'],
                    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_ci_contract.py']):
        result = subprocess.run(command, cwd=ROOT)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
