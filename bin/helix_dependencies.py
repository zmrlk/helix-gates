"""Optional dependency detection shared by CLI and portable tests."""
import importlib.util, json, os, shutil, subprocess
from pathlib import Path

class MissingDependency(Exception):
    pass

STATE_ROOT = None

def node_module(name):
    if not shutil.which('node'): return None
    try:
        p = subprocess.run(['node', str(Path(__file__).with_name('dependencies.cjs')), name], capture_output=True, text=True, timeout=15)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired): return None

def has_yaml():
    return importlib.util.find_spec('yaml') is not None or node_module('js-yaml') is not None

def load_yaml(path):
    try:
        import yaml
        return yaml.safe_load(Path(path).read_text()) or {}
    except ImportError:
        module = node_module('js-yaml')
        if not module: raise MissingDependency('YAML parser missing: pip install -r requirements.txt (PyYAML), or npm install js-yaml')
        p = subprocess.run(['node', '-e', "const y=require(process.argv[1]);console.log(JSON.stringify(y.load(require('fs').readFileSync(process.argv[2],'utf8'))||{}))", module, str(path)], capture_output=True, text=True, timeout=30)
        if p.returncode: raise ValueError('Invalid YAML input')
        return json.loads(p.stdout)

def skipped(out, reason):
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    ledger = [dict(unit='requested analysis', status='skipped', reason=str(reason))]
    (out / 'coverage-ledger.json').write_text(json.dumps(ledger, indent=2) + '\n')
    (out / 'report.md').write_text('# Helix: INCOMPLETE\n\nSkipped: ' + str(reason) + '\n')
    (out / 'run.json').write_text(json.dumps(dict(status='incomplete', coverage=ledger), indent=2) + '\n')
    print('INCOMPLETE: skipped: ' + str(reason) + '; report: ' + str(out / 'report.md'))
