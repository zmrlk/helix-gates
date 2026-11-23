"""Offline license inventory; never equate detection with legal compatibility."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
from helix_runtime import copy_project
from helix_tool_adapters import locate, environment
from helix_paths import relative


def scan(repo, name, timeout=60):
    if name not in ('licensee', 'scancode'): raise ValueError('adapter licencji')
    if isinstance(timeout, bool) or not isinstance(timeout, (int,float)) or not 0 < timeout <= 300:
        raise ValueError('budżet: 0..300 sekund')
    result = dict(tool=name, status='not-run', score=0, findings=[], licenses=[])
    executable = locate(name)
    if not executable: return dict(result, status='unavailable', reason='brak programu; instalacja zabroniona')
    if name == 'licensee':
        return dict(result, reason='Zainstalowany licensee npm wymaga polityki licencji i drzewa zależności; kopia nie zawiera node_modules, instalacja zabroniona. Użyj scancode i manifestów; zgodność pozostaje unknown.')
    with tempfile.TemporaryDirectory(prefix='helix-license-') as tmp:
        home=Path(tmp); target=home/'project'; copy_project(Path(repo).resolve(), target)
        output=home/'licenses.json'
        argv=[executable, '--license', '--strip-root', '--json', str(output), '.']
        try:
            p=subprocess.run(argv,cwd=target,env=environment(home),capture_output=True,text=True,timeout=timeout)
            if p.returncode: raise ValueError('exit')
            data=json.loads(output.read_text())
            inventory=[]
            for item in data['files']:
                if item.get('scan_errors'): raise ValueError('niepełny skan')
                path=relative(target / item['path'],target).as_posix()
                if not (target/path).is_file(): continue
                for key in (item.get('detected_license_expression_spdx') or '').split(' AND '):
                    if re.fullmatch(r'[A-Za-z0-9.+-]{1,100}',key): inventory.append(dict(file=path,license=key))
            return dict(result,status='completed' if inventory else 'incomplete',licenses=inventory,
                        reason='Inwentarz licencji; zgodność zależności wymaga porównania i decyzji, nie certyfikacja.')
        except (OSError,ValueError,TypeError,KeyError,subprocess.TimeoutExpired):
            return dict(result,status='error',reason='Błąd narzędzia, timeout lub raport; brak punktów, surowe dane pominięte.')
