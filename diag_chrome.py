"""Diagnostic only: which sandbox denials stop Chrome in the measurement scope when HOME is a fresh directory."""
import os, subprocess, sys, tempfile, time
from datetime import datetime
from pathlib import Path
sys.path.insert(0, 'bin')
import helix_runtime_isolation as isolation

CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
with tempfile.TemporaryDirectory(dir='/private/tmp') as base:
    root = Path(base).resolve(); work = root / 'work'; work.mkdir(); control = root / 'control'; control.mkdir(mode=0o700)
    readonly = [str(Path(p).resolve()) for p in ('/usr', '/bin', '/System', '/Library', '/private/etc', '/dev', '/Applications/Google Chrome.app')]
    policy = {key: [] for key in isolation.KEYS}; policy.update(scope='measurement', writable_roots=[str(work)], readonly_roots=readonly)
    backend = isolation.SeatbeltBackend(control)
    measurement = root / 'measurement.sb'; measurement.write_text(backend._compile(backend._normalize(policy)))
    import pwd
    real = Path(pwd.getpwuid(os.getuid()).pw_dir) / 'Library/Application Support/Google'
    print('## real default parent exists before:', real.exists(), (real / 'Chrome').exists())
    for label, prepare in (('A fresh HOME', None), ('P1 real Google pre-created', real), ('P2 real Google/Chrome pre-created', real / 'Chrome')):
        home = work / ('home-' + label.split()[0]); home.mkdir()
        if prepare: prepare.mkdir(parents=True, exist_ok=True)
        env = {'HOME': str(home), 'TMPDIR': str(work), 'MAC_CHROMIUM_TMPDIR': str(work), 'PATH': '/usr/bin:/bin'}
        argv = [isolation.SANDBOX_EXEC, '-f', str(measurement), CHROME, '--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
                '--user-data-dir=' + str(work / ('profile-' + label.split()[0])), '--dump-dom', 'about:blank']
        start = datetime.now().strftime('%Y-%m-%d %H:%M:%S'); time.sleep(1)
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=str(work), env=env)
        time.sleep(2); end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print('##', label, 'rc', done.returncode, 'html', '<html' in done.stdout)
        print('\n'.join(done.stderr.strip().splitlines()[-4:]))
        log = subprocess.run(['/usr/bin/log', 'show', '--start', start, '--end', end, '--style', 'compact', '--predicate', 'sender == "Sandbox"'], capture_output=True, text=True)
        lines = sorted({line.split('deny(1) ', 1)[1][:200] for line in log.stdout.splitlines() if 'Chrome' in line and 'deny(1) ' in line})
        print('## denials', label, len(lines)); print('\n'.join(lines[:120]))
        print('## real default dir after', label, sorted(str(x.relative_to(real)) for x in real.rglob('*')) if real.exists() else 'absent')
