"""Diagnostic only: why Chrome cannot start in the measurement Seatbelt scope on this runner."""
import os, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, 'bin')
import helix_runtime_isolation as isolation

CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
for cmd in ([CHROME, '--version'], ['sw_vers'], ['id', '-un']):
    print('$', ' '.join(cmd[-2:]), '->', subprocess.run(cmd, capture_output=True, text=True).stdout.strip().replace('\n', ' | '))
with tempfile.TemporaryDirectory(dir='/private/tmp') as base:
    root = Path(base).resolve(); work = root / 'work'; work.mkdir(); control = root / 'control'; control.mkdir(mode=0o700)
    readonly = [str(Path(p).resolve()) for p in ('/usr', '/bin', '/System', '/Library', '/private/etc', '/dev', '/Applications/Google Chrome.app')]
    policy = {key: [] for key in isolation.KEYS}; policy.update(scope='measurement', writable_roots=[str(work)], readonly_roots=readonly)
    backend = isolation.SeatbeltBackend(control)
    measurement = root / 'measurement.sb'; measurement.write_text(backend._compile(backend._normalize(policy)))
    permissive = root / 'permissive.sb'; permissive.write_text('(version 1)\n(allow default)\n')
    work_env = {'HOME': str(work), 'TMPDIR': str(work), 'MAC_CHROMIUM_TMPDIR': str(work), 'PATH': '/usr/bin:/bin'}
    variants = [('A measurement sandbox, work HOME', measurement, work_env),
                ('B no sandbox, work HOME', None, work_env),
                ('C permissive sandbox, work HOME', permissive, work_env),
                ('D measurement sandbox, runner HOME', measurement, dict(work_env, HOME=os.environ['HOME'])),
                ('E no sandbox, runner environment', None, dict(os.environ))]
    for index, (label, profile, env) in enumerate(variants):
        argv = [CHROME, '--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
                '--user-data-dir=' + str(work / ('profile-' + str(index))), '--dump-dom', 'about:blank']
        if profile: argv = [isolation.SANDBOX_EXEC, '-f', str(profile), *argv]
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=str(work), env=env)
            print('##', label, 'rc', done.returncode, 'html', '<html' in done.stdout)
            print('\n'.join(done.stderr.strip().splitlines()[-8:]))
        except subprocess.TimeoutExpired:
            print('##', label, 'timeout')
    for predicate in ('sender == "Sandbox"', 'eventMessage CONTAINS "deny(" AND eventMessage CONTAINS "Chrome"'):
        log = subprocess.run(['/usr/bin/log', 'show', '--last', '3m', '--style', 'compact', '--predicate', predicate], capture_output=True, text=True)
        lines = [line for line in log.stdout.splitlines() if 'deny' in line]
        print('## sandbox log', predicate, len(lines), 'deny lines'); print('\n'.join(lines[-80:]))
