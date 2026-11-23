"""Bounded runtime adapters. Declarations never establish production execution."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def worker_parts(sources, parts):
    """Discover non-HTTP Python workers without guessing a safe daemon command."""
    result = []
    for path in sorted(sources):
        parent = Path(path).parent.as_posix()
        if Path(path).name not in ('requirements.txt', 'pyproject.toml') or parent == '.' and any(p['path']=='.' for p in parts):
            continue
        if any(p['path'] == parent for p in parts + result):
            continue
        scripts = [p for p in sorted(sources) if p.startswith('' if parent=='.' else parent + '/') and p.endswith('.py')
                   and not Path(p).name.startswith('test_')]
        result.append(dict(name=parent, path=parent, framework='python-worker', package_manager='pip',
                           workspace=parent, lockfile=None, build=None, start=None, port=0, routes=[],
                           worker_scripts=scripts, execution_policy='disabled'))
    return result


def adapter_plan(sources, parts, config):
    cfg = config.get('runtime', {}).get('adapters', {})
    declarations = []
    for path, text in sorted(sources.items()):
        if not (Path(path).name.startswith('Dockerfile') or Path(path).suffix in ('.yaml', '.yml')):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            match = re.search(r'\bTZ\s*[:=]\s*[\"\']?([A-Za-z_]+/[A-Za-z_+/-]+|UTC)\b', line)
            if match:
                declarations.append(dict(path=path, line=number, timezone=match[1]))
    zones = sorted({d['timezone'] for d in declarations})
    selected = cfg.get('timezone') or (zones[0] if len(zones) == 1 else 'UTC')
    try:
        ZoneInfo(selected)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise ValueError('runtime adapters: invalid timezone') from None
    rows = []
    for part in parts:
        prefix = '' if part['path'] == '.' else part['path'] + '/'
        texts = {p: t for p, t in sources.items() if p.startswith(prefix)
                 and (Path(p).suffix in ('.js','.ts','.mjs','.cjs','.svelte','.py') or Path(p).name in ('package.json','requirements.txt'))
                 and not re.search(r'(^|/)(tests?|fixtures|archive)/|\.(test|spec)\.', p)}
        joined = '\n'.join(texts.values())
        names = sorted(item['name'] for item in part.get('env', []) if item['name'].startswith('CRON_'))
        routes = sorted(cfg.get('scheduler_routes', []))
        rows.append(dict(part=part['path'], timezone=dict(primary=selected, additional='UTC',
                         source='explicit_config' if cfg.get('timezone') else 'repository_declaration' if len(zones) == 1 else 'fallback',
                         declarations=declarations, production_verified=False,
                         gaps=['conflicting timezone declarations'] if len(zones) > 1 and not cfg.get('timezone') else []),
                         pdf=dict(required=bool(re.search(r'puppeteer|playwright', joined)), status='NOT_RUN'),
                         whatsapp=dict(strategy='disabled', detected='whatsapp-web.js' in joined,
                                       enforcement='deny CommonJS package load; OS network isolation remains required'),
                         cron=dict(strategy='disabled', env_names=names, routes=routes,
                                   enforcement='empty CRON_* values; deny node-cron/cron package load; no host crontab; custom schedulers not proven'),
                         worker=dict(status='DISABLED' if part['framework'] == 'python-worker' else 'NOT_APPLICABLE',
                                     scripts=part.get('worker_scripts', []), reason='no explicit bounded worker job contract'),
                         native=dict(packages=[p for p in ('sharp', 'satori') if re.search(r'\b' + p + r'\b', joined)],
                                     platform=platform.system(), architecture=platform.machine(), status='NOT_RUN',
                                     warning='sharp native binaries and satori renderer dependencies must match runtime platform; presence is not compatibility'),
                         replay=dict(inbound_enabled=bool(cfg.get('inbound_replay')),
                                     providers=sorted({r['provider'] for r in recordings(config)}), status='NOT_RUN',
                                     limitation='exact recorded requests; inbound routes and synthetic rows require project configuration')))
    return dict(schema_version=1, parts=rows)


def adapter_env(spec):
    """Override examples too: a sample CRON_ENABLED=true must never start a job."""
    values = {'TZ': spec.get('timezone', {}).get('primary', 'UTC'),
              'PUPPETEER_SKIP_DOWNLOAD': 'true', 'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD': '1'}
    for name in spec.get('cron', {}).get('env_names', []):
        values[name] = ''
    return values


def chromium_path(home=None):
    """Existing executables only. Never download Chromium during discovery."""
    home = Path(home or Path.home())
    candidates = [Path('/usr/bin/chromium'), Path('/usr/bin/chromium-browser'),
                  Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')]
    for base in (home / '.cache/ms-playwright', home / 'Library/Caches/ms-playwright', home / '.cache/puppeteer/chrome'):
        for pattern in ('chromium-*/chrome-linux*/chrome', 'chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium',
                        'mac-*/chrome-mac-*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
                        'linux-*/chrome-linux64/chrome'):
            candidates.extend(sorted(base.glob(pattern), reverse=True))
    return next((str(p) for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)


def recordings(config):
    from helix_runtime_registry import load_registry
    registry=load_registry(config)
    providers={p for r in registry['providers'] for p in [r['provider'],*r.get('recording_aliases',[])]}
    rows = config.get('runtime', {}).get('adapters', {}).get('recordings', [])
    if not isinstance(rows, list) or len(rows) > 50:
        raise ValueError('runtime recordings: expected at most 50 synthetic records')
    seen = set()
    result = []
    for row in rows:
        if not isinstance(row, dict) or row.get('synthetic') is not True or row.get('provider') not in providers:
            raise ValueError('runtime recordings: synthetic provider required')
        ident = row.get('id'); request = row.get('request', {}); response = row.get('response', {})
        if not isinstance(ident, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', ident) or ident in seen:
            raise ValueError('runtime recordings: invalid or duplicate id')
        seen.add(ident)
        url = urlsplit(request.get('url', ''))
        if url.scheme not in ('https', 'http') or not url.hostname or url.username or url.password or url.fragment or url.query:
            raise ValueError('runtime recordings: exact URL without credentials required')
        if request.get('method') not in ('GET', 'POST') or type(response.get('status')) is not int or not 200 <= response['status'] < 300:
            raise ValueError('runtime recordings: unsupported method/status')
        body = request.get('body')
        encoded = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode()) > 65536:
            raise ValueError('runtime recordings: record too large')
        result.append(dict(id=ident, provider=row['provider'], request=dict(url=request['url'], method=request['method'], body=body),
                           response=dict(status=response['status'], body=response.get('body')), sha256=hashlib.sha256(encoded.encode()).hexdigest()))
    keys = [json.dumps(r['request'], sort_keys=True) for r in result]
    if len(keys) != len(set(keys)):
        raise ValueError('runtime recordings: ambiguous request')
    return result


def pdf_probe(runner, home):
    from helix_runtime import Blocked
    browser = runner.tools.get('playwright_chromium')
    log = runner.out / 'logs' / ('pdf-' + str(len(runner.private_logs)) + '.log')
    status = 'BLOCKED'; reason = 'CHROMIUM_MISSING'; metrics = dict(scope='synthetic PDF renderer, not application PDF')
    if browser:
        html = runner.project_temporary() / 'helix-pdf.html'
        pdf = runner.project_temporary() / 'helix-pdf.pdf'
        html.write_text('<!doctype html><meta charset="utf-8"><title>Helix</title><p>Synthetic PDF 123</p>')
        pdf.unlink(missing_ok=True)
        try:
            runner.project_command([browser, '--headless', '--no-sandbox', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
                                    '--user-data-dir=' + str(runner.project_temporary() / 'pdf-profile'),
                                    '--print-to-pdf=' + str(pdf), html.as_uri()], maximum=30, phase='measurement')
            valid = pdf.is_file() and pdf.stat().st_size > 100 and pdf.read_bytes().startswith(b'%PDF-')
            status = 'PASS' if valid else 'FAIL'; reason = 'synthetic PDF signature verified' if valid else 'PDF_OUTPUT_INVALID'
            metrics['bytes'] = pdf.stat().st_size if pdf.is_file() else 0
        except (Blocked, OSError, ValueError) as error:
            reason = 'CHROMIUM_LAUNCH_FAILED'; metrics['detail'] = str(error).strip().splitlines()[-1][:300] if str(error).strip() else type(error).__name__
    log.write_text(json.dumps(dict(status=status, reason=reason, metrics=metrics)) + '\n')
    return dict(status=status, reason=reason, metrics=metrics, log=log.relative_to(runner.out).as_posix())


def inbound_replay(runner, part, url, home, config):
    """Only explicit synthetic requests to this run's loopback application."""
    from helix_runtime import Blocked
    rows=config.get('runtime',{}).get('adapters',{}).get('inbound_replay',[])
    log=runner.out/'logs'/('inbound-'+str(len(runner.private_logs))+'.log')
    metrics={'scope':'configured synthetic HTTP only; persistence not verified','requests':[]}
    status='BLOCKED';reason='inbound replay not configured'
    try:
        target=urlsplit(url)
        if target.hostname not in ('localhost','127.0.0.1') or target.scheme!='http' or not target.port:
            raise ValueError('owned loopback origin required')
        if not isinstance(rows,list) or not 0<len(rows)<=20:raise ValueError('invalid inbound records')
        for row in rows:
            path=row.get('path','');method=row.get('method','POST')
            if row.get('synthetic') is not True or not re.fullmatch(r'/[A-Za-z0-9_./{}-]*',path) or path.startswith('//') or '..' in path or method not in ('GET','POST','PUT','PATCH','DELETE'):
                raise ValueError('invalid synthetic inbound request')
            expected=row.get('expected_status',200)
            if type(expected) is not int or not 200<=expected<300:raise ValueError('invalid expected status')
            headers={}
            for key,value in row.get('headers',{}).items():
                if not re.fullmatch(r'[A-Za-z0-9_-]+',key) or not isinstance(value,dict) or set(value)!={'env'} or not runner.env.get(value['env']):raise ValueError('header env required')
                headers[key]=runner.env[value['env']]
            private=runner.project_temporary()/'inbound-input.json'
            runner.write_sink_input(dict(url=target.scheme+'://'+target.netloc+path,method=method,headers=headers,body=row.get('body')),private)
            observed=json.loads(runner.project_command([runner.tool('node'),home/'bin/runtime-bridge-replay.cjs',private],runner.work/part['path'],maximum=20,phase='measurement'))
            if set(observed)!={'status'} or type(observed['status']) is not int:raise ValueError('invalid receipt')
            metrics['requests'].append(dict(http_status=observed['status'],expected_status=expected))
        status='PASS' if all(r['http_status']==r['expected_status'] for r in metrics['requests']) else 'FAIL'
        reason='configured HTTP responses compared; persistence not verified'
    except (Blocked,OSError,ValueError,KeyError,TypeError):
        reason='INBOUND_REPLAY_UNAVAILABLE: explicit synthetic project contract required'
    log.write_text(json.dumps(dict(status=status,reason=reason,metrics=metrics))+'\n')
    return dict(status=status,reason=reason,metrics=metrics,log=log.relative_to(runner.out).as_posix())


def settings_sql(config):
    """No known table names. Explicit synthetic rows for the disposable database."""
    rows=config.get('runtime',{}).get('adapters',{}).get('synthetic_rows',[])
    if not isinstance(rows,list) or len(rows)>30:raise ValueError('invalid synthetic rows')
    statements=[]
    def ident(value):
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}',value):raise ValueError('invalid SQL identifier')
        return '"'+value+'"'
    def literal(value):
        if value is None:return 'NULL'
        if isinstance(value,bool):return 'TRUE' if value else 'FALSE'
        if isinstance(value,(dict,list)):value=json.dumps(value,allow_nan=False)
        if not isinstance(value,(str,int,float)) or len(str(value))>65536 or '\x00' in str(value):raise ValueError('invalid synthetic value')
        return "'"+str(value).replace("'","''")+"'"
    for row in rows:
        if row.get('synthetic') is not True or not isinstance(row.get('values'),dict) or not row['values']:raise ValueError('synthetic rows must be explicit')
        table='.'.join(ident(p) for p in row.get('table','').split('.'))
        if row['table'].count('.')!=1:raise ValueError('qualified table required')
        statements.append('INSERT INTO '+table+' ('+','.join(ident(k) for k in row['values'])+') VALUES ('+','.join(literal(v) for v in row['values'].values())+');')
    return "SET standard_conforming_strings=on;\n"+'\n'.join(statements) if statements else ''


def prepare(runner, part, declaration, config, home):
    """Install only Helix-owned preload, in the already isolated temporary copy."""
    runner.env.update(adapter_env(declaration))
    browser = runner.tools.get('playwright_chromium')
    declaration['pdf'].update(status='AVAILABLE' if browser else 'BLOCKED',
                              reason='existing browser; launch/PDF not yet verified' if browser else 'CHROMIUM_MISSING')
    if browser:
        runner.env.update(PUPPETEER_EXECUTABLE_PATH=browser, CHROME_PATH=browser)
    from helix_runtime_generic import prepare_generic
    prepare_generic(runner,part,declaration,config,home)
    if part['package_manager'] == 'pip':
        return
    cases = recordings(config)
    declaration['replay'].update(status='CONFIGURED' if cases else 'BLOCKED',
                                 records=[dict(id=r['id'], provider=r['provider'], sha256=r['sha256']) for r in cases])
    payload = runner.project_temporary() / ('adapters-' + str(len(runner.private_logs)) + '.json')
    from helix_runtime_registry import load_registry
    definitions={r['provider']:r for r in load_registry(config)['providers']}
    disabled=sorted({p for r in runner.integration_plan['integrations'] if part['path'] in r['parts'] and r['area']=='active' and r['strategy']['selected'] in ('disable','disabled') for p in definitions[r['provider']]['packages'].get('npm',[])})
    runner.write_sink_input(dict(recordings=cases,disabled_packages=disabled), payload)
    runner.env['HELIX_RUNTIME_ADAPTER_INPUT'] = str(payload)
    runner.add_owned_preload(home / 'bin/runtime-adapters.cjs')


# Uses JSONB to canonicalize column order, UTC for timestamptz and a sorted
# multiset of fixed-length row hashes. Duplicates affect both count and digest.
CHECKSUM_SQL = """SET timezone TO 'UTC';
SELECT format('SELECT json_build_object(''table'', %L, ''rows'', count(*), ''checksum'', md5(coalesce(string_agg(h, '''' ORDER BY h COLLATE "C"), ''''))) FROM (SELECT md5(to_jsonb(t)::text) h FROM %I.%I t) hashed;',
              schemaname||'.'||tablename,schemaname,tablename)
FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')
AND schemaname NOT LIKE 'pg_toast%%' ORDER BY schemaname,tablename
\\gexec
"""


def checksum_rows(text):
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.strip() == 'SET':
            continue
        try:
            row = json.loads(line)
            if set(row) != {'table', 'rows', 'checksum'} or not isinstance(row['table'], str) or type(row['rows']) is not int or row['rows'] < 0 or not re.fullmatch(r'[0-9a-f]{32}', row['checksum']):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError('backup: invalid table checksum evidence') from None
        rows.append(row)
    if len({r['table'] for r in rows}) != len(rows):
        raise ValueError('backup: duplicate table checksum evidence')
    return sorted(rows, key=lambda r: r['table'])


def utc_smoke(runner, part, argv, url):
    """One additional UTC process; public HTTP observations, no auth inference."""
    import subprocess
    from helix_runtime import Blocked
    previous = runner.env
    runner.env = dict(previous, TZ='UTC', HELIX_RUNTIME_TIMEZONE_PASS='utc-smoke')
    process = None
    log = runner.out / 'logs' / ('utc-' + str(len(runner.private_logs)) + '.log')
    if getattr(runner,'startup_log_errors',{}):
        runner.env = previous
        log.write_text('UTC_NOT_RUN: primary startup log unavailable\n')
        return dict(status='BLOCKED',metrics={},reason='primary startup log unavailable',log=log.relative_to(runner.out).as_posix())
    raw = runner.tmp / 'private-startup' / ('utc-' + str(len(runner.private_logs)) + '.log')
    raw.touch(mode=0o600)
    runner.private_logs[log] = raw
    rows = []; status = 'BLOCKED'; reason = 'UTC smoke not executed'
    try:
        process = runner.project_spawn(argv, runner.work / part['path'], runner.env, raw, phase='application')
        for route in part['routes'][:3]:
            target = urlsplit(url)
            candidate = target.scheme + '://' + target.netloc + route
            runner.executor.last_health = {}
            options = {'ca_file': runner.active_transport['ca_bundle']} if runner.active_transport else {}
            runner.executor.health(candidate, runner.budget.remaining(10), **options)
            if hasattr(process, 'poll') and process.poll() is not None:
                raise Blocked('UTC process exited')
            code = runner.executor.last_health.get('status')
            rows.append(dict(route=route, http_status=code))
        status = 'FAIL' if any(r['http_status'] is not None and r['http_status'] >= 500 for r in rows) else 'PASS' if rows and all(type(r['http_status']) is int for r in rows) else 'BLOCKED'
        reason = 'UTC public HTTP smoke only; no date/business assertions'
    except (Blocked, OSError, ValueError, subprocess.SubprocessError) as error:
        reason = type(error).__name__ + ': UTC smoke unavailable'
    finally:
        if process is not None:
            runner.executor.stop(process)
        runner.env = previous
        runner.startup_text(log)
    metrics = dict(timezone='UTC', primary=previous.get('TZ'), routes=rows, scope='public_http_smoke')
    with log.open('a') as stream:
        stream.write('\n' + json.dumps(dict(status=status, metrics=metrics, reason=reason)) + '\n')
    return dict(status=status, metrics=metrics, reason=reason, log=log.relative_to(runner.out).as_posix())
