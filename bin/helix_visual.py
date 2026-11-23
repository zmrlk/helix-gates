"""Compatibility commands and compact, evidence-only runtime projections."""
import json
import re
import time
from urllib.parse import urlparse
from pathlib import Path
import shutil
import subprocess

HOME = Path(__file__).resolve().parent.parent
COMMANDS = {('visual', 'audit'): ('node', 'ui-audit.mjs'),
            ('visual', 'baseline'): ('node', 'visual-baseline.mjs'),
            ('perf', 'weight'): ('node', 'perf-audit.mjs'),
            ('review', 'screenshots'): ('sh', 'gemini-review.sh')}


def dispatch(argv):
    argv = list(argv)
    cwd = None
    while argv and argv[0] in ('--repo', '--state-dir', '--no-cache'):
        flag = argv.pop(0)
        if flag == '--no-cache':
            continue
        if not argv:
            return None
        value = argv.pop(0)
        if flag == '--repo':
            cwd = value
    command = COMMANDS.get(tuple(argv[:2]))
    if command is None:
        return None
    executable, script = command
    if '--help' in argv[2:]:
        print('usage: helix '+' '.join(argv[:2])+' [arguments; see below]', flush=True)
    if not shutil.which(executable):
        print(f'incomplete: missing {executable}')
        return 2
    return subprocess.call([executable, str(HOME/'scripts'/script), *argv[2:]], cwd=cwd)


def projection(folder, kind='visual', known=None):
    """Only import actual artifacts, never infer PASS from a filename."""
    path = Path(folder)/('audit.json' if kind == 'visual' else 'perf-audit.json')
    try:
        data = json.loads(path.read_text())
        summary = data.get('summary', {}) if kind == 'visual' else data
        status = summary.get('status', 'incomplete')
        if kind == 'visual' and status == 'passed' and (not summary.get('complete') or not data.get('runs') or summary.get('completed') != summary.get('planned')):
            status = 'incomplete'
        if kind == 'perf' and status == 'passed' and not data.get('routes'):
            status = 'incomplete'
        if status not in ('passed', 'failed', 'incomplete'):
            status = 'incomplete'
        extra = {}
        runs = [run for run in data.get('runs', []) if run] if kind == 'visual' else []
        finals = {urlparse(run.get('finalURL') or '') for run in runs}
        # Odesłanie jest oczekiwane tylko z sesją ekranów (known) i na inny oglądany ekran, który nie jest logowaniem ani stroną błędu.
        if (known is not None and status == 'incomplete' and runs and len(finals) == 1 and all(200 <= (run.get('httpStatus') or 0) < 300 for run in runs)
                and all(run.get('errors') and all('Przekierowanie na inny ekran' in e for e in run['errors']) for run in runs)):
            final, asked = finals.pop(), urlparse(data.get('url') or '')
            if ((final.scheme, final.netloc) == (asked.scheme, asked.netloc) and final.path.rstrip('/') != asked.path.rstrip('/') and final.path in known
                    and not re.search(r'log(in|owanie)|sign-?in|auth|error|b[lł][aą]d|denied|forbidden|unauthori|odmow|brak-?dost|not-?found|(^|/)(40[134]|50\d)(/|$)', final.path, re.I)):
                status, extra = 'redirected', dict(redirects_to=final.path)
        if runs and all(run.get('obscured') for run in runs):
            status, extra = 'obscured', dict(obscured_by=runs[0]['obscured'])
        arrivals = sorted({run['arrival']['window'] for run in runs if run.get('arrival')})
        if arrivals and status != 'obscured':
            extra['arrival_window'] = arrivals[0]
        # pomiar, który miał oglądać stany, ale skończył się wcześniej (odesłanie), niesie samą flagę, nie listę
        states = [state for run in runs if isinstance(run.get('states'), list) for state in run['states']]
        if states:
            if any(run.get('statesIncomplete') for run in runs):
                extra['states_incomplete'] = next(run['statesIncomplete'] for run in runs if run.get('statesIncomplete'))
            extra['states'] = dict(found=sum(run.get('statesFound', 0) for run in runs), skipped=sum(run.get('statesSkipped', 0) for run in runs),
                                   not_run=sum(state.get('kind') == 'not-run' for state in states), triggers=len(states), opened=sum(state.get('kind') in ('dialog', 'menu', 'tab', 'expanded') for state in states),
                                   kinds={kind: sum(state.get('kind') == kind for state in states) for kind in sorted({str(state.get('kind')) for state in states})},
                                   repeated=sum(state.get('repeated', 0) for state in states),
                                   blockers=sum(state.get('blockers', 0) for state in states), blocked_writes=sum(run.get('blockedWrites', 0) for run in runs))
        examples = data.get('errors', []) + data.get('fails', [])
        for run in data.get('runs', []):
            examples += run.get('errors', []) + run.get('contrast', []) + run.get('clip', [])
        return dict(status=status, completed=summary.get('completed', len(data.get('routes', []))),
                    blockers=summary.get('blockers', len(data.get('fails', []))), examples=examples[:3],
                    evidence=str(path), report=str(path.parent/'report.html') if kind == 'visual' else str(path),
                    visual=summary.get('visual', 'not_checked'), manual_review='required', **extra)
    except (OSError, ValueError, TypeError, AttributeError):
        return dict(status='needs-runtime', reason='Brak czytelnego raportu audytu', evidence=str(path))


def session_lost(result):
    """Sesja była, a trasa skończyła odesłaniem, którego nie da się uznać za oczekiwane (np. na logowanie)."""
    return result.get('status') == 'incomplete' and any('odsyła na inny ekran' in str(e) or 'Przekierowanie na inny ekran' in str(e) for e in result.get('examples', []))


def measured(run, state, renew, clock, route=None):
    """Pomiar trasy z odnowieniem sesji: sesja aplikacji wygasa w trakcie długiego przeglądu (token na 30 minut), a człowiek
    zalogowałby się wtedy ponownie. Odesłanie krótko po odnowieniu to zachowanie samej trasy, nie wygasła sesja."""
    current = state() if callable(state) else state
    result = run(current)
    if renew and current and session_lost(result) and time.monotonic()-clock[0] > 120:
        clock[0] = time.monotonic()
        if renew(route):
            result = dict(run(state() if callable(state) else state), session_renewed=True)
    return result


def pattern_regex(pattern):
    return re.compile('^'+'/'.join('[^/]+' if re.fullmatch(r'\[.+\]', part) else re.escape(part) for part in pattern.split('/'))+'/?$')


def runtime_audits(execute, node, cwd, url, routes, out, weight_result=None, storage_state=None, throttled=(), session_for=None, ui_args=(), renew=None, patterns=()):
    """Called only after runtime starts in the existing disposable workspace."""
    out = Path(out)
    results = []
    clock = [float('-inf')]

    def audit(index, route, extra=None):
        folder = out/str(index)

        def run(state):
            known = set(routes) if state else None
            try:
                execute([node, str(HOME/'scripts/ui-audit.mjs'), url.rstrip('/')+'/'+route.lstrip('/'),
                         '--out', str(folder), '--case', route, '--sweep', '280-1600:40',
                         *(['--storage-state', str(state)] if state else []),
                         *(['--throttled-paths', ','.join(throttled)] if throttled else []), *ui_args, '--states', '60', '--states-seen', str(out/'states-seen.json')], cwd, maximum=300)
            except Exception as error:
                result = projection(folder, known=known)
                if result['status'] == 'needs-runtime':
                    result['reason'] = str(error)
                return result
            return projection(folder, known=known)
        # Sesja trasy: scenariusz właściciela dla tras o jego początku, inaczej sesja roli ekranów; może istnieć bez tej drugiej.
        state = (lambda: session_for(route)) if session_for else storage_state
        results.append(dict(route=route, **measured(run, state, renew, clock, route), **(extra or {})))

    for index, route in enumerate(routes):
        audit(index, route)
    # Ekran szczegółów bez znanego adresu (trasa z parametrem): adres daje kliknięcie wiersza listy w przeglądzie stanów,
    # tak jak doszedłby tam człowiek. Jeden ekran na wzorzec trasy.
    reached = {}
    for result in list(results):
        try:
            runs = [run for run in json.loads(Path(result['evidence']).read_text()).get('runs', []) if run]
        except (OSError, ValueError, KeyError):
            continue
        for state in (state for run in runs if isinstance(run.get('states'), list) for state in run['states']):
            target = state.get('target') if state.get('kind') == 'navigation' else None
            if not isinstance(target, str) or any(row['route'].rstrip('/') == target.rstrip('/') for row in results):
                continue
            pattern = next((pattern for pattern in patterns if pattern_regex(pattern).match(target)), None)
            if pattern and pattern not in reached and not any(pattern_regex(pattern).match(row['route']) for row in results):
                reached[pattern] = (target, result['route'])
    for offset, (pattern, (target, source)) in enumerate(sorted(reached.items())[:40]):
        audit(len(routes)+offset, target, dict(pattern=pattern, reached_from=source))
    return dict(visual=results, self_check=self_check(results), weight=weight_result if weight_result is not None else runtime_weight(execute, node, cwd, out/'weight'),
                session_renewals=sum(1 for row in results if row.get('session_renewed')),
                reached_by_click=[dict(pattern=row['pattern'], route=row['route'], reached_from=row['reached_from']) for row in results if row.get('reached_from')])


def sparse_pass(execute, node, cwd, url, routes, out, storage_state=None, session_for=None, ui_args=(), renew=None):
    """Jedno zdjęcie każdego ekranu przy skąpych danych (jedna szerokość, bez przemiatania i klikania): stan pusty lub prawie pusty."""
    out = Path(out)
    shots = []
    clock = [float('-inf')]
    for index, route in enumerate(routes):
        folder = out/str(index)

        def run(state):
            try:
                execute([node, str(HOME/'scripts/ui-audit.mjs'), url.rstrip('/')+'/'+route.lstrip('/'), '--out', str(folder), '--case', route+' [skąpe dane]',
                         '--widths', '1440', '--themes', 'light', *ui_args, *(['--storage-state', str(state)] if state else [])], cwd, maximum=120)
            except Exception:
                pass
            return projection(folder, known=set(routes) if state else None)
        result = measured(run, (lambda: session_for(route)) if session_for else storage_state, renew, clock, route)
        shot = folder/'shot-light-1440.png'
        shots.append(dict(route=route, status=result['status'], blockers=result.get('blockers', 0), shot=str(shot) if shot.is_file() else None, evidence=result.get('evidence')))
    return dict(status='RECORDED', routes=len(shots), with_shot=sum(1 for row in shots if row['shot']), screens=shots)


FINDING_KEYS = ('tap', 'contrast', 'clip', 'lead', 'edge', 'axis', 'gap', 'a11y', 'fontOffLadder', 'runtime')


def run_lines(run):
    """Błędy wykonania jednego pomiaru: po wejściu, po każdym kliknięciu i z odrzuconych podejść."""
    states = run.get('states') if isinstance(run.get('states'), list) else []
    return [line for source in [run, *states, *(run.get('attempts') or [])] for line in source.get('runtime') or []]


def self_check(results, minimum=4, share=.5):
    """Czy przegląd tras opisuje ekrany. To samo znalezisko na większości tras to cecha wspólnej powłoki albo czegoś,
    co zasłania ekrany, a nie tyle osobnych usterek; okno otwarte od wejścia znaczy, że ekranu nie widać wcale."""
    seen, measured, failed, opened = {}, 0, {}, 0
    for result in results:
        if result.get('status') not in ('passed', 'failed', 'incomplete'):
            continue
        try:
            runs = [run for run in json.loads(Path(result['evidence']).read_text()).get('runs', []) if run]
        except (OSError, ValueError, KeyError):
            runs = []
        opened += 1
        if result['status'] == 'incomplete':
            runs, late = [], runs
        else:
            measured, late = measured+1, runs
        for item in {key+': '+str(value) for run in runs for key in FINDING_KEYS for value in run.get(key) or []}:
            seen.setdefault(item, set()).add(result['route'])
        # Żądania do zaplecza zakończone błędem: ekran, którego dotyczą, pokazuje stan błędu albo pusty, więc jego uwagi
        # opisują aplikację bez tej części zaplecza (funkcji serwerowej, danych), a nie ekran, jaki widzi użytkownik.
        broken = {(match.group(1), urlparse(match.group(2)).path) for run in late for line in run_lines(run)
                  for match in [re.match(r'HTTP (\d{3}): (\S+)', str(line))] if match}
        for item in broken: failed.setdefault(item, set()).add(result['route'])
        if broken: result['failed_requests'] = len(broken)
    threshold = max(minimum, measured*share)
    shared = sorted(({'finding': item[:200], 'routes': len(routes)} for item, routes in seen.items() if len(routes) >= threshold),
                    key=lambda row: (-row['routes'], row['finding']))
    obscured = sorted({result['obscured_by'] for result in results if result.get('status') == 'obscured'})
    passed = sum(result.get('status') == 'passed' for result in results)
    # Uwagi do wspólnej powłoki (menu, pasek) są zgłaszane raz; trasę ocenia się po tym, co jest tylko jej.
    shell = {item for item, routes in seen.items() if len(routes) >= threshold}
    own = {route: 0 for route in {r for routes in seen.values() for r in routes}}
    for item, routes in seen.items():
        if item not in shell:
            for route in routes: own[route] += 1
    for result in results:
        if result.get('status') in ('passed', 'failed'):
            result['own_findings'] = own.get(result['route'], 0)
            result['status_without_shell'] = 'passed' if not result['own_findings'] else 'failed'
    passed_own = sum(result.get('status_without_shell') == 'passed' for result in results)
    reasons = []
    if obscured:
        reasons.append('okno zasłania ekran po wejściu na '+str(sum(r.get('status') == 'obscured' for r in results))+' trasach: '+'; '.join(obscured[:3]))
    arrivals = {}
    for result in results:
        if result.get('arrival_window'):
            arrivals[result['arrival_window']] = arrivals.get(result['arrival_window'], 0)+1
    for window, count in sorted(arrivals.items()):
        reasons.append('okno „'+window+'” otwierało się po wejściu na '+str(count)+' trasach; zamykane przed pomiarem')
    states = [result['states'] for result in results if result.get('states')]
    if states:
        total = {key: sum(row.get(key, 0) for row in states) for key in ('found', 'triggers', 'opened', 'skipped', 'not_run', 'blockers')}
        reasons.append('stany po kliknięciu: znaleziono '+str(total['found'])+' wyzwalaczy, kliknięto '+str(total['triggers']-total['not_run'])+', otwarto '+str(total['opened'])
                       +', pominięto '+str(total['skipped']+total['not_run'])+', nowych uwag '+str(total['blockers']))
    requests = sorted(({'status': int(status), 'path': path[:160], 'routes': len(routes)} for (status, path), routes in failed.items()),
                      key=lambda row: (-row['routes'], row['path'], row['status']))
    if requests:
        reasons.append('żądania do zaplecza zakończone błędem na '+str(len({r for routes in failed.values() for r in routes}))+' z '+str(opened)
                       +' otwartych tras ('+str(len(requests))+' adresów); uwagi do tych ekranów opisują stan bez tej części zaplecza')
    if shared:
        reasons.append(str(len(shared))+' znalezisk powtarza się na co najmniej '+str(int(threshold))+' z '+str(measured)+' zmierzonych tras (wspólna powłoka albo coś zasłania ekrany)')
    if shared:
        reasons.append('po odjęciu uwag wspólnej powłoki przechodzi '+str(passed_own)+' z '+str(measured)+' zmierzonych tras')
    elif measured >= minimum and passed*10 < measured:
        reasons.append('przeszło '+str(passed)+' z '+str(measured)+' zmierzonych tras')
    # Podejrzany jest przegląd, w którym ekran zasłania okno albo niemal wszystkie uwagi są te same na wszystkich trasach
    # (pomiar ogląda wtedy coś wspólnego, nie ekrany). Dużo własnych uwag na trasach to wynik, nie powód do podejrzeń.
    total = sum(len(routes) for routes in seen.values())
    same = sum(len(routes) for item, routes in seen.items() if item in shell)
    uniform = measured >= minimum and total > 0 and same*10 >= total*8
    if uniform:
        reasons.append(str(round(same*100/total))+'% wszystkich uwag to te same uwagi powtórzone na trasach')
    return dict(status='SUSPECT' if obscured or uniform else 'OK', measured=measured, passed=passed,
                passed_without_shell=passed_own, reasons=reasons, shared_findings=shared[:30], shared_total=len(shared), failed_requests=requests[:60])


def runtime_weight(execute, node, cwd, out):
    try:
        execute([node, str(HOME/'scripts/perf-audit.mjs'), str(cwd), '--out', str(out)], cwd, maximum=60)
    except Exception as error:
        result = projection(out, 'perf')
        if result['status'] == 'needs-runtime':
            result['reason'] = str(error)
        return result
    return projection(out, 'perf')



def compact_runtime(parts):
    results = []
    for part in parts:
        audits = part.get('legacy_audits', {})
        visual = audits.get('visual', [])
        results.append(dict(name=part['name'], routes=len(visual),
                            completed=sum(r.get('completed', 0) for r in visual),
                            blockers=sum(r.get('blockers', 0) for r in visual),
                            statuses={s:sum(r.get('status')==s for r in visual)
                                      for s in ('passed','failed','incomplete','redirected','obscured','needs-runtime')},
                            self_check={k:v for k,v in audits.get('self_check', {}).items() if k != 'shared_findings'},
                            examples=[e for r in visual for e in r.get('examples', [])][:3],
                            reports=[r['report'] for r in visual if r.get('report')][:3],
                            weight=audits.get('weight', {'status':'needs-runtime', 'reason':audits.get('reason','Brak buildu/audytu')})))
    return results
