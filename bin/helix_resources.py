"""Read-only host telemetry and admission control. Never signal other processes."""
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time

DEFAULT_POLICY = dict(high_load_ratio=1.5, critical_load_ratio=3.0,
                      high_memory_available_ratio=.15, critical_memory_available_ratio=.05,
                      critical_psi_full_avg10=10.0, sample_s=5.0, poll_s=5.0,
                      max_pause_s=300.0, stale_after_s=15.0)
SOURCE_NAMES = ('cpu_count', 'affinity', 'getloadavg', 'sysctl_pressure', 'sysctl_memsize',
                'vm_stat', 'meminfo', 'psi_memory', 'cgroup_v2', 'snapshot')
NUMBER_FIELDS = ('logical_cpus', 'load1', 'load_ratio', 'memory_available_bytes',
                 'memory_total_bytes', 'memory_available_ratio', 'psi_memory_full_avg10',
                 'psi_memory_some_avg10')


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def _iso(now=None):
    return datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).isoformat()


def _empty(system='unknown', now=None):
    return dict(schema_version=1, platform=system if system in ('Darwin', 'Linux', 'Windows') else 'unknown',
                observed_at=_iso(now), **{name: None for name in NUMBER_FIELDS}, memory_pressure='unknown',
                sources={}, missing=[], confidence='unknown', vm_stat=None)


def _run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=1,
                          env={'PATH': os.defpath, 'LC_ALL': 'C'}, cwd=Path(__file__).parent)


def parse_vm_stat(text):
    match = re.search(r'page size of (\d+) bytes', text)
    if not match: return None
    page_size = int(match[1])
    if not 0 < page_size <= 1_048_576: return None
    values = {}
    names = {'Pages free': 'free_bytes', 'Pages inactive': 'inactive_bytes',
             'Pages speculative': 'speculative_bytes', 'Pages occupied by compressor': 'compressor_bytes'}
    for line in text.splitlines():
        row = re.fullmatch(r'([^:]+):\s*(\d+)\.?\s*', line)
        if row and row[1] in names: values[names[row[1]]] = int(row[2]) * page_size
    return dict(page_size=page_size, **values, meaning='VM counters; free pages alone do not establish memory pressure')


def snapshot(*, read_text=None, run=None, platform_name=None, now=None):
    """Fixed OS metadata only; no processes, argv, environment, credentials or network."""
    read_text = read_text or (lambda path: Path(path).read_text())
    run = run or _run
    system = platform_name or platform.system()
    data = _empty(system, now)
    def missing(name):
        data['sources'][name] = 'unavailable'
        if name not in data['missing']: data['missing'].append(name)
    cpus = os.cpu_count()
    if cpus:
        data['logical_cpus'] = cpus; data['sources']['cpu_count'] = 'recorded'
    else: missing('cpu_count')
    if system == 'Linux' and hasattr(os, 'sched_getaffinity'):
        try:
            count = len(os.sched_getaffinity(0))
            if count: data['logical_cpus'] = min(cpus, count) if cpus else count
            data['sources']['affinity'] = 'recorded'
        except OSError: missing('affinity')
    try:
        load = os.getloadavg()[0]
        if _number(load): data['load1'] = load; data['sources']['getloadavg'] = 'recorded'
        else: missing('getloadavg')
    except (AttributeError, OSError): missing('getloadavg')
    if system == 'Darwin':
        for key, label in (('kern.memorystatus_vm_pressure_level', 'sysctl_pressure'), ('hw.memsize', 'sysctl_memsize')):
            try:
                result = run(['/usr/sbin/sysctl', '-n', key])
                if result.returncode: raise ValueError('unavailable')
                value = int(result.stdout.strip())
                if label == 'sysctl_pressure':
                    if value not in (1, 2, 4): raise ValueError('unknown level')
                    data['memory_pressure'] = {1: 'normal', 2: 'high', 4: 'critical'}[value]
                elif value > 0: data['memory_total_bytes'] = value
                else: raise ValueError('invalid memory size')
                data['sources'][label] = 'recorded'
            except (OSError, ValueError, subprocess.SubprocessError): missing(label)
        try:
            result = run(['/usr/bin/vm_stat'])
            parsed = parse_vm_stat(result.stdout) if result.returncode == 0 else None
            if parsed is None: raise ValueError('invalid vm_stat')
            data['vm_stat'] = parsed; data['sources']['vm_stat'] = 'recorded'
        except (OSError, ValueError, subprocess.SubprocessError): missing('vm_stat')
        # vm_stat free/inactive counters are not Linux MemAvailable and are not
        # promoted to an available-memory percentage, even when total is known.
    elif system == 'Linux':
        try:
            values = {key: int(value) * 1024 for key, value in re.findall(r'^(MemTotal|MemAvailable):\s*(\d+)\s+kB\s*$', read_text('/proc/meminfo'), re.M)}
            if not values.get('MemTotal') or 'MemAvailable' not in values: raise ValueError('missing memory data')
            if values['MemAvailable'] > values['MemTotal']: raise ValueError('invalid memory data')
            data.update(memory_available_bytes=values['MemAvailable'], memory_total_bytes=values['MemTotal'])
            data['sources']['meminfo'] = 'recorded'
        except (OSError, ValueError): missing('meminfo')
        try:
            values = {kind: float(value) for kind, value in re.findall(r'^(some|full)\s+avg10=(\d+(?:\.\d+)?)\s', read_text('/proc/pressure/memory'), re.M)}
            if not values or any(not 0 <= value <= 100 for value in values.values()): raise ValueError('invalid PSI')
            data.update(psi_memory_full_avg10=values.get('full'), psi_memory_some_avg10=values.get('some'))
            data['sources']['psi_memory'] = 'recorded'
        except (OSError, ValueError): missing('psi_memory')
        # cgroup v2 limits are optional, but never substitute swap capacity for RAM.
        try:
            group = next(line[3:] for line in read_text('/proc/self/cgroup').splitlines() if line.startswith('0::'))
            root = Path('/sys/fs/cgroup'); location = root / group.lstrip('/')
            if '..' in location.parts: raise ValueError('invalid cgroup path')
            memory_max = read_text(str(location / 'memory.max')).strip()
            if memory_max != 'max':
                maximum = int(memory_max); current = int(read_text(str(location / 'memory.current')).strip())
                if maximum <= 0 or current < 0: raise ValueError('invalid cgroup memory')
                total = data['memory_total_bytes']; available = data['memory_available_bytes']
                data['memory_total_bytes'] = min(total, maximum) if total is not None else maximum
                remaining = max(0, maximum - current)
                data['memory_available_bytes'] = min(available, remaining) if available is not None else remaining
            data['sources']['cgroup_v2'] = 'recorded'
        except (OSError, ValueError, StopIteration): missing('cgroup_v2')
    else:
        data['missing'].append('unsupported_memory_platform')
    if data['logical_cpus'] and data['load1'] is not None: data['load_ratio'] = data['load1'] / data['logical_cpus']
    if data['memory_total_bytes'] and data['memory_available_bytes'] is not None:
        data['memory_available_ratio'] = data['memory_available_bytes'] / data['memory_total_bytes']
    usable = data['load_ratio'] is not None or data['memory_available_ratio'] is not None or data['memory_pressure'] != 'unknown' or data['psi_memory_full_avg10'] is not None
    data['confidence'] = 'partial' if usable and data['missing'] else 'recorded' if usable else 'unknown'
    return data


def policy_values(policy=None):
    if policy is not None and not isinstance(policy, dict): raise ValueError('resources musi być obiektem JSON')
    result = dict(DEFAULT_POLICY)
    if set(policy or {}) - set(result): raise ValueError('Nieznany próg resources')
    result.update(policy or {})
    if any(not _number(value) or value <= 0 for value in result.values()): raise ValueError('Progi resources muszą być dodatnie i skończone')
    if result['high_load_ratio'] >= result['critical_load_ratio']: raise ValueError('critical_load_ratio musi przekraczać high_load_ratio')
    if not 0 < result['critical_memory_available_ratio'] < result['high_memory_available_ratio'] < 1: raise ValueError('Niepoprawne progi pamięci resources')
    if result['critical_psi_full_avg10'] > 100: raise ValueError('Niepoprawny próg PSI resources')
    return result


def _clean_sample(sample):
    sample = sample if isinstance(sample, dict) else {}
    clean = _empty(sample.get('platform'))
    for key in NUMBER_FIELDS: clean[key] = sample.get(key) if _number(sample.get(key)) else None
    if sample.get('memory_pressure') in ('normal', 'high', 'critical', 'unknown'): clean['memory_pressure'] = sample['memory_pressure']
    if sample.get('confidence') in ('recorded', 'partial', 'unknown'): clean['confidence'] = sample['confidence']
    try:
        stamp = datetime.fromisoformat(sample.get('observed_at', ''))
        if stamp.tzinfo is not None: clean['observed_at'] = stamp.isoformat()
    except (TypeError, ValueError): pass
    sources = sample.get('sources', {})
    if isinstance(sources, dict): clean['sources'] = {key: value for key, value in sources.items() if key in SOURCE_NAMES and value in ('recorded', 'partial', 'unavailable', 'unsupported')}
    clean['missing'] = [name for name in sample.get('missing', []) if name in (*SOURCE_NAMES, 'unsupported_memory_platform')] if isinstance(sample.get('missing'), list) else []
    if isinstance(sample.get('vm_stat'), dict):
        clean['vm_stat'] = {key: value for key, value in sample['vm_stat'].items() if key in ('page_size', 'free_bytes', 'inactive_bytes', 'speculative_bytes', 'compressor_bytes') and _number(value)}
    return clean


def decide(sample, requested_jobs, policy=None, previous=None):
    if not isinstance(requested_jobs, int) or isinstance(requested_jobs, bool) or requested_jobs < 1: raise ValueError('requested_jobs musi być dodatnią liczbą całkowitą')
    thresholds = policy_values(policy); sample = _clean_sample(sample)
    critical = []; high = []; known = False
    level = sample['memory_pressure']
    if level != 'unknown': known = True
    if level == 'critical': critical.append('systemowa presja pamięci critical')
    elif level == 'high': high.append('systemowa presja pamięci high')
    load = sample['load_ratio']
    if load is not None:
        known = True
        if load >= thresholds['critical_load_ratio']: critical.append('load/CPU przekracza próg critical')
        elif load >= thresholds['high_load_ratio']: high.append('load/CPU przekracza próg high')
    available = sample['memory_available_ratio']
    if available is not None:
        known = True
        if available < thresholds['critical_memory_available_ratio']: critical.append('dostępna pamięć poniżej progu critical')
        elif available < thresholds['high_memory_available_ratio']: high.append('dostępna pamięć poniżej progu high')
    psi = sample['psi_memory_full_avg10']
    if psi is not None:
        known = True
        if psi >= thresholds['critical_psi_full_avg10']: critical.append('PSI full avg10 przekracza próg critical')
    state = 'critical' if critical else 'high' if high else 'normal' if known else 'unknown'
    jobs = 0 if critical else max(1, requested_jobs // 2) if high else requested_jobs if known else 1
    reason = '; '.join(critical or high) or ('Brak użytecznego pomiaru; ostrożny limit jednego zadania' if not known else 'Brak przekroczenia progów w dostępnych pomiarach')
    if sample['confidence'] == 'partial': reason += '; pomiar częściowy'
    return dict(schema_version=1, state=state, requested_jobs=requested_jobs, effective_jobs=jobs, reason=reason, thresholds=thresholds, sample=sample)


class ResourcePaused(Exception):
    def __init__(self, message, decision=None):
        super().__init__(message); self.message = message; self.decision = decision or {}


@contextmanager
def _directory(path):
    """Create/open every output parent using no-follow descriptors."""
    from helix_audit_context import system_path
    path = system_path(Path(path).expanduser().absolute())
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try: os.mkdir(component, dir_fd=fd)
            except FileExistsError: pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        yield fd
    finally: os.close(fd)


def _atomic(path, value):
    with _directory(path.parent) as parent:
        try:
            if not stat.S_ISREG(os.stat(path.name, dir_fd=parent, follow_symlinks=False).st_mode): raise ValueError('resource output must be a regular file')
        except FileNotFoundError: pass
        temporary = '.' + path.name + '-' + secrets.token_hex(8)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'w') as stream: json.dump(value, stream, allow_nan=False); stream.write('\n')
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            try: os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError: pass


class Governor:
    def __init__(self, snapshot_fn=None, policy=None, requested_jobs=3, out=None):
        self.snapshot_fn = snapshot_fn or snapshot; self.policy = policy_values(policy)
        decide({}, requested_jobs, self.policy)  # validate without sampling
        self.requested_jobs = requested_jobs; self.out = Path(out) if out is not None else None
        self.current_path = self.out / 'resource-current.json' if self.out else None
        self._lock = threading.RLock(); self._last = None; self._sampled = None
        self._history = []; self._recorded = None; self._signature = None; self._published = None
        self._clock = time.monotonic; self._sleep = time.sleep

    @property
    def history(self):
        with self._lock: return copy.deepcopy(self._history)

    @property
    def decisions(self): return self.history

    def decision(self, force=False):
        with self._lock:
            now = self._clock()
            if force or self._last is None or self._sampled is None or now - self._sampled >= self.policy['sample_s']:
                try: sample = self.snapshot_fn()
                except Exception: sample = dict(_empty(), missing=['snapshot'])
                self._last = decide(sample, self.requested_jobs, self.policy, self._last); self._sampled = now
            result = copy.deepcopy(self._last)
            result.update(updated_at=_iso(), max_pause_s=self.policy['max_pause_s'], poll_s=self.policy['poll_s'], stale_after_s=self.policy['stale_after_s'])
            signature = (result['state'], result['effective_jobs'], result['reason'])
            changed = signature != self._signature
            if changed or self._recorded is None or now - self._recorded >= 30:
                self._history.append(copy.deepcopy(result)); self._signature = signature; self._recorded = now
                print(f"[helix resources] {result['state']}: jobs {result['effective_jobs']}/{self.requested_jobs}; {result['reason']}", file=sys.stderr, flush=True)
                if self.out:
                    path = self.out / 'resource-decisions.jsonl'
                    with _directory(self.out) as parent:
                        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            os.close(fd); raise ValueError('resource history must be a regular file')
                        with os.fdopen(fd, 'w') as stream: stream.write(json.dumps(result, ensure_ascii=False, allow_nan=False) + '\n')
            if self.current_path and (force or changed or self._published is None or now - self._published >= self.policy['poll_s']):
                _atomic(self.current_path, result); self._published = now
            return result

    def wait(self, stop=None):
        started = self._clock()
        while True:
            remaining = None
            if stop is not None:
                remaining = stop()
                if isinstance(remaining, (int, float)) and not isinstance(remaining, bool) and remaining <= 0:
                    raise ResourcePaused('Budżet wyczerpany podczas oczekiwania na zasoby', self.decision())
            decision = self.decision()
            if decision['effective_jobs'] > 0: return decision
            if self._clock() - started >= self.policy['max_pause_s']:
                raise ResourcePaused('resource_paused: przekroczono resources.max_pause_s; zachowano wyniki i niewykonane zadania', decision)
            delay = min(self.policy['poll_s'], self.policy['max_pause_s'] - (self._clock() - started))
            if _number(remaining) and not isinstance(remaining, bool): delay = min(delay, remaining)
            self._sleep(max(0, delay))

    @contextmanager
    def monitor(self):
        if self.current_path is None: raise ValueError('Monitor zasobów wymaga zewnętrznego out')
        self.decision(); stopped = threading.Event()
        def watch():
            while not stopped.wait(self.policy['poll_s']):
                try: self.decision()
                except (OSError, ValueError): break  # JS watchdog detects a stale writer.
        worker = threading.Thread(target=watch, name='helix-resource-monitor', daemon=True); worker.start()
        try: yield self.current_path
        finally:
            stopped.set(); worker.join(timeout=self.policy['poll_s'] + 5)
