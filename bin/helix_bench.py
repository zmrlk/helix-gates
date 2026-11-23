"""Metadata-only benchmark on explicitly reviewed detector/file/line labels.

No target I/O or process belongs to the evaluator. Source revision evidence is
supplied by a trusted caller; a dirty flag alone cannot establish or reject it.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SCORING_VERSION = 'reviewed-exact-locations-v1'
MATCHING = 'exact_detector_file_line'
VERDICTS = {'confirmed', 'rejected', 'needs_validation'}
FINDING_VERDICTS = VERDICTS | {'candidate', 'unclear'}
SOURCE_STATES = {'MATCHED', 'MISMATCH', 'UNKNOWN'}


class BenchError(ValueError):
    def __init__(self, code):
        self.code = code
        self.status = 'ERROR'
        super().__init__(code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _path(value, *, absolute=False):
    if not isinstance(value, str) or not value or len(value) > 4096 or '\\' in value or any(ord(c) < 32 for c in value):
        raise BenchError('INVALID_PATH')
    path = PurePosixPath(value)
    if path.is_absolute() is not absolute or '..' in path.parts or str(path) != value or value in ('.', '/'):
        raise BenchError('INVALID_PATH')
    return value


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value):
        raise BenchError('INVALID_DETECTOR_OR_GROUP')
    return value


def _commit(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value)):
        raise BenchError('INVALID_COMMIT')
    return value


def _identity(value):
    if not isinstance(value, dict):
        raise BenchError('INVALID_TARGET_IDENTITY')
    dirty = value.get('dirty')
    if dirty is not None and type(dirty) is not bool:
        raise BenchError('INVALID_DIRTY_FLAG')
    return dict(path=_path(value.get('path'), absolute=True), commit=_commit(value.get('commit')), dirty=dirty)


def _location(detector, file, line):
    if type(line) is not int or line < 1:
        raise BenchError('INVALID_LINE')
    return _name(detector), _path(file), line


def _key(row):
    return row['detector'], row['file'], row['line']


def normalize_labels(payload):
    if not isinstance(payload, dict) or type(payload.get('schema_version')) is not int or payload['schema_version'] != 1:
        raise BenchError('INVALID_LABEL_SCHEMA')
    identity = _identity(payload.get('repo'))
    if payload.get('location_matching', MATCHING) != MATCHING:
        raise BenchError('UNSUPPORTED_LOCATION_MATCHING')
    values = payload.get('labels')
    if not isinstance(values, list) or not values:
        raise BenchError('EMPTY_OR_INVALID_LABELS')
    found = {}
    for value in values:
        if not isinstance(value, dict):
            raise BenchError('INVALID_LABEL')
        key = _location(value.get('detector'), value.get('file'), value.get('line'))
        verdict = value.get('verdict')
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            raise BenchError('INVALID_LABEL_VERDICT')
        group = _name(value['issue_group']) if value.get('issue_group') is not None else None
        refs = value.get('sources', [])
        if not isinstance(refs, list):
            raise BenchError('INVALID_LABEL_SOURCES')
        references = []
        for ref in refs:
            if not isinstance(ref, dict) or type(ref.get('row')) is not int or ref['row'] < 0 or not isinstance(ref.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', ref['sha256']):
                raise BenchError('INVALID_LABEL_SOURCES')
            references.append(dict(file=_path(ref.get('file')), row=ref['row'], sha256=ref['sha256']))
        row = found.setdefault(key, dict(detector=key[0], file=key[1], line=key[2], verdict=verdict,
                                         issue_group=group, sources=[]))
        if row['verdict'] != verdict:
            raise BenchError('CONFLICTING_LABEL_VERDICTS')
        if row['issue_group'] != group:
            raise BenchError('CONFLICTING_LABEL_GROUPS')
        row['sources'].extend(references)
    rows = [found[key] for key in sorted(found)]
    for row in rows:
        refs = {(ref['file'], ref['row'], ref['sha256']) for ref in row['sources']}
        row['sources'] = [dict(file=file, row=index, sha256=digest) for file, index, digest in sorted(refs)]
    repo = dict(path=identity['path'], commit=identity['commit'])
    scoring_labels = [{k: row[k] for k in ('detector', 'file', 'line', 'verdict', 'issue_group')} for row in rows]
    return dict(schema_version=1, repo=repo, location_matching=MATCHING, labels=rows,
                sha256=_digest(dict(repo=repo, location_matching=MATCHING, labels=scoring_labels)),
                digest_basis='canonical_scoring_labels_v1', input_rows=len(values), unique_labels=len(rows))


def normalize_findings(values):
    if not isinstance(values, list):
        raise BenchError('INVALID_FINDINGS')
    found = {}
    for value in values:
        if not isinstance(value, dict):
            raise BenchError('INVALID_FINDING')
        detector = value.get('detector', value.get('id'))
        if value.get('detector') is not None and value.get('id') is not None and value['detector'] != value['id']:
            raise BenchError('CONFLICTING_FINDING_DETECTORS')
        detector = _name(detector)
        verdicts = {value[k] for k in ('verdict', 'verification_status', 'observed_verdict') if value.get(k) is not None and isinstance(value[k], str)}
        if any(k in value and value[k] is not None and not isinstance(value[k], str) for k in ('verdict', 'verification_status', 'observed_verdict')) or not verdicts <= FINDING_VERDICTS:
            raise BenchError('INVALID_FINDING_VERDICT')
        if len(verdicts) > 1:
            raise BenchError('CONFLICTING_FINDING_VERDICTS')
        verdict = next(iter(verdicts), None)
        places = []
        if 'file' in value or 'line' in value:
            places.append(_location(detector, value.get('file'), value.get('line')))
        locations = value.get('locations', [])
        if not isinstance(locations, list):
            raise BenchError('INVALID_FINDING_LOCATIONS')
        for place in locations:
            if isinstance(place, str):
                file, sep, line = place.rpartition(':')
                if not sep or not line.isdecimal():
                    raise BenchError('INVALID_FINDING_LOCATIONS')
                places.append(_location(detector, file, int(line)))
            elif isinstance(place, dict):
                places.append(_location(detector, place.get('file', place.get('path')), place.get('line')))
            else:
                raise BenchError('INVALID_FINDING_LOCATIONS')
        if not places:
            raise BenchError('INVALID_FINDING_LOCATIONS')
        for key in set(places):
            row = found.setdefault(key, dict(detector=key[0], file=key[1], line=key[2], observed_verdict=verdict))
            if row['observed_verdict'] is not None and verdict is not None and row['observed_verdict'] != verdict:
                raise BenchError('CONFLICTING_FINDING_VERDICTS')
            if row['observed_verdict'] is None:
                row['observed_verdict'] = verdict
    return [found[key] for key in sorted(found)]


def _metrics(counts, verified):
    if not verified:
        return dict(tp=None, fp=None, fn=None, tn=None, precision=None, recall=None,
                    status='UNVERIFIED', precision_reason='UNVERIFIED_SOURCE_OR_SCAN', recall_reason='UNVERIFIED_SOURCE_OR_SCAN')
    tp, fp, fn, tn = (counts[key] for key in ('TP', 'FP', 'FN', 'TN'))
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None, status='SCORED_REVIEWED_LOCATIONS',
                precision_reason=None if tp + fp else 'NO_SCORED_DETECTIONS',
                recall_reason=None if tp + fn else 'NO_CONFIRMED_LABELS')


def evaluate(labels, findings, *, target, source_revision='UNKNOWN', scan_status='UNKNOWN', previous=None):
    """Score detector emissions, never use their own verdict as ground truth.

    MATCHED is explicit caller evidence for labelled file contents. Untracked
    files may make dirty=True while that content evidence remains valid.
    """
    normalized = normalize_labels(labels)
    detections = normalize_findings(findings)
    target = _identity(target)
    if not isinstance(source_revision, str) or source_revision not in SOURCE_STATES or not isinstance(scan_status, str) or scan_status not in {'COMPLETE', 'INCOMPLETE', 'UNKNOWN', 'ERROR'}:
        raise BenchError('INVALID_EVIDENCE_STATUS')
    gaps = []
    if target['path'] != normalized['repo']['path']:
        gaps.append('TARGET_PATH_MISMATCH')
    if target['commit'] is None or normalized['repo']['commit'] is None:
        gaps.append('SOURCE_COMMIT_UNKNOWN')
    if source_revision != 'MATCHED':
        gaps.append('SOURCE_REVISION_' + source_revision)
    if scan_status != 'COMPLETE':
        gaps.append('SCAN_' + scan_status)
    verified = not gaps
    by_key = {_key(row): row for row in detections}
    known = {_key(row): row for row in normalized['labels']}
    labelled, unlabelled = [], [row for row in detections if _key(row) not in known]
    by_detector = {name: [] for name in sorted({row['detector'] for row in normalized['labels'] + detections})}
    for label in normalized['labels']:
        detected = _key(label) in by_key
        verdict = label['verdict']
        outcome = ('TP' if detected else 'FN') if verdict == 'confirmed' else ('FP' if detected else 'TN') if verdict == 'rejected' else 'EXCLUDED'
        item = {key: label[key] for key in ('detector', 'file', 'line', 'verdict', 'issue_group')}
        item.update(detected=detected, outcome=outcome if verified or outcome == 'EXCLUDED' else 'UNSCORED')
        labelled.append(item)
        by_detector[label['detector']].append((item, outcome))
    per_detector = []
    all_counts = Counter()
    for detector, values in by_detector.items():
        counts = Counter(outcome for _, outcome in values)
        all_counts.update(counts)
        per_detector.append(dict(detector=detector, metrics=_metrics(counts, verified),
                                 labels=Counter(item['verdict'] for item, _ in values),
                                 excluded=counts['EXCLUDED'],
                                 unlabelled_findings=sum(row['detector'] == detector for row in unlabelled),
                                 observations=dict(confirmed_present=counts['TP'], confirmed_absent=counts['FN'],
                                                   rejected_present=counts['FP'], rejected_absent=counts['TN'])))
    group_names = sorted({row['issue_group'] for row in normalized['labels'] if row['issue_group'] and row['verdict'] == 'confirmed'})
    groups = []
    for name in group_names:
        group = [row for row in labelled if row['issue_group'] == name and row['verdict'] == 'confirmed']
        hits = sum(row['detected'] for row in group)
        groups.append(dict(issue_group=name, labelled_locations=len(group), observed_hits=hits,
                           status='UNVERIFIED' if not verified else 'ALL_FOUND' if hits == len(group) else 'PARTIALLY_FOUND' if hits else 'NONE_FOUND'))
    report = dict(schema_version=1, kind='detector-benchmark', scoring_version=SCORING_VERSION,
                  status='COMPLETE' if verified else 'INCOMPLETE', target=target,
                  source_revision=dict(status=source_revision, label_commit=normalized['repo']['commit'], target_commit=target['commit'], basis='caller_supplied_labelled_file_evidence'),
                  scan_status=scan_status, labels=normalized, findings=detections,
                  summary=dict(metrics=_metrics(all_counts, verified), labels=len(known), excluded=all_counts['EXCLUDED'],
                               unlabelled_findings=len(unlabelled), unique_findings=len(detections)),
                  per_detector=per_detector, labelled=labelled, unlabelled_findings=unlabelled,
                  confirmed_groups=groups, gaps=gaps,
                  limits=['Metryki dotyczą wyłącznie zrecenzowanych miejsc, nie wszystkich usterek repozytorium.',
                          'Dopasowanie to identyczny detektor, względny plik i linia; przesunięcie linii nie dowodzi naprawy.',
                          'needs_validation etykiet jest wyłączone; własny werdykt detektora nie zastępuje ground truth.',
                          'Nieoznaczone alarmy są osobne; ich poprawność pozostaje nieznana.',
                          'Dowód zgodności źródeł dostarcza caller; sam SHA lub dirty nie wystarcza.',
                          'Brak etykiet dla problemu nie jest dowodem, że benchmark go obejmuje.'])
    report['comparison'] = compare(report, previous)
    return report


def compare(current, previous):
    if previous is None:
        return dict(status='NOT_REQUESTED', reason_code='NO_PREVIOUS_REPORT', delta=None)
    reason = None
    if not isinstance(previous, dict) or previous.get('kind') != 'detector-benchmark' or type(previous.get('schema_version')) is not int or previous['schema_version'] != 1:
        reason = 'INVALID_PREVIOUS_REPORT'
    elif previous.get('scoring_version') != SCORING_VERSION:
        reason = 'SCORING_VERSION_MISMATCH'
    elif not isinstance(previous.get('labels'), dict) or previous['labels'].get('sha256') != current['labels']['sha256']:
        reason = 'LABEL_SET_MISMATCH'
    elif not isinstance(previous.get('target'), dict) or any(previous['target'].get(k) != current['target'][k] for k in ('path', 'commit')):
        reason = 'TARGET_IDENTITY_MISMATCH'
    if reason is None:
        try:
            rebuilt = evaluate(previous['labels'], previous['findings'], target=previous['target'],
                               source_revision=previous['source_revision']['status'], scan_status=previous['scan_status'])
            checked = ('summary', 'per_detector', 'status', 'source_revision')
            if rebuilt['labels']['sha256'] != previous['labels']['sha256'] or _digest({k:rebuilt[k] for k in checked}) != _digest({k:previous.get(k) for k in checked}):
                reason = 'INVALID_PREVIOUS_REPORT'
            elif rebuilt['status'] != 'COMPLETE' or current['status'] != 'COMPLETE':
                reason = 'SOURCE_OR_SCAN_NOT_COMPARABLE'
        except (BenchError, KeyError, TypeError, ValueError):
            reason = 'INVALID_PREVIOUS_REPORT'
    if reason:
        return dict(status='NOT_COMPARABLE', reason_code=reason, delta=None)
    metrics = ('tp', 'fp', 'fn', 'tn', 'precision', 'recall')
    def difference(left, right):
        return {key: left[key] - right[key] if left[key] is not None and right[key] is not None else None for key in metrics}
    old = {row['detector']: row['metrics'] for row in rebuilt['per_detector']}
    delta = dict(summary=difference(current['summary']['metrics'], rebuilt['summary']['metrics']), per_detector=[])
    for row in current['per_detector']:
        if row['detector'] in old:
            delta['per_detector'].append(dict(detector=row['detector'], **difference(row['metrics'], old[row['detector']])))
    return dict(status='COMPARABLE', reason_code=None, delta=delta)


def run_benchmark(labels, repo, *, scanner, target, source_revision='UNKNOWN', previous=None):
    """One injected static scan, no target writes, models or implicit verdicts."""
    normalized = normalize_labels(labels)  # reject conflicting ground truth before a scan
    identity = _identity(target)
    if str(repo) != identity['path']:
        raise BenchError('SCANNER_TARGET_MISMATCH')
    result = scanner(repo)
    if not isinstance(result, dict) or not isinstance(result.get('findings'), list):
        raise BenchError('INVALID_SCANNER_REPORT')
    coverage = result.get('source_coverage')
    needed = {}
    for row in normalized['labels']:
        needed[row['file']] = max(needed.get(row['file'], 0), row['line'])
    observed = {}
    valid = isinstance(coverage, dict) and isinstance(coverage.get('files'), list)
    for row in coverage.get('files', []) if valid else []:
        if not isinstance(row, dict):
            valid = False
            continue
        file = row.get('file')
        if not isinstance(file, str):
            valid = False
            continue
        if file not in needed:
            continue
        if file in observed:
            valid = False
        observed[file] = row
    for file, line in needed.items():
        row = observed.get(file, {})
        if row.get('status') != 'read' or type(row.get('lines_read')) is not int or row['lines_read'] < line or type(row.get('lines_total')) is not int or row['lines_total'] != row['lines_read']:
            valid = False
    scan_status = 'COMPLETE' if valid else 'INCOMPLETE'
    report = evaluate(labels, result['findings'], target=target, source_revision=source_revision,
                      scan_status=scan_status, previous=previous)
    report['execution'] = dict(static_scans=1, models=0, target_writes=0)
    report['read_coverage_scope'] = 'labelled_files_only'
    status = coverage.get('status') if isinstance(coverage, dict) else None
    report['scanner_source_coverage_status'] = status if isinstance(status, str) and status in {'COMPLETE', 'INCOMPLETE'} else 'UNKNOWN'
    return report


def select_scope(labels, scope='security'):
    """Never count detectors which this command did not run as true negatives."""
    normalized = normalize_labels(labels)
    if scope != 'security':
        raise BenchError('UNSUPPORTED_SCANNER_SCOPE')
    selected = [row for row in normalized['labels'] if row['detector'].startswith('SEC-')]
    omitted = Counter(row['detector'] for row in normalized['labels'] if not row['detector'].startswith('SEC-'))
    if not selected:
        raise BenchError('NO_LABELS_IN_SCANNER_SCOPE')
    subset = dict(normalized, labels=selected)
    return subset, dict(scope=scope, excluded_label_count=sum(omitted.values()),
                        excluded_detector_scope=[dict(detector=name, labels=count) for name, count in sorted(omitted.items())])


def static_scan(repo, *, engine='auto'):
    """A single analyzer call on exactly the captured source snapshot.

    The analyzer's snapshot API belongs to the static engine. No target import,
    model, application, third-party scanner or monkeypatch is used here.
    """
    import helix_static_security as security
    if engine not in {'auto', 'lexical'}:
        raise BenchError('UNSUPPORTED_ENGINE')
    sources = list(security.sources(repo))
    rows = []
    for file, content in sources:
        lines = content.count('\n') + int(bool(content) and not content.endswith('\n'))
        rows.append(dict(file=file, status='read', lines_total=lines, lines_read=lines,
                         sha256=hashlib.sha256(content.encode()).hexdigest()))
    result = security.analyze(repo, source_snapshot=sources, engine=engine)
    return dict(findings=result['findings'], source_coverage=dict(status='COMPLETE', files=rows),
                engine=result.get('static_engine', dict(requested=engine, status='UNKNOWN')))


def source_proof(labels, coverage, repo):
    """Compare only scanned labelled files with local raw Git blobs, in one batch.

    Git filters, external diff drivers, replacements and lazy object fetches are
    disabled by the shared helper. Missing scanner evidence never causes an
    extra read of an excluded file such as .env or a symlink.
    """
    import subprocess
    from helix_audit_context import safe_read
    from helix_git_readonly import git
    normalized = normalize_labels(labels)
    paths = sorted({row['file'] for row in normalized['labels']})
    observed, duplicates = {}, set()
    for row in coverage.get('files', []) if isinstance(coverage, dict) else []:
        if not isinstance(row, dict) or row.get('file') not in paths:
            continue
        file = row['file']
        if file in observed:
            duplicates.add(file)
        observed[file] = row
    eligible = [file for file in paths if file not in duplicates and observed.get(file, {}).get('status') == 'read'
                and isinstance(observed[file].get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', observed[file]['sha256'])]
    commit = normalized['repo']['commit']
    blobs = {}
    if eligible and commit:
        try:
            result = git(repo, 'cat-file', '--batch', text=False, timeout=120, local_objects_only=True,
                         input_data=''.join(commit + ':' + file + '\n' for file in eligible).encode())
            if result.returncode == 0:
                offset = 0
                for file in eligible:
                    end = result.stdout.find(b'\n', offset)
                    if end < 0:
                        break
                    header = result.stdout[offset:end].split()
                    offset = end + 1
                    if len(header) != 3 or not re.fullmatch(b'[0-9a-f]{40}(?:[0-9a-f]{24})?', header[0]) or header[1] != b'blob' or not header[2].isdigit():
                        # A missing object has one header line and no body.
                        continue
                    size = int(header[2])
                    body = result.stdout[offset:offset + size]
                    if len(body) != size or result.stdout[offset + size:offset + size + 1] != b'\n':
                        break
                    offset += size + 1
                    blobs[file] = hashlib.sha256(body).hexdigest()
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            pass
    proof = []
    for file in paths:
        current = observed.get(file, {}).get('sha256') if file in eligible else None
        stored = blobs.get(file)
        after = None
        if current is not None:
            try:
                after = hashlib.sha256(safe_read(Path(repo) / file, errors='strict').encode()).hexdigest()
            except (OSError, UnicodeError):
                pass
        status, reason = 'UNKNOWN', 'SCANNED_SOURCE_HASH_MISSING'
        if current is not None:
            if after is None:
                reason = 'SOURCE_UNREADABLE_AFTER_SCAN'
            elif after != current:
                status, reason = 'MISMATCH', 'SOURCE_CHANGED_DURING_SCAN'
            elif stored is None:
                reason = 'LOCAL_LABEL_BLOB_UNAVAILABLE'
            elif stored != current:
                status, reason = 'MISMATCH', 'LABEL_SOURCE_CONTENT_MISMATCH'
            else:
                status, reason = 'MATCHED', 'RAW_BLOB_AND_SCANNER_SHA256_MATCH'
        proof.append(dict(file=file, status=status, reason_code=reason, label_sha256=stored,
                          scanned_sha256=current, after_scan_sha256=after))
    status = 'MATCHED' if proof and all(row['status'] == 'MATCHED' for row in proof) else 'MISMATCH' if any(row['status'] == 'MISMATCH' for row in proof) else 'UNKNOWN'
    return dict(status=status, basis='local_raw_git_blob_and_scanned_labelled_file_sha256',
                label_commit=commit, files=proof, network=False)


def benchmark_repository(labels, repo, *, engine='auto', scope='security', previous=None, scanner=None):
    """Trusted static runner with local source evidence and no target writes."""
    from helix_git_readonly import read_ref
    from helix_contracts import VERSION
    from datetime import datetime, timezone
    import platform
    import time
    repo = Path(repo).expanduser().resolve(strict=True)
    selected, scope_report = select_scope(labels, scope)
    if selected['repo']['path'] != str(repo):
        raise BenchError('TARGET_PATH_MISMATCH')
    before = read_ref(repo, require_root=True)
    started = time.monotonic()
    data = (scanner or static_scan)(repo, engine=engine)
    if not isinstance(data, dict) or not isinstance(data.get('findings'), list):
        raise BenchError('INVALID_SCANNER_REPORT')
    proof = source_proof(selected, data.get('source_coverage'), repo)
    after = read_ref(repo, require_root=True)
    if before['head'] != after['head']:
        proof.update(status='MISMATCH', reason_code='TARGET_HEAD_CHANGED')
    identity = dict(path=str(repo), commit=before['head'], dirty=before['dirty'])
    # run_benchmark consumes the captured result; it does not scan a second time.
    report = run_benchmark(selected, str(repo), scanner=lambda _: data, target=identity,
                           source_revision=proof['status'], previous=previous)
    report.update(scope=scope_report, source_proof=proof, target_before=before, target_after=after,
                  elapsed_seconds=round(time.monotonic() - started, 6),
                  producer=dict(helix_version=VERSION, python=platform.python_version(),
                                source_ref=read_ref(Path(__file__).resolve().parents[1]),
                                generated_at=datetime.now(timezone.utc).isoformat()),
                  engine=data.get('engine', dict(requested=engine, status='UNKNOWN')))
    report['execution']['network'] = False
    return report


def _read_json(path):
    from helix_audit_context import safe_read
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError('non-finite value')
    try:
        raw = safe_read(Path(path).expanduser(), errors='strict')
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant), hashlib.sha256(raw.encode()).hexdigest()
    except (OSError, UnicodeError, ValueError, TypeError):
        raise BenchError('INPUT_JSON_UNREADABLE') from None


def _output(value, repo):
    import stat
    from helix_audit_context import system_path
    if value is None:
        return None
    out = system_path(Path(value).expanduser().absolute())
    target = Path(repo).expanduser().resolve(strict=True)
    if '..' in out.parts or out == target or target in out.parents or out in target.parents:
        raise BenchError('OUTPUT_OVERLAPS_TARGET_OR_UNSAFE')
    for part in [*reversed(out.parents), out]:
        try:
            metadata = part.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise BenchError('UNSAFE_OUTPUT_PATH')
    for name in ('benchmark.json', 'BENCHMARK.md'):
        try:
            (out / name).lstat()
        except FileNotFoundError:
            continue
        raise BenchError('OUTPUT_ALREADY_EXISTS')
    return out


def _publish(out, report):
    import os
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise BenchError('SAFE_OUTPUT_UNAVAILABLE')
    descriptor = os.open(out.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in out.parts[1:]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        contents = [('benchmark.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n'),
                    ('BENCHMARK.md', markdown(report))]
        for name, content in contents:
            leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            with os.fdopen(leaf, 'w', encoding='utf-8') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def markdown(report):
    if report['status'] == 'ERROR':
        return 'Benchmark: ERROR; ' + report['reason_code'] + '\n'
    def metric(value):
        return 'nieustalone' if value is None else f'{value:.4f}' if isinstance(value, float) else str(value)
    counts = report['summary']['metrics']
    lines = ['# Benchmark detektorów', '', 'Status: ' + report['status'] + '. Dopasowanie: detektor, plik i dokładna linia.',
             'Wynik dotyczy zrecenzowanych miejsc; COMPLETE nie oznacza braku usterek.', '',
             '| Detektor | TP | FP | FN | TN | Precision | Recall |', '|---|---:|---:|---:|---:|---:|---:|']
    for row in [dict(detector='Razem', metrics=counts), *report['per_detector']]:
        lines.append('| ' + row['detector'] + ' | ' + ' | '.join(metric(row['metrics'][key]) for key in ('tp', 'fp', 'fn', 'tn', 'precision', 'recall')) + ' |')
    lines += ['', f"Nieocenione alarmy: {report['summary']['unlabelled_findings']}; etykiety needs_validation poza oceną: {report['summary']['excluded']}."]
    scope = report.get('scope', {})
    lines.append(f"Etykiety poza zakresem uruchomionych detektorów: {scope.get('excluded_label_count', 0)}; nie są TN.")
    for row in report['confirmed_groups']:
        lines.append(f"- {row['issue_group']}: {row['observed_hits']}/{row['labelled_locations']}, {row['status']}.")
    if report['gaps']:
        lines += ['', 'Luki: ' + ', '.join(report['gaps']) + '.']
    comparison = report['comparison']
    lines += ['', 'Porównanie: ' + comparison['status'] + (('; ' + comparison['reason_code']) if comparison.get('reason_code') else '') + '.',
              'Brak modeli, sieci i uruchomienia aplikacji. Pełne miejsca oraz dowody hash są w benchmark.json.']
    return '\n'.join(lines) + '\n'


def parsers(subparsers):
    import argparse
    parser = subparsers.add_parser('bench', help='lokalny benchmark na zrecenzowanych etykietach')
    parser.add_argument('--labels', required=True)
    parser.add_argument('--previous')
    parser.add_argument('--repo', default=argparse.SUPPRESS)
    parser.add_argument('--out', help='zewnętrzny katalog nowych wyników')
    parser.add_argument('--scope', choices=['security'], default='security')
    parser.add_argument('--engine', choices=['lexical', 'auto'], default='auto')
    parser.add_argument('--json', action='store_true')
    return parser


def dispatch(args):
    import sys
    try:
        out = _output(getattr(args, 'out', None), args.repo)
        labels, raw_hash = _read_json(args.labels)
        previous, previous_hash = _read_json(args.previous) if getattr(args, 'previous', None) else (None, None)
        report = benchmark_repository(labels, args.repo, engine=args.engine, scope=args.scope, previous=previous)
        report.update(labels_artifact_sha256=raw_hash, previous_artifact_sha256=previous_hash)
        if out:
            _publish(out, report)
        print(json.dumps(report, ensure_ascii=False, indent=2) if getattr(args, 'json', False) else markdown(report))
        return 0 if report['status'] == 'COMPLETE' else 3
    except BenchError as error:
        code = error.code
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        code = 'BENCHMARK_IO_OR_SCANNER_ERROR'
    report = dict(schema_version=1, kind='detector-benchmark', status='ERROR', reason_code=code)
    print(json.dumps(report, ensure_ascii=False) if getattr(args, 'json', False) else markdown(report), file=sys.stderr)
    return 3
