#!/usr/bin/env python3
"""Run the unittest suite sharded into small batches of test ids across processes (stdlib only).

Usage: python3 scripts/run_tests_parallel.py [-j N]
Exit code 0 only if every module passes. The serial full suite
(python3 -m unittest discover -s tests) remains the authoritative final gate.
"""
import argparse, json, os, re, subprocess, sys, tempfile, time, unittest
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# macOS hands out /var/... temp dirs whose canonical path is /private/var/...;
# tests compare paths, so give every worker the canonical temp root.
ENV = dict(os.environ, TMPDIR=os.path.realpath(__import__("tempfile").gettempdir()), PYTHONPATH=os.pathsep.join([os.path.join(ROOT, "tests"), ROOT, os.environ.get("PYTHONPATH", "")]))

def ids(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from ids(t)
        else:
            yield t.id()

def failing_tests(stderr):
    """Test ids from unittest FAIL/ERROR headers, including subtest and import failures."""
    return sorted(set(re.findall(r'(?m)^(?:FAIL|ERROR): \S+ \(([^()\s]+)\)', stderr)))


def run(batch):
    t = time.time()
    p = subprocess.run([sys.executable, "-m", "unittest", *batch], cwd=ROOT, env=ENV,
                       capture_output=True, text=True)
    mod = batch[0] + (f" (+{len(batch)-1})" if len(batch) > 1 else "")
    summaries = list(re.finditer(r"(?m)^Ran (\d+) tests? in [\d.]+s$", p.stderr))
    m = summaries[-1] if summaries else None
    completed = int(m.group(1)) if m else 0
    rc, error = p.returncode, p.stderr
    if not rc and (m is None or completed != len(batch) or not re.search(r'(?m)^OK(?: \([^\n]+\))?$', p.stderr[m.end():])):
        rc = 1
        error += f'\nHelix ERROR: worker did not confirm the requested test batch ({completed}/{len(batch)}); exit 0 alone is insufficient.\n'
    return mod, rc, completed, time.time() - t, error


def execute_batches(batches, jobs, governor, run_batch=run):
    """Keep only admitted batches in the pool; active tests are never killed."""
    from helix_resources import ResourcePaused
    results, active, decisions = {}, {}, []
    cursor, paused = 0, None
    last_sample = None
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        while active or cursor < len(batches):
            decision = governor.decision()
            sample_key = (decision['state'], decision['effective_jobs'], decision.get('sample', {}).get('observed_at'))
            if sample_key != last_sample:
                decisions.append(decision)
                last_sample = sample_key
            limit = min(jobs, decision['effective_jobs'])
            if limit == 0 and not active:
                try:
                    decision = governor.wait()
                    decisions.append(decision)
                    limit = min(jobs, decision['effective_jobs'])
                except ResourcePaused as exc:
                    paused = exc.decision
                    break
            while cursor < len(batches) and len(active) < limit:
                # submit in stable discovery order; do not enqueue the whole suite.
                active[pool.submit(run_batch, batches[cursor])] = cursor
                cursor += 1
            if active:
                finished, _ = wait(active, timeout=.1, return_when=FIRST_COMPLETED)
                for future in finished:
                    results[active.pop(future)] = future.result()
    return dict(results=[results[i] for i in sorted(results)],
                not_run=batches[cursor:], paused=paused, resource_decisions=decisions)

def main():
    release = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts/check_release_version.py')], cwd=ROOT)
    if release.returncode: return release.returncode
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=os.cpu_count() or 4)
    ap.add_argument('--resource-config', help='JSON with resource thresholds, no project execution')
    ap.add_argument('--resource-report', help='External directory for resource decisions and test summary')
    a = ap.parse_args()
    if a.j < 1: ap.error('-j must be positive')
    sys.path.insert(0, os.path.join(ROOT, 'bin'))
    from helix_resources import Governor
    from helix_audit_context import system_path
    try:
        policy = json.loads(Path(a.resource_config).read_text()) if a.resource_config else {}
        if not isinstance(policy, dict): raise ValueError('resource policy must be a JSON object')
        report_dir = system_path(Path(a.resource_report or os.environ.get('HELIX_TEST_RESOURCE_REPORT_DIR') or tempfile.mkdtemp(prefix='helix-test-resources-')))
        if any(p.is_symlink() for p in (report_dir, *report_dir.parents)):
            raise ValueError('resource report must not use symlinks')
        report_dir = report_dir.resolve()
        if report_dir.is_relative_to(Path(ROOT).resolve()):
            raise ValueError('resource report must be outside the Helix repository')
        report_dir.mkdir(parents=True, exist_ok=True)
        if (report_dir / 'test-summary.json').exists(): raise ValueError('resource report already exists')
        governor = Governor(policy=policy, requested_jobs=a.j, out=report_dir)
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    ap_b = int(os.environ.get("HELIX_TEST_BATCH", "4"))
    sys.path[:0] = [os.path.join(ROOT, "tests"), ROOT]
    suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"), top_level_dir=os.path.join(ROOT, "tests"))
    all_ids = list(ids(suite))
    bad = [i for i in all_ids if i.startswith("unittest.loader")]
    if bad:
        print("import errors in discovery: " + ", ".join(bad)); return 1
    if ap_b < 1:
        ap.error("HELIX_TEST_BATCH must be positive")
    # Keep class fixtures in one process: splitting them repeats expensive browser
    # scans and defeats unittest's setUpClass/tearDownClass lifecycle.
    classes = OrderedDict()
    for test_id in all_ids:
        classes.setdefault(test_id.rsplit(".", 1)[0], []).append(test_id)
    mods = []
    pending = []
    for class_ids in classes.values():
        case = type(next(iter(unittest.defaultTestLoader.loadTestsFromName(class_ids[0]))))
        shared_fixture = (case.setUpClass.__func__ is not unittest.TestCase.setUpClass.__func__
                          or case.tearDownClass.__func__ is not unittest.TestCase.tearDownClass.__func__)
        if shared_fixture:
            if pending:
                mods.extend(pending[i:i + ap_b] for i in range(0, len(pending), ap_b))
                pending = []
            mods.append(class_ids)
        else:
            pending.extend(class_ids)
    mods.extend(pending[i:i + ap_b] for i in range(0, len(pending), ap_b))
    t0 = time.time(); total = 0; skipped = 0; failed = []; failed_tests = []; unexplained = []
    execution = execute_batches(mods, a.j, governor)
    for mod, rc, n, dt, err in sorted(execution['results'], key=lambda r: -r[3]):
        total += n
        final_summary = re.split(r'(?m)^Ran \d+ tests? in [\d.]+s$', err)[-1]
        skip_match = re.search(r'(?m)^OK \([^\n]*skipped=(\d+)', final_summary)
        if skip_match: skipped += int(skip_match.group(1))
        if os.environ.get("HELIX_TEST_TIMES"): print(f"{dt:6.1f}s {n:4d} {mod}")
        if rc:
            # Name the failing tests, not the batch: its label is only the first test id, and the
            # tail below can cut the unittest headers off.
            # A worker that died without headers stays a batch: its label names no failing test.
            names = failing_tests(err)
            failed.append(mod); failed_tests.extend(names)
            if not names: unexplained.append(f'batch {mod} without a unittest failure header')
            sys.stderr.write(f"--- FAIL {', '.join(names) or unexplained[-1]} [batch {mod}]\n{err[-4000:]}\n")
    status = 'INCOMPLETE' if execution['not_run'] or not all_ids or total and skipped == total else 'FAIL' if failed else 'PASS'
    summary = dict(status=status, tests=total, skipped=skipped, batches_completed=len(execution['results']),
                   batches_total=len(mods), requested_jobs=a.j, seconds=round(time.time()-t0, 3),
                   failed=failed, failed_tests=failed_tests, not_run=execution['not_run'], discovery_empty=not all_ids, resource_paused=execution['paused'],
                   resource_decisions=execution['resource_decisions'])
    if not all_ids: summary['reason'] = 'No test IDs discovered; an empty suite does not prove a passing gate'
    elif total and skipped == total: summary['reason'] = 'All selected tests were skipped; no execution evidence'
    with (report_dir / 'test-summary.json').open('x') as stream:
        json.dump(summary, stream, indent=2); stream.write('\n')
    print(f"Ran {total} tests in {len(execution['results'])}/{len(mods)} batches, {time.time()-t0:.1f}s, -j {a.j}: " + ('OK' if status == 'PASS' else status + ' ' + ', '.join(failed_tests + unexplained)))
    if skipped: print(f'Skipped tests: {skipped}; these do not provide execution evidence')
    print('Resource report: ' + str(report_dir / 'test-summary.json'))
    return 2 if status == 'INCOMPLETE' else 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
