"""Read-only registry planning and explicitly requested, isolated tool installs."""
import copy
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import sys

from helix_audit_context import system_path
from helix_contracts import VERSION
import helix_tool_adapters as adapters
import helix_tools_manager as manager


class ToolsError(ValueError):
    """Fixed public codes never contain process output or target configuration."""


def _producer():
    return dict(helix_version=VERSION, python=platform.python_version())


def _selected(names, available):
    if names is None:
        return list(available)
    if not isinstance(names, list) or not names or any(name not in available for name in names):
        raise ToolsError('UNKNOWN_OR_UNSUPPORTED_TOOL')
    return list(dict.fromkeys(names))


def plan(names=None):
    """Inventory declarations and local evidence without running a tool or repo."""
    names = _selected(names, adapters.REGISTRY)
    managed_names = [name for name in names if name in manager.CATALOG]
    managed_plan = manager.plan(managed_names) if managed_names else None
    managed = {row['name']: row for row in (managed_plan or {}).get('tools', [])}
    rows = []
    for name in names:
        spec = copy.deepcopy(adapters.REGISTRY[name])
        executable = shutil.which(spec['command'])
        runner = spec.get('runner')
        runner_implemented = spec.get('runner_implemented', False) is True
        managed_available = managed.get(name, {}).get('managed_install_status') == 'VERIFIED'
        gaps = []
        if not executable and not managed_available:
            gaps.append('LOCAL_EXECUTABLE_NOT_FOUND')
        if not runner_implemented:
            gaps.append('RUNNER_NOT_IMPLEMENTED')
        if name in managed:
            gaps.append('MANAGED_ADAPTER_UNVERIFIED')
        managed_row = copy.deepcopy(managed.get(name)) or dict(install_supported=False, managed_install_status='UNSUPPORTED')
        managed_row.update(status=managed_row['managed_install_status'], pin=managed_row.get('version'))
        rows.append(dict(name=name, area=spec['area'], declaration=spec,
                         runner=runner, runner_implemented=runner_implemented,
                         parser=dict(name=spec.get('parser'), declared=spec.get('parser') is not None),
                         local_executable_present=bool(executable),
                         local=dict(status='PRESENT' if executable else 'MISSING', executable=executable,
                                    version=None, execution_status='NOT_RUN'),
                         managed=managed_row,
                         execution_status='NOT_RUN', coverage_status='INCOMPLETE' if gaps else 'NOT_RUN',
                         coverage_gaps=gaps))
    reasons = {'LOCAL_EXECUTABLE_NOT_FOUND': 'Brak narzędzia w sprawdzonych lokalizacjach; node_modules celu nie jest odczytywane.',
               'RUNNER_NOT_IMPLEMENTED': 'Brak runnera w rejestrze Helixa.',
               'MANAGED_ADAPTER_UNVERIFIED': 'Zgodność istniejącego adaptera z zarządzanym pinem nie została potwierdzona.'}
    coverage_gaps = [dict(tool=row['name'], reason_code=code, reason=reasons[code])
                     for row in rows for code in row['coverage_gaps']]
    return dict(schema_version=1, kind='tools-plan', status='PLANNED', producer=_producer(),
                groups={area: [name for name in declared.split() if name in names]
                        for area, declared in adapters.GROUPS.items()},
                tools=rows, managed_plan=managed_plan,
                execution=dict(commands=0, network=False, target_reads=0, target_writes=0),
                scope='tool_inventory_only', coverage_status='INCOMPLETE' if coverage_gaps else 'NOT_RUN',
                coverage=dict(status='INCOMPLETE' if coverage_gaps else 'NOT_RUN', gaps=coverage_gaps))


def _path(value):
    path = Path(value).expanduser().absolute()
    if '..' in path.parts:
        raise ToolsError('UNSAFE_OUTPUT_PATH')
    return system_path(path)


def _overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def _output(value, repo, action):
    """Preflight only, before an install can download or activate anything."""
    if value is None:
        return None
    out = _path(value)
    target = Path(repo).expanduser().resolve()
    if _overlap(out, target):
        raise ToolsError('OUTPUT_OVERLAPS_TARGET')
    for part in [*reversed(out.parents), out]:
        try:
            metadata = part.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise ToolsError('UNSAFE_OUTPUT_PATH')
    destination = out / ('tools-' + action + '.json')
    try:
        destination.lstat()
    except FileNotFoundError:
        return destination
    raise ToolsError('OUTPUT_ALREADY_EXISTS')


def _publish(destination, report):
    """Exclusive descriptor-relative write, including every parent directory."""
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise ToolsError('SAFE_OUTPUT_UNAVAILABLE')
    descriptor = os.open(destination.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in destination.parent.parts[1:]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=descriptor)
        with os.fdopen(leaf, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _diagnostic_lines(diagnostic):
    """Render only the bounded diagnostic built by the trusted manager helper.

    Do not read raw stdout/stderr or apply a second, lossy redactor here.
    """
    if not isinstance(diagnostic, dict) or diagnostic.get('schema_version') != 1:
        return []
    returncode = diagnostic.get('returncode')
    lines = [f"  Etap: {diagnostic['phase']}; przyczyna: {diagnostic['code']}; kod wyjścia: {returncode if returncode is not None else 'nieznany'}."]
    if diagnostic.get('command'):
        lines.append('  Polecenie: ' + shlex.join(diagnostic['command']))
    if diagnostic.get('reason_codes'):
        lines.append('  Rozpoznane przyczyny: ' + ', '.join(diagnostic['reason_codes']))
    for item in diagnostic.get('tail', []):
        lines.append(f"  {item['stream']}: {item['line']}")
    for hint in diagnostic.get('hints', []):
        lines.append('  Wskazówka: ' + hint)
    if diagnostic.get('truncated') or diagnostic.get('omitted_lines'):
        lines.append(f"  Diagnostyka ograniczona: pominięte linie {diagnostic.get('omitted_lines', 0)}; skrócono {'tak' if diagnostic.get('truncated') else 'nie'}.")
    return lines


def _public_install(result):
    """Keep the manager contract; raw process fields have no public channel."""
    if not isinstance(result, dict) or not isinstance(result.get('tools'), list):
        raise ToolsError('INVALID_MANAGER_REPORT')
    output = {key: copy.deepcopy(result[key]) for key in
              ('status', 'reason_code', 'proof_kind', 'target_writes', 'diagnostic') if key in result}
    output['tools'] = []
    for row in result['tools']:
        if not isinstance(row, dict):
            raise ToolsError('INVALID_MANAGER_REPORT')
        output['tools'].append({key: copy.deepcopy(row[key]) for key in
            ('tool', 'status', 'reason_code', 'version', 'receipt', 'proof_kind', 'usable',
             'smoke_status', 'adapter_status', 'argv_prefix', 'environment', 'runtime_selection', 'diagnostic') if key in row})
    return output


def text_report(report):
    if report['kind'] == 'tools-plan' and report['status'] == 'PLANNED':
        lines = ['Plan narzędzi: zadeklarowane możliwości, bez uruchamiania narzędzi ani projektu.']
        for area, names in report['groups'].items():
            if not names:
                continue
            lines.append('\n' + area + ':')
            for row in report['tools']:
                if row['name'] not in names:
                    continue
                if row['local']['status'] == 'PRESENT':
                    local = 'lokalny program znaleziony; wersja i działanie niesprawdzone'
                elif row['managed']['status'] == 'VERIFIED':
                    local = 'dostępna zweryfikowana instalacja zarządzana, poza PATH; skan projektu nieuruchomiony'
                else:
                    local = 'zadeklarowane, nieuruchomione: brak narzędzia w sprawdzonych lokalizacjach'
                runner = row['runner'] or 'brak runnera, luka pokrycia'
                parser = row['parser']['name'] or 'brak deklaracji parsera w rejestrze'
                managed = row['managed']
                installation = (managed['managed_install_status'] + '; pin ' + managed['version'] +
                                '; smoke ' + managed['smoke_status'] + '; adapter UNVERIFIED'
                                if managed['install_supported'] else 'instalacja zarządzana nieobsługiwana')
                lines.append(f"- {row['name']}: {local}; runner: {runner}; parser: {parser}; {installation}.")
        lines.append('\nObecność programu i smoke instalacji nie potwierdzają zgodności adaptera ani pokrycia projektu. Skan projektu: NOT_RUN.')
        return '\n'.join(lines)
    lines = ['Instalacja narzędzi: ' + report['status'] + (': ' + report['reason_code'] if report.get('reason_code') else '')]
    lines += _diagnostic_lines(report.get('diagnostic'))
    for row in report.get('tools', []):
        if row:
            lines.append(f"- {row['tool']}: {row.get('status', 'UNKNOWN')}; pin {row.get('version', 'unknown')}; smoke {row.get('smoke_status', 'NOT_RUN')}; adapter {row.get('adapter_status', 'UNVERIFIED')}" +
                         ('; ' + row['reason_code'] if row.get('reason_code') else ''))
            lines += _diagnostic_lines(row.get('diagnostic'))
    lines.append('Instalacja i własny smoke nie oznaczają uruchomienia projektu ani zgodności adaptera. Pokrycie projektu: NOT_RUN.')
    return '\n'.join(lines)


def dispatch(args):
    action = args.action
    try:
        if getattr(args, 'name', None):
            raise ToolsError('USE_REPEATABLE_TOOL_OPTION')
        names = _selected(getattr(args, 'tool', None), adapters.REGISTRY if action == 'plan' else manager.CATALOG)
        if action == 'install' and not getattr(args, 'yes', False):
            report = dict(schema_version=1, kind='tools-install', status='BLOCKED', reason_code='EXPLICIT_YES_REQUIRED', tools=[], project_execution='NOT_RUN', coverage_status='NOT_RUN')
        elif action == 'install' and getattr(args, 'offline', False):
            report = dict(schema_version=1, kind='tools-install', status='BLOCKED', reason_code='OFFLINE_INSTALL_NOT_ALLOWED', tools=[], project_execution='NOT_RUN', coverage_status='NOT_RUN')
        else:
            destination = _output(getattr(args, 'out', None), args.repo, action)
            if action == 'plan':
                report = plan(names)
            else:
                managed_root = (Path.home() / '.local/share/helix/tools').resolve()
                if _overlap(managed_root, Path(args.repo).expanduser().resolve()):
                    raise ToolsError('INSTALL_ROOT_OVERLAPS_TARGET')
                report = dict(_public_install(manager.install(names, yes=True, offline=False)), schema_version=1, kind='tools-install',
                              project_execution='NOT_RUN', coverage_status='NOT_RUN')
            report['producer'] = _producer()
            if destination:
                _publish(destination, report)
        report['producer'] = _producer()
        print(json.dumps(report, ensure_ascii=False, indent=2) if getattr(args, 'json', False) else text_report(report))
        return 0 if report['status'] in ('PLANNED', 'COMPLETE', 'REUSED') else 3
    except ToolsError as error:
        report = dict(schema_version=1, kind='tools-' + action, status='ERROR', reason_code=str(error), tools=[])
    except (OSError, ValueError, TypeError, KeyError):
        report = dict(schema_version=1, kind='tools-' + action, status='ERROR', reason_code='TOOLS_IO_OR_RECEIPT_ERROR', tools=[])
    report['producer'] = _producer()
    print(json.dumps(report, ensure_ascii=False, indent=2) if getattr(args, 'json', False) else text_report(report), file=sys.stderr)
    return 3
