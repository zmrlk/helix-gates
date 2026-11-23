"""Repo-local continuity. No network, credentials, or implicit git commits."""
import datetime as dt
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from helix_contracts import VERSION

HOME = Path(__file__).resolve().parent.parent
ADAPTERS = ('AGENTS.md', 'CLAUDE.md', 'GEMINI.md')


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def secret_check(value):
    text = json.dumps(value, ensure_ascii=False)
    patterns = (r'-----BEGIN [A-Z ]*PRIVATE KEY-----', r'\b(?:sk|ghp|gho|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{16,}',
                r'\bAKIA[A-Z0-9]{16}\b', r'(?i)(?:password|passwd|secret(?:[_-]access[_-]key)?|token|api[_-]?key|access[_-]?key)\s*["\s]*[:=]\s*["\s]*[^\s",;}{]{4,}',
                r'(?i)\bBearer\s+[A-Za-z0-9_.-]{16,}', r'://[^\s/:]+:[^\s/@]+@', r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    if any(re.search(p, text) for p in patterns):
        raise ValueError('wartość wygląda na sekret; zapis odrzucony')


def bounded(root, name):
    path = root / name
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root.parent):
        raise ValueError('symlink niedozwolony')
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('ścieżka poza repo')
    return path


def load(path):
    if path.is_symlink():
        raise ValueError('symlink niedozwolony')
    text = path.read_text(encoding='utf-8')
    if path.suffix == '.yaml':
        try:
            import yaml
        except ImportError:
            data = json.loads(text)  # JSON is a YAML subset.
        else:
            data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    secret_check(data)
    return data


def validate(kind, data):
    schema = json.loads((HOME / 'schemas' / (kind + '.schema.json')).read_text())

    def check(value, spec):
        types = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool}
        if 'type' in spec and (not isinstance(value, types[spec['type']]) or
                               (spec['type'] == 'integer' and isinstance(value, bool))):
            raise ValueError('niepoprawny typ pola')
        if 'enum' in spec and value not in spec['enum']:
            raise ValueError('niepoprawna wartość pola')
        if isinstance(value, dict):
            if any(k not in value for k in spec.get('required', [])):
                raise ValueError('brak wymaganych pól')
            for key, item in value.items():
                if key not in spec.get('properties', {}) and spec.get('additionalProperties') is False:
                    raise ValueError('nieznane pole: ' + key)
                check(item, spec.get('properties', {}).get(key, {}))
        if isinstance(value, list):
            for item in value:
                check(item, spec.get('items', {}))
        if isinstance(value, str):
            if len(value.strip()) < spec.get('minLength', 0):
                raise ValueError('puste pole')
            if 'pattern' in spec and not re.fullmatch(spec['pattern'], value):
                raise ValueError('niepoprawny format pola')
        if isinstance(value, int) and value < spec.get('minimum', value):
            raise ValueError('wartość poniżej minimum')
    check(data, schema)
    if kind in ('handoff', 'claim', 'decision'):
        for field in ('created_at', 'expires_at'):
            if field in data:
                parsed = dt.datetime.fromisoformat(data[field])
                if parsed.tzinfo is None:
                    raise ValueError('data wymaga strefy czasowej')
    if kind == 'agent-policy':
        for rule in data.get('rules', []):
            if rule['kind'] != 'forbidden_file':
                re.compile(rule['pattern'])
    secret_check(data)
    return data


def write(path, data, exclusive=False):
    secret_check(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    if exclusive:
        with path.open('x', encoding='utf-8') as f:
            f.write(payload)
    else:
        fd, name = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(payload)
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)


class Continuity:
    def __init__(self, repo):
        self.repo = Path(repo).resolve()
        config = bounded(self.repo, 'helix.json')
        cfg = json.loads(config.read_text()) if config.exists() else {}
        directory = cfg.get('continuity', {}).get('directory', '.helix')
        if not isinstance(directory, str) or Path(directory).is_absolute() or directory in ('', '.'):
            raise ValueError('katalog ciągłości musi być pod repo')
        self.state = bounded(self.repo, directory)
        self.prefix = self.state.relative_to(self.repo).as_posix()

    def path(self, name):
        return bounded(self.repo, self.prefix + '/' + name)

    def git(self, *args):
        result = subprocess.run(['git', '-C', str(self.repo), *args], capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=30)
        if result.returncode:
            raise ValueError('git: operacja nie powiodła się (' + args[0] + ')')
        return result.stdout.strip()

    def policy(self):
        paths = [self.path('agent-policy.' + ext) for ext in ('yaml', 'json')]
        present = [p for p in paths if p.exists()]
        if len(present) != 1:
            raise ValueError('wymagane dokładnie jedno agent-policy.yaml|json')
        return validate('agent-policy', load(present[0]))

    def adapter(self):
        policy = self.policy()
        source = next(self.path('agent-policy.' + ext) for ext in ('yaml', 'json')
                      if self.path('agent-policy.' + ext).exists())
        source_hash = digest(source.read_bytes())
        return ('<!-- wygenerowane, nie edytuj; source-sha256: ' + source_hash + ' -->\n'
                '# Instrukcje agentów\n\n' + json.dumps(policy, indent=2, ensure_ascii=False) + '\n')

    def agents_check(self):
        expected = self.adapter()
        errors = ['wersja Helixa różni się od pina polityki'] if self.policy()['helix_version'] != VERSION else []
        for name in ADAPTERS:
            path = bounded(self.repo, name)
            if not path.exists() or path.read_text(encoding='utf-8') != expected:
                errors.append('dryf instrukcji: ' + name)
        return errors

    def generate(self):
        text = self.adapter()
        if self.policy()['helix_version'] != VERSION:
            raise ValueError('wersja Helixa różni się od pina polityki')
        paths = [bounded(self.repo, name) for name in ADAPTERS]
        for path in paths:
            path.write_text(text, encoding='utf-8')
        return list(ADAPTERS)

    def records(self, kind):
        directory = self.path(kind)
        if not directory.exists():
            return []
        return [(p, validate({'claims': 'claim', 'decisions': 'decision', 'handoffs': 'handoff'}[kind], load(p)))
                for p in sorted(directory.glob('*.json')) if p.name != 'LATEST']

    def latest(self):
        pointer = self.path('handoffs/LATEST')
        if not pointer.exists():
            raise ValueError('brak handoffu sesji')
        name = pointer.read_text().strip()
        if Path(name).name != name or not name.endswith('.json'):
            raise ValueError('błędny LATEST')
        path = self.path('handoffs/' + name)
        return path, validate('handoff', load(path))

    def handoff_write(self, data):
        data = dict(data, created_at=stamp(), head=self.git('rev-parse', 'HEAD'))
        validate('handoff', data)
        name = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-' + data['agent'] + '.json'
        path = self.path('handoffs/' + name)
        write(path, data, exclusive=True)
        pointer = self.path('handoffs/LATEST')
        pointer.write_text(name + '\n')
        return data

    def handoff_read(self, agent, env):
        path, data = self.latest()
        result = dict(handoff=data, claims=[v for _, v in self.records('claims') if self.active(v)],
                      decisions=[v for _, v in self.records('decisions')][-10:], drift=self.report())
        ack = dict(agent=identifier(agent), env=identifier(env), handoff=path.name,
                   sha256=digest(path.read_bytes()), head=self.git('rev-parse', 'HEAD'), read_at=stamp())
        write(self.path('acks/' + agent + '-' + env + '.json'), ack)
        result['drift'] = self.report()
        return result

    def handoff_check(self):
        path, data = self.latest()
        errors = []
        acks = self.path('acks')
        found = False
        if acks.exists():
            for p in acks.glob('*.json'):
                ack = load(p)
                if ack.get('handoff') == path.name and ack.get('sha256') == digest(path.read_bytes()):
                    found = True
        if not found:
            errors.append('brak ack ostatniego handoffu')
        self.git('merge-base', '--is-ancestor', data['head'], 'HEAD')
        for commit in self.git('rev-list', data['head'] + '..HEAD').splitlines():
            changed = self.git('diff-tree', '--no-commit-id', '--name-only', '-r', '-m', commit).splitlines()
            allowed = (self.prefix + '/handoffs/', self.prefix + '/acks/')
            if any(not name.startswith(allowed) for name in changed):
                errors.append('commit bez nowego handoffu: ' + commit)
        return errors

    @staticmethod
    def active(claim):
        expiry = dt.datetime.fromisoformat(claim['expires_at'])
        if expiry.tzinfo is None:
            raise ValueError('TTL wymaga strefy czasowej')
        return claim['status'] == 'active' and expiry > dt.datetime.now(dt.timezone.utc)

    def claim_take(self, task, agent, ttl=3600, commit=False):
        identifier(task); identifier(agent)
        if ttl <= 0:
            raise ValueError('TTL musi być dodatni')
        if self.path('handoffs/LATEST').exists():
            latest, _ = self.latest()
            acknowledged = any(load(p).get('agent') == agent and
                               load(p).get('sha256') == digest(latest.read_bytes())
                               for p in self.path('acks').glob('*.json'))
            if not acknowledged:
                raise ValueError('najpierw handoff read dla tego agenta')
        # Exclusive local lock serializes contenders; git push arbitrates separate clones.
        lock = self.path('claims/.lock')
        lock.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ValueError('claims zajęte; ponów po zakończeniu operacji') from None
        os.close(fd)
        try:
            for _, old in self.records('claims'):
                if old['task_id'] == task and self.active(old):
                    raise ValueError('aktywny claim: ' + old['agent'])
            data = dict(task_id=task, agent=agent, created_at=stamp(),
                        expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl)).isoformat(),
                        status='active', lease_id=uuid.uuid4().hex)
            validate('claim', data)
            path = self.path('claims/' + task + '.json')
            relative = path.relative_to(self.repo).as_posix()
            if commit:
                ignored = subprocess.run(['git', '-C', str(self.repo), 'check-ignore', '--', relative],
                                         capture_output=True, timeout=30)
                if ignored.returncode == 0:
                    raise ValueError('plik claimu ignorowany przez git; usuń regułę .gitignore dla ' +
                                     relative + ' albo użyj claim take bez --commit')
                if ignored.returncode != 1:
                    raise ValueError('git: nie udało się sprawdzić .gitignore')
            write(path, data)
            if commit:
                self.git('add', '--', relative)
                self.git('commit', '--only', '-m', 'claim: ' + task, '--', path.relative_to(self.repo).as_posix())
            return data
        finally:
            lock.unlink()

    def claim_release(self, task, agent, lease):
        path = self.path('claims/' + identifier(task) + '.json')
        data = validate('claim', load(path))
        if data['agent'] != agent or data['lease_id'] != lease:
            raise ValueError('claim należy do innego agenta lub lease')
        data['status'] = 'released'
        write(path, data)
        return data

    def claims_check(self):
        errors, seen = [], {}
        for _, claim in self.records('claims'):
            if self.active(claim):
                task = claim['task_id']
                if task in seen:
                    errors.append('podwójny claim: ' + task)
                seen[task] = claim
        # A merge choosing one side must not hide concurrent leases from the parents.
        for merge in self.git('rev-list', '--merges', 'HEAD').splitlines():
            parents = self.git('rev-list', '--parents', '-n', '1', merge).split()[1:]
            claims = {}
            for parent in parents:
                for name in self.git('ls-tree', '-r', '--name-only', parent, '--', self.prefix + '/claims').splitlines():
                    if not name.endswith('.json'):
                        continue
                    claim = validate('claim', json.loads(self.git('show', parent + ':' + name)))
                    if self.active(claim):
                        claims.setdefault(claim['task_id'], set()).add((claim['agent'], claim['lease_id']))
            errors.extend('kolizja claimów po merge: ' + task + ' ' + merge
                          for task, leases in claims.items() if len(leases) > 1)
        return errors

    def decisions_add(self, agent, decision, rationale, supersedes=None):
        errors = self.decisions_check()
        if errors:
            raise ValueError('; '.join(errors))
        records = self.records('decisions')
        ids = {v['id'] for _, v in records}
        if supersedes and supersedes not in ids:
            raise ValueError('supersedes wskazuje nieistniejącą decyzję')
        number = max([int(i[4:]) for i in ids] or [0]) + 1
        data = dict(id='DEC-' + str(number).zfill(4), created_at=stamp(), agent=identifier(agent),
                    decision=decision, rationale=rationale, supersedes=supersedes or '')
        validate('decision', data)
        write(self.path('decisions/' + data['id'] + '.json'), data, exclusive=True)
        return data

    def decisions_check(self, base=None):
        errors, versions = [], {}
        for commit in self.git('rev-list', 'HEAD').splitlines():
            for name in self.git('ls-tree', '-r', '--name-only', commit, '--', self.prefix + '/decisions').splitlines():
                if name.endswith('.json'):
                    versions.setdefault(name, set()).add(self.git('rev-parse', commit + ':' + name))
        for name, blobs in versions.items():
            path = bounded(self.repo, name)
            if len(blobs) > 1 or not path.exists():
                errors.append('zmieniona/usunięta decyzja: ' + name)
            elif self.git('hash-object', '--', str(path)) not in blobs:
                errors.append('zmieniona decyzja: ' + name)
        for commit in self.git('rev-list', 'HEAD').splitlines():
            changes = self.git('diff-tree', '-m', '--no-commit-id', '--name-status', '-r', commit,
                               '--', self.prefix + '/decisions').splitlines()
            for change in changes:
                if change[:1] in ('D', 'M', 'R'):
                    errors.append('naruszenie append-only: ' + commit + ' ' + change)
        records = self.records('decisions')
        ids = set()
        for path, data in records:
            if path.stem != data['id'] or data['id'] in ids:
                errors.append('kolizja ID decyzji: ' + data['id'])
            ids.add(data['id'])
        for _, data in records:
            if data['supersedes'] and (data['supersedes'] not in ids or data['supersedes'] >= data['id']):
                errors.append('błędne supersedes: ' + data['id'])
        policy = self.policy()
        if base or policy.get('rules'):
            ref = base or policy.get('diff_base') or self.git('rev-list', '--max-parents=0', 'HEAD').splitlines()[0]
            errors.extend(self.policy_diff(ref))
        return errors

    def policy_diff(self, base):
        rules = self.policy().get('rules', [])
        errors = []
        commits = self.git('rev-list', '--reverse', base + '..HEAD').splitlines()
        for commit in commits:
            author = self.git('show', '-s', '--format=%an', commit)
            names = self.git('diff-tree', '-m', '--no-commit-id', '--name-only', '-r', commit).splitlines()
            for name in names:
                patch = self.git('show', '--format=', '--unified=0', commit, '--', name)
                added = '\n'.join(s[1:] for s in patch.splitlines() if s.startswith('+') and not s.startswith('+++'))
                for rule in rules:
                    if not fnmatch.fnmatch(name, rule.get('glob', '*')):
                        continue
                    violated = rule['kind'] == 'forbidden_file'
                    if rule['kind'] == 'forbidden_pattern':
                        violated = re.search(rule['pattern'], added) is not None
                    if rule['kind'] == 'required_pattern':
                        try:
                            content = self.git('show', commit + ':' + name)
                        except ValueError:
                            content = ''
                        violated = re.search(rule['pattern'], content) is None
                    if violated:
                        errors.append(rule['id'] + ': ' + name + ' commit=' + commit + ' autor=' + author)
        # Uncommitted changes are also part of the diff under review.
        for name in self.git('diff', '--name-only', 'HEAD').splitlines():
            path = bounded(self.repo, name)
            patch = self.git('diff', '--unified=0', 'HEAD', '--', name)
            added = '\n'.join(s[1:] for s in patch.splitlines() if s.startswith('+') and not s.startswith('+++'))
            for rule in rules:
                if not fnmatch.fnmatch(name, rule.get('glob', '*')):
                    continue
                bad = rule['kind'] == 'forbidden_file'
                if rule['kind'] == 'forbidden_pattern':
                    bad = re.search(rule['pattern'], added) is not None
                if rule['kind'] == 'required_pattern':
                    bad = re.search(rule['pattern'], path.read_text() if path.is_file() else '') is None
                if bad:
                    errors.append(rule['id'] + ': ' + name + ' autor=WORKTREE')
        return errors

    def report(self, base=None):
        checks = {'instruction_drift': self.agents_check, 'missing_handoffs': self.handoff_check,
                  'claim_collisions': self.claims_check, 'decision_violations': lambda: self.decisions_check(base)}
        result = {'title': 'Dryf i ciągłość', 'helix_version': VERSION, 'schema_version': 1}
        for name, check in checks.items():
            try:
                result[name] = check()
            except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, re.error) as exc:
                result[name] = ['ERROR: ' + str(exc)]
        try:
            result['version_drift'] = self.policy()['helix_version'] != VERSION
        except (OSError, ValueError, TypeError, KeyError):
            result['version_drift'] = True
        result['status'] = 'FAIL' if result['version_drift'] or any(result[n] for n in checks) else 'PASS'
        return result


def identifier(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', value):
        raise ValueError('niepoprawny identyfikator')
    return value


def parsers(sp):
    for name, actions in [('agents', ('generate', 'check')), ('claim', ('take', 'release', 'list', 'check')),
                          ('decisions', ('add', 'list', 'check')), ('continuity', ('report',))]:
        p = sp.add_parser(name, help='Ciągłość agentów w repo')
        p.add_argument('action', choices=actions)
        p.add_argument('task', nargs='?')
        p.add_argument('--agent', default='reader'); p.add_argument('--env', default='local')
        p.add_argument('--ttl', type=int, default=3600); p.add_argument('--commit', action='store_true')
        p.add_argument('--lease'); p.add_argument('--decision'); p.add_argument('--rationale')
        p.add_argument('--supersedes'); p.add_argument('--base'); p.add_argument('--json', action='store_true')


def handoff_parser(p):
    p.add_argument('action', nargs='?', choices=('write', 'read', 'check', 'run'))
    p.add_argument('--agent', default='reader'); p.add_argument('--env', default='local')
    p.add_argument('--done'); p.add_argument('--evidence'); p.add_argument('--next'); p.add_argument('--risks')
    p.add_argument('--file')


def dispatch(args):
    try:
        if getattr(args, 'state_dir', None):
            raise ValueError('ciągłość wymaga stanu pod repo')
        c = Continuity(args.repo)
        name, action = args.cmd, args.action
        errors = None
        if name == 'agents':
            result = c.generate() if action == 'generate' else c.agents_check()
            if action == 'check': errors = result
        elif name == 'handoff':
            if action == 'write':
                data = load(bounded(c.repo, args.file)) if args.file else {
                    k: getattr(args, k) for k in ('agent', 'env', 'done', 'evidence', 'next', 'risks')}
                result = c.handoff_write(data)
            elif action == 'read': result = c.handoff_read(args.agent, args.env)
            else: result = errors = c.handoff_check()
        elif name == 'claim':
            if action == 'take': result = c.claim_take(args.task, args.agent, args.ttl, args.commit)
            elif action == 'release': result = c.claim_release(args.task, args.agent, args.lease)
            elif action == 'list': result = [dict(v, expired=not c.active(v)) for _, v in c.records('claims')]
            else: result = errors = c.claims_check()
        elif name == 'decisions':
            if action == 'add': result = c.decisions_add(args.agent, args.decision, args.rationale, args.supersedes)
            elif action == 'list': result = [v for _, v in c.records('decisions')]
            else: result = errors = c.decisions_check(args.base)
        else:
            result = c.report(args.base)
            errors = result['status'] != 'PASS'
        if name == 'continuity' and not args.json:
            print('## Dryf i ciągłość\n\nStatus: ' + result['status'])
            for key in ('instruction_drift', 'missing_handoffs', 'claim_collisions', 'decision_violations'):
                print(key + ': ' + ('; '.join(result[key]) or 'OK'))
            print('version_drift: ' + str(result['version_drift']))
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if errors else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError, re.error, OverflowError):
        # Never echo invalid input: it may contain a credential.
        print('FAIL: niepoprawne dane ciągłości, konflikt lub niedostępny git')
        return 2
