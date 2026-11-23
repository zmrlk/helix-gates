"""Shared model boundary: offline mode, unknown providers and the owner's explicit restriction refuse; the rest is admitted.

Only a fixed availability ping has a short-lived, one-use native-call lease.
That lease is not source-review permission or a filesystem sandbox capability.
"""
from contextlib import contextmanager
import copy
import os
from pathlib import Path
import sys
import tempfile
import threading

from helix_data_egress import DataEgressError, normalize_policy, policy_sha256
from helix_provider_plan import FAMILIES, JSON_PROVIDERS


FIXED_PROBE_PROMPT = 'Availability probe. Do not use tools or access files. Reply only with the JSON object {"ok": true}.'
_CODES = frozenset(('INPUT_NOT_ADMITTED', 'SOURCE_INPUT_NOT_ADMITTED',
                    'TRANSPORT_NOT_ADMITTED', 'OFFLINE'))
_LOCK = threading.RLock()
_LEASES = {}


class AdmissionError(DataEgressError):
    """Fixed diagnostics without prompts, source paths or rejected inputs."""
    def __init__(self, code):
        self.code = code if code in _CODES else 'INPUT_NOT_ADMITTED'
        ValueError.__init__(self, 'data_egress: ' + self.code)


class _Token:
    __slots__ = ()


class _Lease:
    __slots__ = ('ctx', 'provider', 'model', 'directory', 'identity', 'used')

    def __init__(self, ctx, provider, model, directory, identity):
        self.ctx, self.provider, self.model = ctx, provider, model
        self.directory, self.identity, self.used = directory, identity, False


def effective_policy(policy):
    """Owner decision 15.11.2026: Helix sends project content to every configured provider unless the owner restricts it.

    No policy, or a proposal still waiting for the owner, means all providers. An explicitly approved policy keeps
    its own provider list (the owner's restriction). Secret files are never read into prompts (helix_audit_context.DENY).
    """
    if policy is None or (isinstance(policy, dict) and policy.get('status') == 'pending_owner'):
        return dict(schema_version=1, status='approved', allowed_providers=sorted(FAMILIES),
                    exclude_paths=list((policy or {}).get('exclude_paths') or []))
    return policy


def authorize_provider(ctx_or_policy, provider):
    """Authorize an exact actual provider, never a family or configured alias.

    A dict is the policy itself. A context supplies cfg.data_egress; see effective_policy for the default.
    """
    if isinstance(ctx_or_policy, dict) or ctx_or_policy is None:
        policy = ctx_or_policy
    else:
        cfg = getattr(ctx_or_policy, 'cfg', None)
        policy = cfg.get('data_egress') if isinstance(cfg, dict) else None
    normalized = normalize_policy(effective_policy(policy))
    if not isinstance(provider, str) or provider not in FAMILIES:
        raise DataEgressError('INVALID_PROVIDER')
    if provider not in normalized['allowed_providers']:
        raise DataEgressError('PROVIDER_NOT_ALLOWED')
    return policy_sha256(normalized)


def source_input_admission(ctx_or_policy, provider):
    """Admit project content for an authorized provider; offline mode refuses."""
    if getattr(ctx_or_policy, 'offline', False): raise AdmissionError('OFFLINE')
    policy_hash = authorize_provider(ctx_or_policy, provider)
    return dict(schema_version=1, status='ADMITTED', kind='source_input', provider=provider, policy_sha256=policy_hash)


def _model_valid(model):
    return model is None or (isinstance(model, str) and bool(model.strip())
        and model == model.strip() and len(model) <= 1024
        and not any(ord(c) < 32 or ord(c) == 127 for c in model))


def _directory_identity(directory):
    """Open every canonical path component without following symlinks."""
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise AdmissionError('INPUT_NOT_ADMITTED')
    fd = os.open(directory.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in directory.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            old, fd = fd, child
            os.close(old)
        stat = os.fstat(fd)
        return stat.st_dev, stat.st_ino
    finally:
        os.close(fd)


def _lease(ctx):
    token = getattr(ctx, '_helix_model_probe_token', None)
    if not isinstance(token, _Token): return None
    lease = _LEASES.get(token)
    return lease if lease is not None and lease.ctx is ctx else None


def probe_provider(ctx):
    """Read the alias from an exact live lease; a config flag grants nothing."""
    with _LOCK:
        lease = _lease(ctx)
        return lease.provider if lease is not None and not lease.used else None


def _same_path(value, expected):
    if not isinstance(value, (str, Path)): return False
    try:
        path = Path(value)
        # Do not resolve a supplied alias or symlink into a seemingly valid cwd.
        return path.is_absolute() and str(path) == str(expected)
    except (TypeError, ValueError):
        return False


def native_call_admission(ctx, provider, model, prompt, images, schema, write, out_dir):
    """Consume a fixed probe lease once; without a lease admit a configured provider unless offline."""
    if getattr(ctx, 'offline', False): raise AdmissionError('OFFLINE')
    with _LOCK:
        lease = _lease(ctx)
        if lease is None:
            if getattr(ctx, '_helix_model_probe_token', None) is not None:
                raise AdmissionError('INPUT_NOT_ADMITTED')
            # Decyzja właściciela (15.11.2026): wywołanie z treścią projektu przechodzi dla dostawcy dopuszczonego polityką
            # (domyślnie: wszyscy). Odmawia tryb --offline (wyżej) i jawne ograniczenie właściciela.
            policy_hash = authorize_provider(ctx, provider)
            return dict(schema_version=1, status='ADMITTED', kind='model_call', provider=provider, model=model,
                        policy_sha256=policy_hash, delivery='SENT')
        valid = (not lease.used and isinstance(provider, str) and provider == lease.provider
                 and _model_valid(model) and model == lease.model
                 and type(prompt) is str and prompt == FIXED_PROBE_PROMPT
                 and images is None and schema is None and write is False
                 and all(_same_path(value, lease.directory) for value in
                    (getattr(ctx, 'repo', None), getattr(ctx, 'state_dir', None),
                     getattr(ctx, 'out_dir', None), out_dir)))
        if not valid: raise AdmissionError('INPUT_NOT_ADMITTED')
        try:
            if _directory_identity(lease.directory) != lease.identity:
                raise AdmissionError('INPUT_NOT_ADMITTED')
        except (OSError, ValueError):
            raise AdmissionError('INPUT_NOT_ADMITTED') from None
        lease.used = True
        return dict(schema_version=1, status='ADMITTED', kind='availability_probe',
            provider=provider, model=model, policy_sha256=None, delivery='NOT_SENT',
            source_review_calls=0, source_paths=[], prompt_scope='fixed_no_project_content')


@contextmanager
def authorized_probe(ctx, provider, model):
    """Own a neutral directory and opaque, current-context probe lease.

    The caller may add its time deadline. It cannot replace the prompt, model,
    provider, paths, schema, image list or write mode admitted at the boundary.
    No model, credentials, source file or network is accessed by this helper.
    """
    if getattr(ctx, 'offline', False): raise AdmissionError('OFFLINE')
    if not isinstance(provider, str) or provider not in JSON_PROVIDERS or not _model_valid(model):
        raise AdmissionError('INPUT_NOT_ADMITTED')
    cfg = getattr(ctx, 'cfg', None)
    if not isinstance(cfg, dict): raise AdmissionError('INPUT_NOT_ADMITTED')
    try:
        target = Path(ctx.repo).expanduser().resolve()
        base = Path(tempfile.gettempdir()).resolve()
        if base.is_relative_to(target): raise AdmissionError('INPUT_NOT_ADMITTED')
    except (OSError, ValueError, TypeError, AttributeError):
        raise AdmissionError('INPUT_NOT_ADMITTED') from None
    token, probe_ctx = None, None
    try:
        owner = tempfile.TemporaryDirectory(prefix='helix-provider-probe-', dir=base)
    except OSError:
        raise AdmissionError('INPUT_NOT_ADMITTED') from None
    try:
        try:
            neutral = Path(owner.name).resolve()
            if neutral.is_relative_to(target) or target.is_relative_to(neutral):
                raise AdmissionError('INPUT_NOT_ADMITTED')
            probe_ctx = copy.copy(ctx)
            probe_ctx.cfg = copy.deepcopy(cfg)
            probe_ctx.repo = probe_ctx.state_dir = probe_ctx.out_dir = neutral
            token = _Token()
            lease = _Lease(probe_ctx, provider, model, neutral, _directory_identity(neutral))
            with _LOCK:
                _LEASES[token] = lease
                probe_ctx._helix_model_probe_token = token
        except (OSError, TypeError, ValueError, AttributeError) as error:
            if isinstance(error, DataEgressError): raise
            raise AdmissionError('INPUT_NOT_ADMITTED') from None
        yield probe_ctx, FIXED_PROBE_PROMPT, neutral
    finally:
        active_error = sys.exc_info()[0] is not None
        with _LOCK:
            _LEASES.pop(token, None)
            if token is not None and probe_ctx is not None and getattr(probe_ctx, '_helix_model_probe_token', None) is token:
                del probe_ctx._helix_model_probe_token
        try:
            owner.cleanup()
        except OSError:
            if not active_error: raise AdmissionError('INPUT_NOT_ADMITTED') from None
