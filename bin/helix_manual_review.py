"""Bound manual review files. No provider calls, availability probes or project reads."""
from contextlib import contextmanager
import hashlib
import json
import math
import os
import re
import stat
import time
import uuid

from helix_audit_context import system_path
from helix_provider_plan import model_family, model_family_basis
from helix_model_admission import source_input_admission


class PendingReview(Exception):
    """This reviewer's exact request has no usable response yet."""


def validate_reviewers(reviewers):
    """Reject ambiguous output identities before creating any request."""
    names = set()
    for entry in reviewers:
        if not entry.get('enabled', True):
            continue
        name = entry.get('name')
        if not isinstance(name, str) or not name.strip() or any(c in name for c in '/\\\0\r\n'):
            raise ValueError('reviewer wymaga niepustej nazwy bez separatorów ścieżek')
        if name in names:
            raise ValueError('aktywne nazwy reviewerów muszą być unikalne')
        names.add(name)


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


@contextmanager
def _directory(out):
    """Resolve existing directory components without following project symlinks."""
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise ValueError('manual review wymaga bezpiecznego dostępu do plików')
    path = system_path(out)
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _read(fd, name):
    if not isinstance(name, str) or name in ('', '.', '..') or any(c in name for c in '/\\\0'):
        raise ValueError('manual review wymaga lokalnej nazwy pliku')
    leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        if not stat.S_ISREG(os.fstat(leaf).st_mode):
            raise ValueError('manual review wymaga zwykłego pliku')
        with os.fdopen(leaf, 'rb', closefd=False) as stream:
            return stream.read()
    finally:
        os.close(leaf)


def _write_once(fd, name, value):
    """Publish complete bytes exclusively; never replace an existing response."""
    temporary = '.manual-' + uuid.uuid4().hex + '.tmp'
    leaf = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(leaf, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        except FileExistsError:
            if _read(fd, name) != value:
                raise ValueError('istniejący request ma inną treść; nie nadpisano dowodu') from None
    finally:
        os.unlink(temporary, dir_fd=fd)


def prepare(out, *, policy=None, **kwargs):
    """Public request export has the same source admission as handoff."""
    if kwargs.get('offline', False):
        raise ValueError('offline: ręczny request review nie został utworzony')
    source_input_admission(policy, 'grok')
    return _prepare_local_protocol(out, **kwargs)


def _prepare_local_protocol(out, *, checkpoint, reviewer, round_no, prompt, diff, base='', requested_model=None, offline=False):
    """Internal protocol writer; synthetic tests do not claim source admission."""
    if offline:
        raise ValueError('offline: ręczny request review nie został utworzony')
    validate_reviewers([dict(name=reviewer)])
    if not isinstance(checkpoint, str) or not checkpoint or not isinstance(base, str):
        raise ValueError('manual review wymaga checkpointu i tekstowej bazy')
    if isinstance(round_no, bool) or not isinstance(round_no, int) or round_no < 1:
        raise ValueError('manual review wymaga dodatniej rundy')
    if not isinstance(prompt, str) or not isinstance(diff, str):
        raise ValueError('manual review wymaga tekstu promptu i pełnego diffu')
    if requested_model is not None and (not isinstance(requested_model, str) or not requested_model.strip()):
        raise ValueError('manual review wymaga konkretnego modelu lub null')
    binding = dict(protocol_version=1, checkpoint=checkpoint, reviewer=reviewer, round=round_no,
                   base=base, requested_model=requested_model,
                   prompt_sha256=_hash(prompt.encode()), diff_sha256=_hash(diff.encode()))
    request_id = _hash(_json(binding).encode())
    slug = re.sub('[^a-zA-Z0-9_-]+', '-', reviewer).strip('-_')[:40] or 'reviewer'
    tag = f'{slug}-r{round_no}-{request_id[:20]}'
    binding.update(request_id=request_id, request=f'manual-request-{tag}.json',
                   prompt=f'manual-request-{tag}.md', verdict=f'manual-verdict-{tag}.json',
                   receipt=f'manual-verdict-{tag}.receipt.json')
    template = dict(request_id=request_id, verdict_sha256='SHA256_RAW_VERDICT_BYTES',
                    provider='grok', model=requested_model or 'EXACT_GROK_MODEL')
    instructions = ('\n\n## Ręczna odpowiedź\n\n'
        'Zapisz osobny werdykt zgodny ze schemas/review.json do: ' + binding['verdict'] + '\n'
        'Zapisz potwierdzenie pochodzenia do: ' + binding['receipt'] + '\n'
        'Wpisz rzeczywisty model oraz SHA-256 bajtów pliku werdyktu. To deklaracja ręczna, nie automatyczna sonda.\n'
        'Nie używaj odpowiedzi innego reviewera lub innego requestu.\n\n' + _json(template) + '\n')
    with _directory(out) as fd:
        _write_once(fd, binding['request'], (_json(binding) + '\n').encode())
        _write_once(fd, binding['prompt'], (prompt + instructions).encode())
    return binding


def read_response(out, binding):
    """Consume bytes once, bound to this request and a declared Grok model."""
    try:
        with _directory(out) as fd:
            raw = _read(fd, binding['verdict'])
            receipt = json.loads(_read(fd, binding['receipt']))
        text = raw.decode('utf-8')
        verdict = json.loads(text)
    except FileNotFoundError:
        raise PendingReview('brak kompletu ' + binding['verdict'] + ' oraz ' + binding['receipt']) from None
    except (OSError, ValueError, UnicodeError):
        raise PendingReview('odpowiedź manual review jest nieczytelna lub ma niepoprawny JSON') from None
    if not isinstance(receipt, dict) or not isinstance(verdict, dict):
        raise PendingReview('odpowiedź i receipt muszą być obiektami JSON')
    if receipt.get('request_id') != binding['request_id'] or receipt.get('verdict_sha256') != _hash(raw):
        raise PendingReview('receipt nie potwierdza tego requestu i tych bajtów werdyktu')
    provider, model = receipt.get('provider'), receipt.get('model')
    if provider not in ('grok', 'grok-cli') or not isinstance(model, str) or not model.strip():
        raise PendingReview('receipt wymaga jawnego providera i konkretnego modelu Groka')
    family = model_family(provider, model)
    if family != 'xai' or model_family_basis(provider, model) != 'known_model_brand':
        raise PendingReview('receipt nie określa rozpoznanej rodziny modelu Groka')
    if binding['requested_model'] is not None and model != binding['requested_model']:
        raise PendingReview('rzeczywisty model nie zgadza się z jawnym wyborem requestu')
    used = dict(provider='grok', model=model, family=family, method='manual_handoff',
                family_basis='manual_model_declaration', request_id=binding['request_id'],
                reviewer=binding['reviewer'], round=binding['round'], role='reviewer')
    return text, used


def handoff(out, *, wait_seconds=0, policy=None, **kwargs):
    """Public export requires an admitted prepared input, unavailable in step 30."""
    if kwargs.get('offline', False):
        raise ValueError('offline: ręczny request review nie został utworzony')
    if isinstance(wait_seconds, bool) or not isinstance(wait_seconds, (int, float)) or not math.isfinite(wait_seconds) or wait_seconds < 0:
        raise ValueError('manual review wymaga nieujemnego czasu oczekiwania')
    source_input_admission(policy, 'grok')
    binding = prepare(out, policy=policy, **kwargs)
    return wait_response(out, binding, wait_seconds=wait_seconds)


def wait_response(out, binding, *, wait_seconds=0):
    """Read the local receipt protocol; never create or export source requests."""
    if isinstance(wait_seconds, bool) or not isinstance(wait_seconds, (int, float)) or not math.isfinite(wait_seconds) or wait_seconds < 0:
        raise ValueError('manual review wymaga nieujemnego czasu oczekiwania')
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            return read_response(out, binding)
        except PendingReview:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(5, remaining))
