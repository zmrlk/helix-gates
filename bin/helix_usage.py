"""Per-call receipts. Missing provider telemetry stays null, never estimated."""
from functools import wraps
import json
import math
from pathlib import Path
import time
import uuid


def number(value, integer=False):
    if type(value) not in ((int,) if integer else (int, float)):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def usage(payload=None):
    payload = payload if isinstance(payload, dict) else {}
    values = payload.get('usage')
    values = values if isinstance(values, dict) else {}
    result = {key: number(values.get(key), integer=True)
              for key in ('input_tokens', 'output_tokens', 'total_tokens')}
    result['cost_usd'] = number(payload.get('total_cost_usd', values.get('cost_usd')))
    result['status'] = 'reported' if any(v is not None for v in result.values()) else 'unknown'
    return result


class Response(str):
    def __new__(cls, text, payload=None):
        result = super().__new__(cls, text)
        result.usage = usage(payload)
        return result


def measured(provider):
    """Wrap the native caller: receipts include failed attempts, no prompt/body.

    AGY and Grok return telemetry only from their outer CLI envelope. JSON in
    model-authored content is never accepted as accounting evidence.
    """
    def decorate(caller):
        @wraps(caller)
        def call(ctx, model, prompt, images, schema, write, out_dir, timeout, **kwargs):
            started = time.monotonic()
            selected_provider = kwargs.get('provider') or provider
            if caller.__name__ == 'call_agy' and not kwargs.get('provider'):
                from helix_model_admission import probe_provider
                selected_provider = probe_provider(ctx) or provider
            row = dict(schema_version=1, kind='model-call', call_id=uuid.uuid4().hex,
                       provider=selected_provider, model=model or 'unknown',
                       status='error', call_invoked=True, elapsed_seconds=None, usage=usage())
            response = None
            try:
                raw = caller(ctx, model, prompt, images, schema, write, out_dir, timeout, **kwargs)
                response = raw if isinstance(raw, Response) else Response(raw)
                row.update(status='complete', usage=response.usage)
                return response
            except BaseException as error:
                if getattr(error, 'admission_code', None) or getattr(error, 'code', '').startswith('DATA_EGRESS'):
                    row.update(status='not_invoked', call_invoked=False)
                raise
            finally:
                row['elapsed_seconds'] = time.monotonic() - started if row['call_invoked'] else None
                if row['call_invoked']:
                    from helix_environment import provenance
                    row['target'] = str(ctx.repo)
                    row['provenance'] = provenance(ctx.repo)
                    path = Path(out_dir) / ('model-call-' + row['call_id'] + '.json')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open('x', encoding='utf-8') as stream:
                        json.dump(row, stream, ensure_ascii=False, indent=2, allow_nan=False)
                        stream.write('\n')
                    if response is not None:
                        response.call = {k: row[k] for k in ('call_id', 'call_invoked', 'elapsed_seconds', 'usage')}
        return call
    return decorate


def describe(row):
    data = row.get('usage') if isinstance(row.get('usage'), dict) else {}
    display = lambda value: 'nieznane' if number(value) is None else str(value)
    return ('czas: ' + display(row.get('elapsed_seconds')) + ' s; tokeny in/out/total: '
            + '/'.join(display(data.get(k)) for k in ('input_tokens', 'output_tokens', 'total_tokens'))
            + '; koszt USD: ' + display(data.get('cost_usd')))
