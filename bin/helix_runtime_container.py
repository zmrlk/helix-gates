"""Local container transport selection, independent from database and identity.

Discovery performs stat on known Unix sockets only. No CLI, socket connection,
Docker context/config, remote endpoint or caller credentials are consulted.
"""
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit


def local_docker_endpoint(home=None):
    home = Path.home() if home is None else Path(home)
    for candidate, source in ((Path('/var/run/docker.sock'), 'system_socket'),
                              (home / '.docker' / 'run' / 'docker.sock', 'docker_desktop_socket')):
        try: info = candidate.stat()
        except OSError: continue
        if candidate.is_absolute() and stat.S_ISSOCK(info.st_mode):
            return validate_endpoint(dict(host='unix://' + str(candidate), kind='unix', source=source))
    return None


def validate_endpoint(endpoint):
    """Validate a trusted selector's private result without echoing its values."""
    if endpoint is None: return None
    if not isinstance(endpoint, dict) or set(endpoint) != {'host', 'kind', 'source'}:
        raise ValueError('invalid local container endpoint record')
    host = endpoint['host']; source = endpoint['source']
    if not isinstance(host, str) or not host.startswith('unix:///') or re.search(r'[\x00-\x1f\x7f]', host):
        raise ValueError('container endpoint must use a local Unix socket')
    value = urlsplit(host)
    if (value.scheme != 'unix' or value.netloc or not value.path.startswith('/') or value.query or value.fragment or
            '..' in Path(value.path).parts or '%' in value.path or endpoint['kind'] != 'unix' or
            not isinstance(source, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,79}', source)):
        raise ValueError('invalid local container endpoint')
    return dict(endpoint)


def public_endpoint(endpoint):
    value = validate_endpoint(endpoint)
    return {key: value[key] for key in ('kind', 'source')} if value else dict(kind='unavailable', source='known_local_paths')


def engine_environment(environment, *, engine, endpoint=None, require_endpoint=True):
    """A new restricted env; app env and remote context never affect transport."""
    if engine not in ('docker', 'podman') or not isinstance(environment, dict):
        raise ValueError('invalid container environment request')
    if not isinstance(environment.get('HOME'), str) or not Path(environment['HOME']).is_absolute():
        raise ValueError('container commands require an explicit private HOME')
    result = {name: environment[name] for name in ('PATH', 'HOME', 'CI')
              if isinstance(environment.get(name), str)}
    if engine == 'docker' and require_endpoint:
        value = validate_endpoint(endpoint)
        if value is None: raise ValueError('known local Docker Unix socket missing; no context fallback')
        result['DOCKER_HOST'] = value['host']
    return result
