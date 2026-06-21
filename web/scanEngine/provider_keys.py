"""Provider API keys that live in tool config files rather than the database.

Currently this covers the Shodan key consumed by **subfinder** during subdomain
enumeration. subfinder auto-loads its `provider-config.yaml` at scan time, so we
write the key straight there instead of introducing a DB model + migration. The
path is overridable via ``settings.SUBFINDER_PROVIDER_CONFIG_PATH`` (handy for
tests, which point it at a temp file).
"""
import json
import os
import re

import yaml
from django.conf import settings

DEFAULT_PROVIDER_CONFIG_PATH = '/root/.config/subfinder/provider-config.yaml'


def _provider_config_path():
    return getattr(settings, 'SUBFINDER_PROVIDER_CONFIG_PATH',
                   DEFAULT_PROVIDER_CONFIG_PATH)


def set_shodan_key(key):
    """Persist the Shodan API key into subfinder's provider-config.yaml.

    Replaces the existing ``shodan:`` line (or appends one) without disturbing
    the other providers' entries. Returns ``True`` when a key was written.
    """
    key = (key or '').strip()
    if not key:
        return False
    path = _provider_config_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        with open(path) as fh:
            content = fh.read()
    except FileNotFoundError:
        content = ''
    # json.dumps gives a valid YAML flow sequence of one quoted string,
    # e.g. shodan: ["abc123"] — and safely escapes the key value.
    line = 'shodan: ' + json.dumps([key])
    if re.search(r'^shodan:.*$', content, flags=re.M):
        content = re.sub(r'^shodan:.*$', line, content, flags=re.M)
    else:
        content = (content.rstrip('\n') + '\n' if content.strip() else '') + line + '\n'
    with open(path, 'w') as fh:
        fh.write(content)
    return True


def get_shodan_key():
    """Return the configured Shodan key, or ``None`` if unset/unreadable."""
    path = _provider_config_path()
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
    except (FileNotFoundError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    val = data.get('shodan')
    if isinstance(val, (list, tuple)) and val:
        first = str(val[0]).strip()
        return first or None
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def is_shodan_configured():
    return get_shodan_key() is not None


def masked_shodan_key():
    """Non-revealing hint for logs/diagnostics: ``jGJO…zvC`` (never the full key)."""
    k = get_shodan_key()
    if not k:
        return None
    if len(k) <= 8:
        return '••••'
    return f'{k[:4]}…{k[-3:]}'
