"""Provider API keys that live in tool config files rather than the database.

This covers the passive-source keys consumed by **subfinder** during subdomain
enumeration. subfinder auto-loads its ``provider-config.yaml`` at scan time, so we
write keys straight there instead of introducing DB models + migrations. The path
is overridable via ``settings.SUBFINDER_PROVIDER_CONFIG_PATH`` (tests point it at a
temp file).

``SUBFINDER_UI_PROVIDERS`` is the curated, high-ROI subset surfaced in the API
Vault page — each ``key`` MUST match subfinder's provider id in
provider-config.yaml. Several of these (shodan, censys, virustotal,
securitytrails, github, fullhunt, quake, zoomeye, intelx) are also consumed by
OneForAll / theHarvester / SpiderFoot, so one key improves multiple scan stages.
"""
import json
import os
import re

import yaml
from django.conf import settings
from django.utils.translation import gettext_lazy as _

DEFAULT_PROVIDER_CONFIG_PATH = '/root/.config/subfinder/provider-config.yaml'

SUBFINDER_UI_PROVIDERS = [
    {'key': 'shodan', 'label': 'Shodan', 'url': 'https://account.shodan.io',
     'description': _("Pulls hostnames from Shodan's internet-wide scan data during subdomain enumeration.")},
    {'key': 'github', 'label': 'GitHub', 'url': 'https://github.com/settings/tokens',
     'description': _("Personal access token — lets subfinder mine public code and commits for subdomains. High coverage, free.")},
    {'key': 'virustotal', 'label': 'VirusTotal', 'url': 'https://www.virustotal.com/gui/my-apikey',
     'description': _("Passive subdomain data from VirusTotal. Free tier available.")},
    {'key': 'securitytrails', 'label': 'SecurityTrails', 'url': 'https://securitytrails.com/app/account/credentials',
     'description': _("Strong passive-DNS source for subdomains. Free tier available.")},
    {'key': 'censys', 'label': 'Censys', 'url': 'https://search.censys.io/account/api',
     'description': _("Certificate / host data. Enter as API_ID:API_SECRET. Free tier available.")},
    {'key': 'binaryedge', 'label': 'BinaryEdge', 'url': 'https://app.binaryedge.io/account/api',
     'description': _("Passive subdomain data from BinaryEdge. Free tier available.")},
    {'key': 'fullhunt', 'label': 'FullHunt', 'url': 'https://fullhunt.io/profile/',
     'description': _("Attack-surface / subdomain data from FullHunt. Free tier available.")},
    {'key': 'intelx', 'label': 'IntelX', 'url': 'https://intelx.io/account?tab=developer',
     'description': _("Intelligence X subdomain / data lookups.")},
    {'key': 'quake', 'label': 'Quake (360)', 'url': 'https://quake.360.net/quake/#/personal',
     'description': _("Quake (360) host / subdomain data.")},
    {'key': 'zoomeyeapi', 'label': 'ZoomEye', 'url': 'https://www.zoomeye.org/profile',
     'description': _("ZoomEye host / subdomain data.")},
]

_PROVIDER_NAME_RE = re.compile(r'^[a-z0-9_]+$')


def _provider_config_path():
    return getattr(settings, 'SUBFINDER_PROVIDER_CONFIG_PATH',
                   DEFAULT_PROVIDER_CONFIG_PATH)


def _read_content():
    try:
        with open(_provider_config_path()) as fh:
            return fh.read()
    except FileNotFoundError:
        return ''


def set_subfinder_key(provider, value):
    """Write ``provider: ["value"]`` into subfinder's provider-config.yaml.

    Replaces the existing ``<provider>:`` line (or appends one) without touching
    the other providers' entries. Returns ``True`` when a value was written.
    """
    if not _PROVIDER_NAME_RE.match(provider or ''):
        return False
    value = (value or '').strip()
    if not value:
        return False
    path = _provider_config_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    content = _read_content()
    # json.dumps gives a valid YAML flow sequence of one quoted string,
    # e.g. shodan: ["abc123"] — and safely escapes the value.
    line = '%s: %s' % (provider, json.dumps([value]))
    pattern = re.compile(r'^%s:.*$' % re.escape(provider), flags=re.M)
    if pattern.search(content):
        content = pattern.sub(line, content)
    else:
        content = (content.rstrip('\n') + '\n' if content.strip() else '') + line + '\n'
    with open(path, 'w') as fh:
        fh.write(content)
    return True


def get_subfinder_key(provider):
    """Return the configured value for ``provider``, or ``None``."""
    try:
        data = yaml.safe_load(_read_content()) or {}
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    val = data.get(provider)
    if isinstance(val, (list, tuple)) and val:
        first = str(val[0]).strip()
        return first or None
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def is_subfinder_key_set(provider):
    return get_subfinder_key(provider) is not None


def masked_key(provider):
    """Non-revealing hint for logs/diagnostics: ``jGJO…zvC`` (never the full key)."""
    k = get_subfinder_key(provider)
    if not k:
        return None
    return '••••' if len(k) <= 8 else '%s…%s' % (k[:4], k[-3:])


def subfinder_providers_status():
    """The UI registry annotated with an ``is_set`` flag, for the template."""
    out = []
    for provider in SUBFINDER_UI_PROVIDERS:
        item = dict(provider)
        item['is_set'] = is_subfinder_key_set(provider['key'])
        out.append(item)
    return out


# --- backward-compatible Shodan wrappers (kept for existing callers/tests) ---
def set_shodan_key(key):
    return set_subfinder_key('shodan', key)


def get_shodan_key():
    return get_subfinder_key('shodan')


def is_shodan_configured():
    return is_subfinder_key_set('shodan')


def masked_shodan_key():
    return masked_key('shodan')
