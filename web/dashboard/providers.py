"""Declarative registry mapping vault credentials to their destinations.

`destination` is either a SpiderFoot config option ('sfp_<module>:<option>')
seeded into spiderfoot.db before a scan, or 'consumer:<name>' read by recon/LLM
code via common_func.get_credential().
"""
import re

PROVIDERS = {
    # --- SpiderFoot-backed (curated, high ROI for the OSINT gap) ---
    'shodan':         {'label': 'Shodan',          'url': 'https://account.shodan.io',
                       'fields': [('key', 'sfp_shodan:api_key')]},
    'haveibeenpwned': {'label': 'HaveIBeenPwned',  'url': 'https://haveibeenpwned.com/API/Key',
                       'fields': [('key', 'sfp_haveibeenpwned:api_key')]},
    'dehashed':       {'label': 'DeHashed',        'url': 'https://dehashed.com',
                       'fields': [('username', 'sfp_dehashed:username'),
                                  ('key', 'sfp_dehashed:api_key')]},
    'virustotal':     {'label': 'VirusTotal',      'url': 'https://www.virustotal.com',
                       'fields': [('key', 'sfp_virustotal:api_key')]},
    'securitytrails': {'label': 'SecurityTrails',  'url': 'https://securitytrails.com',
                       'fields': [('key', 'sfp_securitytrails:api_key')]},
    'hunter':         {'label': 'Hunter.io',       'url': 'https://hunter.io',
                       'fields': [('key', 'sfp_hunter:api_key')]},
    'binaryedge':     {'label': 'BinaryEdge',      'url': 'https://www.binaryedge.io',
                       'fields': [('key', 'sfp_binaryedge:api_key')]},
    'censys':         {'label': 'Censys',          'url': 'https://search.censys.io/account/api',
                       'fields': [('key', 'sfp_censys:api_key_uid'),
                                  ('secret', 'sfp_censys:api_key_secret')]},
    'greynoise':      {'label': 'GreyNoise',       'url': 'https://www.greynoise.io',
                       'fields': [('key', 'sfp_greynoise:api_key')]},
    'abuseipdb':      {'label': 'AbuseIPDB',       'url': 'https://www.abuseipdb.com',
                       'fields': [('key', 'sfp_abuseipdb:api_key')]},
    'ipinfo':         {'label': 'IPInfo',          'url': 'https://ipinfo.io',
                       'fields': [('key', 'sfp_ipinfo:api_key')]},
    'fullhunt':       {'label': 'FullHunt',        'url': 'https://fullhunt.io',
                       'fields': [('key', 'sfp_fullhunt:api_key')]},
    'intelx':         {'label': 'IntelX',          'url': 'https://intelx.io',
                       'fields': [('key', 'sfp_intelx:api_key')]},
    'leakix':         {'label': 'LeakIX',          'url': 'https://leakix.net',
                       'fields': [('key', 'sfp_leakix:api_key')]},
    # --- existing integrations (migrated; consumed by recon/LLM/H1) ---
    'openai':         {'label': 'OpenAI',     'url': 'https://platform.openai.com/api-keys',
                       'fields': [('key', 'consumer:llm')]},
    'netlas':         {'label': 'Netlas',     'url': 'https://netlas.io',
                       'fields': [('key', 'consumer:recon')]},
    'chaos':          {'label': 'Chaos',      'url': 'https://chaos.projectdiscovery.io',
                       'fields': [('key', 'consumer:recon')]},
    'gitguardian':    {'label': 'GitGuardian', 'url': 'https://dashboard.gitguardian.com/api',
                       'fields': [('key', 'consumer:secret')]},
    'hackerone':      {'label': 'HackerOne',  'url': 'https://hackerone.com',
                       'fields': [('username', 'consumer:h1_user'),
                                  ('key', 'consumer:h1_key')]},
}

CUSTOM_OPTION_RE = re.compile(r'^sfp_[a-z0-9_]+:[a-z0-9_]+$')


def sf_destination(dest: str):
    """Return the SpiderFoot option for a destination, or None for consumer fields."""
    return dest if dest.startswith('sfp_') else None


def is_valid_custom_option(s: str) -> bool:
    return bool(CUSTOM_OPTION_RE.match(s or ''))


def custom_provider_slug(option: str) -> str:
    return f'custom:{option}'
