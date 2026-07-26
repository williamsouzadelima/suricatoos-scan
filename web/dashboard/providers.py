"""Declarative registry mapping vault credentials to their destinations.

`destination` documenta QUEM consome a chave. Ele é informativo: a leitura real é por
SLUG — `common_func.get_credential(<slug>)` para os consumidores diretos, e
`scanEngine.provider_keys.propagate_vault_key(<slug>, ...)` para os que são espelhados
nos arquivos de config do subfinder e do theHarvester no momento do save.

Historicamente havia um terceiro destino, `sfp_<módulo>:<opção>`, semeado no
`spiderfoot.db` antes de cada scan. A integração do SpiderFoot foi REMOVIDA (28 de 29
execuções morriam no watchdog de 900s, com o JSON truncado e falha silenciosa; e o fork
mantido do projeto eliminou o modo monolito `sf.py` na v6.0.0). Dos 14 provedores que
existiam por causa dela, **8 permanecem** aqui porque o subfinder e/ou o theHarvester
consomem a mesma chave — ver `VAULT_TOOL_PROPAGATION` em scanEngine/provider_keys.py.
Os 6 que ficariam sem nenhum leitor (haveibeenpwned, dehashed, greynoise, abuseipdb,
ipinfo, leakix) foram removidos: um campo de API key que ninguém lê é uma mentira de UI.
"""

PROVIDERS = {
    # --- espelhados em subfinder / theHarvester por propagate_vault_key() ---
    'shodan':         {'label': 'Shodan',          'url': 'https://account.shodan.io',
                       'fields': [('key', 'consumer:subfinder+theharvester')]},
    'virustotal':     {'label': 'VirusTotal',      'url': 'https://www.virustotal.com',
                       'fields': [('key', 'consumer:subfinder+theharvester')]},
    'securitytrails': {'label': 'SecurityTrails',  'url': 'https://securitytrails.com',
                       'fields': [('key', 'consumer:subfinder+theharvester')]},
    'binaryedge':     {'label': 'BinaryEdge',      'url': 'https://www.binaryedge.io',
                       'fields': [('key', 'consumer:subfinder+theharvester')]},
    'fullhunt':       {'label': 'FullHunt',        'url': 'https://fullhunt.io',
                       'fields': [('key', 'consumer:subfinder+theharvester')]},
    'intelx':         {'label': 'IntelX',          'url': 'https://intelx.io',
                       'fields': [('key', 'consumer:subfinder+theharvester')]},
    'hunter':         {'label': 'Hunter.io',       'url': 'https://hunter.io',
                       'fields': [('key', 'consumer:theharvester')]},
    # subfinder quer id:secret — propagate_vault_key combina os dois campos.
    'censys':         {'label': 'Censys',          'url': 'https://search.censys.io/account/api',
                       'fields': [('key', 'consumer:subfinder'),
                                  ('secret', 'consumer:subfinder')]},
    # --- consumidores diretos (recon / LLM / HackerOne) ---
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
