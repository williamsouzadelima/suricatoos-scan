#!/usr/bin/python
import logging
import os
import re

# Capacity-proportional scaling for the orchestration DURATION timers below.
# scale_timer multiplies by the machine capacity factor (>= 1.0); on the baseline
# 2-CPU box the factor is 1.0, so every value is byte-identical to its base.
# capacity.py imports only os -> no circular import.
from Suricatoos.capacity import scale_timer

###############################################################################
# TOOLS DEFINITIONS
###############################################################################
logger = logging.getLogger('django')

###############################################################################
# TOOLS DEFINITIONS
###############################################################################

EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+')

###############################################################################
# YAML CONFIG DEFINITIONS
###############################################################################

ALL = 'all'
AMASS_WORDLIST = 'amass_wordlist'
AMASS_TIMEOUT = 'amass_timeout'  # minutes; caps amass enum so dead resolvers can't hang the scan
AUTO_CALIBRATION = 'auto_calibration'
CUSTOM_HEADERS = 'custom_headers'
CUSTOM_HEADER = 'custom_header'
FETCH_GPT_REPORT = 'fetch_gpt_report'
RUN_NUCLEI = 'run_nuclei'
RUN_CRLFUZZ = 'run_crlfuzz'
RUN_DALFOX = 'run_dalfox'
RUN_S3SCANNER = 'run_s3scanner'
DIR_FILE_FUZZ = 'dir_file_fuzz'
FOLLOW_REDIRECT = 'follow_redirect'
EXTENSIONS = 'extensions'
EXCLUDED_SUBDOMAINS = 'exclude_subdomains'
EXCLUDE_EXTENSIONS = 'exclude_extensions'
EXCLUDE_TEXT = 'exclude_text'
FETCH_URL = 'fetch_url'
GF_PATTERNS = 'gf_patterns'
HTTP_CRAWL = 'http_crawl'
IGNORE_FILE_EXTENSION = 'ignore_file_extensions'
INTENSITY = 'intensity'
MATCH_HTTP_STATUS = 'match_http_status'
MAX_TIME = 'max_time'
# dir-fuzz runs ffuf once per alive host sequentially, so a fixed per-host max_time
# blows the 90min Celery soft limit when there are many hosts (the recurring
# dir_file_fuzz timeout). Budget the TOTAL: per-host time = budget // host_count,
# floored so few-host scans still go deep. Stays well under CELERY_TASK_SOFT_TIME_LIMIT.
DIR_FUZZ_TIME_BUDGET = scale_timer(4200)   # seconds total for the whole dir-fuzz step (~70min)
DIR_FUZZ_MIN_PER_HOST = scale_timer(30)    # never fuzz a host for less than this
NAABU_EXCLUDE_PORTS = 'exclude_ports'
NAABU_EXCLUDE_SUBDOMAINS = 'exclude_subdomains'
ENABLE_NMAP = 'enable_nmap'
NMAP_COMMAND = 'nmap_cmd'
NMAP_SCRIPT = 'nmap_script'
NMAP_SCRIPT_ARGS = 'nmap_script_args'
NAABU_PASSIVE = 'passive'
NAABU_RATE = 'rate'
NUCLEI_CUSTOM_TEMPLATE = 'custom_templates'
NUCLEI_TAGS = 'tags'
NUCLEI_TEMPLATE = 'templates'
NUCLEI_SEVERITY = 'severities'
NUCLEI_EXCLUDE_TEMPLATE = 'exclude_templates'
NUCLEI_EXCLUDE_TAGS = 'exclude_tags'
NUCLEI_MAX_HOST_ERROR = 'max_host_error'
# nuclei's default -mhe is 30: it gives up on a host after 30 errors, so a slow /
# rate-limited / WAF'd target that times out transiently gets marked "unresponsive
# permanently" and is SKIPPED — missing real findings. Raise it to stay patient.
DEFAULT_NUCLEI_MAX_HOST_ERROR = 100
NUCLEI_CONCURRENCY = 'concurrency'
OSINT = 'osint'
OSINT_DOCUMENTS_LIMIT = 'documents_limit'
OSINT_DISCOVER = 'discover'
OSINT_DORK = 'dorks'
OSINT_CUSTOM_DORK = 'custom_dorks'
PORT = 'port'
PORTS = 'ports'
RECURSIVE = 'recursive'
RECURSIVE_LEVEL = 'recursive_level'
PORT_SCAN = 'port_scan'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
SCREENSHOT = 'screenshot'
SUBDOMAIN_DISCOVERY = 'subdomain_discovery'
STOP_ON_ERROR = 'stop_on_error'
ENABLE_HTTP_CRAWL = 'enable_http_crawl'
THREADS = 'threads'
TIMEOUT = 'timeout'
USE_AMASS_CONFIG = 'use_amass_config'
USE_NAABU_CONFIG = 'use_naabu_config'
USE_NUCLEI_CONFIG = 'use_nuclei_config'
USE_SUBFINDER_CONFIG = 'use_subfinder_config'
USES_TOOLS = 'uses_tools'
VULNERABILITY_SCAN = 'vulnerability_scan'
WAF_DETECTION = 'waf_detection'
WORDLIST = 'wordlist_name'
REMOVE_DUPLICATE_ENDPOINTS = 'remove_duplicate_endpoints'
DUPLICATE_REMOVAL_FIELDS = 'duplicate_fields'
DALFOX = 'dalfox'
S3SCANNER = 's3scanner'
NUCLEI = 'nuclei'
NMAP = 'nmap'
CRLFUZZ = 'crlfuzz'
WAF_EVASION = 'waf_evasion'
BLIND_XSS_SERVER = 'blind_xss_server'
USER_AGENT = 'user_agent'
DELAY = 'delay'
PROVIDERS = 'providers'

# Suricatoos — secret scanning (secret_scan engine)
SECRET_SCAN = 'secret_scan'
RUN_GITLEAKS = 'run_gitleaks'
RUN_GGSHIELD = 'run_ggshield'
GITLEAKS = 'gitleaks'
GGSHIELD = 'ggshield'
GITLEAKS_MODE = 'gitleaks_mode'
SCAN_PATH = 'scan_path'
SECRET_SCAN_TARGETS = 'targets'

###############################################################################
# Scan DEFAULTS
###############################################################################

LIVE_SCAN = 1
SCHEDULED_SCAN = 0

DEFAULT_SCAN_INTENSITY = 'normal'

###############################################################################
# Tools DEFAULTS
###############################################################################

# Suricatoos — secret scan defaults
DEFAULT_RUN_GITLEAKS = True
DEFAULT_RUN_GGSHIELD = False
# Secrets are reported at critical severity (4 in NUCLEI_REVERSE_SEVERITY_MAP).
SECRET_DEFAULT_SEVERITY = 4

# Suricatoos — vulnerability validation (anti false-positive) defaults
# Config lives under vulnerability_scan.validate_vulnerabilities in the engine YAML.
VALIDATE_VULNERABILITIES = 'validate_vulnerabilities'
DEFAULT_VALIDATE_VULNERABILITIES = True
# Re-test timeout per finding (seconds) handed to the native tool re-run.
VALIDATION_TIMEOUT = 'validation_timeout'
DEFAULT_VALIDATION_TIMEOUT = 10
# SSRF guard: loopback/link-local/metadata/unspecified/multicast are ALWAYS blocked.
# Private (RFC1918/ULA) ranges are legitimate targets for internal pentests, so they
# are allowed by default; set this true in the engine YAML to also block them.
VALIDATION_ALLOW_PRIVATE = 'validation_allow_private'
DEFAULT_VALIDATION_ALLOW_PRIVATE = True

# Wall-clock ceiling (seconds) for ANY external tool spawned via run_command /
# stream_command. A watchdog kills the whole process group on expiry so a tool that
# never returns (amass-active brute, theHarvester) can't wedge its Celery
# task forever (the diagnosed scan-#19 hang). Generous global backstop (raise it if huge
# nuclei/ffuf scopes legitimately exceed it); per-tool callers pass a tighter value. 0
# disables. Overridable via the COMMAND_EXEC_TIMEOUT env. When the env is set the
# operator means an absolute value, so it is used VERBATIM (un-scaled); otherwise
# the 5100 default is scaled by the machine capacity factor (5100 < soft 5400 < hard 7200
# ensures the graceful watchdog path fires before Celery SIGKILL). scale_timer keeps 0.
try:
    _raw = os.environ.get('COMMAND_EXEC_TIMEOUT')
    if _raw not in (None, ''):
        DEFAULT_COMMAND_EXEC_TIMEOUT = int(_raw)  # seconds; operator-supplied, verbatim
    else:
        DEFAULT_COMMAND_EXEC_TIMEOUT = scale_timer(5100)  # seconds; ~85min; watchdog < soft 5400s < hard 7200s
except (TypeError, ValueError):
    DEFAULT_COMMAND_EXEC_TIMEOUT = scale_timer(5100)
# Tighter cap for theHarvester, hang-prone e rodando no pool gevent, onde o hard limit
# SIGALRM do Celery NAO se aplica — o watchdog do run_command e a unica protecao ali.
THEHARVESTER_EXEC_TIMEOUT = scale_timer(600)

# Orchestration barrier backstop. Several scan tasks fan out a group/chord of child
# tasks and then block until the children finish (`while not job.ready()` / `.get()`).
# An UNBOUNDED block lets one stuck child wedge the parent forever, holding its worker
# slot — under the prefork main_scan_queue (MAX_CONCURRENCY) that starves the children
# and deadlocks the whole queue for every user (the diagnosed scan-#28 hang). Every
# barrier is now bounded by this deadline: on expiry the parent revokes the outstanding
# children and degrades gracefully (partial results are persisted incrementally). 0
# disables the bound. Overridable via ORCHESTRATION_BARRIER_TIMEOUT env. NOTE the
# live docker-compose.yml sets ORCHESTRATION_BARRIER_TIMEOUT=7200 explicitly, so
# under the "verbatim if env set" rule the barrier stays 7200 (un-scaled) on every
# box; remove that compose line to let it scale with capacity. scale_timer keeps 0.
try:
    _raw = os.environ.get('ORCHESTRATION_BARRIER_TIMEOUT')
    if _raw not in (None, ''):
        DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT = int(_raw)  # seconds; operator-supplied, verbatim
    else:
        DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT = scale_timer(7200)  # seconds; 2h default, capacity-scaled
except (TypeError, ValueError):
    DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT = scale_timer(7200)

# Backstop hang monitor: a scan whose newest ScanActivity is older than this (and is
# still flagged RUNNING) is considered wedged and auto-aborted by the periodic
# hang_monitor beat task. Default = the Celery hard limit (7200s) + a 30min margin so
# a legitimately long single tool can't trip it. Overridable via HANG_MONITOR_STALE_AFTER
# (verbatim if set; else the 9000 default is capacity-scaled).
try:
    _raw = os.environ.get('HANG_MONITOR_STALE_AFTER')
    if _raw not in (None, ''):
        HANG_MONITOR_STALE_AFTER = int(_raw)  # seconds; operator-supplied, verbatim
    else:
        HANG_MONITOR_STALE_AFTER = scale_timer(9000)  # seconds; 2.5h default, capacity-scaled
except (TypeError, ValueError):
    HANG_MONITOR_STALE_AFTER = scale_timer(9000)

# Prazo do "hold": quando a parada e atribuivel a INFRA (fila do pipeline sem consumidor,
# ou backlog, ou o probe do cluster indisponivel), o hang_monitor NAO aborta de imediato —
# segura o scan para que ele retome sozinho quando o worker voltar. Mas segurar nao pode
# virar "nunca abortar": passado este prazo, aborta citando a causa.
#
# Isto tambem fecha um buraco pre-existente: o `except: continue` do guard de liveness
# fazia um inspect quebrado permanentemente significar que o monitor NUNCA abortava nada.
try:
    _raw = os.environ.get('HANG_MONITOR_INFRA_ABORT_AFTER')
    if _raw not in (None, ''):
        HANG_MONITOR_INFRA_ABORT_AFTER = int(_raw)
    else:
        HANG_MONITOR_INFRA_ABORT_AFTER = 24 * 3600
except (TypeError, ValueError):
    HANG_MONITOR_INFRA_ABORT_AFTER = 24 * 3600
# Segurar por MENOS tempo que o prazo normal seria incoerente (abortaria mais cedo
# justamente no caso em que o scan e recuperavel).
HANG_MONITOR_INFRA_ABORT_AFTER = max(HANG_MONITOR_INFRA_ABORT_AFTER, HANG_MONITOR_STALE_AFTER)

# Timeout do broadcast de controle do celery. Curto: o hang_monitor roda no shared_worker
# e nao pode ficar pendurado num cluster degradado.
try:
    _raw = os.environ.get('HANG_MONITOR_INSPECT_TIMEOUT')
    HANG_MONITOR_INSPECT_TIMEOUT = float(_raw) if _raw not in (None, '') else 5.0
except (TypeError, ValueError):
    HANG_MONITOR_INSPECT_TIMEOUT = 5.0

# Prefixo do error_message gravado durante um hold. Existe para poder ser LIMPO depois:
# o hold e transitorio, e um scan que retoma e depois falha por outro motivo nao pode
# exibir "bloqueado por infra" como causa — seria reintroduzir a atribuicao errada de
# causa que esta mudanca existe para eliminar.
HANG_MONITOR_HOLD_PREFIX = 'HELD BY HANG MONITOR'

# amass
AMASS_DEFAULT_WORDLIST_PATH = (
    'wordlist/default_wordlist/deepmagic.com-prefixes-top50000.txt'
)

# dorks
DORKS_DEFAULT_NAMES = [
    'stackoverflow',
    '3rdparty',
    'social_media',
    'project_management',
    'code_sharing',
    'config_files',
    'jenkins',
    'cloud_buckets',
    'php_error',
    'exposed_documents',
    'struts_rce',
    'db_files',
    'traefik',
    'git_exposed'
]

# ffuf
FFUF_DEFAULT_WORDLIST_PATH = '/usr/src/wordlist/dicc.txt'
FFUF_DEFAULT_MATCH_HTTP_STATUS = [200, 204]
FFUF_DEFAULT_RECURSIVE_LEVEL = 2
FFUF_DEFAULT_FOLLOW_REDIRECT = False

# http_crawl: tamanho do lote de alvos por invocacao do httpx.
#
# O httpx guarda estado POR ALVO (corpo da resposta para titulo/tech, cadeia de redirect,
# CNAME, ASN, headers) e a invocacao era UNICA para a lista inteira. Com ~950 alvos ele
# chegou a 1.96GB de RSS e estourou o `mem_limit: 2g` do container do celery — foi o
# gatilho do OOM de 2026-07-22 (que levou junto o coordinator_worker e causou 3 dias de
# scans abortados) e de novo em 2026-07-26 (que dessa vez matou so o httpx). Quem morre
# junto e sorteio do OOM killer, entao o consumo TEM que ser limitado na origem.
#
# Lotear e seguro porque o httpx NAO correlaciona alvos entre si: N lotes de M alvos
# produzem exatamente as mesmas linhas que uma invocacao de N*M. O custo e o startup do
# processo por lote (desprezivel perto de uma sondagem HTTP).
# 0 desliga o loteamento (uma invocacao so, comportamento anterior).
try:
    _raw = os.environ.get('HTTP_CRAWL_BATCH_SIZE')
    HTTP_CRAWL_BATCH_SIZE = int(_raw) if _raw not in (None, '') else 150
except (TypeError, ValueError):
    HTTP_CRAWL_BATCH_SIZE = 150

# ---------------------------------------------------------------------------
# TAXONOMIA DO ACHADO — separar reconhecimento de vulnerabilidade.
#
# Medido em producao (26/07/2026, 12.096 achados): 97,3% eram `info`, e o achado de
# MAIOR volume era "RDAP WHOIS" (3.923) — uma consulta WHOIS. O 3o era "WAF Detection"
# (1.532), que e uma coisa BOA. Isso e inventario e reconhecimento gravado na tabela de
# vulnerabilidades: enquanto for, toda contagem, dashboard, relatorio e rating mente, e
# os 2 achados criticos reais ficam soterrados sob 11.766 linhas de fato de ambiente.
#
# A classificacao NAO precisa de heuristica nova: o proprio nuclei ja marca isso nas
# tags do template. Verificado contra a base real — a regra abaixo separa 8.048 de
# inventario e 3.448 de higiene sem capturar UM UNICO achado de severidade media ou
# maior, e preserva os 10 alta/critica e os 247 media+ do lado de vulnerabilidade.
FINDING_CLASS_VULNERABILITY = 'vulnerability'
FINDING_CLASS_HYGIENE = 'hygiene'
FINDING_CLASS_INVENTORY = 'inventory'

# Fato sobre o ambiente: "existe um WAF", "a tecnologia e X", "o registro CAA e Y".
# Nao ha o que remediar — e inventario, e pertence ao ativo, nao ao backlog de risco.
FINDING_TAGS_INVENTORY = frozenset({
    'discovery', 'tech', 'osint', 'enum', 'passive', 'whois', 'rdap',
})
# Boa pratica ausente: cabecalho de seguranca faltando, SRI ausente. E real e vale
# reportar, mas nao e exploravel por si — misturado com CVE, achata a prioridade.
FINDING_TAGS_HYGIENE = frozenset({
    'misconfig', 'compliance', 'headers',
})
# Piso de seguranca: a classificacao por tag NUNCA rebaixa um achado de severidade
# media ou maior. As tags do nuclei sao inconsistentes (o proprio "RDAP WHOIS" carrega
# a tag `vuln`), entao um template severo que um dia venha marcado `discovery` seria
# escondido em silencio. Hoje o piso nao descarta nada — ele protege o amanha.
FINDING_CLASS_SEVERITY_FLOOR = 2   # 2 = medium na escala do reNgine

# ---------------------------------------------------------------------------
# Curadoria por template — a camada que a regra por tag nao alcanca.
#
# A regra por tag resolve o volume (8.145 de inventario, 3.488 de higiene), mas deixa
# um residuo que ela nao consegue julgar: templates SEM tag util, ou com tag generica
# demais. Medido em producao em 27/07/2026: 375 achados em 36 familias continuavam em
# `vulnerability` so por falta de sinal — "Form Detection" (84) e "Allowed Options
# Method" (75) na mesma lista que "Credentials Disclosure".
#
# A chave e o `template_id` do nuclei, NAO o nome de exibicao: o id e o identificador
# canonico do template e sobrevive a mudanca de titulo upstream. Verificado que esta
# populado em 100% dos 375.
#
# Tres conjuntos em vez de um dict para que o agrupamento fique legivel E para que
# duplicata entre classes seja detectavel — num dict literal ela seria silenciosamente
# sobrescrita. `test_curadoria_conjuntos_disjuntos` trava isso.
#
# MANUTENCAO: template novo e ruidoso nao quebra nada, so continua em `vulnerability`
# ate alguem cura-lo aqui. O erro seguro e o de omissao.

# Fato sobre o ambiente. Nao ha o que remediar: "existe um formulario nesta pagina",
# "o certificado cobre estes nomes", "o tenant Azure e este".
FINDING_TEMPLATES_INVENTORY = frozenset({
    'form-detection',            # 84 — existe um <form> na pagina
    'ssl-dns-names',             # 33 — os SANs do certificado
    'addeventlistener-detect',   # 16 — a pagina registra listener de DOM
    'wildcard-tls',              # 16 — cert curinga (ver NOTA 1)
    'azure-domain-tenant',       # 15 — tenant ID do Azure, fato de OSINT
    'robots-txt',                #  7 — o arquivo existe
    'snmpv3-detect',             #  7 — fingerprint de versao
    'wordpress-readme-file',     #  2 — fingerprint de versao do WP
    'wp-license-file',           #  1 — idem
    'old-copyright',             #  1 — data de copyright antiga; puramente informativo
})

# Boa pratica ausente ou exposicao menor: real, o cliente quer ver, mas nao e
# exploravel por si so. Vai para a secao propria do relatorio, fora da nota de risco.
FINDING_TEMPLATES_HYGIENE = frozenset({
    'options-method',              # 75 — metodo OPTIONS habilitado
    'deprecated-tls',              # 33 — TLS obsoleto negociavel
    'iis-shortname-detect',        # 28 — enumeracao 8.3 do IIS (ver NOTA 2)
    'http-trace',                  #  7 — TRACE habilitado / XST (ver NOTA 3)
    'expired-ssl',                 #  5 — certificado expirado
    'self-signed-ssl',             #  5 — certificado autoassinado
    'mismatched-ssl-certificate',  #  5 — CN/SAN nao casa com o host
    'vscode-launch',               #  2 — launch.json servido
    'wordpress-xmlrpc-listmethods',#  2 — xmlrpc expondo lista de metodos
    'makefile-exposure',           #  2 — Makefile servido
    'editor-exposure',             #  2 — .editorconfig servido
    'htaccess-config',             #  2 — .htaccess servido (ver NOTA 4)
    'exposed-gitignore',           #  2 — .gitignore servido
    'untrusted-root-certificate',  #  1 — raiz nao confiavel
    'wordpress-directory-listing', #  1 — listagem de diretorio
    'drupal-directory-listing',    #  1 — idem
    'wp-xmlrpc-pingback-detection',#  1 — pingback (amplificacao/SSRF)
    'wp-user-enum',                #  1 — enumeracao de usuario via REST
})

# PINOS. Estes ja sao `vulnerability` hoje — listar aqui nao muda contagem nenhuma.
# O valor e travar: se um dia o template vier tagueado `misconfig`, a regra por tag
# rebaixaria um vazamento de credencial para higiene EM SILENCIO. O pino impede.
FINDING_TEMPLATES_VULNERABILITY = frozenset({
    'generic-tokens',            # 6 — token/segredo exposto
    'git-logs-exposure',         # 3 — .git servido = codigo-fonte
    'jwt-token',                 # 2 — JWT exposto
    'host-header-injection',     # 2 — exploravel
    'credentials-disclosure',    # 2 — credencial exposta
    'xff-403-bypass',            # 1 — bypass de autorizacao
    'request-based-interaction', # 1 — interacao OOB (classe SSRF)
    'phpinfo-files',             # 1 — phpinfo vaza ambiente, caminhos, extensoes
})

# NOTAS — os julgamentos discutiveis, registrados para poderem ser revistos:
#  1. wildcard-tls como inventario: certificado curinga amplia o raio de um
#     comprometimento, mas e escolha de arquitetura deliberada e comum, nao pratica
#     ausente. Defensavel move-lo para higiene.
#  2. iis-shortname-detect como higiene: e divulgacao de informacao que HABILITA
#     enumeracao de arquivos; parte do mercado reporta como low/medium. O nuclei manda
#     como info. Se o cliente for IIS-pesado, reconsiderar.
#  3. http-trace como higiene: XST esta majoritariamente mitigado por navegador moderno.
#  4. htaccess-config como higiene: se o conteudo for realmente servido, pode revelar
#     regra de rewrite e config de auth — ai seria vulnerability. Depende do corpo.

FINDING_TEMPLATE_CLASS = {
    **{t: FINDING_CLASS_INVENTORY for t in FINDING_TEMPLATES_INVENTORY},
    **{t: FINDING_CLASS_HYGIENE for t in FINDING_TEMPLATES_HYGIENE},
    **{t: FINDING_CLASS_VULNERABILITY for t in FINDING_TEMPLATES_VULNERABILITY},
}

# naabu
NAABU_DEFAULT_PORTS = ['top-100']

# ---------------------------------------------------------------------------
# Deep-tier UDP sweep (udp_port_scan, na deep_port_queue).
#
# Contexto (incidente de 2026-07): a deep_port_queue acumulou 344 tarefas de scans ja
# encerrados e os 4 slots do worker ficaram ocupados pela MESMA task id, reentregue
# apos perdas de conexao com o redis — cada copia rodando `nmap -sU -p 1-65535` por
# DIAS contra host de cliente, semanas depois do scan ter terminado.
#
# A faixa e varrida em BLOCOS. E tentador usar `--host-timeout` sobre a faixa cheia,
# mas o nmap NAO grava resultado parcial: um host que estoura o host-timeout produz
# `<host timedout="true">` SEM elemento `<ports>`, e parse_nmap_xml_open_ports devolve
# []. Como um -sU de faixa cheia contra alvo que faz rate-limit de ICMP
# port-unreachable (a razao de durar dias) estoura qualquer prazo, o tier deep viraria
# "rapido e sempre vazio" — indistinguivel de "nenhuma porta UDP" na UI. Fatiando, cada
# bloco e um nmap que TERMINA, tem seu proprio -oX e e salvo assim que acaba: o que os
# blocos anteriores confirmaram ja esta no banco.
def _deep_udp_int(name, default):
    try:
        _raw = os.environ.get(name)
        return int(_raw) if _raw not in (None, '') else default
    except (TypeError, ValueError):
        return default


DEEP_UDP_CHUNK_PORTS = _deep_udp_int('DEEP_UDP_CHUNK_PORTS', 8192)      # 8 blocos cobrem 1-65535
DEEP_UDP_CHUNK_TIMEOUT = _deep_udp_int('DEEP_UDP_CHUNK_TIMEOUT', 2700)  # 45min/bloco -> ~6h/host
# Piso da subdivisao adaptativa. Um bloco que estoura o orcamento NAO faz o host ser
# abandonado: ele e DIVIDIDO AO MEIO e cada metade e re-tentada, ate caber no orcamento ou
# atingir este piso.
#
# Sem isso, o fatiamento com bloco FIXO era uma REGRESSAO contra a exata classe de alvo que
# motivou a feature: um host que faz rate-limit de ICMP dest-unreachable (o motivo de um
# `-sU -p-` durar ~18h) responde a ~1 porta/s, entao 8192 portas precisam de ~8200s e nunca
# caberiam nos 2700s. Todo bloco morria por SIGKILL, o nmap nao grava parcial (XML sem
# <host>), e o host inteiro voltava vazio depois de 3 strikes — "rapido e sempre vazio",
# indistinguivel de "nenhuma porta UDP" na UI. Antes dos blocos, esse mesmo alvo rodava um
# unico nmap com watchdog de dias e concluia com as portas reais.
DEEP_UDP_MIN_CHUNK_PORTS = _deep_udp_int('DEEP_UDP_MIN_CHUNK_PORTS', 256)
# Quantas faixas JA NO PISO podem estourar antes de desistir do host. So conta no piso: um
# bloco largo que estourou vira subdivisao, nao strike. 0 = nunca desiste.
DEEP_UDP_MAX_TIMED_OUT_CHUNKS = _deep_udp_int('DEEP_UDP_MAX_TIMED_OUT_CHUNKS', 3)
# Teto de relogio por host. A subdivisao multiplica o numero de execucoes, entao o limite
# precisa ser EXPLICITO e nao emergir do numero de blocos. 18h e a ordem de grandeza
# documentada de um `-sU -p-` completo contra alvo que limita ICMP. 0 = sem teto.
DEEP_UDP_HOST_BUDGET = _deep_udp_int('DEEP_UDP_HOST_BUDGET', 18 * 3600)
# ATENCAO: 0 mantem o default do nmap (10) DE PROPOSITO. udp_port_scan descarta tudo que
# nao seja exatamente 'open' (open|filtered e jogado fora), entao baixar retries reduz
# DIRETAMENTE achados verdadeiros. So mexa depois de medir contra uma porta UDP conhecida.
DEEP_UDP_MAX_RETRIES = _deep_udp_int('DEEP_UDP_MAX_RETRIES', 0)
DEEP_UDP_MAX_HOSTS = _deep_udp_int('DEEP_UDP_MAX_HOSTS', 25)            # 0 = sem teto

# Orcamento de drenagem da fila, derivado — e nao um 48h fixo, que viraria armadilha no
# proprio knob oferecido: subir DEEP_UDP_MAX_HOSTS faria o guard comer a propria cauda
# em silencio. 4 = DEEP_PORT_CONCURRENCY (concorrencia do deep_port_worker).
_DEEP_UDP_CHUNKS = -(-65535 // max(1, DEEP_UDP_CHUNK_PORTS))
_DEEP_UDP_DRAIN = (
    -(-max(1, DEEP_UDP_MAX_HOSTS) // 4) * (_DEEP_UDP_CHUNKS * DEEP_UDP_CHUNK_TIMEOUT))
# Idade a partir da qual a varredura e considerada irrelevante (o scan que a pediu ja
# acabou ha muito). Relevancia NAO e "scan ainda RUNNING": o fan-out e fire-and-forget
# (`group(...).apply_async()` nunca e aguardado) e report() fecha o scan enquanto as
# varreduras seguem na fila — exigir RUNNING descartaria em silencio tudo a partir do
# 5o host.
DEEP_UDP_STALE_AFTER = max(48 * 3600, 2 * _DEEP_UDP_DRAIN)
# TTL da mensagem no broker: alem disso o celery a descarta sozinho, sem nem entregar.
DEEP_UDP_MESSAGE_EXPIRES = DEEP_UDP_STALE_AFTER + 24 * 3600

# nuclei
NUCLEI_DEFAULT_TEMPLATES_PATH = '/root/nuclei-templates'
# Experimental third-party template collections excluded by default: they fire
# weak-matcher HIGH/CRITICAL false positives (substring / status==200 matchers).
# Engines can override via the 'exclude_templates' key (empty list = exclude none).
NUCLEI_DEFAULT_EXCLUDE_TEMPLATES = ['/root/nuclei-templates/geeknik_nuclei_templates']
NUCLEI_SEVERITY_MAP = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': -1,
}
NUCLEI_REVERSE_SEVERITY_MAP = {v: k for k, v in NUCLEI_SEVERITY_MAP.items()}
NUCLEI_DEFAULT_SEVERITIES = list(NUCLEI_SEVERITY_MAP.keys())

# s3scanner
S3SCANNER_DEFAULT_PROVIDERS = ['gcp', 'aws', 'digitalocean', 'dreamhost', 'linode']

# dalfox
DALFOX_SEVERITY_MAP = {
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'unknown': -1,
}

# osint
OSINT_DEFAULT_LOOKUPS = ['emails', 'metainfo', 'employees']
OSINT_DEFAULT_DORKS = [
    'stackoverflow',
    '3rdparty',
    'social_media',
    'project_management',
    'code_sharing',
    'config_files',
    'jenkins',
    'wordpress_files',
    'cloud_buckets',
    'php_error',
    'exposed_documents',
    'struts_rce',
    'db_files',
    'traefik',
    'git_exposed',
]
OSINT_DEFAULT_CONFIG = {
    'discover': OSINT_DEFAULT_LOOKUPS,
    'dork': OSINT_DEFAULT_DORKS
}

# subdomain scan
SUBDOMAIN_SCAN_DEFAULT_TOOLS = ['subfinder', 'ctfr', 'sublist3r', 'tlsx']

# endpoints scan
ENDPOINT_SCAN_DEFAULT_TOOLS = ['gospider']
ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS = ['content_length', 'page_title']


###############################################################################
# Logger DEFINITIONS
###############################################################################

CONFIG_FILE_NOT_FOUND = 'Config file not found'

###############################################################################
# Preferences DEFINITIONS
###############################################################################

SMALL = '100px'
MEDIM = '200px'
LARGE = '400px'
XLARGE = '500px'

# Discord message colors
DISCORD_INFO_COLOR = '0xfbbc00' # yellow
DISCORD_WARNING_COLOR = '0xf75b00' # orange
DISCORD_ERROR_COLOR = '0xf70000'
DISCORD_SUCCESS_COLOR = '0x00ff78'
DISCORD_SEVERITY_COLORS = {
    'info': DISCORD_INFO_COLOR,
    'warning': DISCORD_WARNING_COLOR,
    'error': DISCORD_ERROR_COLOR,
    'aborted': DISCORD_ERROR_COLOR,
    'success': DISCORD_SUCCESS_COLOR
}

STATUS_TO_SEVERITIES = {
    'RUNNING': 'info',
    'SUCCESS': 'success',
    'FAILED': 'error',
    'ABORTED': 'error'
}

###############################################################################
# Interesting Subdomain DEFINITIONS
###############################################################################
MATCHED_SUBDOMAIN = 'Subdomain'
MATCHED_PAGE_TITLE = 'Page Title'

###############################################################################
# Celery Task Status CODES
###############################################################################
INITIATED_TASK = -1
FAILED_TASK = 0
RUNNING_TASK = 1
SUCCESS_TASK = 2
ABORTED_TASK = 3

CELERY_TASK_STATUS_MAP = {
    INITIATED_TASK: 'INITITATED',
    FAILED_TASK: 'FAILED',
    RUNNING_TASK: 'RUNNING',
    SUCCESS_TASK: 'SUCCESS',
    ABORTED_TASK: 'ABORTED'
}

CELERY_TASK_STATUSES = (
    (INITIATED_TASK, INITIATED_TASK),
    (FAILED_TASK, FAILED_TASK),
    (RUNNING_TASK, RUNNING_TASK),
    (SUCCESS_TASK, SUCCESS_TASK),
    (ABORTED_TASK, ABORTED_TASK)
)
DYNAMIC_ID = -1

###############################################################################
# Uncommon Ports
# Source: https://github.com/six2dez/reconftw/blob/main/reconftw.cfg
###############################################################################
UNCOMMON_WEB_PORTS = [
    81,
    300,
    591,
    593,
    832,
    981,
    1010,
    1311,
    1099,
    2082,
    2095,
    2096,
    2480,
    3000,
    3128,
    3333,
    4243,
    4567,
    4711,
    4712,
    4993,
    5000,
    5104,
    5108,
    5280,
    5281,
    5601,
    5800,
    6543,
    7000,
    7001,
    7396,
    7474,
    8000,
    8001,
    8008,
    8014,
    8042,
    8060,
    8069,
    8080,
    8081,
    8083,
    8088,
    8090,
    8091,
    8095,
    8118,
    8123,
    8172,
    8181,
    8222,
    8243,
    8280,
    8281,
    8333,
    8337,
    8443,
    8500,
    8834,
    8880,
    8888,
    8983,
    9000,
    9001,
    9043,
    9060,
    9080,
    9090,
    9091,
    9200,
    9443,
    9502,
    9800,
    9981,
    10000,
    10250,
    11371,
    12443,
    15672,
    16080,
    17778,
    18091,
    18092,
    20720,
    32000,
    55440,
    55672,
]

###############################################################################
# WHOIS DEFINITIONS
# IGNORE_WHOIS_RELATED_KEYWORD: To ignore and disable finding generic related domains
###############################################################################

IGNORE_WHOIS_RELATED_KEYWORD = [
    'Registration Private',
    'Domains By Proxy Llc',
    'Redacted For Privacy',
    'Digital Privacy Corporation',
    'Private Registrant',
    'Domain Administrator',
    'Administrator',
]


# Default FETCH URL params
DEFAULT_IGNORE_FILE_EXTENSIONS = [
    'png',
    'jpg',
    'jpeg',
    'gif',
    'mp4',
    'mpeg',
    'mp3',
]

DEFAULT_GF_PATTERNS = [
    'debug_logic',
    'idor',
    'interestingEXT',
    'interestingparams',
    'interestingsubs',
    'lfi',
    'rce',
    'redirect',
    'sqli',
    'ssrf',
    'ssti',
    'xss'
]


# Default Dir File Fuzz Params
DEFAULT_DIR_FILE_FUZZ_EXTENSIONS =  [
    '.html',
    '.php',
    '.git',
    '.yaml',
    '.conf',
    '.cnf',
    '.config',
    '.gz',
    '.env',
    '.log',
    '.db',
    '.mysql',
    '.bak',
    '.asp',
    '.aspx',
    '.txt',
    '.conf',
    '.sql',
    '.json',
    '.yml',
    '.pdf',
]

# Default Excluded Paths during Initate Scan
# Mostly static files and directories
DEFAULT_EXCLUDED_PATHS = [
    # Static assets (using regex patterns)
    '/static/.*',
    '/assets/.*',
    '/css/.*',
    '/js/.*',
    '/images/.*',
    '/img/.*',
    '/fonts/.*',

    # File types (using regex patterns)
    '.*\.ico',
]

# Roles and Permissions
PERM_MODIFY_SYSTEM_CONFIGURATIONS = 'modify_system_configurations'
PERM_MODIFY_SCAN_CONFIGURATIONS = 'modify_scan_configurations'
PERM_MODIFY_TARGETS = 'modify_targets' # projects and targets
PERM_MODIFY_SCAN_RESULTS = 'modify_scan_results'
PERM_MODIFY_WORDLISTS = 'modify_wordlists'
PERM_MODIFY_INTERESTING_LOOKUP = 'modify_interesting_lookup'
PERM_MODIFY_SCAN_REPORT = 'modify_scan_report'
PERM_INITATE_SCANS_SUBSCANS = 'initiate_scans_subscans'

# 404 page url
FOUR_OH_FOUR_URL = '/404/'


###############################################################################
# OLLAMA DEFINITIONS
###############################################################################
OLLAMA_INSTANCE = 'http://ollama:11434'

# --- LLM false-positive judge (confidence flagger; never auto-deletes) ---
JUDGE_ENABLED = 'judge_enabled'
JUDGE_MODEL = 'judge_model'
DEFAULT_JUDGE_MODEL = 'qwen2.5:1.5b'   # fits the 2g ollama cap; run post-scan only
JUDGE_SYSTEM_PROMPT = (
	"You triage nuclei findings for false positives. Judge the ACTUAL HTTP "
	"response/evidence, NOT the template's claims. The template's CVE id, name and "
	"severity are CLAIMS, not proof — a weak template attaches a scary CVE to a "
	"trivial match.\n"
	"LIKELY_FP when: the response is 401/403/404/redirect or an error/block page "
	"(the issue is NOT actually present); the matcher is weak (matches only a "
	"status code or a generic substring like 'publish'/'login' in the body); "
	"extracted_results is empty or trivial (e.g. ['200']); no exploit artifact is "
	"echoed back.\n"
	"REAL when: the response body actually contains the exploited artifact / "
	"injected payload / sensitive data, with a specific matcher and meaningful "
	"extracted_results.\n"
	"A CVE id ALONE is NOT enough to call it real. When unsure, say needs_review.\n"
	"Reply in ENGLISH with ONLY one JSON object, no prose:\n"
	'{"verdict":"real|likely_fp|needs_review","confidence":0.0-1.0,"reason":"<=160 chars"}'
)

DEFAULT_GPT_MODELS = [
    {
        'name': 'gpt-3',
        'model': 'gpt-3',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~175B',
        }
    },
    {
        'name': 'gpt-3.5-turbo',
        'model': 'gpt-3.5-turbo',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~7B',
        }
    },
    {
        'name': 'gpt-4',
        'model': 'gpt-4',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~1.7T',
        }
    },
    {
        'name': 'gpt-4-turbo',
        'model': 'gpt-4',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~1.7T',
        }
    }
]



# GPT Vulnerability Report Generator
VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE = """
You are an expert penetration tester who has just completed a comprehensive security assessment. Based on the provided vulnerability title, vulnerable URL, and vulnerability description, your task is to generate a detailed, technical penetration testing report in plain text format.
Your task is to generate a detailed, technical penetration testing report. This report should offer an in-depth analysis of the discovered vulnerabilities, adhering to industry best practices and standards.

The output should adhere to the following structure:

Description:
A comprehensive explanation of the vulnerability, including: Detailed technical analysis, Associated CVE IDs (if any), Related known vulnerabilities, Exploitation methods

Impact:
A thorough assessment of the vulnerability's potential impact on web applications, including: Data confidentiality breaches, System integrity compromises, Service availability disruptions, Potential for further exploitation

Remediation:
A prioritized list of specific, actionable steps to address the vulnerability, such as: Code modifications, Configuration changes, Security patch applications, Implementation of security controls

References:
Relevant, authoritative sources supporting your analysis, such as: Official CVE database entries, Vendor security advisories, Respected security research publications, Applicable industry standards or guidelines


Ensure that:
1. Each section (Description, Impact, Remediation, References) is separated by ONLY ONE blank line and no multiple new lines. The content must be immediately after the section title.
2. Do not make title as bold, italic or underline. It must be Title ending with a colon. Example: Description:
3. All URLs in the 'references' section begin with 'http://' or 'https://'.
4. Remediation steps should be specific and actionable and should not contain any ambiguous or general recommendations.
5. Refrain from including any personal opinions or subjective assessments in your report.
"""


ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT = """
    You are a highly skilled penetration tester who has recently completed a reconnaissance on a target.
    As a penetration tester, you've conducted a thorough reconnaissance on a specific subdomain.
    Based on the reconnaissance you will be given with a
        - Subdomain Name
        - Subdomain Page Title
        - Open Ports if any detected
        - HTTP Status
        - Technologies Detected
        - Content Type
        - Web Server
        - Page Content Length
    I'm seeking insights into potential technical web application attacks that could be executed on this subdomain, along with explanations for why these attacks are feasible given the discovered information.
    Please provide a detailed list of these attack types and their underlying technical rationales on every attacks you suggested.
    Also suggest if any CVE ID, known exploits, existing vulnerabilities, any news articles URL related to the information provided to you.
"""


# OSINT GooFuzz Path
GOFUZZ_EXEC_PATH = '/usr/src/github/goofuzz/GooFuzz'


# In App Notification Definitions
SYSTEM_LEVEL_NOTIFICATION = 'system'
PROJECT_LEVEL_NOTIFICATION = 'project'
NOTIFICATION_TYPES = (
    ('system', SYSTEM_LEVEL_NOTIFICATION),
    ('project', PROJECT_LEVEL_NOTIFICATION),
)
NOTIFICATION_STATUS_TYPES = (
    ('success', 'Success'),
    ('info', 'Informational'),
    ('warning', 'Warning'),
    ('error', 'Error'),
)

# Bountyhub Definitions
HACKERONE_ALLOWED_ASSET_TYPES = ["WILDCARD", "DOMAIN", "IP_ADDRESS", "URL"]