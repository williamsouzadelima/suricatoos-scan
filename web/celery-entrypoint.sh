#!/bin/bash

# ---------------------------------------------------------------------------
# Estado local do supervisor.
#
# Fica na CAMADA GRAVAVEL do container, de proposito, e NAO num volume nomeado:
#   * `docker restart` (o que o `restart: always` faz quando um worker morre)
#     PRESERVA a camada -> o marcador `provisioned` sobrevive -> o restart e
#     rapido e, sobretudo, NAO refaz o `collectstatic --clear` que apaga os
#     estaticos servidos pelo nginx (ver o gate mais abaixo);
#   * `docker compose up -d` (recriar, tipicamente apos rebuild da imagem)
#     DESCARTA a camada -> o provisionamento completo roda de novo, que e o
#     comportamento correto quando a imagem mudou.
# Um volume nomeado daria persistencia demais: apos um rebuild o marcador diria
# "provisionado" para uma imagem que nunca foi provisionada.
# ---------------------------------------------------------------------------
SURICATOOS_STATE_DIR=${SURICATOOS_STATE_DIR:-/var/lib/suricatoos}
CRASHLOOP_MARKER="$SURICATOOS_STATE_DIR/crashloop"
WORKER_PIDS_FILE=${WORKER_PIDS_FILE:-/tmp/suricatoos-workers.pids}
mkdir -p "$SURICATOOS_STATE_DIR" 2>/dev/null

# /tmp tambem sobrevive ao `docker restart`. Sem apagar aqui, durante os minutos
# de preambulo o healthcheck leria os pids do boot ANTERIOR e um PID reciclado
# (apt/git/wget/python do proprio preambulo) devolveria `healthy` sem worker no ar.
rm -f "$WORKER_PIDS_FILE"

if [ -s "$SURICATOOS_STATE_DIR/last-worker-death" ]; then
    echo "[celery-supervisor] boot apos morte de worker: $(cat "$SURICATOOS_STATE_DIR/last-worker-death")"
fi

# Freio + visibilidade de crashloop. Roda ANTES do preambulo caro para que um
# container em crashloop nao martele a rede nem inunde o log. Nao mascara nada: o
# container sobe do mesmo jeito, so que marcado `unhealthy` e com backoff.
#
# Validacao por `case` (e nao `$(( ))` direto): `$(( ))` AVALIA o conteudo da
# variavel como expressao aritmetica, entao um valor como 'a[$(cmd)]' EXECUTA cmd.
# Mesma convencao que este arquivo ja usa em SHARED/COORDINATOR/DEEP_PORT_CONCURRENCY.
case "${WORKER_CRASHLOOP_WINDOW:-}" in
    ''|*[!0-9]*) CRASHLOOP_WINDOW=3600 ;;
    *)           CRASHLOOP_WINDOW=$WORKER_CRASHLOOP_WINDOW ;;
esac
case "${WORKER_CRASHLOOP_THRESHOLD:-}" in
    ''|*[!0-9]*) CRASHLOOP_THRESHOLD=5 ;;
    *)           CRASHLOOP_THRESHOLD=$WORKER_CRASHLOOP_THRESHOLD ;;
esac
case "${WORKER_SHUTDOWN_GRACE:-}" in
    ''|*[!0-9]*) WORKER_SHUTDOWN_GRACE=30 ;;
esac
# Clamp: o `stop_grace_period` do compose e 60s. Um grace maior faria o docker
# mandar SIGKILL no MEIO do shutdown quente, produzindo exatamente a parada
# abrupta que o trap existe para evitar.
[ "$WORKER_SHUTDOWN_GRACE" -gt 45 ] && WORKER_SHUTDOWN_GRACE=45

_boot_log="$SURICATOOS_STATE_DIR/celery-boots"
_now=$(date +%s)
echo "$_now" >> "$_boot_log" 2>/dev/null
if awk -v cutoff=$((_now - CRASHLOOP_WINDOW)) \
       '$1 ~ /^[0-9]+$/ && $1 >= cutoff' "$_boot_log" > "$_boot_log.tmp" 2>/dev/null; then
    mv "$_boot_log.tmp" "$_boot_log" 2>/dev/null
fi
_boots=$(wc -l < "$_boot_log" 2>/dev/null || echo 1)
if [ "${_boots:-1}" -ge "$CRASHLOOP_THRESHOLD" ]; then
    case "${WORKER_CRASHLOOP_BACKOFF_MAX:-}" in
        ''|*[!0-9]*) _backoff_max=300 ;;
        *)           _backoff_max=$WORKER_CRASHLOOP_BACKOFF_MAX ;;
    esac
    _backoff=$((30 * _boots))
    [ "$_backoff" -gt "$_backoff_max" ] && _backoff=$_backoff_max
    echo "[celery-supervisor] CRASHLOOP: ${_boots} inicializacoes em ${CRASHLOOP_WINDOW}s." \
         "Container unhealthy ate $((_now + CRASHLOOP_WINDOW)); backoff ${_backoff}s." >&2
    # O marcador guarda o INSTANTE DE EXPIRACAO, nao um arquivo vazio. Um marcador
    # sem expiracao so seria removido no BOOT SEGUINTE — e um container que se
    # recuperou nunca mais faz boot, logo ficaria `unhealthy` para sempre com os 5
    # workers vivos, invertendo o unico sinal novo que esta mudanca cria.
    echo $((_now + CRASHLOOP_WINDOW)) > "$CRASHLOOP_MARKER"
    sleep "$_backoff"
else
    rm -f "$CRASHLOOP_MARKER"
fi

# apply existing migrations
python3 manage.py migrate

# make migrations for specific apps
apps=(
    "targetApp"
    "scanEngine"
    "startScan"
    "dashboard"
    "recon_note"
)

create_migrations() {
    local app=$1
    echo "Creating migrations for $app..."
    python3 manage.py makemigrations $app
    echo "Finished creating migrations for $app"
    echo "----------------------------------------"
}

echo "Starting migration creation process..."

for app in "${apps[@]}"
do
    create_migrations $app
done

echo "Migration creation process completed."

# apply migrations again
echo "Applying migrations..."
python3 manage.py migrate
echo "Migration process completed."


# ATENCAO: esta e a UNICA linha do repo que popula `static_volume`, e esse volume e
# servido pelo nginx (config/nginx/suricatoos.conf:45-46) para a producao VIVA.
# O `--clear` APAGA os estaticos antes de recoletar. Isso era inerte enquanto o
# container do celery nunca reiniciava — que era justamente o bug. Agora que a morte
# de um worker derruba e recria o container por projeto, um `--clear` a cada restart
# faria score.suricatoos.com servir 404 em todo CSS/JS durante a janela de coleta.
# Destrutivo so no provisionamento inicial; nos restarts a coleta e idempotente.
if [ ! -f "$SURICATOOS_STATE_DIR/provisioned" ]; then
    python3 manage.py collectstatic --no-input --clear
else
    python3 manage.py collectstatic --no-input
fi

# Load default engines, keywords, and external tools
python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

# install firefox https://askubuntu.com/a/1404401
echo '
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001

Package: firefox
Pin: version 1:1snap1-0ubuntu2
Pin-Priority: -1
' | tee /etc/apt/preferences.d/mozilla-firefox
# Gateado pelo mesmo motivo do collectstatic: com o restart virando a resposta
# rotineira a morte de worker, um `apt update && apt install` por restart e minutos
# de MTTR e uma dependencia de rede no caminho critico da recuperacao.
if [ ! -f "$SURICATOOS_STATE_DIR/provisioned" ]; then
    apt update
    apt install firefox -y
fi

# Temporary fix for whatportis bug - See https://github.com/williamsouzadelima/suricatoos-scan/issues/984
sed -i 's/purge()/truncate()/g' /usr/local/lib/python3.10/dist-packages/whatportis/cli.py

# update whatportis
yes | whatportis --update

# clone dirsearch default wordlist
if [ ! -d "/usr/src/wordlist" ]
then
  echo "Making Wordlist directory"
  mkdir /usr/src/wordlist
fi

if [ ! -f "/usr/src/wordlist/" ]
then
  echo "Downloading Default Directory Bruteforce Wordlist"
  wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt
fi

# check if default wordlist for amass exists
if [ ! -f /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt ];
then
  echo "Downloading Deepmagic top 50000 Wordlist"
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt
fi


# install gf patterns
if [ ! -d "/root/Gf-Patterns" ];
then
  echo "Installing GF Patterns"
  mkdir ~/.gf
  cp -r $GOPATH/src/github.com/tomnomnom/gf/examples/*.json ~/.gf
  git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
  mv ~/Gf-Patterns/*.json ~/.gf
fi

# store scan_results
if [ ! -d "/usr/src/scan_results" ]
then
  mkdir /usr/src/scan_results
fi

# test tools, required for configuration
naabu && subfinder && amass
nuclei

if [ ! -d "/root/nuclei-templates/geeknik_nuclei_templates" ];
then
  echo "Installing Geeknik Nuclei templates"
  git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/geeknik_nuclei_templates
else
  # `nuclei_templates` e volume nomeado, entao o diretorio SEMPRE existe e este ramo
  # roda em todo boot: `rm -rf` + `git clone` incondicionais. Aceitavel quando o
  # container subia uma vez por mes; inaceitavel agora que restart e rotina.
  # Refresca no maximo 1x/dia.
  if [ ! -f "$SURICATOOS_STATE_DIR/geeknik-refreshed" ] || \
     [ -n "$(find "$SURICATOOS_STATE_DIR/geeknik-refreshed" -mtime +1 2>/dev/null)" ]; then
    echo "Removing old Geeknik Nuclei templates and updating new one"
    rm -rf ~/nuclei-templates/geeknik_nuclei_templates
    git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/geeknik_nuclei_templates \
      && touch "$SURICATOOS_STATE_DIR/geeknik-refreshed"
  else
    echo "Geeknik Nuclei templates atualizados ha menos de 24h; pulando o re-clone."
  fi
fi

if [ ! -f ~/nuclei-templates/ssrf_nagli.yaml ];
then
  echo "Downloading ssrf_nagli for Nuclei"
  wget https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O ~/nuclei-templates/ssrf_nagli.yaml
fi


# httpx seems to have issue, use alias instead!!!
echo 'alias httpx="/go/bin/httpx"' >> ~/.bashrc

# TEMPORARY FIX, httpcore is causing issues with celery, removing it as temp fix
#python3 -m pip uninstall -y httpcore


loglevel='info'
if [ "$DEBUG" == "1" ]; then
    loglevel='debug'
fi

echo "Starting Celery Workers..."

commands=""

# Main scan worker
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/Suricatoos/\" -- celery -A Suricatoos.tasks worker --loglevel=$loglevel --optimization=fair --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &"$'\n'
else
    commands+="celery -A Suricatoos.tasks worker --loglevel=$loglevel --optimization=fair --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &"$'\n'
fi

# API shared task worker
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/api/\" -- celery -A api.shared_api_tasks worker --pool=gevent --optimization=fair --concurrency=10 --loglevel=$loglevel -Q api_queue -n api_worker &"$'\n'
else
    commands+="celery -A api.shared_api_tasks worker --pool=gevent --concurrency=10 --optimization=fair --loglevel=$loglevel -Q api_queue -n api_worker &"$'\n'
fi

# Todas as filas leves/IO-bound sao servidas por UM unico worker gevent.
# Antes havia 1 processo por fila (21 processos), e cada worker Celery carrega
# o Django inteiro (~140MB RSS). Numa VM de 3.8GB isso esgotava a RAM no boot e
# causava swap thrashing -> load explodia e a maquina travava. Greenlets gevent
# sao baratos, entao um unico processo serve todas essas filas tranquilamente.
queues=(
    "initiate_scan_queue"
    "subscan_queue"
    "report_queue"
    "send_notif_queue"
    "send_task_notif_queue"
    "send_file_to_discord_queue"
    "send_hackerone_report_queue"
    "parse_nmap_results_queue"
    "nmap_queue"
    "geo_localize_queue"
    "query_whois_queue"
    "remove_duplicate_endpoints_queue"
    "run_command_queue"
    "query_reverse_whois_queue"
    "query_ip_history_queue"
    "llm_queue"
    "dorking_queue"
    "osint_discovery_queue"
    "h8mail_queue"
    "theHarvester_queue"
    "spiderfoot_queue"
    "send_scan_notif_queue"
    "hang_monitor_queue"
)
all_queues=$(IFS=,; echo "${queues[*]}")
# Concorrencia do worker gevent compartilhado. Greenlets sao baratos (o custo de
# RAM e o unico import do Django, NAO por-greenlet), entao da pra subir bastante
# em hosts maiores. Validado como inteiro porque entra no comando montado via
# eval logo abaixo; valor invalido/vazio cai no default seguro 50.
case "${SHARED_CONCURRENCY:-}" in
    ''|*[!0-9]*) shared_concurrency=50 ;;
    *)           shared_concurrency=$SHARED_CONCURRENCY ;;
esac

if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/Suricatoos/\" -- celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$shared_concurrency --loglevel=$loglevel -Q $all_queues -n shared_worker &"$'\n'
else
    commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$shared_concurrency --loglevel=$loglevel -Q $all_queues -n shared_worker &"$'\n'
fi

# Coordinator worker (gevent): serves coordinator_queue, where the fan-out
# orchestrators (vulnerability_scan, nuclei_scan) block on their group/chord
# barrier. On a PREFORK worker a blocked orchestrator holds a scarce process slot
# and can deadlock its own children (the multi-tenant scan-#28 hang). On gevent a
# blocked task is just a parked greenlet, so a high concurrency is essentially free
# and the orchestrators can never starve the heavy children running on the
# memory-bounded main_scan_queue. Keep this a SEPARATE worker from the shared IO
# worker so parked orchestrators never consume the IO worker's concurrency slots.
case "${COORDINATOR_CONCURRENCY:-}" in
    ''|*[!0-9]*) coordinator_concurrency=30 ;;
    *)           coordinator_concurrency=$COORDINATOR_CONCURRENCY ;;
esac
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/Suricatoos/\" -- celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$coordinator_concurrency --loglevel=$loglevel -Q coordinator_queue -n coordinator_worker &"$'\n'
else
    commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$coordinator_concurrency --loglevel=$loglevel -Q coordinator_queue -n coordinator_worker &"$'\n'
fi

# Deep-tier UDP port scan worker (gevent): serves deep_port_queue, where the
# udp_port_scan task runs `nmap -sU` over all 65535 UDP ports -- a sweep that
# legitimately lasts DAYS. Isolated on its own low-concurrency worker so a
# multi-day scan NEVER consumes a main_scan_queue slot (the deadlock prevention
# of PR #33) nor the shared IO worker's greenlets. gevent keeps a parked
# days-long task cheap; the effective time bound is the run_command WATCHDOG
# (~14d ceiling) inside udp_port_scan -- the global 2h CELERY hard limit is not
# enforced on a gevent pool, which is exactly what lets the long sweep run.
# Low concurrency bounds simultaneous deep sweeps (resource isolation).
case "${DEEP_PORT_CONCURRENCY:-}" in
    ''|*[!0-9]*) deep_port_concurrency=4 ;;
    *)           deep_port_concurrency=$DEEP_PORT_CONCURRENCY ;;
esac
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/Suricatoos/\" -- celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$deep_port_concurrency --loglevel=$loglevel -Q deep_port_queue -n deep_port_worker &"$'\n'
else
    commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$deep_port_concurrency --loglevel=$loglevel -Q deep_port_queue -n deep_port_worker &"$'\n'
fi
# NOTA: aqui existia `commands="${commands%&}"`, removido por ser comprovadamente
# INERTE — cada worker e concatenado como "... &"$'\n', logo o ultimo caractere da
# string e uma quebra de linha e o padrao `%&` nunca casa. Mantido fora porque a
# intencao que ele sugeria (rodar o ultimo worker em foreground) deixaria justamente
# esse worker fora da supervisao abaixo.

# Marca o provisionamento como concluido: os blocos caros e destrutivos acima
# (collectstatic --clear, apt install, git clone) sao pulados nos proximos restarts
# DESTE container. Um `up -d` recria o container, descarta a camada gravavel e
# reprovisiona do zero.
touch "$SURICATOOS_STATE_DIR/provisioned" 2>/dev/null

eval "$commands"

# ===========================================================================
# SUPERVISAO DOS WORKERS
#
# O PORQUE (incidente de 2026-07-22): o `wait` sem argumentos que existia aqui so
# retorna quando TODOS os filhos terminam. Os workers sao jobs de background do
# mesmo bash, entao a morte de UM deles nao fazia o bash pai sair: o container
# seguia `Up`, o `restart: always` nunca disparava e a fila daquele worker ficava
# sem consumidor indefinidamente. Em 22/07 00:04 o httpx chegou a 1.9GB e estourou
# o `mem_limit: 2g`; o OOM killer do cgroup levou junto o processo do
# coordinator_worker. Resultado: `coordinator_queue` orfa por 3 dias, todo scan
# travando apos o `Http crawl` e o hang_monitor auto-abortando os scans 66, 67 e 68.
# A liveness do container estava DESACOPLADA da liveness dos workers.
#
# A ESCOLHA (derrubar tudo, em vez de respawnar so o morto): os 5 workers dividem
# UM cgroup e UM `mem_limit`. O OOM killer escolhe a vitima por oom_score dentro
# desse cgroup — em 22/07 o coordinator morreu por ser vizinho do httpx, nao por
# culpa propria. Respawnar so ele o devolveria ao mesmo cgroup pressionado, para
# morrer de novo. Enquanto o isolamento por worker for ficticio, a unidade de falha
# e o container e a unidade de recuperacao tem que ser o container tambem.
# A remocao estrutural e dividir o servico `celery` em N servicos no compose, um
# por worker, cada um com seu proprio mem_limit — fora do escopo desta mudanca.
# ===========================================================================
declare -A WORKER_LABEL=()

stop_workers() {
    local pid waited alive
    for pid in "${!WORKER_LABEL[@]}"; do
        kill -TERM "$pid" 2>/dev/null
    done
    waited=0
    while [ "$waited" -lt "$WORKER_SHUTDOWN_GRACE" ]; do
        alive=0
        for pid in "${!WORKER_LABEL[@]}"; do
            kill -0 "$pid" 2>/dev/null && alive=1
        done
        [ "$alive" -eq 0 ] && return 0
        sleep 1
        waited=$((waited + 1))
    done
    for pid in "${!WORKER_LABEL[@]}"; do
        kill -KILL "$pid" 2>/dev/null
    done
    return 0
}

graceful_stop() {
    trap '' TERM INT HUP
    echo "[celery-supervisor] parada intencional; encerrando os workers."
    stop_workers
    exit 0
}
# Sem este trap, um `docker stop` mata o bash e deixa os 5 celery orfaos ate o
# SIGKILL do docker — desconexao abrupta do redis, que e o gatilho do
# "Restoring N unacknowledged message(s)" visto no log.
trap graceful_stop TERM INT HUP

: > "$WORKER_PIDS_FILE"
# O tmp vive no state dir, que sobrevive ao restart: zerar antes, senao o manifesto
# acumula as filas de todos os boots anteriores.
rm -f "$SURICATOOS_STATE_DIR/served-queues.tmp"
for _pid in $(jobs -p); do
    # Rotulo derivado do proprio cmdline: `-n <nome>` quando existe (api_worker,
    # shared_worker, coordinator_worker, deep_port_worker) e, para o main scan
    # worker (que nao usa -n), a fila do `-Q`.
    _cmd=$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null)
    _label=$(printf '%s' "$_cmd" | grep -oE '\-n [A-Za-z0-9_.@-]+' | head -1 | cut -d' ' -f2)
    [ -z "$_label" ] && _label=$(printf '%s' "$_cmd" | grep -oE '\-Q [A-Za-z0-9_]+' | head -1 | cut -d' ' -f2)
    [ -z "$_label" ] && _label="worker_$_pid"
    WORKER_LABEL[$_pid]="$_label"
    echo "$_pid $_label" >> "$WORKER_PIDS_FILE"
    # Manifesto das filas que ESTE boot se comprometeu a servir. O healthcheck compara
    # este conjunto (o esperado) com o que os processos vivos cobrem, e assim consegue
    # NOMEAR a fila que ficou orfa — o diagnostico que faltou por 3 dias em 22/07,
    # quando a unica pista era "scan abortado pelo hang monitor".
    # A classe precisa de [A-Za-z0-9]: ha filas com digito (h8mail_queue) e com
    # maiuscula (theHarvester_queue). Com [a-z_,] o match parava na primeira delas e
    # o manifesto saia TRUNCADO (23 de 27), perdendo justamente hang_monitor_queue.
    printf '%s' "$_cmd" | grep -oE '\-Q [A-Za-z0-9_,]+' | head -1 | cut -d' ' -f2 | tr ',' '\n' \
        >> "$SURICATOOS_STATE_DIR/served-queues.tmp"
done
sort -u "$SURICATOOS_STATE_DIR/served-queues.tmp" 2>/dev/null > "$SURICATOOS_STATE_DIR/served-queues"
rm -f "$SURICATOOS_STATE_DIR/served-queues.tmp"
echo "[celery-supervisor] ${#WORKER_LABEL[@]} workers no ar: ${WORKER_LABEL[*]}"
echo "[celery-supervisor] $(wc -l < "$SURICATOOS_STATE_DIR/served-queues" 2>/dev/null) filas com consumidor."

while :; do
    wait -n
    status=$?
    dead_pid=""
    for pid in "${!WORKER_LABEL[@]}"; do
        kill -0 "$pid" 2>/dev/null || { dead_pid="$pid"; break; }
    done
    [ -n "$dead_pid" ] && break     # achamos o worker morto -> fatal
    [ "$status" -eq 127 ] && break  # nao ha mais filho algum -> fatal
    continue                        # sinal, ou filho nao-worker -> volta a esperar
done

if [ -n "$dead_pid" ]; then
    label="${WORKER_LABEL[$dead_pid]}"
else
    label="desconhecido"
fi
_msg="$(date -u +%Y-%m-%dT%H:%M:%SZ) worker '$label' (pid ${dead_pid:-?}) morreu com status $status"
echo "[celery-supervisor] FATAL: $_msg" >&2
echo "$_msg" > "$SURICATOOS_STATE_DIR/last-worker-death" 2>/dev/null
# Prova de OOM do cgroup no proprio log, junto do obito: e o dado que faltou em
# 22/07 e que so foi recuperado no journal do host, 3 dias depois.
{
    for _ev in /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory/memory.oom_control; do
        [ -r "$_ev" ] && { echo "[celery-supervisor] $_ev:"; cat "$_ev"; }
    done
} >&2
echo "[celery-supervisor] encerrando os demais workers para que 'restart: always' recrie os 5." >&2
stop_workers
exit 1