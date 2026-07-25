#!/bin/bash
# Bateria E2E do supervisor + healthcheck, rodando em ubuntu:22.04 (base real do
# web/Dockerfile). Cada teste imprime PASS/FAIL e o motivo.
set -u
PASS=0; FAIL=0
ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }
orphans(){ n=0; for c in /proc/[0-9]*/cmdline; do tr '\0' ' ' < "$c" 2>/dev/null | grep -q -- "-A Suricatoos.tasks\|-A api.shared_api_tasks" && n=$((n+1)); done; echo $n; }
# espera bounded: nunca deixa o teste pendurar
waitfor(){ local pid=$1 secs=${2:-20} i=0; while kill -0 "$pid" 2>/dev/null; do i=$((i+1)); [ "$i" -gt $((secs*4)) ] && { echo "TIMEOUT esperando pid $pid" >&2; kill -9 "$pid" 2>/dev/null; return 99; }; sleep 0.25; done; wait "$pid"; }
ko(){ echo "FAIL: $1 -- $2"; FAIL=$((FAIL+1)); }

# stub `celery`: dorme; o que importa e o /proc/pid/cmdline
mkdir -p /usr/local/bin
# NAO usar `exec`: exec substitui a imagem do processo e APAGA o argv, enquanto o
# celery real (script python) preserva os argumentos em /proc/pid/cmdline — que e de
# onde o supervisor deriva o rotulo. Confirmado no ps da producao.
printf '#!/bin/sh\ntrap "exit 143" TERM\nwhile :; do sleep 0.2; done\n' > /usr/local/bin/celery
chmod +x /usr/local/bin/celery

echo "=== bash version: $(bash --version | head -1)"
echo

# ---------------------------------------------------------------- T1: morte de worker
echo "--- T1: kill -9 no coordinator_worker deve derrubar o container ---"
rm -rf /var/lib/suricatoos; mkdir -p /var/lib/suricatoos
bash /test/harness.sh > /tmp/t1.log 2>&1 &
H=$!
for i in $(seq 1 40); do [ -s /tmp/suricatoos-workers.pids ] && break; sleep 0.25; done
NW=$(wc -l < /tmp/suricatoos-workers.pids)
[ "$NW" = "5" ] && ok "5 workers registrados" || ko "registro de workers" "esperado 5, veio $NW"

echo "--- rotulos derivados de /proc/cmdline ---"; cat /tmp/suricatoos-workers.pids
for lbl in main_scan_queue api_worker shared_worker coordinator_worker deep_port_worker; do
  grep -qw "$lbl" /tmp/suricatoos-workers.pids && ok "rotulo '$lbl'" || ko "rotulo '$lbl'" "ausente"
done

NQ=$(wc -l < /var/lib/suricatoos/served-queues)
[ "$NQ" = "8" ] && ok "manifesto com 8 filas" || ko "manifesto de filas" "esperado 8, veio $NQ ($(tr '\n' ' ' < /var/lib/suricatoos/served-queues))"
grep -qx coordinator_queue /var/lib/suricatoos/served-queues && ok "coordinator_queue no manifesto" || ko "manifesto" "coordinator_queue ausente"

# healthcheck deve estar VERDE agora
sh /test/celery-healthcheck.sh 2>/tmp/hc1.err; RC=$?
[ "$RC" = "0" ] && ok "healthcheck verde com os 5 vivos" || ko "healthcheck verde" "rc=$RC $(cat /tmp/hc1.err)"

# mata o coordinator, como o OOM killer fez em 22/07
CP=$(grep -w coordinator_worker /tmp/suricatoos-workers.pids | cut -d' ' -f1)
kill -9 "$CP"

# healthcheck deve ficar VERMELHO e NOMEAR a fila orfa
sleep 0.5
sh /test/celery-healthcheck.sh 2>/tmp/hc2.err; RC=$?
[ "$RC" = "1" ] && ok "healthcheck vermelho apos a morte" || ko "healthcheck vermelho" "rc=$RC"
grep -q "worker MORTO: coordinator_worker" /tmp/hc2.err && ok "healthcheck nomeia o worker morto" || ko "diagnostico do healthcheck" "$(cat /tmp/hc2.err)"

# o supervisor deve derrubar o container
waitfor "$H" 25; EXIT=$?
[ "$EXIT" = "1" ] && ok "supervisor sai com 1 (dispara restart: always)" || ko "exit do supervisor" "esperado 1, veio $EXIT"
grep -q "FATAL: .*worker 'coordinator_worker'.*morreu com status 137" /tmp/t1.log \
  && ok "log FATAL nomeia o worker e o status" || ko "log FATAL" "$(grep FATAL /tmp/t1.log)"
grep -q "memory.events" /tmp/t1.log && ok "dump do memory.events do cgroup" || ko "dump de OOM" "ausente"
[ -s /var/lib/suricatoos/last-worker-death ] && ok "obito persistido p/ o boot seguinte" || ko "last-worker-death" "vazio"

ORPH=$(orphans)
[ "${ORPH:-0}" = "0" ] && ok "zero workers orfaos apos o fatal" || ko "orfaos" "$ORPH sobraram"
echo

# ---------------------------------------------------------------- T2: parada intencional
echo "--- T2: SIGTERM (docker stop) deve sair 0 e nao deixar orfaos ---"
rm -f /tmp/suricatoos-workers.pids
bash /test/harness.sh > /tmp/t2.log 2>&1 &
H=$!
for i in $(seq 1 40); do [ -s /tmp/suricatoos-workers.pids ] && break; sleep 0.25; done
kill -TERM "$H"
waitfor "$H" 25; EXIT=$?
[ "$EXIT" = "0" ] && ok "parada intencional sai com 0" || ko "exit do trap" "esperado 0, veio $EXIT"
sleep 0.5
ORPH=$(orphans)
[ "${ORPH:-0}" = "0" ] && ok "zero orfaos no docker stop (hoje deixa 5)" || ko "orfaos no stop" "$ORPH sobraram"
echo

# ---------------------------------------------------------------- T3: crashloop
echo "--- T3: marcador de crashloop e AUTO-EXPIRAVEL ---"
rm -f /tmp/suricatoos-workers.pids
printf '1 fake\n' > /tmp/suricatoos-workers.pids   # pid 1 existe sempre
mkdir -p /var/lib/suricatoos
# Isola a checagem (1): sem isto sobra o manifesto de filas do T1, e o pid falso nao
# cobre nenhuma delas -> a checagem (3) reprova por um motivo diferente do testado.
rm -f /var/lib/suricatoos/served-queues
echo $(( $(date +%s) + 600 )) > /var/lib/suricatoos/crashloop
sh /test/celery-healthcheck.sh 2>/dev/null; RC=$?
[ "$RC" = "1" ] && ok "marcador dentro da janela -> unhealthy" || ko "crashloop ativo" "rc=$RC"
echo $(( $(date +%s) - 1 )) > /var/lib/suricatoos/crashloop
sh /test/celery-healthcheck.sh 2>/dev/null; RC=$?
[ "$RC" = "0" ] && ok "marcador EXPIRADO -> volta a healthy sozinho" || ko "auto-expiracao" "rc=$RC (ficaria unhealthy p/ sempre)"
echo "lixo" > /var/lib/suricatoos/crashloop
sh /test/celery-healthcheck.sh 2>/dev/null; RC=$?
[ "$RC" = "1" ] && ok "marcador corrompido -> fail-closed" || ko "fail-closed" "rc=$RC"
rm -f /var/lib/suricatoos/crashloop
echo

# --------------------------------------------------- T3b: nomear a fila orfa
echo "--- T3b: healthcheck NOMEIA a fila sem consumidor ---"
rm -f /var/lib/suricatoos/crashloop
printf '1 fake\n' > /tmp/suricatoos-workers.pids
printf 'coordinator_queue\nmain_scan_queue\n' > /var/lib/suricatoos/served-queues
sh /test/celery-healthcheck.sh 2>/tmp/hc3.err; RC=$?
[ "$RC" = "1" ] && ok "fila sem consumidor -> unhealthy" || ko "cobertura de fila" "rc=$RC"
grep -q "FILA SEM CONSUMIDOR: coordinator_queue" /tmp/hc3.err \
  && ok "nomeia coordinator_queue (o diagnostico que faltou em 22/07)" \
  || ko "nome da fila orfa" "$(cat /tmp/hc3.err)"
rm -f /var/lib/suricatoos/served-queues
echo

# ---------------------------------------------------------------- T4: injecao nos envs
echo "--- T4: env hostil nao executa comando ---"
rm -rf /var/lib/suricatoos /tmp/pwn; mkdir -p /var/lib/suricatoos
WORKER_CRASHLOOP_WINDOW='a[$(touch /tmp/pwn)]' bash -c '
  case "${WORKER_CRASHLOOP_WINDOW:-}" in
    ""|*[!0-9]*) CRASHLOOP_WINDOW=3600 ;;
    *)           CRASHLOOP_WINDOW=$WORKER_CRASHLOOP_WINDOW ;;
  esac
  : $((0 + CRASHLOOP_WINDOW))' 2>/dev/null
[ ! -e /tmp/pwn ] && ok "validacao por case bloqueia injecao aritmetica" || ko "injecao" "/tmp/pwn foi criado"
echo

# ---------------------------------------------------------------- T5: pids do boot anterior
echo "--- T5: healthcheck nao aceita manifesto vazio/ausente ---"
rm -f /tmp/suricatoos-workers.pids
sh /test/celery-healthcheck.sh 2>/dev/null; RC=$?
[ "$RC" = "1" ] && ok "sem manifesto -> unhealthy (start_period cobre o boot)" || ko "manifesto ausente" "rc=$RC"
echo

echo "==================== PASS=$PASS FAIL=$FAIL ===================="
[ "$FAIL" = "0" ]
