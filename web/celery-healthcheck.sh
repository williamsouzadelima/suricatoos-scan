#!/bin/sh
# Healthcheck do container `celery`.
#
# O incidente que motiva este script (2026-07-22): o OOM killer do cgroup matou o
# processo do coordinator_worker dentro de um container que continuou `Up` e verde.
# `coordinator_queue` ficou sem consumidor por 3 dias e TODO scan travava logo apos o
# `Http crawl`, ate o hang_monitor auto-abortar. Nao havia um unico sinal externo.
#
# Cobre tres coisas, em ordem crescente de custo:
#   (1) o container nao esta em crashloop (marcador auto-expiravel);
#   (2) todos os workers que este boot subiu continuam vivos;
#   (3) toda fila do manifesto deste boot continua coberta por um processo vivo
#       — e, quando nao esta, o log do healthcheck NOMEIA a fila orfa.
#
# Deliberadamente NAO importa Django: um boot custa ~140MB RSS e, rodando a cada
# intervalo dentro de um cgroup de 2g, alimentaria o proprio OOM que se quer detectar.
# Tudo aqui e leitura de /proc e de dois arquivos de estado.
#
# POSIX sh: o `test` do compose roda sob `dash`, nao bash.

STATE_DIR=${SURICATOOS_STATE_DIR:-/var/lib/suricatoos}
MARKER="$STATE_DIR/crashloop"
PIDS=${WORKER_PIDS_FILE:-/tmp/suricatoos-workers.pids}
SERVED="$STATE_DIR/served-queues"

# --- (1) crashloop, com marcador auto-expiravel -----------------------------
if [ -e "$MARKER" ]; then
    exp=$(cat "$MARKER" 2>/dev/null)
    case "$exp" in
        ''|*[!0-9]*)
            echo "crashloop: marcador invalido" >&2
            exit 1 ;;                                  # conteudo corrompido -> fail-closed
        *)
            if [ "$(date +%s)" -lt "$exp" ]; then
                echo "crashloop: em backoff ate $exp" >&2
                exit 1
            fi ;;
    esac
fi

# --- (2) workers vivos ------------------------------------------------------
# Ausente/vazio = ainda no preambulo (o entrypoint apaga o arquivo no inicio do boot)
# ou supervisor caido. Ambos sao "nao pronto". O `start_period` do compose e quem
# impede que o preambulo legitimo conte como falha.
if [ ! -s "$PIDS" ]; then
    echo "workers: manifesto de pids ausente ou vazio (boot em andamento?)" >&2
    exit 1
fi

alive_cmdlines=""
rc=0
while read -r pid label; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
        alive_cmdlines="$alive_cmdlines $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
    else
        echo "worker MORTO: $label (pid $pid)" >&2
        rc=1
    fi
done < "$PIDS"
[ "$rc" -eq 0 ] || exit 1

# --- (3) cobertura das filas ------------------------------------------------
# Redundante com (2) enquanto 1 worker == N filas fixas, mas e o que transforma
# "um processo sumiu" em "a fila X esta sem consumidor", que e a frase que o
# operador precisa ler. Tambem pega o caso de um worker respawnado com -Q menor.
if [ -s "$SERVED" ]; then
    while read -r q; do
        [ -n "$q" ] || continue
        case " $alive_cmdlines " in
            *"$q"*) ;;
            *)
                echo "FILA SEM CONSUMIDOR: $q" >&2
                rc=1 ;;
        esac
    done < "$SERVED"
fi

exit "$rc"
