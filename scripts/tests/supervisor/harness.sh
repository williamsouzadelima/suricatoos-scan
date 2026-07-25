#!/bin/bash
# Harness: reproduz o preambulo minimo que o bloco real de supervisao espera e
# depois executa o bloco REAL, extraido do celery-entrypoint.sh sem edicao.
SURICATOOS_STATE_DIR=/var/lib/suricatoos
WORKER_PIDS_FILE=/tmp/suricatoos-workers.pids
WORKER_SHUTDOWN_GRACE=3
mkdir -p "$SURICATOOS_STATE_DIR"
rm -f "$WORKER_PIDS_FILE"

# Os 5 workers reais, com os MESMOS argumentos que o entrypoint monta (o rotulo e
# derivado de /proc/pid/cmdline, entao os argumentos precisam ser fieis).
commands=""
commands+="celery -A Suricatoos.tasks worker --loglevel=info --optimization=fair --autoscale=4,1 -Q main_scan_queue &"$'\n'
commands+="celery -A api.shared_api_tasks worker --pool=gevent --concurrency=10 --optimization=fair --loglevel=info -Q api_queue -n api_worker &"$'\n'
commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=10 --loglevel=info -Q initiate_scan_queue,subscan_queue,report_queue,hang_monitor_queue -n shared_worker &"$'\n'
commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=30 --loglevel=info -Q coordinator_queue -n coordinator_worker &"$'\n'
commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=4 --loglevel=info -Q deep_port_queue -n deep_port_worker &"$'\n'

source /test/supervision.inc
