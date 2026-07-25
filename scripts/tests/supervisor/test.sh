#!/usr/bin/env bash
# Bateria de regressao do supervisor de workers do container `celery`.
#
# Por que ela existe: em 2026-07-22 o OOM killer do cgroup matou o processo do
# coordinator_worker dentro de um container que continuou `Up`. O `wait` sem
# argumentos do entrypoint so retorna quando TODOS os filhos morrem, entao o
# `restart: always` nunca disparou. `coordinator_queue` ficou 3 dias sem consumidor
# e todo scan travava apos o `Http crawl` ate o hang_monitor auto-abortar
# (scans 66, 67 e 68). Estes testes travam esse comportamento.
#
# Uso: scripts/tests/supervisor/test.sh
# Requer docker. Roda em ubuntu:22.04, a base real de web/Dockerfile (bash 5.1).
#
# O bloco de supervisao NAO e copiado: e EXTRAIDO de web/celery-entrypoint.sh a cada
# execucao, a partir do `eval "$commands"`. Assim o teste nunca valida uma copia
# desatualizada — se alguem mexer no entrypoint, e o codigo novo que roda aqui.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
ENTRYPOINT="$REPO/web/celery-entrypoint.sh"
HEALTHCHECK="$REPO/web/celery-healthcheck.sh"
IMAGE=${SUPERVISOR_TEST_IMAGE:-ubuntu:22.04}

[ -f "$ENTRYPOINT" ]  || { echo "nao achei $ENTRYPOINT" >&2; exit 2; }
[ -f "$HEALTHCHECK" ] || { echo "nao achei $HEALTHCHECK" >&2; exit 2; }

bash -n "$ENTRYPOINT"
sh   -n "$HEALTHCHECK"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

LINE=$(grep -n '^eval "\$commands"' "$ENTRYPOINT" | head -1 | cut -d: -f1)
[ -n "$LINE" ] || { echo 'nao achei o `eval "$commands"` no entrypoint' >&2; exit 2; }
sed -n "${LINE},\$p" "$ENTRYPOINT" > "$WORK/supervision.inc"

cp "$HEALTHCHECK" "$HERE/harness.sh" "$HERE/run.sh" "$WORK/"

echo "Bloco de supervisao extraido de web/celery-entrypoint.sh (a partir da linha $LINE)."
exec docker run --rm --network none -v "$WORK":/test:ro "$IMAGE" bash /test/run.sh
