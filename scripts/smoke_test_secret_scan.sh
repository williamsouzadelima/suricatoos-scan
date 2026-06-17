#!/usr/bin/env bash
#
# Smoke test for the secret-scanning feature (gitleaks / ggshield / SpiderFoot).
#
# Brings up the stack, runs the secret-scan unit tests inside the worker
# container (where Django and all dependencies are installed), verifies the
# fixtures loaded, and prints a manual end-to-end checklist.
#
# Usage (from the repo root):
#     ./scripts/smoke_test_secret_scan.sh            # build + up + test
#     SKIP_BUILD=1 ./scripts/smoke_test_secret_scan.sh   # skip the image build
#
# Requires: Docker + Docker Compose v2, and a populated .env (see .env.example).
set -euo pipefail

cd "$(dirname "$0")/.."

DC="docker compose"
SVC=celery   # the worker container has Django + all deps + the code mounted

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

if [ ! -f .env ]; then
  echo "ERROR: .env not found. Copy .env.example to .env and fill it in." >&2
  exit 1
fi

if [ "${SKIP_BUILD:-0}" = "1" ]; then
  say "Starting the stack (no rebuild)..."
  $DC up -d db redis "$SVC" web
else
  say "Building and starting the stack (first build is slow — installs tools)..."
  $DC up -d --build db redis "$SVC" web
fi

say "Waiting for PostgreSQL..."
for _ in $(seq 1 90); do
  if $DC exec -T db pg_isready >/dev/null 2>&1; then echo "    db is ready"; break; fi
  sleep 2
done

say "Applying migrations (incl. startScan 0003_leakedsecret + dashboard 0003_gitguardianapikey)..."
$DC exec -T "$SVC" python3 manage.py migrate --noinput

say "Verifying fixtures loaded (new tools + secret_scan in default engines)..."
$DC exec -T "$SVC" python3 manage.py shell -c "
from scanEngine.models import InstalledExternalTool, EngineType
tools = set(InstalledExternalTool.objects.values_list('name', flat=True))
for t in ['gitleaks', 'ggshield', 'spiderfoot']:
    assert t in tools, f'tool {t} not registered'
print('  tools registered:', sorted(t for t in tools if t in {'gitleaks','ggshield','spiderfoot'}))
fs = EngineType.objects.filter(engine_name='Full Scan').first()
assert fs and 'secret_scan' in fs.tasks, 'secret_scan missing from Full Scan engine'
print('  Full Scan engine tasks include secret_scan:', 'secret_scan' in fs.tasks)
print('  OK')
"

say "Running the secret-scan unit tests (13 tests)..."
$DC exec -T "$SVC" python3 manage.py test tests.test_secret_scan -v 2

say "Automated checks passed. Manual end-to-end check (UI):"
cat <<'EOF'
  1. Scan Engines -> Add: confirm the YAML editor now shows a `secret_scan:` block
     and `enable_spiderfoot` under `osint`.
  2. (Optional, for ggshield) Settings -> API: set the GitGuardian key.
  3. Run a scan with "Full Scan" or "Suricatoos Recommended" against a target that
     exposes a fake secret (e.g. an AWS-looking key in a reachable .js/.env).
  4. On the scan detail page: the "Secrets Discovered" card shows a count and the
     "Secrets" tab lists findings — with the secret value MASKED.
  5. API: GET /api/listLeakedSecrets/?scan_history=<scan_id>&format=json
EOF

say "Smoke test complete."
