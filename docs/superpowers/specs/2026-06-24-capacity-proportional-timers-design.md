# Capacity-proportional orchestration timers — design

**Date:** 2026-06-24
**Branch:** `feat/capacity-proportional-timers` (off `main` @ bcd1bd5)
**Driver:** User directive — *"se a capacidade da máquina for maior, temos que ampliar os temporizadores proporcionalmente."* The orchestration timeouts are currently absolute values calibrated for the baseline box (2 vCPU / ~3.8 GB). On a larger deployment that takes on more concurrent / heavier scans, individual tools and orchestration barriers legitimately run longer (resource contention), so the time budgets must scale **up** with capacity to avoid premature kills.

## Principle

Introduce a single **capacity factor** `F` that scales every *duration* timer **uniformly**. Uniform scaling is the safety property: multiplying all timers by the same `F` preserves their relative ordering by construction:

```
watchdog (COMMAND_EXEC) ≤ CELERY soft ≤ CELERY hard ≤ HANG_MONITOR stale
DIR_FUZZ_TIME_BUDGET < CELERY soft
```

These orderings are what keep the system correct (a stuck subprocess is caught by its watchdog before Celery soft-kills the task; a task is hard-killed before the hang-monitor aborts the whole scan; dir-fuzz stays under the soft limit). Uniform `×F` keeps all of them true at any `F`.

## Factor computation (pure, testable)

New module `web/Suricatoos/capacity.py` (imports only `os` — zero Django/circular-import risk, so both `definitions.py` and `settings.py` can import it):

```python
import os

def _detect_cpus():
    try:
        return max(1, len(os.sched_getaffinity(0)))   # cgroup/cpuset-aware on Linux
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)

def compute_capacity_factor(detected_cpus, baseline_cpus, factor_max, explicit=None):
    """Pure. explicit (float|str|None) wins if parseable. Else cpus/baseline.
    Always clamped to [1.0, factor_max] — only ENLARGES, never shrinks."""
    if explicit is not None and str(explicit).strip() != '':
        try:
            val = float(explicit)
        except (TypeError, ValueError):
            val = 1.0
    else:
        try:
            val = float(detected_cpus) / float(max(1, baseline_cpus))
        except (TypeError, ValueError, ZeroDivisionError):
            val = 1.0
    return min(float(factor_max), max(1.0, val))

# resolved at import:
#   TIMER_BASELINE_CPUS            env, default 2   (this box)
#   SURICATOOS_CAPACITY_FACTOR_MAX env, default 8.0 (ceiling)
#   SURICATOOS_CAPACITY_FACTOR     env, explicit override (optional)
# CAPACITY_FACTOR = compute_capacity_factor(_detect_cpus(), baseline, max, explicit)

def scale_timer(seconds, factor=None):
    """Scale a duration by the capacity factor. 0 (=disabled sentinel) stays 0.
    factor defaults to module CAPACITY_FACTOR."""
    f = CAPACITY_FACTOR if factor is None else factor
    if not seconds:
        return seconds
    return int(round(seconds * f))
```

## Application rule

- **Hardcoded duration timers** (no env today) → always `scale_timer(base)`:
  - `DIR_FUZZ_TIME_BUDGET` (4200), `DIR_FUZZ_MIN_PER_HOST` (30), `THEHARVESTER_EXEC_TIMEOUT` (600), `SPIDERFOOT_EXEC_TIMEOUT` (900).
- **Env-overridable timers** → if the env var is **explicitly set**, use it **verbatim** (operator means an absolute value); **else** `scale_timer(base_default)`:
  - `DEFAULT_COMMAND_EXEC_TIMEOUT` (env `COMMAND_EXEC_TIMEOUT`, default 7200) — note `0` disables; `scale_timer` preserves 0.
  - `DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT` (env `ORCHESTRATION_BARRIER_TIMEOUT`, default 7200) — preserves 0.
  - `HANG_MONITOR_STALE_AFTER` (env, default 9000).
  - `CELERY_TASK_SOFT_TIME_LIMIT` (settings.py, env, default 5400).
  - `CELERY_TASK_TIME_LIMIT` (settings.py, env, default 7200).

Implementation detail for the "verbatim if env set" rule: read `raw = os.environ.get(VAR)`; if `raw not in (None, '')` → `int(raw)` verbatim; else `scale_timer(DEFAULT)`. Keep the existing `try/except (TypeError, ValueError)` fallbacks.

⚠️ `DEFAULT_COMMAND_EXEC_TIMEOUT` and `DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT` already read their env in `definitions.py`. **Live `docker-compose.yml` sets `ORCHESTRATION_BARRIER_TIMEOUT=7200` explicitly** → under the "verbatim if env set" rule it would stay 7200 (un-scaled) on every box. That's acceptable/conservative, but document it: to let the barrier scale automatically on a bigger box, the operator should **remove** that explicit compose line (or set it per-box). Mention in the spec/PR body and add a commented note in `.env`.

## Files

- `web/Suricatoos/capacity.py` — new module (factor + `scale_timer`).
- `web/Suricatoos/definitions.py` — import + apply to the 6 hardcoded/env timers (lines ~49–50, ~172/174, ~177–178, ~189/191, ~198/200).
- `web/Suricatoos/settings.py` — import + apply to `CELERY_TASK_SOFT_TIME_LIMIT` / `CELERY_TASK_TIME_LIMIT` (lines ~323–324). Verify no circular import (capacity.py imports only `os`).
- `web/tests/test_capacity_scaling.py` — new tests (below).
- `.env` — commented-out documentation of the new knobs (no behavior change; baseline box stays F=1.0).

## Tests (`tests.test_capacity_scaling`)

Pure-function tests (no reload needed):
1. `compute_capacity_factor(2, 2, 8)` == 1.0 (baseline → no-op).
2. `compute_capacity_factor(8, 2, 8)` == 4.0 (linear).
3. `compute_capacity_factor(1, 2, 8)` == 1.0 (never shrinks below 1.0).
4. `compute_capacity_factor(64, 2, 8)` == 8.0 (clamped to max).
5. explicit override: `compute_capacity_factor(2, 2, 8, explicit='3.5')` == 3.5; `explicit='100'` → 8.0 (clamped); `explicit='0.1'` → 1.0; `explicit='garbage'` → 1.0.
6. `scale_timer(0, 4.0)` == 0 (disable sentinel preserved); `scale_timer(4200, 2.0)` == 8400; `scale_timer(900, 1.0)` == 900.

Invariant tests (import live `definitions` + `settings`, at the resolved CAPACITY_FACTOR on the test box, AND simulate F=4 via the pure functions):
7. At any factor F≥1: `scale_timer(soft) < scale_timer(hard)` and `scale_timer(budget) < scale_timer(soft)` and `scale_timer(hard) <= scale_timer(stale)` and `scale_timer(watchdog) <= scale_timer(hard)`. Assert with the BASE constants (5400/7200/4200/9000/7200) at F ∈ {1, 2, 4, 8}.
8. On the test box (2 CPU, no env) the resolved `CAPACITY_FACTOR` == 1.0 and the live constants equal their original values (regression guard: no accidental change to live behavior).

Run (ephemeral container, from `/root/suricatoos`, mounting the timers worktree):
```
docker run --rm --network suricatoos_suricatoos_network --env-file .env \
  -e RENGINE_VAULT_KEY=$(python3 -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())") \
  -v /root/suricatoos-timers/web:/usr/src/app -w /usr/src/app \
  --entrypoint python3 suricatoos/web:latest manage.py test tests.test_capacity_scaling -v 2
```
Also `manage.py check` must stay clean and `makemigrations --check` must report no changes (this touches no models).

## Out of scope / not scaled

- `DEFAULT_HTTP_TIMEOUT` (per-request; a single HTTP request isn't slower on a bigger box), cache `TIMEOUT`, login cooldown, concurrency knobs (`MAX_CONCURRENCY` etc. — those are separate operator tuning, not duration timers).
- No DB migration. No live deploy on this box (F=1.0 ⇒ no-op). PR for review; merge/deploy only on explicit approval.
