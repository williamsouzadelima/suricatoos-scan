# Scan Depth Tiers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 3 selectable scan-depth engines (Fast / Medium / Deep) where Fast is light/passive, Medium is balanced, and Deep does full 65535 TCP **and** UDP with very long (but finite) timers.

**Architecture:** Each tier is a NEW engine in the fixture carrying `depth_tier: fast|medium|deep` in its `yaml_configuration`. TCP port depth is already config-driven (`port_scan.ports`), so the fixture alone covers most of the matrix. New CODE adds: a per-tier timer factor (composing with the existing capacity factor), a Deep-only UDP-full (`nmap -sU -p-`) path in `port_scan`, runtime routing of the Deep `port_scan` to a dedicated `deep_port_queue`, and an optional single-concurrent-Deep lock.

**Tech Stack:** Django 3.2 + Celery 5.4 (prefork + gevent workers), naabu/nmap, YAML fixtures (`loaddata`), Python 3.10.

## Global Constraints

- **No DB migration.** Fixture + code only.
- **All timers stay FINITE** — never disable a watchdog/time_limit. Preserve the ordering `command_watchdog <= celery soft <= celery hard <= hang_monitor` and `dir_fuzz < celery soft` (see `web/Suricatoos/capacity.py` docstring) at every tier.
- **`depth_tier` default = `medium`** when the key is absent (retrocompat: all 8 existing engines have no `depth_tier`).
- **Non-destructive:** do not edit/remove the 8 existing engines in the fixture; only append 3.
- **Queue isolation pattern:** follow the existing `coordinator_queue` isolation (PR #33) — a dedicated worker per isolated queue, declared in `docker-compose.yml`-driven `web/celery-entrypoint.sh`.
- **Command-injection safety:** any new tool args (UDP/nmap) must pass the existing allowlist regexes in `tasks.py` (`NMAP_CMD_RE`, `SAFE_PORT_RE`) — no raw user data onto a `shell=True` line.

---

### Task 1: `depth_tier` parsing + `tier_factor()` in capacity.py

**Files:**
- Modify: `web/Suricatoos/capacity.py` (append functions; module currently ends at `scale_timer`, line 123)
- Test: `web/tests/test_capacity_scaling.py` (exists from PR #34 — append)

**Interfaces:**
- Produces: `tier_factor(tier: str) -> float` (fast→0.4, medium→1.0, deep→4.0; unknown/None→1.0); `normalize_tier(value) -> str` (returns one of `'fast'|'medium'|'deep'`, default `'medium'`); `scale_for_tier(seconds: int, tier: str) -> int` (= `scale_timer(seconds) * tier_factor(tier)`, preserves the `0` sentinel).

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_capacity_scaling.py
from Suricatoos.capacity import tier_factor, normalize_tier, scale_for_tier, scale_timer

def test_tier_factor_values():
    assert tier_factor('fast') == 0.4
    assert tier_factor('medium') == 1.0
    assert tier_factor('deep') == 4.0

def test_tier_factor_unknown_defaults_to_one():
    assert tier_factor('bogus') == 1.0
    assert tier_factor(None) == 1.0

def test_normalize_tier():
    assert normalize_tier('Deep') == 'deep'
    assert normalize_tier('  fast ') == 'fast'
    assert normalize_tier(None) == 'medium'
    assert normalize_tier('nope') == 'medium'

def test_scale_for_tier_preserves_zero_sentinel():
    assert scale_for_tier(0, 'deep') == 0  # 0 = "disabled", never scaled

def test_scale_for_tier_composes_with_capacity():
    # on the baseline 2-vCPU box CAPACITY_FACTOR == 1.0, so == base * tier_factor
    assert scale_for_tier(100, 'fast') == scale_timer(40)
    assert scale_for_tier(100, 'medium') == scale_timer(100)
    assert scale_for_tier(100, 'deep') == scale_timer(400)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose run --rm --no-deps --entrypoint python3 web -m pytest web/tests/test_capacity_scaling.py -k "tier" -v` (or `manage.py test tests.test_capacity_scaling`)
Expected: FAIL — `ImportError: cannot import name 'tier_factor'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to web/Suricatoos/capacity.py
_TIER_FACTORS = {'fast': 0.4, 'medium': 1.0, 'deep': 4.0}


def normalize_tier(value):
    """Coerce a raw depth_tier value to one of fast|medium|deep (default medium)."""
    t = str(value).strip().lower() if value is not None else ''
    return t if t in _TIER_FACTORS else 'medium'


def tier_factor(tier):
    """Per-tier duration multiplier. Unknown/None -> 1.0 (medium)."""
    return _TIER_FACTORS.get(str(tier).strip().lower() if tier is not None else '', 1.0)


def scale_for_tier(seconds, tier):
    """scale_timer(seconds) further multiplied by the tier factor. Keeps the 0 sentinel."""
    if not seconds:
        return seconds
    return int(round(scale_timer(seconds) * tier_factor(tier)))
```

- [ ] **Step 4: Run test to verify it passes**

Run: same as Step 2.
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/capacity.py web/tests/test_capacity_scaling.py
git commit -m "feat(capacity): tier_factor + scale_for_tier (fast/medium/deep) composing with capacity"
```

---

### Task 2: Deep-tier helpers — port_scan ceiling + scan time_limit + UDP command

**Files:**
- Modify: `web/Suricatoos/capacity.py`
- Test: `web/tests/test_capacity_scaling.py`

**Interfaces:**
- Produces: `port_scan_ceiling(tier) -> int` (seconds; fast/medium scale the 7200 base via `scale_for_tier`; deep returns a dedicated large finite ceiling = `scale_timer(14*24*3600)` = ~14 days); `scan_time_limit(tier) -> int` (deep → `scale_timer(21*24*3600)` ~21 days; else `scale_for_tier(7200, tier)`).

- [ ] **Step 1: Write the failing test**

```python
from Suricatoos.capacity import port_scan_ceiling, scan_time_limit, scale_timer

def test_port_scan_ceiling_deep_is_multi_day_and_finite():
    c = port_scan_ceiling('deep')
    assert c == scale_timer(14 * 24 * 3600)
    assert c > 0  # finite, never the 0/disabled sentinel

def test_port_scan_ceiling_fast_short():
    assert port_scan_ceiling('fast') < port_scan_ceiling('medium') < port_scan_ceiling('deep')

def test_scan_time_limit_deep_exceeds_port_ceiling():
    # the whole-scan limit must cover the long port_scan plus the other stages
    assert scan_time_limit('deep') > port_scan_ceiling('deep')
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... -m pytest web/tests/test_capacity_scaling.py -k "ceiling or time_limit" -v`
Expected: FAIL — `ImportError: cannot import name 'port_scan_ceiling'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to web/Suricatoos/capacity.py
_DEEP_PORT_SCAN_SECONDS = 14 * 24 * 3600   # ~14 days finite ceiling for nmap -sU -p-
_DEEP_SCAN_LIMIT_SECONDS = 21 * 24 * 3600  # ~21 days finite ceiling for the whole deep scan


def port_scan_ceiling(tier):
    """Per-command timeout for the port_scan stage. Deep gets a dedicated multi-day
    (but finite) ceiling because nmap -sU -p- legitimately runs for days/weeks."""
    if normalize_tier(tier) == 'deep':
        return scale_timer(_DEEP_PORT_SCAN_SECONDS)
    return scale_for_tier(7200, tier)


def scan_time_limit(tier):
    """Whole-scan Celery time limit. Deep covers the long port_scan plus other stages."""
    if normalize_tier(tier) == 'deep':
        return scale_timer(_DEEP_SCAN_LIMIT_SECONDS)
    return scale_for_tier(7200, tier)
```

- [ ] **Step 4: Run test to verify it passes**

Run: same as Step 2. Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/capacity.py web/tests/test_capacity_scaling.py
git commit -m "feat(capacity): port_scan_ceiling + scan_time_limit (deep multi-day finite ceilings)"
```

---

### Task 3: The 3 depth-tier engine fixtures

**Files:**
- Modify: `web/fixtures/default_scan_engines.yaml` (append 3 `scanEngine.enginetype` records; do NOT touch existing ones)
- Test: `web/tests/test_scan_engines.py` (create)

**Interfaces:**
- Consumes: nothing (pure data).
- Produces: 3 engines named `Fast Scan`, `Medium Scan`, `Deep Scan`, each with `depth_tier` in `yaml_configuration`, used by Tasks 4–6 at runtime.

Each new record follows the YAML-block form already used by `Full-Validated` (fixture lines 108+). Use unique `pk`s not already present (check the file — existing pks include 1–8,13; use e.g. 20/21/22). The `yaml_configuration` is a YAML string. Key per-tier values (everything else mirrors the `Suricatoos Recommended` engine):

**Fast Scan (pk 20):**
```yaml
depth_tier: fast
subdomain_discovery:
  uses_tools: [subfinder, ctfr, sublist3r, oneforall]
  enable_http_crawl: true
  threads: 30
http_crawl: {}
port_scan:
  enable_http_crawl: true
  ports: [top-100]
  rate_limit: 300
  threads: 30
  passive: false
  enable_nmap: false
fetch_url:
  uses_tools: [waybackurls, gau]
  enable_http_crawl: false
  threads: 30
vulnerability_scan:
  run_nuclei: true
  run_dalfox: false
  run_crlfuzz: false
  enable_http_crawl: false
  nuclei: {severities: [high, critical]}
```
(no `osint`, no `dir_file_fuzz`, no `screenshot`, no `waf_detection`, no `secret_scan` keys → those stages are skipped.)

**Medium Scan (pk 21):** `depth_tier: medium` + the current `Suricatoos Recommended` config verbatim, except `port_scan.ports: [top-1000]`, `port_scan.enable_nmap: true`, `dir_file_fuzz.recursive_level: 1`.

**Deep Scan (pk 22):** `depth_tier: deep` + all stages on, `subdomain_discovery.uses_tools` = full list incl. `amass-active`, `port_scan: {ports: [full], enable_nmap: true, udp: true}` (the `udp` key is consumed by Task 4), `dir_file_fuzz.recursive_level: 2`, `vulnerability_scan.nuclei.severities: [unknown, info, low, medium, high, critical]`, `run_dalfox: true`, `run_crlfuzz: true`, lower `rate_limit`/higher `timeout`.

- [ ] **Step 1: Write the failing test**

```python
# web/tests/test_scan_engines.py
import yaml
from django.test import TestCase
from django.core.management import call_command
from scanEngine.models import EngineType

class DepthTierEngineTests(TestCase):
    def setUp(self):
        call_command('loaddata', 'fixtures/default_scan_engines.yaml', app_label='scanEngine')

    def test_three_depth_engines_loaded(self):
        names = set(EngineType.objects.values_list('engine_name', flat=True))
        assert {'Fast Scan', 'Medium Scan', 'Deep Scan'} <= names

    def test_depth_tier_and_ports_per_engine(self):
        cases = {'Fast Scan': ('fast', ['top-100']),
                 'Medium Scan': ('medium', ['top-1000']),
                 'Deep Scan': ('deep', ['full'])}
        for name, (tier, ports) in cases.items():
            cfg = yaml.safe_load(EngineType.objects.get(engine_name=name).yaml_configuration)
            assert cfg['depth_tier'] == tier
            assert cfg['port_scan']['ports'] == ports
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... manage.py test tests.test_scan_engines -v 2`
Expected: FAIL — `Deep Scan` etc. not in names.

- [ ] **Step 3: Append the 3 records to the fixture** (full YAML records per the values above; mirror the `Full-Validated` block style for `model`/`pk`/`fields.engine_name`/`fields.yaml_configuration`/`fields.default_engine: false`).

- [ ] **Step 4: Run test to verify it passes**

Run: same as Step 2. Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add web/fixtures/default_scan_engines.yaml web/tests/test_scan_engines.py
git commit -m "feat(engines): add Fast/Medium/Deep depth-tier scan engines (fixture)"
```

---

### Task 4: Deep-only UDP-full port scan (`nmap -sU -p-`) + tier-scaled timeout

**Files:**
- Modify: `web/Suricatoos/tasks.py` — `port_scan` task (line 1483) + its `run_command`/`stream_command` call sites for the timeout
- Test: `web/tests/test_command_injection.py` (exists — append a port_scan-build test) or `web/tests/test_port_scan_tiers.py` (create)

**Interfaces:**
- Consumes: `port_scan_ceiling`, `normalize_tier` (Task 1/2); reads tier via `normalize_tier(self.yaml_configuration.get('depth_tier'))`.
- Produces: when `depth_tier == 'deep'` and `port_scan.udp` is true, after the naabu/nmap-TCP path the task ALSO runs `nmap -sU -p- <host> ...` with `timeout=port_scan_ceiling('deep')`; non-deep tiers never emit `-sU`.

- [ ] **Step 1: Write the failing test** (factor the cmd-building into a helper so it's unit-testable)

```python
# web/tests/test_port_scan_tiers.py
from Suricatoos.tasks import build_udp_nmap_cmd  # new pure helper

def test_udp_cmd_only_for_deep():
    assert build_udp_nmap_cmd('example.com', tier='deep').startswith('nmap -sU -p- ')
    assert build_udp_nmap_cmd('example.com', tier='fast') is None
    assert build_udp_nmap_cmd('example.com', tier='medium') is None

def test_udp_cmd_quotes_host():
    cmd = build_udp_nmap_cmd('a.com; rm -rf /', tier='deep')
    assert 'rm -rf' not in cmd  # host must be shlex.quoted / allowlisted
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... manage.py test tests.test_port_scan_tiers -v 2`
Expected: FAIL — `cannot import name 'build_udp_nmap_cmd'`.

- [ ] **Step 3: Implement the helper + wire it into `port_scan`**

```python
# near the other port_scan helpers in tasks.py
def build_udp_nmap_cmd(host, tier, out_file=None):
    """Deep-tier only: full UDP port sweep. Returns None for non-deep tiers.
    Host is allowlisted (no shell metachars) so it is safe on a shell=True line."""
    from Suricatoos.capacity import normalize_tier
    if normalize_tier(tier) != 'deep':
        return None
    safe_host = shlex.quote(host)
    cmd = f'nmap -sU -p- -T3 --open {safe_host}'
    if out_file:
        cmd += f' -oG {shlex.quote(out_file)}'
    return cmd
```
Then in `port_scan`, after the existing naabu/nmap TCP block, read `tier = normalize_tier(self.yaml_configuration.get('depth_tier'))` and `udp = (self.yaml_configuration.get(PORT_SCAN) or {}).get('udp', False)`; if `tier == 'deep' and udp`, for each host run `udp_cmd = build_udp_nmap_cmd(host, tier, out_file)` via the existing `run_command(udp_cmd, shell=True, timeout=port_scan_ceiling(tier), scan_id=..., activity_id=...)` and parse results into ports the same way the TCP nmap path does.

- [ ] **Step 4: Run test to verify it passes**

Run: same as Step 2. Expected: PASS (2 tests). Also run `manage.py test tests.test_command_injection` to confirm no regression.

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/tasks.py web/tests/test_port_scan_tiers.py
git commit -m "feat(port_scan): deep-tier full UDP sweep (nmap -sU -p-) with multi-day ceiling"
```

---

### Task 5: Route Deep `port_scan` to a dedicated queue + new worker + single-Deep lock

**Files:**
- Modify: `web/Suricatoos/tasks.py` — `initiate_scan` (line ~285, the chain) to `.set(queue='deep_port_queue')` on the `port_scan` signature when tier is deep
- Modify: `web/celery-entrypoint.sh` — add `deep_port_queue` to a dedicated low-concurrency worker
- Modify: `docker-compose.yml` — (only if a separate service is wanted; default: add the queue to the existing celery worker command in the entrypoint)
- Test: `web/tests/test_port_scan_tiers.py`

**Interfaces:**
- Consumes: `normalize_tier`, the engine's `depth_tier`.
- Produces: Deep scans dispatch `port_scan` on `deep_port_queue`; a `deep_port_queue` worker (concurrency 1–2) consumes it; non-deep scans keep `port_scan` on `main_scan_queue`.

- [ ] **Step 1: Write the failing test** (factor the routing decision into a pure helper)

```python
from Suricatoos.tasks import port_scan_queue_for_tier
def test_deep_routes_to_dedicated_queue():
    assert port_scan_queue_for_tier('deep') == 'deep_port_queue'
    assert port_scan_queue_for_tier('medium') == 'main_scan_queue'
    assert port_scan_queue_for_tier('fast') == 'main_scan_queue'
```

- [ ] **Step 2: Run to verify it fails** → `cannot import name 'port_scan_queue_for_tier'`.

- [ ] **Step 3: Implement**

```python
def port_scan_queue_for_tier(tier):
    from Suricatoos.capacity import normalize_tier
    return 'deep_port_queue' if normalize_tier(tier) == 'deep' else 'main_scan_queue'
```
In `initiate_scan`, build the chain so the `port_scan.si(ctx=ctx, ...)` signature gets `.set(queue=port_scan_queue_for_tier(tier))` where `tier = normalize_tier(yaml_configuration.get('depth_tier'))` (read from the engine config already loaded in `initiate_scan`). In `web/celery-entrypoint.sh`, add a dedicated worker line near the `coordinator_worker` block:
```bash
commands+="celery -A Suricatoos.tasks worker --pool=prefork --concurrency=2 --optimization=fair --loglevel=$loglevel -Q deep_port_queue -n deep_port_worker &"$'\n'
```
Optional single-Deep lock: in `port_scan`, when deep, acquire a Redis/cache lock `deep_port_scan_lock` (non-blocking `cache.add(key, 1, timeout=port_scan_ceiling('deep'))`); if not acquired, requeue with countdown. (YAGNI-guard: include only if the box must never run 2 deep port scans at once.)

- [ ] **Step 4: Run** the unit test (PASS) + `bash -n web/celery-entrypoint.sh` (syntax OK).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/tasks.py web/celery-entrypoint.sh docker-compose.yml web/tests/test_port_scan_tiers.py
git commit -m "feat(scan): isolate deep port_scan on deep_port_queue with dedicated worker"
```

---

### Task 6: Apply tier-scaled timers to dir_fuzz + scan time_limit + e2e validation

**Files:**
- Modify: `web/Suricatoos/tasks.py` — `dir_file_fuzz` ffuf `-maxtime` uses `scale_for_tier(base, tier)` instead of the global `DIR_FUZZ_TIME_BUDGET`; `initiate_scan` sets the scan's effective time limit via `scan_time_limit(tier)` (apply on the chain / task `.set(soft_time_limit=, time_limit=)` where the codebase sets Celery limits).
- Test: `web/tests/test_port_scan_tiers.py`

**Interfaces:**
- Consumes: `scale_for_tier`, `scan_time_limit` (Tasks 1/2).

- [ ] **Step 1: Write the failing test**

```python
from Suricatoos.capacity import scale_for_tier
def test_dir_fuzz_budget_scales_by_tier():
    # deep gets a much larger -maxtime than medium
    assert scale_for_tier(4200, 'deep') > scale_for_tier(4200, 'medium')
    assert scale_for_tier(4200, 'fast') < scale_for_tier(4200, 'medium')
```

- [ ] **Step 2: Run to verify it fails** (if assertion form already passes from Task 1, instead assert the `dir_file_fuzz` cmd embeds the tier-scaled maxtime via a small build helper — mirror Task 4's pure-helper pattern).

- [ ] **Step 3: Wire `scale_for_tier(DIR_FUZZ_BASE, tier)` into the ffuf `-maxtime` and `scan_time_limit(tier)` into the scan limit.** Read `tier` in each task from `self.yaml_configuration.get('depth_tier')`.

- [ ] **Step 4: Run** unit tests (PASS) + `manage.py test tests.test_capacity_scaling tests.test_scan_engines tests.test_port_scan_tiers`.

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/tasks.py web/tests/test_port_scan_tiers.py
git commit -m "feat(scan): tier-scaled dir-fuzz budget + scan time_limit"
```

- [ ] **Step 6: e2e validation (manual, post-deploy — document, do not run UDP-full in CI)**
  - Rebuild image + recreate workers (incl. `deep_port_worker`); `loaddata` runs in entrypoint.
  - Trigger a **Fast Scan** on `demo.testfire.net` → confirm it finishes in minutes (no amass-active, no dir_fuzz, top-100).
  - Trigger a **Deep Scan** → confirm (via `celery inspect active` / logs) the `port_scan` lands on `deep_port_queue`/`deep_port_worker` and the command is `nmap -sU -p- ...`. Abort after confirming routing (do NOT wait for the full multi-day UDP sweep).

---

## Notes
- TCP port depth (top-100/top-1000/full) is already handled by the existing `port_scan` cmd builder (`tasks.py:1539-1547`) reading `port_scan.ports` — Fast/Medium/Deep TCP need NO code, only the fixture (Task 3).
- The capacity factor is `1.0` on the 2-vCPU box, so `scale_for_tier` reduces to `base * tier_factor` here; on bigger boxes both factors compound (intended).
- Keep the ordering invariant: verify `port_scan_ceiling('deep') < scan_time_limit('deep')` (Task 2 test enforces it).
