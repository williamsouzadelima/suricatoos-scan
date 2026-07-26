# Orchestration-Core Audit — Suricatoos `main` @ `bcd1bd5`

**Date:** 2026-06-24
**Scope:** The merged + deployed scan orchestration core: PR #33 (multi-tenant deadlock + tool-reaping wedge fix, `268580d`) and the #29–#32 scan-quality merges that land on `main` at `bcd1bd5`.
**Method:** 8 dimensions audited (residual-wedge, barrier, queue-routing, hang-monitor, timeout-layering, security, config-defaults, concurrency-mem). Every candidate finding was put through two independent adversarial skeptics before being recorded as confirmed.

---

## 1. Executive verdict

**The orchestration core is SAFE for multi-tenant concurrent scans as deployed.** It clears the CTO bar.

The audit produced **zero confirmed findings of any severity** and **zero findings that needed to be refuted** (no candidate survived even the first skeptic pass with anything actionable). The five layers of the #33 fix — interruptible reads, bounded barriers, queue isolation onto a dedicated gevent coordinator worker, `tini`-based zombie reaping, and the `hang_monitor` beat backstop — are each present, correctly wired, and mutually reinforcing in the deployed `docker-compose.yml` and `celery-entrypoint.sh`. The structural property that caused scan #28 to wedge for 35h — a blocking parent orchestrator holding a scarce prefork slot while its own children starve for slots — has been eliminated at the architectural level (parents now park as cheap greenlets on a queue physically separate from the memory-bounded `main_scan_queue` that runs the heavy children). **No confirmed finding undermines the multi-tenant concurrency guarantee.**

This is a clean bill of health. The remaining sections document coverage rather than defects.

---

## 2. Confirmed findings (severity-ordered)

| Severity | Dimension | Location | One-line |
|----------|-----------|----------|----------|
| _(none)_ | — | — | No confirmed findings at any severity. |

Counts: **Critical 0 · High 0 · Medium 0 · Low 0 · Nit 0.**

---

## 3. Critical / High findings

None. Nothing in the orchestration core rises to Critical or High, so there are no must-fix items blocking continued multi-tenant operation.

---

## 4. Medium / Low / Nit findings

None.

---

## 5. Verified-sound (coverage)

The following were inspected at `bcd1bd5` and found correct. This is recorded so the reader knows what the clean verdict actually covers.

**The five #33 layers:**

1. **Interruptible read** — `web/Suricatoos/tasks.py:5094` (`_read_lines_until_dead`), consumed at `tasks.py:5237` and `tasks.py:5321`. `select()` bounds every read so a watchdog `SIGKILL` that orphans a grandchild holding the stdout pipe can no longer block `readline()` on an EOF that never arrives; the loop always reaches `process.wait()` with a guaranteed reap in `finally`. This was the primary root cause of #28 and is closed.
2. **Bounded barriers** — `web/Suricatoos/tasks.py:61` (`join_group_with_timeout`), applied across `vulnerability_scan`, `nuclei_scan`, `port_scan`, `fetch_url`, and `osint`. Every previously-unbounded `while not job.ready()` / `.get()` join now has a deadline, revokes its children on expiry, and returns gracefully so the chain still reaches `report()`. No unbounded join remained in the orchestrators.
3. **Queue isolation** — `vulnerability_scan` (`tasks.py:2339`) and `nuclei_scan` (`tasks.py:3328`) are pinned to `queue='coordinator_queue'`, served by a **separate** gevent worker (`web/celery-entrypoint.sh:276`+, `-Q coordinator_queue -n coordinator_worker`), distinct from both the prefork `main_scan_queue` (heavy children) and the shared IO gevent worker (`celery-entrypoint.sh:271`). A parked orchestrator is a near-zero-cost greenlet and can no longer consume a slot needed by its own children — the structural cause of the deadlock is gone, not merely papered over with a timeout.
4. **Zombie reaping** — `init: true` (`tini` as PID 1) on the celery and web services: `docker-compose.yml:36` and `docker-compose.yml:110`. Defunct tool children (e.g. the `[nuclei] <defunct>` seen in #28) are reaped by PID 1.
5. **Hang monitor** — `web/Suricatoos/tasks.py:5129` (`hang_monitor`), scheduled on celery-beat every ~10m via `HANG_MONITOR_INTERVAL` (`web/Suricatoos/settings.py:335`) on the dedicated `hang_monitor_queue` (`celery-entrypoint.sh`). Auto-aborts any scan stuck `RUNNING` past `HANG_MONITOR_STALE_AFTER`, so even an unforeseen wedge self-heals rather than blocking the queue for other tenants.

**Cross-cutting checks that passed:** timeout-layering (subprocess watchdog ↔ Celery soft/hard limits ↔ barrier deadlines ↔ hang_monitor compose into a strict outer-bounds-inner hierarchy with no gap that leaves a scan unbounded); config-defaults (`SHARED_CONCURRENCY` and `COORDINATOR_CONCURRENCY` both validate-or-fall-back to safe integer defaults — 50 and 30 — in `celery-entrypoint.sh`, immune to empty/garbage env); concurrency-mem (heavy children remain on the memory-bounded prefork `main_scan_queue`; parking many orchestrators costs only Django's one-time import, not per-greenlet RSS); security (no new command-injection / untrusted-input sink introduced by the orchestration changes); and the #29–#32 scan-quality merges (adaptive dir-fuzz time budget and engine-fixture sync) were checked for interaction with the new timers and found independent.

**Refuted / dismissed:** **0.** No candidate finding required refutation.

---

## 6. Recommended next actions

Ordered by the user's standing priority (security > architecture > performance). Nothing here is required for safety; these are optional hardening / hygiene items.

**Security — SAFE to auto-fix:**
- None outstanding from this audit. (No action needed.)

**Architecture — needs a decision (do not auto-apply):**
- Decide whether to add a lightweight CI smoke test that asserts the concurrent-scan invariant directly against the running topology (the #33 "8/8 vs 0/8" repro), so a future change that re-couples parents and children to the same queue fails CI rather than being caught only by adversarial audit. This changes test infrastructure and is a judgment call, so it should be confirmed before implementing.
- Note (informational only): live `main` has already advanced past the audit target to `9b0ae85` (PR #34, capacity-proportional timers). That follow-up tunes the timer *values* the audited layers rely on; if those timers are ever lowered aggressively, re-confirm the timeout-layering hierarchy still has outer > inner margins. No issue today — flagged so it is not forgotten.

**Performance — SAFE to auto-fix:**
- None warranted. `COORDINATOR_CONCURRENCY` (default 30) and `SHARED_CONCURRENCY` (default 50) are appropriate for the deployed box; tune only if real concurrent-tenant load data later suggests it. No change recommended now.

**Bottom line:** ship as-is. The orchestration core is safe for multi-tenant concurrent scans at `bcd1bd5`; the only open items are optional hardening that require an explicit decision, not fixes.
