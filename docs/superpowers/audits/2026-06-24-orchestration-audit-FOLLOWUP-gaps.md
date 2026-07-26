# Orchestration audit — FOLLOW-UP gaps (completeness critic) + workflow caveat

- Date: 2026-06-24
- Target: main @ bcd1bd5 (post #33 deadlock fix + #29–#32)
- Companion to `2026-06-24-orchestration-core-audit-bcd1bd5.md`

## ⚠️ CAVEAT — the main report's "SAFE / 0 findings" verdict is NOT trustworthy

The audit workflow had a script bug: the adversarial **verify** stage called `parallel([agent(...), agent(...)])` passing *promises* instead of thunks (`() => agent(...)`), so every verification threw and was dropped. Result: `confirmed=0, refuted=0` is an **artifact of the crashed verify stage**, not a clean bill of health. The finders DID run and produce candidate findings, but they were never adversarially verified or synthesized into the report. **Do not rely on the "0 findings" verdict.**

The one part that ran correctly was the **completeness critic** (a single `agent()` call, not via the broken `parallel`). It found `coverage_sufficient=false` and surfaced 3 real gaps — the intersections the per-dimension finders missed. These are **UNVERIFIED** (need an adversarial pass with the fixed workflow) but are concrete and code-cited.

## Gap 1 — HIGH (suspected): hang_monitor false-abort + data loss under multi-tenant prefork saturation

**Locations:** `tasks.py:5143-5168` (hang_monitor), `tasks.py:198` (initiate_scan sets RUNNING immediately), `tasks.py:5159` (revoke terminate=True), `celery_custom_task.py:200,229` (ScanActivity.time only bumped at phase start/end — no heartbeat, none while QUEUED), `.env:32` (MAX_CONCURRENCY=4), `celery-entrypoint.sh:220`.

**Why:** The hang-monitor and concurrency-mem dimensions were each checked in isolation, never their INTERSECTION. `initiate_scan` sets `scan_status=RUNNING_TASK` (`:198`) before any child runs; heavy children share only 4 prefork slots (MAX_CONCURRENCY=4) across ALL tenants. hang_monitor's progress reference is the newest `ScanActivity.time`, written ONLY at phase start (`create_scan_activity`, `:200`) and end (`update_scan_activity`, `:229`) — never mid-phase, never while a child sits QUEUED in redis waiting for a slot. Under sustained multi-tenant load a HEALTHY scan can be RUNNING with its next heavy child queued; if that queue-wait exceeds `HANG_MONITOR_STALE_AFTER` (`scale_timer(9000)`=150 min baseline, `definitions.py:222`) with no new activity, hang_monitor (`:5143-5151`) treats it as wedged and aborts a healthy scan. WORSE: `app.control.revoke(task_id, terminate=True)` (`:5159`) on a still-queued task makes Celery DISCARD it when a worker picks it up → the queued phase and the rest of the chain are permanently lost = **incorrect abort + data loss precisely under the multi-tenant saturation the CTO guarantee targets**. The audit's "timeout-layering has no unbounded gap" verdict didn't consider queue-wait time counting against the staleness budget.

**Possible fixes to evaluate (after verification):** heartbeat the scan's progress timestamp while a phase is queued/running (not just at phase boundaries); OR have hang_monitor distinguish "queued-but-progressing-cluster" from "wedged" (e.g. only abort if NO task for the scan is queued/active in `inspect`); OR don't `revoke(terminate)` a task that is still queued (only revoke active wedged tasks). Tie staleness to actual inactivity, not wall-clock since last phase boundary.

## Gap 2 — MEDIUM (suspected): prefork fan-out parents still block on a barrier while holding a scarce slot

**Locations:** `tasks.py:814` (osint, queue main_scan_queue @ `:775`), `:1684` (port_scan, main_scan_queue @ `:1481`), `:2186` (fetch_url, main_scan_queue @ `:2049`) — all call `join_group_with_timeout` which `time.sleep(poll)` at `:90`.

**Why:** #33 moved `vulnerability_scan` (`:2339`) and `nuclei_scan` (`:3328`) to `coordinator_queue` (gevent) precisely so a blocked parent costs ~0. But THREE other fan-out parents — osint, port_scan, fetch_url — still run on the prefork `main_scan_queue` and BLOCK inside `join_group_with_timeout` (busy-parks via `time.sleep`, `:90`) while holding 1 of only 4 prefork slots. Their children run on non-prefork queues (so NOT the same self-starvation as #28), but with 4 concurrent tenants all parked at one of these barriers, all 4 prefork slots are consumed by SLEEPING parents for up to the 2h barrier deadline (`DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT=scale_timer(7200)`, `definitions.py:208`), stalling a 5th tenant's heavy children. Confirm whether a multi-tenant burst can fill all 4 slots with parked parents and how long the stall lasts; if so, move these three to `coordinator_queue` too (same fix as #33).

## Gap 3 — LOW (suspected): timeout-layering is coincident, not nested, at the tool↔Celery-hard boundary

**Locations:** `definitions.py:184` (`DEFAULT_COMMAND_EXEC_TIMEOUT=scale_timer(7200)`), `settings.py:330-338` (`SOFT=5400`, `HARD=7200`), `tasks.py:5232,5247` (watchdog arm + wait).

**Why:** The per-tool command watchdog (7200s) EQUALS the Celery hard limit (7200s) and EXCEEDS the soft limit (5400s) — coincident, not nested. On the prefork queue (where the tool watchdog actually matters, since SIGALRM is a no-op on gevent), the Celery hard limit SIGKILLs the worker child at 120 min, RACING the tool watchdog firing at the same 120 min. If Celery's hard kill wins, the graceful watchdog path (`os.killpg` of the process group at `:5082`, partial-output write, reap at `:5247`) is pre-empted by an abrupt worker SIGKILL — the orphaned-grandchild / unreaped condition #33 worked to eliminate. Because all tiers scale via the same `scale_timer`, the margins are identical at every capacity factor — raising capacity never opens a gap. Low severity (redundant layers still bound the scan) but the "clean nesting" claim doesn't hold. **Fix:** make the tool watchdog strictly LESS than the Celery soft limit (e.g. command watchdog 5100 < soft 5400 < hard 7200), so the graceful watchdog always fires before Celery's SIGKILL.

## Next step
Re-run an adversarial verification of these 3 gaps with the FIXED workflow (`parallel(thunks)`), confirm which are real, then fix the confirmed ones (Gap 1 is the priority — multi-tenant false-abort + data loss). NOT yet verified or fixed.
