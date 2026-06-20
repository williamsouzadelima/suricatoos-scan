# OWASP Audit — RISKY Fix Approval Briefs (Task 7)

These 5 confirmed findings are **NOT applied**. Each is behavioral / build-affecting, so per the standing rule they need explicit per-item approval. Listed in recommended priority order. The 15 SAFE fixes are already applied & verified live (see `2026-06-20-owasp-top10-audit-report.md`).

---

## 1. A07-1 — CSRF via state-changing GET (`change_status`)  ·  Medium  ·  **recommend approve**

**Finding.** `admin_interface_update` (`web/dashboard/views.py:215-218`) flips `user.is_active` on an HTTP **GET** when `mode=change_status`; `dashboard/admin.html:103/105` wires it as a bare `<a href="./update?mode=change_status&user={{ id }}">`. Django's CSRF middleware only protects unsafe methods, so a cross-site `<img src=".../update?mode=change_status&user=N">` loaded by a logged-in admin silently enables/disables an account (account lockout / self-DoS). Every sibling mode (delete/update/create) already uses POST + `X-CSRFToken`.

**Proposed remediation.** Move the `change_status` mutation into the `request.method == 'POST'` branch (or add `@require_POST` to a dedicated handler) and convert the admin.html link to a CSRF-tokened `fetch`/form, mirroring the existing `delete` handler.

**Blast radius.** Touches the admin "enable/disable user" control: the admin.html template wiring + the view branch. If the JS/CSRF wiring is wrong, the toggle button stops working (UI-only, no data risk). No DB/schema change.

**Rollback.** Revert the view branch + template hunk; the GET link returns. One commit.

**Why not auto-applied.** Changes a request flow (GET→POST) + template — a behavioral change with a (small) chance of breaking the admin toggle, so it needs a verified click-through. **This is the highest-value RISKY item; recommend approving — it's a real CSRF on an admin control.**

---

## 2. A04-1 — Synchronous `task.wait()` pins web workers (DoS-by-design)  ·  Medium

**Finding.** `Whois` / `ReverseWhois` / `DomainIPHistory` (`web/api/views.py:1540-1560`) dispatch a Celery task then call `task.wait()` (blocking, no timeout) inside the gunicorn/web request thread; the task itself does an untimed external fetch (viewdns.info / WHOIS). With no DRF throttle, an authenticated low-priv user can fire many in parallel and exhaust the worker pool → whole-app DoS. ReverseWhois/DomainIPHistory also skip input validation (pass a possibly-None param straight to the task).

**Proposed remediation (staged).**
- *Minimal (lower risk):* bound the wait — `task.wait(timeout=15)`, return 504 on timeout; add `timeout=` to the underlying `requests.*` in `reverse_whois()` / `get_domain_historical_ip_address()`; validate the lookup keyword/domain before dispatch (match the `Whois` view).
- *Proper (higher risk):* convert to the codebase's async-job pattern (return a task id, poll for the result) like the rest of the API.

**Blast radius.** *Minimal* variant: the three tool endpoints return 504 instead of hanging on slow upstreams — a behavior change for slow lookups, but no UI contract change. *Proper* variant: changes the frontend contract for these three tools (needs JS polling) — larger.

**Rollback.** Revert the view hunks. The `requests` timeout addition is independently safe.

**Recommendation.** Approve the **minimal** variant first (bounded wait + timeouts + input validation); defer the async-job rearchitecture.

---

## 3. A04-3 / A07-3 — No login lockout / brute-force throttle  ·  Medium  ·  **hands to initiative C**

**Finding.** `auth_views.LoginView` (`web/Suricatoos/urls.py:51-53`) has no failed-attempt throttling/lockout; no `django-axes`, no `django-ratelimit`, no DRF throttle. The only auth surface is open to unlimited online password guessing (worsened by the now-fixed weak-password gap, A07-2). Expensive scan-trigger endpoints likewise have no per-user rate limit.

**Proposed remediation.** Integrate `django-axes` (lock after N failures per username/IP, cooldown) **or** `django-ratelimit` on the login POST; optionally a global DRF `AnonRateThrottle`/`UserRateThrottle` + a per-user throttle on scan-trigger endpoints.

**Blast radius.** New dependency + middleware + a new migration (axes tables) + behavioral change (legitimate operators can be locked out). Needs a migration on the live DB (authorization-gated) and monitoring on rollout.

**Rollback.** Remove the app/middleware + reverse the migration. Non-trivial (DB migration).

**Recommendation.** Build under **initiative C** (AI attack detection/blocking) where lockout + monitoring belong together. Brief recorded; not for this PR.

---

## 4. A08-3 — Build-time downloads without checksum verification  ·  Medium  ·  reclassified SAFE→RISKY

**Finding.** `web/Dockerfile:60/68/74/126` fetch the Go toolchain, geckodriver, rustup and Google Chrome at build time with no integrity check; Chrome uses the mutable `google-chrome-stable_current_amd64.deb` (no version pin). A MITM/poisoned mirror injects root-level code into the published image. Every CI build runs these steps.

**Proposed remediation.** For each download, fetch the upstream-published SHA256 and `echo "<sha256>  file" | sha256sum -c -` before extract/install; pin Chrome to a specific versioned `.deb` (not `_current_`) + verify it; pin/verify the rustup installer.

**Blast radius — why this is RISKY, not SAFE.** Pinning the *mutable* Chrome URL to a fixed version + hardcoding hashes means the build **breaks** the moment Google rotates `_current_` or removes the pinned `.deb` from `dl.google.com` (they don't keep old versioned debs reliably), or when any pinned hash drifts. That breaks **every CI build** (`build.yml`/`build-pr.yml`/`tests.yml` all `docker build web/`). Verification requires a full, long image rebuild on each iteration.

**Rollback.** Revert the Dockerfile hunks.

**Recommendation.** Approve as its own change with a **verified clean rebuild** in the loop (pin to a known-good Chrome version + confirmed hashes), not as part of the auto-applied SAFE set. The runtime impact of the current state is supply-chain-at-build-time only (no live-deployment exposure).

---

## 5. A06 / Django upgrade — the single largest RISKY item (recorded, not scheduled)

`pip-audit` flagged ~50 advisories, but the audit confirmed only **A06-1** (PDF font fetch, already fixed) is reachable; `pyjwt` is a stray transitive (not imported), and the requests `.netrc` / langchain-serialization / markdown CVEs are all on unreachable code paths. Django **3.2.23** itself (EOL-adjacent) is the largest latent risk. Upgrading Django is a major, breaking change warranting its **own spec/plan** — recorded here, not scheduled in this initiative.
