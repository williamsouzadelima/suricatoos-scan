# Login Brute-Force / Account-Lockout Protection — Design (OWASP A04-3 / A07-3)

**Date:** 2026-06-21
**Status:** Approved (design) — proceeding to implementation (user approved spec + implement)
**Origin:** RISKY finding from the OWASP Top-10 audit (`2026-06-20-owasp-risky-fix-briefs.md`). The login is stock `auth_views.LoginView` (`web/Suricatoos/urls.py:51-53`) with no throttle/lockout/attempt-counting → unlimited online password guessing. Chosen via a 3-approach design panel + judge.

## 1. Purpose & success criteria
- Online password guessing against `/login/` is throttled: after N failed attempts the offending client/account is temporarily blocked (HTTP 429 / re-rendered form), defeating brute force.
- **No single-admin DoS:** an attacker spamming the (often single, shared-per-role) admin username must NOT be able to lock the legitimate operator out.
- **Non-breaking & env-flagged:** dev/HTTP, local use, and the CI test runner are unaffected when the flag is off; real users (behind the nginx HTTPS proxy) get protection.
- **No DB migration, no new runtime dependency** (avoids the live-DB-migration authorization gate — `celery-entrypoint` auto-runs `migrate` on deploy, so a new migration is a policy event).
- **Recovery is always possible** for the lone admin (auto-heal + management command + out-of-band bypass).

## 2. Chosen approach (and why)

**Custom, dependency-free cache-based throttle wired via a `LoginView` subclass.** Considered three approaches:

| Approach | Verdict |
|---|---|
| **A. django-axes** | Correct but: adds a dep pinned to the **EOL axes 5.x** line (6.x drops Django 3.2, 8.x needs Django≥4.2), introduces `AUTHENTICATION_BACKENDS` (none exists today → sensitive auth-path change) + `AxesMiddleware` ordering, and ships **DB migrations** that `celery-entrypoint`'s auto-`migrate` would apply on the live DB — exactly the gated event we avoid. **Rejected.** |
| **B. django-ratelimit** | Adds **two** deps (django-ratelimit + django-redis, since Django 3.2 has no native Redis cache). Workable but more surface. **Rejected.** |
| **C. custom cache throttle (LoginView subclass)** | **Chosen.** Zero deps, zero models, **zero migration**; smallest, most reversible surface (one view subclass + settings); aligns with the existing `SURICATOOS_*` env-flag pattern. Its only weakness (hand-rolled, and LocMemCache under-counts across multiple workers) is bounded — the box runs a **single** `runserver` process today, so the counter is coherent now, and the fix's failure mode is over-counting (over-protecting), never under-protecting. |

## 3. Throttle policy
- **Primary key — `(real_client_ip, normalized_username)` combination:** `SURICATOOS_LOGIN_FAIL_LIMIT` (default **5**) failures → block. The combination (not username-only) is the deliberate single-tenant choice: an attacker spamming the admin username from their own IP only blocks *their* (IP, username) pair; the real admin logging in from their own IP is unaffected.
- **IP-only backstop:** a coarser counter per real IP, `SURICATOOS_LOGIN_IP_FAIL_LIMIT` (default **20**), defeats username-rotation from one IP. Blank/empty-username attempts count toward the **IP backstop only**, never attributed to a real account.
- **Window / cooldown:** `SURICATOOS_LOGIN_COOLDOWN` (default **900s / 15 min**) implemented as the cache-key TTL → sliding, auto-expiring lock. No cron, no manual unlock in the common case.
- **Reset on success:** a successful login clears **both** the `(ip, username)` counter and the IP-only backstop for that IP (so a fat-finger-then-success doesn't leave a poisoned backstop).

## 4. Real client-IP resolution (the #1 footgun)
- nginx (`config/nginx/suricatoos.conf:25-26`) sets `X-Real-IP $remote_addr` (single, non-appendable hop, overwritten every request) and `X-Forwarded-For`.
- **Behind the proxy** (gate on the **existing** `SURICATOOS_BEHIND_TLS_PROXY` flag — reuse it to avoid drift): trust `HTTP_X_REAL_IP`. It is the simplest spoof-resistant primitive given nginx is the sole ingress (nginx overwrites it every request; the client cannot forge it through nginx).
- **Otherwise** (dev/CI/internal `:8000`): use `REMOTE_ADDR` only.
- Every candidate IP is validated with `ipaddress.ip_address()`; an unparseable/missing IP falls back to a constant bucket. **Never trust `X-Forwarded-For[0]`** (client-controllable).
- Documented deployment invariant: if the app is ever reached directly (bypassing nginx) while behind-proxy trust is on, `X-Real-IP` is forgeable — keep `:8000` internal-only.

## 5. Cache store
- A dedicated **`login_throttle`** cache alias, separate from `default` (so throttle counters and scan-result caching don't evict each other).
- **Default:** a separate `LocMemCache` instance — correct for the current **single-process** `runserver`, **zero dependency**.
- **Production-scale path (documented):** for gunicorn multi-worker or multiple web replicas, LocMemCache silently under-counts (attacker gets `N_workers × N` tries). Operators point `login_throttle` at a shared store (Redis via `django-redis`, distinct DB index e.g. `/3` — celery owns `/0`). The implementation **logs a WARNING at startup** when throttling is enabled while `login_throttle` is still LocMemCache, so the limitation is never silent.
- **Fail-OPEN:** any cache error/outage → the request is **allowed** (a Redis blip can never lock out the lone admin). Failures are logged.

## 6. Enablement (env flags, mirroring `settings.py:49-84`)
- `SURICATOOS_LOGIN_THROTTLE_ENABLED` — `env.bool`, default **`not DEBUG`**. Off → the LoginView subclass behaves exactly like stock `LoginView` (dev/HTTP + the CI runner untouched; no login tests exist today).
- `SURICATOOS_LOGIN_FAIL_LIMIT` (5), `SURICATOOS_LOGIN_IP_FAIL_LIMIT` (20), `SURICATOOS_LOGIN_COOLDOWN` (900) — all `env.int`-overridable.
- Proxy-IP trust gated on the existing `SURICATOOS_BEHIND_TLS_PROXY`.

## 7. Recovery (single-admin safe — total lockout is impossible)
1. **Auto-heal:** the 15-min TTL expires the lock with no action.
2. **Management command** `clear_login_lockouts [--ip X | --username Y | --all]` — the canonical break-glass one-liner (`docker compose exec celery python3 manage.py clear_login_lockouts --all`).
3. **Kill switch:** set `SURICATOOS_LOGIN_THROTTLE_ENABLED=0` and reload (bind-mount picks it up; web is `runserver`).
4. **Out-of-band:** `docker compose exec ... createsuperuser` / shell always bypasses the HTTP form — the throttle only guards `/login/`.

## 8. Observability
- Every block/lockout is logged at **WARNING** with the resolved IP + **masked** username (e.g. `ad***`) → a forensic trail without a DB model (the one thing cache-only loses vs django-axes, mitigated).

## 9. Scope
- **In:** the `/login/` POST. **Out (recorded, not built here):** per-user rate-limiting of expensive scan-trigger endpoints (`start_scan_ui`/`start_multiple_scan`/`initiate_subscan`) — lower-value, deferred to a follow-up; the login gap is the priority.

## 10. File structure
| File | Action |
|---|---|
| `web/dashboard/views.py` (or a small `web/Suricatoos/security_views.py`) | **Create** `ThrottledLoginView(LoginView)` + `_resolve_client_ip(request)` + counter helpers |
| `web/Suricatoos/urls.py:51-53` | **Modify** the `login/` route to use `ThrottledLoginView` |
| `web/Suricatoos/settings.py` | **Modify** — env flags + the `login_throttle` CACHES alias + startup LocMem warning |
| `web/dashboard/management/commands/clear_login_lockouts.py` | **Create** the recovery command |
| `web/tests/test_login_lockout.py` | **Create** — TDD (see §11) |
| `.github/workflows/tests.yml:53` | **Modify** — add `tests.test_login_lockout` |

## 11. Testability
Django `TestCase` with `override_settings(SURICATOOS_LOGIN_THROTTLE_ENABLED=True, ...)` and a `LocMemCache` `login_throttle` alias (cleared per test):
- After `SURICATOOS_LOGIN_FAIL_LIMIT` bad POSTs to `/login/`, the next attempt is blocked (429 / re-render with error) — **even with correct credentials** (proves the lock).
- A successful login **before** the limit clears the counter (no carry-over).
- An attacker hammering the admin **username from IP-A** does **not** block a correct login of the same username **from IP-B** (no single-admin DoS) — drive the IP via `X-Real-IP` with `SURICATOOS_BEHIND_TLS_PROXY=True`.
- Blank-username attempts only feed the IP backstop.
- Flag **off** → unlimited attempts behave like stock LoginView (no regression).
- `_resolve_client_ip` uses `X-Real-IP` behind proxy and `REMOTE_ADDR` otherwise; rejects garbage.

## 12. Blast radius & accepted risks
- **Auth path:** only the login VIEW is subclassed — `AUTHENTICATION_BACKENDS`, DRF `SessionAuthentication`, and django-role-permissions are untouched. Internal `:8000` health checks don't POST `/login/`, so create no attempts.
- **LocMemCache multi-worker under-count:** accepted for the current single-process deployment; mitigated by the startup warning + documented Redis path. Failure mode is under-protection only in a config the box doesn't run today.
- **Proxy misconfig** (trust-on but reached directly): documented invariant; the per-account primary key still discriminates.
- **No DB migration, no new dependency** → no live-DB-migration gate; deploy is a bind-mount reload + (optionally) a calm-window celery restart. **Merge to main still gated on explicit approval.**
