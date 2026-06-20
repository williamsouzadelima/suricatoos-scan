# OWASP Top 10 (2021) Audit Report — Suricatoos

**Date:** 2026-06-20 · **Scope:** whole codebase · **Method:** hybrid (SAST tools + per-category multi-agent review + adversarial verification). See the design spec `2026-06-20-owasp-top10-audit-design.md`.

## Summary

**Audit run:** Phase-1 = 10 per-category finder agents; Phase-2 = 2 adversarial skeptics per finding (refute-by-default, single-tenant model respected). **22 candidates → 20 confirmed, 2 refuted.**

| Severity | Confirmed | Fix-risk |
|---|---|---|
| High | 3 | all SAFE |
| Medium | 11 | 7 SAFE / 4 RISKY |
| Low | 6 | all SAFE |
| **Total** | **20** | **16 SAFE / 4 RISKY** |

| Category | Status | Confirmed | Fix-risk |
|---|---|---|---|
| A01 Broken Access Control | has-findings | 3 (1 Med, 2 Low) | SAFE ×3 |
| A02 Cryptographic Failures | has-findings | 1 (High) | SAFE |
| A03 Injection (XSS) | has-findings | 3 (1 High, 2 Med) | SAFE ×3 |
| A04 Insecure Design | has-findings | 3 (2 Med, 1 Low) | 1 SAFE / 2 RISKY |
| A05 Security Misconfiguration | has-findings | 2 (1 Med, 1 Low) | SAFE ×2 |
| A06 Vulnerable Components | has-findings | 1 (Low) | SAFE (reachable subset only) |
| A07 Auth Failures | has-findings | 4 (3 Med, 1 Low) | 2 SAFE / 2 RISKY |
| A08 Integrity Failures | has-findings | 1 (Med) | SAFE |
| A09 Logging/Monitoring | has-findings | 1 (High) | SAFE |
| A10 SSRF | has-findings | 1 (Med) | SAFE |

**Refuted (false positives correctly killed):** A08-1 (entrypoint pulls tools from master/HEAD — refuted: build does not, tools are install-time pinned) and A08-2 (Go `@latest` makes image non-reproducible — refuted as the live integrity concern; superseded by the confirmed A08-3 which is the precise, real version of the concern).

**Key reachability rulings (single-tenant model respected):** `?project=` cross-project access is a UI filter, NOT IDOR — not reported. SPA/JWT removal aftermath (dead code) — not reported. Command-exec sinks already covered by prior `shlex.quote`/validator hardening — not re-reported; only the residual SSRF-class gap (A10-1) and operator-facing fetches survived.

---

## SAFE fix batches (Task 5 plan)

| Batch | Findings | Theme | Testable? |
|---|---|---|---|
| B1 | A01-1, A01-2, A01-3 | RBAC tightening — result viewsets → ReadOnly, missing decorator | yes (DRF perm test) |
| B2 | A03-1, A03-2, A03-3 | XSS output escaping (`htmlEncode`) in tables/modals | review + live render |
| B3 | A09-1 | Redact h8mail breach creds in logs + delete raw report | yes (unit) |
| B4 | A05-1, A05-2, A07-4 | CSP header, env-driven ALLOWED_HOSTS, session age | yes (header/settings test) |
| B5 | A04-2, A06-1, A10-1 | Request-path fetch timeouts + SSRF gate on WAF/CMS detector | yes (SSRF reject test) |
| B6 | A07-2 | Enforce `validate_password()` on admin/onboarding user paths | yes (unit) |
| B7 | A02-1, A08-3 | Docker build hygiene — `secret` out of context, checksum pins | rebuild-verify |

## RISKY findings — approval briefs (Task 7, NOT applied)

| ID | Severity | Why risky | Recommendation |
|---|---|---|---|
| A07-1 | Medium | CSRF via state-changing GET (`change_status`); fix changes admin link GET→POST | **High-priority** — small, contained; recommend approving |
| A04-1 | Medium | Synchronous `task.wait()` in web request threads (DoS-by-design); fix is async-job rearchitecture | Recommend approving the bounded-timeout variant first |
| A04-3 / A07-3 | Med/Low | No login lockout/throttle; needs `django-axes` (new dep + behavioral) | Hands to **initiative C**; brief provided |

---

## Phase 0 — SAST tool findings (deterministic baseline)

Tool outputs under `/tmp/owasp-audit/phase0/`. Seeded the per-category agents.
- **A05** `check --deploy`: W004/W008/W012/W016 — **addressed** by the env-flagged security block (commit `ec95ac0`); CSP + ALLOWED_HOSTS remained (→ B4).
- **A06** `pip-audit` (installed env): ~50 advisories — agents confirmed only **reachability-relevant** items; pyjwt is a stray transitive leftover (not imported, nothing to remove); requests/.netrc, langchain serialization, markdown paths all unreachable. Only A06-1 (PDF font fetch) is a real, reachable issue. Version bumps stay RISKY/unjustified.
- **A03/A08** `bandit -ll` (45 ≥Med): the 20× `shell=True`/subprocess in the scan engine are covered by prior command-injection hardening (agents found no residual reachable injection); 3× `pickle` confirmed Celery-internal/trusted (not attacker-controlled); the surviving injection findings are XSS (A03-1/2/3), not shell.
- `semgrep` deferred (box memory); the per-category agent pass covered its scope.

---

## Verified findings (adversarially confirmed)

### A01 — Broken Access Control — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A01-1 | `ListTargetsDatatableViewSet` is a full `ModelViewSet` over `Domain.objects.all()` (`api/views.py:529`); DRF router exposes POST/PUT/DELETE with only `IsAuthenticated`. An **Auditor** (`PERM_MODIFY_TARGETS:False`) can `DELETE /api/listTargets/{id}/` and destroy a target. | Medium | SAFE | 2/2 verifiers confirmed reachable; Auditor role real/assignable; sibling LeakedSecret/Osint viewsets already ReadOnly | staged-safe → B1 |
| A01-2 | Subdomains/EndPoint/Directory/Vulnerability/IpAddress/SubdomainDatatable viewsets are write-capable `ModelViewSet` with only `IsAuthenticated`; UI only reads. Defense-in-depth + becomes escalation for any future role lacking `MODIFY_SCAN_RESULTS`. | Low | SAFE | viewsets at `api/views.py:2062/2086/2339/2654/2897/2976`; no write callers in UI | staged-safe → B1 |
| A01-3 | `change_vuln_status` (`startScan/views.py:748`) mutates vuln state on POST with no `@has_permission_decorator`, unlike every sibling mutating view. | Low | SAFE | sibling views all gate `PERM_MODIFY_SCAN_RESULTS` | staged-safe → B1 |

### A02 — Cryptographic Failures — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A02-1 | `web/.dockerignore` omits `secret`; build context is `./web`, so `Dockerfile:143 COPY . /usr/src/app/` bakes `./web/secret` (the live Django `SECRET_KEY`) into the image. Anyone with the image forges session cookies. Root `.dockerignore` lists `secret` but is unused for a `./web` context (false safety). | High | SAFE | build-context analysis; key path `Suricatoos/init.py:17-18` ↔ `Dockerfile:143`; runtime unaffected (bind-mount) | staged-safe → B7 |

### A03 — Injection / Cross-Site Scripting — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A03-1 | Stored XSS: scan-derived `webserver`/`content_type`/`cname` rendered unescaped in `subdomains.html:114/118/178`; sibling `page_title` already uses `htmlEncode` (line 210). Crafted `Server:` header → script in operator session. | High | SAFE | data path httpx → `tasks.py:3820-3826` → DRF JSON → DataTable innerHTML | staged-safe → B2 |
| A03-2 | DOM XSS in GPT attack-surface modal (`custom.js:3355/3357`): `subdomain_name` via `.html()` and LLM `description` via `.append()` unescaped; LLM is fed target-controlled data (prompt-injection amplifies). | Medium | SAFE | `api/views.py:447-463` → `llm.py:97` → modal | staged-safe → B2 |
| A03-3 | Stored XSS via tech names (`custom.js:424/426`) and nmap port `service_name`/`description` (`custom.js:1096`) rendered unescaped on result pages. | Medium | SAFE | httpx tech / nmap banner → JSON → innerHTML | staged-safe → B2 |

### A04 — Insecure Design — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A04-1 | Synchronous `task.wait()` (no timeout) in Whois/ReverseWhois/DomainIPHistory web handlers (`api/views.py:1540-1560`) pins gunicorn workers on worker-queue depth + 3rd-party latency → DoS. ReverseWhois/DomainIPHistory also skip input validation. | Medium | **RISKY** | inherits `IsAuthenticated`; no throttle | staged-risky → A07-brief / Task 7 |
| A04-2 | Multiple `requests.*` calls on the web request path with no `timeout=` (CVEDetails→circl.lu, update checks→github, hackerone, ollama toolkit). CVEDetails also concatenates unencoded `cve_id` into the URL. | Medium | SAFE | `api/views.py:861/1262/1451`, `scanEngine/views.py:372/495` | staged-safe → B5 |
| A04-3 | No brute-force/rate-limit on login (and scan-trigger). | Low | **RISKY** | duplicate of A07-3 | staged-risky → Task 7 |

### A05 — Security Misconfiguration — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A05-1 | No Content-Security-Policy emitted anywhere (settings/middleware/nginx/template). App renders attacker-influenced recon output; any escaping miss → script exec with no second layer. | Medium | SAFE | grep: 0 CSP occurrences; B2 closes the misses, B4 adds the layer | staged-safe → B4 |
| A05-2 | `ALLOWED_HOSTS = ['*']` hard-coded (`settings.py:43`); `DOMAIN_NAME` read but never used. Disables host-header validation. Low (behind nginx `server_name`). | Low | SAFE | inherited reNgine boilerplate | staged-safe → B4 |

### A06 — Vulnerable & Outdated Components — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A06-1 | Report PDF (`startScan/views.py:1183` WeasyPrint `write_pdf`) makes an untimed, unguarded server-side fetch to `fonts.googleapis.com` (hardcoded `<link>` in `report/default.html`+`modern.html`). Slow/blocked egress hangs the worker; leaks egress IP+timing. (The pip-audit CVE-2025-68616 itself is NOT reachable — no custom url_fetcher exists.) | Low | SAFE | hardcoded link → default_url_fetcher (urllib, no timeout) | staged-safe → B5 |

**Other A06 advisories ruled NOT reachable** (no fix): pyjwt (stray transitive, not imported), requests `.netrc` CVE (no `~/.netrc`), langchain serialization/SQLChain CVEs (only `Ollama` llm imported, hardcoded base_url), markdown (operator-only config). Django 3.2.23 upgrade remains the single largest RISKY item (Task 7).

### A07 — Identification & Auth Failures — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A07-1 | State-changing GET → CSRF: `admin_interface_update` flips `is_active` on `GET ?mode=change_status` (`dashboard/views.py:215-218`); admin.html wires a bare `<a href>`. `<img src=...>` on attacker page disables/locks an admin account. | Medium | **RISKY** | sibling delete/update use POST+CSRF; this is the lone GET mutation | staged-risky → Task 7 (recommend approve) |
| A07-2 | `AUTH_PASSWORD_VALIDATORS` configured but `validate_password()` never called; admin create/update + onboarding accept any password (`dashboard/views.py:240/253-256/363-366`). | Medium | SAFE | self-service `profile()` IS validated; admin/bootstrap paths are not | staged-safe → B6 |
| A07-3 | No account lockout/throttle on login (`urls.py:51-53`); unlimited online guessing. | Medium | **RISKY** | needs django-axes (new dep + behavioral) | staged-risky → Task 7 (initiative C) |
| A07-4 | No session idle/absolute timeout — 14-day persistent cookie for a tool storing 3rd-party API keys (`settings.py:49-54`). | Low | SAFE | `SESSION_COOKIE_AGE`/`EXPIRE_AT_BROWSER_CLOSE` at defaults | staged-safe → B4 |

### A08 — Software & Data Integrity Failures — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A08-3 | `Dockerfile:60/68/74/126` fetch Go toolchain, geckodriver, rustup and Google Chrome at build with no checksum; Chrome uses mutable `_current_` (no version pin). MITM/poisoned mirror → root-level code in the published image. | Medium | SAFE | every CI build runs these RUN steps | staged-safe → B7 |

### A09 — Security Logging & Monitoring Failures — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A09-1 | h8mail OSINT task does `logger.warning(cred)` per breached target (`tasks.py:1269`) — full leaked-credential records (plaintext passwords/hashes/PII) into logs; raw `h8mail.json` never deleted. Inconsistent with gitleaks/ggshield which `redact_secret()` + `_safe_remove()`. | High | SAFE | runs on any default-on OSINT scan with a harvested email | staged-safe → B3 |

### A10 — SSRF — **has-findings**

| ID | Description | Severity | Fix-risk | Evidence | Status |
|---|---|---|---|---|---|
| A10-1 | `WafDetector`/`CMSDetector` (`api/views.py:571-593/1563-1616`) fetch a request-supplied `url` after only `validators.url/domain` (a command-injection check, NOT SSRF). IMDS `169.254.169.254`, loopback, RFC1918 all pass → server fetches internal/metadata. Existing always-block gate `_validation_target_url` (`tasks.py:2790`) is bypassed. | Medium | SAFE | `validators.url('http://169.254.169.254/...')` returns True; routes `api/urls.py:150/158`, `IsAuthenticated` | staged-safe → B5 |

---

## Accepted risks
- `SECURE_SSL_REDIRECT=False` in Django — nginx performs the http→https redirect; enabling it in Django breaks internal :8000 health checks/smoke tests. Accepted (documented in settings).
- Django **3.2.23** stays pinned — upgrade is the largest RISKY item; deferred to its own approved spec/plan (Task 7).
- Cross-project `?project=` access — intentional UI filter in a single-tenant app; not a security boundary.
