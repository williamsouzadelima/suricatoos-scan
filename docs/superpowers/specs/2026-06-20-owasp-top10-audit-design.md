# OWASP Top 10 (2021) Audit + Staged Fixes + Guardrails — Design

**Date:** 2026-06-20
**Status:** Approved (design) — pending spec review → writing-plans
**Initiative:** B of 3 (A = per-user dashboard widgets; C = AI attack detection/blocking — both deferred to their own cycles)

## 1. Purpose & success criteria

Validate that Suricatoos (a rebranded fork of reNgine, Django 3.2.23) applies OWASP Top 10 (2021) controls, **fix** the gaps, and add **guardrails** so the controls don't silently regress.

**Success criteria:**
- Every OWASP 2021 category (A01–A10) has an explicit, evidence-backed status: *no issue found* / *fixed* / *staged for approval* / *accepted risk*.
- All confirmed SAFE fixes are applied and verified live (legacy UI still 100% functional).
- All RISKY fixes are documented with blast-radius and applied only after explicit approval.
- CI fails on new security misconfiguration and newly-vulnerable dependencies.

## 2. Scope

**Whole codebase** — both the inherited reNgine code and Suricatoos-specific additions (SPA-removal aftermath, secret-scan, OSINT/SpiderFoot, branding/white-label, the REST API, prior hardening). The audit covers the reachable attack surface AND deeper/internal code.

**Non-goals (this initiative):** the dashboard-widgets feature (A) and the AI attack-detection feature (C). Note A09 (logging/monitoring) and A07 lockout findings will be *recorded* here but their build-out hands off to initiative C.

## 3. Methodology — Hybrid (tools anchor, agents judge)

### Phase 0 — Deterministic tooling baseline (run in the `web` container; Python available)
| Tool | OWASP coverage | Notes |
|---|---|---|
| `pip-audit` (and/or `safety`) | A06 vulnerable/outdated deps | flags Django 3.2.23 CVEs, transitive deps |
| `python manage.py check --deploy` | A05 security misconfiguration | missing `SECURE_*`, cookie flags, HSTS, etc. |
| `bandit -r web/` | A03 injection, A02 weak crypto | `shell=True`, SQL string-format, md5, `random` for secrets |
| `semgrep --config p/django --config p/owasp-top-ten` | broad pattern coverage | anchors agent findings |

Tool output is captured as structured findings and fed into Phase 1 (agents verify/expand, never re-derive what a tool already proved).

### Phase 1 — Per-category multi-agent review (judgment-heavy; one agent per A01–A10)
Each agent reviews the whole codebase for its category, seeded with (a) the Phase-0 tool findings for that category and (b) app context: Django reNgine fork, **single-tenant** RBAC (global `HasPermission`/rolepermissions, no object-level ownership), runs external security tools (command execution), fetches arbitrary URLs (scan targets), stores secrets (API keys) in the DB. Directed focus per category:

- **A01 Broken Access Control:** RBAC enforcement, `LOGIN_REQUIRED_IGNORE_PATHS`, IDOR on REST endpoints, the `?project=` filter (UI filter, NOT a security boundary), admin surface.
- **A02 Cryptographic Failures:** `SECRET_KEY` generation/storage, password hashing, secret storage at rest (API keys), TLS/proxy config.
- **A03 Injection:** command-exec sinks in the scan engine (nmap/nuclei/amass/etc. — prior hardening exists; check for residual sinks), SQL, template injection, **LLM prompt injection**.
- **A04 Insecure Design:** trust boundaries, missing rate limits, abuse cases of a tool that runs attacker-influenced commands.
- **A05 Security Misconfiguration:** `DEBUG`, `ALLOWED_HOSTS=['*']`, cookie/HSTS/header settings, CSP, error verbosity, default creds.
- **A06 Vulnerable & Outdated Components:** the dependency tree (Django 3.2.23 is EOL-adjacent), pinned vs unpinned, Dockerfile tool installs.
- **A07 Identification & Auth Failures:** session config, password validators, login flow, **account lockout (absent → hands to C)**, session fixation/rotation.
- **A08 Software & Data Integrity Failures:** dependency pinning/integrity, CI/build integrity, **tools installed from the internet at build time** (Dockerfile `go install @latest`, curl|sh), deserialization.
- **A09 Security Logging & Monitoring Failures:** auth/security event logging (currently minimal → hands to C), log injection, sensitive data in logs.
- **A10 SSRF:** the scan engine fetches attacker/operator-supplied URLs (target fetch, screenshots, webhooks to Slack/Discord); prior SSRF gate work — verify completeness.

### Phase 2 — Adversarial verification
Every Phase-1 finding is independently challenged by skeptic agents instructed to **refute** it (default = not-a-real-issue unless reachability/exploitability is demonstrated). Majority-refuted findings are dropped. This is essential because auditing inherited reNgine code surfaces many plausible-but-unreachable candidates. Only confirmed findings proceed to triage.

## 4. Triage model

Each confirmed finding is tagged:
- **OWASP category** (A01–A10).
- **Severity** — Critical / High / Medium / Low.
- **Fix-risk** — **SAFE** (non-breaking: security headers, cookie flags, output escaping, input validation, permission tightening) vs **RISKY** (auth-flow changes, dependency/Django upgrade, rate-limiting, any behavioral change).
- **Reachability/exploitability evidence** (the artifact from Phase 2).

## 5. Fix application — staged by risk

- **SAFE fixes** → applied automatically in **coherent batches** (e.g., "security headers + cookie flags", "input validation", "permission tightening"). Each batch is verified live before moving on: `manage.py check`, the **authenticated legacy smoke test** (login + page crawl + shared-API + static), and finding-specific checks. Committed on a branch → PR → merge when green.
- **RISKY fixes** → **not applied**. Presented to the user with: the finding, the proposed remediation, and the blast-radius. On explicit approval, applied + verified in their own batch/PR. The Django/deps upgrade (A06) is treated as its own risky item.
- The live deployment is re-verified after each SAFE batch (the legacy UI must stay 100% functional; a scan may be running — never restart celery mid-scan).

## 6. Guardrails (anti-regression)

- **Django security settings** (the SAFE subset) enabled behind env flags so dev/HTTP keeps working: `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_HSTS_*`, `SECURE_REFERRER_POLICY`, `X-Frame-Options` (already on), and a tightened CSP where feasible.
- **CI checks:** add `manage.py check --deploy` and `pip-audit` to the pipeline — fail on new misconfiguration or newly-vulnerable deps.
- **Security regression test:** assert key security headers are present on responses and that protected endpoints require auth.

## 7. Deliverables

1. **Audit report** (`docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md`): every finding mapped to OWASP 2021 category, severity, status (fixed/staged/accepted), and evidence.
2. **Fix PR(s):** SAFE fixes (merge when green); RISKY fixes as separate, individually-approved PRs.
3. **Guardrails** wired into CI + settings + a regression test.

## 8. Risks & constraints

- **False positives** from inherited reNgine code → mitigated by the Phase-2 adversarial verification.
- **Breaking the live app** → mitigated by staging by risk + live verification after each SAFE batch + never auto-applying RISKY fixes.
- **Resource limits** (3.8 GB box; a scan may be running) → tooling/agents are read-only in Phase 0–2; fixes verified without restarting celery mid-scan.
- **Django 3.2.23 upgrade** is the single largest RISKY item; it may warrant its own spec/plan if the audit confirms it's needed.

## 9. Out of scope / explicitly deferred

- Initiative A (dashboard widgets) and Initiative C (AI attack detection + blocking).
- Penetration testing of third-party scan tools themselves (nmap, nuclei, etc.).
- Infrastructure/host hardening beyond the app and its container/compose config.
