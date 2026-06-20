# OWASP Top 10 (2021) Audit Report — Suricatoos

**Date:** 2026-06-20 · **Scope:** whole codebase · **Method:** hybrid (SAST tools + per-category multi-agent review + adversarial verification). See the design spec `2026-06-20-owasp-top10-audit-design.md`.

## Summary (filled during triage — Task 3)

| Category | Status | Confirmed findings | Notes |
|---|---|---|---|
| A01 Broken Access Control | pending | – | |
| A02 Cryptographic Failures | pending | – | |
| A03 Injection | pending | – | command-exec sinks, mark_safe |
| A04 Insecure Design | pending | – | |
| A05 Security Misconfiguration | has-findings | 4 (tool) | cookies/HSTS/headers missing |
| A06 Vulnerable Components | has-findings | ~50 (tool) | risky upgrades → approval gate |
| A07 Auth Failures | pending | – | no lockout (→ initiative C) |
| A08 Integrity Failures | pending | – | pickle, internet tool installs |
| A09 Logging/Monitoring | pending | – | minimal (→ initiative C) |
| A10 SSRF | pending | – | scan-engine URL fetch |

---

## Phase 0 — SAST tool findings (deterministic baseline)

Tool outputs captured under `/tmp/owasp-audit/phase0/`. Seeds the per-category agents (Task 2).

### A05 — Security Misconfiguration (`manage.py check --deploy`)
Baseline (current settings, no `SECURE_*` defined):
- `security.W004` — `SECURE_HSTS_SECONDS` not set.
- `security.W008` — `SECURE_SSL_REDIRECT` not True. *(Design decision: nginx owns the http→https redirect; Django redirect stays OFF — accepted with rationale, documented.)*
- `security.W012` — `SESSION_COOKIE_SECURE` not True.
- `security.W016` — `CSRF_COOKIE_SECURE` not True.
- Also addressed by the fix: `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_REFERRER_POLICY`, `SESSION_COOKIE_HTTPONLY`, SameSite.
- **Fix-risk: SAFE** → Task 4 (env-flagged settings + regression test).

### A06 — Vulnerable & Outdated Components (`pip-audit`, installed env)
~50+ advisories across: `langchain-core` (CVE-2026-26013/40087/44843), `langchain-text-splitters`, `langsmith`, `pyjwt` 2.6.0 (multiple PYSEC-2026), `requests` 2.32.3 (CVE-2024-47081), `weasyprint` 53.3 (CVE-2025-68616), `markdown` 3.3.4, `python-dotenv`, `pyopenssl`, `setuptools` 72.1.0, `pip` 22.0.2. Django 3.2.23 itself to be checked separately.
- **Fix-risk: RISKY** (version bumps can break runtime; `pydyf`/`wafw00f`/`weasyprint` are pinned for reasons) → Task 7 approval briefs. Note: `pyjwt` may now be unused after the SPA/JWT removal — verify (could be a free removal).

### A03 — Injection / A08 — Integrity (`bandit -ll`, 45 issues ≥Medium)
- 20× `B604` + 2× `B602` + 1× `B605` — `shell=True` / subprocess-with-shell in the scan engine. Prior command-injection hardening exists; agents (A03) verify which are reachable with attacker-influenced input vs safe constant commands.
- 3× `B301` — `pickle` deserialization (A08) — confirm the data source is trusted (Celery internal) vs attacker-controlled.
- 1× `B703` + 1× `B308` — `mark_safe()` (A03/XSS) — confirm the marked content can't carry user input.
- 17× `B113` — `requests` without timeout (A04/availability) — low severity, batchable SAFE fix.

### Phase 0 gaps
- `semgrep` deferred (box memory + a scan is running); rerun when the box is idle, fold results into A01/A04/A10.
- `pip-audit -r requirements.txt` fails (needs `python3-venv`); audited the installed environment instead (the versions that actually run).

---

## Verified findings (filled by Task 2 → Task 3)

*Per-category tables (ID | Description | Severity | Fix-risk | Evidence | Status) populated after adversarial verification.*

## Accepted risks
- `SECURE_SSL_REDIRECT=False` in Django — nginx performs the http→https redirect; enabling it in Django breaks internal :8000 health checks/smoke tests. Accepted.
