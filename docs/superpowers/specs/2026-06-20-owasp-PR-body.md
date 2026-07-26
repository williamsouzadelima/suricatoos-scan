## OWASP Top 10 (2021) audit + staged SAFE fixes + guardrails

Hybrid audit of the whole codebase (SAST tools + 10 per-category finder agents + 2-skeptic adversarial verification), then the SAFE fixes applied in verified batches, plus an adversarial review of the fixes themselves. The 5 RISKY findings are documented for separate approval — **none applied here**.

### Audit
- 22 candidates → **20 confirmed**, 2 refuted (single-tenant model respected: `?project=` is not IDOR; SPA/JWT dead code excluded; command-exec sinks already hardened).
- 3 High · 11 Medium · 6 Low. Full report: `docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md`.

### SAFE fixes (applied, tested, verified live)
| OWASP | Fix |
|---|---|
| A01 | Result-listing DRF viewsets → `ReadOnlyModelViewSet`; `@has_permission_decorator` on `change_vuln_status` |
| A02 | Keep the Django `SECRET_KEY` out of the Docker image (`web/.dockerignore` + `rm`) |
| A03 | `htmlEncode`/`jsEscape` scan-derived strings in result tables + GPT/port modals |
| A04/A06/A10 | SSRF gate on WAF/CMS detectors; web-path fetch timeouts; `cve_id` validation; WeasyPrint `url_fetcher` |
| A05/A07 | Baseline CSP; env-driven `ALLOWED_HOSTS`; 8h session; `validate_password()` on admin/onboarding |
| A09 | Redact h8mail breach creds in logs + delete the raw report |

Incidental latent-bug fixes: `_` gettext-shadowing in WAF/CMS detectors (500 on reject), `change_vuln_status` 500-on-missing-id, login-signal robustness, and a `test_nmap` import-scope `logging.disable` that polluted the whole test session.

### Guardrails
- New regression tests wired into CI: `test_access_control`, `test_security_headers` (CSP/session/cookies), `test_osint_logging`, `test_ssrf_fetch_guard`, `test_password_policy`.
- CI already gates `check --deploy --tag security --fail-level WARNING` + `pip-audit`.

### Verification
- **103/103 unit tests green**; `check --deploy --tag security` exit 0; bandit B113 (requests-without-timeout) 17→4; live legacy UI healthy after every batch.
- **Adversarial review of the fixes** (9 agents): 7/7 batches sound; 1 regression caught & fixed (line breaks in the attack-surface modal).

### NOT in this PR — RISKY, await per-item approval
A07-1 (CSRF state-changing GET — recommend approving), A04-1 (sync `task.wait` DoS), A04-3/A07-3 (login lockout → initiative C), A08-3 (build-time download checksums), Django 3.2.23 upgrade. See `docs/superpowers/specs/2026-06-20-owasp-risky-fix-briefs.md`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
