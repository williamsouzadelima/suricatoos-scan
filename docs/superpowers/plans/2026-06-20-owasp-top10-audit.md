# OWASP Top 10 Audit + Staged Fixes + Guardrails — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit the whole Suricatoos codebase against OWASP Top 10 (2021), fix the gaps (safe fixes auto-applied & verified live, risky fixes gated on approval), and add guardrails so the controls don't silently regress.

**Architecture:** Hybrid audit — deterministic SAST tools anchor the facts (deps, config, crypto, injection patterns), per-category multi-agent review covers the judgment-heavy categories, adversarial verification kills false positives. Findings are triaged by category × severity × fix-risk; fixes ship in verified batches; guardrails land in CI + settings + a regression test.

**Tech Stack:** Django 3.2.23 (Python 3.10 in the `web` container), `manage.py test` (Django TestCase, NOT pytest), Docker Compose (bind-mounted `web/`), GitHub Actions CI, Workflow tool for multi-agent phases. SAST: `pip-audit`, `bandit`, `semgrep`, `manage.py check --deploy`.

## Global Constraints

- Django stays **3.2.23** unless an upgrade is explicitly approved (A06 risky item). `pydyf==0.1.1`, `wafw00f==2.2.0` are pinned for runtime reasons — do not bump.
- The **legacy Django UI is the only UI** (SPA removed). Every fix must keep it 100% functional (verified via the authenticated legacy smoke test).
- The app is **single-tenant**: authorization is global RBAC (`HasPermission`/rolepermissions), no object-level ownership; `?project=` is a UI filter, not a security boundary. Do NOT "fix" `?project=` as if it were IDOR.
- `web/` is **bind-mounted** into `web` + `celery`; a scan may be running — **never restart celery mid-scan**; verify the web layer without bouncing workers.
- Security settings must be **env-flagged** so dev/HTTP and the CI test runner keep working; real users reach the app via the nginx HTTPS proxy (443).
- Tests run via `python manage.py test tests.<module>` from `/usr/src/app` in the `web` container.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `web/Suricatoos/settings.py` | env-flagged security settings (cookies, headers, HSTS, proxy-ssl-header) | Modify (append a security block) |
| `web/tests/test_security_headers.py` | regression test: security headers + cookie flags + protected endpoints require auth | Create |
| `.github/workflows/tests.yml` | add `check --deploy` + `pip-audit` steps + run the new test module | Modify |
| `docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md` | the audit report (findings → category/severity/status/evidence) | Create + fill during audit |
| (orchestration only) | Phase 1/2 multi-agent review via the Workflow tool — no source file | n/a |

Findings artifacts (Phase 0 tool output, Phase 1/2 JSON) live under `/tmp/owasp-audit/` during the run and are summarized into the report — they are not committed.

---

## Task 1: Audit Phase 0 — SAST tooling baseline

**Files:**
- Create: `/tmp/owasp-audit/phase0/` (tool outputs, not committed)
- Create: `docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md` (scaffold)

**Interfaces:**
- Produces: `phase0/*.txt|json` tool reports + a report scaffold with the 10 category headers, consumed by Tasks 2–3.

- [ ] **Step 1: Install the SAST tools in the web container (ephemeral, no image change)**

Run:
```bash
docker exec suricatoos-web-1 sh -c 'pip3 install --quiet pip-audit bandit "semgrep<2" 2>&1 | tail -2'
```
Expected: installs succeed (or note any that fail; semgrep is optional — if it won't install, proceed without it and record that in the report).

- [ ] **Step 2: Run the deterministic scanners, capturing output to the host**

Run (each writes to `/tmp/owasp-audit/phase0/`):
```bash
mkdir -p /tmp/owasp-audit/phase0
# A06 — vulnerable/outdated deps
docker exec suricatoos-web-1 sh -c 'cd /usr/src/app && pip-audit -r requirements.txt -f json 2>/dev/null' > /tmp/owasp-audit/phase0/pip-audit.json
# A05 — security misconfiguration
docker exec suricatoos-web-1 sh -c 'cd /usr/src/app && DEBUG=0 python3 manage.py check --deploy 2>&1' > /tmp/owasp-audit/phase0/check-deploy.txt
# A03/A02 — injection + weak crypto
docker exec suricatoos-web-1 sh -c 'cd /usr/src/app && bandit -r . -x ./tests,./static -f txt 2>/dev/null' > /tmp/owasp-audit/phase0/bandit.txt
# broad patterns (skip gracefully if semgrep absent)
docker exec suricatoos-web-1 sh -c 'cd /usr/src/app && command -v semgrep >/dev/null && semgrep --config p/django --config p/owasp-top-ten --json 2>/dev/null || echo SEMGREP_ABSENT' > /tmp/owasp-audit/phase0/semgrep.json
```
Expected: four files populated. `check-deploy.txt` should list `security.W*` warnings (missing SECURE_*/cookie flags) — that is expected and feeds Task 4.

- [ ] **Step 3: Create the audit report scaffold**

Write `docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md` with one section per OWASP 2021 category (A01–A10), each containing: `**Status:** pending`, a `Tool findings` subsection (paste the relevant Phase-0 lines), and an empty `Verified findings` table with columns `ID | Description | Severity | Fix-risk | Evidence | Status`.

- [ ] **Step 4: Commit the scaffold**

```bash
cd /root/suricatoos && git add docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md
git commit -m "docs(owasp): Phase 0 SAST baseline + report scaffold"
```

## Task 2: Audit Phase 1 + 2 — per-category review + adversarial verification

**Files:**
- Create: `/tmp/owasp-audit/findings.json` (not committed)

**Interfaces:**
- Consumes: Task 1 Phase-0 outputs (seed each category agent with its tool lines).
- Produces: `findings.json` — array of `{id, category, title, file, line, description, severity, exploitability, fix_risk}` for adversarially-confirmed findings, consumed by Task 3.

- [ ] **Step 1: Run the Phase-1 review as a Workflow (one agent per A01–A10)**

Use the Workflow tool. Each agent reviews the whole `web/` codebase for one OWASP 2021 category, is seeded with that category's Phase-0 tool lines and the Global Constraints (single-tenant RBAC, command-exec, URL-fetch, secrets-in-DB), and returns a structured finding list (schema: `{title, file, line, severity, description, why_reachable, proposed_fix, fix_risk}`). Directed focus per category exactly as in the spec §3 Phase 1.

- [ ] **Step 2: Run the Phase-2 adversarial verification as a Workflow (pipeline)**

Pipeline each Phase-1 finding through ≥2 skeptic agents instructed to REFUTE it (default `refuted=true` unless reachability/exploitability is demonstrated, respecting the single-tenant model so cross-project `?project=` is NOT treated as IDOR). Keep only findings that survive (majority not-refuted). Write survivors to `/tmp/owasp-audit/findings.json`.

- [ ] **Step 3: Sanity-check the survivor set**

Run:
```bash
python3 -c "import json; d=json.load(open('/tmp/owasp-audit/findings.json')); print('confirmed:', len(d)); import collections; print(collections.Counter(f['category'] for f in d))"
```
Expected: a per-category count; every category has an explicit count (0 is a valid, recordable result).

## Task 3: Triage + fill the audit report

**Files:**
- Modify: `docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md`

**Interfaces:**
- Consumes: `findings.json` (Task 2).
- Produces: the completed report; each finding carries `Fix-risk = SAFE|RISKY`, consumed by Tasks 4–7.

- [ ] **Step 1: Populate each category's Verified findings table** from `findings.json`, setting `Status = staged-safe` or `staged-risky` per `fix_risk`, and set each category header `**Status:**` to `no-issue` / `has-findings`.

- [ ] **Step 2: Add a top-of-report summary table** (counts by severity and by fix-risk) and an "Accepted risks" section for anything intentionally not fixed (with rationale).

- [ ] **Step 3: Commit the triaged report**
```bash
cd /root/suricatoos && git add docs/superpowers/specs/2026-06-20-owasp-top10-audit-report.md
git commit -m "docs(owasp): triaged audit findings (category/severity/fix-risk)"
```

## Task 4: SAFE fix — env-flagged security settings + regression test (TDD)

This is the highest-value predictable safe fix (A05/A02/A07) and doubles as the guardrail's regression target. Do it TDD-first.

**Files:**
- Create: `web/tests/test_security_headers.py`
- Modify: `web/Suricatoos/settings.py` (append a security block near the other globals, after `ALLOWED_HOSTS`)

**Interfaces:**
- Produces: settings `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, `CSRF_COOKIE_SAMESITE`, `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_REFERRER_POLICY`, and (proxy-gated) `SECURE_PROXY_SSL_HEADER`, `SECURE_HSTS_*`; asserted by the test in Task 6's CI step.

- [ ] **Step 1: Write the failing test**

Create `web/tests/test_security_headers.py`:
```python
from django.test import TestCase, override_settings
from django.conf import settings


class SecuritySettingsTests(TestCase):
    """OWASP A05/A02/A07 — security headers & cookie flags are configured."""

    def test_cookie_flags_present(self):
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, 'Lax')
        self.assertEqual(settings.CSRF_COOKIE_SAMESITE, 'Lax')

    def test_secure_header_settings(self):
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertEqual(settings.SECURE_REFERRER_POLICY, 'same-origin')

    @override_settings(SECURE_CONTENT_TYPE_NOSNIFF=True)
    def test_nosniff_header_on_response(self):
        resp = self.client.get('/login/')
        self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')

    def test_protected_page_requires_auth(self):
        # an unauthenticated request to a protected legacy page must not 200
        resp = self.client.get('/scanEngine/default/', follow=False)
        self.assertIn(resp.status_code, (301, 302))  # redirected to /login
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
docker exec suricatoos-web-1 sh -c 'cd /usr/src/app && python3 manage.py test tests.test_security_headers -v 2 2>&1 | tail -20'
```
Expected: FAIL on `test_cookie_flags_present` / `test_secure_header_settings` (AttributeError or wrong value — settings not yet defined).

- [ ] **Step 3: Add the security block to settings.py**

Append after `ALLOWED_HOSTS = ['*']` (around line 43):
```python
# --- Security hardening (OWASP A05/A02/A07) -------------------------------
# Env-flagged so dev/HTTP and the CI test runner keep working. Real users reach
# the app through the nginx HTTPS proxy (443); Secure cookies apply there.
_SECURE_COOKIES = env.bool('SURICATOOS_SECURE_COOKIES', default=not DEBUG)
SESSION_COOKIE_SECURE = _SECURE_COOKIES
CSRF_COOKIE_SECURE = _SECURE_COOKIES
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
# nginx terminates TLS — trust its X-Forwarded-Proto so request.is_secure()/HSTS
# work without Django itself doing the http->https redirect (nginx already does).
if env.bool('SURICATOOS_BEHIND_TLS_PROXY', default=not DEBUG):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_HSTS_SECONDS = env.int('SECURE_HSTS_SECONDS', default=31536000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
# NOTE: SECURE_SSL_REDIRECT stays OFF — nginx owns the http->https redirect; turning
# it on in Django would break internal :8000 health checks and the smoke tests.
```

- [ ] **Step 4: Run the test to verify it passes**

Run:
```bash
docker exec suricatoos-web-1 sh -c 'cd /usr/src/app && python3 manage.py test tests.test_security_headers -v 2 2>&1 | tail -20'
```
Expected: PASS (4 tests). If `test_nosniff_header_on_response` fails because `manage.py test` runs with `DEBUG=False` and the test client doesn't set the header, the SecurityMiddleware adds `X-Content-Type-Options` when `SECURE_CONTENT_TYPE_NOSNIFF=True` — confirm SecurityMiddleware is first in MIDDLEWARE (it is).

- [ ] **Step 5: Verify the live legacy UI still works (Secure cookies are now on in prod-mode)**

Run the authenticated legacy smoke test **via the HTTPS proxy (443)** (Secure cookies are not sent over plain :8000 once enabled). Confirm login + dashboard + one DataTable page all 200. If the live container runs with `DEBUG=1` (dev compose), `_SECURE_COOKIES` defaults False and :8000 http still works — check `docker exec suricatoos-web-1 printenv DEBUG` and pick the right transport for the smoke test.

- [ ] **Step 6: Commit**
```bash
cd /root/suricatoos && git add web/Suricatoos/settings.py web/tests/test_security_headers.py
git commit -m "fix(security): env-flagged cookie/header hardening + regression test (OWASP A05/A02/A07)"
```

## Task 5: SAFE fix batches — remaining confirmed safe findings

**Files:** per-finding (each batch touches the files named in its findings).

**Interfaces:** Consumes the `SAFE` findings from the Task 3 report.

- [ ] **Step 1: Group the SAFE findings into coherent batches** by theme (e.g., "output escaping / XSS", "input validation", "permission tightening", "logging hygiene"). Record the batch list in the report.

- [ ] **Step 2: For each batch — apply the fix, with a test where the finding is testable.** Where a finding has a reproducible vector, write a failing test first (Django TestCase under `web/tests/`), apply the fix, confirm it passes. Where it is a config/hardening change, apply and assert via `manage.py check`.

- [ ] **Step 3: After each batch — verify live.** Run `manage.py check` + the authenticated legacy smoke test (correct transport per Task 4 Step 5) + the finding-specific check. The legacy UI must stay 100% functional.

- [ ] **Step 4: Commit each batch** with a message naming the OWASP category and the batch theme; update the finding `Status` to `fixed` in the report.

## Task 6: Guardrails — CI checks + run the security test

**Files:**
- Modify: `.github/workflows/tests.yml` (the "🔬 Security tests" job)

**Interfaces:** Consumes the test from Task 4; adds deterministic gates.

- [ ] **Step 1: Add steps to the `security-tests` job** (after the existing test step). Insert:
```yaml
      - name: 🔧 Django deploy-config check (OWASP A05)
        run: |
          cd web
          DEBUG=0 SURICATOOS_SECURE_COOKIES=1 SURICATOOS_BEHIND_TLS_PROXY=1 \
          python manage.py check --deploy --fail-level WARNING
      - name: 📦 Dependency vulnerability audit (OWASP A06)
        run: |
          pip install pip-audit
          pip-audit -r web/requirements.txt || true   # report-only initially; flip to gating after the A06 backlog is cleared
```
(Use the same Python/Django setup the existing job already establishes; match its checkout/setup steps.)

- [ ] **Step 2: Add the security-headers test module to the existing test run.** Change the `manage.py test ...` line to include `tests.test_security_headers`:
```
            manage.py test tests.test_command_injection tests.test_secret_scan tests.test_nmap tests.test_security_headers -v 2
```

- [ ] **Step 3: Commit**
```bash
cd /root/suricatoos && git add .github/workflows/tests.yml
git commit -m "ci(security): add check --deploy + pip-audit gates + security-headers test (OWASP guardrails)"
```

- [ ] **Step 4: Open the PR for the SAFE-fix + guardrails branch** (`feat/owasp-audit`), let CI run, merge when green (per the standing pattern), verify live.

## Task 7: RISKY fixes — present for approval

**Files:** none yet (presentation only).

**Interfaces:** Consumes the `RISKY` findings from the Task 3 report.

- [ ] **Step 1: For each RISKY finding, write an approval brief**: the finding + evidence, the proposed remediation, the blast-radius (what could break), and a rollback note. The Django/deps upgrade (A06) gets its own brief and, if approved, its own spec/plan.

- [ ] **Step 2: Present the briefs to the user and STOP.** Do not apply any RISKY fix without explicit per-item approval.

- [ ] **Step 3: On approval — apply each in its own branch/PR**, with a failing test where possible, verified live, merged when green.

---

## Self-Review

**Spec coverage:** ✅ §1 success criteria → Tasks 3 (status per category) + 4/5 (safe fixes) + 7 (risky) + 6 (CI). §3 methodology Phase 0/1/2 → Tasks 1/2. §4 triage → Task 3. §5 staged fixes → Tasks 4/5 (safe) + 7 (risky). §6 guardrails → Tasks 4 (settings+test) + 6 (CI). §7 deliverables → report (Tasks 1/3) + PRs (Tasks 6/7). §8 risks (false-positive, breakage, scan-running, Django upgrade) → Task 2 (adversarial), Task 4/5 Step "verify live", Global Constraints (no celery restart), Task 7 (Django upgrade gated).

**Placeholder scan:** the per-finding fix CODE in Tasks 5/7 is intentionally not literal — fixes are data-dependent on the audit, which is the nature of an audit; the *protocol* (failing test → fix → verify-live → commit) and exact verification commands ARE concrete. The predictable parts (settings, test, CI YAML) carry exact code. No "TBD/handle edge cases" placeholders in the deterministic tasks.

**Type consistency:** settings names in Task 4 (`SESSION_COOKIE_SECURE`, etc.) match the test assertions (Task 4 Step 1) and the CI env in Task 6 (`SURICATOOS_SECURE_COOKIES`, `SURICATOOS_BEHIND_TLS_PROXY`). Report path is consistent across Tasks 1/3 and the spec.
