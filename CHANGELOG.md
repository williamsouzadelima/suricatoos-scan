# Changelog

All notable changes to Suricatoos are documented in this file.

## Unreleased

### Security

- **Command-injection hardening across the scan engine.** Target hosts and
  user-editable engine-YAML config (proxies, wordlists, ports, extensions, custom
  headers, nuclei tags/templates/severities, API keys, gf patterns, dork fields)
  are now allowlisted, `shlex.quote`d (for `shell=True` tools) or argv-filtered (for
  `shell=False` tools) before reaching a command line. The scan-target host is also
  re-validated at every intake path (`store_url`/`store_domain`/`store_ip`, the
  add-target views) so a URL such as `http://user:$(id)@example.com/` can no longer
  persist a `Domain.name` carrying shell metacharacters. The secret-scan engine got
  the same treatment (gitleaks/ggshield/SpiderFoot, GitGuardian token handling).
- **Behavior change:** for the `shell=False` tools (nuclei, httpx, dalfox, crlfuzz),
  custom headers whose *value* contains an internal space (e.g.
  `Authorization: Bearer <token>`) are dropped, since they cannot be passed as a
  single argv token. Use a space-free value or the affected header on a `shell=True`
  tool (ffuf, fetch_url), which are unaffected.

## v2.2.0

- Initial public release of Suricatoos: a web-based automated reconnaissance
  platform with scan engines, subdomain discovery, port scanning, endpoint
  enumeration, vulnerability scanning, OSINT, scheduling and reporting.
- **Secret scanning** via the `secret_scan` engine, powered by gitleaks and
  ggshield, detecting hardcoded secrets (passwords, API keys, tokens) in
  collected scan artifacts. Findings are stored in the `LeakedSecret` model with
  values masked — the raw secret is never persisted. Enabled by default in the
  "Full Scan" and "Suricatoos Recommended" engines.
- **SpiderFoot** as an opt-in OSINT module, enabled via the
  `osint.enable_spiderfoot` engine setting.
- A **Secrets** tab and a "Secrets Discovered" summary card on the scan detail
  page, plus a `listLeakedSecrets` API endpoint.
- A **GitGuardian API key** field in Settings → API for the ggshield scanner
  (falls back to the `GITGUARDIAN_API_KEY` environment variable).
