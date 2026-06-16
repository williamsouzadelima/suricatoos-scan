# Changelog

All notable changes to Suricatoos are documented in this file.

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
