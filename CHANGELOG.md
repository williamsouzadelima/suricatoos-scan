# Changelog

All notable changes to Suricatoos are documented in this file.

## v1.1.0

- Add **secret scanning** via the new `secret_scan` engine, powered by gitleaks
  and ggshield, detecting hardcoded secrets (passwords, API keys, tokens) in
  collected scan artifacts. Findings are stored in the new `LeakedSecret` model
  with values masked — the raw secret is never persisted. Enabled by default in
  the "Full Scan" and "Suricatoos Recommended" engines.
- Add **SpiderFoot** as an opt-in OSINT module, enabled via the
  `osint.enable_spiderfoot` engine setting, integrating 100+ data sources to
  gather intelligence on IPs, domains and emails.
- Add a **Secrets** tab and a "Secrets Discovered" summary card to the scan
  detail page, plus a `listLeakedSecrets` API endpoint.
- Add a **GitGuardian API key** field to Settings → API for the ggshield
  scanner (falls back to the `GITGUARDIAN_API_KEY` environment variable).

## v1.0.0

- Initial Suricatoos release.
- Web-based automated reconnaissance platform: scan engines, subdomain
  discovery, port scanning, endpoint enumeration, vulnerability scanning,
  OSINT, scheduling and reporting.
