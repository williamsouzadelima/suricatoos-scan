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
- **Residual injection sinks closed (post-hardening audit, 2026-06-17).** A
  follow-up adversarial audit found gaps the first pass missed; all are now fixed:
  - **(Critical) nmap newline RCE.** `is_valid_nmap_command` blocked shell
    metacharacters but not `\n`/`\r`/`\t`; `str.split()` hid a newline-injected
    command from the per-token check, letting engine-YAML `port_scan.nmap_cmd` /
    `nmap_script` / `nmap_script_args` run a second command under `shell=True`.
    The validator now rejects all control characters up front.
  - **(High) nmap flag smuggling.** The validator accepted *any* dash-prefixed
    token, allowing `-oN`/`-oG`/`-oA`/`--datadir`/`--script <path>` (arbitrary file
    write / NSE execution). It now enforces an explicit nmap-flag allowlist, and the
    three nmap fields are allowlisted at intake (no `/`, control chars or leading
    dash; NSE scripts restricted to bare names).
  - **(High) httpx flag smuggling.** Directly-passed URLs reaching `http_crawl`
    were interpolated unquoted into a `shell=False` httpx command; they are now
    filtered through `validators.url`, so a URL embedding ` -store-response-dir …`
    can no longer smuggle a flag.
  - **(Medium) nuclei template path traversal.** `_filter_list` skipped the `..`
    guard that `_allow`/`SAFE_PATH_RE` promised, so `templates: [../../../etc/passwd]`
    passed. `_filter_list` now enforces the same `..`/control-char guard.
  - Hardening regexes switched from `^…$` to `\A…\Z` (the `$` anchor also matched
    before a trailing newline, so `"80\n"` slipped through and was returned verbatim).
  - The nmap host, theHarvester `-d` and netlas host args now reject a leading dash
    (`SAFE_HOST_ARG_RE`); the nmap host is additionally `shlex.quote`d.
- **CI:** build/CodeQL workflows now trigger on `main` (they were pinned to the
  non-default `master`, so PR builds and static analysis never ran), and a new
  `tests.yml` job runs the command-injection and secret-scan suites on every PR.

## v1.0.0

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
