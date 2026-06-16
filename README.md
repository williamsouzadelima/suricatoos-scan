<h1 align="center">Suricatoos</h1>

<p align="center">
  <b>Automated reconnaissance & attack surface management framework</b><br>
  Subdomain discovery · port scanning · endpoint enumeration · vulnerability scanning · reporting
</p>

<p align="center">
  <a href="https://github.com/williamsouzadelima/suricatoos/releases"><img src="https://img.shields.io/badge/version-v1.0.0-informational" alt="Version" /></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-red.svg" alt="License" /></a>
</p>

---

## Overview

**Suricatoos** is a web-based automated reconnaissance platform for security
researchers, bug bounty hunters and pentesters. It orchestrates a customizable
pipeline of recon tools and presents the results through a clean dashboard, with
scheduling, scan engines, and exportable reports.

> ⚠️ Use Suricatoos only against assets you are explicitly authorized to test.

## Features

- **Scan engines** — fully customizable YAML-based recon workflows
- **Subdomain discovery** with multiple sources and aggregation
- **Port scanning** and service detection
- **Endpoint / directory enumeration** and screenshotting
- **Vulnerability scanning** (template-based) with severity triage
- **Secret scanning** — detect hardcoded secrets & credentials (gitleaks + GitGuardian ggshield)
- **OSINT** gathering (emails, metadata, leaked credentials, optional SpiderFoot integration)
- **Scheduled & recurring scans**
- **PDF/HTML reporting** with multiple templates
- **Project-based** organization and role-based access

## Requirements

- 4GB+ RAM (8GB recommended)
- 50GB+ disk
- Docker & Docker Compose
- Linux host recommended

## Quick install

```bash
git clone https://github.com/williamsouzadelima/suricatoos && cd suricatoos
sudo ./install.sh
```

The installer generates TLS certificates, builds the containers and brings the
stack up. Once finished, open `https://127.0.0.1` and log in with the
super-user created during install.

### Manual (make)

```bash
make certs      # generate TLS certificates
make build      # build images
make up         # start the stack
make username   # create an admin user
```

Useful targets: `make down`, `make restart`, `make logs`, `make pull`.

## Configuration

Application and infrastructure settings live in `.env` (database credentials,
super-user, domain name, concurrency). Default scan-engine definitions are in
`default_yaml_config.yaml` and editable in-app under **Scan Engines**, including
the `secret_scan` (gitleaks/ggshield) and `osint.enable_spiderfoot` sections.

The GitGuardian API key used by the `ggshield` secret scanner can be set in-app
under **Settings → API**, or via the optional `GITGUARDIAN_API_KEY` in `.env`
(see `.env.example`); it is only required for ggshield.

## Updating

```bash
./update.sh
```

## Contributing

Contributions are welcome — see `.github/CONTRIBUTING.md`. Pick an
[open issue](https://github.com/williamsouzadelima/suricatoos/issues) or propose a new one.

## Security

Found a vulnerability? Please follow the responsible-disclosure process in
`.github/SECURITY.md` instead of opening a public issue.

## License

Suricatoos is released under the **GNU General Public License v3.0**.
See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details and attribution.

> Note: replace `williamsouzadelima` throughout this repository with your own GitHub
> organization/username before publishing.
