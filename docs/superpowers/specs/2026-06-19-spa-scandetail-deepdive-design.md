# ScanDetail deep-dive — SPA design

**Date:** 2026-06-19
**Status:** Approved (brainstorming) → implementation plan next
**Branch:** `feat/scandetail-deepdive`

## Summary

The Suricatoos SPA (`/app`, React + Vite + TS, JWT/REST) surfaces scans but not the
recon data a scan produces — endpoints, IPs/ports, screenshots, directories, and
technologies all have backend data but no SPA view. This feature enriches the
**ScanDetail** page (`/app/scans/:id`) with a tab bar that exposes that data,
scoped to the scan.

## Goals

- Add tabs to ScanDetail: **Overview** (existing: status/progress/timeline/counts) +
  **Endpoints**, **Ports & IPs**, **Screenshots**, **Directories**, **Tech**.
- Each tab is scan-scoped (`?scan_history=<id>`), lazy-loaded (fetch only when the
  tab is opened), and deep-linkable via a URL query param (`?tab=endpoints`).
- Follow the established SPA pattern: `ReadOnlyModelViewSet` + lean serializer +
  plain-array JSON (`pagination_class = None`) + client-side TanStack tables.

## Non-goals (out of scope for this batch)

- Top-level project-scoped Endpoints / Leaked Secrets screens (separate effort).
- Real-time/SSE updates (Scans list already polls every 5s).
- A frontend test harness (project has none today; verify live as in prior work).
- shadcn/ui migration.

## Backend — new REST endpoints (`/api/`, JWT, scan-scoped)

All list viewsets follow the existing Spa* pattern: `ReadOnlyModelViewSet`,
`pagination_class = None`, lean serializer, and a list-scope guard
(`if self.action == 'list' and not scan_id: return qs.none()`) so an unscoped GET
never serializes everything. `retrieve` is unaffected.

Route names are plain nouns, consistent with the existing Spa* routes
(`subdomains`, `vulnerabilities`, `scans`, `targets`) and distinct from the legacy
DataTables routes (`listEndpoints`, `listIps`, `listDirectories`), so there is no
collision.

| Route (under `/api/`) | Source model | Filter | Serializer fields |
|---|---|---|---|
| `endpoints/` | `EndPoint` (direct FK `scan_history`) | `?scan_history=` | `id, http_url, http_status, page_title, content_length, content_type, webserver, response_time, is_important` |
| `ips/` | `IpAddress` via `Subdomain.ip_addresses` | `?scan_history=` | `address, is_cdn, geo_iso, ports:[{number, service_name, is_uncommon}]` (nested) |
| `screenshots/` | `Subdomain` with non-empty `screenshot_path` | `?scan_history=` | `subdomain_id, subdomain_name, image_url` |
| `directories/` | `DirectoryFile` via `Subdomain.directories → DirectoryScan.directory_files` | `?scan_history=` | `subdomain_name, name, http_status, length, words, lines` |
| `technologies/` | `Technology` via `Subdomain.technologies` | `?scan_history=` | `name, subdomain_count` |

The `screenshots/` list returns each row's `image_url` pointing at the separate,
distinctly-named image-streaming endpoint below (an `APIView`, not a router route).

### Screenshot image endpoint (auth design)

Screenshots live under `MEDIA_ROOT/scan_results` and are normally served by
`serve_protected_media`, which is `@login_required` (Django **session**) via
`X-Accel-Redirect`. The SPA authenticates with a **JWT Bearer header**, not a
session cookie, so an `<img src="/media/...">` from the SPA would be redirected to
login. Therefore:

- New `GET /api/scan-screenshot/<subdomain_id>/` — DRF view, `IsAuthenticated`
  (accepts JWT). It resolves the file path **from the DB** (`Subdomain.screenshot_path`,
  a trusted value), validates containment under `MEDIA_ROOT` with
  `realpath`/`commonpath` (no request data reaches the filesystem path — same
  barrier used for the branding asset / CodeQL path-injection), and streams the
  image. Returns 404 if the subdomain has no screenshot.
- The SPA fetches this URL via axios with the Bearer header as a **blob** and
  renders it through an object URL (see `<AuthImage>`).

## Frontend

- **`ScanDetail.tsx`** is refactored to a tab layout. The current Overview content
  is extracted into its own component; a tab bar selects the active tab; the active
  tab is stored in a URL search param (`?tab=`) and defaults to `overview`.
- Each non-overview tab is a lazy component using TanStack Query with
  `enabled: activeTab === '<name>'` so data loads only on first open.
- **`<DataTable>` (shared)** — extract a reusable TanStack table component. The four
  tabular tabs (Endpoints, Ports/IPs, Directories, Tech) consume it. The existing
  `Vulnerabilities` and `Subdomains` pages, which currently duplicate table wiring,
  are migrated onto it (focused cleanup that serves this work).
- **`<AuthImage>`** — small component that fetches an image with the JWT Bearer
  header, exposes it via an object URL, and shows loading / error / placeholder
  states. Used by the Screenshots grid (cards of subdomain_name + image). Object
  URLs are revoked on unmount.

## Data flow

SPA (JWT) → `GET /api/<tab>?scan_history=<id>` → plain JSON array → TanStack table
(client-side sort/filter/paginate). Screenshots: list endpoint → grid → each
`<AuthImage>` lazily fetches its blob from `/api/scan-screenshot/<id>/`.

Measured volume: ~2070 endpoints ≈ ~400KB JSON — comfortable for client-side
tables, so no server-side pagination is needed.

## Error handling & security

- Per-tab loading / error / empty states ("No endpoints for this scan").
- Screenshot endpoint: `IsAuthenticated` + `realpath`/`commonpath` containment under
  `MEDIA_ROOT`; 404 when absent.
- List-scope guards (`scan_history` required → `none()`) on every new viewset,
  matching the existing Spa* viewsets (single-tenant: authenticated staff see all
  scan data by design; the guard bounds payload, not authorization).

## Testing

- **Backend:** unit tests per viewset (scan-scope filter, empty-scope guard returns
  `none()`, serializer field shape) + the screenshot endpoint (auth required,
  containment blocks traversal, 404 without a screenshot). Run in the container
  (`docker compose ... manage.py test`), the project's standard.
- **Frontend:** no test harness exists; verify live — `npm run build` clean, then
  open each tab on a real scan with data (the verification approach used for the
  SPA throughout this project).

## Rollout

Feature branch `feat/scandetail-deepdive` → PR against `main` → CI (CodeQL, Analyze,
cmd-injection suite, multi-arch Docker build). The SPA bundle is built by the image
(multi-stage, PR #12), so no committed artifact; `npm run build` is exercised by the
image build. Merge gated on explicit approval.
