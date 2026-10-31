# Web Application Security Scanning

Production-style AppSec module for the Threat Hunting Platform.

## Architecture

```
AUTHORIZED TARGET
  → validation / SSRF
  → HTTP discovery (TLS, headers, cookies)
  → optional crawl
  → optional Nuclei / Nmap / ZAP
  → normalize → dedupe → risk score
  → WebFinding / WebScan / AuditLog / Alert
```

Package: `backend/src/th/web_scanner/`

| Module | Role |
|--------|------|
| `validators.py` | URL normalize + SSRF (DNS validation, redirect scope) |
| `http_discovery.py` | HTTP/TLS/header/cookie/common-file checks |
| `technology.py` | Lightweight fingerprinting |
| `crawler.py` | Bounded same-host crawl |
| `engines.py` | Optional Nuclei / Nmap / ZAP (`shell=False`) |
| `normalizer.py` / `deduplicator.py` / `risk_web.py` | Unified findings |
| `orchestrator.py` | Background jobs, stages, Socket.IO, alerts |
| `config.py` | Profiles + env configuration |

## Attack surface / Website Map

Persisted nodes in `web_scan_nodes` with parent/child relationships.
Realtime Socket.IO events grow the tree while the scan runs:

- `webscan_node_discovered` / `webscan_node_updated`
- `webscan_finding_discovered`
- `webscan_log`
- plus existing `web_scan_*` lifecycle events

API:

- `GET /api/web-scans/<id>/tree`
- `GET /api/web-scans/<id>/events`
- `GET /api/web-targets/<id>/attack-surface`
- `POST /api/web-scans/<id>/resume`
- `GET /api/webscan/health`

Frontend: **Web Security → Website Map** (`/webscan/map`).

## Scan profiles

`QUICK`, `STANDARD`, `DEEP`, `PASSIVE`, `API`, `AUTHENTICATED`, `LAB`, `DEMO`

`DEMO` emits clearly labeled `[DEMO]` synthetic findings for UI rehearsal.
`LAB` / aggressive engines respect `WEBSCAN_PRODUCTION_SAFETY_MODE` and `WEBSCAN_LAB_MODE`.

## Security model

- Scans require `authorization_status == AUTHORIZED` (never PENDING).
- Authorization is an explicit audited `POST .../authorize` with `confirm=true`.
- Creating a target always starts as `PENDING` (client cannot set AUTHORIZED).
- Permissions: `webscan.read`, `webscan.run` (server-side RBAC).
- SSRF: block localhost, loopback, link-local, multicast, metadata, private RFC1918 unless `WEBSCAN_ALLOW_PRIVATE_TARGETS=true`.
- Only `http`/`https`; redirects re-validated; no `shell=True`.
- Resource limits: concurrent scans, timeouts, max URLs/depth/response size, request budget.

## Scan profiles

| Profile | Engines |
|---------|---------|
| QUICK | HTTP/TLS/headers/tech/passive |
| STANDARD | QUICK + crawl + Nuclei (if installed) + ZAP (spider + passive scan only) |
| DEEP | STANDARD + Nmap (lab-gated) + ZAP (spider + passive scan) |
| LAB | Aggressive: ZAP Active Scan (injection fuzzing) + Nmap + Nuclei (requires `safety_mode=lab` or `WEBSCAN_LAB_MODE=true`) |
| PASSIVE | Non-intrusive TLS/headers/sitemap only |
| API | API & OpenAPI endpoint discovery + sitemap |
| AUTHENTICATED | Authenticated crawl with configured auth profile |

Missing binaries are skipped with warnings — scans continue.

### Active Scanning vs. Passive Scanning

By default (`WEBSCAN_PRODUCTION_SAFETY_MODE=true`), active injection scanning (SQL injection, XSS fuzzing, command injection) is strictly safety-gated to prevent accidental disruption of production applications.

- **STANDARD and BASELINE profiles**: Run ZAP in **passive inspection + spider mode only**. These profiles inspect response headers, cookies, TLS certificates, and passive application attributes (e.g. CSP headers, anti-clickjacking, X-Content-Type-Options, timestamp disclosure). They do **not** launch active parameter injection attacks.
- **LAB profile**: Runs ZAP's **Active Scanner** (`ascan`) to fuzz input parameters with injection payloads (verified on OWASP Juice Shop to detect SQL Injection). Users can select the `LAB` profile in the web scan wizard when `WEBSCAN_LAB_MODE=true` or when targeting private lab networks (`WEBSCAN_ALLOW_PRIVATE_TARGETS=true`), or supply `safety_mode="lab"` via the API. Note: Browser-based client-side DOM XSS analysis (Rule 40026) is disabled in the headless daemon container; server-side injection rules (including SQL injection) execute fully.

### Active Scan Budget & Timeout Limits

Active scanning fuzzes multiple parameters with payload variations and can run indefinitely if unbounded. DecodeX enforces a dedicated active scan timeout budget:

- **Default Timeout**: 180 seconds (`WEBSCAN_ACTIVE_TIMEOUT=180` in `.env`, capped by overall `WEBSCAN_TIMEOUT`).
- **Graceful Budget Stop**: If the active scan reaches the timeout deadline before 100% completion, DecodeX stops the active scan cleanly (`ascan/action/stop`), retrieves and stores all alerts discovered up to the budget cutoff, marks the scan status as `PARTIAL`, and records an explicit engine note on the scan (e.g. `ZAP active scan stopped at 79% by 180s budget`).
- **Raising the Budget**: To allow longer active scans on large attack surfaces, set `WEBSCAN_ACTIVE_TIMEOUT=600` (and `WEBSCAN_TIMEOUT=600`) in `.env` and restart the backend service.

### Resources & Hardware Sizing

Active vulnerability scanning with ZAP is CPU and memory intensive. Measured container resource utilization during active scans on OWASP Juice Shop:
- **ZAP Memory Consumption**: ~600 MB to 900 MB RAM (JVM max heap 1 GB).
- **CPU Utilization**: 1 to 2 CPU cores during multi-threaded parameter fuzzing.
- **Minimum Docker Host Allocation**: **4 GB RAM** and **2 CPU cores** allocated to Docker Desktop/Engine to prevent out-of-memory container termination when running the full stack (backend, frontend, proxy, ZAP daemon, and target).

### SPA & API Target Seeding for Active Scans

Single Page Applications (SPAs built with React, Angular, Vue, or Next.js) often expose minimal parameterized links in raw static HTML. To ensure thorough active vulnerability testing:

1. **Crawler & Script Inspection**: DecodeX extracts both page links and script references, parsing JavaScript bundles for relative API endpoints (`/api/...`, `/rest/...`). Generic fuzzable parameters (`test`) replace `${...}` template literals.
2. **Schema & OpenAPI Discovery**: Automatically queries OpenAPI/Swagger schemas (`/api-docs/swagger.json`, `/openapi.json`) and extracts parameterized endpoints.
3. **Sites Tree Pre-Seeding**: Before launching ZAP's active scan engine (`ascan`), DecodeX seeds discovered parameterized endpoints into ZAP's sites tree via ZAP's core access API. Static assets (`.jpg`, `.png`, `.css`, `.js`, `/socket.io/`) are excluded from active fuzzing candidates. This ensures ZAP active scan rules (such as SQL Injection) receive targeted endpoints to fuzz.

## Environment variables

See `backend/.env.example` (`WEBSCAN_*`, `NUCLEI_*`, `NMAP_*`, `ZAP_*`).

## API (selected)

- `GET/POST /api/web-targets`
- `POST /api/web-targets/<id>/authorize`
- `POST /api/web-scans` (async; returns 202)
- `GET /api/web-scans/<id>/progress`
- `POST /api/web-scans/<id>/cancel`
- `GET /api/web-scans/<id>/compare/<other>`
- `GET /api/web-scans/<id>/report?format=json|csv`
- `GET /api/web-findings` / `PATCH /api/web-findings/<id>`
- `GET /api/web/overview`
- `GET /api/web/scanner/engines`
- `GET /api/web/attack-surface`

## Socket.IO events

`web_scan_started`, `web_scan_progress`, `web_scan_stage`, `web_scan_finding`,
`web_scan_completed`, `web_scan_failed`, `web_scan_cancelled`

## Frontend

Sidebar → **Web Security**: Overview, Targets, Scans, Findings, Attack Surface, Scanner Health.

## Risk scoring

Transparent 0–100 score from severity weight × confidence × exposure/criticality factors, with optional CVSS blend. Factors stored on findings as `risk_factors_json`.

## Development / lab

Set `WEBSCAN_ALLOW_PRIVATE_TARGETS=true` only for private lab targets. Never present mock findings as real — unavailable engines show `NOT_INSTALLED` on Scanner Health.
