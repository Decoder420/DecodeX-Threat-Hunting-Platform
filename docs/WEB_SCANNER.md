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
| STANDARD | QUICK + crawl + Nuclei (if installed) |
| DEEP | STANDARD + Nmap + ZAP (if configured) |

Missing binaries are skipped with warnings — scans continue.

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
