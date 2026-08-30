# Changelog & Security Hardening History

All notable changes, architectural enhancements, and security hardening milestones for DecodeX Threat Hunting Platform.

---

## [2.1.0] - 2026-08-30 (Phase Next: Post-Verification Upgrade)

### Security Hardening & Secret Protection
- **Authenticated Web Scanning**: Implemented token-based and form-based authenticated crawling in OWASP ZAP. Target credentials are encrypted at rest using Fernet symmetric encryption (`cryptography`) and never exposed in plaintext or logged.
- **Login Rate Limiting**: Added sliding-window rate limiting on `/api/auth/login` (configurable via `AUTH_RATE_LIMIT_MAX` and `AUTH_RATE_LIMIT_WINDOW`) returning RFC-compliant HTTP 429 with `Retry-After` headers to prevent credential stuffing and brute-force attacks.
- **Structured JSON Logging & Secret Redaction**: Replaced unstructured string logging with machine-readable structured JSON format containing ISO-8601 UTC timestamps, logger names, and source lines. Integrated automated regex-based redaction filters that scrub Bearer tokens, API keys, and passwords from all log sinks.
- **System Health Probing**: Created `/api/health` providing real-time database latency, background thread liveness, and security scanner reachability (OWASP ZAP 2.17.0, YARA engine, built-in analyzers). Aligned Docker Compose healthcheck probes directly to this endpoint.
- **Continuous Integration Guardrails**: Added `.github/workflows/ci.yml` running backend test suites, frontend unit tests (`CI=true npm test`), production compilation (`npm run build`), and static grep guardrails detecting wildcard CORS regressions, unexpanded compose passwords, and leaked legacy secrets.
- **Git History Hygiene Runbook**: Authored `docs/GIT_HISTORY_SCRUB_RUNBOOK.md` detailing step-by-step instructions for permanently purging rotated historical secrets (legacy admin password, legacy ZAP key) across past commit objects using `git-filter-repo`.

### Architecture & Scanner Engine
- **Scan Policy Control**: Supported ZAP scan policy configurations (`QUICK`, `BASELINE`, `STANDARD`, `THOROUGH`, `DEEP`) mapping directly to ZAP alert thresholds (`HIGH`, `MEDIUM`, `LOW`) and attack strengths (`LOW`, `MEDIUM`, `HIGH`).
- **Scan Diffing & Comparison**: Enabled real scan comparison via `/api/web-scans/<id>/compare/<other_id>` reporting new, resolved, and persistent findings across scan runs.
- **Target Safety Isolation**: Strict distinction between `lab` environment (allowing controlled active scanning against dedicated containers) and `production` environment (strictly enforcing passive spidering and non-destructive inspection).

---

## [2.0.0] - 2026-08-29 (Audit & Verification Phase)

### Fabricated Data Purge
- **Zero-Demo Telemetry**: Completely excised client-side synthetic log generators (`setInterval` + `Math.random`) and hardcoded IP pools from the HUD telemetry stream. Implemented genuine empty states when real ingestion drains are inactive.
- **Dynamic Threat Geography**: Removed all hardcoded adversaries, fake percentages, and fabricated targets (`iuis.in`, `newskothri.com`) from `Dashboard.js`. Connected all charts and KPIs to live backend alert aggregations.
- **Attack Surface Tree Live Wiring**: Eliminated mock file trees; website hierarchy is now dynamically populated exclusively by spidered URLs and discovered endpoints from real scanner engines.

### Security Hardening
- **CORS Restriction**: Removed wildcard (`*`) origins. `ALLOWED_ORIGINS` strictly controls CORS across REST endpoints and Socket.IO namespaces.
- **SSRF Defense**: Enforced strict URL parsing, DNS resolution validation, and private RFC-1918 / loopback range blocking on target creation unless explicit lab mode is enabled.
- **RBAC Enforcement**: Hardened 3 distinct roles (`admin`, `analyst`, `viewer`). Enforced strict endpoint permissions and user management safeguards (preventing admin self-demotion or orphan lockouts).
- **Timezone Canonicalization**: Standardized all datetime columns to naive UTC across SQLite/PostgreSQL, eliminating timezone skew in alert queries and Socket.IO payloads.
- **Canonical Status Enums**: Unified scan state machines across backend and frontend to standardized status codes (`COMPLETED`, `PARTIAL`, `RUNNING`, `FAILED`, `CANCELLED`, `INTERRUPTED`).
