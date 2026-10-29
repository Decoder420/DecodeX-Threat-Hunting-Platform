# Changelog & Security Hardening History

All notable changes, architectural enhancements, and security hardening milestones for DecodeX Threat Hunting Platform.

---

## [Unreleased]

### Breaking Changes
- **Enforced Non-Static Role Credentials**: `TH_ADMIN_PASSWORD`, `TH_ANALYST_PASSWORD`, and `TH_VIEWER_PASSWORD` no longer have static default values in `docker-compose.yaml` or `.env.example`. Directly invoking `docker compose up` without these variables set will now fail loud with an explicit error message. For local setup, run `./scripts/first-run.sh` to generate high-entropy 24-character credentials automatically, or define non-empty values manually in `.env`.
- **Existing Deployments Unaffected**: The backend user seeding logic (`backend/src/th/db.py:865-875`) checks if accounts already exist in the database; existing deployments with an initialized database preserve their existing password hashes and will not overwrite credentials unless explicit, different passwords are provided in `.env`.

### Repository Hygiene & Structure
- **Embedded Submodule Gitlink Purged**: Removed broken gitlink pointer (`DecodeX-Threat-Hunting-Platform/`, mode 160000) from root tree and ignored nested clone directories via `.gitignore`.
- **Documentation & Script Reorganization**:
  - Moved `DecodeX_Platform_Report.pdf` and `DecodeX_User_Guide.pdf` to `docs/` and purged obsolete `Threat_Hunting_Platform_*.pdf` legacy assets.
  - Moved `merge-nonbreaking.sh` to `scripts/merge-nonbreaking.sh` with updated execution paths.
  - Moved `sample_yara_rule.txt` to `docs/examples/sample_yara_rule.txt`.
  - Dropped hardcoded, out-of-date test counts badge from `README.md`.
  - Updated PDF generation utilities (`generate_project_report.py`, `generate_user_guide_pdf.py`) to output directly to `docs/`.

### Reporting Enhancements
- **Enterprise Report Templates**:
  - Added timezone-aware datetime rendering (`tz_name`) to incident reports (`incident_report.py`) and dynamic web scan executive summaries (`web_scanner_report.py`).
  - Added configurable company name header and footer ribbons.
  - Added standardized 3-column verification and sign-off blocks (Lead Security Assessor, SOC Lead / Reviewer, CISO / Authorization) on incident and web security reports.

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
