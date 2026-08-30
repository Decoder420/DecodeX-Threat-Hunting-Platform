# DecodeX Security Architecture & Policy

## 1. Authentication & Role-Based Access Control (RBAC)

DecodeX enforces database-backed authentication and granular role-based access control across all endpoints:

- **Password Hashing**: Passwords are saved as cryptographic hashes using Werkzeug's `pbkdf2:sha256` implementation with unique per-user salts.
- **Session Tokens**: Stateful, revocable session tokens stored in the `auth_tokens` table. Expired or revoked tokens are immediately rejected across all API calls and Socket.IO handshakes.
- **Three Verified Roles**:
  - **`admin`**: Full administrative access. Can manage users, adjust organizational settings, authorize targets, and view full audit logs. Safeguards prevent self-demotion or deleting the last active admin account.
  - **`analyst`**: Core security workflow access. Can initiate authorized scans, triage findings, promote alerts into cases, annotate investigations, and trigger IOC syncs. Access to `/admin/*` and user management is strictly forbidden (HTTP 403).
  - **`viewer`**: Read-only access. Can inspect dashboards, telemetry streams, and generated incident reports. Prohibited from modifying alerts, starting scans, or updating system configuration.
- **Brute-Force Rate Limiting**: The `/api/auth/login` endpoint is guarded by a sliding-window rate limiter (default: 30 attempts per 60-second rolling window per client IP). Exceeding this threshold returns HTTP 429 `TOO_MANY_REQUESTS` with an RFC-compliant `Retry-After` header.
  > [!NOTE]
  > The rate limiter counter is maintained in-memory per Gunicorn worker process. In multi-worker deployments without sticky load-balancing or external stores (e.g. Redis), the effective request threshold across the cluster scales with the worker count (`worker_count × AUTH_RATE_LIMIT_MAX`).

---

## 2. Web Application Security Scanning Guardrails

The DecodeX web scanner incorporates multi-tiered safety guardrails to ensure scans strictly respect authorization:

- **Target Authorization**: Every scan target must have explicit ownership documentation and formal authorization (`POST /api/web-targets/<id>/authorize`) before scans can be scheduled or executed.
- **Environment Isolation (`lab` vs. `production`)**:
  - **`lab`**: Targets running in dedicated, controlled test environments (e.g. throwaway local containers) permit full active scanning with attack payloads.
  - **`production`**: Production targets enforce non-destructive inspection. Port scanning and ZAP active scanning with aggressive attack vectors are strictly disabled, permitting only passive HTTP/TLS analysis, sitemap probing, and passive spidering.
- **SSRF Prevention**: Scan URLs are strictly validated prior to dispatch. Hostnames are resolved to IP addresses; attempts to target private RFC-1918 ranges, loopback addresses (`127.0.0.1`), link-local metadata addresses (`169.254.169.254`), or broadcast ranges are rejected with `SSRFError` unless explicit lab authorization (`WEBSCAN_ALLOW_PRIVATE_TARGETS=true`) is active.

---

## 3. Authenticated Scanning & Credential Vault

DecodeX supports scanning web applications behind authentication barriers:
- **Authentication Types**: Supports `token` (Bearer / custom header) and `form` (form-based credential login sequences).
- **Encryption at Rest**: Credentials configured on a scan target are encrypted at rest using AES-128-CBC and HMAC-SHA256 authenticated encryption (`cryptography.fernet.Fernet`).
- **Fail-Closed Vault Architecture (No Insecure Fallback)**:
  > [!IMPORTANT]
  > The platform strictly refuses to encrypt or decrypt target credentials unless `ENCRYPTION_KEY` or `SECRET_KEY` is explicitly configured. If both are missing, `VaultConfigurationError` is raised immediately, failing the API request (HTTP 500 `VAULT_NOT_CONFIGURED`) or scan execution loudly. Static or hardcoded default keys are prohibited and completely eliminated.
- **Key Derivation & Rotation Warning**:
  > [!WARNING]
  > The Fernet encryption key is resolved from `ENCRYPTION_KEY`, falling back to `SECRET_KEY` if `ENCRYPTION_KEY` is unset. If tied to `SECRET_KEY`, rotating `SECRET_KEY` without pinning `ENCRYPTION_KEY` will **render all previously-encrypted scan target credentials unrecoverable**. Administrators must configure a dedicated, persistent `ENCRYPTION_KEY` in production environments prior to storing target credentials.
- **Zero Cleartext Leakage**: Target credentials are never logged, never emitted over Socket.IO events, and excluded from public API responses (which only return `has_credentials: true/false`).

---

## 4. Structured Logging & Automated Redaction

Backend logging utilizes a structured JSON formatter (`StructuredJsonFormatter`) with automated sensitive data masking:
- Every log message and exception is filtered through `RedactingFilter`.
- Regex patterns automatically intercept and redact `Bearer [REDACTED_TOKEN]`, `password=[REDACTED_PASSWORD]`, and `apikey=[REDACTED_KEY]` even when debug-level tracing is enabled.

---

## 5. Configuration & Environment Variables

| Variable | Requirement | Description |
| :--- | :--- | :--- |
| `TH_ADMIN_PASSWORD` | **Required** | Administrator password. Sourced from `.env`, never committed to git. |
| `TH_ANALYST_PASSWORD` | **Required** | Security Analyst initial password. |
| `TH_VIEWER_PASSWORD` | **Required** | Viewer initial password. |
| `ALLOWED_ORIGINS` | **Required** | Strict comma-separated list of allowed CORS origins (e.g. `http://localhost`). Wildcards (`*`) are prohibited. |
| `ZAP_URL` | Optional | URL of the OWASP ZAP daemon (default: `http://zap:8080`). |
| `ZAP_API_KEY` | **Required** | API key authenticating requests to the ZAP daemon. |
| `ENCRYPTION_KEY` | **Recommended** | Dedicated symmetric vault key for encrypting scan target credentials at rest. If unset, falls back to `SECRET_KEY`. |
| `SECRET_KEY` | **Required** | Application session secret key. |
| `AUTH_RATE_LIMIT_MAX` | Optional | Maximum failed/total login attempts per window (default: `30`). |
| `AUTH_RATE_LIMIT_WINDOW` | Optional | Rolling window in seconds for login rate limiter (default: `60`). |
| `WEBSCAN_ALLOW_PRIVATE_TARGETS` | Optional | Set to `true` **only** in local isolated labs to permit scanning private containers. Default is `false`. |
| `SQLITE_JOURNAL_MODE` | Optional | SQLite journal mode (`DELETE` on macOS/VirtioFS to prevent file locking issues, `WAL` on Linux production). |

---

## 6. Historical Secret Scrubbing

If legacy test credentials exist in past commit history, follow the verified procedure in [docs/GIT_HISTORY_SCRUB_RUNBOOK.md](file:///Users/manan/Desktop/Projects/Threat-Hunting-Platform/docs/GIT_HISTORY_SCRUB_RUNBOOK.md) to rewrite repository commit objects using `git-filter-repo`.
