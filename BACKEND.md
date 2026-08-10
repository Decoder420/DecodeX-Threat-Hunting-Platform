# Threat Hunting Platform — Backend Documentation

This document describes the **backend** of the Threat Hunting Platform: architecture, modules, APIs, data model, detection pipeline, configuration, and a recommended professional folder layout that cleanly separates backend from frontend.

---

## 1. Overview

The backend is a **Python SOC / SIEM API** that:

1. Ingests security logs (local NDJSON files + HTTP webhooks)
2. Normalizes and stores events in **SQLite**
3. Evaluates events against **YAML hunting rules**, **YARA**, and **IOC** watchlists
4. Enriches alerts with **MITRE ATT&CK** context
5. Exposes a **REST API** and **Socket.IO** real-time channel for the React SIEM UI
6. Supports **RBAC**, case workflow, threat feeds, suppressions, and PDF reports

| Item | Detail |
|------|--------|
| Primary entrypoint | `backend/src/th/webapp.py` |
| CLI batch hunter | `backend/src/th/main.py` |
| Package root | `backend/src/th/` |
| Default API port | `5000` (`PORT` env override) |
| Database | `backend/threat_hunting.db` (SQLite) |
| Live UI consumer | React app in `frontend/` (see `FRONTEND.md`) |

---

## 2. Tech Stack

| Layer | Technology |
|-------|------------|
| Web framework | Flask 2.x |
| Realtime | Flask-SocketIO (threading mode) |
| CORS | Flask-CORS |
| ORM / DB | SQLAlchemy 2 + SQLite |
| Auth | Werkzeug password hashes + opaque DB session tokens |
| Rules | PyYAML (`hunting_rules.yml`) |
| Pattern matching | yara-python |
| Threat intel HTTP | requests |
| CLI formatting | Rich |
| PDF reports | ReportLab |
| Tests | `tests/test_pipeline.py` |

**Dependencies** (`requirements.txt`):

```
Flask, Flask-Cors, Flask-SocketIO, Flask-Sock, PyYAML, requests,
rich, reportlab, yara-python, SQLAlchemy
```

---

## 3. Current Backend Layout (separated)

```
Threat-Hunting-Platform/
├── backend/
│   ├── requirements.txt
│   ├── hunting_rules.yml              # YAML detection rules
│   ├── sigma_sample.yml               # Sample Sigma rule
│   ├── sample_payload.json            # Sample ingest payload
│   ├── setup_admin.py                 # Seed users / feeds
│   ├── generate_mass_data.py          # Demo event/alert generator
│   ├── generate_project_report.py
│   ├── generate_user_guide_pdf.py
│   ├── rules/
│   │   └── threat_rules.yar           # Extra YARA (not auto-loaded today)
│   ├── data/
│   │   └── logs/                      # NDJSON log sources
│   ├── tests/
│   │   └── test_pipeline.py
│   └── src/th/                        # Python package
│       ├── webapp.py                  # Flask + SocketIO API server
│       ├── main.py                    # CLI batch hunt
│       ├── pipeline.py                # Ingest → detect → persist
│       ├── db.py                      # Models + session
│       ├── rule_evaluator.py
│       ├── scanner.py
│       ├── anomaly.py                 # Heuristics (unused by API today)
│       ├── feed_collector.py
│       ├── sigma_importer.py
│       ├── rules/webshell_detect.yar
│       └── templates/                 # Legacy Jinja UI (orphaned)
└── frontend/                          # see FRONTEND.md
```

> **Note:** Flask Jinja templates under `backend/src/th/templates/` are **legacy**. The active product UI is the React app (`FRONTEND.md`).

---

## 4. Core Features

### 4.1 Multi-source log ingestion

| Source | How |
|--------|-----|
| Local files | `data/logs/*.log` (NDJSON), offset-tracked via `IngestionState` |
| Manual / webhook JSON | `POST /api/ingest_logs`, `POST /api/ingest/manual` |
| Machine ingest (API key) | `POST /api/ingest/vercel` with `X-Ingest-Key` |
| CLI batch | `python -m th.main` (with `PYTHONPATH=src`) |

Pipeline steps (`pipeline.py`):

1. Read / accept log records  
2. Normalize → `Event`  
3. Optional **YARA** annotation on command lines  
4. Deduplicate by fingerprint  
5. Evaluate YAML rules + IOC sets  
6. Apply **suppression rules**  
7. Persist **alerts** and broadcast via Socket.IO  

### 4.2 Persistent storage (SQLite models)

Defined in `src/th/db.py`:

| Model | Purpose |
|-------|---------|
| `Event` | Normalized telemetry (host, user, process, commandline, IP, domain, hash, source, raw) |
| `Alert` | Detection output + MITRE + case fields (status, assignee, notes) |
| `IOC` | Indicators of compromise (IP / domain / hash) |
| `User` | Accounts with roles: `viewer` &lt; `analyst` &lt; `admin` |
| `AuthToken` | Bearer session tokens (~12h) |
| `IngestKey` | Machine-to-machine ingest keys (`thk_…`) |
| `SuppressionRule` | Noise reduction for known-benign indicators |
| `FeedSource` | External threat-intel feed URLs + enabled flag |
| `IngestionState` | Per-file read offset for incremental ingest |

Default admin is seeded using `TH_ADMIN_PASSWORD` (or a one-time random OTP printed at startup). Default feed sources include Abuse.ch / ThreatFox-style lists.

### 4.3 Rule-based detection (YAML)

File: `hunting_rules.yml`

Condition types (`rule_evaluator.py`):

- `event_field_contains`
- `ioc_ip_match`
- `ioc_domain_match`
- `ioc_hash_match`

Example rule families present in the repo:

- Advanced / encoded PowerShell  
- Brute-force failed logins  
- Admin login + IOC IP  
- LOLBin abuse  
- Beaconing / C2-style patterns  
- Malware hash match  
- Lateral movement (SMB)  
- Privilege escalation  
- Exfiltration  
- Scheduled-task persistence  

Alerts carry **severity**, **description**, **technique_id**, and **tactic** (MITRE).

### 4.4 YARA scanning

- Loader: `scanner.py`  
- Auto-loaded directory: `src/th/rules/*.yar` (e.g. `webshell_detect.yar`)  
- Root `rules/threat_rules.yar` exists but is **not** automatically loaded today  
- Admin APIs can list / read / save YARA files under the rules directory  

### 4.5 IOC correlation & threat feeds

- Seeded / synced IOCs stored in `iocs`  
- `feed_collector.py` downloads enabled TXT feeds into IOC table  
- Admin can toggle feeds and trigger sync (`/api/admin/feeds/sync`)  

### 4.6 Sigma importer

- `sigma_importer.py` converts Sigma YAML into local rule dicts  
- Can write into `hunting_rules.yml` via helper functions  
- **No live HTTP route** currently exposes Sigma import in `webapp.py` (legacy UI expected this)

### 4.7 Anomaly heuristics

- `anomaly.py` implements spike / odd-hour login / rare PowerShell style checks  
- Imported in CLI path historically; **not wired into the live API pipeline** today  

### 4.8 Authentication & RBAC

| Role | Capabilities (typical) |
|------|------------------------|
| `viewer` | Read dashboard / alerts |
| `analyst` | Case updates, ingest, suppressions, SOAR simulate |
| `admin` | Users, feeds, rules, ingest keys, debug (if enabled) |

Auth endpoints:

- `POST /api/auth/login` → `{ token, user }`  
- `POST /api/auth/logout`  
- `GET /api/auth/me`  

Decorators: `@login_required`, `@admin_required`, `@role_required(...)`, `@ingest_key_required`.

### 4.9 Case management

`POST /api/alerts/<id>/case` updates:

- Status: `Open` / `In Progress` / `False Positive` / `Resolved`  
- Assignee  
- Investigation notes  

### 4.10 Simulated SOAR

`POST /api/soar/action` — isolate / block style actions are **simulated** for demo / training (not real endpoint enforcement).

### 4.11 PDF incident reports

`GET /api/report/<alert_id>` — ReportLab PDF download (token/query auth as implemented).

### 4.12 Realtime alerts

Flask-SocketIO emits `new_alert` so the frontend can toast / merge new detections without refresh.

### 4.13 Admin operations

- List dashboard admin payload (feeds, users, suppressions, etc.)  
- Toggle / sync threat feeds  
- Add suppressions  
- Manage YARA rule files  
- CRUD-ish user role / deactivate  
- Create / revoke ingest API keys  

---

## 5. API Reference

Base path: `/api`  
Auth header: `Authorization: Bearer <token>`  
Ingest key header: `X-Ingest-Key: thk_...`

### Auth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | Public | Login |
| POST | `/api/auth/logout` | User | Revoke token |
| GET | `/api/auth/me` | User | Current user |

### SIEM / investigation

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/dashboard?range=` | User | KPIs, alerts, chart series (`1h`…`1Y`) |
| GET | `/api/alert_context/<id>` | User | ±30m host timeline around alert |
| POST | `/api/alerts/<id>/case` | Analyst+ | Case status / assignee / notes |
| POST | `/api/ingest_logs` | Analyst+ | JSON log ingest |
| POST | `/api/soar/action` | Analyst+ | Simulated response action |
| GET | `/api/report/<id>` | Token/query | PDF report |

### Admin / detection engineering

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/admin/data` | Admin | Admin panel payload |
| POST | `/api/admin/feed/<id>/toggle` | Admin | Enable/disable feed |
| POST | `/api/admin/suppressions/add` | Analyst+ | Add suppression |
| GET | `/api/admin/rules` | Admin | List YARA files |
| GET | `/api/admin/rules/content` | Admin | Read YARA content |
| POST | `/api/admin/rules/save` | Admin | Save YARA content |
| POST | `/api/admin/feeds/sync` | Admin | Pull IOC feeds |
| GET/POST | `/api/admin/users` | Admin | List / create users |
| POST | `/api/admin/users/<id>/role` | Admin | Change role |
| POST | `/api/admin/users/<id>/deactivate` | Admin | Deactivate user |
| GET/POST | `/api/admin/ingest_keys` | Admin | List / create keys |
| POST | `/api/admin/ingest_keys/<id>/revoke` | Admin | Revoke key |

### Ingest

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/ingest/vercel` | Ingest key | Log-drain style ingest |
| POST | `/api/ingest/manual` | Analyst+ | Manual JSON / raw text |

### Debug

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/debug/trigger_alert` | Admin + `TH_ENABLE_DEBUG_ROUTES=true` | Force test alert |

### CORS / origins

Controlled by `ALLOWED_ORIGINS` (or defaults for `localhost:3000` / `3001` and ngrok-style origins). Credentials allowed for cookie/token SPA usage.

---

## 6. Data Flow

```text
[data/logs/*.log] ──┐
[HTTP ingest APIs] ─┼──► pipeline.ingest_* ──► normalize ──► YARA annotate
[CLI th.main] ──────┘                              │
                                                   ▼
                                               events (SQLite)
                                                   │
                    IOC feeds ──► iocs ────────────┤
                    hunting_rules.yml ─────────────┤
                                                   ▼
                                         rule_evaluator + suppressions
                                                   ▼
                                               alerts (SQLite)
                                                   │
                                   ┌───────────────┼───────────────┐
                                   ▼               ▼               ▼
                              REST /dashboard   Socket.IO      PDF /report
                                   │            new_alert
                                   ▼
                            React SIEM UI (frontend)
```

---

## 7. Environment Variables

| Variable | Purpose |
|----------|---------|
| `PORT` | API listen port (default `5000`) |
| `TH_ADMIN_PASSWORD` | Initial / seeded admin password |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins |
| `TH_FLASK_DEBUG` | Flask debug mode |
| `TH_ENABLE_DEBUG_ROUTES` | Expose debug alert trigger |

---

## 8. How to Run (Backend Only)

```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
pip install -r requirements.txt

set TH_ADMIN_PASSWORD=YourStrongPassword
set PYTHONPATH=src
python -m th.webapp
# → http://127.0.0.1:5000
```

Optional helpers:

```bash
cd backend
python setup_admin.py
python generate_mass_data.py
set PYTHONPATH=src
python -m th.main
```

---

## 9. Gaps / Technical Debt (Backend)

1. Legacy Jinja templates are unused — keep only if you plan a server-rendered UI.  
2. `anomaly.py` is not integrated into the live pipeline.  
3. Sigma importer has no HTTP route in current `webapp.py`.  
4. Root `rules/threat_rules.yar` is not auto-loaded (only `src/th/rules/`).  
5. Prefer consolidating YARA under one directory and loading it consistently.  
6. Optionally split monolithic `webapp.py` into `api/` route modules (see §10).

---

## 10. Recommended Professional Folder Structure (Next-Level Modular Backend)

Top-level separation is already done (`backend/` beside `frontend/`). Next step: modularize inside `backend/` (split `webapp.py`, clarify `app/` package).

### Recommended monorepo layout

```text
Threat-Hunting-Platform/
├── README.md
├── BACKEND.md                          # this file
├── FRONTEND.md
├── package.json                        # optional: concurrently start both
├── .gitignore
│
├── backend/                            # <<< ALL backend lives here
│   ├── README.md                       # backend-only quickstart
│   ├── requirements.txt
│   ├── pyproject.toml                  # optional (modern Python packaging)
│   ├── .env.example
│   ├── hunting_rules.yml
│   ├── sigma_sample.yml
│   ├── sample_payload.json
│   ├── alembic/                        # optional migrations later
│   ├── data/
│   │   └── logs/
│   ├── rules/                          # shared/extra YARA packs
│   ├── scripts/
│   │   ├── setup_admin.py
│   │   ├── generate_mass_data.py
│   │   └── generate_reports.py
│   ├── tests/
│   │   ├── unit/
│   │   └── integration/
│   └── app/                            # rename from src/th (clearer)
│       ├── __init__.py
│       ├── main.py                     # CLI
│       ├── wsgi.py / asgi entry
│       ├── api/
│       │   ├── __init__.py
│       │   ├── auth.py
│       │   ├── dashboard.py
│       │   ├── alerts.py
│       │   ├── ingest.py
│       │   ├── admin.py
│       │   └── soar.py
│       ├── core/
│       │   ├── config.py
│       │   ├── security.py
│       │   └── socketio.py
│       ├── db/
│       │   ├── session.py
│       │   └── models.py
│       ├── services/
│       │   ├── pipeline.py
│       │   ├── rule_evaluator.py
│       │   ├── scanner.py
│       │   ├── feed_collector.py
│       │   ├── sigma_importer.py
│       │   ├── anomaly.py
│       │   └── reporting.py
│       └── detection/
│           └── yara/
│               └── webshell_detect.yar
│
└── frontend/                           # <<< React SIEM (see FRONTEND.md)
    ├── package.json
    └── src/
```

### Why this structure

| Principle | Benefit |
|-----------|---------|
| Top-level `backend/` + `frontend/` | Clear ownership, CI, and onboarding |
| `api/` split by domain | Smaller files than a monolithic `webapp.py` |
| `services/` for business logic | Keeps HTTP layer thin |
| `db/models` + optional Alembic | Safer schema evolution than ad-hoc SQLite edits |
| `scripts/` outside package | One-off tools don’t pollute importable package |
| Single rules home under `detection/` | Avoid dual `rules/` vs `src/th/rules/` confusion |
| Remove orphaned `templates/` (or archive) | Avoid dual-UI confusion |

### Path note

`db.py` / `pipeline.py` resolve project root as `Path(__file__).parents[2]`, which is now correctly `backend/` (DB + `hunting_rules.yml` live there).

### Suggested backend run scripts

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
set PYTHONPATH=src
python -m th.webapp
```

---

## 11. Backend Module Map (Quick Reference)

| Module | Responsibility |
|--------|----------------|
| `webapp.py` | HTTP routes, auth decorators, Socket.IO, CORS |
| `pipeline.py` | Ingest, normalize, evaluate, persist, broadcast |
| `db.py` | SQLAlchemy models, engine, seed helpers |
| `rule_evaluator.py` | YAML rule loading + matching |
| `scanner.py` | YARA compile/scan |
| `feed_collector.py` | Pull external IOC lists |
| `sigma_importer.py` | Sigma conversion |
| `anomaly.py` | Heuristic detectors (unused in API) |
| `main.py` | Offline/CLI hunt runner |

---

## 12. Related Documents

- **Frontend features & UI structure:** `FRONTEND.md`  
- **Product overview / setup:** `README.md`  
- **Long-form writeup:** `FULL_PROJECT_REPORT.md`
