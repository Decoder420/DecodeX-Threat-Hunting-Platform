# Architecture

## Stack

```text
React (frontend/)
   ↓ REST + Socket.IO
Flask + Flask-SocketIO (backend/src/th/webapp.py)
   ↓
SQLAlchemy / SQLite (backend/threat_hunting.db)
```

## Data flow

```text
LOG SOURCE (backend/data/logs/*.log)
 ↓ log_watcher (offset via IngestionState)
 ↓ normalize_event_record
 ↓ Event table
 ↓ IOC enrichment + RuleEvaluator + YARA
 ↓ risk.compute_risk_score
 ↓ Alert persist + Socket.IO new_alert
 ↓ correlation.correlate_new_alerts → CorrelatedIncident
 ↓ Case (optional) → SOAR (simulated) → AuditLog
 ↓ React dashboards / role pages
```

## Key modules

| Module | Role |
|--------|------|
| `webapp.py` | Flask app, auth, dashboard, SOAR, PDF, Socket.IO |
| `enterprise_api.py` | Cases, assets, IOC, audit, webscan, events, incidents |
| `pipeline.py` | Ingest, normalize, evaluate, persist |
| `log_watcher.py` | Background tail of log directory |
| `risk.py` | Deterministic 0–100 risk scoring |
| `correlation.py` | Host/user/IP windowed incidents |
| `web_scanner.py` | Authorized safe TLS/header checks |
| `audit.py` | Append-only audit writer |
| `db.py` | Models + seed + migrations |

Modular monolith — no Kafka/Redis/K8s required.
