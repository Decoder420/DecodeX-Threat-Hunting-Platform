# Full platform delivery report

This report summarizes the multi-phase upgrade of the Threat Hunting Platform into a coherent SOC / threat-hunting modular monolith.

## What was delivered

### Auth & RBAC (Phases 1–3)
- Username/password + hashed passwords + revocable session tokens
- Explicit permissions + `@require_permission`
- Admin user management (create/role/activate/deactivate/reset password)
- Last-admin protection + audit on login/logout

### Role UI (Phase 4)
- React Router + Sidebar + ProtectedRoute
- Routes: dashboard, alerts, hunting, cases, intelligence, webscan, reports, admin/users, admin/audit, admin/console
- Viewer: read-only; Analyst: no admin; Admin: full

### Ingestion & normalization (Phases 5–6)
- Background log watcher with offset tracking
- Expanded Event schema (event_type, ingested_at, dest IP/port, url, parent/pid…)
- `/api/ingestion/status` + `/api/ingestion/run`

### Detection / MITRE / alerts / correlation / risk (Phases 7–11)
- Extended hunting rules (encoded/hidden PowerShell)
- Alert `risk_score`, `confidence`, normalized severity
- MITRE tactic/technique retained and shown in UI
- Correlation engine → `CorrelatedIncident` timelines
- Deterministic risk scoring using severity, IOC, asset criticality, correlation

### Assets / IOC / cases / timeline / audit (Phases 12–16)
- Asset inventory with demo hosts (DC-01, WEB-01, PC-01…)
- Enriched IOC fields + CRUD API
- Case model + notes + create-from-alert
- Richer alert_context timeline + IOC matches
- AuditLog append-only + admin audit page

### Web scanner / SOAR / reports / dashboard (Phases 17–20)
- Authorized safe web scanner (TLS/headers/cookies)
- SOAR remains simulated, permissioned, audited, labeled SIMULATION MODE
- PDF reports preserved (authenticated token query)
- Dashboard KPIs expanded (events, critical/high, cases, assets, IOC, web findings)

## How to run

```powershell
# Backend
cd D:\manan\Threat-Hunting-Platform\backend
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="src"
python -m th.webapp

# Frontend
cd D:\manan\Threat-Hunting-Platform\frontend
npm start
```

Accounts: see `backend/.env` (`admin` / `analyst` / `viewer`).

## Demo script

1. LOGIN as admin → sidebar shows Admin Users / Audit / Console  
2. RBAC → logout → login as viewer → no Admin / Cases write / Web Scan run  
3. LIVE LOG → append NDJSON line to `backend/data/logs/sample.log` → watcher ingests  
4. DETECTION → encoded PowerShell rule fires  
5. IOC MATCH → use `185.220.101.1` / seeded IOC  
6. ALERT → appears via Socket.IO on dashboard  
7. CORRELATION → open Cases → Incidents timeline  
8. CASE → Alerts page → Create Case  
9. SOAR → incident panel Isolate Host (SIMULATION)  
10. AUDIT → Admin Audit shows login/SOAR entries  
11. REPORT → Reports page → PDF  

## Known limitations

- SOAR is simulation only  
- Web scanner is passive/safe-active only  
- Correlation is host/user/IP time-window heuristic  
- SQLite single-node (fine for Master's demo)  
- Not a claim of production hardening (MFA, WAF, HA, etc.)
