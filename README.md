# 🚨 Threat Hunting Platform (SIEM)

A full-stack cybersecurity platform that simulates real-world Security Operations Center (SOC) workflows including:

- Log ingestion (multi-source)
- Sigma-based detection rules
- IOC matching (IP, domain, hash)
- Alert generation & deduplication
- Case management system
- MITRE ATT&CK mapping
- Real-time dashboard (WebSocket)
- Anomaly detection (baseline vs deviation)

---

## 🧱 Architecture

Frontend: React (Splunk-like UI)  
Backend: Flask + SQLAlchemy  
Detection Engine: Custom rule evaluator + Sigma parser  
Data Sources: Logs, API ingestion, IOC feeds  

---

## ⚙️ Features

- 🔍 Threat Detection using Sigma-like rules
- 🌐 IOC Feed Integration (Abuse.ch style)
- 📊 Splunk-style Dashboard with filters
- 🚨 Real-time alerts via WebSocket
- 📁 Case Management System
- 🧠 Anomaly Detection Engine
- 🛡 MITRE ATT&CK mapping

---

## 🚀 Setup

### Backend

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
PYTHONPATH=src python3 -m th.webapp
```

On first run, if `TH_ADMIN_PASSWORD` isn't set in your environment, the app
generates a random admin password and prints it once to the console — copy
it down, you'll need it to log in as `admin`. To set your own instead:

```bash
TH_ADMIN_PASSWORD='your-strong-password' PYTHONPATH=src python3 -m th.webapp
```

The backend listens on port 5000 by default (`PORT=5001` is what `npm start`
uses via `package.json`).

### Frontend

```bash
cd siem-ui
npm install
npm start
```

Set `REACT_APP_API_URL` in `siem-ui/.env.local` (gitignored — never commit
`.env`) if the backend isn't at the default `http://127.0.0.1:5001`.

### Both at once

```bash
npm install
npm start   # runs backend + frontend concurrently, see package.json
```

---

## 🔐 Authentication

Login is real: the frontend calls `POST /api/auth/login` with a
username/password, the backend checks it against a hashed password in the
`users` table, and issues a random session token stored server-side
(`auth_tokens` table) with a 12-hour expiry. There is no shared static
token — every session is tied to a real account and can be revoked.

To add more analyst accounts:
```bash
PYTHONPATH=src python3 setup_admin.py
```

## 📡 API Example

```
POST /api/ingest_logs
Authorization: Bearer <token from /api/auth/login>
```

## ⚠️ Known limitations (as of this cleanup pass)

- `/api/soar/action` is a **simulated** response — it does not call a real
  firewall/EDR yet. It says `"status": "simulated"` in the response so this
  is never mistaken for a real action downstream.
- Single-tenant: the `users` table has an `org_id` column reserved for
  future multi-tenant support, but no tenant isolation is enforced yet.
- The dev server (`python -m th.webapp`) is not a production WSGI server —
  use `gunicorn` + `eventlet` (or similar) behind a reverse proxy for
  real deployments, and set `ALLOWED_ORIGINS` to your real frontend domain.

---

## 📸 Screenshots

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Alerts
![Alerts](screenshots/alerts.png)

### Timeline
![Timeline](screenshots/timeline.png)

---

## 🧠 Skills Demonstrated

- Security Operations (SOC)
- Threat Hunting & Detection Engineering
- SIEM Development
- Python Backend Engineering
- React Dashboard Development
- Data Processing Pipelines
- Cyber Threat Intelligence (CTI)

---

## 📌 Author

Manan Mandal  
Cybersecurity Enthusiast | SOC | Threat Hunting | SIEM Engineering# Threat-Hunting-Platform
# Threat-Hunting-Platform
# Threat-Hunting-Platform
