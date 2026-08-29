# DecodeX — Frontend Documentation

This document describes the **frontend** of DecodeX (by **DecodeX Security Technologies Private Limited**): UI features, pages/components, API client, auth/realtime flows, known gaps, and a recommended professional folder layout that cleanly separates frontend from backend.

---

## 1. Overview

The frontend is a **React Single-Page Application (SPA)** that acts as a SOC / SIEM console for analysts:

1. Authenticates users against the Flask backend  
2. Displays KPIs, alerts, charts, and MITRE context  
3. Receives **live alerts** over Socket.IO  
4. Supports investigation drawers and simulated SOAR actions  
5. Provides an **Admin** view for feeds, users, suppressions, and YARA editing  

| Item | Detail |
|------|--------|
| App folder (current) | `frontend/` |
| Framework | Create React App (`react-scripts` 5) |
| UI library | Custom CSS (not Mantine, despite README mention) |
| Default dev port | `3000` (root script may use `3001`) |
| Backend consumer | Flask API documented in `BACKEND.md` |

---

## 2. Tech Stack

| Layer | Technology |
|-------|------------|
| UI runtime | React 19 |
| Bundler / DX | Create React App (`react-scripts`) |
| HTTP client | Axios |
| Charts | Recharts (+ Chart.js / react-chartjs-2 available) |
| Realtime | socket.io-client |
| Code editor (YARA) | react-simple-code-editor + PrismJS |
| Routing | react-router-dom (installed; **not used** in active App flow) |
| Testing libs | Testing Library + Jest (CRA defaults) |

**Dependencies** (`frontend/package.json`):

```
react, react-dom, react-scripts, axios, recharts, chart.js, react-chartjs-2,
socket.io-client, prismjs, react-simple-code-editor, react-router-dom, web-vitals
```

---

## 3. Current Frontend Layout (separated)

```
frontend/
├── package.json
├── package-lock.json
├── .env.example                 # REACT_APP_API_BASE_URL
├── public/
│   ├── index.html
│   ├── favicon.ico
│   ├── manifest.json
│   ├── robots.txt
│   └── logo*.png
└── src/
    ├── index.js                 # CRA entry (+ some stale axios helpers)
    ├── index.css
    ├── App.js                   # Auth gate + login form + Dashboard mount
    ├── App.css
    ├── api.js                   # Primary Axios client + API helpers
    ├── pages/
    │   ├── Dashboard.js         # ACTIVE main console (dashboard + admin + incident)
    │   ├── Login.js             # Unused alternate login page
    │   └── AdminPanel.js        # Unused; calls obsolete endpoints
    ├── components/
    │   ├── Navbar.js            # ACTIVE
    │   ├── AlertTable.js        # Mostly unused (older modular UI)
    │   ├── KPI.js
    │   ├── Filters.js
    │   ├── TimelineChart.js
    │   ├── MitrePanel.js
    │   ├── AttackMap.js
    │   ├── CaseModal.js         # Case API helper UI (not mounted in Dashboard)
    │   └── AdminPanel.js
    └── styles/
        └── dashboard.css
```

### Active vs leftover UI

| Path | Status | Notes |
|------|--------|-------|
| `App.js` → `pages/Dashboard.js` | **Active** | Real product path |
| `components/Navbar.js` | **Active** | Nav + logout |
| Inline KPI / charts / Admin / Incident in `Dashboard.js` | **Active** | Large single file |
| `pages/Login.js` | Orphan | Login is inlined in `App.js` |
| `pages/AdminPanel.js` | Orphan | Targets dead APIs (`/sigma`, `/ioc/sync`, …) |
| Most `components/*` except Navbar | Orphan / legacy | Useful references for a modular rewrite |

---

## 4. Core Features (Active UI)

### 4.1 Authentication

- Login form in `App.js` (username / password)  
- Calls `POST /api/auth/logout` counterparts via Axios (`/auth/login`)  
- Stores `token` + `user` in `localStorage`  
- Axios request interceptor attaches `Authorization: Bearer <token>`  
- On `401`, token is cleared and the page reloads to login  
- Logout clears storage and can call backend logout  

Roles expected from backend: `viewer`, `analyst`, `admin` (admin gates Admin nav).

### 4.2 SOC Dashboard

Implemented primarily in `pages/Dashboard.js`:

- **Time range** selection for metrics / alerts  
- **Search** across alert content  
- **KPI cards** (counts by severity / status style metrics from `/api/dashboard`)  
- **Alert cards / list** with pagination  
- **Charts**
  - Alert timeline  
  - Severity radar  
  - Top hosts  
  - MITRE tactics distribution (pie)  
- **Live updates**: Socket.IO `new_alert` → toast + merge into list  

### 4.3 Investigation drawer (Incident panel)

Selecting an alert opens an investigation-style panel:

- Alert details (rule, severity, MITRE, host/user/process context)  
- Host timeline via `/api/alert_context/<id>`  
- Simulated **SOAR** actions (isolate / block) via `/api/soar/action`  
- **PDF export** via `/api/report/<id>`  
- Notes / status UI is partially present — full persistence is intended via `/api/alerts/<id>/case` (see gaps; `CaseModal` would call this but is not mounted)

### 4.4 Admin panel (embedded in Dashboard)

Admin-capable users can:

- View / toggle **threat intel feeds**  
- Trigger **feed sync**  
- List **users**  
- Add **suppression** indicators  
- List / open / edit / deploy **YARA** rules (Prism editor)  

### 4.5 Navigation

`Navbar.js`:

- Dashboard  
- Admin (role-gated)  
- Logout  

---

## 5. API Client

Primary client: `frontend/src/api.js`

| Helper | Backend endpoint |
|--------|------------------|
| `getDashboard(range)` | `GET /api/dashboard` |
| `getAlertContext(id)` | `GET /api/alert_context/<id>` |
| `getAdminData()` | `GET /api/admin/data` |
| `toggleFeed(id)` | `POST /api/admin/feed/<id>/toggle` |
| `listYaraRules()` | `GET /api/admin/rules` |
| `getRuleContent(file)` | `GET /api/admin/rules/content` |
| `saveYaraRule(file, content)` | `POST /api/admin/rules/save` |
| `addSuppression(indicator)` | `POST /api/admin/suppressions/add` |
| `syncFeeds()` | `POST /api/admin/feeds/sync` |
| `executeSoarAction(action, target)` | `POST /api/soar/action` |

### Backend URL configuration (important)

API / Socket.IO base URL is env-driven:

```js
process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:5000"
```

Used in:

- `frontend/src/api.js`  
- `frontend/src/pages/Dashboard.js`  

Copy `frontend/.env.example` → `frontend/.env` to override. There is **no** CRA `"proxy"` field; the browser calls the absolute API origin (CORS must allow it).

---

## 6. App Flow

```text
index.js
   └── App.js
         ├── no token → Login form (inline)
         └── token present → Dashboard.js
                               ├── Navbar
                               ├── Dashboard view (KPIs, charts, alerts)
                               ├── Admin view (feeds, users, YARA, suppressions)
                               └── Incident drawer (context, SOAR, PDF)
                               └── Socket.IO ← backend new_alert
```

```text
Browser                Frontend                     Backend
  |                       |                            |
  |-- login -----------> api.js --- POST /auth/login ->|
  |<- token ------------|                            |
  |-- dashboard -------> getDashboard --------------->|
  |<- alerts/KPIs ------|                            |
  |<- socket new_alert -|<---- Socket.IO -------------|
  |-- open alert ------> getAlertContext ------------>|
  |-- SOAR / PDF ------> soar / report --------------->|
```

---

## 7. How to Run (Frontend Only)

Prerequisites: Node.js 16+, backend running (see `BACKEND.md`).

```bash
cd frontend
npm install
npm start
# → http://localhost:3000
```

Login with the backend admin credentials (`TH_ADMIN_PASSWORD` / seeded user).

Optional root orchestration: from repo root run `npm start` (`concurrently` starts `backend` + `frontend`).

---

## 8. Gaps / Technical Debt (Frontend)

1. **Monolithic `Dashboard.js`** — dashboard, admin, charts, and incident UI in one file.  
2. **Orphan components/pages** — `Login.js`, page/component `AdminPanel`, `CaseModal`, chart helpers unused.  
3. **Case management UI incomplete** — case API exists; `CaseModal` not wired into active Dashboard.  
4. **react-router-dom unused** — navigation is local state, not routes (`/login`, `/dashboard`, `/admin`).  
5. **README historically claimed Mantine UI** — not present in dependencies.  
6. **Orphan AdminPanel endpoints** — Sigma upload / old IOC sync paths do not match current backend.  
7. Stale helpers in `index.js` still mention port `5001`.

---

## 9. Recommended Professional Folder Structure (Next-Level Modular Frontend)

Top-level separation is already done (`frontend/` beside `backend/`). Next step: modularize inside `frontend/src`.

### Recommended monorepo layout

```text
Threat-Hunting-Platform/
├── README.md
├── BACKEND.md
├── FRONTEND.md                     # this file
├── package.json                    # workspace / concurrently only
├── .gitignore
│
├── backend/                        # see BACKEND.md
│   └── ...
│
└── frontend/                       # <<< ALL UI lives here
    ├── README.md
    ├── package.json
    ├── .env.example                # REACT_APP_API_BASE_URL=...
    ├── public/
    │   └── index.html
    ├── src/
    │   ├── main.jsx                # or index.js
    │   ├── App.jsx
    │   ├── routes/
    │   │   └── AppRoutes.jsx       # /login /dashboard /admin
    │   ├── api/
    │   │   ├── client.js           # axios instance + interceptors
    │   │   ├── auth.js
    │   │   ├── dashboard.js
    │   │   ├── alerts.js
    │   │   └── admin.js
    │   ├── features/
    │   │   ├── auth/
    │   │   │   ├── LoginPage.jsx
    │   │   │   └── AuthContext.jsx
    │   │   ├── dashboard/
    │   │   │   ├── DashboardPage.jsx
    │   │   │   ├── KpiRow.jsx
    │   │   │   ├── AlertList.jsx
    │   │   │   └── charts/
    │   │   ├── investigation/
    │   │   │   ├── IncidentDrawer.jsx
    │   │   │   ├── HostTimeline.jsx
    │   │   │   ├── CaseForm.jsx
    │   │   │   └── SoarActions.jsx
    │   │   ├── admin/
    │   │   │   ├── AdminPage.jsx
    │   │   │   ├── FeedsPanel.jsx
    │   │   │   ├── UsersPanel.jsx
    │   │   │   ├── SuppressionsPanel.jsx
    │   │   │   └── YaraEditor.jsx
    │   │   └── realtime/
    │   │       └── useAlertSocket.js
    │   ├── components/             # shared presentational only
    │   │   ├── Navbar.jsx
    │   │   ├── Spinner.jsx
    │   │   └── EmptyState.jsx
    │   ├── hooks/
    │   ├── styles/
    │   │   ├── tokens.css
    │   │   └── dashboard.css
    │   └── utils/
    │       └── format.js
    └── tests/
```

### Why this structure

| Principle | Benefit |
|-----------|---------|
| Top-level `frontend/` next to `backend/` | Clear separation of concerns |
| Feature folders (`features/auth`, `features/admin`, …) | Matches SOC workflows; easier ownership |
| Thin `api/` modules | One place for endpoint contracts |
| Real router routes | Shareable URLs, cleaner auth gates |
| Env-based API base URL | Local / staging / ngrok without code edits |
| Shared `components/` only for generics | Avoid dumping all UI into `Dashboard.js` |
| Delete or archive orphans | Less confusion for new contributors |

### Next incremental cleanup

1. Mount `CaseModal` / case API for real case workflow  
2. Split `Dashboard.js` into feature folders  
3. Enable `react-router-dom` routes  
4. Remove unused pages/components or move to `_legacy/`  

### Suggested frontend run scripts (after separation)

```bash
cd frontend
npm install
copy .env.example .env   # Windows
npm start
```

Root optional script:

```json
{
  "scripts": {
    "dev": "concurrently \"npm:dev:backend\" \"npm:dev:frontend\"",
    "dev:backend": "cd backend && .venv\\Scripts\\python -m th.webapp",
    "dev:frontend": "cd frontend && npm start"
  }
}
```

---

## 10. Frontend ↔ Backend Contract (Summary)

| UI capability | Backend dependency |
|---------------|--------------------|
| Login / logout / session | `/api/auth/*` |
| Dashboard KPIs & alerts | `/api/dashboard` |
| Investigation timeline | `/api/alert_context/<id>` |
| Case updates | `/api/alerts/<id>/case` |
| Live toast / merge | Socket.IO event `new_alert` |
| SOAR buttons | `/api/soar/action` (simulated) |
| PDF download | `/api/report/<id>` |
| Admin feeds / users / YARA / suppressions | `/api/admin/*` |

Full API tables live in **`BACKEND.md`**.

---

## 11. Recommended Cleanup Checklist (Frontend)

- [x] Rename `siem-ui` → `frontend`  
- [x] Use `REACT_APP_API_BASE_URL` (default local `5000`)  
- [ ] Wire case management UI to `/api/alerts/<id>/case`  
- [ ] Split `Dashboard.js` into feature modules  
- [ ] Use React Router for `/login`, `/dashboard`, `/admin`  
- [ ] Remove or archive unused `Login.js` / AdminPanel / dead components  
- [ ] Align README UI stack text with actual libraries  
- [x] Keep root `package.json` orchestration-only

---

## 12. Related Documents

- **Backend features, APIs, detection pipeline:** `BACKEND.md`  
- **Product overview / setup:** `README.md`  
- **Long-form writeup:** `FULL_PROJECT_REPORT.md`
