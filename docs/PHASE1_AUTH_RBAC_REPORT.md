# Phase 1 Report — Authentication & RBAC

**Project:** Threat Hunting Platform  
**Scope completed:** Phase 1 only (authentication + role-based access control)  
**Date:** 2026-08-11  

This document explains what changed, how auth/RBAC works now, and how the rest of the platform fits together so you can demonstrate and continue later phases safely.

---

## 1. Executive summary

Phase 1 upgraded the existing Flask + React SOC app so that:

1. Users sign in with **username/password** (hashed in SQLite).
2. Sessions use **revocable server-side tokens** (not a shared dummy token).
3. Every protected API checks **explicit permissions** (not UI hiding alone).
4. The React UI loads `/api/auth/me`, stores **role + permissions**, and hides Admin / write / SOAR controls for viewers.
5. Admin user APIs gained **activate**, **password reset**, and **last-admin protection**.

Detection, ingestion pipeline, YARA engine, Socket.IO, dashboard charts, and SOAR simulation logic were **not rewritten** — only authorization around them was tightened.

---

## 2. Files created

| File | Purpose |
|------|---------|
| `backend/tests/test_auth_rbac.py` | Backend login / JWT-session / RBAC unit tests |
| `frontend/src/auth.js` | Central `hasPermission` / `hasRole` / session helpers |
| `frontend/src/components/PermissionGate.js` | `<PermissionGate>` / `<RoleGate>` UI helpers |
| `frontend/src/auth.test.js` | Frontend permission helper tests |
| `docs/PHASE1_AUTH_RBAC_REPORT.md` | This report |

---

## 3. Files modified

| File | What changed |
|------|----------------|
| `backend/src/th/db.py` | `ROLE_PERMISSIONS`, helpers, `User.last_login`, safe SQLite column migration |
| `backend/src/th/webapp.py` | `require_permission`, enriched login/me, hardened user APIs, permission on routes |
| `frontend/src/api.js` | Auth helpers, user-management API wrappers, session clear on 401 |
| `frontend/src/App.js` | Login via API helpers; session refresh via `/auth/me` |
| `frontend/src/components/Navbar.js` | Role badge, Admin nav only if permitted, Read-only hint for viewers |
| `frontend/src/pages/Dashboard.js` | Gates admin view, feed sync, case edits, SOAR |
| `frontend/src/App.test.js` | Asserts login screen renders when logged out |

---

## 4. Database changes

| Change | Detail |
|--------|--------|
| Column `users.last_login` | Nullable `DATETIME`; set on successful login |
| Migration | Added via existing `_add_column_if_missing` — **does not wipe** `threat_hunting.db` |
| Tables reused | `users`, `auth_tokens` (opaque session tokens) |
| Not added yet | Separate `permissions` / `roles` / `audit_logs` tables (future phases) |

Permissions are **not** stored per-user in the DB. They are derived from `User.role` using `ROLE_PERMISSIONS` in Python. That keeps the schema simple for a Master's project while still giving explicit permission strings to the API and UI.

---

## 5. Authentication architecture

```text
Browser login form
    → POST /api/auth/login {username, password}
    → Werkzeug check_password_hash(password_hash)
    → issue opaque AuthToken (hex, ~12h TTL) into auth_tokens table
    → response: { token, user: { id, username, role, permissions, ... } }
    → frontend stores token + user in localStorage

Later requests
    → Authorization: Bearer <token>
    → get_user_for_token() validates token + expiry + is_active
    → g.current_user set
    → @require_permission("...")

Logout
    → POST /api/auth/logout
    → delete AuthToken row (server-side revoke)
```

### Why opaque tokens (not JWT)?

The project already used DB-backed session tokens. They remain because they are:

- Revocable immediately (role change / deactivate / logout)
- Free of an extra crypto dependency
- Compatible with the existing frontend contract (`token` + Bearer header)

PDF downloads still accept `?token=` because browsers open that URL directly (no Axios header). The report endpoint also checks `reports.read`.

### Bootstrap accounts (from `backend/.env`)

| Env vars | Role |
|----------|------|
| `TH_ADMIN_USERNAME` / `TH_ADMIN_PASSWORD` | admin |
| `TH_ANALYST_USERNAME` / `TH_ANALYST_PASSWORD` | analyst |
| `TH_VIEWER_USERNAME` / `TH_VIEWER_PASSWORD` | viewer |

On startup, `_seed_defaults()` creates or syncs these users. Passwords must be 8+ characters. Never commit real `.env` secrets.

---

## 6. RBAC architecture

### Roles

| Role | Intent |
|------|--------|
| `admin` | Full SOC config + user management |
| `analyst` | Hunt, cases, SOAR (simulated), feeds sync, suppressions |
| `viewer` | Read-only dashboard / alerts / IOC / reports |

### Permissions (examples)

**Admin** includes: `users.read/write`, `yara.write`, `feeds.write`, `system.write`, `soar.execute`, …

**Analyst** includes: `alerts.write`, `events.write`, `ioc.write`, `soar.execute`, `yara.read`, …

**Viewer** includes only: `alerts.read`, `events.read`, `ioc.read`, `reports.read`, `dashboard.read`

### Backend enforcement

```python
@login_required
@require_permission("alerts.write")
def update_alert_case_route(...):
    ...
```

Viewers calling analyst/admin APIs receive:

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to perform this action (alerts.write)."
  }
}
```

HTTP status: **403**.

### Frontend enforcement (defense in depth)

- `hasPermission("…")` / `hasRole("…")` in `frontend/src/auth.js`
- Admin nav hidden without `users.read` or `yara.write`
- Case save / SOAR hidden for viewers
- Feed sync button requires `ioc.write`
- Backend remains authoritative if someone bypasses the UI

---

## 7. API changes (auth / users)

| Method | Path | Permission |
|--------|------|------------|
| POST | `/api/auth/login` | public |
| POST | `/api/auth/logout` | public (revokes if token present) |
| GET | `/api/auth/me` | authenticated → full user + permissions |
| GET | `/api/dashboard` | `dashboard.read` |
| GET | `/api/alert_context/<id>` | `alerts.read` |
| POST | `/api/alerts/<id>/case` | `alerts.write` |
| POST | `/api/soar/action` | `soar.execute` |
| GET | `/api/admin/data` | `users.read` |
| GET/POST | `/api/admin/users` | `users.read` / `users.write` |
| POST | `/api/admin/users/<id>/role` | `users.write` (+ last-admin guard) |
| POST | `/api/admin/users/<id>/deactivate` | `users.write` |
| POST | `/api/admin/users/<id>/activate` | `users.write` **(new)** |
| POST | `/api/admin/users/<id>/reset_password` | `users.write` **(new)** |
| GET | `/api/report/<id>?token=` | `reports.read` |

Existing routes for YARA, feeds, ingest, suppressions now use matching permissions instead of only `role_required("analyst"|"admin")`. The old `role_required` helper remains for compatibility.

---

## 8. Frontend changes

1. **Login** still lives in `App.js` (professional dark SOC card).
2. After login / on reload → `GET /api/auth/me` refreshes permissions.
3. **Navbar** shows `username · role`; Admin tab only for admins; “Read-only” for viewers.
4. **Incident panel**: viewers see timeline/PDF; no case save / SOAR.
5. Central API module exports `login`, `logout`, `getMe`, user admin helpers.

`react-router-dom` is installed but multi-page routes (`/alerts`, `/cases`, …) are intentionally **not** introduced yet (later UI phase).

---

## 9. How the full project works today

End-to-end SOC flow that already exists in this repo:

```text
Log files (backend/data/logs/*.log) or HTTP ingest
    → pipeline normalize + store Event
    → RuleEvaluator (YAML) + IOC match + YARA
    → Alert persisted
    → Socket.IO emit('new_alert')
    → React Dashboard live update
    → Analyst updates case / runs simulated SOAR
    → PDF incident report download
```

| Layer | Tech | Key modules |
|-------|------|-------------|
| UI | React (CRA) | `frontend/src/App.js`, `pages/Dashboard.js` |
| API | Flask + SocketIO | `backend/src/th/webapp.py` |
| DB | SQLite + SQLAlchemy | `backend/src/th/db.py` → `backend/threat_hunting.db` |
| Detection | YAML rules + YARA + IOC feeds | `pipeline.py`, `rule_evaluator.py`, `scanner.py` |
| Auth | Password hash + AuthToken | `db.py` + `webapp.py` |

Default ports (this repo):

- Backend: `http://127.0.0.1:5000` (`PORT` in `backend/.env`)
- Frontend: `http://localhost:3000`
- Configure UI with `REACT_APP_API_BASE_URL`

---

## 10. Testing performed

| Suite | Result |
|-------|--------|
| `python -m unittest tests.test_auth_rbac -v` | **15 passed** (login, me, viewer 403s, analyst SOAR, admin users, last-admin demote block, logout revoke) |
| Frontend `npm test -- --watchAll=false --testPathPattern="auth\|App"` | **5 passed** |
| `npm run build` | **Succeeded** |
| Import check `from th.webapp import app` | **OK** (31 routes) |

Pipeline unit tests (`test_pipeline.py`) remain available; auth suite was the Phase 1 focus.

---

## 11. Commands to run

### Backend

```powershell
cd d:\manan\Threat-Hunting-Platform\backend
.\venv\Scripts\activate
$env:PYTHONPATH="src"
python -m th.webapp
```

### Frontend

```powershell
cd d:\manan\Threat-Hunting-Platform\frontend
# ensure .env has REACT_APP_API_BASE_URL=http://127.0.0.1:5000
npm start
```

### Auth / RBAC tests

```powershell
cd d:\manan\Threat-Hunting-Platform\backend
$env:PYTHONPATH="src"
python -m unittest tests.test_auth_rbac -v
```

### Example API checks

```powershell
# Login
curl -X POST http://127.0.0.1:5000/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"YOUR_PASSWORD\"}"

# Me
curl http://127.0.0.1:5000/api/auth/me -H "Authorization: Bearer TOKEN"

# Viewer must get 403
curl -X POST http://127.0.0.1:5000/api/soar/action -H "Authorization: Bearer VIEWER_TOKEN" -H "Content-Type: application/json" -d "{\"action\":\"Block IP\",\"target\":\"1.1.1.1\"}"
```

### Development accounts

Set in `backend/.env` (see `.env.example`). Typical local usernames: `admin`, `analyst`, `viewer`.

---

## 12. Short demo script (Phase 1)

1. **Login as admin** → see Admin tab + username/role in navbar.  
2. **Logout → login as viewer** → no Admin tab, “Read-only”, open an alert → no Save Case / SOAR.  
3. **Call SOAR API as viewer** (or DevTools) → HTTP 403.  
4. **Login as analyst** → can update case + simulated SOAR; cannot open Admin / create users.  
5. **Login as admin** → `/api/admin/users` lists users with `last_login` / permissions.  
6. Try demoting the only admin → **409 CONFLICT**.

---

## 13. Known limitations (honest)

- No audit log table yet (login success/failure not persisted for forensics).
- No fine-grained per-user custom permissions (role → fixed set).
- Admin user management UI in the React Admin panel is still basic (list users); new activate/reset APIs exist for later UI polish.
- Report download still uses query-string token (common for file downloads); do not share report URLs.
- Multi-route role dashboards (`/hunting`, `/cases`, …) not built yet.
- SOAR remains **simulated** (unchanged behavior, now permission-gated).
- Not claiming production hardening (rate limiting, MFA, lockout policy, etc.).

---

## 14. Recommended next phases

1. **Phase 3–4:** Full role-specific navigation + admin user management UI wired to activate/reset APIs.  
2. **Phase 5–7:** Real-time file watcher ingestion polish + richer detections.  
3. **Phase 8+:** Audit logs, cases model, correlation, risk scoring, authorized web scanner.

---

## 15. Acceptance criteria checklist

| Criterion | Status |
|-----------|--------|
| Admin / analyst / viewer can log in | Yes (env-seeded) |
| Invalid credentials fail | Yes (tested) |
| Session token works + expires / logout revokes | Yes (tested) |
| Admin can access user APIs | Yes (tested) |
| Analyst cannot manage users | Yes (tested) |
| Viewer cannot modify alerts / SOAR | Yes (API + UI) |
| Permissions returned from login/me | Yes |
| No dummy shared token | Yes |
| Existing detection / Socket.IO preserved | Yes (not rewritten) |
