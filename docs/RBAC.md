# RBAC

Roles: `admin`, `analyst`, `viewer` (lowercase).

Permissions are explicit strings in `ROLE_PERMISSIONS` (`backend/src/th/db.py`) and mirrored in `frontend/src/auth.js`.

Backend enforcement: `@login_required` + `@require_permission("…")`.

| Role | Summary |
|------|---------|
| admin | Users, YARA write, feeds write, audit, assets write, all analyst perms |
| analyst | Alerts write, cases, IOC write, webscan run, SOAR, hunting |
| viewer | Dashboard, alerts read, IOC read, assets limited, reports |

Frontend: `hasPermission`, `PermissionGate`, `ProtectedRoute`, Sidebar filtered by permission.
