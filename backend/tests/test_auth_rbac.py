"""Phase 1 authentication and RBAC tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure backend/src is importable the same way production uses PYTHONPATH=src
BACKEND_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = BACKEND_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

# Isolate tests on a temporary SQLite DB before importing th.db / webapp.
_tmp = tempfile.TemporaryDirectory(prefix="th_auth_rbac_", ignore_cleanup_errors=True)
os.environ["TH_ADMIN_USERNAME"] = "admin"
os.environ["TH_ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["TH_ANALYST_USERNAME"] = "analyst"
os.environ["TH_ANALYST_PASSWORD"] = "AnalystPass123!"
os.environ["TH_VIEWER_USERNAME"] = "viewer"
os.environ["TH_VIEWER_PASSWORD"] = "ViewerPass123!"
os.environ.pop("DATABASE_URL", None)

from th import db as dbmod  # noqa: E402

dbmod.DATABASE_PATH = Path(_tmp.name) / "test_auth.db"
dbmod.engine = dbmod.create_engine(
    f"sqlite:///{dbmod.DATABASE_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)
dbmod.SessionLocal = dbmod.sessionmaker(
    bind=dbmod.engine, autoflush=False, expire_on_commit=False
)
dbmod._db_initialized = False

from th.webapp import app  # noqa: E402
from th.db import (  # noqa: E402
    ROLE_PERMISSIONS,
    User,
    get_db,
    permissions_for_role,
    user_has_permission,
)


class AuthRbacTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        # Force DB init + seed
        with app.app_context():
            get_db()

    def _login(self, username: str, password: str):
        return self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )

    def _auth_header(self, token: str):
        return {"Authorization": f"Bearer {token}"}

    def test_permissions_map_roles(self):
        self.assertIn("users.write", ROLE_PERMISSIONS["admin"])
        self.assertNotIn("users.write", ROLE_PERMISSIONS["analyst"])
        self.assertNotIn("soar.execute", ROLE_PERMISSIONS["viewer"])
        self.assertIn("dashboard.read", permissions_for_role("viewer"))

    def test_login_success_includes_permissions(self):
        res = self._login("admin", "AdminPass123!")
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertIn("token", body)
        self.assertEqual(body["user"]["role"], "admin")
        self.assertIn("users.write", body["user"]["permissions"])
        self.assertTrue(body["user"]["last_login"])

    def test_login_invalid_credentials(self):
        res = self._login("admin", "wrong-password")
        self.assertEqual(res.status_code, 401)
        err = res.get_json()["error"]
        self.assertEqual(err["code"], "UNAUTHORIZED")

    def test_me_requires_token(self):
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.status_code, 401)

    def test_me_returns_permissions(self):
        token = self._login("analyst", "AnalystPass123!").get_json()["token"]
        res = self.client.get("/api/auth/me", headers=self._auth_header(token))
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertEqual(body["role"], "analyst")
        self.assertIn("alerts.write", body["permissions"])
        self.assertNotIn("users.write", body["permissions"])

    def test_viewer_forbidden_on_admin_users(self):
        token = self._login("viewer", "ViewerPass123!").get_json()["token"]
        res = self.client.get("/api/admin/users", headers=self._auth_header(token))
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.get_json()["error"]["code"], "FORBIDDEN")

    def test_viewer_forbidden_on_alert_write(self):
        token = self._login("viewer", "ViewerPass123!").get_json()["token"]
        res = self.client.post(
            "/api/alerts/1/case",
            json={"status": "Resolved"},
            headers=self._auth_header(token),
        )
        self.assertEqual(res.status_code, 403)

    def test_viewer_forbidden_on_soar(self):
        token = self._login("viewer", "ViewerPass123!").get_json()["token"]
        res = self.client.post(
            "/api/soar/action",
            json={"action": "Block IP", "target": "1.2.3.4"},
            headers=self._auth_header(token),
        )
        self.assertEqual(res.status_code, 403)

    def test_viewer_can_read_dashboard(self):
        token = self._login("viewer", "ViewerPass123!").get_json()["token"]
        res = self.client.get("/api/dashboard", headers=self._auth_header(token))
        self.assertEqual(res.status_code, 200)

    def test_analyst_forbidden_on_user_management(self):
        token = self._login("analyst", "AnalystPass123!").get_json()["token"]
        res = self.client.post(
            "/api/admin/users",
            json={"username": "x", "password": "Password123!", "role": "viewer"},
            headers=self._auth_header(token),
        )
        self.assertEqual(res.status_code, 403)

    def test_analyst_can_execute_soar_simulated(self):
        token = self._login("analyst", "AnalystPass123!").get_json()["token"]
        res = self.client.post(
            "/api/soar/action",
            json={"action": "Block IP", "target": "1.2.3.4"},
            headers=self._auth_header(token),
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "simulated")

    def test_admin_can_list_users(self):
        token = self._login("admin", "AdminPass123!").get_json()["token"]
        res = self.client.get("/api/admin/users", headers=self._auth_header(token))
        self.assertEqual(res.status_code, 200)
        usernames = {u["username"] for u in res.get_json()["users"]}
        self.assertTrue({"admin", "analyst", "viewer"}.issubset(usernames))

    def test_cannot_demote_last_admin(self):
        token = self._login("admin", "AdminPass123!").get_json()["token"]
        headers = self._auth_header(token)
        with app.app_context():
            admin = get_db().query(User).filter_by(username="admin").first()
            admin_id = admin.id
        res = self.client.post(
            f"/api/admin/users/{admin_id}/role",
            json={"role": "viewer"},
            headers=headers,
        )
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.get_json()["error"]["code"], "CONFLICT")

    def test_logout_revokes_token(self):
        token = self._login("viewer", "ViewerPass123!").get_json()["token"]
        res = self.client.post("/api/auth/logout", headers=self._auth_header(token))
        self.assertEqual(res.status_code, 200)
        me = self.client.get("/api/auth/me", headers=self._auth_header(token))
        self.assertEqual(me.status_code, 401)

    def test_user_has_permission_helper(self):
        with app.app_context():
            viewer = get_db().query(User).filter_by(username="viewer").first()
            self.assertTrue(user_has_permission(viewer, "alerts.read"))
            self.assertFalse(user_has_permission(viewer, "alerts.write"))

    def test_change_password_success_and_revokes_old_sessions(self):
        login_res = self._login("analyst", "AnalystPass123!")
        old_token = login_res.get_json()["token"]

        # Change password
        res = self.client.post(
            "/api/auth/change_password",
            json={"current_password": "AnalystPass123!", "new_password": "NewSecretPass456!"},
            headers=self._auth_header(old_token),
        )
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertTrue(body["success"])
        new_token = body["token"]

        # Old token must now be invalid
        me_old = self.client.get("/api/auth/me", headers=self._auth_header(old_token))
        self.assertEqual(me_old.status_code, 401)

        # New token works
        me_new = self.client.get("/api/auth/me", headers=self._auth_header(new_token))
        self.assertEqual(me_new.status_code, 200)

        # Can login with new password
        login_new = self._login("analyst", "NewSecretPass456!")
        self.assertEqual(login_new.status_code, 200)

        # Restore original password for other tests
        self.client.post(
            "/api/auth/change_password",
            json={"current_password": "NewSecretPass456!", "new_password": "AnalystPass123!"},
            headers=self._auth_header(login_new.get_json()["token"]),
        )

    def test_change_password_wrong_current_password(self):
        token = self._login("viewer", "ViewerPass123!").get_json()["token"]
        res = self.client.post(
            "/api/auth/change_password",
            json={"current_password": "WrongPassword!", "new_password": "NewViewerPass123!"},
            headers=self._auth_header(token),
        )
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.get_json()["error"]["code"], "UNAUTHORIZED")

    def test_change_password_short_password(self):
        token = self._login("viewer", "ViewerPass123!").get_json()["token"]
        res = self.client.post(
            "/api/auth/change_password",
            json={"current_password": "ViewerPass123!", "new_password": "short"},
            headers=self._auth_header(token),
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.get_json()["error"]["code"], "BAD_REQUEST")

    def test_admin_reset_password_revokes_sessions(self):
        admin_token = self._login("admin", "AdminPass123!").get_json()["token"]
        viewer_token = self._login("viewer", "ViewerPass123!").get_json()["token"]

        with app.app_context():
            viewer = get_db().query(User).filter_by(username="viewer").first()
            viewer_id = viewer.id

        # Admin resets viewer password
        res = self.client.post(
            f"/api/admin/users/{viewer_id}/reset_password",
            json={"password": "ResetViewerPass789!"},
            headers=self._auth_header(admin_token),
        )
        self.assertEqual(res.status_code, 200)

        # Viewer session is immediately revoked
        me = self.client.get("/api/auth/me", headers=self._auth_header(viewer_token))
        self.assertEqual(me.status_code, 401)

        # Viewer can log in with new password
        login_new = self._login("viewer", "ResetViewerPass789!")
        self.assertEqual(login_new.status_code, 200)

        # Restore original password
        self.client.post(
            f"/api/admin/users/{viewer_id}/reset_password",
            json={"password": "ViewerPass123!"},
            headers=self._auth_header(admin_token),
        )

    def test_consistent_error_structure(self):
        res = self.client.get("/api/auth/me")
        body = res.get_json()
        self.assertIn("error", body)
        self.assertIn("code", body["error"])
        self.assertIn("message", body["error"])
        self.assertIn("details", body["error"])
        self.assertFalse(body.get("success", True))


if __name__ == "__main__":
    unittest.main()
