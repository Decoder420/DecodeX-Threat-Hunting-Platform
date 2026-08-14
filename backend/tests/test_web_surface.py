"""Attack-surface tree / website map unit tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = BACKEND_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

_tmp = tempfile.TemporaryDirectory(prefix="th_surface_", ignore_cleanup_errors=True)
os.environ["TH_ADMIN_USERNAME"] = "admin"
os.environ["TH_ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["TH_ANALYST_USERNAME"] = "analyst"
os.environ["TH_ANALYST_PASSWORD"] = "AnalystPass123!"
os.environ["TH_VIEWER_USERNAME"] = "viewer"
os.environ["TH_VIEWER_PASSWORD"] = "ViewerPass123!"
os.environ["WEBSCAN_ALLOW_PRIVATE_TARGETS"] = "true"
os.environ["WEBSCAN_DEMO_MODE"] = "true"
os.environ.pop("DATABASE_URL", None)

from th import db as dbmod  # noqa: E402

dbmod.DATABASE_PATH = Path(_tmp.name) / "test_surface.db"
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
from th.db import WebScan, WebTarget, get_db  # noqa: E402
from th.web_scanner.config import SCAN_PROFILES, max_severity  # noqa: E402
from th.web_scanner.surface import AttackSurfaceBuilder, build_tree_payload  # noqa: E402
from th.web_scanner.demo import demo_surface  # noqa: E402


class SurfaceUnitTests(unittest.TestCase):
    def test_profiles_include_new_ones(self):
        for name in ("PASSIVE", "API", "LAB", "DEMO", "AUTHENTICATED"):
            self.assertIn(name, SCAN_PROFILES)

    def test_max_severity(self):
        self.assertEqual(max_severity("LOW", "HIGH"), "HIGH")
        self.assertEqual(max_severity("CRITICAL", "INFO"), "CRITICAL")

    def test_demo_surface_labeled(self):
        data = demo_surface("https://example.com", "example.com")
        self.assertTrue(all("[DEMO]" in f["title"] for f in data["findings"]))


class SurfaceApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        with app.app_context():
            get_db()

    def _token(self):
        res = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "AdminPass123!"},
        )
        return res.get_json()["token"]

    def test_tree_and_events_endpoints(self):
        token = self._token()
        h = {"Authorization": f"Bearer {token}"}
        with app.app_context():
            db = get_db()
            t = WebTarget(
                name="map",
                url="https://example.com",
                owner="admin",
                authorization_status="AUTHORIZED",
                created_by="admin",
            )
            db.add(t)
            db.flush()
            s = WebScan(target_id=t.id, status="RUNNING", created_by="admin", scan_profile="DEMO")
            db.add(s)
            db.commit()
            surface = AttackSurfaceBuilder(db, s, emit=lambda *a, **k: None)
            root = surface.ensure_root("https://example.com", hostname="example.com")
            leaf = surface.ensure_url_path(root, "https://example.com/login", http_status=200)
            surface.attach_finding(leaf, severity="HIGH", risk_score=70, has_alert=True)
            sid, tid = s.id, t.id

        tree = self.client.get(f"/api/web-scans/{sid}/tree", headers=h)
        self.assertEqual(tree.status_code, 200)
        body = tree.get_json()
        self.assertGreaterEqual(len(body["nodes"]), 2)
        self.assertTrue(body["root_ids"])

        # Parent should show descendant finding indicator
        nodes = {n["id"]: n for n in body["nodes"]}
        parents = [n for n in body["nodes"] if n["parent_id"] is None]
        self.assertTrue(parents)
        self.assertGreaterEqual(parents[0]["descendant_finding_count"], 1)

        surface_res = self.client.get(f"/api/web-targets/{tid}/attack-surface", headers=h)
        self.assertEqual(surface_res.status_code, 200)
        self.assertEqual(surface_res.get_json()["scan_id"], sid)

        health = self.client.get("/api/webscan/health", headers=h)
        self.assertEqual(health.status_code, 200)
        self.assertIn("engines", health.get_json())


if __name__ == "__main__":
    unittest.main()
