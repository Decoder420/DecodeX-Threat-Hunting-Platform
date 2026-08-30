"""Web application security scanning — SSRF, authz, RBAC, normalize, risk."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = BACKEND_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

_tmp_dir = tempfile.mkdtemp(prefix="th_webscan_")
os.environ["TH_ADMIN_USERNAME"] = "admin"
os.environ["TH_ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["TH_ANALYST_USERNAME"] = "analyst"
os.environ["TH_ANALYST_PASSWORD"] = "AnalystPass123!"
os.environ["TH_VIEWER_USERNAME"] = "viewer"
os.environ["TH_VIEWER_PASSWORD"] = "ViewerPass123!"
os.environ["WEBSCAN_ALLOW_PRIVATE_TARGETS"] = "false"
os.environ["WEBSCAN_ENABLED"] = "true"
os.environ.pop("DATABASE_URL", None)

from th import db as dbmod  # noqa: E402

dbmod.DATABASE_PATH = Path(_tmp_dir) / "test_webscan.db"
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
from th.db import WebFinding, WebScan, WebTarget, get_db  # noqa: E402
from th.web_scanner.validators import (  # noqa: E402
    SSRFError,
    normalize_url,
    validate_redirect_url,
    validate_scan_url,
)
from th.web_scanner.normalizer import normalize_finding  # noqa: E402
from th.web_scanner.deduplicator import dedupe_findings  # noqa: E402
from th.web_scanner.risk_web import score_web_finding  # noqa: E402
from th.web_scanner.engines import detect_engines, run_nuclei  # noqa: E402


class ValidatorTests(unittest.TestCase):
    def test_normalize_adds_https(self):
        self.assertTrue(normalize_url("example.com").startswith("https://"))

    def test_blocks_file_scheme(self):
        with self.assertRaises(SSRFError):
            normalize_url("file:///etc/passwd")

    def test_blocks_localhost(self):
        with self.assertRaises(SSRFError):
            validate_scan_url("http://localhost/", allow_private=False)

    def test_blocks_loopback_ip(self):
        with self.assertRaises(SSRFError):
            validate_scan_url("http://127.0.0.1/", allow_private=False)

    def test_blocks_metadata(self):
        with self.assertRaises(SSRFError):
            validate_scan_url("http://169.254.169.254/", allow_private=True)

    def test_blocks_private_without_lab_mode(self):
        with self.assertRaises(SSRFError):
            validate_scan_url("http://10.0.0.5/", allow_private=False)

    def test_allows_private_in_lab_mode(self):
        meta = validate_scan_url("http://10.0.0.5/", allow_private=True)
        self.assertEqual(meta["hostname"], "10.0.0.5")

    def test_redirect_out_of_host_blocked(self):
        out = validate_redirect_url(
            "https://example.com/",
            "https://evil.example/",
            allow_private=True,
            allowed_host="example.com",
        )
        self.assertIsNone(out)


class NormalizeDedupeRiskTests(unittest.TestCase):
    def test_normalize_fingerprint_stable(self):
        a = normalize_finding(
            {
                "title": "Missing CSP",
                "severity": "medium",
                "category": "headers",
                "affected_url": "https://Example.com/Path",
            },
            target_url="https://example.com",
        )
        b = normalize_finding(
            {
                "title": "Missing CSP",
                "severity": "MEDIUM",
                "category": "headers",
                "affected_url": "https://example.com/Path",
            },
            target_url="https://example.com",
        )
        self.assertEqual(a["fingerprint"], b["fingerprint"])
        self.assertEqual(a["severity"], "MEDIUM")

    def test_dedupe_merges(self):
        items = [
            {"title": "A", "severity": "HIGH", "category": "x", "affected_url": "https://a/"},
            {"title": "A", "severity": "HIGH", "category": "x", "affected_url": "https://a/"},
            {"title": "B", "severity": "LOW", "category": "y", "affected_url": "https://a/b"},
        ]
        out = dedupe_findings(items, target_url="https://a/")
        self.assertEqual(len(out), 2)
        self.assertGreaterEqual(out[0]["occurrence_count"], 1)

    def test_risk_score_bounds(self):
        score, factors = score_web_finding(
            severity="CRITICAL", confidence=90, cvss=9.8, host="x", db=None
        )
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertIn("severity_weight", factors)


class EngineGracefulTests(unittest.TestCase):
    def test_detect_engines_structure(self):
        status = detect_engines()
        self.assertIn("builtin", status)
        self.assertIn("nuclei", status)
        self.assertEqual(status["builtin"]["status"], "READY")

    def test_nuclei_missing_does_not_raise(self):
        with patch("th.web_scanner.engines._which", return_value=None):
            findings, err = run_nuclei("https://example.com")
        self.assertEqual(findings, [])
        self.assertTrue(err)


class WebScanApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        with app.app_context():
            get_db()
        cls._real_getaddrinfo = socket.getaddrinfo

        def _mock_getaddrinfo(host, port, *args, **kwargs):
            if host in ("example.com", "example.org"):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]
            return cls._real_getaddrinfo(host, port, *args, **kwargs)

        cls._dns_patcher = patch("socket.getaddrinfo", side_effect=_mock_getaddrinfo)
        cls._dns_patcher.start()

    @classmethod
    def tearDownClass(cls):
        cls._dns_patcher.stop()

    def _login(self, username="admin", password="AdminPass123!"):
        res = self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(res.status_code, 200)
        return res.get_json()["token"]

    def _h(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_viewer_cannot_create_target(self):
        token = self._login("viewer", "ViewerPass123!")
        res = self.client.post(
            "/api/web-targets",
            json={"name": "x", "url": "https://example.com"},
            headers=self._h(token),
        )
        self.assertIn(res.status_code, (401, 403))

    def test_create_target_always_pending(self):
        token = self._login()
        res = self.client.post(
            "/api/web-targets",
            json={
                "name": "Ex",
                "url": "https://example.com",
                "authorization_status": "AUTHORIZED",
            },
            headers=self._h(token),
        )
        self.assertEqual(res.status_code, 201)
        body = res.get_json()
        self.assertEqual(body["authorization_status"], "PENDING")

    def test_cannot_authorize_via_patch(self):
        token = self._login()
        created = self.client.post(
            "/api/web-targets",
            json={"name": "PatchAuth", "url": "https://example.org"},
            headers=self._h(token),
        ).get_json()
        res = self.client.patch(
            f"/api/web-targets/{created['id']}",
            json={"authorization_status": "AUTHORIZED"},
            headers=self._h(token),
        )
        self.assertEqual(res.status_code, 403)

    def test_scan_requires_authorized_and_confirm(self):
        token = self._login()
        created = self.client.post(
            "/api/web-targets",
            json={"name": "ScanMe", "url": "https://example.com"},
            headers=self._h(token),
        ).get_json()
        # Not authorized yet
        res = self.client.post(
            "/api/web-scans",
            json={"target_id": created["id"], "confirm": True, "profile": "QUICK"},
            headers=self._h(token),
        )
        self.assertEqual(res.status_code, 403)

        # Authorize (DNS for example.com is public — OK)
        auth = self.client.post(
            f"/api/web-targets/{created['id']}/authorize",
            json={"confirm": True},
            headers=self._h(token),
        )
        self.assertEqual(auth.status_code, 200)

        # Missing confirm
        res2 = self.client.post(
            "/api/web-scans",
            json={"target_id": created["id"], "profile": "QUICK"},
            headers=self._h(token),
        )
        self.assertEqual(res2.status_code, 400)

    def test_ssrf_blocked_on_create(self):
        token = self._login()
        res = self.client.post(
            "/api/web-targets",
            json={"name": "bad", "url": "http://127.0.0.1/"},
            headers=self._h(token),
        )
        self.assertEqual(res.status_code, 400)

    def test_engines_endpoint(self):
        # Analyst has webscan.read; viewer may be read-dashboard-only depending on role map.
        token = self._login("analyst", "AnalystPass123!")
        res = self.client.get("/api/web/scanner/engines", headers=self._h(token))
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertIn("engines", body)
        serialized = json.dumps(body).lower()
        self.assertNotIn("api_key", serialized)
        self.assertNotIn("zap_api_key", serialized)

    def test_compare_and_report(self):
        token = self._login()
        with app.app_context():
            db = get_db()
            t = WebTarget(
                name="cmp",
                url="https://example.com",
                owner="admin",
                authorization_status="AUTHORIZED",
                created_by="admin",
            )
            db.add(t)
            db.flush()
            s1 = WebScan(target_id=t.id, status="COMPLETED", findings_count=1, created_by="admin")
            s2 = WebScan(target_id=t.id, status="COMPLETED", findings_count=2, created_by="admin")
            db.add_all([s1, s2])
            db.flush()
            db.add(
                WebFinding(
                    target_id=t.id,
                    scan_id=s1.id,
                    title="Old",
                    severity="LOW",
                    fingerprint="fp-old",
                )
            )
            db.add(
                WebFinding(
                    target_id=t.id,
                    scan_id=s2.id,
                    title="New",
                    severity="HIGH",
                    fingerprint="fp-new",
                )
            )
            db.add(
                WebFinding(
                    target_id=t.id,
                    scan_id=s2.id,
                    title="Old",
                    severity="LOW",
                    fingerprint="fp-old",
                )
            )
            db.commit()
            sid1, sid2 = s1.id, s2.id

        cmp_res = self.client.get(
            f"/api/web-scans/{sid2}/compare/{sid1}", headers=self._h(token)
        )
        self.assertEqual(cmp_res.status_code, 200)
        body = cmp_res.get_json()
        self.assertEqual(body["new_count"], 1)
        self.assertEqual(body["resolved_count"], 0)
        self.assertEqual(body["persistent_count"], 1)

        report = self.client.get(
            f"/api/web-scans/{sid2}/report", headers=self._h(token)
        )
        self.assertEqual(report.status_code, 200)
        self.assertIn("executive_summary", report.get_json())


if __name__ == "__main__":
    unittest.main()
