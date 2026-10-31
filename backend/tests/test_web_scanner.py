"""Web application security scanning — SSRF, authz, RBAC, normalize, risk."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

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

    def test_consecutive_scans_preserve_findings_and_compare(self):
        token = self._login()
        with app.app_context():
            db = get_db()
            t = WebTarget(
                name="target-compare",
                url="https://example.com",
                owner="admin",
                authorization_status="AUTHORIZED",
                created_by="admin",
            )
            db.add(t)
            db.commit()

            # First scan with 2 findings: A and B
            s1 = WebScan(target_id=t.id, status="PENDING", created_by="admin", scan_profile="BASELINE")
            db.add(s1)
            db.commit()
            sid1 = s1.id

            from th.web_scanner.orchestrator import _run_scan_job
            with patch("th.web_scanner.orchestrator.check_tls", return_value=([], {})):
                with patch("th.web_scanner.orchestrator.extract_sitemap_urls", return_value={"count": 0, "urls": []}):
                    with patch("th.web_scanner.orchestrator.run_zap_passive") as mock_zap:
                        mock_zap.return_value = (
                            [
                                {"title": "Finding Shared B", "severity": "MEDIUM", "affected_url": "https://example.com/b", "source_engine": "zap"},
                                {"title": "Finding Unique S1 A", "severity": "LOW", "affected_url": "https://example.com/a", "source_engine": "zap"},
                            ],
                            ["https://example.com/a", "https://example.com/b"],
                            None,
                        )
                        with patch("th.web_scanner.orchestrator.crawl") as mock_crawl:
                            mock_crawl.return_value = {"count": 2, "urls": []}
                            with patch("th.web_scanner.orchestrator.discover_http") as mock_disc:
                                mock_disc.return_value = ([], {"headers": {}, "body_sample": ""})
                                with patch("th.web_scanner.orchestrator.check_common_files", return_value=[]):
                                    _run_scan_job(sid1)

            # Verify s1 has 2 findings in DB
            db.expire_all()
            s1_db = db.get(WebScan, sid1)
            s1_findings = db.query(WebFinding).filter_by(scan_id=sid1).all()
            self.assertEqual(len(s1_findings), 2, f"Scan 1 failed with error: {s1_db.error_message}, status: {s1_db.status}, stage: {s1_db.current_stage}")

            # Second scan with 2 findings: B (shared) and C (new)
            s2 = WebScan(target_id=t.id, status="PENDING", created_by="admin", scan_profile="STANDARD")
            db.add(s2)
            db.commit()
            sid2 = s2.id

            with patch("th.web_scanner.orchestrator.check_tls", return_value=([], {})):
                with patch("th.web_scanner.orchestrator.extract_sitemap_urls", return_value={"count": 0, "urls": []}):
                    with patch("th.web_scanner.orchestrator.run_zap_passive") as mock_zap2:
                        mock_zap2.return_value = (
                            [
                                {"title": "Finding Shared B", "severity": "MEDIUM", "affected_url": "https://example.com/b", "source_engine": "zap"},
                                {"title": "Finding Unique S2 C", "severity": "HIGH", "affected_url": "https://example.com/c", "source_engine": "zap"},
                            ],
                            ["https://example.com/b", "https://example.com/c"],
                            None,
                        )
                        with patch("th.web_scanner.orchestrator.run_zap_active", return_value=([], None)):
                            with patch("th.web_scanner.orchestrator.crawl") as mock_crawl2:
                                mock_crawl2.return_value = {"count": 2, "urls": []}
                                with patch("th.web_scanner.orchestrator.discover_http") as mock_disc2:
                                    mock_disc2.return_value = ([], {"headers": {}, "body_sample": ""})
                                    with patch("th.web_scanner.orchestrator.check_common_files", return_value=[]):
                                        _run_scan_job(sid2)

            # Crucial check: Scan 1 MUST still have its 2 findings (not stolen/reallocated to s2!)
            s1_after = db.query(WebFinding).filter_by(scan_id=sid1).all()
            self.assertEqual(len(s1_after), 2, "Scan 1 findings were overwritten or reallocated to Scan 2!")

            # Scan 2 has its 2 findings
            s2_findings = db.query(WebFinding).filter_by(scan_id=sid2).all()
            self.assertEqual(len(s2_findings), 2)

        # Call compare API
        res = self.client.get(f"/api/web-scans/{sid2}/compare/{sid1}", headers=self._h(token))
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["persistent_count"], 1, "Finding Shared B must be persistent")
        self.assertEqual(data["new_count"], 1, "Finding Unique S2 C must be new")
        self.assertEqual(data["resolved_count"], 1, "Finding Unique S1 A must be resolved")
        self.assertEqual(data["current_count"], 2)
        self.assertEqual(data["previous_count"], 2)

    def test_finding_triage_carries_over_across_scans(self):
        token = self._login()
        with app.app_context():
            db = get_db()
            t = WebTarget(
                name="target-triage",
                url="https://example.com",
                owner="admin",
                authorization_status="AUTHORIZED",
                created_by="admin",
            )
            db.add(t)
            db.commit()

            # First scan with 2 findings
            s1 = WebScan(target_id=t.id, status="PENDING", created_by="admin", scan_profile="BASELINE")
            db.add(s1)
            db.commit()
            sid1 = s1.id

            from th.web_scanner.orchestrator import _run_scan_job
            with patch("th.web_scanner.orchestrator.check_tls", return_value=([], {})):
                with patch("th.web_scanner.orchestrator.extract_sitemap_urls", return_value={"count": 0, "urls": []}):
                    with patch("th.web_scanner.orchestrator.run_zap_passive") as mock_zap:
                        mock_zap.return_value = (
                            [
                                {"title": "XSS Vulnerability", "severity": "HIGH", "affected_url": "https://example.com/search", "source_engine": "zap"},
                                {"title": "Old Deprecated API", "severity": "MEDIUM", "affected_url": "https://example.com/api/old", "source_engine": "zap"},
                            ],
                            ["https://example.com/search", "https://example.com/api/old"],
                            None,
                        )
                        with patch("th.web_scanner.orchestrator.crawl") as mock_crawl:
                            mock_crawl.return_value = {"count": 2, "urls": []}
                            with patch("th.web_scanner.orchestrator.discover_http") as mock_disc:
                                mock_disc.return_value = ([], {"headers": {}, "body_sample": ""})
                                with patch("th.web_scanner.orchestrator.check_common_files", return_value=[]):
                                    _run_scan_job(sid1)

            # Analyst triages the findings:
            # 1. Marks XSS finding as FALSE_POSITIVE and links to case 101
            # 2. Marks Old Deprecated API finding as RESOLVED
            db.expire_all()
            xss_s1 = db.query(WebFinding).filter_by(scan_id=sid1, title="XSS Vulnerability").one()
            old_s1 = db.query(WebFinding).filter_by(scan_id=sid1, title="Old Deprecated API").one()

            xss_s1.status = "FALSE_POSITIVE"
            xss_s1.case_id = 101
            old_s1.status = "RESOLVED"
            db.commit()

            # Second scan runs against the same target with the same findings
            s2 = WebScan(target_id=t.id, status="PENDING", created_by="admin", scan_profile="BASELINE")
            db.add(s2)
            db.commit()
            sid2 = s2.id

            with patch("th.web_scanner.orchestrator.check_tls", return_value=([], {})):
                with patch("th.web_scanner.orchestrator.extract_sitemap_urls", return_value={"count": 0, "urls": []}):
                    with patch("th.web_scanner.orchestrator.run_zap_passive") as mock_zap2:
                        mock_zap2.return_value = (
                            [
                                {"title": "XSS Vulnerability", "severity": "HIGH", "affected_url": "https://example.com/search", "source_engine": "zap"},
                                {"title": "Old Deprecated API", "severity": "MEDIUM", "affected_url": "https://example.com/api/old", "source_engine": "zap"},
                            ],
                            ["https://example.com/search", "https://example.com/api/old"],
                            None,
                        )
                        with patch("th.web_scanner.orchestrator.crawl") as mock_crawl2:
                            mock_crawl2.return_value = {"count": 2, "urls": []}
                            with patch("th.web_scanner.orchestrator.discover_http") as mock_disc2:
                                mock_disc2.return_value = ([], {"headers": {}, "body_sample": ""})
                                with patch("th.web_scanner.orchestrator.check_common_files", return_value=[]):
                                    _run_scan_job(sid2)

            db.expire_all()
            xss_s2 = db.query(WebFinding).filter_by(scan_id=sid2, title="XSS Vulnerability").one()
            old_s2 = db.query(WebFinding).filter_by(scan_id=sid2, title="Old Deprecated API").one()

            # Assert FALSE_POSITIVE status carried forward
            self.assertEqual(xss_s2.status, "FALSE_POSITIVE", "Analyst-set FALSE_POSITIVE status must carry over")
            # Assert case_id carried forward
            self.assertEqual(xss_s2.case_id, 101, "Associated case_id must carry over")
            # Assert occurrence count incremented
            self.assertEqual(xss_s2.occurrence_count, 2, "Occurrence count must increment")
            # Assert first_seen preserved
            self.assertEqual(xss_s2.first_seen, xss_s1.first_seen, "First seen timestamp must carry over")

            # Assert RESOLVED finding reopens as OPEN (regression detection)
            self.assertEqual(old_s2.status, "OPEN", "Re-occurring finding previously marked RESOLVED must reopen as OPEN")

    @patch("requests.get")
    def test_crawler_extracts_api_routes_with_template_literals(self, mock_get):
        """Test crawler extracts ES6 template literal API routes and replaces ${...} with test parameter."""
        from urllib.parse import urlparse
        from th.web_scanner.crawler import crawl

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/javascript"}
        mock_resp.text = """
        const searchApi = `/rest/products/search?q=${searchQuery}&category=${cat}`;
        const userApi = `/api/v1/users/${userId}/profile`;
        const orderStatus = `/api/orders/${orderId}?token=${authToken}`;
        const staticDoc = `/docs/readme.md`;
        """
        mock_get.return_value = mock_resp

        def _mock_validate(u, **kw):
            parsed = urlparse(u)
            return {"url": u, "hostname": parsed.hostname or "example.com", "port": 80}

        with patch("th.web_scanner.crawler.validate_scan_url", side_effect=_mock_validate):
            result = crawl("http://example.com/main.js", allow_private=True, max_depth=2)
        extracted_urls = [u["url"] for u in result.get("urls", [])]

        # Verify ES6 template literals were extracted and replaced with 'test'
        self.assertIn("http://example.com/rest/products/search?q=test&category=test", extracted_urls)
        self.assertIn("http://example.com/api/v1/users/test/profile", extracted_urls)
        self.assertIn("http://example.com/api/orders/test?token=test", extracted_urls)

    def test_surface_ensure_url_path_keeps_port_and_query(self):
        """Test surface.ensure_url_path preserves non-standard ports and query strings."""
        from th.web_scanner.surface import AttackSurfaceBuilder

        db = get_db()
        scan = WebScan(id=888, target_id=1, scan_profile="QUICK")
        db.add(scan)
        db.commit()

        builder = AttackSurfaceBuilder(db, scan)
        root = builder.ensure_root("http://juice:3000")
        self.assertEqual(root.port, 3000)

        # Call ensure_url_path with path, non-standard port, and query parameter
        node = builder.ensure_url_path(root, "http://juice:3000/rest/products/search?q=test")
        self.assertEqual(node.port, 3000, "Port :3000 must be preserved in node")
        self.assertEqual(node.url, "http://juice:3000/rest/products/search?q=test", "Full URL with port and query must be preserved")
        self.assertEqual(node.label, "/rest/products/search?q=test", "Query parameter must be preserved in label")
        self.assertEqual(node.node_type, "endpoint")
        db.close()

    def test_seeded_url_filter_excludes_static_assets(self):
        """Test filter_active_scan_candidate_urls excludes static assets/sockets and prioritizes parameters."""
        from th.web_scanner.orchestrator import filter_active_scan_candidate_urls

        urls = [
            "http://juice:3000/assets/public/images/products/apple.png",
            "http://juice:3000/main.js",
            "http://juice:3000/styles.css",
            "http://juice:3000/favicon.ico",
            "http://juice:3000/socket.io/?EIO=4&transport=polling",
            "http://juice:3000/sockjs/info",
            "http://juice:3000/api/Users",
            "http://juice:3000/rest/products/search?q=test",
            "http://juice:3000/rest/admin/whoami",
        ]
        candidates = filter_active_scan_candidate_urls(urls)

        # Assert static files, assets folder, and websockets are excluded
        self.assertNotIn("http://juice:3000/assets/public/images/products/apple.png", candidates)
        self.assertNotIn("http://juice:3000/main.js", candidates)
        self.assertNotIn("http://juice:3000/styles.css", candidates)
        self.assertNotIn("http://juice:3000/favicon.ico", candidates)
        self.assertNotIn("http://juice:3000/socket.io/?EIO=4&transport=polling", candidates)
        self.assertNotIn("http://juice:3000/sockjs/info", candidates)

        # Assert parameterized endpoint is prioritized at front of candidates list
        self.assertEqual(candidates[0], "http://juice:3000/rest/products/search?q=test")
        self.assertIn("http://juice:3000/api/Users", candidates)
        self.assertIn("http://juice:3000/rest/admin/whoami", candidates)



if __name__ == "__main__":
    unittest.main()
