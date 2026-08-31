"""Automated tests proving full OWASP ZAP Integration in DecodeX."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = BACKEND_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

_tmp_dir = tempfile.mkdtemp(prefix="th_zaptest_")
os.environ["TH_ADMIN_USERNAME"] = "admin"
os.environ["TH_ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["TH_ANALYST_USERNAME"] = "analyst"
os.environ["TH_ANALYST_PASSWORD"] = "AnalystPass123!"
os.environ["TH_VIEWER_USERNAME"] = "viewer"
os.environ["TH_VIEWER_PASSWORD"] = "ViewerPass123!"
os.environ["WEBSCAN_ALLOW_PRIVATE_TARGETS"] = "false"
os.environ["WEBSCAN_ENABLED"] = "true"
os.environ["ZAP_ENABLED"] = "true"
os.environ["ZAP_URL"] = "http://127.0.0.1:8080"
os.environ["ZAP_API_KEY"] = "test-api-key"
os.environ.pop("DATABASE_URL", None)

from th import db as dbmod
dbmod.DATABASE_PATH = Path(_tmp_dir) / "test_zap.db"
dbmod.engine = dbmod.create_engine(
    f"sqlite:///{dbmod.DATABASE_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)
dbmod.SessionLocal = dbmod.sessionmaker(
    bind=dbmod.engine, autoflush=False, expire_on_commit=False
)
dbmod._db_initialized = False

from th.db import Alert, Event, WebFinding, WebScan, WebScanNode, WebTarget, get_db, _initialize_database
from th.web_scanner.engines import detect_engines, run_zap_active, run_zap_passive
from th.web_scanner.orchestrator import _run_scan_job
from th.web_scanner.surface import AttackSurfaceBuilder, build_tree_payload
from th.web_scanner.validators import SSRFError, validate_scan_url
from th.web_scanner.zap_client import ZapClient, ZAP_RISK_MAP, zap_client


class ZapIntegrationTests(unittest.TestCase):
    """Forensic verification of OWASP ZAP integration capabilities."""

    def setUp(self):
        _initialize_database()
        self._dns_patcher = patch(
            "th.web_scanner.validators.resolve_and_validate_host",
            return_value=["93.184.216.34"],
        )
        self._dns_patcher.start()

    def tearDown(self):
        self._dns_patcher.stop()

    # -------------------------------------------------------------------------
    # Requirement G: ZAP Health Detection
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_zap_health_detection_works(self, mock_req):
        client = ZapClient("http://127.0.0.1:8080", "secret-key")

        # Mock version response
        v_resp = MagicMock()
        v_resp.ok = True
        v_resp.json.return_value = {"version": "2.14.0"}

        # Mock add-ons response
        a_resp = MagicMock()
        a_resp.ok = True
        a_resp.json.return_value = {
            "installedAddons": [
                {"id": "spiderAjax", "version": "23.15.0", "name": "AJAX Spider"},
                {"id": "openapi", "version": "33.0.0", "name": "OpenAPI Support"},
                {"id": "replacer", "version": "14.0.0", "name": "Replacer"},
            ]
        }

        mock_req.side_effect = [v_resp, a_resp]
        health = client.health_check()

        self.assertTrue(health["available"])
        self.assertEqual(health["version"], "2.14.0")
        self.assertTrue(health["capabilities"]["ajax_spider"])
        self.assertTrue(health["capabilities"]["openapi_import"])
        self.assertTrue(health["capabilities"]["replacer"])

    # -------------------------------------------------------------------------
    # Requirement H: ZAP Unavailable State Graceful Handling
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req", side_effect=Exception("Connection refused"))
    def test_zap_unavailable_state_works(self, mock_req):
        client = ZapClient("http://127.0.0.1:9999", "")
        health = client.health_check()
        self.assertFalse(health["available"])
        self.assertIn("Connection refused", str(health["error"]))

        # Passive scan handles failure gracefully without crashing
        findings, err = client.fetch_normalized_alerts("https://example.com")
        self.assertEqual(findings, [])
        self.assertIn("Connection refused", str(err))

    # -------------------------------------------------------------------------
    # Requirement I: ZAP Scan Starts Successfully
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_zap_spider_scan_starts_successfully(self, mock_req):
        client = ZapClient("http://127.0.0.1:8080", "test-key")

        # Mock scan start, status 100, and results
        r_start = MagicMock(ok=True)
        r_start.json.return_value = {"scan": "42"}

        r_status = MagicMock(ok=True)
        r_status.json.return_value = {"status": "100"}

        r_results = MagicMock(ok=True)
        r_results.json.return_value = {
            "results": [
                "https://example.com/",
                "https://example.com/login",
                "https://example.com/api/v1/users",
            ]
        }

        r_opt = MagicMock(ok=True)
        mock_req.side_effect = [r_opt, r_start, r_status, r_results]
        urls, err = client.run_spider("https://example.com")

        self.assertIsNone(err)
        self.assertEqual(len(urls), 3)
        self.assertIn("https://example.com/api/v1/users", urls)

    # -------------------------------------------------------------------------
    # Requirement J: Scan Progress Reporting
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_zap_scan_progress_is_reported(self, mock_req):
        client = ZapClient("http://127.0.0.1:8080", "test-key")

        r_opt = MagicMock(ok=True)
        r_start = MagicMock(ok=True)
        r_start.json.return_value = {"scan": "1"}

        r_st1 = MagicMock(ok=True)
        r_st1.json.return_value = {"status": "45"}

        r_st2 = MagicMock(ok=True)
        r_st2.json.return_value = {"status": "100"}

        r_res = MagicMock(ok=True)
        r_res.json.return_value = {"results": ["https://example.com/"]}

        mock_req.side_effect = [r_opt, r_start, r_st1, r_st2, r_res]

        progress_reports = []
        urls, err = client.run_spider(
            "https://example.com",
            progress_callback=lambda p: progress_reports.append(p),
        )
        self.assertIsNone(err)
        self.assertIn(45, progress_reports)
        self.assertIn(100, progress_reports)

    # -------------------------------------------------------------------------
    # Requirement K & L: ZAP Findings Imported and Converted Correctly
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_zap_findings_imported_and_converted_correctly(self, mock_req):
        client = ZapClient("http://127.0.0.1:8080", "test-key")

        r_alerts = MagicMock(ok=True)
        r_alerts.json.return_value = {
            "alerts": [
                {
                    "alert": "SQL Injection",
                    "risk": "High",
                    "confidence": "Certain",
                    "description": "SQL injection in parameter id",
                    "solution": "Use parameterized queries",
                    "cweid": "89",
                    "url": "https://example.com/api/user?id=1",
                    "param": "id",
                    "method": "GET",
                    "evidence": "syntax error in SQL query",
                },
                {
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "risk": "Medium",
                    "confidence": "Medium",
                    "description": "CSP header is missing",
                    "solution": "Configure CSP header",
                    "cweid": "693",
                    "url": "https://example.com/",
                    "param": "",
                    "method": "GET",
                    "evidence": "",
                },
            ]
        }
        mock_req.return_value = r_alerts

        findings, err = client.fetch_normalized_alerts("https://example.com")
        self.assertIsNone(err)
        self.assertEqual(len(findings), 2)

        sqli = findings[0]
        self.assertEqual(sqli["title"], "SQL Injection")
        self.assertEqual(sqli["severity"], "HIGH")
        self.assertEqual(sqli["cwe"], "CWE-89")
        self.assertEqual(sqli["confidence"], 90)
        self.assertEqual(sqli["source_engine"], "zap")

        csp = findings[1]
        self.assertEqual(csp["severity"], "MEDIUM")
        self.assertEqual(csp["cwe"], "CWE-693")

    # -------------------------------------------------------------------------
    # Requirement M: Severity Mapping
    # -------------------------------------------------------------------------
    def test_zap_severity_mapping_works(self):
        self.assertEqual(ZAP_RISK_MAP.get("HIGH"), "HIGH")
        self.assertEqual(ZAP_RISK_MAP.get("MEDIUM"), "MEDIUM")
        self.assertEqual(ZAP_RISK_MAP.get("LOW"), "LOW")
        self.assertEqual(ZAP_RISK_MAP.get("INFORMATIONAL"), "INFO")
        self.assertEqual(ZAP_RISK_MAP.get("INFO"), "INFO")

    # -------------------------------------------------------------------------
    # Requirement N: Scan Cancellation
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_scan_cancellation_works(self, mock_req):
        client = ZapClient("http://127.0.0.1:8080", "test-key")

        r_opt = MagicMock(ok=True)
        r_start = MagicMock(ok=True)
        r_start.json.return_value = {"scan": "99"}
        r_stop = MagicMock(ok=True)
        mock_req.side_effect = [r_opt, r_start, r_stop]

        # Cancel immediately
        urls, err = client.run_spider(
            "https://example.com",
            cancel_check=lambda: True,
        )
        self.assertEqual(urls, [])
        self.assertIn("cancelled", str(err).lower())

    # -------------------------------------------------------------------------
    # Requirement O: Scan Timeout
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_scan_timeout_works(self, mock_req):
        client = ZapClient("http://127.0.0.1:8080", "test-key")

        r_opt = MagicMock(ok=True)
        r_start = MagicMock(ok=True)
        r_start.json.return_value = {"scan": "100"}
        r_status = MagicMock(ok=True)
        r_status.json.return_value = {"status": "10"}
        r_res = MagicMock(ok=True)
        r_res.json.return_value = {"results": []}

        mock_req.side_effect = [r_opt, r_start, r_status, r_res]

        # Timeout after 0.01 seconds
        urls, err = client.run_spider(
            "https://example.com",
            timeout=0,
        )
        self.assertIsNone(err)

    # -------------------------------------------------------------------------
    # Requirement P: SSRF Protection
    # -------------------------------------------------------------------------
    def test_ssrf_protection_blocks_private_destinations(self):
        self._dns_patcher.stop()
        try:
            client = ZapClient("http://127.0.0.1:8080", "")
            # Private IPs and localhosts must be blocked by default
            with self.assertRaises(SSRFError):
                client.run_spider("http://127.0.0.1:8080/admin", allow_private=False)

            with self.assertRaises(SSRFError):
                client.run_spider("http://169.254.169.254/latest/meta-data/", allow_private=False)

            with self.assertRaises(SSRFError):
                client.run_spider("http://10.0.0.1:8080", allow_private=False)
        finally:
            self._dns_patcher.start()

    # -------------------------------------------------------------------------
    # Requirement Q: Context and Scope Restrictions
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_scope_and_context_creation(self, mock_req):
        client = ZapClient("http://127.0.0.1:8080", "test-key")

        r_new = MagicMock(ok=True)
        r_new.json.return_value = {"contextId": "5"}
        r_inc = MagicMock(ok=True)
        r_ex = MagicMock(ok=True)
        r_scope = MagicMock(ok=True)

        mock_req.side_effect = [r_new, r_inc, r_ex, r_ex, r_ex, r_scope]

        cid = client.create_target_context(
            "ctx_example_1",
            "https://example.com/app/",
            exclude_regexes=[r".*logout.*"],
        )
        self.assertEqual(cid, "5")

    # -------------------------------------------------------------------------
    # Requirement R, S, T: Real-Time Attack Surface Tree & Severity Bubble-Up
    # -------------------------------------------------------------------------
    def test_attack_surface_receives_scan_events_and_propagates_severity(self):
        db = dbmod.SessionLocal()
        try:
            target = WebTarget(
                name="Security Target",
                url="https://sec-target.internal",
                authorization_status="AUTHORIZED",
            )
            db.add(target)
            db.commit()

            scan = WebScan(
                target_id=target.id,
                scan_profile="STANDARD",
                status="RUNNING",
            )
            db.add(scan)
            db.commit()

            builder = AttackSurfaceBuilder(db, scan)
            root = builder.ensure_root(target.url, hostname="sec-target.internal")

            # 1. ZAP discovers /admin and /admin/panel
            node_admin = builder.ensure_url_path(root, "https://sec-target.internal/admin")
            node_panel = builder.ensure_url_path(root, "https://sec-target.internal/admin/panel")

            self.assertIsNotNone(node_admin.id)
            self.assertIsNotNone(node_panel.id)

            # 2. Attach a CRITICAL finding to /admin/panel and verify propagation
            builder.attach_finding(node_panel, severity="CRITICAL", risk_score=95, has_alert=True)

            finding = WebFinding(
                scan_id=scan.id,
                target_id=target.id,
                node_id=node_panel.id,
                title="Remote Code Execution",
                severity="CRITICAL",
                confidence=95,
                affected_url="https://sec-target.internal/admin/panel",
                cwe="CWE-78",
                fingerprint="rce_zap_01",
                source_engine="zap",
            )
            db.add(finding)
            db.commit()

            # 3. Verify upward severity propagation
            tree_data = build_tree_payload(db, scan.id)
            self.assertIn("nodes", tree_data)
            self.assertIn("root_ids", tree_data)

            # Ancestors must have propagated severity to CRITICAL
            db.refresh(node_admin)
            db.refresh(root)
            self.assertEqual(node_admin.descendant_severity, "CRITICAL")
            self.assertEqual(root.descendant_severity, "CRITICAL")

            # Affected panel node is marked CRITICAL and clickable
            panel_node = db.get(WebScanNode, node_panel.id)
            self.assertEqual(panel_node.severity, "CRITICAL")
            self.assertEqual(panel_node.finding_count, 1)
            self.assertTrue(panel_node.has_alert)
        finally:
            db.close()

    # -------------------------------------------------------------------------
    # Scan Comparison & Diffing
    # -------------------------------------------------------------------------
    def test_zap_scan_comparison_diff(self):
        prev = [
            {"title": "Missing CSP", "affected_url": "https://example.com/", "parameter": ""},
            {"title": "Open Redirect", "affected_url": "https://example.com/redirect", "parameter": "to"},
        ]
        curr = [
            {"title": "Missing CSP", "affected_url": "https://example.com/", "parameter": ""},
            {"title": "SQL Injection", "affected_url": "https://example.com/api", "parameter": "q"},
        ]
        diff = ZapClient.compare_scans(prev, curr)
        self.assertEqual(diff["new_findings_count"], 1)
        self.assertEqual(diff["resolved_findings_count"], 1)
        self.assertEqual(diff["persistent_findings_count"], 1)
        self.assertEqual(diff["new_findings"][0]["title"], "SQL Injection")
        self.assertEqual(diff["resolved_findings"][0]["title"], "Open Redirect")

    # -------------------------------------------------------------------------
    # ZapDaemonManager Telemetry & Status
    # -------------------------------------------------------------------------
    @patch.object(ZapClient, "_req")
    def test_zap_daemon_manager_status(self, mock_req):
        from th.web_scanner.zap_daemon import ZapDaemonManager

        v_resp = MagicMock()
        v_resp.ok = True
        v_resp.json.return_value = {"version": "2.14.0"}

        a_resp = MagicMock()
        a_resp.ok = True
        a_resp.json.return_value = {"installedAddons": [{"id": "openapi", "version": "1.0", "name": "OpenAPI"}]}

        s_resp = MagicMock()
        s_resp.ok = True
        s_resp.json.return_value = {"scans": [{"id": "1", "status": "RUNNING"}]}

        mock_req.side_effect = [v_resp, a_resp, s_resp, s_resp]
        mgr = ZapDaemonManager("http://127.0.0.1:8080", "test-key")
        status = mgr.get_status()

        self.assertTrue(status["available"])
        self.assertTrue(status["healthy"])
        self.assertEqual(status["version"], "2.14.0")
        self.assertTrue(status["api_reachable"])
        self.assertEqual(status["active_scans"], 2)

    # -------------------------------------------------------------------------
    # OpenAPI Specification Parser (JSON & YAML)
    # -------------------------------------------------------------------------
    def test_openapi_spec_parser(self):
        from th.web_scanner.api_discovery import parse_openapi_spec

        json_spec = """{
            "openapi": "3.0.0",
            "info": {"title": "Test User API", "version": "1.0.0"},
            "paths": {
                "/api/users": {
                    "get": {
                        "summary": "List users",
                        "tags": ["Users"],
                        "parameters": [{"name": "limit", "in": "query", "type": "integer"}]
                    },
                    "post": {
                        "summary": "Create user",
                        "tags": ["Users"]
                    }
                },
                "/api/users/{id}": {
                    "delete": {
                        "summary": "Delete user",
                        "tags": ["Users"]
                    }
                }
            }
        }"""
        endpoints, meta, err = parse_openapi_spec(json_spec, base_url="https://api.example.com")
        self.assertIsNone(err)
        self.assertEqual(meta["title"], "Test User API")
        self.assertEqual(len(endpoints), 3)
        self.assertEqual(endpoints[0]["method"], "GET")
        self.assertEqual(endpoints[0]["path"], "/api/users")
        self.assertEqual(endpoints[0]["parameters"][0]["name"], "limit")

        yaml_spec = """
openapi: 3.0.1
info:
  title: YAML API
  version: 2.0.0
paths:
  /auth/login:
    post:
      summary: Login endpoint
"""
        ep_yaml, meta_yaml, err_yaml = parse_openapi_spec(yaml_spec, base_url="https://api.example.com")
        self.assertIsNone(err_yaml)
        self.assertEqual(meta_yaml["title"], "YAML API")
        self.assertEqual(len(ep_yaml), 1)
        self.assertEqual(ep_yaml[0]["path"], "/auth/login")
        self.assertEqual(ep_yaml[0]["method"], "POST")


if __name__ == "__main__":
    unittest.main()
