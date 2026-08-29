import unittest
from th.ai_engine import triage_alert, triage_web_finding
from th.pipeline import normalize_event_record
from th.db import get_db, OrgSettings, get_org_settings, update_org_settings

class TestPhase4Features(unittest.TestCase):

    def test_ai_alert_triage(self):
        sample_alert = {
            "id": 101,
            "description": "beaconing_activity",
            "technique_id": "T1071",
            "tactic": "Command and Control",
            "host": "WS-PROD-01",
            "user": "system",
            "ip": "45.148.10.12",
            "process": "svchost.exe",
            "severity": "HIGH",
            "risk_score": 88
        }
        res = triage_alert(sample_alert)
        self.assertEqual(res["engine"], "DecodeX AI Copilot")
        self.assertEqual(res["severity"], "HIGH")
        self.assertIn("T1071", res["mitre_analysis"]["technique_id"])
        self.assertIn("vercel_firewall", res["remediation_code"])
        self.assertIn("cloudflare_waf", res["remediation_code"])

    def test_ai_web_finding_triage(self):
        finding = {
            "title": "SQL Injection in Search Query",
            "severity": "CRITICAL",
            "cve_id": "CVE-2024-1234",
            "cwe_id": "CWE-89",
            "url": "https://example.com/api/search?q=1",
            "param": "q",
            "method": "GET"
        }
        target = {"name": "Example API", "url": "https://example.com"}
        res = triage_web_finding(finding, target)
        self.assertEqual(res["engine"], "DecodeX AI Copilot")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertIn("vercel_edge_middleware", res["edge_waf_mitigation"])

    def test_vercel_log_drain_normalization(self):
        vercel_record = {
            "timestamp": 1724915400000,
            "host": "acme-store.vercel.app",
            "proxy": {
                "clientIp": "203.0.113.45",
                "method": "POST",
                "path": "/api/auth/login",
                "statusCode": 401,
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            },
            "source": "lambda",
            "projectId": "prj_decodex_123"
        }
        event = normalize_event_record(vercel_record, source_name="vercel", source_type="cloud")
        self.assertIsNotNone(event)
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.url, "/api/auth/login")
        self.assertIn("POST /api/auth/login HTTP/401", event.commandline)
        self.assertEqual(event.event_type, "HTTP_401")

    def test_org_settings_persistence(self):
        db = get_db()
        s = get_org_settings(db, "test_org")
        self.assertIsNotNone(s)
        update_org_settings(db, {"company_name": "DecodeX Enterprise Inc", "timezone": "Asia/Kolkata"}, "test_org")
        updated = get_org_settings(db, "test_org")
        self.assertEqual(updated.company_name, "DecodeX Enterprise Inc")
        self.assertEqual(updated.timezone, "Asia/Kolkata")

if __name__ == "__main__":
    unittest.main()
