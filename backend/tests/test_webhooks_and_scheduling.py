"""
Automated unit and integration tests for Option B:
- Webhook Dispatcher Engine & Channel Formatters (Discord, Slack, Teams, Generic)
- SSRF Validation Guardrails
- Webhook CRUD & RBAC
- Target Recurring Scan Scheduling & Daemon Runner
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = BACKEND_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from th.webapp import app
from th import db as dbmod
from th.webhook_dispatcher import (
    is_ssrf_safe_url,
    format_discord_payload,
    format_slack_payload,
    format_teams_payload,
    format_generic_payload,
    dispatch_webhook_event,
)
from th.scan_scheduler import _check_and_trigger_scheduled_scans


class WebhooksAndSchedulingTestCase(unittest.TestCase):
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

        # Create sample test target
        self.test_target = db.query(dbmod.WebTarget).filter_by(name="Scheduled Scan Target").first()
        if not self.test_target:
            self.test_target = dbmod.WebTarget(
                name="Scheduled Scan Target",
                url="https://example.com",
                authorization_status="AUTHORIZED",
                schedule_enabled=False,
            )
            db.add(self.test_target)
            db.commit()
        self.target_id = self.test_target.id
        db.close()

    def test_ssrf_guardrail_validation(self):
        """Test SSRF validation logic against public vs loopback/private URLs."""
        # Public URLs -> Safe
        safe, _ = is_ssrf_safe_url("https://discord.com/api/webhooks/123/xyz")
        self.assertTrue(safe)
        safe, _ = is_ssrf_safe_url("https://hooks.slack.com/services/T00/B00/X00")
        self.assertTrue(safe)

        # Loopback & Metadata -> Blocked
        safe, reason = is_ssrf_safe_url("http://127.0.0.1:5000/webhook")
        self.assertFalse(safe)
        self.assertIn("loopback", reason.lower())

        safe, reason = is_ssrf_safe_url("http://localhost/webhook")
        self.assertFalse(safe)

        safe, reason = is_ssrf_safe_url("http://169.254.169.254/latest/meta-data")
        self.assertFalse(safe)

        # Non-HTTP schemes -> Blocked
        safe, reason = is_ssrf_safe_url("ftp://example.com/webhook")
        self.assertFalse(safe)

    def test_channel_formatters(self):
        """Test Discord, Slack, Teams, and Generic payload generation."""
        # Discord Embed
        discord = format_discord_payload(
            severity="CRITICAL",
            title="SQL Injection Detected",
            description="Vulnerable parameter: id",
            source="https://target.local",
            event_type="finding.critical",
            details={"cve": "CWE-89"},
        )
        self.assertEqual(discord["username"], "DecodeX SOC & DAST")
        self.assertEqual(len(discord["embeds"]), 1)
        self.assertEqual(discord["embeds"][0]["color"], 0xFF2D55)
        self.assertIn("SQL Injection", discord["embeds"][0]["title"])

        # Slack Blocks
        slack = format_slack_payload(
            severity="HIGH",
            title="CORS Misconfiguration",
            description="Wildcard origin allowed",
            source="https://target.local",
            event_type="finding.high",
        )
        self.assertIn("blocks", slack)
        self.assertIn("HIGH", slack["text"])

        # Microsoft Teams MessageCard
        teams = format_teams_payload(
            severity="CRITICAL",
            title="Sensitive File Exposed",
            description="/.git/HEAD is accessible",
            source="https://target.local",
            event_type="finding.critical",
        )
        self.assertEqual(teams["@type"], "MessageCard")
        self.assertEqual(teams["themeColor"], "FF0000")

        # Generic JSON
        generic = format_generic_payload(
            severity="MEDIUM",
            title="Missing CSP Header",
            description="Content Security Policy missing",
            source="https://target.local",
            event_type="finding.medium",
        )
        self.assertEqual(generic["platform"], "DecodeX")
        self.assertEqual(generic["severity"], "MEDIUM")

    def test_webhook_crud_and_rbac(self):
        """Test webhook subscription management endpoints and role-based permissions."""
        webhook_payload = {
            "name": "SOC Discord Alerts",
            "url": "https://discord.com/api/webhooks/test/channel",
            "channel_type": "discord",
            "events_subscribed": "alert.critical,finding.critical",
            "is_active": True,
        }

        # Viewer attempt -> 403 Forbidden
        res_viewer = self.client.post(
            "/api/webhooks",
            headers={"Authorization": f"Bearer {self.viewer_token}"},
            json=webhook_payload,
        )
        self.assertEqual(res_viewer.status_code, 403)

        # Admin attempt -> 201 Created
        res_admin = self.client.post(
            "/api/webhooks",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json=webhook_payload,
        )
        self.assertEqual(res_admin.status_code, 201)
        wh_data = res_admin.get_json().get("webhook", {})
        wh_id = wh_data.get("id")
        self.assertIsNotNone(wh_id)
        self.assertEqual(wh_data.get("channel_type"), "discord")

        # List webhooks
        res_list = self.client.get(
            "/api/webhooks",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(res_list.status_code, 200)
        self.assertGreater(res_list.get_json().get("count", 0), 0)

        # Test Webhook Ping Endpoint (Mocked remote HTTP POST)
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.status_code = 204
            mock_post.return_value.text = ""

            res_test = self.client.post(
                f"/api/webhooks/{wh_id}/test",
                headers={"Authorization": f"Bearer {self.admin_token}"},
            )
            self.assertEqual(res_test.status_code, 200)
            self.assertTrue(res_test.get_json().get("delivered"))

        # Update Webhook
        res_update = self.client.put(
            f"/api/webhooks/{wh_id}",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json={"name": "SOC Discord Alerts (Renamed)"},
        )
        self.assertEqual(res_update.status_code, 200)
        self.assertEqual(res_update.get_json()["webhook"]["name"], "SOC Discord Alerts (Renamed)")

        # Delete Webhook
        res_del = self.client.delete(
            f"/api/webhooks/{wh_id}",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(res_del.status_code, 200)

    def test_target_scan_scheduling_api(self):
        """Test enabling and configuring recurring automated scans for a target."""
        schedule_payload = {
            "schedule_enabled": True,
            "schedule_interval_hours": 48,
        }

        # Enable schedule
        res = self.client.post(
            f"/api/web-targets/{self.target_id}/schedule",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json=schedule_payload,
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("schedule_enabled"))
        self.assertEqual(data.get("schedule_interval_hours"), 48)
        self.assertIsNotNone(data.get("next_scheduled_scan"))

        # Disable schedule
        res_disable = self.client.post(
            f"/api/web-targets/{self.target_id}/schedule",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json={"schedule_enabled": False},
        )
        self.assertEqual(res_disable.status_code, 200)
        self.assertFalse(res_disable.get_json().get("schedule_enabled"))
        self.assertIsNone(res_disable.get_json().get("next_scheduled_scan"))

    def test_scheduler_daemon_triggering(self):
        """Test that the scheduler loop detects due targets and initiates scan runs."""
        db = dbmod.SessionLocal()
        target = db.get(dbmod.WebTarget, self.target_id)
        target.enabled = True
        target.schedule_enabled = True
        # Set next_scheduled_scan in the past so it is immediately due
        target.next_scheduled_scan = dbmod.utcnow() - timedelta(minutes=5)
        target.schedule_interval_hours = 12
        db.commit()
        db.close()

        with patch("th.web_scanner.orchestrator._run_scan_job") as mock_scan_runner:
            _check_and_trigger_scheduled_scans()

            # Verify that a new scheduled WebScan was created in DB
            db = dbmod.SessionLocal()
            created_scan = (
                db.query(dbmod.WebScan)
                .filter_by(target_id=self.target_id, created_by="system.scheduler")
                .order_by(dbmod.WebScan.id.desc())
                .first()
            )
            self.assertIsNotNone(created_scan)
            self.assertEqual(created_scan.status, "PENDING")

            # Verify that target's next_scheduled_scan was advanced into the future
            updated_target = db.get(dbmod.WebTarget, self.target_id)
            self.assertGreater(updated_target.next_scheduled_scan, dbmod.utcnow())
            db.close()


if __name__ == "__main__":
    unittest.main()
