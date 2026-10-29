"""Tests for incident and web scanner report generation: timezone formatting,

company name branding, and sign-off table roles.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
import sys

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = BACKEND_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from th.incident_report import _fmt_dt as incident_fmt_dt, render_incident_pdf
from th.web_scanner_report import _fmt_dt as web_fmt_dt


class TestReportGeneration(unittest.TestCase):
    """Test report generation enhancements (timezones, branding, sign-off table)."""

    def test_fmt_dt_with_timezone(self):
        """Verify _fmt_dt converts UTC timestamps accurately according to timezone name."""
        dt = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        # Test UTC rendering
        res_utc = incident_fmt_dt(dt, "UTC")
        self.assertIn("12:00 UTC", res_utc)
        self.assertIn("01 September 2026", res_utc)

        # Test Asia/Kolkata (IST = UTC + 5:30)
        res_ist = incident_fmt_dt(dt, "Asia/Kolkata")
        self.assertIn("17:30 IST", res_ist)

        # Test America/New_York (EDT = UTC - 4:00)
        res_ny = incident_fmt_dt(dt, "America/New_York")
        self.assertIn("08:00 EDT", res_ny)

        # Verify web_scanner_report implementation matches
        res_web_ist = web_fmt_dt(dt, "Asia/Kolkata")
        self.assertEqual(res_ist, res_web_ist)

    def test_incident_report_branding_and_signoff_roles(self):
        """Assert generated report contains company name and the 3 required sign-off roles."""
        dt = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        ctx = {
            "incident_id": "IR-2026-TEST",
            "title": "Unauthorized Access Attempt",
            "severity": "HIGH",
            "status": "OPEN",
            "prepared_by": "Test Analyst",
            "prepared_role": "Information Security Engineer",
            "incident_date": dt,
            "report_date": dt,
            "organization": "DecodeX Security Technologies",
            "company_name": "DecodeX Security Technologies",
            "tagline": "Enterprise Threat Hunting & Modern Cloud SIEM",
            "timezone": "UTC",
            "contact_email": "soc@decodex.internal",
            "target_web_url": "https://target.internal",
            "target_web_name": "Internal Portal",
            "category": "Initial Access",
            "detection_source": "YARA Detection Engine",
            "affected_asset": "srv-auth-01",
            "affected_user": "admin_service",
            "business_impact": "High Risk — Account Compromise",
            "risk_score": 85,
            "confidence": 95,
            "tactic": "Initial Access",
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "description": "Multiple failed attempts followed by anomalous privilege escalation",
            "notes": "Isolated host srv-auth-01 from production subnet.",
            "commandline": "sudo su -",
            "process": "sudo",
            "ip": "10.0.1.45",
            "domain": "internal.corp",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "source_type": "auth_log",
            "events": [],
            "ioc_rows": [],
            "asset": None,
            "case": None,
            "timeline": [],
            "evidence": [],
            "alert": None,
        }

        pdf_buffer = render_incident_pdf(ctx)
        pdf_bytes = pdf_buffer.getvalue()
        self.assertGreater(len(pdf_bytes), 1000)

        with tempfile.NamedTemporaryFile(suffix=".pdf") as tmp:
            tmp.write(pdf_bytes)
            tmp.flush()
            text = subprocess.check_output(["pdftotext", tmp.name, "-"], text=True)

        # Assert default company name is rendered in the PDF document
        self.assertIn("DecodeX Security Technologies", text)

        # Assert the three sign-off roles exist in the ownership/approval table
        self.assertIn("SOC Analyst", text)
        self.assertIn("SOC Lead", text)
        self.assertIn("CISO", text)


if __name__ == "__main__":
    unittest.main()
