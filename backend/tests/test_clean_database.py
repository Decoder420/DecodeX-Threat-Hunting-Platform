"""Automated tests proving that DecodeX contains zero demo or sample security data."""

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

_tmp_dir = tempfile.mkdtemp(prefix="th_cleandb_")
os.environ["TH_ADMIN_USERNAME"] = "admin"
os.environ["TH_ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["TH_ANALYST_USERNAME"] = "analyst"
os.environ["TH_ANALYST_PASSWORD"] = "AnalystPass123!"
os.environ["TH_VIEWER_USERNAME"] = "viewer"
os.environ["TH_VIEWER_PASSWORD"] = "ViewerPass123!"
os.environ.pop("DATABASE_URL", None)

from th import db as dbmod
dbmod.DATABASE_PATH = Path(_tmp_dir) / "test_clean.db"
dbmod.engine = dbmod.create_engine(
    f"sqlite:///{dbmod.DATABASE_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)
dbmod.SessionLocal = dbmod.sessionmaker(
    bind=dbmod.engine, autoflush=False, expire_on_commit=False
)
dbmod._db_initialized = False

from th.db import (
    Alert,
    Asset,
    Case,
    Event,
    IOC,
    User,
    WebFinding,
    WebScan,
    WebTarget,
    get_db,
    _initialize_database,
)
from th.pipeline import IOC_FEEDS, refresh_hunting_state
from th.rule_evaluator import RuleEvaluator


class CleanDatabaseVerificationTests(unittest.TestCase):
    """Forensic verification that fresh DecodeX installations contain zero demo security data."""

    def setUp(self):
        with dbmod.engine.connect() as conn:
            pass

    def test_fresh_database_contains_zero_demo_security_records(self):
        """Requirement A: Fresh database contains no demo security data."""
        _initialize_database()
        db = dbmod.SessionLocal()
        try:
            # Zero security records
            self.assertEqual(db.query(Alert).count(), 0, "Expected 0 alerts in fresh database.")
            self.assertEqual(db.query(Event).count(), 0, "Expected 0 events in fresh database.")
            self.assertEqual(db.query(IOC).count(), 0, "Expected 0 IOCs in fresh database.")
            self.assertEqual(db.query(Asset).count(), 0, "Expected 0 assets in fresh database.")
            self.assertEqual(db.query(Case).count(), 0, "Expected 0 cases in fresh database.")
            self.assertEqual(db.query(WebTarget).count(), 0, "Expected 0 web targets in fresh database.")
            self.assertEqual(db.query(WebScan).count(), 0, "Expected 0 web scans in fresh database.")
            self.assertEqual(db.query(WebFinding).count(), 0, "Expected 0 web findings in fresh database.")
        finally:
            db.close()

    def test_starting_decodex_does_not_insert_demo_assets(self):
        """Requirement B: Starting DecodeX does not insert demo assets (DC-01, WEB-01, etc.)."""
        _initialize_database()
        db = dbmod.SessionLocal()
        try:
            demo_hostnames = ["DC-01", "WEB-01", "PC-01", "PC-02", "PC-03", "DB-01", "FW-01"]
            for h in demo_hostnames:
                asset = db.query(Asset).filter_by(hostname=h).first()
                self.assertIsNone(asset, f"Demo asset '{h}' must not exist in fresh database.")
            self.assertEqual(db.query(Asset).count(), 0)
        finally:
            db.close()

    def test_starting_decodex_does_not_insert_demo_iocs(self):
        """Requirement C: Starting DecodeX does not insert demo IOCs."""
        self.assertEqual(len(IOC_FEEDS), 0, "Default IOC_FEEDS must be empty in production.")
        _initialize_database()
        db = dbmod.SessionLocal()
        try:
            demo_iocs = ["45.148.10.12", "185.220.101.1", "malicious.example.com"]
            for val in demo_iocs:
                found = db.query(IOC).filter_by(value=val).first()
                self.assertIsNone(found, f"Demo IOC '{val}' must not be auto-seeded.")
            self.assertEqual(db.query(IOC).count(), 0)
        finally:
            db.close()

    def test_refresh_hunting_state_does_not_seed_demo_alerts_or_events(self):
        """Requirement D & E: Starting/refreshing DecodeX does not insert demo alerts or events."""
        db = dbmod.SessionLocal()
        try:
            evaluator = RuleEvaluator(str(BACKEND_ROOT / "hunting_rules.yml"))
            res = refresh_hunting_state(db, evaluator)
            self.assertEqual(res["iocs_added"], 0)
            self.assertEqual(res["events_added"], 0)
            self.assertEqual(res["alerts_added"], 0)

            self.assertEqual(db.query(Event).count(), 0)
            self.assertEqual(db.query(Alert).count(), 0)
        finally:
            db.close()

    def test_only_authorized_configured_users_exist(self):
        """Required users may exist only if explicitly configured through environment variables."""
        _initialize_database()
        db = dbmod.SessionLocal()
        try:
            users = db.query(User).all()
            usernames = {u.username for u in users}
            self.assertIn("admin", usernames)
            self.assertIn("analyst", usernames)
            self.assertIn("viewer", usernames)
            self.assertEqual(len(users), 3)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
