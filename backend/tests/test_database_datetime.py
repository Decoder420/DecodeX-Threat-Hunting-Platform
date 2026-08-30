"""Tests for canonical datetime handling, naive vs aware normalization, and migration safety."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from th.db import (
    AuthToken,
    Event,
    User,
    _initialize_database,
    _seed_defaults,
    create_engine,
    get_user_for_token,
    issue_token,
    sessionmaker,
    utcnow,
)
from th.pipeline import normalize_event_record


class DatabaseDatetimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
            future=True,
        )
        self.Session = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)

        # Initialize schema
        from th.db import Base

        Base.metadata.create_all(self.engine)

    def tearDown(self):
        try:
            self.engine.dispose()
            Path(self.db_path).unlink(missing_ok=True)
        except Exception:
            pass

    def test_utcnow_returns_naive_datetime(self):
        now = utcnow()
        self.assertIsInstance(now, datetime)
        self.assertIsNone(now.tzinfo, "utcnow() must return timezone-naive UTC for SQLite compatibility")

    def test_normalize_event_record_converts_aware_to_naive(self):
        # 1. ISO format with 'Z'
        rec1 = {"timestamp": "2026-08-29T12:00:00Z", "host": "srv1", "message": "test"}
        ev1 = normalize_event_record(rec1, "test_source", "syslog")
        self.assertIsNotNone(ev1)
        self.assertIsNone(ev1.timestamp.tzinfo)
        self.assertEqual(ev1.timestamp.year, 2026)

        # 2. ISO format with explicit offset +05:30
        rec2 = {"timestamp": "2026-08-29T17:30:00+05:30", "host": "srv2", "message": "offset test"}
        ev2 = normalize_event_record(rec2, "test_source", "syslog")
        self.assertIsNotNone(ev2)
        self.assertIsNone(ev2.timestamp.tzinfo)
        self.assertEqual(ev2.timestamp.hour, 12)  # 17:30 +05:30 -> 12:00 UTC

        # 3. Epoch milliseconds
        epoch_ms = 1756468800000  # approx timestamp
        rec3 = {"timestamp": epoch_ms, "host": "srv3", "message": "epoch test"}
        ev3 = normalize_event_record(rec3, "test_source", "syslog")
        self.assertIsNotNone(ev3)
        self.assertIsNone(ev3.timestamp.tzinfo)

    def test_token_expiration_with_naive_and_aware_comparison(self):
        db = self.Session()
        try:
            user = User(username="test_analyst", password_hash="hash", role="analyst", is_active=True)
            db.add(user)
            db.commit()

            # Active token
            token_active = issue_token(db, user, ttl_hours=2)
            fetched_user = get_user_for_token(db, token_active)
            self.assertIsNotNone(fetched_user)
            self.assertEqual(fetched_user.username, "test_analyst")

            # Expired token (simulate past expiration with naive UTC)
            token_row = db.query(AuthToken).filter_by(token=token_active).first()
            token_row.expires_at = utcnow() - timedelta(minutes=5)
            db.commit()

            expired_user = get_user_for_token(db, token_active)
            self.assertIsNone(expired_user, "Expired token should return None")
        finally:
            db.close()

    def test_idempotent_seeding(self):
        db = self.Session()
        try:
            # Seed multiple times on the same database
            _seed_defaults(db)
            user_count_1 = db.query(User).count()

            _seed_defaults(db)
            user_count_2 = db.query(User).count()

            self.assertEqual(user_count_1, user_count_2, "Seeding twice must not duplicate users")
            self.assertTrue(user_count_1 >= 3, "Should have seeded admin, analyst, and viewer")
        finally:
            db.close()
