import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean, UniqueConstraint, inspect, text, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash

# 1. Get the absolute path to the root folder
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# 2. Define DATABASE_PATH
DATABASE_PATH = PROJECT_ROOT / "threat_hunting.db"

# 3. Create the engine and session
engine = create_engine(f"sqlite:///{DATABASE_PATH}", connect_args={"check_same_thread": False}, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint(
            "timestamp",
            "host",
            "user",
            "process",
            "commandline",
            "ip",
            "domain",
            "file_hash",
            "source_name",
            name="uq_event_fingerprint",
        ),
    )

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    host = Column(String, nullable=False, default="")
    user = Column(String, nullable=False, default="")
    process = Column(String, nullable=False, default="")
    commandline = Column(String, nullable=False, default="")
    ip = Column(String, nullable=False, default="")
    domain = Column(String, nullable=False, default="")
    file_hash = Column(String, nullable=False, default="")
    source_type = Column(String, nullable=False, default="endpoint")
    source_name = Column(String, nullable=False, default="sample.log")
    raw_payload = Column(Text, nullable=False, default="")


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_ioc_type_value"),)

    id = Column(Integer, primary_key=True)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    source = Column(String, nullable=False, default="manual")
    first_seen = Column(DateTime, nullable=False, default=utcnow)
    last_seen = Column(DateTime, nullable=False, default=utcnow)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_users_username"),)

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    # RBAC: "admin" > "analyst" > "viewer". Enforced server-side via
    # ROLE_RANK / role_required in webapp.py — never trust a client role.
    role = Column(String, nullable=False, default="analyst")
    # Lightweight tenant scoping now so a future multi-tenant migration
    # doesn't require backfilling every table. Single-tenant deployments
    # can leave this as the default "default" org.
    org_id = Column(String, nullable=False, default="default")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


class AuthToken(Base):
    """Server-side session tokens issued at login.

    Deliberately simple (opaque random token, DB-backed, expiring) rather
    than JWT — no new crypto dependency, tokens are revocable server-side
    (just delete the row), and it's easy to swap for JWT/OAuth later
    without changing the auth contract the frontend relies on.
    """
    __tablename__ = "auth_tokens"

    id = Column(Integer, primary_key=True)
    token = Column(String, nullable=False, unique=True, index=True)
    user_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False)


class IngestKey(Base):
    """API keys for machine-to-machine log ingestion (Vercel log drains,
    custom apps, etc.) — separate from user login tokens since the sender
    isn't a logged-in person. Scoped to a source name so events/alerts can
    be traced back to which integration sent them."""
    __tablename__ = "ingest_keys"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    source = Column(String, nullable=False, default="external")
    key = Column(String, nullable=False, unique=True, index=True)
    org_id = Column(String, nullable=False, default="default")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    last_used_at = Column(DateTime, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("rule_id", "event_id", name="uq_alert_rule_event"),)

    id = Column(Integer, primary_key=True)
    rule_id = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(String, nullable=False)
    tactic = Column(String, nullable=False, default="")
    technique_id = Column(String, nullable=False, default="")
    technique_name = Column(String, nullable=False, default="")
    event_id = Column(Integer, nullable=False)
    host = Column(String, nullable=False, default="")
    user = Column(String, nullable=False, default="")
    process = Column(String, nullable=False, default="")
    ip = Column(String, nullable=False, default="")
    domain = Column(String, nullable=False, default="")
    file_hash = Column(String, nullable=False, default="")
    commandline = Column(String, nullable=False, default="")
    source_type = Column(String, nullable=False, default="")
    source_name = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="Open")
    assigned_to = Column(String, nullable=False, default="")
    analyst_notes = Column(Text, nullable=False, default="")
    is_suppressed = Column(Boolean, nullable=False, default=False)
    suppression_reason = Column(String, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=utcnow)
    event_timestamp = Column(DateTime, nullable=False)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    rule_id = Column(String, nullable=False, default="")
    field_name = Column(String, nullable=False, default="")
    field_value = Column(String, nullable=False, default="")
    reason = Column(String, nullable=False, default="")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class FeedSource(Base):
    __tablename__ = "feed_sources"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    ioc_type = Column(String, nullable=False, default="ip")
    enabled = Column(Boolean, nullable=False, default=True)
    last_sync = Column(DateTime, nullable=True)
    last_error = Column(String, nullable=False, default="")


class IngestionState(Base):
    __tablename__ = "ingestion_state"
    __table_args__ = (UniqueConstraint("source", name="uq_ingestion_source"),)

    id = Column(Integer, primary_key=True)
    source = Column(String, nullable=False)
    offset = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime, nullable=False, default=utcnow)


def _column_names(table_name: str) -> set[str]:
    inspector = inspect(engine)
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add_column_if_missing(connection, table_name: str, column_name: str, ddl: str) -> None:
    if inspect(engine).has_table(table_name) and column_name not in _column_names(table_name):
        connection.execute(text(ddl))


def _ensure_legacy_sqlite_columns() -> None:
    if not DATABASE_PATH.exists():
        return

    with engine.begin() as connection:
        if inspect(engine).has_table("events"):
            _add_column_if_missing(connection, "events", "domain", "ALTER TABLE events ADD COLUMN domain VARCHAR NOT NULL DEFAULT ''")
            _add_column_if_missing(connection, "events", "file_hash", "ALTER TABLE events ADD COLUMN file_hash VARCHAR NOT NULL DEFAULT ''")
            _add_column_if_missing(connection, "events", "source_type", "ALTER TABLE events ADD COLUMN source_type VARCHAR NOT NULL DEFAULT 'endpoint'")
            _add_column_if_missing(connection, "events", "source_name", "ALTER TABLE events ADD COLUMN source_name VARCHAR NOT NULL DEFAULT 'sample.log'")
            _add_column_if_missing(connection, "events", "raw_payload", "ALTER TABLE events ADD COLUMN raw_payload TEXT NOT NULL DEFAULT ''")

        if inspect(engine).has_table("iocs"):
            _add_column_if_missing(connection, "iocs", "first_seen", "ALTER TABLE iocs ADD COLUMN first_seen DATETIME")
            _add_column_if_missing(connection, "iocs", "last_seen", "ALTER TABLE iocs ADD COLUMN last_seen DATETIME")
            if "first_seen" in _column_names("iocs"):
                connection.execute(text("UPDATE iocs SET first_seen = CURRENT_TIMESTAMP WHERE first_seen IS NULL"))
            if "last_seen" in _column_names("iocs"):
                connection.execute(text("UPDATE iocs SET last_seen = CURRENT_TIMESTAMP WHERE last_seen IS NULL"))

        if inspect(engine).has_table("alerts"):
            alert_columns = {
                "tactic": "ALTER TABLE alerts ADD COLUMN tactic VARCHAR NOT NULL DEFAULT ''",
                "technique_id": "ALTER TABLE alerts ADD COLUMN technique_id VARCHAR NOT NULL DEFAULT ''",
                "technique_name": "ALTER TABLE alerts ADD COLUMN technique_name VARCHAR NOT NULL DEFAULT ''",
                "domain": "ALTER TABLE alerts ADD COLUMN domain VARCHAR NOT NULL DEFAULT ''",
                "file_hash": "ALTER TABLE alerts ADD COLUMN file_hash VARCHAR NOT NULL DEFAULT ''",
                "commandline": "ALTER TABLE alerts ADD COLUMN commandline VARCHAR NOT NULL DEFAULT ''",
                "created_at": "ALTER TABLE alerts ADD COLUMN created_at DATETIME",
                "event_timestamp": "ALTER TABLE alerts ADD COLUMN event_timestamp DATETIME",
                "source_type": "ALTER TABLE alerts ADD COLUMN source_type VARCHAR NOT NULL DEFAULT ''",
                "source_name": "ALTER TABLE alerts ADD COLUMN source_name VARCHAR NOT NULL DEFAULT ''",
                "status": "ALTER TABLE alerts ADD COLUMN status VARCHAR NOT NULL DEFAULT 'Open'",
                "assigned_to": "ALTER TABLE alerts ADD COLUMN assigned_to VARCHAR NOT NULL DEFAULT ''",
                "analyst_notes": "ALTER TABLE alerts ADD COLUMN analyst_notes TEXT NOT NULL DEFAULT ''",
                "is_suppressed": "ALTER TABLE alerts ADD COLUMN is_suppressed BOOLEAN NOT NULL DEFAULT 0",
                "suppression_reason": "ALTER TABLE alerts ADD COLUMN suppression_reason VARCHAR NOT NULL DEFAULT ''",
            }
            for column_name, ddl in alert_columns.items():
                _add_column_if_missing(connection, "alerts", column_name, ddl)
            if "created_at" in _column_names("alerts"):
                connection.execute(text("UPDATE alerts SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
            if "event_timestamp" in _column_names("alerts"):
                connection.execute(text("UPDATE alerts SET event_timestamp = CURRENT_TIMESTAMP WHERE event_timestamp IS NULL"))

        if inspect(engine).has_table("users"):
            _add_column_if_missing(connection, "users", "org_id", "ALTER TABLE users ADD COLUMN org_id VARCHAR NOT NULL DEFAULT 'default'")
            _add_column_if_missing(connection, "users", "is_active", "ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1")


def _seed_defaults(db) -> None:
    if not db.query(User).filter_by(username="admin").first():
        # Never ship a hardcoded default password. Require it from the
        # environment; generate + print a random one-time password if the
        # operator hasn't set one, so there's no "admin123" anyone can guess.
        admin_password = os.environ.get("TH_ADMIN_PASSWORD")
        if not admin_password:
            import secrets as _secrets
            admin_password = _secrets.token_urlsafe(12)
            print(
                "\n[SETUP] No TH_ADMIN_PASSWORD set. Generated one-time admin "
                f"password: {admin_password}\n"
                "         Log in as 'admin' with this password, then change it "
                "immediately (or set TH_ADMIN_PASSWORD and re-seed).\n"
            )
        db.add(User(username="admin", password_hash=generate_password_hash(admin_password), role="admin", org_id="default"))

    default_feeds = [
        {"name": "Abuse.ch IP Feed", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ioc_type": "ip"},
        {"name": "ThreatFox Domains", "url": "https://threatfox.abuse.ch/export/json/domains/", "ioc_type": "domain"},
    ]
    existing_names = {feed.name for feed in db.query(FeedSource).all()}
    for feed in default_feeds:
        if feed["name"] not in existing_names:
            db.add(FeedSource(**feed))

    db.commit()


def issue_token(db, user: "User", ttl_hours: int = 12) -> str:
    """Create and persist a new session token for a user."""
    import secrets as _secrets

    token = _secrets.token_hex(32)
    db.add(AuthToken(token=token, user_id=user.id, expires_at=utcnow() + timedelta(hours=ttl_hours)))
    db.commit()
    return token


def get_user_for_token(db, token: str):
    """Return the active User for a valid, unexpired token, else None."""
    if not token:
        return None
    entry = db.query(AuthToken).filter_by(token=token).first()
    if not entry:
        return None
    if entry.expires_at.replace(tzinfo=timezone.utc) < utcnow():
        db.delete(entry)
        db.commit()
        return None
    user = db.query(User).get(entry.user_id)
    if not user or not user.is_active:
        return None
    return user


def revoke_token(db, token: str) -> None:
    entry = db.query(AuthToken).filter_by(token=token).first()
    if entry:
        db.delete(entry)
        db.commit()


def revoke_all_tokens_for_user(db, user_id: int) -> None:
    """Used when a user is deactivated or has their role changed, so an
    already-issued session can't keep using old privileges."""
    db.query(AuthToken).filter_by(user_id=user_id).delete()
    db.commit()


def create_ingest_key(db, name: str, source: str, org_id: str = "default") -> "IngestKey":
    import secrets as _secrets

    key = "thk_" + _secrets.token_hex(24)  # "thk_" prefix makes leaked keys greppable
    entry = IngestKey(name=name, source=source, key=key, org_id=org_id)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def get_active_ingest_key(db, key: str):
    if not key:
        return None
    entry = db.query(IngestKey).filter_by(key=key, is_active=True).first()
    if entry:
        entry.last_used_at = utcnow()
        db.commit()
    return entry


def revoke_ingest_key(db, key_id: int) -> bool:
    entry = db.query(IngestKey).get(key_id)
    if not entry:
        return False
    entry.is_active = False
    db.commit()
    return True


def get_db():
    Base.metadata.create_all(engine)
    _ensure_legacy_sqlite_columns()
    db = SessionLocal()
    _seed_defaults(db)
    return db