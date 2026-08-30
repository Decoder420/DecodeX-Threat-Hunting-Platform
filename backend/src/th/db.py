import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, Boolean, UniqueConstraint, inspect, text, create_engine, event
)
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

# 1. Get the absolute path to the root folder
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Load backend/.env safely without overriding environment variables set by host/Docker/tests
load_dotenv(PROJECT_ROOT / ".env", override=False)


# 2. Define DATABASE_PATH
DATABASE_PATH = PROJECT_ROOT / "threat_hunting.db"

# --- ENTERPRISE FIX: Support both PostgreSQL (Production) and SQLite (Legacy/Local) ---
DB_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")

# Set connection args safely (Postgres rejects SQLite-specific args)
connect_args = {"check_same_thread": False, "timeout": 30} if DB_URL.startswith("sqlite") else {}

# 3. Create the engine
engine = create_engine(
    DB_URL,
    connect_args=connect_args,
    future=True,
)

# Only apply SQLite PRAGMAs if we are actually using SQLite
if DB_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
# --- END ENTERPRISE FIX ---

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

Base = declarative_base()

_init_lock = threading.Lock()
_db_initialized = False


def utcnow() -> datetime:
    # Naive UTC — SQLite + SQLAlchemy comparisons stay consistent.
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
    event_type = Column(String, nullable=False, default="")
    ingested_at = Column(DateTime, nullable=False, default=utcnow)
    destination_ip = Column(String, nullable=False, default="")
    destination_port = Column(String, nullable=False, default="")
    url = Column(String, nullable=False, default="")
    parent_process = Column(String, nullable=False, default="")
    pid = Column(String, nullable=False, default="")
    ppid = Column(String, nullable=False, default="")


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_ioc_type_value"),)

    id = Column(Integer, primary_key=True)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    source = Column(String, nullable=False, default="manual")
    first_seen = Column(DateTime, nullable=False, default=utcnow)
    last_seen = Column(DateTime, nullable=False, default=utcnow)
    confidence = Column(Integer, nullable=False, default=70)
    malicious = Column(Boolean, nullable=False, default=True)
    tags = Column(String, nullable=False, default="")
    expires_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, nullable=False, default="")


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
    last_login = Column(DateTime, nullable=True)


ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}

# Explicit permissions used by @require_permission. Roles stay on User.role;
# this map is the source of truth for what each role may do.
ROLE_PERMISSIONS = {
    "admin": frozenset({
        "users.read", "users.write",
        "roles.read", "roles.write",
        "alerts.read", "alerts.write",
        "events.read", "events.write",
        "rules.read", "rules.write",
        "yara.read", "yara.write",
        "sigma.read", "sigma.write",
        "feeds.read", "feeds.write",
        "suppressions.read", "suppressions.write",
        "cases.read", "cases.write",
        "ioc.read", "ioc.write",
        "assets.read", "assets.write",
        "webscan.read", "webscan.run",
        "soar.execute",
        "reports.read",
        "audit.read",
        "system.read", "system.write",
        "dashboard.read",
        "ingest_keys.read", "ingest_keys.write",
    }),
    "analyst": frozenset({
        "alerts.read", "alerts.write",
        "events.read", "events.write",
        "rules.read",
        "yara.read",
        "sigma.read",
        "feeds.read",
        "suppressions.read", "suppressions.write",
        "cases.read", "cases.write",
        "ioc.read", "ioc.write",
        "assets.read",
        "webscan.read", "webscan.run",
        "soar.execute",
        "reports.read",
        "dashboard.read",
    }),
    "viewer": frozenset({
        "alerts.read",
        "events.read",
        "ioc.read",
        "assets.read",
        "reports.read",
        "dashboard.read",
    }),
}


def permissions_for_role(role: str) -> list[str]:
    """Return sorted permission strings for a role (empty if unknown)."""
    return sorted(ROLE_PERMISSIONS.get(role or "", frozenset()))


def user_has_permission(user: "User", permission: str) -> bool:
    if not user or not user.is_active:
        return False
    return permission in ROLE_PERMISSIONS.get(user.role, frozenset())


def count_active_admins(db, *, exclude_user_id: int | None = None) -> int:
    query = db.query(User).filter_by(role="admin", is_active=True)
    if exclude_user_id is not None:
        query = query.filter(User.id != exclude_user_id)
    return query.count()


def serialize_user(user: "User") -> dict:
    """Canonical user payload for login / me / admin listings."""
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "permissions": permissions_for_role(user.role),
        "is_active": bool(user.is_active),
        "org_id": user.org_id,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


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
    risk_score = Column(Integer, nullable=False, default=0)
    confidence = Column(Integer, nullable=False, default=70)
    case_id = Column(Integer, nullable=True)
    title = Column(String, nullable=False, default="")


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
    source_type = Column(String, nullable=False, default="endpoint")
    enabled = Column(Boolean, nullable=False, default=True)
    status = Column(String, nullable=False, default="idle")
    last_error = Column(String, nullable=False, default="")
    event_count = Column(Integer, nullable=False, default=0)
    last_event_at = Column(DateTime, nullable=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("hostname", name="uq_assets_hostname"),)

    id = Column(Integer, primary_key=True)
    hostname = Column(String, nullable=False)
    ip = Column(String, nullable=False, default="")
    asset_type = Column(String, nullable=False, default="OTHER")
    operating_system = Column(String, nullable=False, default="")
    criticality = Column(String, nullable=False, default="MEDIUM")
    owner = Column(String, nullable=False, default="")
    environment = Column(String, nullable=False, default="lab")
    description = Column(String, nullable=False, default="")
    enabled = Column(Boolean, nullable=False, default=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True)
    case_number = Column(String, nullable=False, unique=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    severity = Column(String, nullable=False, default="MEDIUM")
    status = Column(String, nullable=False, default="OPEN")
    assigned_to = Column(String, nullable=False, default="")
    created_by = Column(String, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow)
    closed_at = Column(DateTime, nullable=True)
    risk_score = Column(Integer, nullable=False, default=0)


class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, nullable=False, index=True)
    author = Column(String, nullable=False, default="")
    body = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=utcnow)


class CaseAlert(Base):
    __tablename__ = "case_alerts"
    __table_args__ = (UniqueConstraint("case_id", "alert_id", name="uq_case_alert"),)

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, nullable=False, index=True)
    alert_id = Column(Integer, nullable=False, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow)
    user_id = Column(Integer, nullable=True)
    username = Column(String, nullable=False, default="")
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False, default="")
    resource_id = Column(String, nullable=False, default="")
    source_ip = Column(String, nullable=False, default="")
    details = Column(Text, nullable=False, default="")
    success = Column(Boolean, nullable=False, default=True)


class CorrelatedIncident(Base):
    __tablename__ = "correlated_incidents"

    id = Column(Integer, primary_key=True)
    case_number = Column(String, nullable=False, unique=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    severity = Column(String, nullable=False, default="MEDIUM")
    risk_score = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="OPEN")
    host = Column(String, nullable=False, default="")
    user = Column(String, nullable=False, default="")
    source_ip = Column(String, nullable=False, default="")
    tactic = Column(String, nullable=False, default="")
    technique_id = Column(String, nullable=False, default="")
    alert_count = Column(Integer, nullable=False, default=0)
    case_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),)

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, nullable=False, index=True)
    alert_id = Column(Integer, nullable=False, index=True)


class WebTarget(Base):
    __tablename__ = "web_targets"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    owner = Column(String, nullable=False, default="")
    authorization_status = Column(String, nullable=False, default="PENDING")
    scope = Column(String, nullable=False, default="")
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(String, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=utcnow)
    last_scan = Column(DateTime, nullable=True)
    last_status = Column(String, nullable=False, default="")
    environment = Column(String, nullable=False, default="lab")


class WebScan(Base):
    __tablename__ = "web_scans"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    status = Column(String, nullable=False, default="PENDING")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    findings_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    created_by = Column(String, nullable=False, default="")
    critical_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)
    scan_profile = Column(String, nullable=False, default="QUICK")
    progress = Column(Integer, nullable=False, default=0)
    current_stage = Column(String, nullable=False, default="")
    error_message = Column(Text, nullable=False, default="")
    duration = Column(Integer, nullable=False, default=0)
    discovered_urls = Column(Integer, nullable=False, default=0)
    discovered_ports = Column(Integer, nullable=False, default=0)
    technologies_count = Column(Integer, nullable=False, default=0)
    risk_score = Column(Integer, nullable=False, default=0)
    engine_versions = Column(Text, nullable=False, default="")
    configuration_json = Column(Text, nullable=False, default="")
    ports_json = Column(Text, nullable=False, default="")
    technologies_json = Column(Text, nullable=False, default="")
    nodes_count = Column(Integer, nullable=False, default=0)
    requests_used = Column(Integer, nullable=False, default=0)
    request_budget = Column(Integer, nullable=False, default=0)
    completed_stages = Column(Text, nullable=False, default="")  # JSON list
    safety_mode = Column(String, nullable=False, default="production")  # production|lab
    interrupted = Column(Boolean, nullable=False, default=False)


class WebFinding(Base):
    __tablename__ = "web_findings"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False, index=True)
    scan_id = Column(Integer, nullable=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    severity = Column(String, nullable=False, default="INFO")
    confidence = Column(Integer, nullable=False, default=70)
    category = Column(String, nullable=False, default="")
    evidence = Column(Text, nullable=False, default="")
    recommendation = Column(Text, nullable=False, default="")
    url = Column(String, nullable=False, default="")
    risk_score = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    cwe = Column(String, nullable=False, default="")
    owasp = Column(String, nullable=False, default="")
    cve = Column(String, nullable=False, default="")
    cvss = Column(Float, nullable=False, default=0.0)
    remediation = Column(Text, nullable=False, default="")
    affected_url = Column(String, nullable=False, default="")
    parameter = Column(String, nullable=False, default="")
    method = Column(String, nullable=False, default="")
    request = Column(Text, nullable=False, default="")
    response = Column(Text, nullable=False, default="")
    fingerprint = Column(String, nullable=False, default="", index=True)
    source_engine = Column(String, nullable=False, default="builtin")
    template_id = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="OPEN")
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    occurrence_count = Column(Integer, nullable=False, default=1)
    case_id = Column(Integer, nullable=True)
    risk_factors_json = Column(Text, nullable=False, default="")
    node_id = Column(Integer, nullable=True, index=True)
    alert_id = Column(Integer, nullable=True)


class WebScanNode(Base):
    """Attack-surface tree node discovered during a web scan."""

    __tablename__ = "web_scan_nodes"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, nullable=False, index=True)
    target_id = Column(Integer, nullable=False, index=True)
    parent_id = Column(Integer, nullable=True, index=True)
    node_key = Column(String, nullable=False, default="", index=True)
    node_type = Column(String, nullable=False, default="url")  # domain|subdomain|port|path|endpoint|api|service|finding
    label = Column(String, nullable=False, default="")
    url = Column(String, nullable=False, default="")
    hostname = Column(String, nullable=False, default="")
    ip = Column(String, nullable=False, default="")
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=False, default="")
    http_status = Column(Integer, nullable=True)
    title = Column(String, nullable=False, default="")
    technology = Column(String, nullable=False, default="")
    depth = Column(Integer, nullable=False, default=0)
    severity = Column(String, nullable=False, default="INFO")  # max direct finding severity
    descendant_severity = Column(String, nullable=False, default="")  # max among descendants
    finding_count = Column(Integer, nullable=False, default=0)
    descendant_finding_count = Column(Integer, nullable=False, default=0)
    has_alert = Column(Boolean, nullable=False, default=False)
    risk_score = Column(Integer, nullable=False, default=0)
    metadata_json = Column(Text, nullable=False, default="")
    discovered_at = Column(DateTime, nullable=False, default=utcnow)
    last_seen = Column(DateTime, nullable=False, default=utcnow)


class WebScanEvent(Base):
    """Persisted live scan activity events for replay and history."""

    __tablename__ = "web_scan_events"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, nullable=False, index=True)
    target_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String, nullable=False, default="")
    message = Column(String, nullable=False, default="")
    severity = Column(String, nullable=False, default="INFO")
    node_id = Column(Integer, nullable=True)
    finding_id = Column(Integer, nullable=True)
    payload_json = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=utcnow)


def _column_names(table_name: str) -> set[str]:
    inspector = inspect(engine)
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add_column_if_missing(connection, table_name: str, column_name: str, ddl: str) -> None:
    if inspect(engine).has_table(table_name) and column_name not in _column_names(table_name):
        connection.execute(text(ddl))


def _ensure_legacy_sqlite_columns() -> None:
    """One-time schema migration for older SQLite files. Must not run per-request."""
    if not DATABASE_PATH.exists():
        return

    with engine.begin() as connection:
        if inspect(engine).has_table("events"):
            event_cols = {
                "domain": "ALTER TABLE events ADD COLUMN domain VARCHAR NOT NULL DEFAULT ''",
                "file_hash": "ALTER TABLE events ADD COLUMN file_hash VARCHAR NOT NULL DEFAULT ''",
                "source_type": "ALTER TABLE events ADD COLUMN source_type VARCHAR NOT NULL DEFAULT 'endpoint'",
                "source_name": "ALTER TABLE events ADD COLUMN source_name VARCHAR NOT NULL DEFAULT 'sample.log'",
                "raw_payload": "ALTER TABLE events ADD COLUMN raw_payload TEXT NOT NULL DEFAULT ''",
                "event_type": "ALTER TABLE events ADD COLUMN event_type VARCHAR NOT NULL DEFAULT ''",
                "ingested_at": "ALTER TABLE events ADD COLUMN ingested_at DATETIME",
                "destination_ip": "ALTER TABLE events ADD COLUMN destination_ip VARCHAR NOT NULL DEFAULT ''",
                "destination_port": "ALTER TABLE events ADD COLUMN destination_port VARCHAR NOT NULL DEFAULT ''",
                "url": "ALTER TABLE events ADD COLUMN url VARCHAR NOT NULL DEFAULT ''",
                "parent_process": "ALTER TABLE events ADD COLUMN parent_process VARCHAR NOT NULL DEFAULT ''",
                "pid": "ALTER TABLE events ADD COLUMN pid VARCHAR NOT NULL DEFAULT ''",
                "ppid": "ALTER TABLE events ADD COLUMN ppid VARCHAR NOT NULL DEFAULT ''",
            }
            for column_name, ddl in event_cols.items():
                _add_column_if_missing(connection, "events", column_name, ddl)

        if inspect(engine).has_table("iocs"):
            added_first = "first_seen" not in _column_names("iocs")
            added_last = "last_seen" not in _column_names("iocs")
            _add_column_if_missing(connection, "iocs", "first_seen", "ALTER TABLE iocs ADD COLUMN first_seen DATETIME")
            _add_column_if_missing(connection, "iocs", "last_seen", "ALTER TABLE iocs ADD COLUMN last_seen DATETIME")
            _add_column_if_missing(connection, "iocs", "confidence", "ALTER TABLE iocs ADD COLUMN confidence INTEGER NOT NULL DEFAULT 70")
            _add_column_if_missing(connection, "iocs", "malicious", "ALTER TABLE iocs ADD COLUMN malicious BOOLEAN NOT NULL DEFAULT 1")
            _add_column_if_missing(connection, "iocs", "tags", "ALTER TABLE iocs ADD COLUMN tags VARCHAR NOT NULL DEFAULT ''")
            _add_column_if_missing(connection, "iocs", "expires_at", "ALTER TABLE iocs ADD COLUMN expires_at DATETIME")
            _add_column_if_missing(connection, "iocs", "metadata_json", "ALTER TABLE iocs ADD COLUMN metadata_json TEXT NOT NULL DEFAULT ''")
            if added_first:
                connection.execute(text("UPDATE iocs SET first_seen = CURRENT_TIMESTAMP WHERE first_seen IS NULL"))
            if added_last:
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
                "risk_score": "ALTER TABLE alerts ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0",
                "confidence": "ALTER TABLE alerts ADD COLUMN confidence INTEGER NOT NULL DEFAULT 70",
                "case_id": "ALTER TABLE alerts ADD COLUMN case_id INTEGER",
                "title": "ALTER TABLE alerts ADD COLUMN title VARCHAR NOT NULL DEFAULT ''",
            }
            existing_alert_cols = _column_names("alerts")
            for column_name, ddl in alert_columns.items():
                _add_column_if_missing(connection, "alerts", column_name, ddl)
            if "created_at" not in existing_alert_cols and "created_at" in _column_names("alerts"):
                connection.execute(text("UPDATE alerts SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
            if "event_timestamp" not in existing_alert_cols and "event_timestamp" in _column_names("alerts"):
                connection.execute(text("UPDATE alerts SET event_timestamp = CURRENT_TIMESTAMP WHERE event_timestamp IS NULL"))

        if inspect(engine).has_table("users"):
            _add_column_if_missing(connection, "users", "org_id", "ALTER TABLE users ADD COLUMN org_id VARCHAR NOT NULL DEFAULT 'default'")
            _add_column_if_missing(connection, "users", "is_active", "ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1")
            _add_column_if_missing(connection, "users", "last_login", "ALTER TABLE users ADD COLUMN last_login DATETIME")

        if inspect(engine).has_table("ingestion_state"):
            _add_column_if_missing(connection, "ingestion_state", "source_type", "ALTER TABLE ingestion_state ADD COLUMN source_type VARCHAR NOT NULL DEFAULT 'endpoint'")
            _add_column_if_missing(connection, "ingestion_state", "enabled", "ALTER TABLE ingestion_state ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 1")
            _add_column_if_missing(connection, "ingestion_state", "status", "ALTER TABLE ingestion_state ADD COLUMN status VARCHAR NOT NULL DEFAULT 'idle'")
            _add_column_if_missing(connection, "ingestion_state", "last_error", "ALTER TABLE ingestion_state ADD COLUMN last_error VARCHAR NOT NULL DEFAULT ''")
            _add_column_if_missing(connection, "ingestion_state", "event_count", "ALTER TABLE ingestion_state ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0")
            _add_column_if_missing(connection, "ingestion_state", "last_event_at", "ALTER TABLE ingestion_state ADD COLUMN last_event_at DATETIME")

        if inspect(engine).has_table("web_targets"):
            _add_column_if_missing(
                connection, "web_targets", "environment",
                "ALTER TABLE web_targets ADD COLUMN environment VARCHAR NOT NULL DEFAULT 'lab'",
            )

        if inspect(engine).has_table("web_scans"):
            scan_cols = {
                "critical_count": "ALTER TABLE web_scans ADD COLUMN critical_count INTEGER NOT NULL DEFAULT 0",
                "medium_count": "ALTER TABLE web_scans ADD COLUMN medium_count INTEGER NOT NULL DEFAULT 0",
                "low_count": "ALTER TABLE web_scans ADD COLUMN low_count INTEGER NOT NULL DEFAULT 0",
                "info_count": "ALTER TABLE web_scans ADD COLUMN info_count INTEGER NOT NULL DEFAULT 0",
                "scan_profile": "ALTER TABLE web_scans ADD COLUMN scan_profile VARCHAR NOT NULL DEFAULT 'QUICK'",
                "progress": "ALTER TABLE web_scans ADD COLUMN progress INTEGER NOT NULL DEFAULT 0",
                "current_stage": "ALTER TABLE web_scans ADD COLUMN current_stage VARCHAR NOT NULL DEFAULT ''",
                "error_message": "ALTER TABLE web_scans ADD COLUMN error_message TEXT NOT NULL DEFAULT ''",
                "duration": "ALTER TABLE web_scans ADD COLUMN duration INTEGER NOT NULL DEFAULT 0",
                "discovered_urls": "ALTER TABLE web_scans ADD COLUMN discovered_urls INTEGER NOT NULL DEFAULT 0",
                "discovered_ports": "ALTER TABLE web_scans ADD COLUMN discovered_ports INTEGER NOT NULL DEFAULT 0",
                "technologies_count": "ALTER TABLE web_scans ADD COLUMN technologies_count INTEGER NOT NULL DEFAULT 0",
                "risk_score": "ALTER TABLE web_scans ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0",
                "engine_versions": "ALTER TABLE web_scans ADD COLUMN engine_versions TEXT NOT NULL DEFAULT ''",
                "configuration_json": "ALTER TABLE web_scans ADD COLUMN configuration_json TEXT NOT NULL DEFAULT ''",
                "ports_json": "ALTER TABLE web_scans ADD COLUMN ports_json TEXT NOT NULL DEFAULT ''",
                "technologies_json": "ALTER TABLE web_scans ADD COLUMN technologies_json TEXT NOT NULL DEFAULT ''",
            }
            for column_name, ddl in scan_cols.items():
                _add_column_if_missing(connection, "web_scans", column_name, ddl)

        if inspect(engine).has_table("web_findings"):
            finding_cols = {
                "cwe": "ALTER TABLE web_findings ADD COLUMN cwe VARCHAR NOT NULL DEFAULT ''",
                "owasp": "ALTER TABLE web_findings ADD COLUMN owasp VARCHAR NOT NULL DEFAULT ''",
                "cve": "ALTER TABLE web_findings ADD COLUMN cve VARCHAR NOT NULL DEFAULT ''",
                "cvss": "ALTER TABLE web_findings ADD COLUMN cvss FLOAT NOT NULL DEFAULT 0",
                "remediation": "ALTER TABLE web_findings ADD COLUMN remediation TEXT NOT NULL DEFAULT ''",
                "affected_url": "ALTER TABLE web_findings ADD COLUMN affected_url VARCHAR NOT NULL DEFAULT ''",
                "parameter": "ALTER TABLE web_findings ADD COLUMN parameter VARCHAR NOT NULL DEFAULT ''",
                "method": "ALTER TABLE web_findings ADD COLUMN method VARCHAR NOT NULL DEFAULT ''",
                "request": "ALTER TABLE web_findings ADD COLUMN request TEXT NOT NULL DEFAULT ''",
                "response": "ALTER TABLE web_findings ADD COLUMN response TEXT NOT NULL DEFAULT ''",
                "fingerprint": "ALTER TABLE web_findings ADD COLUMN fingerprint VARCHAR NOT NULL DEFAULT ''",
                "source_engine": "ALTER TABLE web_findings ADD COLUMN source_engine VARCHAR NOT NULL DEFAULT 'builtin'",
                "template_id": "ALTER TABLE web_findings ADD COLUMN template_id VARCHAR NOT NULL DEFAULT ''",
                "status": "ALTER TABLE web_findings ADD COLUMN status VARCHAR NOT NULL DEFAULT 'OPEN'",
                "first_seen": "ALTER TABLE web_findings ADD COLUMN first_seen DATETIME",
                "last_seen": "ALTER TABLE web_findings ADD COLUMN last_seen DATETIME",
                "occurrence_count": "ALTER TABLE web_findings ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1",
                "case_id": "ALTER TABLE web_findings ADD COLUMN case_id INTEGER",
                "risk_factors_json": "ALTER TABLE web_findings ADD COLUMN risk_factors_json TEXT NOT NULL DEFAULT ''",
                "node_id": "ALTER TABLE web_findings ADD COLUMN node_id INTEGER",
                "alert_id": "ALTER TABLE web_findings ADD COLUMN alert_id INTEGER",
            }
            for column_name, ddl in finding_cols.items():
                _add_column_if_missing(connection, "web_findings", column_name, ddl)

        if inspect(engine).has_table("web_scans"):
            extra_scan = {
                "nodes_count": "ALTER TABLE web_scans ADD COLUMN nodes_count INTEGER NOT NULL DEFAULT 0",
                "requests_used": "ALTER TABLE web_scans ADD COLUMN requests_used INTEGER NOT NULL DEFAULT 0",
                "request_budget": "ALTER TABLE web_scans ADD COLUMN request_budget INTEGER NOT NULL DEFAULT 0",
                "completed_stages": "ALTER TABLE web_scans ADD COLUMN completed_stages TEXT NOT NULL DEFAULT ''",
                "safety_mode": "ALTER TABLE web_scans ADD COLUMN safety_mode VARCHAR NOT NULL DEFAULT 'production'",
                "interrupted": "ALTER TABLE web_scans ADD COLUMN interrupted BOOLEAN NOT NULL DEFAULT 0",
            }
            for column_name, ddl in extra_scan.items():
                _add_column_if_missing(connection, "web_scans", column_name, ddl)


def _ensure_role_user(db, *, username: str, password: str | None, role: str, allow_generated: bool = False) -> None:
    """Create or sync a role account from backend/.env credentials."""
    username = (username or "").strip()
    password = (password or "").strip() or None
    if not username:
        return

    user = db.query(User).filter_by(username=username).first()

    if not password:
        if user:
            return
        if not allow_generated:
            return
        import secrets as _secrets
        password = _secrets.token_urlsafe(12)
        print(
            f"\n[SETUP] No password set for role '{role}'. Generated one-time "
            f"password for '{username}': {password}\n"
            f"         Set TH_{role.upper()}_PASSWORD in backend/.env, then restart.\n"
        )

    if len(password) < 8:
        print(
            f"[SETUP] Skipping '{username}' ({role}): password in .env must be "
            "at least 8 characters."
        )
        return

    if user:
        changed = False
        if user.role != role:
            user.role = role
            changed = True
        if not check_password_hash(user.password_hash, password):
            user.password_hash = generate_password_hash(password)
            changed = True
            # Force re-login after password change from .env
            revoke_all_tokens_for_user(db, user.id)
            print(f"[SETUP] Updated password for '{username}' ({role}) from .env.")
        elif changed:
            print(f"[SETUP] Updated role for '{username}' -> '{role}' from .env.")
        return

    db.add(
        User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            org_id="default",
        )
    )
    print(f"[SETUP] Seeded user '{username}' with role '{role}'.")


def _seed_defaults(db) -> None:
    # Role accounts (viewer < analyst < admin). Credentials come from backend/.env.
    _ensure_role_user(
        db,
        username=os.environ.get("TH_ADMIN_USERNAME", "admin"),
        password=os.environ.get("TH_ADMIN_PASSWORD"),
        role="admin",
        allow_generated=True,
    )
    _ensure_role_user(
        db,
        username=os.environ.get("TH_ANALYST_USERNAME", "analyst"),
        password=os.environ.get("TH_ANALYST_PASSWORD"),
        role="analyst",
    )
    _ensure_role_user(
        db,
        username=os.environ.get("TH_VIEWER_USERNAME", "viewer"),
        password=os.environ.get("TH_VIEWER_PASSWORD"),
        role="viewer",
    )

    default_feeds = [
        {
            "name": "Abuse.ch IP Feed",
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "ioc_type": "ip",
        },
        {
            "name": "ThreatFox Domains",
            "url": "https://threatfox.abuse.ch/export/csv/domains/recent/",
            "ioc_type": "domain",
        },
    ]
    existing = {feed.name: feed for feed in db.query(FeedSource).all()}
    for feed in default_feeds:
        current = existing.get(feed["name"])
        if not current:
            db.add(FeedSource(**feed))
            continue
        # Repair known-broken seeded URL from older installs.
        if "threatfox.abuse.ch/export/json/domains" in (current.url or ""):
            current.url = feed["url"]
            current.ioc_type = feed["ioc_type"]
            current.last_error = ""
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
    expires = entry.expires_at
    if expires is None:
        db.delete(entry)
        db.commit()
        return None
    # Normalize to naive UTC for comparison with utcnow().
    if getattr(expires, "tzinfo", None) is not None:
        expires = expires.astimezone(timezone.utc).replace(tzinfo=None)
    if expires < utcnow():
        db.delete(entry)
        db.commit()
        return None
    user = db.get(User, entry.user_id)
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
    entry = db.get(IngestKey, key_id)
    if not entry:
        return False
    entry.is_active = False
    db.commit()
    return True


class OrgSettings(Base):
    __tablename__ = "org_settings"

    id = Column(Integer, primary_key=True)
    org_id = Column(String(64), unique=True, default="default", index=True)
    company_name = Column(String(255), default="DecodeX Security Technologies Private Limited")
    tagline = Column(String(255), default="Enterprise Threat Hunting & Modern Cloud SIEM")
    timezone = Column(String(64), default="UTC")
    contact_email = Column(String(255), default="soc@decodex.internal")
    slack_webhook_url = Column(Text, default="")
    discord_webhook_url = Column(Text, default="")
    teams_webhook_url = Column(Text, default="")
    ai_provider = Column(String(64), default="builtin")  # "builtin", "gemini", "openai"
    ai_api_key = Column(String(255), default="")
    retention_days = Column(Integer, default=90)
    compliance_mode = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


def get_org_settings(db, org_id: str = "default") -> OrgSettings:
    settings = db.query(OrgSettings).filter_by(org_id=org_id).first()
    if not settings:
        settings = OrgSettings(org_id=org_id)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def update_org_settings(db, data: dict, org_id: str = "default") -> OrgSettings:
    settings = get_org_settings(db, org_id)
    allowed_fields = [
        "company_name", "tagline", "timezone", "contact_email",
        "slack_webhook_url", "discord_webhook_url", "teams_webhook_url",
        "ai_provider", "ai_api_key", "retention_days", "compliance_mode"
    ]
    for field in allowed_fields:
        if field in data:
            setattr(settings, field, data[field])
    settings.updated_at = utcnow()
    db.commit()
    db.refresh(settings)
    return settings


def _initialize_database() -> None:
    """Create tables, migrate legacy columns, and seed defaults once per process."""
    global _db_initialized
    if _db_initialized:
        return

    with _init_lock:
        if _db_initialized:
            return
        Base.metadata.create_all(engine)
        _ensure_legacy_sqlite_columns()
        db = SessionLocal()
        try:
            _seed_defaults(db)
        finally:
            db.close()
        _db_initialized = True


def get_db():
    """Return a request-scoped session when Flask context exists, else a new session."""
    _initialize_database()
    try:
        from flask import g, has_app_context

        if has_app_context():
            db = getattr(g, "th_db", None)
            if db is None:
                db = SessionLocal()
                g.th_db = db
            return db
    except Exception:
        pass
    return SessionLocal()


def close_db(exception=None):
    """Close the request-scoped session (register as Flask teardown)."""
    try:
        from flask import g

        db = g.pop("th_db", None)
        if db is not None:
            db.close()
    except Exception:
        pass