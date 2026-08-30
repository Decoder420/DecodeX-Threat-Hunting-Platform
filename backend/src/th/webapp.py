import os
os.environ.setdefault("EVENTLET_NO_GREENDNS", "yes")
import time 
import re
import threading
from datetime import datetime, timedelta

from functools import wraps

from flask import Flask, jsonify, request, send_file, g
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func

# Database and Scanner imports
from .db import (
    get_db, close_db, Alert, Event, User, FeedSource, SuppressionRule, IOC, ROLE_RANK,
    issue_token, get_user_for_token, revoke_token, revoke_all_tokens_for_user,
    create_ingest_key, get_active_ingest_key, revoke_ingest_key, IngestKey,
    user_has_permission, serialize_user, count_active_admins, utcnow,
    Asset, Case, WebFinding
)
from .incident_report import generate_alert_incident_pdf
from .pipeline import (
    DEFAULT_RULE_FILE,
    ingest_log_payload,
    build_ioc_sets,
    evaluate_events,
    persist_alerts,
    sync_ioc_feeds,
    update_alert_case,
)
from .rule_evaluator import RuleEvaluator
from .scanner import scanner
from .audit import write_audit
from .enterprise_api import register_enterprise_routes
from .log_watcher import start_log_watcher
from .web_scanner import set_broadcast as set_webscan_broadcast
from .logging_config import configure_structured_logging

configure_structured_logging()

app = Flask(__name__)
app.teardown_appcontext(close_db)

# CORS: restrict to known frontend origins strictly from ALLOWED_ORIGINS env var.
_allowed_origins_str = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost,http://127.0.0.1,http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001"
)
_allowed_origins = [o.strip() for o in _allowed_origins_str.split(",") if o.strip()]

# Expanded CORS to cover ALL routes (r"/*") using explicit allowed origins
CORS(
    app,
    resources={r"/*": {"origins": _allowed_origins}},
    supports_credentials=True,
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
)

socketio = SocketIO(
    app,
    cors_allowed_origins=_allowed_origins,
    async_mode="threading",
    ping_timeout=60,
    ping_interval=25,
    logger=True,
    engineio_logger=False
)

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# --- SYSTEM HEALTH & MONITORING ---
@app.route("/api/health")
def health():
    """System health check endpoint for uptime monitors, orchestrator liveness probes, and load balancers."""
    from sqlalchemy import text
    t0 = time.time()
    db_ok = False
    db_latency_ms = 0.0
    try:
        db = get_db()
        db.execute(text("SELECT 1"))
        db_ok = True
        db_latency_ms = round((time.time() - t0) * 1000, 2)
    except Exception as exc:
        db_ok = False
        db_latency_ms = round((time.time() - t0) * 1000, 2)

    # Engine reachability
    zap_status = {"available": False, "version": ""}
    try:
        from .web_scanner import zap_client
        zh = zap_client.health_check()
        zap_status = {"available": zh.get("available", False), "version": zh.get("version", "")}
    except Exception:
        pass

    from .log_watcher import get_watcher_status
    watcher_info = get_watcher_status()

    is_healthy = db_ok
    status_code = 200 if is_healthy else 503
    return jsonify({
        "status": "healthy" if is_healthy else "degraded",
        "timestamp": utcnow().isoformat(),
        "database": {
            "status": "connected" if db_ok else "disconnected",
            "latency_ms": db_latency_ms,
        },
        "engines": {
            "builtin": {"available": True, "version": "2.0"},
            "zap": zap_status,
        },
        "background_services": {
            "log_watcher": watcher_info,
        },
    }), status_code


# --- AUTHENTICATION RATE LIMITING ---
# Note: Counter is in-memory per worker process; effective cluster limit scales with Gunicorn worker count.
_login_rate_limits: dict[str, list[float]] = {}
_login_rate_lock = threading.Lock()
AUTH_RATE_LIMIT_MAX = int(os.environ.get("AUTH_RATE_LIMIT_MAX", "30"))  # 30 attempts
AUTH_RATE_LIMIT_WINDOW = int(os.environ.get("AUTH_RATE_LIMIT_WINDOW", "60"))  # 60s window


def _check_login_rate_limit(client_ip: str) -> tuple[bool, int]:
    now = time.time()
    with _login_rate_lock:
        window_start = now - AUTH_RATE_LIMIT_WINDOW
        attempts = [t for t in _login_rate_limits.get(client_ip, []) if t > window_start]
        if len(attempts) >= AUTH_RATE_LIMIT_MAX:
            retry_after = int(attempts[0] + AUTH_RATE_LIMIT_WINDOW - now) + 1
            return False, max(1, retry_after)
        attempts.append(now)
        _login_rate_limits[client_ip] = attempts
        return True, 0


# --- AUTHENTICATION ---
def api_error(code: str, message: str, status: int = 400, details: dict | None = None):
    return jsonify({
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }), status

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return ("", 204)
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split("Bearer ", 1)[-1].strip() if "Bearer " in auth_header else auth_header.strip()
        db = get_db()
        user = get_user_for_token(db, token)
        if not user:
            return api_error("UNAUTHORIZED", "Authentication required.", 401)
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if g.current_user.role != "admin":
            return api_error("FORBIDDEN", "Admin role required.", 403)
        return f(*args, **kwargs)
    return decorated

def require_permission(perm: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == "OPTIONS":
                return ("", 204)
            user = getattr(g, "current_user", None)
            if not user or not user_has_permission(user, perm):
                return api_error("FORBIDDEN", f"You do not have permission to perform this action ({perm}).", 403)
            return f(*args, **kwargs)
        return decorated
    return decorator

def role_required(min_role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_rank = ROLE_RANK.get(g.current_user.role, 0)
            if user_rank < ROLE_RANK.get(min_role, 99):
                return api_error("FORBIDDEN", f"Requires '{min_role}' role or higher.", 403)
            return f(*args, **kwargs)
        return decorated
    return decorator

def ingest_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        raw_key = (
            request.headers.get("X-API-Key")
            or request.headers.get("X-Ingest-Key")
            or request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        )
        if not raw_key:
            return jsonify({"error": "Ingest key required (X-API-Key header)"}), 401
        db = get_db()
        entry = authenticate_ingest_key(db, raw_key)
        if not entry:
            return jsonify({"error": "Invalid or missing ingest key"}), 401
        g.ingest_key = entry
        return f(*args, **kwargs)
    return decorated

@app.route("/api/auth/login", methods=["POST"])
def login():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    allowed, retry_after = _check_login_rate_limit(client_ip)
    if not allowed:
        err_body, status_code = api_error("TOO_MANY_REQUESTS", f"Too many login attempts. Please retry in {retry_after} seconds.", 429)
        resp = app.make_response((err_body, status_code))
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    data = request.get_json(silent=True) or {}
    username, password = data.get("username", "").strip(), data.get("password", "")
    if not username or not password:
        return api_error("BAD_REQUEST", "Username and password required.", 400)

    db = get_db()
    user = db.query(User).filter_by(username=username).first()
    if not user or not user.is_active or not check_password_hash(user.password_hash, password):
        write_audit(db, action="login.failure", username=username, details="Invalid credentials", success=False)
        return api_error("UNAUTHORIZED", "Invalid username or password.", 401)

    user.last_login = utcnow()
    db.commit()
    token = issue_token(db, user)
    write_audit(db, action="login.success", user=user, details="Session issued")
    return jsonify({"token": token, "user": serialize_user(user)})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.split("Bearer ", 1)[-1].strip() if "Bearer " in auth_header else auth_header.strip()
    db = get_db()
    user = get_user_for_token(db, token) if token else None
    if token:
        revoke_token(db, token)
    if user:
        write_audit(db, action="logout", user=user, details="Session revoked")
    return jsonify({"status": "logged out"})

@app.route("/api/auth/me")
@login_required
def me():
    return jsonify(serialize_user(g.current_user))

@app.route("/api/auth/change_password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    current_password = str(data.get("current_password") or "")
    new_password = str(data.get("new_password") or "")

    if not current_password or not new_password:
        return api_error("BAD_REQUEST", "Current password and new password are required.", 400)

    if not check_password_hash(g.current_user.password_hash, current_password):
        return api_error("UNAUTHORIZED", "Current password is incorrect.", 401)

    if len(new_password.strip()) < 8:
        return api_error("BAD_REQUEST", "New password must be at least 8 characters long.", 400)

    db = get_db()
    g.current_user.password_hash = generate_password_hash(new_password)
    db.commit()

    # Revoke all existing sessions so old tokens become invalid
    revoke_all_tokens_for_user(db, g.current_user.id)

    # Issue a fresh token for current session
    fresh_token = issue_token(db, g.current_user)

    write_audit(
        db,
        action="auth.password_change",
        user=g.current_user,
        resource_type="user",
        resource_id=str(g.current_user.id),
        details="User successfully changed password",
        success=True,
    )

    return jsonify({
        "success": True,
        "message": "Password changed successfully.",
        "token": fresh_token,
        "user": serialize_user(g.current_user),
    })

@app.route("/api/auth/revoke_all_sessions", methods=["POST"])
@login_required
def revoke_all_sessions():
    db = get_db()
    revoke_all_tokens_for_user(db, g.current_user.id)
    write_audit(
        db,
        action="auth.revoke_all_sessions",
        user=g.current_user,
        resource_type="user",
        resource_id=str(g.current_user.id),
        details="User revoked all active sessions",
        success=True,
    )
    return jsonify({"success": True, "message": "All active sessions have been revoked."})

def broadcast_new_alert(alert_obj):
    socketio.emit('new_alert', {
        "id": alert_obj.id,
        "name": alert_obj.description or "Unknown Alert",
        "severity": alert_obj.severity,
        "tactic": alert_obj.tactic,
        "host": alert_obj.host,
        "status": alert_obj.status or "OPEN",
        "source": "endpoint/live.log",
        "assigned": alert_obj.assigned_to or "Unassigned",
        "suppressed": "No",
        "timestamp": alert_obj.event_timestamp.isoformat()
    })

# --- CORE SIEM ROUTES ---
@app.route("/api/dashboard")
@login_required
@require_permission("dashboard.read")
def get_dashboard():
    range_val = request.args.get("range", "24h")
    db = get_db()
    
    delta_map = {
        "1h": timedelta(hours=1), "12h": timedelta(hours=12), "24h": timedelta(hours=24), 
        "3d": timedelta(days=3), "7d": timedelta(days=7), "15d": timedelta(days=15), 
        "1M": timedelta(days=30), "3M": timedelta(days=90), "6M": timedelta(days=180), "1Y": timedelta(days=365)
    }
    delta = delta_map.get(range_val, timedelta(hours=24))
    start_time = utcnow() - delta

    alerts_query = db.query(Alert).filter(Alert.event_timestamp >= start_time)
    alerts = alerts_query.order_by(Alert.event_timestamp.desc()).all()
    total_events = db.query(Event).filter(Event.timestamp >= start_time).count()

    high_or_above = sum(1 for a in alerts if a.severity.lower() in ['high', 'critical'])
    critical_alerts = sum(1 for a in alerts if a.severity.lower() == "critical")
    high_alerts = sum(1 for a in alerts if a.severity.lower() == "high")

    last_event = db.query(Event).order_by(Event.timestamp.desc()).first()
    last_ingest = last_event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_event else "N/A"
    
    feeds = db.query(FeedSource).all()
    ioc_total = db.query(func.count(IOC.id)).scalar() or 0
    ioc_by_type = {
        (row[0] or "unknown"): row[1]
        for row in db.query(IOC.type, func.count(IOC.id)).group_by(IOC.type).all()
    }
    open_cases = db.query(func.count(Case.id)).filter(Case.status.in_(["OPEN", "INVESTIGATING", "Open", "In Progress"])).scalar() or 0
    critical_assets = db.query(func.count(Asset.id)).filter(func.upper(Asset.criticality) == "CRITICAL").scalar() or 0
    web_findings = db.query(func.count(WebFinding.id)).scalar() or 0

    tactic_counts = [
        {"name": t, "value": c}
        for t, c in db.query(Alert.tactic, func.count(Alert.id))
        .filter(Alert.event_timestamp >= start_time, Alert.tactic != "")
        .group_by(Alert.tactic)
        .all()
        if t
    ]

    return jsonify({
        "metadata": {
            "last_ingest": last_ingest,
            "total_events": total_events,
            "total_alerts": len(alerts),
            "total_iocs": ioc_total,
            "open_cases": open_cases,
            "critical_assets": critical_assets,
            "web_findings": web_findings,
        },
        "kpis": {
            "total_alerts": len(alerts),
            "high_or_above": high_or_above,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "total_events": total_events,
            "open_cases": open_cases,
            "critical_assets": critical_assets,
            "ioc_matches": ioc_total,
            "web_findings": web_findings,
        },
        "alerts": [
            {
                "id": a.id, 
                "name": a.title or a.description or f"{a.tactic} Activity", 
                "severity": a.severity, 
                "status": a.status or "OPEN",
                "tactic": a.tactic,
                "technique_id": a.technique_id,
                "technique": a.technique_name,
                "risk_score": a.risk_score or 0,
                "host": a.host, 
                "user": a.user, 
                "source": a.source_name or "endpoint/sample.log",
                "timestamp": a.event_timestamp.isoformat(),
                "assigned": a.assigned_to or "Unassigned",
                "suppressed": "Yes" if a.is_suppressed else "No",
            } for a in alerts
        ],
        "feeds": [
            {
                "id": f.id,
                "name": f.name,
                "type": f.ioc_type or ("ip" if "IP" in (f.name or "") else "domain"),
                "url": f.url,
                "enabled": bool(f.enabled),
                "last_sync": f.last_sync.isoformat() if f.last_sync else None,
                "last_error": f.last_error or "",
            }
            for f in feeds
        ],
        "ioc_stats": {
            "total": ioc_total,
            "by_type": ioc_by_type,
        },
        "charts": {
            "tactics": tactic_counts,
            "hosts": [{"name": h, "count": c} for h, c in db.query(Alert.host, func.count(Alert.id)).filter(Alert.event_timestamp >= start_time).group_by(Alert.host).order_by(func.count(Alert.id).desc()).limit(5).all()]
        }
    })

@app.route("/api/alert_context/<int:alert_id>")
@login_required
@require_permission("alerts.read")
def get_alert_context(alert_id):
    db = get_db()
    alert = db.get(Alert, alert_id)
    if not alert: return jsonify({"error": "Not found"}), 404

    start, end = alert.event_timestamp - timedelta(minutes=30), alert.event_timestamp + timedelta(minutes=30)
    events = db.query(Event).filter(Event.host == alert.host, Event.timestamp >= start, Event.timestamp <= end).order_by(Event.timestamp.asc()).all()
    assignees = [
        {"id": u.id, "username": u.username, "role": u.role}
        for u in db.query(User).filter_by(is_active=True).order_by(User.username).all()
    ]

    ioc_hits = []
    if alert.ip:
        hit = db.query(IOC).filter_by(type="ip", value=alert.ip).first()
        if hit:
            ioc_hits.append({"indicator": hit.value, "type": hit.type, "source": hit.source, "confidence": getattr(hit, "confidence", 70)})
    if alert.domain:
        hit = db.query(IOC).filter_by(type="domain", value=alert.domain).first()
        if hit:
            ioc_hits.append({"indicator": hit.value, "type": hit.type, "source": hit.source, "confidence": getattr(hit, "confidence", 70)})

    return jsonify({
        "alert_id": alert.id,
        "status": alert.status or "Open",
        "assigned": alert.assigned_to or "",
        "assigned_to": alert.assigned_to or "",
        "analyst_notes": alert.analyst_notes or "",
        "assignees": assignees,
        "risk_score": alert.risk_score or 0,
        "confidence": alert.confidence or 70,
        "tactic": alert.tactic,
        "technique_id": alert.technique_id,
        "technique_name": alert.technique_name,
        "ioc_matches": ioc_hits,
        "timeline": [{
            "id": e.id,
            "ts": e.timestamp.isoformat(),
            "host": e.host,
            "user": e.user,
            "proc": e.process,
            "cmd": e.commandline,
            "ip": e.ip,
            "event_type": getattr(e, "event_type", ""),
            "source": e.source_name,
            "is_incident": e.id == alert.event_id,
        } for e in events]
    })

@app.route("/api/alerts/<int:alert_id>/case", methods=["POST"])
@login_required
@require_permission("alerts.write")
def update_alert_case_route(alert_id):
    """Updates an alert's case status, assignment, and notes."""
    data = request.get_json(silent=True) or request.form
    status = data.get("status")
    assigned_to = data.get("assigned_to", "")
    analyst_notes = data.get("analyst_notes", "")

    db = get_db()
    update_alert_case(db, alert_id, status, assigned_to, analyst_notes)

    updated_alert = db.get(Alert, alert_id)
    if not updated_alert:
        return jsonify({"error": "Alert not found after update"}), 404

    return jsonify({
        "id": updated_alert.id, "status": updated_alert.status,
        "assigned_to": updated_alert.assigned_to, "analyst_notes": updated_alert.analyst_notes,
    })

# --- LOG INGESTION ENDPOINT ---
@app.route("/api/ingest_logs", methods=["POST"])
@login_required
@require_permission("events.write")
def ingest_logs_route():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON payload"}), 400

    result = _run_ingest_pipeline(payload, source_name="webhook", source_type="cloud")
    return jsonify(result)

ALLOWED_SOAR_ACTIONS = {
    "BLOCK_IP", "ISOLATE_HOST", "DISABLE_USER", "MARK_FALSE_POSITIVE", "CLOSE_ALERT",
    "Isolate Host", "Block IP",
}

@app.route("/api/soar/action", methods=["POST"])
@login_required
@require_permission("soar.execute")
def soar_action():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    target = data.get("target")
    if not action or not target:
        return api_error("BAD_REQUEST", "action and target are required.", 400)
    if action not in ALLOWED_SOAR_ACTIONS:
        return api_error("BAD_REQUEST", f"Unsupported SOAR action '{action}'.", 400)
    time.sleep(0.3)
    write_audit(
        get_db(),
        action="soar.execute",
        user=g.current_user,
        resource_type="soar",
        resource_id=str(target),
        details=f"SIMULATION action={action} target={target}",
        success=True,
    )
    return jsonify({
        "status": "simulated",
        "mode": "SIMULATION",
        "message": f"[SIMULATION MODE] Would execute '{action}' on {target}. No real firewall/EDR action was performed.",
    })

# --- PDF REPORTING ENGINE ---
@app.route("/api/report/<int:alert_id>")
def generate_report(alert_id):
    # Token arrives as a query param here (not a header) because this URL is
    # opened directly by the browser for file download, not called via axios.
    token = request.args.get("token", "")
    db = get_db()
    user = get_user_for_token(db, token)
    if not user:
        return "Unauthorized", 401
    if not user_has_permission(user, "reports.read"):
        return "Forbidden", 403

    alert = db.get(Alert, alert_id)
    if not alert:
        return "Not found", 404

    prepared_by = (getattr(user, "username", None) or "Manan Mandal").strip()
    if prepared_by.lower() in {"admin", "administrator"}:
        prepared_by = "Manan Mandal"

    buffer = generate_alert_incident_pdf(db, alert, prepared_by=prepared_by)
    year = (alert.event_timestamp or alert.created_at or utcnow()).year
    download_name = f"IR-{year}-{int(alert.id):03d}_Incident_Report.pdf"
    response = send_file(
        buffer,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/pdf",
    )
    # Prevent browsers from serving a cached old single-page PDF.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Incident-Report-Template"] = "IR-TEMPLATE-2026.2"
    return response

# --- ADMIN, YARA & SUPPRESSION ---
@app.route("/api/admin/data")
@login_required
@require_permission("users.read")
def get_admin_data():
    db = get_db()
    return jsonify({
        "users": [serialize_user(u) for u in db.query(User).all()],
        "feeds": [{"id": f.id, "name": f.name, "url": f.url, "enabled": f.enabled, "last_sync": f.last_sync.isoformat() if f.last_sync else None, "last_error": f.last_error} for f in db.query(FeedSource).all()],
        "suppressions": [{"id": s.id, "indicator": s.field_value or s.name, "reason": s.reason, "active": s.is_active} for s in db.query(SuppressionRule).all()],
        "rules": []
    })

@app.route("/api/admin/feed/<int:feed_id>/toggle", methods=["POST"])
@login_required
@require_permission("feeds.write")
def toggle_feed(feed_id):
    db = get_db()
    feed = db.query(FeedSource).filter_by(id=feed_id).first()
    if not feed:
        return jsonify({"error": "Feed not found"}), 404
    feed.enabled = not feed.enabled
    db.commit()
    return jsonify({
        "id": feed.id,
        "name": feed.name,
        "enabled": feed.enabled,
        "last_sync": feed.last_sync.isoformat() if feed.last_sync else None,
        "last_error": feed.last_error,
    })

@app.route("/api/admin/suppressions/add", methods=["POST"])
@login_required
@require_permission("suppressions.write")
def add_suppression():
    data = request.get_json(silent=True) or {}
    indicator = data.get("indicator") or "unknown"
    db = get_db()
    rule = SuppressionRule(
        name=f"Suppression: {indicator}",
        rule_id="",
        field_name="indicator",
        field_value=indicator,
        reason="Manual suppression",
        is_active=True,
    )
    db.add(rule)
    db.commit()
    return jsonify({"status": "success", "message": "Suppression added successfully"})

def _safe_yara_filename(filename: str) -> str | None:
    """Allow only simple *.yar names inside RULES_DIR (no path traversal)."""
    if not filename:
        return None
    name = os.path.basename(str(filename).strip().replace("\\", "/"))
    if not name.lower().endswith(".yar"):
        name = f"{name}.yar"
    # Keep alnum, dash, underscore, and dot only.
    cleaned = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in name)
    if cleaned in {".", "..", ".yar"} or not cleaned.lower().endswith(".yar"):
        return None
    if ".." in cleaned:
        return None
    return cleaned


def _yara_template(rule_name: str) -> str:
    ident = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in rule_name)
    if ident[0:1].isdigit() or not ident:
        ident = f"rule_{ident or 'custom'}"
    return (
        f"rule {ident}\n"
        "{\n"
        "    meta:\n"
        '        description = "Custom uploaded / created YARA signature"\n'
        '        author = "SOC Analyst"\n'
        "    strings:\n"
        '        $a = "replace_me" ascii nocase\n'
        "    condition:\n"
        "        $a\n"
        "}\n"
    )

@app.route("/api/admin/rules")
@login_required
@require_permission("yara.read")
def list_rules():
    if not os.path.exists(RULES_DIR): os.makedirs(RULES_DIR)
    files = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".yar"))
    return jsonify({"rules": files})

@app.route("/api/admin/rules/content")
@login_required
@require_permission("yara.read")
def get_rule_content():
    filename = _safe_yara_filename(request.args.get("file"))
    if not filename:
        return api_error("BAD_REQUEST", "Invalid rule filename.", 400)
    path = os.path.join(RULES_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"content": f.read(), "file": filename})
    return api_error("NOT_FOUND", "File not found.", 404)

@app.route("/api/admin/rules/save", methods=["POST"])
@login_required
@require_permission("yara.write")
def save_rule():
    data = request.get_json(silent=True) or {}
    filename = _safe_yara_filename(data.get("file"))
    if not filename:
        return api_error("BAD_REQUEST", "Invalid rule filename.", 400)
    content = data.get("content")
    if content is None:
        return api_error("BAD_REQUEST", "Rule content required.", 400)
    if not os.path.exists(RULES_DIR):
        os.makedirs(RULES_DIR)
    path = os.path.join(RULES_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(content))
    scanner.reload_rules()
    return jsonify({"status": "deployed", "file": filename})

@app.route("/api/admin/rules/create", methods=["POST"])
@login_required
@require_permission("yara.write")
def create_rule():
    """Create a new blank/template YARA rule file."""
    data = request.get_json(silent=True) or {}
    filename = _safe_yara_filename(data.get("file") or data.get("name"))
    if not filename:
        return api_error("BAD_REQUEST", "Provide a valid .yar filename.", 400)
    if not os.path.exists(RULES_DIR):
        os.makedirs(RULES_DIR)
    path = os.path.join(RULES_DIR, filename)
    if os.path.exists(path) and not data.get("overwrite"):
        return api_error("CONFLICT", f"Rule '{filename}' already exists.", 409)
    content = data.get("content")
    if content is None or str(content).strip() == "":
        content = _yara_template(os.path.splitext(filename)[0])
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(content))
    scanner.reload_rules()
    return jsonify({"status": "created", "file": filename, "content": content})

@app.route("/api/admin/rules/upload", methods=["POST"])
@login_required
@require_permission("yara.write")
def upload_rule():
    """Upload one or more .yar signature files."""
    files = request.files.getlist("files") or []
    single = request.files.get("file")
    if single and single.filename:
        files.append(single)
    if not files:
        return jsonify({"error": "No .yar files uploaded"}), 400

    if not os.path.exists(RULES_DIR):
        os.makedirs(RULES_DIR)

    saved = []
    errors = []
    for uploaded in files:
        filename = _safe_yara_filename(uploaded.filename)
        if not filename:
            errors.append({"file": uploaded.filename, "error": "Invalid filename"})
            continue
        try:
            content = uploaded.read().decode("utf-8", errors="replace")
            path = os.path.join(RULES_DIR, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            saved.append(filename)
        except Exception as exc:
            errors.append({"file": uploaded.filename, "error": str(exc)})

    if saved:
        scanner.reload_rules()

    if not saved:
        return jsonify({"error": "No valid YARA files saved", "details": errors}), 400

    return jsonify({
        "status": "uploaded",
        "saved": saved,
        "errors": errors,
        "rules": sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".yar")),
    })

@app.route("/api/admin/feeds/sync", methods=["POST"])
@login_required
@require_permission("ioc.write")
def sync_feeds():
    summary = sync_ioc_feeds()
    return jsonify({"status": "success", "summary": summary})

# --- USER MANAGEMENT (admin only) ---
@app.route("/api/admin/users", methods=["GET"])
@login_required
@require_permission("users.read")
def list_users():
    db = get_db()
    return jsonify({
        "users": [serialize_user(u) for u in db.query(User).order_by(User.id).all()]
    })

@app.route("/api/admin/users", methods=["POST"])
@login_required
@require_permission("users.write")
def create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "analyst"

    if role not in ROLE_RANK:
        return api_error("BAD_REQUEST", f"role must be one of {list(ROLE_RANK)}", 400)
    if not username or len(password) < 8:
        return api_error("BAD_REQUEST", "username required, password must be 8+ characters.", 400)

    db = get_db()
    if db.query(User).filter_by(username=username).first():
        return api_error("CONFLICT", "Username already exists.", 409)

    user = User(username=username, password_hash=generate_password_hash(password), role=role, org_id=g.current_user.org_id)
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit(
        db,
        action="user.create",
        user=g.current_user,
        resource_type="user",
        resource_id=str(user.id),
        details=f"Created user '{user.username}' with role '{user.role}'",
        success=True,
    )
    return jsonify(serialize_user(user)), 201

@app.route("/api/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@require_permission("users.write")
def update_user_role(user_id):
    data = request.get_json(silent=True) or {}
    role = data.get("role")
    if role not in ROLE_RANK:
        return api_error("BAD_REQUEST", f"role must be one of {list(ROLE_RANK)}", 400)

    db = get_db()
    user = db.get(User, user_id)
    if not user:
        return api_error("NOT_FOUND", "User not found.", 404)

    # Prevent demoting/removing the last active administrator.
    if user.role == "admin" and user.is_active and role != "admin":
        if count_active_admins(db, exclude_user_id=user.id) < 1:
            return api_error(
                "CONFLICT",
                "Cannot change role: this is the last active administrator.",
                409,
            )

    old_role = user.role
    user.role = role
    db.commit()
    revoke_all_tokens_for_user(db, user.id)  # force re-login so new role takes effect immediately
    write_audit(
        db,
        action="user.role_change",
        user=g.current_user,
        resource_type="user",
        resource_id=str(user.id),
        details=f"Changed user '{user.username}' role from '{old_role}' to '{role}'",
        success=True,
    )
    return jsonify(serialize_user(user))

@app.route("/api/admin/users/<int:user_id>/deactivate", methods=["POST"])
@login_required
@require_permission("users.write")
def deactivate_user(user_id):
    db = get_db()
    user = db.get(User, user_id)
    if not user:
        return api_error("NOT_FOUND", "User not found.", 404)
    if user.id == g.current_user.id:
        return api_error("BAD_REQUEST", "Cannot deactivate your own account.", 400)
    if user.role == "admin" and user.is_active and count_active_admins(db, exclude_user_id=user.id) < 1:
        return api_error(
            "CONFLICT",
            "Cannot deactivate the last active administrator.",
            409,
        )
    user.is_active = False
    db.commit()
    revoke_all_tokens_for_user(db, user.id)
    write_audit(
        db,
        action="user.deactivate",
        user=g.current_user,
        resource_type="user",
        resource_id=str(user.id),
        details=f"Deactivated user '{user.username}'",
        success=True,
    )
    return jsonify({"status": "deactivated", "id": user.id})

@app.route("/api/admin/users/<int:user_id>/activate", methods=["POST"])
@login_required
@require_permission("users.write")
def activate_user(user_id):
    db = get_db()
    user = db.get(User, user_id)
    if not user:
        return api_error("NOT_FOUND", "User not found.", 404)
    user.is_active = True
    db.commit()
    write_audit(
        db,
        action="user.activate",
        user=g.current_user,
        resource_type="user",
        resource_id=str(user.id),
        details=f"Activated user '{user.username}'",
        success=True,
    )
    return jsonify(serialize_user(user))

@app.route("/api/admin/users/<int:user_id>/reset_password", methods=["POST"])
@login_required
@require_permission("users.write")
def reset_user_password(user_id):
    data = request.get_json(silent=True) or {}
    password = str(data.get("password") or "")
    if len(password.strip()) < 8:
        return api_error("BAD_REQUEST", "password must be 8+ characters.", 400)

    db = get_db()
    user = db.get(User, user_id)
    if not user:
        return api_error("NOT_FOUND", "User not found.", 404)

    user.password_hash = generate_password_hash(password)
    db.commit()
    revoke_all_tokens_for_user(db, user.id)
    write_audit(
        db,
        action="user.password_reset",
        user=g.current_user,
        resource_type="user",
        resource_id=str(user.id),
        details=f"Admin reset password for user '{user.username}'",
        success=True,
    )
    return jsonify({"status": "password_reset", "id": user.id})

# --- INGEST KEY MANAGEMENT (admin only) ---
@app.route("/api/admin/ingest_keys", methods=["GET"])
@login_required
@require_permission("ingest_keys.read")
def list_ingest_keys():
    db = get_db()
    keys = db.query(IngestKey).order_by(IngestKey.id).all()
    return jsonify({
        "keys": [
            {
                "id": k.id, "name": k.name, "source": k.source,
                "key_preview": f"...{k.key[-4:]}",
                "is_active": k.is_active,
                "created_at": k.created_at.isoformat(),
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            } for k in keys
        ]
    })

@app.route("/api/admin/ingest_keys", methods=["POST"])
@login_required
@require_permission("ingest_keys.write")
def create_ingest_key_route():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    source = (data.get("source") or "external").strip()
    if not name:
        return api_error("BAD_REQUEST", "name is required.", 400)
    db = get_db()
    entry = create_ingest_key(db, name=name, source=source, org_id=g.current_user.org_id)
    return jsonify({
        "id": entry.id, "name": entry.name, "source": entry.source,
        "key": entry.key, 
    }), 201

@app.route("/api/admin/ingest_keys/<int:key_id>/revoke", methods=["POST"])
@login_required
@require_permission("ingest_keys.write")
def revoke_ingest_key_route(key_id):
    db = get_db()
    if not revoke_ingest_key(db, key_id):
        return api_error("NOT_FOUND", "Key not found.", 404)
    return jsonify({"status": "revoked", "id": key_id})

# --- REAL-TIME LOG INGESTION (external sources) ---
def _run_ingest_pipeline(payload, source_name: str, source_type: str):
    db = get_db()
    evaluator = RuleEvaluator(str(DEFAULT_RULE_FILE))
    added, skipped, new_events = ingest_log_payload(db, payload, source_name=source_name, source_type=source_type)
    ioc_sets = build_ioc_sets(db.query(IOC).all())
    alerts = evaluate_events(db, new_events, evaluator, ioc_sets)
    alerts_added = persist_alerts(db, alerts, broadcast_fn=broadcast_new_alert)
    return {
        "status": "success",
        "events_added": added,
        "events_skipped": skipped,
        "alerts_generated": len(alerts),
        "alerts_added": alerts_added,
    }

@app.route("/api/ingest/vercel", methods=["GET", "POST"])
@ingest_key_required
def ingest_vercel():
    # Respond to verification handshake if Vercel sends GET or ping
    if request.method == "GET":
        verify_val = request.headers.get("x-vercel-verify") or "ok"
        response = jsonify({"status": "ready", "collector": "DecodeX Vercel Ingestion Gateway"})
        response.headers["x-vercel-verify"] = verify_val
        return response, 200

    payload = request.get_json(silent=True)
    if payload is None:
        raw_text = request.get_data(as_text=True)
        if raw_text:
            parsed = []
            for line in raw_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed.append(json.loads(line))
                except Exception:
                    parsed.append({"message": line, "timestamp": utcnow().isoformat() + "Z"})
            payload = parsed
        else:
            payload = []

    if not payload:
        return jsonify({"status": "success", "events_added": 0, "message": "Empty batch received"}), 200

    result = _run_ingest_pipeline(payload, source_name=f"vercel:{g.ingest_key.name}", source_type="cloud")
    return jsonify(result)

@app.route("/api/ingest/manual", methods=["POST"])
@login_required
@require_permission("events.write")
def ingest_manual():
    data = request.get_json(silent=True) or {}
    if "raw_text" in data:
        now = utcnow().isoformat() + "Z"
        lines = [line.strip() for line in (data.get("raw_text") or "").splitlines() if line.strip()]
        payload = [{"timestamp": now, "message": line} for line in lines]
    else:
        payload = data.get("logs", data)

    if not payload:
        return jsonify({"error": "No log content provided"}), 400

    result = _run_ingest_pipeline(payload, source_name=f"manual:{g.current_user.username}", source_type="manual")
    return jsonify(result)

@app.route("/api/ingest/upload", methods=["POST"])
@login_required
@require_permission("events.write")
def ingest_upload_file():
    uploaded_file = request.files.get("file") or request.files.get("log_file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"error": "No file uploaded. Please select a JSON or log file."}), 400

    filename = secure_filename(uploaded_file.filename) or "uploaded_logs.json"

    try:
        raw_bytes = uploaded_file.read()
        raw_text = raw_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"error": f"Failed to read file: {str(e)}"}), 400

    payload = None
    # 1. Try parsing full content as standard JSON (list of objects or single object)
    try:
        payload = json.loads(raw_text)
    except Exception:
        pass

    # 2. Try parsing as line-delimited JSON (NDJSON / JSONL) or fallback to text lines
    if payload is None:
        parsed_lines = []
        for line in raw_text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                parsed_lines.append(json.loads(line_str))
            except Exception:
                parsed_lines.append({
                    "message": line_str,
                    "timestamp": utcnow().isoformat() + "Z",
                })
        payload = parsed_lines

    if not payload:
        return jsonify({"error": "The uploaded file contains no valid log entries."}), 400

    db = get_db()
    source_name = f"upload:{filename}"
    try:
        result = _run_ingest_pipeline(payload, source_name=source_name, source_type="file_upload")
    except Exception as e:
        app.logger.exception("Failed to run ingest pipeline on uploaded file")
        return jsonify({"error": f"Log scanning error: {str(e)}"}), 500

    result["filename"] = filename

    try:
        write_audit(
            db,
            action="logs.upload",
            user=g.current_user,
            resource_type="logs",
            resource_id=filename,
            details=f"Uploaded {filename}: {result['events_added']} events added, {result['alerts_generated']} alerts generated",
            success=True,
        )
    except Exception:
        pass

    return jsonify(result)


# --- DEBUG SIMULATOR ---
@app.route("/api/debug/trigger_alert")
@login_required
@require_permission("system.write")
def trigger_alert():
    if os.environ.get("TH_ENABLE_DEBUG_ROUTES", "false").lower() != "true":
        return api_error("NOT_FOUND", "Debug routes disabled.", 404)
    db = get_db()
    ts = utcnow()
    new_event = Event(timestamp=ts, host="WIN-SRV-01", process="malware.exe", commandline="C2-Beacon")
    db.add(new_event)
    db.commit()
    new_alert = Alert(severity="Critical", description="beaconing_activity", tactic="Command and Control", host="WIN-SRV-01", event_id=new_event.id, event_timestamp=ts, status="OPEN")
    db.add(new_alert)
    db.commit()
    broadcast_new_alert(new_alert)
    return jsonify({"status": "broadcasted"})

# Register enterprise SOC routes (cases, assets, IOC, audit, webscan, ingestion, …)
register_enterprise_routes(
    app,
    login_required=login_required,
    require_permission=require_permission,
    broadcast_new_alert=broadcast_new_alert,
)

# --- SOCKET.IO EVENT HANDLERS ---
@socketio.on('connect')
def handle_connect():
    """Accept incoming WebSocket connections."""
    print(f"[Socket.IO] Client connected: {request.sid}")
    emit('connected', {'data': 'Connected to DecodeX SOC SIEM', 'sid': request.sid})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnections."""
    print(f"[Socket.IO] Client disconnected: {request.sid}")

@socketio.on('ping')
def handle_ping():
    """Echo pings from client (heartbeat)."""
    emit('pong', {'timestamp': utcnow().isoformat()})

# Web scan progress / lifecycle events over Socket.IO
from .web_scanner import set_broadcast as set_webscan_broadcast, recover_stale_scans, get_engine_status
set_webscan_broadcast(lambda event, payload: socketio.emit(event, payload))

# Recover any stale or interrupted scans from previous process lifetime
if os.environ.get("FLASK_ENV") != "testing":
    try:
        recovered = recover_stale_scans()
        if recovered:
            print(f"[OK] Recovered {recovered} stale/interrupted web scan(s).")
    except Exception as exc:
        print(f"[WARN] Failed recovering stale web scans: {exc}")

# Start background log tailer (offset-tracked via IngestionState).
if os.environ.get("TH_DISABLE_LOG_WATCHER", "").lower() not in ("1", "true", "yes") and os.environ.get("FLASK_ENV") != "testing":
    start_log_watcher(broadcast_fn=broadcast_new_alert, poll_seconds=float(os.environ.get("TH_INGEST_POLL_SECONDS", "2")))

if __name__ == "__main__":
    # Force 0.0.0.0 so Docker can route traffic to your Mac
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("TH_FLASK_DEBUG", "false").lower() == "true"

    # Startup diagnostics banner
    engine_status = get_engine_status()
    print("=" * 60)
    print("  DecodeX Threat Hunting & Web Security Platform")
    print(f"  Listening on: http://{host}:{port}")
    print(f"  Database Engine: {os.environ.get('DATABASE_URL', 'SQLite (threat_hunting.db)')}")
    print(f"  ZAP Available: {engine_status.get('zap', {}).get('available', False)}")
    print(f"  Nuclei Available: {engine_status.get('nuclei', {}).get('available', False)}")
    print(f"  Nmap Available: {engine_status.get('nmap', {}).get('available', False)}")
    print(f"  Safety Mode: {'LAB' if engine_status.get('safety', {}).get('lab_mode') else 'PRODUCTION'}")
    print("=" * 60)

    socketio.run(app, host=host, port=port, debug=debug_mode, allow_unsafe_werkzeug=True)