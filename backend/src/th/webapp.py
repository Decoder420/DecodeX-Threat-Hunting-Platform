from flask import Flask, jsonify, request, send_file, g
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import os
import io
import time 
import re

# ReportLab for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Database and Scanner imports
from .db import (
    get_db, close_db, Alert, Event, User, FeedSource, SuppressionRule, IOC, ROLE_RANK,
    issue_token, get_user_for_token, revoke_token, revoke_all_tokens_for_user,
    create_ingest_key, get_active_ingest_key, revoke_ingest_key, IngestKey,
)
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
from sqlalchemy import func

app = Flask(__name__)
app.teardown_appcontext(close_db)

# CORS: restrict to known frontend origins. Set ALLOWED_ORIGINS as a
# comma-separated env var in production (e.g. "https://app.yourdomain.com").
# Falls back to local dev origins only — never "*" with credentials.
_allowed_origins_str = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001",
)
_allowed_origins = _allowed_origins_str.split(",")
# Also allow ngrok domains for development.
# The free plan uses a random subdomain on each launch.
_allowed_origins.append(re.compile(r"https?://.*\.ngrok-free\.app"))

CORS(app, resources={r"/*": {"origins": _allowed_origins}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins=_allowed_origins, async_mode="threading")

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# --- AUTHENTICATION ---
# Real, DB-backed session tokens. Issued by /api/auth/login after checking
# the hashed password, verified here on every request, and revocable via
# /api/auth/logout. No more shared static token.
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split("Bearer ", 1)[-1].strip() if "Bearer " in auth_header else auth_header.strip()
        db = get_db()
        user = get_user_for_token(db, token)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if g.current_user.role != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


def role_required(min_role):
    """Require the caller's role to be at least `min_role` in the
    viewer < analyst < admin hierarchy. Always stack under @login_required
    (it reads g.current_user, which login_required sets)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_rank = ROLE_RANK.get(g.current_user.role, 0)
            if user_rank < ROLE_RANK.get(min_role, 99):
                return jsonify({"error": f"Forbidden: requires '{min_role}' role or higher"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def ingest_key_required(f):
    """Auth for machine-to-machine ingestion (Vercel log drains, custom
    apps) — a static per-integration key, not a user login token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Ingest-Key") or request.args.get("key", "")
        db = get_db()
        entry = get_active_ingest_key(db, key)
        if not entry:
            return jsonify({"error": "Invalid or missing ingest key"}), 401
        g.ingest_key = entry
        return f(*args, **kwargs)
    return decorated


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username", "").strip(), data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    db = get_db()
    user = db.query(User).filter_by(username=username).first()
    # Constant-shape response whether the user exists or not, to avoid
    # leaking which usernames are valid via response differences.
    if not user or not user.is_active or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = issue_token(db, user)
    return jsonify({
        "token": token,
        "user": {"id": user.id, "username": user.username, "role": user.role},
    })


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    # Idempotent: always succeed locally even if the token is already gone.
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.split("Bearer ", 1)[-1].strip() if "Bearer " in auth_header else auth_header.strip()
    if token:
        revoke_token(get_db(), token)
    return jsonify({"status": "logged out"})


@app.route("/api/auth/me")
@login_required
def me():
    u = g.current_user
    return jsonify({"id": u.id, "username": u.username, "role": u.role})

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
def get_dashboard():
    range_val = request.args.get("range", "24h")
    db = get_db()
    
    # NEW: Expanded Mega-Time Ranges
    delta_map = {
        "1h": timedelta(hours=1), "12h": timedelta(hours=12), "24h": timedelta(hours=24), 
        "3d": timedelta(days=3), "7d": timedelta(days=7), "15d": timedelta(days=15), 
        "1M": timedelta(days=30), "3M": timedelta(days=90), "6M": timedelta(days=180), "1Y": timedelta(days=365)
    }
    delta = delta_map.get(range_val, timedelta(hours=24))
    start_time = datetime.utcnow() - delta

    alerts_query = db.query(Alert).filter(Alert.event_timestamp >= start_time)
    alerts = alerts_query.order_by(Alert.event_timestamp.desc()).all()
    total_events = db.query(Event).filter(Event.timestamp >= start_time).count()

    # By fetching all alerts first, we can derive counts in memory
    # instead of hitting the database multiple times for the same dataset.
    high_or_above = sum(1 for a in alerts if a.severity.lower() in ['high', 'critical'])

    last_event = db.query(Event).order_by(Event.timestamp.desc()).first()
    last_ingest = last_event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_event else "N/A"
    
    feeds = db.query(FeedSource).all()
    ioc_total = db.query(func.count(IOC.id)).scalar() or 0
    ioc_by_type = {
        (row[0] or "unknown"): row[1]
        for row in db.query(IOC.type, func.count(IOC.id)).group_by(IOC.type).all()
    }

    # Pre-calculate tactic counts for MITRE heatmap
    tactic_counts = [{"name": t, "value": c} for t, c in db.query(Alert.tactic, func.count(Alert.id)).filter(Alert.event_timestamp >= start_time).group_by(Alert.tactic).all()]

    return jsonify({
        "metadata": {
            "last_ingest": last_ingest,
            "total_events": total_events,
            "total_alerts": len(alerts),
            "total_iocs": ioc_total,
        },
        "kpis": {
            "total_alerts": len(alerts),
            "high_or_above": high_or_above
        },
        "alerts": [
            {
                "id": a.id, 
                "name": a.description or f"{a.tactic} Activity", 
                "severity": a.severity, 
                "status": a.status or "OPEN",
                "tactic": a.tactic,
                "host": a.host, 
                "user": a.user, 
                "source": "endpoint/sample.log",
                "timestamp": a.event_timestamp.isoformat(),
                "assigned": a.assigned_to or "Unassigned",
                "suppressed": "No"
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

    return jsonify({
        "alert_id": alert.id,
        "status": alert.status or "Open",
        "assigned": alert.assigned_to or "",
        "assigned_to": alert.assigned_to or "",
        "analyst_notes": alert.analyst_notes or "",
        "assignees": assignees,
        "timeline": [{"id": e.id, "ts": e.timestamp.isoformat(), "proc": e.process, "cmd": e.commandline, "is_incident": e.id == alert.event_id} for e in events]
    })

@app.route("/api/alerts/<int:alert_id>/case", methods=["POST"])
@login_required
@role_required("analyst")
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
@role_required("analyst")
def ingest_logs_route():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON payload"}), 400

    result = _run_ingest_pipeline(payload, source_name="webhook", source_type="cloud")
    return jsonify(result)


# --- SOAR ACTION ENDPOINT ---
# NOTE: This does not yet call a real firewall/EDR API. It's stubbed so the
# UI flow works end-to-end; wiring a real integration (see integrations/)
# is tracked as a follow-up. The response says so explicitly so nothing
# downstream (reports, audit logs) can mistake this for a real action.
@app.route("/api/soar/action", methods=["POST"])
@login_required
@role_required("analyst")
def soar_action():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    target = data.get("target")
    if not action or not target:
        return jsonify({"error": "action and target are required"}), 400
    time.sleep(1)
    return jsonify({
        "status": "simulated",
        "message": f"[SIMULATED] Would execute '{action}' on {target}. No real integration is connected yet.",
    })

# --- PDF REPORTING ENGINE ---
@app.route("/api/report/<int:alert_id>")
def generate_report(alert_id):
    # Token arrives as a query param here (not a header) because this URL is
    # opened directly by the browser for file download, not called via axios.
    token = request.args.get("token", "")
    db = get_db()
    if not get_user_for_token(db, token):
        return "Unauthorized", 401

    alert = db.get(Alert, alert_id)
    start, end = alert.event_timestamp - timedelta(minutes=15), alert.event_timestamp + timedelta(minutes=15)
    events = db.query(Event).filter(Event.host == alert.host, Event.timestamp >= start, Event.timestamp <= end).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph(f"SOC Incident Report: {alert.tactic}", styles['Title']),
        Paragraph(f"<b>Host:</b> {alert.host} | <b>User:</b> {alert.user} | <b>Severity:</b> {alert.severity}", styles['Normal']),
        Spacer(1, 20)
    ]

    data = [["Time", "Process", "Command Line"]]
    for e in events:
        data.append([e.timestamp.strftime("%H:%M:%S"), e.process, (e.commandline[:50] + '...') if len(e.commandline) > 50 else e.commandline])

    t = Table(data, colWidths=[80, 100, 300])
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.darkblue), ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
    elements.append(t)
    
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"Incident_{alert_id}.pdf", mimetype='application/pdf')

# --- ADMIN, YARA & SUPPRESSION ---
@app.route("/api/admin/data")
@login_required
@role_required("admin")
def get_admin_data():
    db = get_db()
    return jsonify({
        "users": [{"id": u.id, "username": u.username, "role": u.role} for u in db.query(User).all()],
        "feeds": [{"id": f.id, "name": f.name, "url": f.url, "enabled": f.enabled, "last_sync": f.last_sync.isoformat() if f.last_sync else None, "last_error": f.last_error} for f in db.query(FeedSource).all()],
        "suppressions": [{"id": s.id, "indicator": s.field_value or s.name, "reason": s.reason, "active": s.is_active} for s in db.query(SuppressionRule).all()],
        "rules": []
    })

@app.route("/api/admin/feed/<int:feed_id>/toggle", methods=["POST"])
@login_required
@role_required("admin")
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
@role_required("analyst")
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
@role_required("analyst")
def list_rules():
    if not os.path.exists(RULES_DIR): os.makedirs(RULES_DIR)
    files = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".yar"))
    return jsonify({"rules": files})

@app.route("/api/admin/rules/content")
@login_required
@role_required("analyst")
def get_rule_content():
    filename = _safe_yara_filename(request.args.get("file"))
    if not filename:
        return jsonify({"error": "Invalid rule filename"}), 400
    path = os.path.join(RULES_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"content": f.read(), "file": filename})
    return jsonify({"error": "File not found"}), 404

@app.route("/api/admin/rules/save", methods=["POST"])
@login_required
@role_required("admin")
def save_rule():
    data = request.get_json(silent=True) or {}
    filename = _safe_yara_filename(data.get("file"))
    if not filename:
        return jsonify({"error": "Invalid rule filename"}), 400
    content = data.get("content")
    if content is None:
        return jsonify({"error": "Rule content required"}), 400
    if not os.path.exists(RULES_DIR):
        os.makedirs(RULES_DIR)
    path = os.path.join(RULES_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(content))
    scanner.reload_rules()
    return jsonify({"status": "deployed", "file": filename})


@app.route("/api/admin/rules/create", methods=["POST"])
@login_required
@role_required("admin")
def create_rule():
    """Create a new blank/template YARA rule file."""
    data = request.get_json(silent=True) or {}
    filename = _safe_yara_filename(data.get("file") or data.get("name"))
    if not filename:
        return jsonify({"error": "Provide a valid .yar filename"}), 400
    if not os.path.exists(RULES_DIR):
        os.makedirs(RULES_DIR)
    path = os.path.join(RULES_DIR, filename)
    if os.path.exists(path) and not data.get("overwrite"):
        return jsonify({"error": f"Rule '{filename}' already exists"}), 409
    content = data.get("content")
    if content is None or str(content).strip() == "":
        content = _yara_template(os.path.splitext(filename)[0])
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(content))
    scanner.reload_rules()
    return jsonify({"status": "created", "file": filename, "content": content})


@app.route("/api/admin/rules/upload", methods=["POST"])
@login_required
@role_required("admin")
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
@role_required("analyst")
def sync_feeds():
    summary = sync_ioc_feeds()
    return jsonify({"status": "success", "summary": summary})


# --- USER MANAGEMENT (admin only) ---
@app.route("/api/admin/users", methods=["GET"])
@login_required
@role_required("admin")
def list_users():
    db = get_db()
    return jsonify({
        "users": [
            {"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active,
             "created_at": u.created_at.isoformat()}
            for u in db.query(User).order_by(User.id).all()
        ]
    })


@app.route("/api/admin/users", methods=["POST"])
@login_required
@role_required("admin")
def create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "analyst"

    if role not in ROLE_RANK:
        return jsonify({"error": f"role must be one of {list(ROLE_RANK)}"}), 400
    if not username or len(password) < 8:
        return jsonify({"error": "username required, password must be 8+ characters"}), 400

    db = get_db()
    if db.query(User).filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    user = User(username=username, password_hash=generate_password_hash(password), role=role, org_id=g.current_user.org_id)
    db.add(user)
    db.commit()
    db.refresh(user)
    return jsonify({"id": user.id, "username": user.username, "role": user.role}), 201


@app.route("/api/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("admin")
def update_user_role(user_id):
    data = request.get_json(silent=True) or {}
    role = data.get("role")
    if role not in ROLE_RANK:
        return jsonify({"error": f"role must be one of {list(ROLE_RANK)}"}), 400

    db = get_db()
    user = db.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.role = role
    db.commit()
    revoke_all_tokens_for_user(db, user.id)  # force re-login so new role takes effect immediately
    return jsonify({"id": user.id, "username": user.username, "role": user.role})


@app.route("/api/admin/users/<int:user_id>/deactivate", methods=["POST"])
@login_required
@role_required("admin")
def deactivate_user(user_id):
    db = get_db()
    user = db.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.id == g.current_user.id:
        return jsonify({"error": "Cannot deactivate your own account"}), 400
    user.is_active = False
    db.commit()
    revoke_all_tokens_for_user(db, user.id)
    return jsonify({"status": "deactivated", "id": user.id})


# --- INGEST KEY MANAGEMENT (admin only) ---
# These keys authenticate external systems (Vercel log drains, custom apps)
# pushing logs in — separate from user login since the sender isn't a person.
@app.route("/api/admin/ingest_keys", methods=["GET"])
@login_required
@role_required("admin")
def list_ingest_keys():
    db = get_db()
    keys = db.query(IngestKey).order_by(IngestKey.id).all()
    return jsonify({
        "keys": [
            {
                "id": k.id, "name": k.name, "source": k.source,
                # Only the last 4 characters are shown after creation —
                # the full key is returned once, at creation time only.
                "key_preview": f"...{k.key[-4:]}",
                "is_active": k.is_active,
                "created_at": k.created_at.isoformat(),
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            } for k in keys
        ]
    })


@app.route("/api/admin/ingest_keys", methods=["POST"])
@login_required
@role_required("admin")
def create_ingest_key_route():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    source = (data.get("source") or "external").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    db = get_db()
    entry = create_ingest_key(db, name=name, source=source, org_id=g.current_user.org_id)
    return jsonify({
        "id": entry.id, "name": entry.name, "source": entry.source,
        "key": entry.key,  # full key shown ONCE, here, at creation
    }), 201


@app.route("/api/admin/ingest_keys/<int:key_id>/revoke", methods=["POST"])
@login_required
@role_required("admin")
def revoke_ingest_key_route(key_id):
    db = get_db()
    if not revoke_ingest_key(db, key_id):
        return jsonify({"error": "Key not found"}), 404
    return jsonify({"status": "revoked", "id": key_id})


# --- REAL-TIME LOG INGESTION (external sources) ---
def _run_ingest_pipeline(payload, source_name: str, source_type: str):
    """Shared by every ingestion entrypoint (manual, Vercel, ingest_logs) so
    they all get identical detection + IOC matching + live WebSocket alerts."""
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


@app.route("/api/ingest/vercel", methods=["POST"])
@ingest_key_required
def ingest_vercel():
    """Configure this as a Vercel Log Drain URL:
        https://<your-host>/api/ingest/vercel?key=<ingest key>
    (or send the key in an 'X-Ingest-Key' header if your drain config
    supports custom headers). Vercel POSTs a JSON array of log entries —
    each has 'timestamp' (epoch ms), 'message', 'source', 'host', etc.,
    which normalize_event_record() already knows how to read.
    """
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid or missing JSON body"}), 400
    result = _run_ingest_pipeline(payload, source_name=f"vercel:{g.ingest_key.name}", source_type="cloud")
    return jsonify(result)


@app.route("/api/ingest/manual", methods=["POST"])
@login_required
@role_required("analyst")
def ingest_manual():
    """For pasting logs directly in the UI. Accepts either:
      - {"logs": [...]} / a raw JSON array of structured log objects, or
      - {"raw_text": "line1\\nline2\\n..."} plain log lines, one per line —
        each line becomes an event with the current time as its timestamp
        and the line itself as the message (best-effort, no field parsing).
    """
    data = request.get_json(silent=True) or {}

    if "raw_text" in data:
        now = datetime.utcnow().isoformat() + "Z"
        lines = [line.strip() for line in (data.get("raw_text") or "").splitlines() if line.strip()]
        payload = [{"timestamp": now, "message": line} for line in lines]
    else:
        payload = data.get("logs", data)

    if not payload:
        return jsonify({"error": "No log content provided"}), 400

    result = _run_ingest_pipeline(payload, source_name=f"manual:{g.current_user.username}", source_type="manual")
    return jsonify(result)

# --- DEBUG SIMULATOR ---
# Gated behind both auth AND an explicit env flag, and refuses to run at all
# unless debug mode is on — this must never be reachable in a real deployment.
@app.route("/api/debug/trigger_alert")
@login_required
@role_required("admin")
def trigger_alert():
    if os.environ.get("TH_ENABLE_DEBUG_ROUTES", "false").lower() != "true":
        return jsonify({"error": "Debug routes disabled"}), 404
    db = get_db()
    ts = datetime.utcnow()
    new_event = Event(timestamp=ts, host="WIN-SRV-01", process="malware.exe", commandline="C2-Beacon")
    db.add(new_event)
    db.commit()
    new_alert = Alert(severity="Critical", description="beaconing_activity", tactic="Command and Control", host="WIN-SRV-01", event_id=new_event.id, event_timestamp=ts, status="OPEN")
    db.add(new_alert)
    db.commit()
    broadcast_new_alert(new_alert)
    return jsonify({"status": "broadcasted"})

if __name__ == "__main__":
    # Default to localhost so Windows Firewall does not require "Private network"
    # access on managed/org laptops. Override with HOST=0.0.0.0 only if needed.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("TH_FLASK_DEBUG", "false").lower() == "true"
    socketio.run(app, host=host, port=port, debug=debug_mode, allow_unsafe_werkzeug=debug_mode) 