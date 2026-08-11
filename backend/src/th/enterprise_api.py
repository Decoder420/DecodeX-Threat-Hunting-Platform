"""Enterprise SOC routes: events, cases, assets, IOC, audit, webscan, incidents, ingestion."""

from __future__ import annotations

from datetime import datetime

from flask import g, jsonify, request
from sqlalchemy import func, or_

from .audit import write_audit
from .correlation import correlate_new_alerts, incident_timeline
from .db import (
    Alert,
    Asset,
    AuditLog,
    Case,
    CaseAlert,
    CaseNote,
    CorrelatedIncident,
    Event,
    IOC,
    IngestionState,
    WebFinding,
    WebScan,
    WebTarget,
    utcnow,
)
from .log_watcher import get_watcher_status
from .pipeline import (
    DEFAULT_RULE_FILE,
    DATA_LOG_DIR,
    build_ioc_sets,
    discover_log_sources,
    evaluate_events,
    import_sigma_rules,
    ingest_logs,
    persist_alerts,
)
from .risk import compute_risk_score, risk_category
from .rule_evaluator import RuleEvaluator
from .web_scanner import run_safe_scan


def _err(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def _serialize_alert(a: Alert) -> dict:
    return {
        "id": a.id,
        "title": a.title or a.description,
        "description": a.description,
        "severity": a.severity,
        "risk_score": a.risk_score or 0,
        "risk_category": risk_category(a.risk_score or 0),
        "confidence": a.confidence or 70,
        "status": a.status,
        "host": a.host,
        "user": a.user,
        "source": a.source_name,
        "tactic": a.tactic,
        "technique": a.technique_name,
        "technique_id": a.technique_id,
        "assigned_to": a.assigned_to,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "event_timestamp": a.event_timestamp.isoformat() if a.event_timestamp else None,
        "event_id": a.event_id,
        "case_id": a.case_id,
        "suppressed": bool(a.is_suppressed),
        "suppression_reason": a.suppression_reason,
        "ip": a.ip,
        "process": a.process,
        "commandline": a.commandline,
        "rule_id": a.rule_id,
    }


def register_enterprise_routes(app, *, login_required, require_permission, broadcast_new_alert):
    # -------- Events --------
    @app.route("/api/events")
    @login_required
    @require_permission("events.read")
    def list_events():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 25))))
        q = db.query(Event).order_by(Event.timestamp.desc())
        host = request.args.get("host")
        if host:
            q = q.filter(Event.host == host)
        total = q.count()
        rows = q.offset((page - 1) * per_page).limit(per_page).all()
        return jsonify({
            "total": total,
            "page": page,
            "per_page": per_page,
            "events": [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "host": e.host,
                    "user": e.user,
                    "process": e.process,
                    "commandline": e.commandline,
                    "ip": e.ip,
                    "source_type": e.source_type,
                    "source_name": e.source_name,
                    "event_type": getattr(e, "event_type", ""),
                    "ingested_at": e.ingested_at.isoformat() if getattr(e, "ingested_at", None) else None,
                }
                for e in rows
            ],
        })

    @app.route("/api/events/search")
    @login_required
    @require_permission("events.read")
    def search_events():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        term = (request.args.get("q") or "").strip()
        q = db.query(Event)
        if term:
            like = f"%{term}%"
            q = q.filter(or_(
                Event.host.ilike(like),
                Event.user.ilike(like),
                Event.process.ilike(like),
                Event.commandline.ilike(like),
                Event.ip.ilike(like),
            ))
        rows = q.order_by(Event.timestamp.desc()).limit(100).all()
        return jsonify({"events": [
            {"id": e.id, "timestamp": e.timestamp.isoformat(), "host": e.host, "user": e.user,
             "process": e.process, "commandline": e.commandline, "ip": e.ip}
            for e in rows
        ]})

    # -------- Alerts list / status / assign --------
    @app.route("/api/alerts")
    @login_required
    @require_permission("alerts.read")
    def list_alerts():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 25))))
        q = db.query(Alert).order_by(Alert.event_timestamp.desc())
        sev = request.args.get("severity")
        if sev:
            q = q.filter(func.lower(Alert.severity) == sev.lower())
        total = q.count()
        rows = q.offset((page - 1) * per_page).limit(per_page).all()
        return jsonify({"total": total, "page": page, "alerts": [_serialize_alert(a) for a in rows]})

    @app.route("/api/alerts/<int:alert_id>")
    @login_required
    @require_permission("alerts.read")
    def get_alert(alert_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        alert = db.get(Alert, alert_id)
        if not alert:
            return _err("NOT_FOUND", "Alert not found.", 404)
        return jsonify(_serialize_alert(alert))

    @app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
    @login_required
    @require_permission("alerts.write")
    def set_alert_status(alert_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        alert = db.get(Alert, alert_id)
        if not alert:
            return _err("NOT_FOUND", "Alert not found.", 404)
        status = (request.get_json(silent=True) or {}).get("status")
        if not status:
            return _err("BAD_REQUEST", "status required.", 400)
        alert.status = status
        db.commit()
        write_audit(db, action="alert.status_change", user=g.current_user,
                    resource_type="alert", resource_id=alert_id, details=f"status={status}")
        return jsonify(_serialize_alert(alert))

    @app.route("/api/alerts/<int:alert_id>/assign", methods=["POST"])
    @login_required
    @require_permission("alerts.write")
    def assign_alert(alert_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        alert = db.get(Alert, alert_id)
        if not alert:
            return _err("NOT_FOUND", "Alert not found.", 404)
        assigned = (request.get_json(silent=True) or {}).get("assigned_to", "")
        alert.assigned_to = assigned
        db.commit()
        write_audit(db, action="alert.assign", user=g.current_user,
                    resource_type="alert", resource_id=alert_id, details=f"assigned_to={assigned}")
        return jsonify(_serialize_alert(alert))

    # -------- Cases --------
    @app.route("/api/cases")
    @login_required
    @require_permission("cases.read")
    def list_cases():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(Case).order_by(Case.updated_at.desc()).limit(200).all()
        return jsonify({"cases": [
            {
                "id": c.id, "case_number": c.case_number, "title": c.title,
                "severity": c.severity, "status": c.status, "assigned_to": c.assigned_to,
                "created_by": c.created_by, "risk_score": c.risk_score,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            } for c in rows
        ]})

    @app.route("/api/cases", methods=["POST"])
    @login_required
    @require_permission("cases.write")
    def create_case():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        data = request.get_json(silent=True) or {}
        title = (data.get("title") or "").strip()
        if not title:
            return _err("BAD_REQUEST", "title required.", 400)
        next_num = (db.query(Case).count() or 0) + 1
        case = Case(
            case_number=f"CASE-{next_num:05d}",
            title=title,
            description=data.get("description") or "",
            severity=(data.get("severity") or "MEDIUM").upper(),
            status=(data.get("status") or "OPEN").upper(),
            assigned_to=data.get("assigned_to") or "",
            created_by=g.current_user.username,
            risk_score=int(data.get("risk_score") or 0),
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        alert_id = data.get("alert_id")
        if alert_id:
            alert = db.get(Alert, int(alert_id))
            if alert:
                db.add(CaseAlert(case_id=case.id, alert_id=alert.id))
                alert.case_id = case.id
                case.risk_score = case.risk_score or alert.risk_score or 0
                db.commit()
        write_audit(db, action="case.create", user=g.current_user,
                    resource_type="case", resource_id=case.id, details=case.case_number)
        return jsonify({"id": case.id, "case_number": case.case_number, "title": case.title}), 201

    @app.route("/api/cases/<int:case_id>")
    @login_required
    @require_permission("cases.read")
    def get_case(case_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        case = db.get(Case, case_id)
        if not case:
            return _err("NOT_FOUND", "Case not found.", 404)
        links = db.query(CaseAlert).filter_by(case_id=case.id).all()
        alert_ids = [l.alert_id for l in links]
        alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all() if alert_ids else []
        notes = db.query(CaseNote).filter_by(case_id=case.id).order_by(CaseNote.created_at.asc()).all()
        return jsonify({
            "id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "description": case.description,
            "severity": case.severity,
            "status": case.status,
            "assigned_to": case.assigned_to,
            "created_by": case.created_by,
            "risk_score": case.risk_score,
            "alerts": [_serialize_alert(a) for a in alerts],
            "notes": [{"id": n.id, "author": n.author, "body": n.body,
                       "created_at": n.created_at.isoformat()} for n in notes],
        })

    @app.route("/api/cases/<int:case_id>/notes", methods=["POST"])
    @login_required
    @require_permission("cases.write")
    def add_case_note(case_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        case = db.get(Case, case_id)
        if not case:
            return _err("NOT_FOUND", "Case not found.", 404)
        body = ((request.get_json(silent=True) or {}).get("body") or "").strip()
        if not body:
            return _err("BAD_REQUEST", "body required.", 400)
        note = CaseNote(case_id=case.id, author=g.current_user.username, body=body)
        case.updated_at = utcnow()
        db.add(note)
        db.commit()
        return jsonify({"id": note.id, "author": note.author, "body": note.body}), 201

    @app.route("/api/alerts/<int:alert_id>/create_case", methods=["POST"])
    @login_required
    @require_permission("cases.write")
    def case_from_alert(alert_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        alert = db.get(Alert, alert_id)
        if not alert:
            return _err("NOT_FOUND", "Alert not found.", 404)
        next_num = (db.query(Case).count() or 0) + 1
        case = Case(
            case_number=f"CASE-{next_num:05d}",
            title=alert.title or alert.description or f"Case for alert {alert.id}",
            description=f"Created from alert #{alert.id}",
            severity=(alert.severity or "MEDIUM").upper(),
            status="OPEN",
            assigned_to=alert.assigned_to or g.current_user.username,
            created_by=g.current_user.username,
            risk_score=alert.risk_score or 0,
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        db.add(CaseAlert(case_id=case.id, alert_id=alert.id))
        alert.case_id = case.id
        db.commit()
        write_audit(db, action="case.create_from_alert", user=g.current_user,
                    resource_type="case", resource_id=case.id, details=f"alert={alert_id}")
        return jsonify({"id": case.id, "case_number": case.case_number}), 201

    # -------- Incidents (correlation) --------
    @app.route("/api/incidents")
    @login_required
    @require_permission("alerts.read")
    def list_incidents():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(CorrelatedIncident).order_by(CorrelatedIncident.updated_at.desc()).limit(100).all()
        return jsonify({"incidents": [
            {
                "id": i.id, "case_number": i.case_number, "title": i.title,
                "severity": i.severity, "risk_score": i.risk_score, "status": i.status,
                "host": i.host, "user": i.user, "alert_count": i.alert_count,
                "tactic": i.tactic, "technique_id": i.technique_id,
                "updated_at": i.updated_at.isoformat() if i.updated_at else None,
            } for i in rows
        ]})

    @app.route("/api/incidents/<int:incident_id>")
    @login_required
    @require_permission("alerts.read")
    def get_incident(incident_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        incident = db.get(CorrelatedIncident, incident_id)
        if not incident:
            return _err("NOT_FOUND", "Incident not found.", 404)
        return jsonify({
            "id": incident.id,
            "case_number": incident.case_number,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "host": incident.host,
            "user": incident.user,
            "timeline": incident_timeline(db, incident),
        })

    @app.route("/api/incidents/correlate", methods=["POST"])
    @login_required
    @require_permission("alerts.write")
    def run_correlation():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        recent = db.query(Alert).order_by(Alert.event_timestamp.desc()).limit(200).all()
        created = correlate_new_alerts(db, recent)
        return jsonify({"created": len(created), "incidents": [c.case_number for c in created]})

    # -------- Assets --------
    @app.route("/api/assets")
    @login_required
    @require_permission("assets.read")
    def list_assets():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(Asset).order_by(Asset.hostname).all()
        limited = g.current_user.role == "viewer"
        return jsonify({"assets": [
            {
                "id": a.id,
                "hostname": a.hostname,
                "ip": a.ip if not limited else (a.ip[:6] + "…" if a.ip else ""),
                "asset_type": a.asset_type,
                "criticality": a.criticality,
                "operating_system": "" if limited else a.operating_system,
                "owner": "" if limited else a.owner,
                "environment": a.environment,
                "enabled": a.enabled,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            } for a in rows
        ]})

    @app.route("/api/assets", methods=["POST"])
    @login_required
    @require_permission("assets.write")
    def create_asset():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        data = request.get_json(silent=True) or {}
        hostname = (data.get("hostname") or "").strip()
        if not hostname:
            return _err("BAD_REQUEST", "hostname required.", 400)
        if db.query(Asset).filter_by(hostname=hostname).first():
            return _err("CONFLICT", "Asset already exists.", 409)
        asset = Asset(
            hostname=hostname,
            ip=data.get("ip") or "",
            asset_type=(data.get("asset_type") or "OTHER").upper(),
            operating_system=data.get("operating_system") or "",
            criticality=(data.get("criticality") or "MEDIUM").upper(),
            owner=data.get("owner") or "",
            environment=data.get("environment") or "lab",
            description=data.get("description") or "",
        )
        db.add(asset)
        db.commit()
        write_audit(db, action="asset.create", user=g.current_user,
                    resource_type="asset", resource_id=asset.id, details=hostname)
        return jsonify({"id": asset.id, "hostname": asset.hostname}), 201

    # -------- IOC --------
    @app.route("/api/ioc")
    @login_required
    @require_permission("ioc.read")
    def list_ioc():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(IOC).order_by(IOC.last_seen.desc()).limit(500).all()
        return jsonify({"iocs": [
            {
                "id": i.id, "indicator": i.value, "type": i.type, "source": i.source,
                "confidence": getattr(i, "confidence", 70),
                "malicious": bool(getattr(i, "malicious", True)),
                "tags": getattr(i, "tags", ""),
                "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                "last_seen": i.last_seen.isoformat() if i.last_seen else None,
                "expires_at": i.expires_at.isoformat() if getattr(i, "expires_at", None) else None,
            } for i in rows
        ]})

    @app.route("/api/ioc/search")
    @login_required
    @require_permission("ioc.read")
    def search_ioc():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        term = (request.args.get("q") or "").strip()
        q = db.query(IOC)
        if term:
            q = q.filter(IOC.value.ilike(f"%{term}%"))
        rows = q.limit(100).all()
        return jsonify({"iocs": [{"id": i.id, "indicator": i.value, "type": i.type, "source": i.source} for i in rows]})

    @app.route("/api/ioc", methods=["POST"])
    @login_required
    @require_permission("ioc.write")
    def create_ioc():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        data = request.get_json(silent=True) or {}
        value = (data.get("indicator") or data.get("value") or "").strip()
        ioc_type = (data.get("type") or "ip").strip().lower()
        if not value:
            return _err("BAD_REQUEST", "indicator required.", 400)
        existing = db.query(IOC).filter_by(type=ioc_type, value=value).first()
        if existing:
            existing.last_seen = utcnow()
            existing.confidence = int(data.get("confidence") or existing.confidence or 70)
            db.commit()
            return jsonify({"id": existing.id, "deduplicated": True})
        ioc = IOC(
            type=ioc_type,
            value=value,
            source=data.get("source") or "manual",
            confidence=int(data.get("confidence") or 80),
            malicious=bool(data.get("malicious", True)),
            tags=data.get("tags") or "",
        )
        db.add(ioc)
        db.commit()
        write_audit(db, action="ioc.create", user=g.current_user,
                    resource_type="ioc", resource_id=ioc.id, details=value)
        return jsonify({"id": ioc.id, "indicator": ioc.value, "type": ioc.type}), 201

    # -------- Audit --------
    @app.route("/api/audit")
    @login_required
    @require_permission("audit.read")
    def list_audit():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(300).all()
        return jsonify({"logs": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "username": r.username,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "source_ip": r.source_ip,
                "details": r.details,
                "success": r.success,
            } for r in rows
        ]})

    # -------- Web scanner --------
    @app.route("/api/web-targets")
    @login_required
    @require_permission("webscan.read")
    def list_web_targets():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(WebTarget).order_by(WebTarget.id.desc()).all()
        return jsonify({"targets": [
            {
                "id": t.id, "name": t.name, "url": t.url, "owner": t.owner,
                "authorization_status": t.authorization_status, "scope": t.scope,
                "enabled": t.enabled, "last_scan": t.last_scan.isoformat() if t.last_scan else None,
                "last_status": t.last_status,
            } for t in rows
        ]})

    @app.route("/api/web-targets", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def create_web_target():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        url = (data.get("url") or "").strip()
        if not name or not url:
            return _err("BAD_REQUEST", "name and url required.", 400)
        target = WebTarget(
            name=name,
            url=url,
            owner=data.get("owner") or g.current_user.username,
            authorization_status=(data.get("authorization_status") or "PENDING").upper(),
            scope=data.get("scope") or "",
            created_by=g.current_user.username,
        )
        db.add(target)
        db.commit()
        write_audit(db, action="web_target.create", user=g.current_user,
                    resource_type="web_target", resource_id=target.id, details=url)
        return jsonify({"id": target.id, "name": target.name, "url": target.url}), 201

    @app.route("/api/web-targets/<int:target_id>", methods=["PATCH"])
    @login_required
    @require_permission("webscan.run")
    def patch_web_target(target_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        target = db.get(WebTarget, target_id)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        data = request.get_json(silent=True) or {}
        if "authorization_status" in data:
            target.authorization_status = str(data["authorization_status"]).upper()
        if "enabled" in data:
            target.enabled = bool(data["enabled"])
        if "scope" in data:
            target.scope = data["scope"] or ""
        db.commit()
        return jsonify({"id": target.id, "authorization_status": target.authorization_status})

    @app.route("/api/web-targets/<int:target_id>/scan", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def scan_web_target(target_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        target = db.get(WebTarget, target_id)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        if target.authorization_status != "AUTHORIZED" or not target.enabled:
            return _err("FORBIDDEN", "Only AUTHORIZED and enabled targets can be scanned.", 403)
        data = request.get_json(silent=True) or {}
        if not data.get("confirm"):
            return _err("BAD_REQUEST", "Set confirm=true to run an authorized safe scan.", 400)
        scan = run_safe_scan(db, target, created_by=g.current_user.username)
        write_audit(db, action="web_scan.run", user=g.current_user,
                    resource_type="web_scan", resource_id=scan.id, details=target.url)
        return jsonify({
            "id": scan.id,
            "status": scan.status,
            "findings_count": scan.findings_count,
            "high_count": scan.high_count,
        })

    @app.route("/api/web-scans/<int:scan_id>")
    @login_required
    @require_permission("webscan.read")
    def get_web_scan(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        findings = db.query(WebFinding).filter_by(scan_id=scan.id).all()
        return jsonify({
            "id": scan.id,
            "status": scan.status,
            "findings": [
                {
                    "id": f.id, "title": f.title, "severity": f.severity,
                    "confidence": f.confidence, "category": f.category,
                    "evidence": f.evidence, "recommendation": f.recommendation,
                    "risk_score": f.risk_score,
                } for f in findings
            ],
        })

    @app.route("/api/web-findings")
    @login_required
    @require_permission("webscan.read")
    def list_web_findings():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(WebFinding).order_by(WebFinding.created_at.desc()).limit(200).all()
        return jsonify({"findings": [
            {
                "id": f.id, "target_id": f.target_id, "title": f.title,
                "severity": f.severity, "category": f.category,
                "risk_score": f.risk_score, "url": f.url,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            } for f in rows
        ]})

    # -------- Sigma --------
    @app.route("/api/sigma/import", methods=["POST"])
    @login_required
    @require_permission("sigma.write")
    def sigma_import():
        from pathlib import Path
        import tempfile

        uploaded = request.files.get("sigma_file") or request.files.get("file")
        if not uploaded:
            return _err("BAD_REQUEST", "sigma_file required.", 400)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as tmp:
            tmp.write(uploaded.read().decode("utf-8", errors="replace"))
            tmp_path = Path(tmp.name)
        try:
            count = import_sigma_rules(tmp_path)
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        write_audit(db, action="sigma.import", user=g.current_user,
                    resource_type="sigma", details=f"imported={count}")
        return jsonify({"imported": count})

    # -------- Ingest once (manual trigger) --------
    @app.route("/api/ingestion/run", methods=["POST"])
    @login_required
    @require_permission("events.write")
    def ingestion_run_once():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        evaluator = RuleEvaluator(str(DEFAULT_RULE_FILE))
        added, skipped, new_events = ingest_logs(db)
        ioc_sets = build_ioc_sets(db.query(IOC).all())
        alerts = evaluate_events(db, new_events, evaluator, ioc_sets)
        for alert in alerts:
            alert["risk_score"] = compute_risk_score(
                severity=alert.get("severity", "medium"),
                confidence=75,
                host=alert.get("host", ""),
                db=db,
                technique_id=alert.get("technique_id", ""),
            )
            alert["confidence"] = 75
        max_id_before = db.query(Alert.id).order_by(Alert.id.desc()).limit(1).scalar() or 0
        alerts_added = persist_alerts(db, alerts, broadcast_fn=broadcast_new_alert)
        created = db.query(Alert).filter(Alert.id > max_id_before).all()
        correlate_new_alerts(db, created)
        return jsonify({
            "events_added": added,
            "events_skipped": skipped,
            "alerts_added": alerts_added,
        })

    @app.route("/api/ingestion/status")
    @login_required
    @require_permission("events.read")
    def ingestion_status():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        sources = db.query(IngestionState).all()
        discovered = discover_log_sources()
        return jsonify({
            "watcher": get_watcher_status(),
            "log_dir": str(DATA_LOG_DIR),
            "discovered": [{"name": s["source_name"], "type": s["source_type"]} for s in discovered],
            "sources": [
                {
                    "source": s.source,
                    "source_type": getattr(s, "source_type", ""),
                    "enabled": bool(getattr(s, "enabled", True)),
                    "status": getattr(s, "status", "idle"),
                    "offset": s.offset,
                    "event_count": getattr(s, "event_count", 0),
                    "last_error": getattr(s, "last_error", ""),
                    "last_event_at": s.last_event_at.isoformat() if getattr(s, "last_event_at", None) else None,
                    "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                } for s in sources
            ],
        })
