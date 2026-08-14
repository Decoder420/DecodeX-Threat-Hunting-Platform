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
    WebScanEvent,
    WebScanNode,
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
from .web_scanner import cancel_scan, get_engine_status, resume_scan, start_scan_async
from .web_scanner.config import SCAN_PROFILES, WEBSCAN_ALLOW_PRIVATE_TARGETS
from .web_scanner.surface import build_tree_payload
from .web_scanner.validators import SSRFError, validate_scan_url


def _err(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def _serialize_target(t: WebTarget) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "url": t.url,
        "owner": t.owner,
        "authorization_status": t.authorization_status,
        "scope": t.scope,
        "enabled": t.enabled,
        "environment": getattr(t, "environment", None) or "lab",
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "last_scan": t.last_scan.isoformat() if t.last_scan else None,
        "last_status": t.last_status,
    }


def _serialize_scan(s: WebScan, *, include_detail: bool = False) -> dict:
    out = {
        "id": s.id,
        "target_id": s.target_id,
        "status": s.status,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "findings_count": s.findings_count or 0,
        "critical_count": getattr(s, "critical_count", 0) or 0,
        "high_count": s.high_count or 0,
        "medium_count": getattr(s, "medium_count", 0) or 0,
        "low_count": getattr(s, "low_count", 0) or 0,
        "info_count": getattr(s, "info_count", 0) or 0,
        "created_by": s.created_by,
        "scan_profile": getattr(s, "scan_profile", None) or "QUICK",
        "progress": getattr(s, "progress", 0) or 0,
        "current_stage": getattr(s, "current_stage", None) or "",
        "error_message": getattr(s, "error_message", None) or "",
        "duration": getattr(s, "duration", 0) or 0,
        "discovered_urls": getattr(s, "discovered_urls", 0) or 0,
        "discovered_ports": getattr(s, "discovered_ports", 0) or 0,
        "technologies_count": getattr(s, "technologies_count", 0) or 0,
        "risk_score": getattr(s, "risk_score", 0) or 0,
        "nodes_count": getattr(s, "nodes_count", 0) or 0,
        "requests_used": getattr(s, "requests_used", 0) or 0,
        "request_budget": getattr(s, "request_budget", 0) or 0,
        "safety_mode": getattr(s, "safety_mode", None) or "production",
        "interrupted": bool(getattr(s, "interrupted", False)),
    }
    if include_detail:
        import json

        for key in ("engine_versions", "configuration_json", "ports_json", "technologies_json"):
            raw = getattr(s, key, None) or ""
            try:
                out[key.replace("_json", "").replace("engine_versions", "engines")] = (
                    json.loads(raw) if raw else ({} if "json" in key or key == "engine_versions" else [])
                )
            except Exception:
                out[key] = raw
        # Normalize keys
        if "engines" not in out and getattr(s, "engine_versions", None):
            try:
                out["engines"] = json.loads(s.engine_versions or "{}")
            except Exception:
                out["engines"] = {}
        if "ports" not in out:
            try:
                out["ports"] = json.loads(getattr(s, "ports_json", None) or "[]")
            except Exception:
                out["ports"] = []
        if "technologies" not in out:
            try:
                out["technologies"] = json.loads(getattr(s, "technologies_json", None) or "[]")
            except Exception:
                out["technologies"] = []
        try:
            out["configuration"] = json.loads(getattr(s, "configuration_json", None) or "{}")
        except Exception:
            out["configuration"] = {}
    return out


def _serialize_finding(f: WebFinding, *, detail: bool = False) -> dict:
    import json

    out = {
        "id": f.id,
        "target_id": f.target_id,
        "scan_id": f.scan_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "confidence": f.confidence,
        "category": f.category,
        "evidence": f.evidence,
        "recommendation": f.recommendation,
        "remediation": getattr(f, "remediation", None) or f.recommendation,
        "url": f.url or getattr(f, "affected_url", "") or "",
        "affected_url": getattr(f, "affected_url", None) or f.url or "",
        "risk_score": f.risk_score or 0,
        "cwe": getattr(f, "cwe", None) or "",
        "owasp": getattr(f, "owasp", None) or "",
        "cve": getattr(f, "cve", None) or "",
        "cvss": getattr(f, "cvss", None) or 0,
        "source_engine": getattr(f, "source_engine", None) or "builtin",
        "template_id": getattr(f, "template_id", None) or "",
        "status": getattr(f, "status", None) or "OPEN",
        "fingerprint": getattr(f, "fingerprint", None) or "",
        "first_seen": f.first_seen.isoformat() if getattr(f, "first_seen", None) else None,
        "last_seen": f.last_seen.isoformat() if getattr(f, "last_seen", None) else None,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "occurrence_count": getattr(f, "occurrence_count", 1) or 1,
        "case_id": getattr(f, "case_id", None),
        "method": getattr(f, "method", None) or "",
        "parameter": getattr(f, "parameter", None) or "",
    }
    if detail:
        out["request"] = getattr(f, "request", None) or ""
        out["response"] = getattr(f, "response", None) or ""
        try:
            out["risk_factors"] = json.loads(getattr(f, "risk_factors_json", None) or "{}")
        except Exception:
            out["risk_factors"] = {}
    return out


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

    # -------- Web Application Security Scanning --------
    @app.route("/api/web-targets")
    @login_required
    @require_permission("webscan.read")
    def list_web_targets():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        rows = db.query(WebTarget).order_by(WebTarget.id.desc()).all()
        # Attach latest risk / finding counts lightly
        out = []
        for t in rows:
            latest = (
                db.query(WebScan)
                .filter_by(target_id=t.id)
                .order_by(WebScan.id.desc())
                .first()
            )
            item = _serialize_target(t)
            item["risk_score"] = getattr(latest, "risk_score", 0) if latest else 0
            item["findings_count"] = (
                db.query(func.count(WebFinding.id)).filter_by(target_id=t.id).scalar() or 0
            )
            out.append(item)
        return jsonify({"targets": out})

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
        try:
            meta = validate_scan_url(url, allow_private=WEBSCAN_ALLOW_PRIVATE_TARGETS)
            url = meta["url"]
        except SSRFError as exc:
            return _err("INVALID_URL", str(exc), 400)
        # Authorization must be an explicit separate action — never trust client AUTHORIZED.
        target = WebTarget(
            name=name,
            url=url,
            owner=(data.get("owner") or g.current_user.username or "").strip(),
            authorization_status="PENDING",
            scope=(data.get("scope") or "").strip(),
            environment=(data.get("environment") or "lab").strip()[:64],
            created_by=g.current_user.username,
            enabled=True,
        )
        db.add(target)
        db.commit()
        write_audit(
            db,
            action="web_target.create",
            user=g.current_user,
            resource_type="web_target",
            resource_id=target.id,
            details=url,
        )
        return jsonify(_serialize_target(target)), 201

    @app.route("/api/web-targets/<int:target_id>")
    @login_required
    @require_permission("webscan.read")
    def get_web_target(target_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        target = db.get(WebTarget, target_id)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        return jsonify(_serialize_target(target))

    @app.route("/api/web-targets/<int:target_id>", methods=["PUT", "PATCH"])
    @login_required
    @require_permission("webscan.run")
    def patch_web_target(target_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        target = db.get(WebTarget, target_id)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        data = request.get_json(silent=True) or {}
        # Disallow silent authorization via generic PATCH — use /authorize.
        if "authorization_status" in data:
            status = str(data["authorization_status"]).upper()
            if status == "AUTHORIZED":
                return _err(
                    "FORBIDDEN",
                    "Use POST /api/web-targets/<id>/authorize with confirm=true.",
                    403,
                )
            if status in {"PENDING", "REVOKED", "DENIED"}:
                target.authorization_status = status
        if "enabled" in data:
            target.enabled = bool(data["enabled"])
        if "scope" in data:
            target.scope = data["scope"] or ""
        if "name" in data and str(data["name"]).strip():
            target.name = str(data["name"]).strip()
        if "owner" in data:
            target.owner = str(data["owner"] or "").strip()
        if "environment" in data:
            target.environment = str(data["environment"] or "lab").strip()[:64]
        if "url" in data and str(data["url"]).strip():
            try:
                meta = validate_scan_url(
                    str(data["url"]).strip(),
                    allow_private=WEBSCAN_ALLOW_PRIVATE_TARGETS,
                )
                target.url = meta["url"]
            except SSRFError as exc:
                return _err("INVALID_URL", str(exc), 400)
        db.commit()
        write_audit(
            db,
            action="web_target.update",
            user=g.current_user,
            resource_type="web_target",
            resource_id=target.id,
            details=f"authz={target.authorization_status} enabled={target.enabled}",
        )
        return jsonify(_serialize_target(target))

    @app.route("/api/web-targets/<int:target_id>", methods=["DELETE"])
    @login_required
    @require_permission("webscan.run")
    def delete_web_target(target_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        target = db.get(WebTarget, target_id)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        target.enabled = False
        target.authorization_status = "REVOKED"
        db.commit()
        write_audit(
            db,
            action="web_target.disable",
            user=g.current_user,
            resource_type="web_target",
            resource_id=target.id,
        )
        return jsonify({"id": target.id, "enabled": False, "authorization_status": "REVOKED"})

    @app.route("/api/web-targets/<int:target_id>/authorize", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def authorize_web_target(target_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        target = db.get(WebTarget, target_id)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        data = request.get_json(silent=True) or {}
        if not data.get("confirm"):
            return _err(
                "BAD_REQUEST",
                "Set confirm=true to acknowledge you are authorized to assess this target.",
                400,
            )
        try:
            meta = validate_scan_url(target.url, allow_private=WEBSCAN_ALLOW_PRIVATE_TARGETS)
        except SSRFError as exc:
            write_audit(
                db,
                action="web_target.authorize",
                user=g.current_user,
                resource_type="web_target",
                resource_id=target.id,
                details=str(exc),
                success=False,
            )
            return _err("INVALID_URL", str(exc), 400)
        target.authorization_status = "AUTHORIZED"
        target.enabled = True
        db.commit()
        write_audit(
            db,
            action="web_target.authorize",
            user=g.current_user,
            resource_type="web_target",
            resource_id=target.id,
            details=f"AUTHORIZED {target.url} ips={meta.get('resolved_ips')}",
        )
        payload = _serialize_target(target)
        payload["resolved_ips"] = meta.get("resolved_ips") or []
        return jsonify(payload)

    @app.route("/api/web-targets/<int:target_id>/scan", methods=["POST"])
    @app.route("/api/web-scans", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def start_web_scan(target_id=None):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        data = request.get_json(silent=True) or {}
        tid = target_id or data.get("target_id")
        try:
            tid = int(tid)
        except (TypeError, ValueError):
            return _err("BAD_REQUEST", "target_id required.", 400)
        target = db.get(WebTarget, tid)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        if (target.authorization_status or "").upper() != "AUTHORIZED" or not target.enabled:
            return _err("FORBIDDEN", "Only AUTHORIZED and enabled targets can be scanned.", 403)
        if not data.get("confirm"):
            return _err("BAD_REQUEST", "Set confirm=true to start an authorized scan.", 400)
        profile = (data.get("profile") or data.get("scan_profile") or "QUICK").upper()
        if profile not in SCAN_PROFILES:
            return _err("BAD_REQUEST", f"profile must be one of: {', '.join(sorted(SCAN_PROFILES))}.", 400)
        try:
            # Flush session so background worker sees latest target state.
            db.commit()
            scan = start_scan_async(
                target.id,
                created_by=g.current_user.username,
                profile=profile,
                user=g.current_user,
                create_alerts=bool(data.get("create_alerts", True)),
                safety_mode=data.get("safety_mode"),
            )
        except PermissionError as exc:
            return _err("FORBIDDEN", str(exc), 403)
        except ValueError as exc:
            return _err("BAD_REQUEST", str(exc), 400)
        except RuntimeError as exc:
            return _err("UNAVAILABLE", str(exc), 503)
        except SSRFError as exc:
            return _err("INVALID_URL", str(exc), 400)
        # Re-load in request session for response
        scan = db.get(WebScan, scan.id) or scan
        return jsonify(_serialize_scan(scan)), 202

    @app.route("/api/web-scans")
    @login_required
    @require_permission("webscan.read")
    def list_web_scans():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        q = db.query(WebScan).order_by(WebScan.id.desc())
        target_id = request.args.get("target_id")
        if target_id:
            try:
                q = q.filter_by(target_id=int(target_id))
            except ValueError:
                return _err("BAD_REQUEST", "Invalid target_id.", 400)
        limit = min(int(request.args.get("limit") or 50), 200)
        rows = q.limit(limit).all()
        return jsonify({"scans": [_serialize_scan(s) for s in rows]})

    @app.route("/api/web-scans/<int:scan_id>")
    @login_required
    @require_permission("webscan.read")
    def get_web_scan(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        findings = (
            db.query(WebFinding)
            .filter_by(scan_id=scan.id)
            .order_by(WebFinding.risk_score.desc())
            .all()
        )
        payload = _serialize_scan(scan, include_detail=True)
        payload["findings"] = [_serialize_finding(f) for f in findings]
        target = db.get(WebTarget, scan.target_id)
        payload["target"] = _serialize_target(target) if target else None
        return jsonify(payload)

    @app.route("/api/web-scans/<int:scan_id>/progress")
    @login_required
    @require_permission("webscan.read")
    def get_web_scan_progress(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        return jsonify({
            "scan_id": scan.id,
            "status": scan.status,
            "stage": getattr(scan, "current_stage", None) or "",
            "progress": getattr(scan, "progress", 0) or 0,
            "findings_count": scan.findings_count or 0,
            "error_message": getattr(scan, "error_message", None) or "",
            "discovered_urls": getattr(scan, "discovered_urls", 0) or 0,
            "discovered_ports": getattr(scan, "discovered_ports", 0) or 0,
            "technologies_count": getattr(scan, "technologies_count", 0) or 0,
        })

    @app.route("/api/web-scans/<int:scan_id>/cancel", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def cancel_web_scan(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        ok = cancel_scan(scan_id)
        write_audit(
            db,
            action="web_scan.cancel",
            user=g.current_user,
            resource_type="web_scan",
            resource_id=scan_id,
            success=ok,
        )
        scan = db.get(WebScan, scan_id)
        return jsonify(_serialize_scan(scan) if scan else {"id": scan_id, "status": "CANCELLED"})

    @app.route("/api/web-scans/<int:scan_id>/findings")
    @login_required
    @require_permission("webscan.read")
    def list_scan_findings(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        rows = db.query(WebFinding).filter_by(scan_id=scan_id).order_by(WebFinding.risk_score.desc()).all()
        return jsonify({"findings": [_serialize_finding(f) for f in rows]})

    @app.route("/api/web-scans/<int:scan_id>/compare/<int:other_scan_id>")
    @login_required
    @require_permission("webscan.read")
    def compare_web_scans(scan_id, other_scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        a = db.get(WebScan, scan_id)
        b = db.get(WebScan, other_scan_id)
        if not a or not b:
            return _err("NOT_FOUND", "One or both scans not found.", 404)
        fa = {
            f.fingerprint or f"id:{f.id}": f
            for f in db.query(WebFinding).filter_by(scan_id=a.id).all()
        }
        fb = {
            f.fingerprint or f"id:{f.id}": f
            for f in db.query(WebFinding).filter_by(scan_id=b.id).all()
        }
        # Treat `scan_id` as current, `other` as previous when ids suggest order.
        current, previous = (a, b) if a.id >= b.id else (b, a)
        fc = fa if current.id == a.id else fb
        fp = fb if current.id == a.id else fa
        new_keys = set(fc) - set(fp)
        resolved_keys = set(fp) - set(fc)
        persistent_keys = set(fc) & set(fp)
        return jsonify({
            "current_scan_id": current.id,
            "previous_scan_id": previous.id,
            "current_count": len(fc),
            "previous_count": len(fp),
            "new_count": len(new_keys),
            "resolved_count": len(resolved_keys),
            "persistent_count": len(persistent_keys),
            "net_change": len(fc) - len(fp),
            "risk_current": getattr(current, "risk_score", 0) or 0,
            "risk_previous": getattr(previous, "risk_score", 0) or 0,
            "new_findings": [_serialize_finding(fc[k]) for k in list(new_keys)[:50]],
            "resolved_findings": [_serialize_finding(fp[k]) for k in list(resolved_keys)[:50]],
            "persistent_findings": [_serialize_finding(fc[k]) for k in list(persistent_keys)[:50]],
        })

    @app.route("/api/web-scans/<int:scan_id>/report")
    @login_required
    @require_permission("webscan.read")
    def web_scan_report(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        target = db.get(WebTarget, scan.target_id)
        findings = (
            db.query(WebFinding)
            .filter_by(scan_id=scan.id)
            .order_by(WebFinding.risk_score.desc())
            .all()
        )
        fmt = (request.args.get("format") or "json").lower()
        report = {
            "title": "Web Application Security Assessment",
            "generated_at": utcnow().isoformat(),
            "executive_summary": {
                "target": target.name if target else "",
                "url": target.url if target else "",
                "authorization_status": target.authorization_status if target else "",
                "profile": getattr(scan, "scan_profile", "QUICK"),
                "status": scan.status,
                "risk_score": getattr(scan, "risk_score", 0) or 0,
                "findings_count": scan.findings_count or 0,
                "critical": getattr(scan, "critical_count", 0) or 0,
                "high": scan.high_count or 0,
                "medium": getattr(scan, "medium_count", 0) or 0,
                "low": getattr(scan, "low_count", 0) or 0,
                "info": getattr(scan, "info_count", 0) or 0,
            },
            "scan": _serialize_scan(scan, include_detail=True),
            "target": _serialize_target(target) if target else None,
            "findings": [_serialize_finding(f, detail=True) for f in findings],
            "remediation_priorities": [
                _serialize_finding(f)
                for f in findings
                if f.severity in {"CRITICAL", "HIGH"}
            ][:25],
        }
        if fmt == "csv":
            import csv
            import io

            buf = io.StringIO()
            writer = csv.DictWriter(
                buf,
                fieldnames=[
                    "id", "severity", "risk_score", "title", "category",
                    "affected_url", "cwe", "owasp", "cve", "source_engine", "status",
                ],
            )
            writer.writeheader()
            for f in findings:
                writer.writerow({
                    "id": f.id,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                    "title": f.title,
                    "category": f.category,
                    "affected_url": getattr(f, "affected_url", None) or f.url,
                    "cwe": getattr(f, "cwe", ""),
                    "owasp": getattr(f, "owasp", ""),
                    "cve": getattr(f, "cve", ""),
                    "source_engine": getattr(f, "source_engine", ""),
                    "status": getattr(f, "status", ""),
                })
            from flask import Response

            return Response(
                buf.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=webscan_{scan_id}.csv"},
            )
        return jsonify(report)

    @app.route("/api/web-findings")
    @login_required
    @require_permission("webscan.read")
    def list_web_findings():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        q = db.query(WebFinding)
        if request.args.get("severity"):
            q = q.filter(WebFinding.severity == request.args["severity"].upper())
        if request.args.get("status"):
            q = q.filter(WebFinding.status == request.args["status"].upper())
        if request.args.get("target_id"):
            try:
                q = q.filter(WebFinding.target_id == int(request.args["target_id"]))
            except ValueError:
                return _err("BAD_REQUEST", "Invalid target_id.", 400)
        if request.args.get("scan_id"):
            try:
                q = q.filter(WebFinding.scan_id == int(request.args["scan_id"]))
            except ValueError:
                return _err("BAD_REQUEST", "Invalid scan_id.", 400)
        if request.args.get("engine"):
            q = q.filter(WebFinding.source_engine == request.args["engine"])
        search = (request.args.get("q") or "").strip()
        if search:
            like = f"%{search}%"
            q = q.filter(or_(
                WebFinding.title.ilike(like),
                WebFinding.evidence.ilike(like),
                WebFinding.url.ilike(like),
                WebFinding.affected_url.ilike(like),
                WebFinding.template_id.ilike(like),
            ))
        limit = min(int(request.args.get("limit") or 100), 500)
        rows = q.order_by(WebFinding.risk_score.desc(), WebFinding.id.desc()).limit(limit).all()
        return jsonify({"findings": [_serialize_finding(f) for f in rows]})

    @app.route("/api/web-findings/<int:finding_id>")
    @login_required
    @require_permission("webscan.read")
    def get_web_finding(finding_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        finding = db.get(WebFinding, finding_id)
        if not finding:
            return _err("NOT_FOUND", "Finding not found.", 404)
        payload = _serialize_finding(finding, detail=True)
        target = db.get(WebTarget, finding.target_id)
        payload["target"] = _serialize_target(target) if target else None
        return jsonify(payload)

    @app.route("/api/web-findings/<int:finding_id>", methods=["PATCH"])
    @login_required
    @require_permission("webscan.run")
    def patch_web_finding(finding_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        finding = db.get(WebFinding, finding_id)
        if not finding:
            return _err("NOT_FOUND", "Finding not found.", 404)
        data = request.get_json(silent=True) or {}
        status = (data.get("status") or "").upper()
        if status and status not in {"OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED", "SUPPRESSED", "ACCEPTED_RISK"}:
            return _err("BAD_REQUEST", "Invalid status.", 400)
        if status:
            finding.status = status
        if "case_id" in data:
            finding.case_id = data["case_id"]
        db.commit()
        write_audit(
            db,
            action="web_finding.update",
            user=g.current_user,
            resource_type="web_finding",
            resource_id=finding.id,
            details=f"status={finding.status}",
        )
        return jsonify(_serialize_finding(finding, detail=True))

    @app.route("/api/web-findings/<int:finding_id>/case", methods=["POST"])
    @login_required
    @require_permission("cases.write")
    def web_finding_to_case(finding_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        finding = db.get(WebFinding, finding_id)
        if not finding:
            return _err("NOT_FOUND", "Finding not found.", 404)
        data = request.get_json(silent=True) or {}
        case_id = data.get("case_id")
        if case_id:
            case = db.get(Case, int(case_id))
            if not case:
                return _err("NOT_FOUND", "Case not found.", 404)
        else:
            next_num = (db.query(func.count(Case.id)).scalar() or 0) + 1
            case = Case(
                case_number=f"CASE-{next_num:05d}",
                title=f"Web: {finding.title}"[:200],
                description=finding.description or finding.evidence or "",
                severity=(finding.severity or "MEDIUM").upper(),
                status="OPEN",
                created_by=g.current_user.username,
                risk_score=finding.risk_score or 0,
            )
            db.add(case)
            db.flush()
        finding.case_id = case.id
        db.commit()
        return jsonify({
            "case_id": case.id,
            "case_number": case.case_number,
            "finding_id": finding.id,
        })

    @app.route("/api/web/overview")
    @login_required
    @require_permission("webscan.read")
    def web_security_overview():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        targets = db.query(func.count(WebTarget.id)).scalar() or 0
        authorized = (
            db.query(func.count(WebTarget.id))
            .filter(WebTarget.authorization_status == "AUTHORIZED")
            .scalar()
            or 0
        )
        active = (
            db.query(func.count(WebScan.id))
            .filter(WebScan.status.in_(["PENDING", "RUNNING", "VALIDATING", "DISCOVERING", "CRAWLING", "SCANNING", "ANALYZING", "FINALIZING"]))
            .scalar()
            or 0
        )
        completed = (
            db.query(func.count(WebScan.id)).filter(WebScan.status == "COMPLETED").scalar() or 0
        )
        sev = dict(
            db.query(WebFinding.severity, func.count(WebFinding.id))
            .group_by(WebFinding.severity)
            .all()
        )
        cat = dict(
            db.query(WebFinding.category, func.count(WebFinding.id))
            .group_by(WebFinding.category)
            .all()
        )
        avg_risk = db.query(func.avg(WebScan.risk_score)).filter(WebScan.status == "COMPLETED").scalar()
        engines = get_engine_status()
        return jsonify({
            "totals": {
                "targets": targets,
                "authorized_targets": authorized,
                "active_scans": active,
                "completed_scans": completed,
                "critical_findings": sev.get("CRITICAL", 0),
                "high_findings": sev.get("HIGH", 0),
                "medium_findings": sev.get("MEDIUM", 0),
                "low_findings": sev.get("LOW", 0),
                "info_findings": sev.get("INFO", 0),
                "avg_risk_score": int(round(float(avg_risk or 0))),
            },
            "findings_by_severity": sev,
            "findings_by_category": cat,
            "engines": engines,
            "profiles": list(SCAN_PROFILES.keys()),
        })

    @app.route("/api/web/scanner/status")
    @app.route("/api/web/scanner/engines")
    @login_required
    @require_permission("webscan.read")
    def web_scanner_engines():
        engines = get_engine_status()
        # Never expose API keys
        safe = {}
        for name, info in (engines or {}).items():
            if isinstance(info, dict):
                safe[name] = {
                    k: v for k, v in info.items()
                    if "key" not in k.lower() and "secret" not in k.lower() and "password" not in k.lower()
                }
            else:
                safe[name] = info
        return jsonify({
            "engines": safe,
            "allow_private_targets": WEBSCAN_ALLOW_PRIVATE_TARGETS,
            "profiles": SCAN_PROFILES,
        })

    @app.route("/api/web/attack-surface")
    @login_required
    @require_permission("webscan.read")
    def web_attack_surface():
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        import json

        target_id = request.args.get("target_id")
        q = db.query(WebScan).filter(WebScan.status == "COMPLETED").order_by(WebScan.id.desc())
        if target_id:
            try:
                q = q.filter_by(target_id=int(target_id))
            except ValueError:
                return _err("BAD_REQUEST", "Invalid target_id.", 400)
        scans = q.limit(20).all()
        nodes = []
        seen_targets = set()
        for s in scans:
            if s.target_id in seen_targets:
                continue
            seen_targets.add(s.target_id)
            t = db.get(WebTarget, s.target_id)
            try:
                ports = json.loads(getattr(s, "ports_json", None) or "[]")
            except Exception:
                ports = []
            try:
                tech = json.loads(getattr(s, "technologies_json", None) or "[]")
            except Exception:
                tech = []
            urls = [
                f.affected_url or f.url
                for f in db.query(WebFinding)
                .filter_by(target_id=s.target_id)
                .limit(40)
                .all()
                if (f.affected_url or f.url)
            ]
            nodes.append({
                "target": _serialize_target(t) if t else {"id": s.target_id},
                "scan_id": s.id,
                "ports": ports,
                "technologies": tech,
                "urls": sorted(set(urls))[:40],
                "risk_score": getattr(s, "risk_score", 0) or 0,
            })
        return jsonify({"surfaces": nodes})

    @app.route("/api/web-scans/<int:scan_id>/tree")
    @login_required
    @require_permission("webscan.read")
    def web_scan_tree(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        return jsonify(build_tree_payload(db, scan_id))

    @app.route("/api/web-scans/<int:scan_id>/events")
    @login_required
    @require_permission("webscan.read")
    def web_scan_events(scan_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan_id)
        if not scan:
            return _err("NOT_FOUND", "Scan not found.", 404)
        event_filter = (request.args.get("type") or "").upper()
        q = db.query(WebScanEvent).filter_by(scan_id=scan_id).order_by(WebScanEvent.id.asc())
        rows = q.limit(min(int(request.args.get("limit") or 500), 2000)).all()
        events = []
        for e in rows:
            if event_filter and event_filter != "ALL" and e.event_type.upper() != event_filter:
                continue
            events.append({
                "id": e.id,
                "scan_id": e.scan_id,
                "target_id": e.target_id,
                "event_type": e.event_type,
                "message": e.message,
                "severity": e.severity,
                "node_id": e.node_id,
                "finding_id": e.finding_id,
                "timestamp": e.created_at.isoformat() if e.created_at else None,
            })
        return jsonify({"events": events})

    @app.route("/api/web-scans/<int:scan_id>/resume", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def web_scan_resume(scan_id):
        try:
            scan = resume_scan(scan_id, user=g.current_user, created_by=g.current_user.username)
        except PermissionError as exc:
            return _err("FORBIDDEN", str(exc), 403)
        except ValueError as exc:
            return _err("BAD_REQUEST", str(exc), 400)
        except RuntimeError as exc:
            return _err("UNAVAILABLE", str(exc), 503)
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        scan = db.get(WebScan, scan.id) or scan
        return jsonify(_serialize_scan(scan)), 202

    @app.route("/api/web-targets/<int:target_id>/attack-surface")
    @login_required
    @require_permission("webscan.read")
    def target_attack_surface(target_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        target = db.get(WebTarget, target_id)
        if not target:
            return _err("NOT_FOUND", "Target not found.", 404)
        scan = (
            db.query(WebScan)
            .filter_by(target_id=target_id)
            .order_by(WebScan.id.desc())
            .first()
        )
        if not scan:
            return jsonify({"target": _serialize_target(target), "scan_id": None, "tree": {"nodes": [], "root_ids": []}})
        tree = build_tree_payload(db, scan.id)
        return jsonify({
            "target": _serialize_target(target),
            "scan": _serialize_scan(scan),
            "scan_id": scan.id,
            "tree": tree,
        })

    @app.route("/api/webscan/health")
    @login_required
    @require_permission("webscan.read")
    def webscan_health_alias():
        engines = get_engine_status()
        return jsonify({"engines": engines, "status": "ok"})

    @app.route("/api/web-findings/<int:finding_id>/false-positive", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def web_finding_false_positive(finding_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        finding = db.get(WebFinding, finding_id)
        if not finding:
            return _err("NOT_FOUND", "Finding not found.", 404)
        finding.status = "FALSE_POSITIVE"
        db.commit()
        write_audit(db, action="web_finding.false_positive", user=g.current_user,
                    resource_type="web_finding", resource_id=finding.id)
        return jsonify(_serialize_finding(finding, detail=True))

    @app.route("/api/web-findings/<int:finding_id>/suppress", methods=["POST"])
    @login_required
    @require_permission("webscan.run")
    def web_finding_suppress(finding_id):
        db = __import__("th.db", fromlist=["get_db"]).get_db()
        finding = db.get(WebFinding, finding_id)
        if not finding:
            return _err("NOT_FOUND", "Finding not found.", 404)
        finding.status = "SUPPRESSED"
        db.commit()
        write_audit(db, action="web_finding.suppress", user=g.current_user,
                    resource_type="web_finding", resource_id=finding.id)
        return jsonify(_serialize_finding(finding, detail=True))

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
