"""Correlate related alerts into incidents within a time window."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .db import Alert, CorrelatedIncident, IncidentAlert, utcnow
from .risk import compute_risk_score


WINDOW_MINUTES = 30


def _naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _window_key(alert: Alert) -> tuple:
    return (
        (alert.host or "").lower(),
        (alert.user or "").lower(),
        (alert.ip or "").lower(),
    )


def correlate_new_alerts(db, alerts: list[Alert]) -> list[CorrelatedIncident]:
    """Attach newly created alerts to open incidents or create new ones."""
    created: list[CorrelatedIncident] = []
    for alert in alerts:
        if not alert or alert.is_suppressed:
            continue
        host, user, ip = _window_key(alert)
        if not host and not user and not ip:
            continue

        event_ts = _naive(alert.event_timestamp) or _naive(utcnow())
        window_start = event_ts - timedelta(minutes=WINDOW_MINUTES)
        # Find open incident with overlapping correlation keys.
        candidates = (
            db.query(CorrelatedIncident)
            .filter(CorrelatedIncident.status == "OPEN")
            .order_by(CorrelatedIncident.updated_at.desc())
            .limit(50)
            .all()
        )
        incident = None
        for cand in candidates:
            same_host = host and cand.host and cand.host.lower() == host
            same_user = user and cand.user and cand.user.lower() == user
            same_ip = ip and cand.source_ip and cand.source_ip.lower() == ip
            if not (same_host or same_user or same_ip):
                continue
            cand_updated = _naive(cand.updated_at)
            if cand_updated and cand_updated < window_start:
                continue
            incident = cand
            break

        if incident is None:
            next_num = (db.query(CorrelatedIncident).count() or 0) + 1
            incident = CorrelatedIncident(
                case_number=f"INC-{next_num:05d}",
                title=alert.description or "Correlated security incident",
                description=f"Auto-correlated activity on host={alert.host} user={alert.user}",
                severity=(alert.severity or "MEDIUM").upper(),
                risk_score=alert.risk_score or 0,
                status="OPEN",
                host=alert.host or "",
                user=alert.user or "",
                source_ip=alert.ip or "",
                tactic=alert.tactic or "",
                technique_id=alert.technique_id or "",
            )
            db.add(incident)
            db.flush()
            created.append(incident)

        # Link alert if not already linked
        exists = (
            db.query(IncidentAlert)
            .filter_by(incident_id=incident.id, alert_id=alert.id)
            .first()
        )
        if not exists:
            db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))

        alert_count = db.query(IncidentAlert).filter_by(incident_id=incident.id).count()
        incident.alert_count = alert_count
        incident.risk_score = compute_risk_score(
            severity=incident.severity,
            confidence=80,
            ioc_matched=bool(alert.ip or alert.domain or alert.file_hash),
            correlation_count=max(0, alert_count - 1),
            host=incident.host,
            db=db,
            technique_id=incident.technique_id,
        )
        # Escalate severity from child if higher
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        child_sev = (alert.severity or "").upper()
        if order.get(child_sev, 0) > order.get((incident.severity or "").upper(), 0):
            incident.severity = child_sev
        incident.updated_at = utcnow()
        if alert.case_id and not incident.case_id:
            incident.case_id = alert.case_id

    db.commit()
    return created


def incident_timeline(db, incident: CorrelatedIncident) -> list[dict]:
    links = (
        db.query(IncidentAlert)
        .filter_by(incident_id=incident.id)
        .all()
    )
    alert_ids = [link.alert_id for link in links]
    if not alert_ids:
        return []
    alerts = (
        db.query(Alert)
        .filter(Alert.id.in_(alert_ids))
        .order_by(Alert.event_timestamp.asc())
        .all()
    )
    return [
        {
            "alert_id": a.id,
            "timestamp": a.event_timestamp.isoformat() if a.event_timestamp else None,
            "title": a.description,
            "severity": a.severity,
            "host": a.host,
            "user": a.user,
            "process": a.process,
            "commandline": a.commandline,
            "ip": a.ip,
            "tactic": a.tactic,
            "technique_id": a.technique_id,
            "risk_score": a.risk_score,
        }
        for a in alerts
    ]
