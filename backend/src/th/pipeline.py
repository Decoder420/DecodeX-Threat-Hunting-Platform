from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
import yara
import yaml
from sqlalchemy import delete

from .db import Alert, Event, IOC, IngestionState, SuppressionRule
from .feed_collector import FeedCollector
from .scanner import scanner
from .sigma_importer import sigma_to_local_rules

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_LOG_DIR = PROJECT_ROOT / "data" / "logs"
DEFAULT_RULE_FILE = PROJECT_ROOT / "hunting_rules.yml"

IOC_FEEDS = [
    {"type": "ip", "value": "45.148.10.12", "source": "abuse.ch"},
    {"type": "ip", "value": "185.220.101.1", "source": "abuse.ch"},
    {"type": "domain", "value": "malicious.example.com", "source": "abuse.ch"},
    {"type": "hash", "value": "44d88612fea8a8f36de82e1278abb02f", "source": "malwaredb"},
]

CASE_STATUSES = ["Open", "In Progress", "Quarantine", "False Positive", "Resolved"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_event_record(record: dict, source_name: str, source_type: str) -> Event | None:
    if not isinstance(record, dict):
        return None

    timestamp_value = record.get("timestamp") or record.get("time")
    if timestamp_value is None:
        raise ValueError("missing timestamp")

    timestamp_text = str(timestamp_value)
    try:
        parsed_time = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    except ValueError:
        parsed_time = datetime.fromtimestamp(int(timestamp_text) / 1000.0, tz=timezone.utc)

    host = record.get("host") or record.get("hostname") or source_name
    user = record.get("user") or record.get("service") or ""
    process = record.get("process") or record.get("event_type") or record.get("level") or ""
    commandline = record.get("commandline") or record.get("message") or record.get("text") or ""
    ip = record.get("ip") or record.get("source_ip") or record.get("client_ip") or ""
    domain = record.get("domain") or record.get("request_host") or ""
    file_hash = record.get("file_hash") or record.get("hash") or ""
    raw_payload = json.dumps(record, ensure_ascii=True)

    event = Event(
        timestamp=parsed_time,
        host=host,
        user=user,
        process=process,
        commandline=commandline,
        ip=ip,
        domain=domain,
        file_hash=file_hash,
        source_type=source_type,
        source_name=source_name,
        raw_payload=raw_payload,
    )

    yara_matches = scanner.scan_log(raw_payload)
    if yara_matches:
        event.commandline = f"[YARA: {', '.join(yara_matches)}] {event.commandline}"

    return event


def seed_iocs(db, feeds: Iterable[dict] = IOC_FEEDS) -> int:
    added = 0
    for ioc_data in feeds:
        exists = db.query(IOC).filter_by(type=ioc_data["type"], value=ioc_data["value"]).first()
        if exists:
            continue
        db.add(IOC(**ioc_data))
        added += 1
    db.commit()
    return added


def discover_log_sources(log_dir: Path = DATA_LOG_DIR) -> list[dict]:
    sources = []
    for path in sorted(log_dir.glob("*.log")):
        source_name = path.name
        source_type = "endpoint"
        lowered = source_name.lower()
        if "auth" in lowered:
            source_type = "authentication"
        elif "firewall" in lowered:
            source_type = "firewall"
        elif "endpoint" in lowered:
            source_type = "endpoint"
        sources.append({"path": path, "source_name": source_name, "source_type": source_type})
    return sources


def get_or_create_ingestion_state(db, source: str) -> IngestionState:
    state = db.query(IngestionState).filter_by(source=source).first()
    if state:
        return state
    state = IngestionState(source=source, offset=0, updated_at=utcnow())
    db.add(state)
    db.commit()
    return state


def ingest_log_payload(db, payload, source_name: str = "webhook", source_type: str = "cloud") -> tuple[int, int, list[Event]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("logs"), list):
            records = payload["logs"]
        else:
            records = [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        return 0, 0, []

    added = 0
    skipped = 0
    new_events: list[Event] = []
    state = get_or_create_ingestion_state(db, source_name)

    for record in records:
        try:
            event = normalize_event_record(record, source_name, source_type)
            if not event:
                raise ValueError("invalid record")
        except (TypeError, ValueError, KeyError):
            skipped += 1
            continue

        duplicate = (
            db.query(Event)
            .filter_by(
                timestamp=event.timestamp,
                host=event.host,
                user=event.user,
                process=event.process,
                commandline=event.commandline,
                ip=event.ip,
                domain=event.domain,
                file_hash=event.file_hash,
                source_name=event.source_name,
            )
            .first()
        )
        if duplicate:
            skipped += 1
            continue

        db.add(event)
        new_events.append(event)
        added += 1

    state.updated_at = utcnow()
    db.commit()
    return added, skipped, new_events

def ingest_logs(db, sources: Iterable[dict] | None = None) -> tuple[int, int, list[Event]]:
    sources = list(sources or discover_log_sources())
    added = 0
    skipped = 0
    new_events: list[Event] = []

    for source in sources:
        path = source["path"]
        state = get_or_create_ingestion_state(db, source["source_name"])
        if not path.exists():
            continue

        file_size = path.stat().st_size
        start_offset = state.offset if state.offset <= file_size else 0

        with path.open("r", encoding="utf-8") as handle:
            handle.seek(start_offset)
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = normalize_event_record(data, source["source_name"], source["source_type"])
                    if not event:
                        raise ValueError("invalid record")
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    skipped += 1
                    continue

                duplicate = (
                    db.query(Event)
                    .filter_by(
                        timestamp=event.timestamp,
                        host=event.host,
                        user=event.user,
                        process=event.process,
                        commandline=event.commandline,
                        ip=event.ip,
                        domain=event.domain,
                        file_hash=event.file_hash,
                        source_name=event.source_name,
                    )
                    .first()
                )
                if duplicate:
                    skipped += 1
                    continue

                db.add(event)
                new_events.append(event)
                added += 1

            state.offset = handle.tell()
            state.updated_at = utcnow()

    db.commit()
    return added, skipped, new_events


def persist_alerts(db, alerts: Iterable[dict], broadcast_fn=None) -> int:
    persisted = 0
    created_alerts = []
    existing_rows = db.query(Alert).all()
    seen_rule_event = {(row.rule_id, row.event_id) for row in existing_rows}
    seen_identity = {alert_identity(row) for row in existing_rows}

    for alert in alerts:
        identity = alert_identity(alert)
        rule_event = (alert["id"], alert["event_id"])
        if identity in seen_identity or rule_event in seen_rule_event:
            existing = db.query(Alert).filter_by(rule_id=alert["id"], event_id=alert["event_id"]).first()
            if existing:
                existing.is_suppressed = alert.get("is_suppressed", False)
                existing.suppression_reason = alert.get("suppression_reason", "")
            continue

        new_alert = Alert(
            rule_id=alert["id"],
            severity=alert["severity"],
            description=alert["description"],
            tactic=alert.get("tactic", ""),
            technique_id=alert.get("technique_id", ""),
            technique_name=alert.get("technique_name", ""),
            event_id=alert["event_id"],
            host=alert.get("host", ""),
            user=alert.get("user", ""),
            process=alert.get("process", ""),
            ip=alert.get("ip", ""),
            domain=alert.get("domain", ""),
            file_hash=alert.get("file_hash", ""),
            commandline=alert.get("commandline", ""),
            source_type=alert.get("source_type", ""),
            source_name=alert.get("source_name", ""),
            is_suppressed=alert.get("is_suppressed", False),
            suppression_reason=alert.get("suppression_reason", ""),
            event_timestamp=alert["timestamp"],
        )
        db.add(new_alert)
        created_alerts.append(new_alert)
        seen_identity.add(identity)
        seen_rule_event.add(rule_event)
        persisted += 1

    db.commit()

    if broadcast_fn:
        for created_alert in created_alerts:
            broadcast_fn(created_alert)

    return persisted


def build_ioc_sets(iocs: Iterable[IOC]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {"ip": set(), "domain": set(), "hash": set()}
    for ioc in iocs:
        grouped.setdefault(ioc.type, set()).add(ioc.value)
    return grouped


def alert_value(alert, key: str):
    if isinstance(alert, dict):
        return alert.get(key, "")
    return getattr(alert, key, "")


def alert_identity(alert) -> tuple:
    return (
        alert_value(alert, "rule_id") or alert_value(alert, "id"),
        alert_value(alert, "host"),
        alert_value(alert, "user"),
        alert_value(alert, "process"),
        alert_value(alert, "ip"),
        alert_value(alert, "domain"),
        alert_value(alert, "file_hash"),
        alert_value(alert, "commandline"),
        alert_value(alert, "source_name"),
        str(alert_value(alert, "timestamp") or alert_value(alert, "event_timestamp")),
    )


def severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get((severity or "").lower(), 0)


def get_suppression_reason(db, alert: dict) -> str:
    for rule in db.query(SuppressionRule).filter_by(is_active=True).all():
        if rule.rule_id and rule.rule_id != alert["id"]:
            continue
        field_value = str(alert.get(rule.field_name, ""))
        if rule.field_name and rule.field_value and field_value == rule.field_value:
            return rule.reason or rule.name
    return ""


def evaluate_events(db, events, evaluator, ioc_sets: dict[str, set[str]]) -> list[dict]:
    alerts: list[dict] = []
    seen = set()

    for event in events:
        matches = evaluator.evaluate(
            event,
            ioc_ips=ioc_sets.get("ip", set()),
            ioc_domains=ioc_sets.get("domain", set()),
            ioc_hashes=ioc_sets.get("hash", set()),
        )
        for alert in matches:
            alert["source_type"] = getattr(event, "source_type", "")
            alert["source_name"] = getattr(event, "source_name", "")
            alert["suppression_reason"] = get_suppression_reason(db, alert)
            alert["is_suppressed"] = bool(alert["suppression_reason"])
            key = alert_identity(alert)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(alert)

    alerts.sort(key=lambda item: (severity_rank(item["severity"]), item["timestamp"]), reverse=True)
    return alerts




def unique_alerts(alerts: Iterable) -> list:
    deduped = []
    seen = set()
    for alert in alerts:
        identity = alert_identity(alert)
        if identity in seen:
            continue
        seen.add(identity)
        deduped.append(alert)
    return deduped


def prune_duplicate_alert_rows(db) -> int:
    delete_ids = []
    seen = set()
    for alert in db.query(Alert).order_by(Alert.id.asc()).all():
        identity = alert_identity(alert)
        if identity in seen:
            delete_ids.append(alert.id)
            continue
        seen.add(identity)
    if delete_ids:
        db.execute(delete(Alert).where(Alert.id.in_(delete_ids)))
        db.commit()
    return len(delete_ids)


def summarize_alerts(alerts: Iterable) -> dict[str, object]:
    alerts = list(alerts)
    severities = Counter(alert_value(alert, "severity").lower() for alert in alerts)
    tactics = Counter((alert_value(alert, "tactic") or "Unmapped") for alert in alerts)
    rule_hits = Counter(alert_value(alert, "rule_id") or alert_value(alert, "id") for alert in alerts)
    statuses = Counter(alert_value(alert, "status") or "Open" for alert in alerts)
    sources = Counter(alert_value(alert, "source_type") or "endpoint" for alert in alerts)
    return {
        "total_alerts": len(alerts),
        "high_or_above": sum(count for severity, count in severities.items() if severity in {"high", "critical"}),
        "by_severity": dict(sorted(severities.items())),
        "top_tactics": tactics.most_common(5),
        "top_rules": rule_hits.most_common(5),
        "by_status": dict(sorted(statuses.items())),
        "by_source": dict(sorted(sources.items())),
    }


def analytics_snapshot(events, alerts) -> dict[str, object]:
    host_counter = Counter(getattr(event, "host", "") for event in events if getattr(event, "host", ""))

    # 📈 Timeline aggregation (hourly buckets)
    timeline_counter = Counter()

    for alert in alerts:
        ts = alert_value(alert, "event_timestamp")
        if not ts:
            continue

        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)

        bucket = ts.strftime("%Y-%m-%d %H:00")  # hourly aggregation
        timeline_counter[bucket] += 1

    # Sort timeline
    sorted_timeline = sorted(timeline_counter.items())

    labels = [x[0] for x in sorted_timeline]
    values = [x[1] for x in sorted_timeline]

    # 🧠 MITRE Heatmap
    heatmap = defaultdict(lambda: defaultdict(int))
    for alert in alerts:
        tactic = alert_value(alert, "tactic") or "Unmapped"
        severity = (alert_value(alert, "severity") or "unknown").title()
        heatmap[tactic][severity] += 1

    return {
        "top_hosts": host_counter.most_common(5),

        # ✅ THIS FIXES YOUR ERROR
        "timeline": {
            "labels": labels,
            "values": values
        },

        "mitre_heatmap": {tactic: dict(values) for tactic, values in heatmap.items()},
    }

def build_dashboard_summary(events, iocs, alerts, ingestion_states=None) -> dict[str, object]:
    event_list = list(events)
    ioc_list = list(iocs)
    alert_list = list(alerts)
    states = list(ingestion_states or [])
    base = summarize_alerts(alert_list)
    base.update(
        {
            "total_events": len(event_list),
            "total_iocs": len(ioc_list),
            "last_event_at": event_list[0].timestamp.isoformat() if event_list else "",
            "live_offset": sum(state.offset for state in states),
            "last_ingest_at": max((state.updated_at.isoformat() for state in states), default=""),
            "analytics": analytics_snapshot(event_list, alert_list),
        }
    )
    return base


def update_alert_case(db, alert_id: int, status: str, assigned_to: str, analyst_notes: str) -> None:
    alert = db.query(Alert).filter_by(id=alert_id).first()
    if not alert:
        return
    if status in CASE_STATUSES:
        alert.status = status
    alert.assigned_to = assigned_to
    alert.analyst_notes = analyst_notes
    db.commit()


def create_suppression_rule(db, name: str, rule_id: str, field_name: str, field_value: str, reason: str) -> None:
    db.add(
        SuppressionRule(
            name=name,
            rule_id=rule_id,
            field_name=field_name,
            field_value=field_value,
            reason=reason,
            is_active=True,
        )
    )
    db.commit()


def sync_ioc_feeds() -> dict[str, object]:
    collector = FeedCollector()
    return collector.sync_enabled_feeds()


def import_sigma_rules(sigma_path: Path, rule_file: Path = DEFAULT_RULE_FILE) -> int:
    payload = {}
    if rule_file.exists():
        with rule_file.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
    rules = payload.get("rules", [])
    imported = sigma_to_local_rules(sigma_path)
    existing_ids = {rule["id"] for rule in rules}
    for rule in imported:
        if rule["id"] not in existing_ids:
            rules.append(rule)
    with rule_file.open("w", encoding="utf-8") as handle:
        yaml.safe_dump({"rules": rules}, handle, sort_keys=False)
    return len(imported)


def refresh_hunting_state(db, evaluator, broadcast_fn=None) -> dict[str, int]:
    iocs_added = seed_iocs(db)
    events_added, events_skipped, _ = ingest_logs(db)
    ioc_sets = build_ioc_sets(db.query(IOC).all())
    alerts = evaluate_events(db, db.query(Event).order_by(Event.timestamp.asc()).all(), evaluator, ioc_sets)
    alerts_added = persist_alerts(db, alerts, broadcast_fn=broadcast_fn)
    duplicate_alerts_removed = prune_duplicate_alert_rows(db)
    return {
        "iocs_added": iocs_added,
        "events_added": events_added,
        "events_skipped": events_skipped,
        "alerts_added": alerts_added,
        "duplicate_alerts_removed": duplicate_alerts_removed,
    }