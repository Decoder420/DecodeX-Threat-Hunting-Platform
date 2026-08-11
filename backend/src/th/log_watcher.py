"""Background log-directory watcher that tails files using IngestionState offsets."""

from __future__ import annotations

import logging
import threading
import time

from .correlation import correlate_new_alerts
from .db import IOC, Alert, SessionLocal, _initialize_database
from .pipeline import (
    DEFAULT_RULE_FILE,
    DATA_LOG_DIR,
    build_ioc_sets,
    evaluate_events,
    ingest_logs,
    persist_alerts,
)
from .risk import compute_risk_score
from .rule_evaluator import RuleEvaluator

logger = logging.getLogger("th.ingestion")

_watcher_thread: threading.Thread | None = None
_stop_event = threading.Event()
_status = {
    "enabled": False,
    "running": False,
    "last_cycle_at": None,
    "last_error": "",
    "events_added_total": 0,
    "alerts_added_total": 0,
    "cycle_count": 0,
}


def get_watcher_status() -> dict:
    return dict(_status)


def _process_cycle(broadcast_fn=None) -> None:
    _initialize_database()
    db = SessionLocal()
    try:
        evaluator = RuleEvaluator(str(DEFAULT_RULE_FILE))
        added, skipped, new_events = ingest_logs(db)
        _status["cycle_count"] += 1
        _status["last_cycle_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not new_events:
            return

        ioc_sets = build_ioc_sets(db.query(IOC).all())
        alerts = evaluate_events(db, new_events, evaluator, ioc_sets)

        for alert in alerts:
            ioc_hit = (
                alert.get("ip") in ioc_sets.get("ip", set())
                or alert.get("domain") in ioc_sets.get("domain", set())
                or alert.get("file_hash") in ioc_sets.get("hash", set())
            )
            alert["risk_score"] = compute_risk_score(
                severity=alert.get("severity", "medium"),
                confidence=75,
                ioc_matched=ioc_hit,
                correlation_count=0,
                host=alert.get("host", ""),
                db=db,
                technique_id=alert.get("technique_id", ""),
            )
            alert["confidence"] = 75

        max_id_before = db.query(Alert.id).order_by(Alert.id.desc()).limit(1).scalar() or 0
        alerts_added = persist_alerts(db, alerts, broadcast_fn=broadcast_fn)
        created = (
            db.query(Alert)
            .filter(Alert.id > max_id_before)
            .order_by(Alert.id.asc())
            .all()
        )
        for row in created:
            if not getattr(row, "risk_score", None):
                row.risk_score = compute_risk_score(
                    severity=row.severity,
                    confidence=getattr(row, "confidence", None) or 70,
                    host=row.host,
                    db=db,
                    technique_id=row.technique_id,
                )
            if not getattr(row, "confidence", None):
                row.confidence = 70
        db.commit()
        if created:
            correlate_new_alerts(db, created)

        _status["events_added_total"] += added
        _status["alerts_added_total"] += alerts_added
        _status["last_error"] = ""
        if added:
            logger.info(
                "Ingestion cycle: events+=%s skipped=%s alerts+=%s",
                added,
                skipped,
                alerts_added,
            )
    except Exception as exc:
        logger.exception("Ingestion cycle failed")
        _status["last_error"] = str(exc)
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()


def _loop(poll_seconds: float, broadcast_fn=None) -> None:
    _status["running"] = True
    while not _stop_event.is_set():
        _process_cycle(broadcast_fn=broadcast_fn)
        _stop_event.wait(poll_seconds)
    _status["running"] = False


def start_log_watcher(broadcast_fn=None, poll_seconds: float = 2.0) -> None:
    global _watcher_thread
    if _watcher_thread and _watcher_thread.is_alive():
        return
    DATA_LOG_DIR.mkdir(parents=True, exist_ok=True)
    _stop_event.clear()
    _status["enabled"] = True
    _watcher_thread = threading.Thread(
        target=_loop,
        kwargs={"poll_seconds": poll_seconds, "broadcast_fn": broadcast_fn},
        name="th-log-watcher",
        daemon=True,
    )
    _watcher_thread.start()
    logger.info("Log watcher started on %s (poll=%ss)", DATA_LOG_DIR, poll_seconds)


def stop_log_watcher() -> None:
    _stop_event.set()
    _status["enabled"] = False
