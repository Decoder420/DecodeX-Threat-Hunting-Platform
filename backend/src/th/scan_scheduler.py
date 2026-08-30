"""
DecodeX Continuous DAST Scan Scheduler Daemon
=============================================
Runs a background daemon polling active targets with enabled schedules (e.g. daily/weekly).
When next_scheduled_scan is reached, it creates and launches an automated DAST scan job.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from sqlalchemy import inspect

from . import db as dbmod

logger = logging.getLogger("th.scheduler")

_scheduler_thread: threading.Thread | None = None
_stop_event = threading.Event()
_scheduler_status = {
    "running": False,
    "last_run_at": None,
    "scans_triggered_total": 0,
    "last_error": "",
}


def get_scheduler_status() -> dict:
    return dict(_scheduler_status)


def _check_and_trigger_scheduled_scans() -> None:
    """Checks for due targets and triggers automated scans."""
    try:
        dbmod._initialize_database()
        if not inspect(dbmod.engine).has_table("web_targets") or not inspect(dbmod.engine).has_table("web_scans"):
            return
    except Exception as exc:
        logger.debug("Database not yet initialized for scheduler: %s", exc)
        return

    now = dbmod.utcnow()
    db = dbmod.SessionLocal()
    try:
        # Find targets that are enabled, scheduled, and due
        due_targets = (
            db.query(dbmod.WebTarget)
            .filter(
                dbmod.WebTarget.enabled == True,
                dbmod.WebTarget.schedule_enabled == True,
                (dbmod.WebTarget.next_scheduled_scan == None) | (dbmod.WebTarget.next_scheduled_scan <= now),
            )
            .all()
        )

        for target in due_targets:
            interval_hours = max(1, target.schedule_interval_hours or 24)
            target.last_scheduled_scan = now
            target.next_scheduled_scan = now + timedelta(hours=interval_hours)
            db.commit()

            # Create a scheduled WebScan entry
            new_scan = dbmod.WebScan(
                target_id=target.id,
                status="PENDING",
                scan_profile="STANDARD",
                created_by="system.scheduler",
                started_at=now,
            )
            db.add(new_scan)
            db.commit()

            scan_id = new_scan.id
            logger.info(
                "Triggering scheduled automated scan #%s for target '%s' (%s). Next run in %sh.",
                scan_id, target.name, target.url, interval_hours
            )
            _scheduler_status["scans_triggered_total"] += 1

            # Dispatch scan job in worker thread
            def _runner(s_id: int):
                try:
                    from .web_scanner.orchestrator import _run_scan_job
                    _run_scan_job(s_id)
                except Exception as err:
                    logger.error("Automated scheduled scan %s failed: %s", s_id, err)

            threading.Thread(target=_runner, args=(scan_id,), daemon=True).start()

    except Exception as exc:
        _scheduler_status["last_error"] = str(exc)
        logger.error("Scan scheduler cycle encountered an error: %s", exc)
    finally:
        db.close()


def _scheduler_loop(interval_seconds: int = 60) -> None:
    logger.info("Scan scheduler daemon started (poll=%ss)", interval_seconds)
    _scheduler_status["running"] = True
    while not _stop_event.is_set():
        _scheduler_status["last_run_at"] = datetime.now(timezone.utc).isoformat()
        _check_and_trigger_scheduled_scans()
        _stop_event.wait(timeout=interval_seconds)
    _scheduler_status["running"] = False
    logger.info("Scan scheduler daemon stopped.")


def start_scan_scheduler(interval_seconds: int = 60) -> None:
    """Starts the scan scheduler in a daemon thread if not already running."""
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _stop_event.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop, args=(interval_seconds,), daemon=True, name="decodex_scan_scheduler"
    )
    _scheduler_thread.start()


def stop_scan_scheduler() -> None:
    """Signals the scheduler daemon to terminate."""
    _stop_event.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=3.0)
