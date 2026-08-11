"""Backward-compatible sync entrypoint used by older API callers. """

from __future__ import annotations

from ..db import WebScan, utcnow
from .orchestrator import start_scan_async


def run_safe_scan(db, target, created_by: str = "") -> WebScan:
    """
    Legacy synchronous-looking API.

    Starts an async QUICK scan and polls until completion (bounded),
    preserving older call sites that expected a finished WebScan.
    """
    import time

    # Commit any pending target state before background worker opens its session.
    db.commit()
    scan = start_scan_async(
        target.id,
        created_by=created_by or "",
        profile="QUICK",
        create_alerts=True,
    )
    # Poll up to ~3 minutes for compatibility with old sync route.
    deadline = time.time() + 180
    while time.time() < deadline:
        db.expire_all()
        row = db.get(WebScan, scan.id)
        if row and row.status in {"COMPLETED", "FAILED", "CANCELLED"}:
            return row
        time.sleep(0.5)
    row = db.get(WebScan, scan.id)
    if row:
        return row
    return scan
