"""Central web scan orchestrator with background execution and progress."""

from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from ..audit import write_audit
from ..db import Alert, Event, SessionLocal, WebFinding, WebScan, WebTarget, utcnow
from ..pipeline import persist_alerts
from .config import (
    SCAN_PROFILES,
    WEBSCAN_ALLOW_PRIVATE_TARGETS,
    WEBSCAN_ENABLED,
    WEBSCAN_MAX_CONCURRENT,
    WEBSCAN_TIMEOUT,
)
from .crawler import crawl
from .deduplicator import dedupe_findings
from .engines import detect_engines, run_nmap, run_nuclei, run_zap_passive
from .http_discovery import check_common_files, check_tls, discover_http
from .risk_web import score_web_finding
from .technology import fingerprint
from .validators import SSRFError, validate_scan_url

logger = logging.getLogger("th.web_scanner")

_executor = ThreadPoolExecutor(max_workers=WEBSCAN_MAX_CONCURRENT, thread_name_prefix="webscan")
_cancel_flags: dict[int, threading.Event] = {}
_lock = threading.Lock()
_active = 0

_broadcast: Callable | None = None


def set_broadcast(fn: Callable | None) -> None:
    global _broadcast
    _broadcast = fn


def _emit(event: str, payload: dict) -> None:
    if _broadcast:
        try:
            _broadcast(event, payload)
        except Exception:
            logger.exception("Socket broadcast failed for %s", event)


def get_engine_status() -> dict:
    return detect_engines()


def cancel_scan(scan_id: int) -> bool:
    flag = _cancel_flags.get(scan_id)
    if not flag:
        return False
    flag.set()
    db = SessionLocal()
    try:
        scan = db.get(WebScan, scan_id)
        if scan and scan.status not in {"COMPLETED", "FAILED", "CANCELLED"}:
            scan.status = "CANCELLED"
            scan.current_stage = "CANCELLED"
            scan.finished_at = utcnow()
            db.commit()
            _emit("web_scan_cancelled", {"scan_id": scan_id})
        return True
    finally:
        db.close()


def start_scan_async(
    target_id: int,
    *,
    created_by: str,
    profile: str = "QUICK",
    user=None,
    create_alerts: bool = True,
) -> WebScan:
    if not WEBSCAN_ENABLED:
        raise RuntimeError("Web scanning is disabled (WEBSCAN_ENABLED=false).")

    profile = (profile or "QUICK").upper()
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile '{profile}'. Use QUICK, STANDARD, or DEEP.")

    db = SessionLocal()
    try:
        target = db.get(WebTarget, target_id)
        if not target:
            raise ValueError("Target not found.")
        if not target.enabled:
            raise PermissionError("Target is disabled.")
        if (target.authorization_status or "").upper() != "AUTHORIZED":
            raise PermissionError("Only AUTHORIZED targets can be scanned.")

        # SSRF / URL validation before creating scan
        url_meta = validate_scan_url(
            target.url, allow_private=WEBSCAN_ALLOW_PRIVATE_TARGETS
        )

        with _lock:
            global _active
            if _active >= WEBSCAN_MAX_CONCURRENT:
                raise RuntimeError(
                    f"Maximum concurrent scans reached ({WEBSCAN_MAX_CONCURRENT})."
                )
            _active += 1

        scan = WebScan(
            target_id=target.id,
            status="PENDING",
            started_at=utcnow(),
            created_by=created_by or "",
            scan_profile=profile,
            progress=0,
            current_stage="PENDING",
            configuration_json=json.dumps({
                "profile": profile,
                "resolved_ips": url_meta["resolved_ips"],
                "url": url_meta["url"],
            }),
            engine_versions=json.dumps(detect_engines()),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

        write_audit(
            db,
            action="web_scan.start",
            user=user,
            username=created_by,
            resource_type="web_scan",
            resource_id=scan_id,
            details=f"profile={profile} target={target.url}",
        )
        _cancel_flags[scan_id] = threading.Event()
        _emit("web_scan_started", {
            "scan_id": scan_id,
            "target_id": target.id,
            "profile": profile,
            "resolved_ips": url_meta["resolved_ips"],
        })
        _executor.submit(
            _run_scan_job,
            scan_id,
            create_alerts=create_alerts,
        )
        return scan
    except Exception:
        with _lock:
            _active = max(0, _active - 1)
        raise
    finally:
        db.close()


def _update(db, scan: WebScan, *, stage: str, progress: int, **kwargs) -> None:
    scan.current_stage = stage
    terminal = {"COMPLETED", "FAILED", "CANCELLED"}
    if stage in terminal:
        scan.status = stage
    elif scan.status not in terminal:
        scan.status = "RUNNING"
    scan.progress = max(0, min(100, int(progress)))
    for k, v in kwargs.items():
        if hasattr(scan, k):
            setattr(scan, k, v)
    db.commit()
    _emit("web_scan_progress", {
        "scan_id": scan.id,
        "stage": stage,
        "progress": scan.progress,
        "findings_count": scan.findings_count or 0,
    })
    _emit("web_scan_stage", {"scan_id": scan.id, "stage": stage, "progress": scan.progress})


def _cancelled(scan_id: int) -> bool:
    flag = _cancel_flags.get(scan_id)
    return bool(flag and flag.is_set())


def _run_scan_job(scan_id: int, *, create_alerts: bool = True) -> None:
    db = SessionLocal()
    started = time.time()
    try:
        scan = db.get(WebScan, scan_id)
        target = db.get(WebTarget, scan.target_id) if scan else None
        if not scan or not target:
            return

        profile = SCAN_PROFILES.get((scan.scan_profile or "QUICK").upper(), SCAN_PROFILES["QUICK"])
        allow_private = WEBSCAN_ALLOW_PRIVATE_TARGETS
        raw_findings: list[dict] = []
        tech: list[dict] = []
        ports: list[dict] = []
        urls_discovered = 0

        _update(db, scan, stage="VALIDATING", progress=5)
        if _cancelled(scan_id):
            return
        url_meta = validate_scan_url(target.url, allow_private=allow_private)
        scan_url = url_meta["url"]

        _update(db, scan, stage="DISCOVERING", progress=15)
        if profile.get("tls"):
            tls_findings, _tls = check_tls(scan_url, allow_private=allow_private)
            raw_findings.extend(tls_findings)
        http_findings, discovery = discover_http(scan_url, allow_private=allow_private)
        raw_findings.extend(http_findings)
        if profile.get("technology"):
            tech = fingerprint(discovery.get("headers") or {}, discovery.get("body_sample") or "")
            scan.technologies_count = len(tech)
        if profile.get("passive"):
            raw_findings.extend(check_common_files(scan_url, allow_private=allow_private))

        if _cancelled(scan_id):
            _update(db, scan, stage="CANCELLED", progress=scan.progress, finished_at=utcnow())
            return

        if profile.get("crawl"):
            _update(db, scan, stage="CRAWLING", progress=35)
            crawl_result = crawl(scan_url, allow_private=allow_private)
            urls_discovered = crawl_result.get("count") or 0
            scan.discovered_urls = urls_discovered
            for u in (crawl_result.get("urls") or [])[:20]:
                if u.get("status") == 200 and any(
                    x in (u.get("url") or "") for x in ("/admin", "/.env", "/.git")
                ):
                    raw_findings.append({
                        "title": f"Discovered path {u.get('url')}",
                        "description": "Crawler found a potentially sensitive path.",
                        "severity": "LOW",
                        "confidence": 60,
                        "category": "crawl",
                        "affected_url": u.get("url"),
                        "source_engine": "crawler",
                        "recommendation": "Review exposure of discovered paths.",
                    })

        if _cancelled(scan_id):
            _update(db, scan, stage="CANCELLED", progress=scan.progress, finished_at=utcnow())
            return

        _update(db, scan, stage="SCANNING", progress=55)
        warnings = []
        if profile.get("nuclei"):
            n_findings, err = run_nuclei(scan_url)
            if err:
                warnings.append(err)
            else:
                raw_findings.extend(n_findings)
        if profile.get("nmap"):
            host = url_meta["hostname"]
            nmap_findings, ports, err = run_nmap(host)
            if err:
                warnings.append(err)
            else:
                raw_findings.extend(nmap_findings)
                scan.discovered_ports = len(ports)
        if profile.get("zap"):
            z_findings, err = run_zap_passive(scan_url)
            if err:
                warnings.append(err)
            else:
                raw_findings.extend(z_findings)

        if _cancelled(scan_id):
            _update(db, scan, stage="CANCELLED", progress=scan.progress, finished_at=utcnow())
            return

        _update(db, scan, stage="ANALYZING", progress=80)
        normalized = dedupe_findings(raw_findings, target_url=scan_url)

        # Cross-scan dedupe: update last_seen on existing fingerprints for target
        existing = {
            f.fingerprint: f
            for f in db.query(WebFinding).filter(
                WebFinding.target_id == target.id,
                WebFinding.fingerprint != "",
            ).all()
            if getattr(f, "fingerprint", None)
        }

        counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        alert_payloads = []
        for item in normalized:
            score, factors = score_web_finding(
                severity=item["severity"],
                confidence=item["confidence"],
                cvss=float(item.get("cvss") or 0),
                host=target.name or url_meta["hostname"] or "",
                db=db,
            )
            item["risk_score"] = score
            fp = item["fingerprint"]
            if fp in existing:
                row = existing[fp]
                row.last_seen = utcnow()
                row.occurrence_count = int(getattr(row, "occurrence_count", 1) or 1) + 1
                row.scan_id = scan.id
                row.risk_score = score
                row.severity = item["severity"]
                counts[item["severity"]] = counts.get(item["severity"], 0) + 1
                continue

            row = WebFinding(
                target_id=target.id,
                scan_id=scan.id,
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                confidence=item["confidence"],
                category=item["category"],
                evidence=item["evidence"],
                recommendation=item["recommendation"],
                remediation=item.get("remediation") or item["recommendation"],
                url=item["url"],
                affected_url=item["affected_url"],
                risk_score=score,
                cwe=item.get("cwe") or "",
                owasp=item.get("owasp") or "",
                cve=item.get("cve") or "",
                cvss=float(item.get("cvss") or 0),
                source_engine=item.get("source_engine") or "builtin",
                template_id=item.get("template_id") or "",
                fingerprint=fp,
                method=item.get("method") or "",
                parameter=item.get("parameter") or "",
                request=item.get("request") or "",
                response=item.get("response") or "",
                status="OPEN",
                first_seen=utcnow(),
                last_seen=utcnow(),
                occurrence_count=int(item.get("occurrence_count") or 1),
                risk_factors_json=json.dumps(factors),
            )
            db.add(row)
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
            _emit("web_scan_finding", {
                "scan_id": scan.id,
                "title": row.title,
                "severity": row.severity,
                "risk_score": row.risk_score,
            })
            if create_alerts and item["severity"] in {"HIGH", "CRITICAL"}:
                alert_payloads.append(item)

        db.flush()

        # Optional SIEM alerts for high findings
        if create_alerts and alert_payloads:
            try:
                _promote_alerts(db, target, scan, alert_payloads)
            except Exception:
                logger.exception("Failed promoting web findings to alerts")

        _update(db, scan, stage="FINALIZING", progress=92)
        scan.findings_count = sum(counts.values())
        scan.info_count = counts["INFO"]
        scan.low_count = counts["LOW"]
        scan.medium_count = counts["MEDIUM"]
        scan.high_count = counts["HIGH"]
        scan.critical_count = counts["CRITICAL"]
        scan.discovered_urls = urls_discovered or scan.discovered_urls or 0
        scan.technologies_count = len(tech)
        if ports:
            scan.discovered_ports = len(ports)
            scan.ports_json = json.dumps(ports)
        if tech:
            scan.technologies_json = json.dumps(tech)
        if warnings:
            scan.error_message = "; ".join(warnings)[:2000]
        # Overall scan risk = max finding risk weighted by critical/high
        scan.risk_score = min(
            100,
            counts["CRITICAL"] * 20 + counts["HIGH"] * 12 + counts["MEDIUM"] * 5 + counts["LOW"],
        )
        scan.duration = int(time.time() - started)
        scan.status = "COMPLETED"
        scan.current_stage = "COMPLETED"
        scan.progress = 100
        scan.finished_at = utcnow()
        target.last_scan = utcnow()
        target.last_status = "COMPLETED"
        db.commit()
        _emit("web_scan_completed", {
            "scan_id": scan.id,
            "findings_count": scan.findings_count,
            "risk_score": scan.risk_score,
            "warnings": warnings,
        })
    except SSRFError as exc:
        _fail_scan(db, scan_id, f"SSRF/validation blocked: {exc}")
    except Exception as exc:
        logger.exception("Web scan %s failed", scan_id)
        _fail_scan(db, scan_id, str(exc))
    finally:
        with _lock:
            global _active
            _active = max(0, _active - 1)
        _cancel_flags.pop(scan_id, None)
        db.close()


def _fail_scan(db, scan_id: int, message: str) -> None:
    scan = db.get(WebScan, scan_id)
    if not scan:
        return
    scan.status = "FAILED"
    scan.current_stage = "FAILED"
    scan.error_message = (message or "Scan failed")[:2000]
    scan.finished_at = utcnow()
    scan.progress = scan.progress or 0
    target = db.get(WebTarget, scan.target_id)
    if target:
        target.last_status = "FAILED"
        target.last_scan = utcnow()
    db.commit()
    _emit("web_scan_failed", {"scan_id": scan_id, "error": scan.error_message})


def _promote_alerts(db, target: WebTarget, scan: WebScan, items: list[dict]) -> None:
    """Create Event+Alert rows for high/critical web findings (reuse SIEM pipeline)."""
    broadcast_fn = None
    try:
        # Late import avoids circular dependency at module load.
        from .. import webapp as webapp_module

        broadcast_fn = getattr(webapp_module, "broadcast_new_alert", None)
    except Exception:
        broadcast_fn = None

    alerts = []
    for item in items[:10]:
        ts = utcnow()
        event = Event(
            timestamp=ts,
            host=target.name or "",
            user="",
            process="web_scanner",
            commandline=item.get("title") or "",
            ip="",
            domain="",
            file_hash="",
            source_type="web",
            source_name=f"webscan:{scan.id}",
            raw_payload=json.dumps({"finding": item.get("title"), "url": item.get("affected_url")}),
            event_type="web_finding",
            ingested_at=ts,
            url=item.get("affected_url") or target.url,
        )
        db.add(event)
        db.flush()
        alerts.append({
            "id": f"web_{item.get('source_engine', 'builtin')}_{item.get('fingerprint', '')[:12]}",
            "severity": item.get("severity") or "HIGH",
            "description": item.get("title") or "Web finding",
            "title": item.get("title") or "Web finding",
            "tactic": "Initial Access",
            "technique_id": "",
            "technique_name": item.get("owasp") or "Web Application Finding",
            "event_id": event.id,
            "host": target.name or "",
            "user": "",
            "process": "web_scanner",
            "ip": "",
            "domain": "",
            "file_hash": "",
            "commandline": (item.get("affected_url") or "")[:500],
            "source_type": "web",
            "source_name": f"webscan:{scan.id}",
            "timestamp": ts,
            "risk_score": item.get("risk_score") or 0,
            "confidence": item.get("confidence") or 70,
            "is_suppressed": False,
            "suppression_reason": "",
        })
    if alerts:
        persist_alerts(db, alerts, broadcast_fn=broadcast_fn)
