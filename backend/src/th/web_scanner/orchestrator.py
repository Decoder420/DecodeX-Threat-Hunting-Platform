"""Central web scan orchestrator with attack-surface tree and realtime events."""

from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from urllib.parse import urlparse

from ..audit import write_audit
from ..db import Event, SessionLocal, WebFinding, WebScan, WebTarget, utcnow
from ..pipeline import persist_alerts
from .api_discovery import discover_api_paths
from .config import (
    SCAN_PROFILES,
    WEBSCAN_ALLOW_PRIVATE_TARGETS,
    WEBSCAN_DEMO_MODE,
    WEBSCAN_ENABLED,
    WEBSCAN_LAB_MODE,
    WEBSCAN_MAX_CONCURRENT,
    WEBSCAN_PRODUCTION_SAFETY_MODE,
    WEBSCAN_REQUEST_BUDGET,
)
from .crawler import crawl
from .deduplicator import dedupe_findings
from .engines import detect_engines, run_nmap, run_nuclei, run_zap_active, run_zap_passive
from .http_discovery import check_common_files, check_tls, discover_http
from .risk_web import score_web_finding
from .sitemap import extract_sitemap_urls
from .surface import AttackSurfaceBuilder, persist_scan_event
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
    status = detect_engines()
    status["safety"] = {
        "production_safety_mode": WEBSCAN_PRODUCTION_SAFETY_MODE,
        "lab_mode": WEBSCAN_LAB_MODE,
        "allow_private_targets": WEBSCAN_ALLOW_PRIVATE_TARGETS,
        "demo_mode": WEBSCAN_DEMO_MODE,
        "request_budget": WEBSCAN_REQUEST_BUDGET,
    }
    status["profiles"] = list(SCAN_PROFILES.keys())
    return status


from sqlalchemy import inspect

def recover_stale_scans(db=None) -> int:
    """Transition any orphan scans left in RUNNING or PENDING state on startup to INTERRUPTED."""
    owns_db = db is None
    if db is None:
        db = SessionLocal()
    count = 0
    try:
        bind = db.get_bind()
        if bind is not None and not inspect(bind).has_table("web_scans"):
            return 0
        orphans = (
            db.query(WebScan)
            .filter(WebScan.status.in_(["RUNNING", "PENDING", "DISCOVERING", "CRAWLING", "SCANNING", "RESUMING"]))
            .all()
        )
        for s in orphans:
            s.status = "INTERRUPTED"
            s.interrupted = True
            s.current_stage = "INTERRUPTED"
            s.error_message = "Scan interrupted by application restart. Ready to resume."
            count += 1
        if count:
            db.commit()
            logger.info("Recovered %s stale/interrupted web scans on startup.", count)
        return count
    finally:
        if owns_db:
            db.close()


def cancel_scan(scan_id: int) -> bool:
    flag = _cancel_flags.get(scan_id)
    if not flag:
        # Still mark DB if scan exists and is running
        db = SessionLocal()
        try:
            scan = db.get(WebScan, scan_id)
            if scan and scan.status not in {"COMPLETED", "FAILED", "CANCELLED"}:
                scan.status = "CANCELLING"
                scan.current_stage = "CANCELLING"
                db.commit()
                scan.status = "CANCELLED"
                scan.current_stage = "CANCELLED"
                scan.finished_at = utcnow()
                db.commit()
                _emit("web_scan_cancelled", {"scan_id": scan_id})
                _emit("webscan_cancelled", {"scan_id": scan_id})
                return True
            return False
        finally:
            db.close()
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
            _emit("webscan_cancelled", {"scan_id": scan_id})
        return True
    finally:
        db.close()


def resume_scan(scan_id: int, *, user=None, created_by: str = "") -> WebScan:
    """Resume an interrupted/failed scan from last completed stage (best-effort)."""
    db = SessionLocal()
    try:
        scan = db.get(WebScan, scan_id)
        if not scan:
            raise ValueError("Scan not found.")
        if scan.status not in {"FAILED", "CANCELLED", "PARTIAL"} and not getattr(scan, "interrupted", False):
            raise ValueError("Only interrupted/failed/cancelled/partial scans can be resumed.")
        target = db.get(WebTarget, scan.target_id)
        if not target or (target.authorization_status or "").upper() != "AUTHORIZED" or not target.enabled:
            raise PermissionError("Target must remain AUTHORIZED and enabled.")
        with _lock:
            global _active
            if _active >= WEBSCAN_MAX_CONCURRENT:
                raise RuntimeError(f"Maximum concurrent scans reached ({WEBSCAN_MAX_CONCURRENT}).")
            _active += 1
        scan.status = "RUNNING"
        scan.interrupted = False
        scan.error_message = ""
        scan.finished_at = None
        scan.current_stage = "RESUMING"
        db.commit()
        write_audit(
            db,
            action="web_scan.resume",
            user=user,
            username=created_by,
            resource_type="web_scan",
            resource_id=scan.id,
        )
        _cancel_flags[scan.id] = threading.Event()
        _emit("webscan_started", {"scan_id": scan.id, "target_id": scan.target_id, "resumed": True})
        _executor.submit(_run_scan_job, scan.id, create_alerts=True, resume=True)
        return scan
    except Exception:
        with _lock:
            _active = max(0, _active - 1)
        raise
    finally:
        db.close()


def start_scan_async(
    target_id: int,
    *,
    created_by: str,
    profile: str = "QUICK",
    user=None,
    create_alerts: bool = True,
    safety_mode: str | None = None,
) -> WebScan:
    if not WEBSCAN_ENABLED:
        raise RuntimeError("Web scanning is disabled (WEBSCAN_ENABLED=false).")

    profile = (profile or "QUICK").upper()
    if profile not in SCAN_PROFILES:
        raise ValueError(
            f"Unknown scan profile '{profile}'. Use: {', '.join(sorted(SCAN_PROFILES))}."
        )
    if profile == "LAB" and not WEBSCAN_LAB_MODE and not WEBSCAN_ALLOW_PRIVATE_TARGETS:
        raise PermissionError("LAB profile requires WEBSCAN_LAB_MODE=true (or private lab targets enabled).")

    db = SessionLocal()
    try:
        target = db.get(WebTarget, target_id)
        if not target:
            raise ValueError("Target not found.")
        if not target.enabled:
            raise PermissionError("Target is disabled.")
        if (target.authorization_status or "").upper() != "AUTHORIZED":
            raise PermissionError("Only AUTHORIZED targets can be scanned.")

        url_meta = validate_scan_url(target.url, allow_private=WEBSCAN_ALLOW_PRIVATE_TARGETS)

        with _lock:
            global _active
            if _active >= WEBSCAN_MAX_CONCURRENT:
                raise RuntimeError(f"Maximum concurrent scans reached ({WEBSCAN_MAX_CONCURRENT}).")
            _active += 1

        mode = (safety_mode or ("lab" if WEBSCAN_LAB_MODE else "production")).lower()
        if WEBSCAN_PRODUCTION_SAFETY_MODE and mode != "lab":
            mode = "production"

        scan = WebScan(
            target_id=target.id,
            status="PENDING",
            started_at=utcnow(),
            created_by=created_by or "",
            scan_profile=profile,
            progress=0,
            current_stage="PENDING",
            request_budget=WEBSCAN_REQUEST_BUDGET,
            requests_used=0,
            safety_mode=mode,
            completed_stages="[]",
            configuration_json=json.dumps({
                "profile": profile,
                "policy": SCAN_PROFILES.get(profile, {}).get("policy", "DEFAULT"),
                "alert_threshold": SCAN_PROFILES.get(profile, {}).get("alert_threshold", "MEDIUM"),
                "attack_strength": SCAN_PROFILES.get(profile, {}).get("attack_strength", "MEDIUM"),
                "resolved_ips": url_meta["resolved_ips"],
                "url": url_meta["url"],
                "safety_mode": mode,
                "request_budget": WEBSCAN_REQUEST_BUDGET,
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
            details=f"profile={profile} target={target.url} safety={mode}",
        )
        _cancel_flags[scan_id] = threading.Event()
        started = {
            "scan_id": scan_id,
            "target_id": target.id,
            "profile": profile,
            "resolved_ips": url_meta["resolved_ips"],
            "safety_mode": mode,
        }
        _emit("web_scan_started", started)
        _emit("webscan_started", started)
        _executor.submit(_run_scan_job, scan_id, create_alerts=create_alerts, resume=False)
        return scan
    except Exception:
        with _lock:
            _active = max(0, _active - 1)
        raise
    finally:
        db.close()


def _update(db, scan: WebScan, *, stage: str, progress: int, **kwargs) -> None:
    scan.current_stage = stage
    terminal = {"COMPLETED", "FAILED", "CANCELLED", "PARTIAL"}
    if stage in terminal:
        scan.status = stage
    elif scan.status not in terminal:
        scan.status = "RUNNING"
    scan.progress = max(0, min(100, int(progress)))
    for k, v in kwargs.items():
        if hasattr(scan, k):
            setattr(scan, k, v)
    # Track completed stages
    try:
        done = json.loads(scan.completed_stages or "[]")
        if not isinstance(done, list):
            done = []
    except Exception:
        done = []
    if stage not in done and stage not in terminal and stage not in {"PENDING", "VALIDATING"}:
        # mark previous stage done when advancing
        pass
    if stage in {
        "DISCOVERING", "CRAWLING", "API_DISCOVERY", "SCANNING", "ANALYZING", "FINALIZING",
        "DNS", "PORT_SCAN", "TLS_ANALYSIS", "HEADER_ANALYSIS",
    }:
        if stage not in done:
            done.append(stage)
            scan.completed_stages = json.dumps(done)
    db.commit()
    payload = {
        "scan_id": scan.id,
        "stage": stage,
        "progress": scan.progress,
        "findings_count": scan.findings_count or 0,
        "nodes_count": getattr(scan, "nodes_count", 0) or 0,
        "requests_used": getattr(scan, "requests_used", 0) or 0,
        "request_budget": getattr(scan, "request_budget", 0) or 0,
    }
    _emit("web_scan_progress", payload)
    _emit("web_scan_stage", payload)
    _emit("webscan_progress", payload)
    _emit("webscan_stage_started", payload)


def _cancelled(scan_id: int) -> bool:
    flag = _cancel_flags.get(scan_id)
    return bool(flag and flag.is_set())


def _log(db, scan, surface_log, event_type: str, message: str, **kwargs):
    persist_scan_event(
        db,
        scan,
        event_type=event_type,
        message=message,
        emit=_emit,
        **kwargs,
    )


def _run_scan_job(scan_id: int, *, create_alerts: bool = True, resume: bool = False) -> None:
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
        requests_used = int(getattr(scan, "requests_used", 0) or 0)
        budget = int(getattr(scan, "request_budget", 0) or WEBSCAN_REQUEST_BUDGET)

        # Authenticated scanning: decrypt target credentials if configured
        target_auth_type = getattr(target, "auth_type", "none") or "none"
        target_auth_config = None
        if target_auth_type != "none":
            from ..db import decrypt_secret, VaultConfigurationError
            enc = getattr(target, "auth_config_encrypted", "") or ""
            if enc:
                try:
                    dec = decrypt_secret(enc)
                    target_auth_config = json.loads(dec) if dec else None
                except VaultConfigurationError as exc:
                    logger.error("Authenticated scan aborted: %s", exc)
                    log("SCAN", f"Vault configuration error: {exc}", severity="ERROR")
                    _update(db, scan, stage="FAILED", progress=scan.progress, error_message=str(exc), finished_at=utcnow())
                    return
                except Exception as exc:
                    logger.warning("Failed to decrypt credentials: %s", exc)
                    target_auth_config = None

        scan_cfg = {}
        try:
            scan_cfg = json.loads(scan.configuration_json or "{}")
        except Exception:
            scan_cfg = {}
        scan_policy = scan_cfg.get("policy")
        scan_alert_threshold = scan_cfg.get("alert_threshold")
        scan_attack_strength = scan_cfg.get("attack_strength")

        def bump_requests(n: int = 1) -> bool:
            nonlocal requests_used
            requests_used += n
            scan.requests_used = requests_used
            return requests_used <= budget

        def log(event_type: str, message: str, **kw):
            _log(db, scan, None, event_type, message, **kw)

        surface = AttackSurfaceBuilder(db, scan, emit=_emit, log_event=log)

        _update(db, scan, stage="VALIDATING", progress=5)
        log("SCAN", "Scan started" + (" (resumed)" if resume else ""))
        if _cancelled(scan_id):
            return

        url_meta = validate_scan_url(target.url, allow_private=allow_private)
        scan_url = url_meta["url"]
        hostname = url_meta["hostname"] or urlparse(scan_url).hostname or ""

        _update(db, scan, stage="DISCOVERING", progress=15)
        root = surface.ensure_root(scan_url, hostname=hostname, ips=url_meta.get("resolved_ips"))
        surface.ensure_url_path(root, scan_url)

        if profile.get("tls"):
            _update(db, scan, stage="TLS_ANALYSIS", progress=18)
            if bump_requests():
                tls_findings, _tls = check_tls(scan_url, allow_private=allow_private)
                raw_findings.extend(tls_findings)

        if bump_requests():
            http_findings, discovery = discover_http(scan_url, allow_private=allow_private)
            raw_findings.extend(http_findings)
            if profile.get("technology"):
                tech = fingerprint(discovery.get("headers") or {}, discovery.get("body_sample") or "")
                scan.technologies_count = len(tech)
                if tech:
                    root.technology = ", ".join(
                        (t.get("technology") or t.get("name") or "") for t in tech[:5]
                    )
                    db.commit()
        if profile.get("passive") and bump_requests(3):
            raw_findings.extend(check_common_files(scan_url, allow_private=allow_private))

        # Sitemap extraction → grow Website Map immediately
        if profile.get("sitemap") and requests_used < budget:
            _update(db, scan, stage="SITEMAP", progress=25)
            sm = extract_sitemap_urls(scan_url, allow_private=allow_private)
            bump_requests(max(1, len(sm.get("sitemap_urls") or []) + 1))
            if sm.get("sitemap_urls"):
                for sm_url in sm["sitemap_urls"]:
                    surface.ensure_url_path(root, sm_url, http_status=200)
                log("SITEMAP", f"Parsed {len(sm['sitemap_urls'])} sitemap document(s)")
            else:
                log("SITEMAP", "No sitemap discovered", severity="WARN")
            for entry in sm.get("urls") or []:
                if not bump_requests(0):
                    break
                u = entry.get("url") or ""
                if not u:
                    continue
                surface.ensure_url_path(root, u)
                urls_discovered += 1
            scan.discovered_urls = max(int(scan.discovered_urls or 0), urls_discovered)
            log("SITEMAP", f"Extracted {sm.get('count', 0)} URL(s) from sitemap")
            if sm.get("count"):
                raw_findings.append({
                    "title": f"Sitemap URLs discovered ({sm['count']})",
                    "description": "URLs extracted from sitemap.xml / robots.txt Sitemap directives.",
                    "severity": "INFO",
                    "confidence": 90,
                    "category": "sitemap",
                    "affected_url": (sm.get("sitemap_urls") or [scan_url])[0],
                    "source_engine": "sitemap",
                    "evidence": f"sitemaps={len(sm.get('sitemap_urls') or [])}; urls={sm.get('count')}",
                    "recommendation": "Review publicly listed paths for unintended exposure.",
                })

        if _cancelled(scan_id):
            _update(db, scan, stage="CANCELLED", progress=scan.progress, finished_at=utcnow())
            return

        if profile.get("crawl") and requests_used < budget:
            _update(db, scan, stage="CRAWLING", progress=35)
            crawl_result = crawl(scan_url, allow_private=allow_private, max_depth=profile.get("max_depth", 3))
            urls_discovered = crawl_result.get("count") or 0
            scan.discovered_urls = urls_discovered
            for u in crawl_result.get("urls") or []:
                if not bump_requests(0):
                    break
                node = surface.ensure_url_path(root, u.get("url") or "", http_status=u.get("status"))
                if u.get("status") == 200 and any(
                    x in (u.get("url") or "") for x in ("/admin", "/.env", "/.git", "/debug")
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
                        "_node_id": node.id,
                    })

        if profile.get("api_discovery") and requests_used < budget:
            _update(db, scan, stage="API_DISCOVERY", progress=45)
            apis = discover_api_paths(scan_url, allow_private=allow_private)
            bump_requests(len(apis) or 1)
            for a in apis:
                node = surface.ensure_url_path(root, a["url"], http_status=a.get("status"))
                surface.ensure_api(node, a["url"], method=a.get("method") or "GET")
                log("API", f"API path {a['url']} ({a.get('status')})")

        if _cancelled(scan_id):
            _update(db, scan, stage="CANCELLED", progress=scan.progress, finished_at=utcnow())
            return

        _update(db, scan, stage="SCANNING", progress=55)
        warnings = []
        # Production safety: skip ZAP active / nmap when production and not LAB profile
        allow_aggressive = (scan.safety_mode == "lab") or profile.get("lab") or not WEBSCAN_PRODUCTION_SAFETY_MODE

        if profile.get("nuclei"):
            n_findings, err = run_nuclei(scan_url)
            if err:
                warnings.append(err)
                log("NUCLEI", f"Unavailable: {err}", severity="WARN")
            else:
                raw_findings.extend(n_findings)
                log("NUCLEI", f"Nuclei returned {len(n_findings)} finding(s)")
        if profile.get("nmap") and allow_aggressive:
            _update(db, scan, stage="PORT_SCAN", progress=60)
            nmap_findings, ports, err = run_nmap(hostname)
            if err:
                warnings.append(err)
                log("NMAP", f"Unavailable: {err}", severity="WARN")
            else:
                raw_findings.extend(nmap_findings)
                scan.discovered_ports = len(ports)
                for p in ports:
                    surface.ensure_port(
                        root,
                        port=int(p.get("port") or 0),
                        protocol=p.get("protocol") or "tcp",
                        service=p.get("service") or p.get("product") or "",
                        state=p.get("state") or "open",
                    )
        elif profile.get("nmap") and not allow_aggressive:
            warnings.append("Nmap skipped (production safety mode)")
            log("NMAP", "Skipped under production safety mode", severity="WARN")

        if profile.get("zap"):
            log("ZAP", f"Starting scoped passive scan & spider on {scan_url}" + (f" (auth={target_auth_type})" if target_auth_type != "none" else ""), severity="INFO")
            z_findings, z_urls, err = run_zap_passive(
                scan_url,
                max_depth=profile.get("max_depth", 3),
                cancel_check=lambda: _cancelled(scan_id),
                allow_private=allow_private,
                auth_type=target_auth_type,
                auth_config=target_auth_config,
            )
            if err:
                warnings.append(err)
                log("ZAP", f"Notice: {err}", severity="WARN")
            else:
                # Feed ZAP spidered URLs directly into the Website Map attack-surface tree!
                added_nodes = 0
                for u in z_urls:
                    try:
                        surface.ensure_url_path(root, u)
                        added_nodes += 1
                    except Exception:
                        pass
                if added_nodes:
                    urls_discovered += added_nodes
                    scan.discovered_urls = max(int(scan.discovered_urls or 0), urls_discovered)
                    db.commit()

                # Link ZAP findings to attack surface tree nodes
                for f in z_findings:
                    aff_url = f.get("affected_url") or scan_url
                    try:
                        node = surface.ensure_url_path(root, aff_url)
                        f["_node_id"] = node.id
                    except Exception:
                        pass
                raw_findings.extend(z_findings)
                log("ZAP", f"Completed spider ({len(z_urls)} URLs) & passive scan ({len(z_findings)} findings)", severity="INFO")

            # Active Scan if permitted
            if allow_aggressive and not _cancelled(scan_id):
                log("ZAP", f"Initiating rate-limited active scan on {scan_url}" + (f" (policy={scan_policy})" if scan_policy else ""), severity="INFO")
                _update(db, scan, stage="ACTIVE_SCAN", progress=65)
                za_findings, za_err = run_zap_active(
                    scan_url,
                    timeout=min(timeout, 90),
                    cancel_check=lambda: _cancelled(scan_id),
                    allow_private=allow_private,
                    auth_type=target_auth_type,
                    auth_config=target_auth_config,
                    policy=scan_policy,
                    alert_threshold=scan_alert_threshold,
                    attack_strength=scan_attack_strength,
                )
                if za_err:
                    warnings.append(za_err)
                    log("ZAP", f"Active scan note: {za_err}", severity="WARN")
                else:
                    for f in za_findings:
                        aff_url = f.get("affected_url") or scan_url
                        try:
                            node = surface.ensure_url_path(root, aff_url)
                            f["_node_id"] = node.id
                        except Exception:
                            pass
                    raw_findings.extend(za_findings)
                    log("ZAP", f"Active scan completed with {len(za_findings)} finding(s)", severity="INFO")

        if _cancelled(scan_id):
            _update(db, scan, stage="CANCELLED", progress=scan.progress, finished_at=utcnow())
            return

        _update(db, scan, stage="ANALYZING", progress=80)
        if warnings:
            scan.error_message = "; ".join(warnings)[:2000]

        normalized = dedupe_findings(raw_findings, target_url=scan_url)
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
                host=target.name or hostname or "",
                db=db,
            )
            item["risk_score"] = score
            fp = item["fingerprint"]
            affected = item.get("affected_url") or item.get("url") or scan_url
            node = surface.ensure_url_path(surface.ensure_root(scan_url, hostname=hostname), affected)

            if fp in existing:
                row = existing[fp]
                row.last_seen = utcnow()
                row.occurrence_count = int(getattr(row, "occurrence_count", 1) or 1) + 1
                row.scan_id = scan.id
                row.risk_score = score
                row.severity = item["severity"]
                row.node_id = node.id
                counts[item["severity"]] = counts.get(item["severity"], 0) + 1
                surface.attach_finding(node, severity=item["severity"], risk_score=score)
                continue

            row = WebFinding(
                target_id=target.id,
                scan_id=scan.id,
                node_id=node.id,
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
            db.flush()
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
            will_alert = create_alerts and item["severity"] in {"HIGH", "CRITICAL"}
            surface.attach_finding(node, severity=item["severity"], risk_score=score, has_alert=will_alert)
            finding_evt = {
                "scan_id": scan.id,
                "finding_id": row.id,
                "title": row.title,
                "severity": row.severity,
                "risk_score": row.risk_score,
                "url": row.affected_url or row.url,
                "node_id": node.id,
            }
            _emit("web_scan_finding", finding_evt)
            _emit("webscan_finding_discovered", finding_evt)
            log("FINDING", f"{row.severity}: {row.title}", severity=row.severity, finding_id=row.id, node_id=node.id)
            if will_alert:
                alert_payloads.append(item)

        db.flush()
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
        scan.requests_used = requests_used
        if ports:
            scan.discovered_ports = len(ports)
            scan.ports_json = json.dumps(ports)
        if tech:
            scan.technologies_json = json.dumps(tech)
        scan.risk_score = min(
            100,
            counts["CRITICAL"] * 20 + counts["HIGH"] * 12 + counts["MEDIUM"] * 5 + counts["LOW"],
        )
        scan.duration = int(time.time() - started)
        partial = bool(scan.error_message)
        scan.status = "PARTIAL" if partial and scan.findings_count else "COMPLETED"
        scan.current_stage = scan.status
        scan.progress = 100
        scan.finished_at = utcnow()
        target.last_scan = utcnow()
        target.last_status = scan.status
        db.commit()
        done = {
            "scan_id": scan.id,
            "findings_count": scan.findings_count,
            "nodes_count": scan.nodes_count,
            "risk_score": scan.risk_score,
            "status": scan.status,
            "warnings": (scan.error_message or "").split("; ") if scan.error_message else [],
        }
        _emit("web_scan_completed", done)
        _emit("webscan_completed", done)
        log("SCAN", f"Scan {scan.status.lower()} with {scan.findings_count} findings / {scan.nodes_count} nodes")

        # Dispatch webhook notification on scan completion
        try:
            from ..webhook_dispatcher import dispatch_webhook_event
            sev = "CRITICAL" if counts["CRITICAL"] > 0 else "HIGH" if counts["HIGH"] > 0 else "MEDIUM" if counts["MEDIUM"] > 0 else "INFO"
            dispatch_webhook_event(
                event_type="scan.completed",
                severity=sev,
                title=f"DAST Scan Completed: {target.name}",
                description=f"Scan #{scan.id} finished on {target.url} with {scan.findings_count} finding(s) (Risk Score: {scan.risk_score}/100).",
                source=target.url,
                details={
                    "scan_id": scan.id,
                    "target_name": target.name,
                    "target_url": target.url,
                    "critical_count": counts["CRITICAL"],
                    "high_count": counts["HIGH"],
                    "medium_count": counts["MEDIUM"],
                    "low_count": counts["LOW"],
                    "risk_score": scan.risk_score,
                    "duration_seconds": scan.duration,
                },
            )
        except Exception as wh_exc:
            logger.debug("Failed dispatching scan webhook: %s", wh_exc)
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
    scan.interrupted = True
    scan.progress = scan.progress or 0
    target = db.get(WebTarget, scan.target_id)
    if target:
        target.last_status = "FAILED"
        target.last_scan = utcnow()
    db.commit()
    payload = {"scan_id": scan_id, "error": scan.error_message}
    _emit("web_scan_failed", payload)
    _emit("webscan_failed", payload)
    _emit("webscan_error", payload)


def _promote_alerts(db, target: WebTarget, scan: WebScan, items: list[dict]) -> None:
    broadcast_fn = None
    try:
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
        _emit("webscan_alert_created", {
            "scan_id": scan.id,
            "target_id": target.id,
            "title": item.get("title"),
            "severity": item.get("severity"),
            "url": item.get("affected_url"),
        })
    if alerts:
        persist_alerts(db, alerts, broadcast_fn=broadcast_fn)
