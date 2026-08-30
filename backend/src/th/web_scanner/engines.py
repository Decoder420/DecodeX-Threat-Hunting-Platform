"""Optional external scanner adapters (Nuclei / Nmap / ZAP). Never use shell=True."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from .config import (
    NMAP_ENABLED,
    NMAP_PATH,
    NUCLEI_ENABLED,
    NUCLEI_PATH,
    WEBSCAN_ALLOW_PRIVATE_TARGETS,
    WEBSCAN_TIMEOUT,
    ZAP_API_KEY,
    ZAP_ENABLED,
    ZAP_URL,
)

logger = logging.getLogger("th.web_scanner.engines")


def _which(path: str) -> str | None:
    """Resolve scanner binary from absolute path or PATH."""
    if not path:
        return None
    raw = str(path).strip().strip('"')
    candidate = Path(raw)
    if candidate.is_file():
        return str(candidate.resolve())
    # Allow path without extension on Windows
    if os.name == "nt" and not candidate.suffix:
        exe = candidate.with_suffix(".exe")
        if exe.is_file():
            return str(exe.resolve())
    found = shutil.which(raw)
    if found:
        return found
    # shutil.which may miss bare names when PATH was updated in another shell
    return shutil.which(raw + ".exe") if os.name == "nt" and not raw.lower().endswith(".exe") else None


def detect_engines() -> dict:
    from .zap_client import zap_client

    nuclei = _which(NUCLEI_PATH) if NUCLEI_ENABLED else None
    nmap = _which(NMAP_PATH) if NMAP_ENABLED else None
    zap_health = zap_client.health_check() if ZAP_ENABLED else {"available": False, "version": "", "capabilities": {}, "addons": []}
    zap_ok = zap_health.get("available", False)
    zap_version = zap_health.get("version", "")

    return {
        "builtin": {"installed": True, "version": "2.0", "status": "READY", "path": "builtin"},
        "httpx": {
            "installed": True,
            "version": "builtin",
            "status": "READY",
            "path": "builtin",
            "note": "HTTP discovery uses the built-in engine (httpx-style).",
            "enabled": True,
        },
        "nuclei": {
            "installed": bool(nuclei),
            "version": _version([nuclei, "-version"]) if nuclei else "",
            "status": "READY" if nuclei else "NOT_INSTALLED",
            "path": nuclei or NUCLEI_PATH,
            "enabled": NUCLEI_ENABLED,
        },
        "nmap": {
            "installed": bool(nmap),
            "version": _version([nmap, "-V"]) if nmap else "",
            "status": "READY" if nmap else "NOT_INSTALLED",
            "path": nmap or NMAP_PATH,
            "enabled": NMAP_ENABLED,
        },
        "zap": {
            "installed": zap_ok,
            "version": zap_version,
            "status": "READY" if zap_ok else ("DISABLED" if not ZAP_ENABLED else "NOT_INSTALLED"),
            "path": ZAP_URL,
            "enabled": ZAP_ENABLED,
            "capabilities": zap_health.get("capabilities", {}),
            "addons": zap_health.get("addons", []),
        },
    }



def _version(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        out = (proc.stdout or proc.stderr or "").strip().splitlines()
        line = out[0][:160] if out else ""
        # Strip ANSI color codes from tools like Nuclei.
        return re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
    except Exception:
        return ""


def run_nuclei(url: str, *, timeout: int | None = None) -> tuple[list[dict], str | None]:
    """Run safe Nuclei templates; return findings + error message if skipped."""
    if not NUCLEI_ENABLED:
        return [], "Nuclei disabled by configuration"
    binary = _which(NUCLEI_PATH)
    if not binary:
        return [], "Nuclei binary not found"
    timeout = timeout or min(WEBSCAN_TIMEOUT, 120)
    # Safe-ish tags only — no intrusive exploit templates by default
    cmd = [
        binary,
        "-u", url,
        "-silent",
        "-jsonl",
        "-severity", "info,low,medium,high,critical",
        "-tags", "misconfig,exposure,cve,tech,vuln,panel",
        "-c", "10",
        "-timeout", "8",
    ]
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "Nuclei timed out"
    except Exception as exc:
        return [], f"Nuclei failed: {exc}"

    findings: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Malformed Nuclei JSON line skipped")
            continue
        info = item.get("info") or {}
        severity = str(info.get("severity") or item.get("severity") or "info").upper()
        if severity == "UNKNOWN":
            severity = "INFO"
        findings.append({
            "title": info.get("name") or item.get("template-id") or "Nuclei finding",
            "description": (info.get("description") or "")[:2000],
            "severity": severity if severity in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} else "INFO",
            "confidence": 80,
            "category": "nuclei",
            "cve": ",".join(info.get("classification", {}).get("cve-id") or []) if isinstance(info.get("classification"), dict) else "",
            "cwe": ",".join(info.get("classification", {}).get("cwe-id") or []) if isinstance(info.get("classification"), dict) else "",
            "evidence": json.dumps({
                "matched-at": item.get("matched-at"),
                "template-id": item.get("template-id"),
                "extractor": item.get("extractor-name"),
            })[:2000],
            "recommendation": "Review Nuclei template references and apply vendor guidance.",
            "affected_url": item.get("matched-at") or url,
            "source_engine": "nuclei",
            "template_id": item.get("template-id") or "",
            "method": "GET",
        })
    return findings, None


def run_nmap(hostname: str, *, timeout: int | None = None) -> tuple[list[dict], list[dict], str | None]:
    """Safe top-ports SYN/connect scan. Returns (findings, ports, error)."""
    if not NMAP_ENABLED:
        return [], [], "Nmap disabled by configuration"
    binary = _which(NMAP_PATH)
    if not binary:
        return [], [], "Nmap binary not found"
    # Controlled flags only — no user-supplied args
    cmd = [
        binary,
        "-Pn",
        "-T3",
        "--top-ports", "20",
        "-sV",
        "--version-light",
        "-oX", "-",
        hostname,
    ]
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout or min(WEBSCAN_TIMEOUT, 90),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], [], "Nmap timed out"
    except Exception as exc:
        return [], [], f"Nmap failed: {exc}"

    xml = proc.stdout or ""
    ports: list[dict] = []
    # Minimal XML scrape without requiring lxml
    for block in xml.split("<port "):
        if "portid=" not in block:
            continue
        try:
            portid = block.split('portid="')[1].split('"')[0]
            proto = block.split('protocol="')[1].split('"')[0] if 'protocol="' in block else "tcp"
            state = "open" if 'state="open"' in block else "closed"
            service = ""
            product = ""
            if "<service " in block:
                svc = block.split("<service ")[1]
                if 'name="' in svc:
                    service = svc.split('name="')[1].split('"')[0]
                if 'product="' in svc:
                    product = svc.split('product="')[1].split('"')[0]
            if state != "open":
                continue
            ports.append({
                "port": int(portid),
                "protocol": proto,
                "state": state,
                "service": service,
                "product": product,
                "version": "",
            })
        except Exception:
            continue

    findings = []
    for p in ports:
        if p["port"] in {21, 23, 445, 3389} or (p["port"] == 22 and True):
            findings.append({
                "title": f"Open service {p['service'] or 'unknown'} on port {p['port']}/{p['protocol']}",
                "description": "Nmap discovered an open port/service on the authorized target host.",
                "severity": "INFO" if p["port"] in {80, 443} else "LOW",
                "confidence": 75,
                "category": "ports",
                "evidence": json.dumps(p),
                "recommendation": "Ensure only required services are exposed; restrict by firewall.",
                "affected_url": f"{hostname}:{p['port']}",
                "source_engine": "nmap",
            })
    return findings, ports, None


def run_zap_passive(
    url: str,
    *,
    timeout: int = 60,
    cancel_check: callable = None,
    progress_callback: callable = None,
    allow_private: bool = WEBSCAN_ALLOW_PRIVATE_TARGETS,
    auth_type: str = "none",
    auth_config: dict | None = None,
) -> tuple[list[dict], list[str], str | None]:
    """ZAP spider + passive inspection via ZAP REST API with scope isolation. Non-destructive."""
    from .zap_client import zap_client

    if not ZAP_ENABLED:
        return [], [], "ZAP disabled by configuration"

    health = zap_client.health_check()
    if not health.get("available"):
        return [], [], f"ZAP daemon unreachable: {health.get('error')}"

    # 1. Create scoped context for target
    parsed = urlparse(url)
    context_name = f"ctx_{parsed.hostname or 'target'}_{int(time.time())}"
    zap_client.create_target_context(context_name, url)

    # Configure authentication if target has credentials
    if auth_type and auth_type != "none" and auth_config:
        zap_client.configure_auth_credentials(context_name, auth_type, auth_config, url)

    # 2. Traditional Spider
    spider_urls, err = zap_client.run_spider(
        url,
        context_name=context_name,
        max_children=50,
        timeout=timeout,
        cancel_check=cancel_check,
        progress_callback=progress_callback,
        allow_private=allow_private,
    )
    if err and "cancelled" in err.lower():
        return [], spider_urls, err

    # 3. AJAX Spider (if supported)
    if health.get("capabilities", {}).get("ajax_spider"):
        ajax_urls, _ajax_err = zap_client.run_ajax_spider(
            url,
            context_name=context_name,
            timeout=min(timeout, 45),
            cancel_check=cancel_check,
            allow_private=allow_private,
        )
        for u in ajax_urls:
            if u not in spider_urls:
                spider_urls.append(u)

    # 4. Drain passive scanner queue
    zap_client.wait_for_passive_scan(timeout=15, cancel_check=cancel_check)

    # 5. Fetch normalized findings
    findings, alert_err = zap_client.fetch_normalized_alerts(url)
    return findings, spider_urls, alert_err


def run_zap_active(
    url: str,
    *,
    timeout: int = 120,
    delay_ms: int = 100,
    cancel_check: callable = None,
    progress_callback: callable = None,
    allow_private: bool = WEBSCAN_ALLOW_PRIVATE_TARGETS,
    auth_type: str = "none",
    auth_config: dict | None = None,
    policy: str | None = None,
    alert_threshold: str | None = None,
    attack_strength: str | None = None,
) -> tuple[list[dict], str | None]:
    """ZAP active scan against authorized target with rate limiting, policies, and scope guardrails."""
    from .zap_client import zap_client

    if not ZAP_ENABLED:
        return [], "ZAP disabled by configuration"

    health = zap_client.health_check()
    if not health.get("available"):
        return [], f"ZAP daemon unreachable: {health.get('error')}"

    parsed = urlparse(url)
    context_name = f"ascan_{parsed.hostname or 'target'}_{int(time.time())}"
    context_id = zap_client.create_target_context(context_name, url)

    # Configure authentication if target has credentials
    if auth_type and auth_type != "none" and auth_config:
        zap_client.configure_auth_credentials(context_name, auth_type, auth_config, url)

    # Run active scan with policy and threshold settings
    _status, err = zap_client.run_active_scan(
        url,
        context_id=context_id,
        delay_ms=delay_ms,
        timeout=timeout,
        cancel_check=cancel_check,
        progress_callback=progress_callback,
        allow_private=allow_private,
        policy=policy,
        alert_threshold=alert_threshold,
        attack_strength=attack_strength,
    )
    if err and "cancelled" in err.lower():
        return [], err

    # Fetch alerts discovered during active scan
    findings, alert_err = zap_client.fetch_normalized_alerts(url)
    return findings, alert_err or err


