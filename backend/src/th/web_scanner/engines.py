"""Optional external scanner adapters (Nuclei / Nmap / ZAP). Never use shell=True."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests

from .config import (
    NMAP_ENABLED,
    NMAP_PATH,
    NUCLEI_ENABLED,
    NUCLEI_PATH,
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
    nuclei = _which(NUCLEI_PATH) if NUCLEI_ENABLED else None
    nmap = _which(NMAP_PATH) if NMAP_ENABLED else None
    zap_ok = False
    zap_version = ""
    if ZAP_ENABLED:
        try:
            r = requests.get(
                f"{ZAP_URL}/JSON/core/view/version/",
                params={"apikey": ZAP_API_KEY} if ZAP_API_KEY else {},
                timeout=3,
            )
            if r.ok:
                zap_ok = True
                zap_version = str((r.json() or {}).get("version") or "")
        except Exception:
            zap_ok = False
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


def run_zap_passive(url: str, *, timeout: int = 60) -> tuple[list[dict], str | None]:
    """Optional ZAP spider + passive alerts via API (no arbitrary active scan by default)."""
    if not ZAP_ENABLED:
        return [], "ZAP disabled by configuration"
    try:
        params = {"apikey": ZAP_API_KEY} if ZAP_API_KEY else {}
        # Access URL (adds to site tree)
        requests.get(
            f"{ZAP_URL}/JSON/core/action/accessUrl/",
            params={**params, "url": url, "followRedirects": "true"},
            timeout=15,
        )
        # Spider
        spider = requests.get(
            f"{ZAP_URL}/JSON/spider/action/scan/",
            params={**params, "url": url, "maxChildren": "20", "recurse": "true"},
            timeout=15,
        )
        if spider.ok:
            scan_id = (spider.json() or {}).get("scan")
            # Wait briefly
            import time
            deadline = time.time() + min(timeout, 45)
            while time.time() < deadline and scan_id is not None:
                st = requests.get(
                    f"{ZAP_URL}/JSON/spider/view/status/",
                    params={**params, "scanId": scan_id},
                    timeout=5,
                )
                if st.ok and str((st.json() or {}).get("status")) == "100":
                    break
                time.sleep(2)
        alerts = requests.get(
            f"{ZAP_URL}/JSON/alert/view/alerts/",
            params={**params, "baseurl": url, "start": "0", "count": "100"},
            timeout=15,
        )
        if not alerts.ok:
            return [], f"ZAP alerts API error: {alerts.status_code}"
        findings = []
        for a in (alerts.json() or {}).get("alerts") or []:
            risk = str(a.get("risk") or "Informational").upper()
            sev_map = {
                "INFORMATIONAL": "INFO",
                "INFO": "INFO",
                "LOW": "LOW",
                "MEDIUM": "MEDIUM",
                "HIGH": "HIGH",
                "CRITICAL": "CRITICAL",
            }
            findings.append({
                "title": a.get("alert") or a.get("name") or "ZAP finding",
                "description": (a.get("description") or "")[:2000],
                "severity": sev_map.get(risk, "INFO"),
                "confidence": 70,
                "category": "zap",
                "cwe": str(a.get("cweid") or ""),
                "evidence": (a.get("evidence") or a.get("other") or "")[:2000],
                "recommendation": (a.get("solution") or "Review ZAP guidance.")[:2000],
                "affected_url": a.get("url") or url,
                "source_engine": "zap",
                "method": a.get("method") or "GET",
                "parameter": a.get("param") or "",
            })
        return findings, None
    except Exception as exc:
        return [], f"ZAP unavailable: {exc}"
