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
            headers = {"X-ZAP-API-Key": ZAP_API_KEY} if ZAP_API_KEY else {}
            params = {"apikey": ZAP_API_KEY} if ZAP_API_KEY else {}
            r = requests.get(
                f"{ZAP_URL}/JSON/core/view/version/",
                headers=headers,
                params=params,
                timeout=3,
            )
            if r.ok:
                zap_ok = True
                zap_version = str((r.json() or {}).get("version") or "")
            else:
                logger.warning("ZAP version probe returned HTTP %s: %s", r.status_code, r.text)
        except Exception as exc:
            logger.debug("ZAP probe failed: %s", exc)
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


def run_zap_passive(url: str, *, timeout: int = 60) -> tuple[list[dict], list[str], str | None]:
    """ZAP spider + passive inspection via ZAP REST API. Non-destructive."""
    if not ZAP_ENABLED:
        return [], [], "ZAP disabled by configuration"
    try:
        headers = {"X-ZAP-API-Key": ZAP_API_KEY} if ZAP_API_KEY else {}
        params = {"apikey": ZAP_API_KEY} if ZAP_API_KEY else {}

        # 1. Access URL (seeds ZAP site tree)
        r_access = requests.get(
            f"{ZAP_URL}/JSON/core/action/accessUrl/",
            headers=headers,
            params={**params, "url": url, "followRedirects": "true"},
            timeout=15,
        )
        if not r_access.ok and r_access.status_code == 403:
            return [], [], "ZAP API Access Denied (check ZAP api.key and network whitelist config)"

        # 2. Spider site & extract site tree URLs
        spider_urls: list[str] = []
        spider = requests.get(
            f"{ZAP_URL}/JSON/spider/action/scan/",
            headers=headers,
            params={**params, "url": url, "maxChildren": "50", "recurse": "true"},
            timeout=15,
        )
        if spider.ok:
            scan_id = (spider.json() or {}).get("scan")
            import time
            deadline = time.time() + min(timeout, 45)
            while time.time() < deadline and scan_id is not None:
                st = requests.get(
                    f"{ZAP_URL}/JSON/spider/view/status/",
                    headers=headers,
                    params={**params, "scanId": scan_id},
                    timeout=5,
                )
                if st.ok and str((st.json() or {}).get("status")) == "100":
                    break
                time.sleep(1.5)

            if scan_id is not None:
                try:
                    res_sp = requests.get(
                        f"{ZAP_URL}/JSON/spider/view/results/",
                        headers=headers,
                        params={**params, "scanId": scan_id},
                        timeout=10,
                    )
                    if res_sp.ok:
                        for item in (res_sp.json() or {}).get("results") or []:
                            if isinstance(item, str) and item.startswith("http"):
                                spider_urls.append(item)
                except Exception:
                    pass

        # Also query all discovered URLs from ZAP core view
        try:
          res_core = requests.get(
              f"{ZAP_URL}/JSON/core/view/urls/",
              headers=headers,
              params={**params, "baseurl": url},
              timeout=10,
          )
          if res_core.ok:
              for u in (res_core.json() or {}).get("urls") or []:
                  if isinstance(u, str) and u.startswith("http") and u not in spider_urls:
                      spider_urls.append(u)
        except Exception:
          pass

        # 3. Fetch Passive Scan Alerts with fallback for trailing slash variations
        alerts_data = []
        for base in [url, url.rstrip("/"), f"{url.rstrip('/')}/"]:
            alerts_resp = requests.get(
                f"{ZAP_URL}/JSON/alert/view/alerts/",
                headers=headers,
                params={**params, "baseurl": base, "start": "0", "count": "100"},
                timeout=15,
            )
            if alerts_resp.ok:
                items = (alerts_resp.json() or {}).get("alerts") or []
                if items:
                    alerts_data = items
                    break

        if not alerts_data:
            # Query session alerts and filter by hostname
            alerts_all = requests.get(
                f"{ZAP_URL}/JSON/alert/view/alerts/",
                headers=headers,
                params={**params, "start": "0", "count": "50"},
                timeout=10,
            )
            if alerts_all.ok:
                parsed_target = urlparse(url)
                target_host = (parsed_target.netloc or parsed_target.hostname or "").lower()
                all_items = (alerts_all.json() or {}).get("alerts") or []
                alerts_data = [a for a in all_items if target_host in (a.get("url") or "").lower()]

        findings = []
        sev_map = {
            "INFORMATIONAL": "INFO",
            "INFO": "INFO",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        for a in alerts_data:
            risk = str(a.get("risk") or "Informational").upper()
            findings.append({
                "title": a.get("alert") or a.get("name") or "ZAP finding",
                "description": (a.get("description") or "")[:2000],
                "severity": sev_map.get(risk, "INFO"),
                "confidence": 75,
                "category": "zap",
                "cwe": str(a.get("cweid") or ""),
                "cve": "",
                "evidence": (a.get("evidence") or a.get("other") or "")[:2000],
                "recommendation": (a.get("solution") or "Review ZAP guidance.")[:2000],
                "affected_url": a.get("url") or url,
                "source_engine": "zap",
                "method": a.get("method") or "GET",
                "parameter": a.get("param") or "",
            })
        return findings, spider_urls, None
    except Exception as exc:
        logger.debug("ZAP passive execution failed: %s", exc)
        return [], [], f"ZAP unavailable: {exc}"


