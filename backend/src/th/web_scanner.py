"""Authorized, non-destructive web security checks only."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .db import WebFinding, WebScan, utcnow
from .risk import compute_risk_score

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _parse_host(url: str) -> tuple[str, int, bool]:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    scheme = (parsed.scheme or "https").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return host, port, scheme == "https"


def check_tls(url: str) -> list[dict]:
    findings = []
    host, port, is_https = _parse_host(url)
    if not is_https or not host:
        findings.append({
            "title": "Target is not HTTPS",
            "description": "Scanning over plain HTTP; TLS checks skipped.",
            "severity": "MEDIUM",
            "confidence": 90,
            "category": "tls",
            "evidence": url,
            "recommendation": "Enforce HTTPS and redirect HTTP to HTTPS.",
        })
        return findings
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                not_after = cert.get("notAfter")
                findings.append({
                    "title": "TLS certificate valid",
                    "description": f"Handshake succeeded using {version}.",
                    "severity": "INFO",
                    "confidence": 95,
                    "category": "tls",
                    "evidence": f"notAfter={not_after}; version={version}",
                    "recommendation": "Continue monitoring certificate expiration.",
                })
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (expiry - datetime.now(timezone.utc)).days
                    if days < 30:
                        findings.append({
                            "title": "TLS certificate expiring soon",
                            "description": f"Certificate expires in {days} days.",
                            "severity": "HIGH" if days < 7 else "MEDIUM",
                            "confidence": 95,
                            "category": "tls",
                            "evidence": not_after,
                            "recommendation": "Renew the certificate before expiry.",
                        })
    except Exception as exc:
        findings.append({
            "title": "TLS validation failed",
            "description": str(exc),
            "severity": "HIGH",
            "confidence": 80,
            "category": "tls",
            "evidence": str(exc),
            "recommendation": "Fix certificate chain / hostname mismatch.",
        })
    return findings


def check_http_headers(url: str) -> list[dict]:
    findings = []
    try:
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "TH-Platform-SafeScanner/1.0"},
        )
    except Exception as exc:
        return [{
            "title": "HTTP request failed",
            "description": str(exc),
            "severity": "MEDIUM",
            "confidence": 70,
            "category": "http",
            "evidence": str(exc),
            "recommendation": "Ensure the target is reachable from the scanner.",
        }]

    headers = {k.lower(): v for k, v in resp.headers.items()}
    for header in SECURITY_HEADERS:
        if header.lower() not in headers:
            sev = "HIGH" if header in ("Content-Security-Policy", "Strict-Transport-Security") else "MEDIUM"
            findings.append({
                "title": f"Missing {header}",
                "description": f"Response did not include the {header} security header.",
                "severity": sev,
                "confidence": 90,
                "category": "headers",
                "evidence": f"status={resp.status_code}",
                "recommendation": f"Add a strong {header} header.",
            })
        else:
            findings.append({
                "title": f"{header} present",
                "description": f"Header value observed.",
                "severity": "INFO",
                "confidence": 90,
                "category": "headers",
                "evidence": headers[header.lower()][:300],
                "recommendation": "Review header value for hardening opportunities.",
            })

    server = headers.get("server")
    if server:
        findings.append({
            "title": "Server header exposes technology",
            "description": "Server banner may aid reconnaissance.",
            "severity": "LOW",
            "confidence": 85,
            "category": "disclosure",
            "evidence": server,
            "recommendation": "Remove or genericize the Server header.",
        })

    # Cookie flags
    for cookie in resp.cookies:
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "has_nonstandard_attr", lambda *_: False)("HttpOnly"):
            # http.cookiejar uses rest dict
            rest = getattr(cookie, "_rest", {}) or {}
            if "HttpOnly" not in rest and "httponly" not in {k.lower() for k in rest}:
                missing.append("HttpOnly")
        if missing:
            findings.append({
                "title": f"Cookie missing flags: {', '.join(missing)}",
                "description": f"Cookie '{cookie.name}' lacks recommended security flags.",
                "severity": "MEDIUM",
                "confidence": 80,
                "category": "cookies",
                "evidence": cookie.name,
                "recommendation": "Set Secure, HttpOnly, and SameSite on session cookies.",
            })

    # robots.txt presence (safe GET)
    try:
        parsed = urlparse(resp.url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        robots = requests.get(robots_url, timeout=5, headers={"User-Agent": "TH-Platform-SafeScanner/1.0"})
        if robots.status_code == 200:
            findings.append({
                "title": "robots.txt present",
                "description": "Public robots.txt discovered (informational).",
                "severity": "INFO",
                "confidence": 90,
                "category": "discovery",
                "evidence": robots_url,
                "recommendation": "Ensure robots.txt does not disclose sensitive paths.",
            })
    except Exception:
        pass

    return findings


def run_safe_scan(db, target, created_by: str = "") -> WebScan:
    scan = WebScan(
        target_id=target.id,
        status="RUNNING",
        started_at=utcnow(),
        created_by=created_by or "",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    findings_data = []
    findings_data.extend(check_tls(target.url))
    findings_data.extend(check_http_headers(target.url))

    high = 0
    for item in findings_data:
        sev = (item.get("severity") or "INFO").upper()
        if sev in ("HIGH", "CRITICAL"):
            high += 1
        finding = WebFinding(
            target_id=target.id,
            scan_id=scan.id,
            title=item["title"],
            description=item.get("description", ""),
            severity=sev,
            confidence=int(item.get("confidence") or 70),
            category=item.get("category", ""),
            evidence=item.get("evidence", ""),
            recommendation=item.get("recommendation", ""),
            url=target.url,
            risk_score=compute_risk_score(
                severity=sev,
                confidence=int(item.get("confidence") or 70),
                host=target.name or "",
            ),
        )
        db.add(finding)

    scan.status = "COMPLETED"
    scan.finished_at = utcnow()
    scan.findings_count = len(findings_data)
    scan.high_count = high
    target.last_scan = utcnow()
    target.last_status = "COMPLETED"
    db.commit()
    db.refresh(scan)
    return scan
