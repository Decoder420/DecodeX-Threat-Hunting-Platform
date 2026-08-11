"""HTTP discovery, TLS, headers, and passive security checks."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .config import WEBSCAN_MAX_RESPONSE_BYTES, WEBSCAN_REQUEST_TIMEOUT
from .validators import validate_redirect_url, validate_scan_url

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def _finding(**kwargs) -> dict:
    kwargs.setdefault("source_engine", "builtin")
    kwargs.setdefault("confidence", 80)
    return kwargs


def check_tls(url: str, *, allow_private: bool = False) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    meta = validate_scan_url(url, allow_private=allow_private)
    tls_info: dict = {"https": meta["scheme"] == "https"}
    if meta["scheme"] != "https":
        findings.append(_finding(
            title="Target is not HTTPS",
            description="Scanning over plain HTTP; TLS checks skipped.",
            severity="MEDIUM",
            confidence=95,
            category="tls",
            owasp="A02:2021-Cryptographic Failures",
            cwe="CWE-319",
            evidence=url,
            recommendation="Enforce HTTPS and redirect HTTP to HTTPS.",
            affected_url=url,
        ))
        return findings, tls_info

    host, port = meta["hostname"], meta["port"]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=WEBSCAN_REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                not_after = cert.get("notAfter")
                tls_info.update({"version": version, "not_after": not_after})
                findings.append(_finding(
                    title="TLS certificate valid",
                    description=f"Handshake succeeded using {version}.",
                    severity="INFO",
                    confidence=95,
                    category="tls",
                    evidence=f"notAfter={not_after}; version={version}",
                    recommendation="Continue monitoring certificate expiration.",
                    affected_url=url,
                ))
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days = (expiry - datetime.now(timezone.utc)).days
                    if days < 30:
                        findings.append(_finding(
                            title="TLS certificate expiring soon",
                            description=f"Certificate expires in {days} days.",
                            severity="HIGH" if days < 7 else "MEDIUM",
                            confidence=95,
                            category="tls",
                            cwe="CWE-295",
                            evidence=not_after,
                            recommendation="Renew the certificate before expiry.",
                            affected_url=url,
                        ))
    except Exception as exc:
        findings.append(_finding(
            title="TLS validation failed",
            description=str(exc),
            severity="HIGH",
            confidence=80,
            category="tls",
            cwe="CWE-295",
            evidence=str(exc),
            recommendation="Fix certificate chain / hostname mismatch.",
            affected_url=url,
        ))
    return findings, tls_info


def discover_http(url: str, *, allow_private: bool = False) -> tuple[list[dict], dict]:
    """Fetch URL with careful redirects; return findings + discovery metadata."""
    findings: list[dict] = []
    meta = validate_scan_url(url, allow_private=allow_private)
    current = meta["url"]
    allowed_host = meta["hostname"]
    history = []
    final_resp = None
    session = requests.Session()
    session.max_redirects = 0

    for _ in range(5):
        try:
            resp = session.get(
                current,
                timeout=WEBSCAN_REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "TH-Platform-WebScanner/2.0"},
                stream=True,
            )
        except Exception as exc:
            findings.append(_finding(
                title="HTTP request failed",
                description=str(exc),
                severity="MEDIUM",
                confidence=70,
                category="http",
                evidence=str(exc),
                recommendation="Ensure the authorized target is reachable.",
                affected_url=current,
            ))
            return findings, {"url": current, "error": str(exc), "redirects": history}

        # Bound body size
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) >= WEBSCAN_MAX_RESPONSE_BYTES:
                break
        resp.close()

        history.append({"url": current, "status": resp.status_code})
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            nxt = validate_redirect_url(
                current, loc, allow_private=allow_private, allowed_host=allowed_host
            )
            if not nxt:
                findings.append(_finding(
                    title="Redirect outside authorized host blocked",
                    description="Scanner refused to follow an out-of-scope or unsafe redirect.",
                    severity="INFO",
                    confidence=90,
                    category="http",
                    evidence=loc,
                    recommendation="Keep redirects within the authorized hostname.",
                    affected_url=current,
                ))
                final_resp = resp
                body_text = content.decode("utf-8", errors="replace")
                break
            current = nxt
            continue
        final_resp = resp
        body_text = content.decode("utf-8", errors="replace")
        break
    else:
        body_text = ""

    if final_resp is None:
        return findings, {"url": current, "redirects": history}

    headers = {k.lower(): v for k, v in final_resp.headers.items()}
    discovery = {
        "url": current,
        "status_code": final_resp.status_code,
        "headers": dict(final_resp.headers),
        "content_type": headers.get("content-type", ""),
        "server": headers.get("server", ""),
        "redirects": history,
        "body_sample": body_text[:4000],
        "cookies": [],
    }

    for header in SECURITY_HEADERS:
        if header.lower() not in headers:
            sev = "HIGH" if header in (
                "Content-Security-Policy",
                "Strict-Transport-Security",
            ) else "MEDIUM"
            findings.append(_finding(
                title=f"Missing {header}",
                description=f"Response did not include the {header} security header.",
                severity=sev,
                confidence=90,
                category="headers",
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-693",
                evidence=f"status={final_resp.status_code}",
                recommendation=f"Add a strong {header} header.",
                remediation=f"Configure the reverse proxy or application to emit {header}.",
                affected_url=current,
                method="GET",
            ))
        else:
            findings.append(_finding(
                title=f"{header} present",
                description="Header value observed.",
                severity="INFO",
                confidence=90,
                category="headers",
                evidence=str(headers[header.lower()])[:400],
                recommendation="Review header value for hardening opportunities.",
                affected_url=current,
                method="GET",
            ))

    if headers.get("server"):
        findings.append(_finding(
            title="Server header exposes technology",
            description="Server banner may aid reconnaissance.",
            severity="LOW",
            confidence=85,
            category="disclosure",
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-200",
            evidence=headers["server"],
            recommendation="Remove or genericize the Server header.",
            affected_url=current,
        ))

    # Cookies
    for cookie in final_resp.cookies:
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        rest = getattr(cookie, "_rest", {}) or {}
        if "HttpOnly" not in rest and "httponly" not in {k.lower() for k in rest}:
            missing.append("HttpOnly")
        discovery["cookies"].append({"name": cookie.name, "secure": bool(cookie.secure)})
        if missing:
            findings.append(_finding(
                title=f"Cookie missing flags: {', '.join(missing)}",
                description=f"Cookie '{cookie.name}' lacks recommended security flags.",
                severity="MEDIUM",
                confidence=80,
                category="cookies",
                cwe="CWE-614",
                evidence=cookie.name,
                recommendation="Set Secure, HttpOnly, and SameSite on session cookies.",
                affected_url=current,
            ))

    # CORS reflection (passive observation only)
    acao = headers.get("access-control-allow-origin")
    if acao == "*":
        findings.append(_finding(
            title="CORS allows any origin",
            description="Access-Control-Allow-Origin is set to wildcard '*'.",
            severity="MEDIUM",
            confidence=85,
            category="cors",
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-942",
            evidence=acao,
            recommendation="Restrict CORS to trusted origins.",
            affected_url=current,
        ))

    return findings, discovery


def check_common_files(base_url: str, *, allow_private: bool = False) -> list[dict]:
    findings: list[dict] = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    root = f"{parsed.scheme}://{parsed.netloc}"
    paths = [
        ("/robots.txt", "INFO", "discovery"),
        ("/security.txt", "INFO", "discovery"),
        ("/.well-known/security.txt", "INFO", "discovery"),
        ("/sitemap.xml", "INFO", "discovery"),
        ("/.env", "HIGH", "exposure"),
        ("/.git/HEAD", "HIGH", "exposure"),
        ("/server-status", "MEDIUM", "exposure"),
        ("/admin", "LOW", "discovery"),
    ]
    for path, sev, cat in paths:
        url = root + path
        try:
            validate_scan_url(url, allow_private=allow_private)
            resp = requests.get(
                url,
                timeout=WEBSCAN_REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "TH-Platform-WebScanner/2.0"},
            )
        except Exception:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            if cat == "exposure":
                findings.append(_finding(
                    title=f"Sensitive path accessible: {path}",
                    description="A potentially sensitive path returned HTTP 200.",
                    severity=sev,
                    confidence=75,
                    category=cat,
                    owasp="A01:2021-Broken Access Control",
                    cwe="CWE-538",
                    evidence=f"status=200 length={len(resp.content)}",
                    recommendation=f"Restrict access to {path} or remove it from production.",
                    affected_url=url,
                    method="GET",
                ))
            else:
                findings.append(_finding(
                    title=f"{path} present",
                    description="Public discovery document found.",
                    severity=sev,
                    confidence=90,
                    category=cat,
                    evidence=url,
                    recommendation="Review disclosed paths for sensitive information.",
                    affected_url=url,
                    method="GET",
                ))
    return findings
