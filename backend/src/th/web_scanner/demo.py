"""Synthetic DEMO profile data — clearly labeled, never presented as live scanner output."""

from __future__ import annotations


def demo_surface(base_url: str, hostname: str) -> dict:
    """Return synthetic nodes/findings for UI demos when WEBSCAN_DEMO_MODE / DEMO profile."""
    base = (base_url or f"https://{hostname}").rstrip("/")
    return {
        "mode": "DEMO",
        "warning": "Synthetic DEMO data — not a live scan of the target.",
        "urls": [
            {"url": f"{base}/", "status": 200},
            {"url": f"{base}/login", "status": 200},
            {"url": f"{base}/dashboard", "status": 200},
            {"url": f"{base}/api/v1/users", "status": 200},
            {"url": f"{base}/api/v1/admin", "status": 200},
            {"url": f"{base}/swagger.json", "status": 200},
            {"url": f"{base}/debug", "status": 200},
        ],
        "ports": [
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
        ],
        "apis": [
            {"url": f"{base}/api/v1/users", "method": "GET"},
            {"url": f"{base}/api/v1/users", "method": "POST"},
            {"url": f"{base}/api/v1/admin", "method": "GET"},
            {"url": f"{base}/swagger.json", "method": "GET"},
        ],
        "findings": [
            {
                "title": "[DEMO] Missing Content-Security-Policy",
                "description": "Synthetic demo finding for UI rehearsal.",
                "severity": "MEDIUM",
                "confidence": 80,
                "category": "headers",
                "affected_url": f"{base}/",
                "source_engine": "demo",
                "cwe": "CWE-693",
                "owasp": "A05:2021 Security Misconfiguration",
                "recommendation": "Configure a restrictive CSP header.",
            },
            {
                "title": "[DEMO] Exposed admin endpoint",
                "description": "Synthetic high-severity demo finding.",
                "severity": "HIGH",
                "confidence": 75,
                "category": "exposure",
                "affected_url": f"{base}/api/v1/admin",
                "source_engine": "demo",
                "cwe": "CWE-200",
                "owasp": "A01:2021 Broken Access Control",
                "recommendation": "Restrict admin APIs and require strong authentication.",
            },
            {
                "title": "[DEMO] Debug endpoint exposed",
                "description": "Synthetic critical demo finding.",
                "severity": "CRITICAL",
                "confidence": 90,
                "category": "exposure",
                "affected_url": f"{base}/debug",
                "source_engine": "demo",
                "cwe": "CWE-489",
                "owasp": "A05:2021 Security Misconfiguration",
                "recommendation": "Disable debug endpoints in non-lab environments.",
            },
        ],
        "technologies": [
            {"technology": "nginx", "version": "", "confidence": 70},
            {"technology": "React", "version": "", "confidence": 60},
        ],
    }
