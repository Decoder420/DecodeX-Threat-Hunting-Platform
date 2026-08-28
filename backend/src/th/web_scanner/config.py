"""Environment-driven web scanner configuration and scan profiles."""

from __future__ import annotations

import os


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


WEBSCAN_ENABLED = _bool("WEBSCAN_ENABLED", True)
WEBSCAN_MAX_CONCURRENT = max(1, _int("WEBSCAN_MAX_CONCURRENT", 2))
WEBSCAN_TIMEOUT = max(30, _int("WEBSCAN_TIMEOUT", 300))
WEBSCAN_REQUEST_TIMEOUT = max(3, _int("WEBSCAN_REQUEST_TIMEOUT", 10))
WEBSCAN_MAX_URLS = max(10, _int("WEBSCAN_MAX_URLS", 200))
WEBSCAN_MAX_CRAWL_DEPTH = max(0, _int("WEBSCAN_MAX_CRAWL_DEPTH", 3))
WEBSCAN_MAX_RESPONSE_BYTES = max(1024, _int("WEBSCAN_MAX_RESPONSE_BYTES", 512_000))
WEBSCAN_ALLOW_PRIVATE_TARGETS = _bool("WEBSCAN_ALLOW_PRIVATE_TARGETS", False)
WEBSCAN_REQUEST_BUDGET = max(50, _int("WEBSCAN_REQUEST_BUDGET", 10_000))
WEBSCAN_PRODUCTION_SAFETY_MODE = _bool("WEBSCAN_PRODUCTION_SAFETY_MODE", True)
WEBSCAN_LAB_MODE = _bool("WEBSCAN_LAB_MODE", False)
WEBSCAN_DEMO_MODE = _bool("WEBSCAN_DEMO_MODE", False)

NUCLEI_ENABLED = _bool("NUCLEI_ENABLED", True)
NUCLEI_PATH = os.environ.get("NUCLEI_PATH", "nuclei")

NMAP_ENABLED = _bool("NMAP_ENABLED", True)
NMAP_PATH = os.environ.get("NMAP_PATH", "nmap")

ZAP_ENABLED = _bool("ZAP_ENABLED", False)
ZAP_URL = os.environ.get("ZAP_URL", "http://127.0.0.1:8080").rstrip("/")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

# Shared capability flags — sitemap extraction is on for every live profile.
_BASE = {
    "http_discovery": True,
    "headers": True,
    "tls": True,
    "technology": True,
    "passive": True,
    "sitemap": True,
    "crawl": True,
    "nuclei": True,
    "nmap": False,
    "zap": False,
    "api_discovery": True,
    "demo": False,
}

SCAN_PROFILES = {
    "QUICK": {
        **_BASE,
        "crawl": True,
        "nuclei": False,
        "nmap": False,
        "zap": False,
        "api_discovery": True,
    },
    "STANDARD": {
        **_BASE,
        "crawl": True,
        "nuclei": True,
        "zap": True,
        "api_discovery": True,
    },

    "DEEP": {
        **_BASE,
        "crawl": True,
        "nuclei": True,
        "nmap": True,
        "zap": True,
        "api_discovery": True,
    },
    "PASSIVE": {
        **_BASE,
        "crawl": False,
        "nuclei": False,
        "nmap": False,
        "zap": False,
        "api_discovery": False,
        "sitemap": True,
        "passive": True,
        "tls": True,
        "headers": True,
    },
    "API": {
        **_BASE,
        "crawl": True,
        "nuclei": True,
        "api_discovery": True,
        "sitemap": True,
        "nmap": False,
        "zap": False,
    },
    "AUTHENTICATED": {
        **_BASE,
        "crawl": True,
        "nuclei": True,
        "api_discovery": True,
        "sitemap": True,
        "authenticated": True,
    },
    "LAB": {
        **_BASE,
        "crawl": True,
        "nuclei": True,
        "nmap": True,
        "zap": True,
        "api_discovery": True,
        "sitemap": True,
        "lab": True,
    },
    "DEMO": {
        **_BASE,
        "demo": True,
        "sitemap": False,
        "crawl": False,
        "nuclei": False,
        "nmap": False,
        "zap": False,
        "tls": False,
        "passive": False,
        "http_discovery": False,
        "api_discovery": False,
    },
}

SEVERITY_RANK = {
    "": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def max_severity(a: str, b: str) -> str:
    aa = (a or "").upper()
    bb = (b or "").upper()
    return aa if SEVERITY_RANK.get(aa, 0) >= SEVERITY_RANK.get(bb, 0) else bb
