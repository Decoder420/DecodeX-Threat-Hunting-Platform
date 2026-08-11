"""Environment-driven web scanner configuration."""

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
WEBSCAN_MAX_URLS = max(10, _int("WEBSCAN_MAX_URLS", 50))
WEBSCAN_MAX_CRAWL_DEPTH = max(0, _int("WEBSCAN_MAX_CRAWL_DEPTH", 2))
WEBSCAN_MAX_RESPONSE_BYTES = max(1024, _int("WEBSCAN_MAX_RESPONSE_BYTES", 512_000))
WEBSCAN_ALLOW_PRIVATE_TARGETS = _bool("WEBSCAN_ALLOW_PRIVATE_TARGETS", False)

NUCLEI_ENABLED = _bool("NUCLEI_ENABLED", True)
NUCLEI_PATH = os.environ.get("NUCLEI_PATH", "nuclei")

NMAP_ENABLED = _bool("NMAP_ENABLED", True)
NMAP_PATH = os.environ.get("NMAP_PATH", "nmap")

ZAP_ENABLED = _bool("ZAP_ENABLED", False)
ZAP_URL = os.environ.get("ZAP_URL", "http://127.0.0.1:8080").rstrip("/")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

SCAN_PROFILES = {
    "QUICK": {
        "http_discovery": True,
        "headers": True,
        "tls": True,
        "technology": True,
        "passive": True,
        "crawl": False,
        "nuclei": False,
        "nmap": False,
        "zap": False,
    },
    "STANDARD": {
        "http_discovery": True,
        "headers": True,
        "tls": True,
        "technology": True,
        "passive": True,
        "crawl": True,
        "nuclei": True,
        "nmap": False,
        "zap": False,
    },
    "DEEP": {
        "http_discovery": True,
        "headers": True,
        "tls": True,
        "technology": True,
        "passive": True,
        "crawl": True,
        "nuclei": True,
        "nmap": True,
        "zap": True,
    },
}
