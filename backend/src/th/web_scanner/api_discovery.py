"""Lightweight API path discovery (OpenAPI/Swagger/GraphQL common locations)."""

from __future__ import annotations

from urllib.parse import urljoin

import requests

from .config import WEBSCAN_REQUEST_TIMEOUT
from .validators import SSRFError, validate_scan_url

COMMON_API_PATHS = (
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/swagger/",
    "/graphql",
    "/api/v1",
    "/api/v2",
    "/.well-known/openid-configuration",
)


def discover_api_paths(base_url: str, *, allow_private: bool = False) -> list[dict]:
    """Probe common API documentation endpoints. Bounded and SSRF-validated."""
    found: list[dict] = []
    try:
        meta = validate_scan_url(base_url, allow_private=allow_private)
    except SSRFError:
        return found
    root = meta["url"].rstrip("/") + "/"
    for path in COMMON_API_PATHS:
        url = urljoin(root, path.lstrip("/"))
        try:
            validate_scan_url(url, allow_private=allow_private)
            resp = requests.get(
                url,
                timeout=WEBSCAN_REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "ThreatHuntingPlatform-WebScan/2"},
            )
            if resp.status_code < 400:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                found.append({
                    "url": url,
                    "status": resp.status_code,
                    "content_type": ctype,
                    "method": "GET",
                })
        except Exception:
            continue
    return found
