"""Lightweight API path discovery and OpenAPI/Swagger specification parser.

Supports:
- Probing common OpenAPI/Swagger/GraphQL endpoints
- Parsing OpenAPI 2.x, 3.x, and Swagger definitions (JSON/YAML)
- Extracting endpoints, HTTP methods, parameters, summary, and tags
- SSRF-safe fetching of remote API specifications
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import yaml

from .config import WEBSCAN_REQUEST_TIMEOUT
from .validators import SSRFError, validate_scan_url

logger = logging.getLogger("th.api_discovery")

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


def parse_openapi_spec(
    spec_content: str | dict,
    base_url: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Optional[str]]:
    """Parse an OpenAPI (2.0/3.0/3.1) or Swagger spec from JSON/YAML or dict.

    Returns:
        (endpoints_list, spec_metadata, error_message)
    """
    spec_data: dict = {}
    if isinstance(spec_content, dict):
        spec_data = spec_content
    elif isinstance(spec_content, str):
        content_clean = spec_content.strip()
        if not content_clean:
            return [], {}, "Empty specification content."
        try:
            if content_clean.startswith("{"):
                spec_data = json.loads(content_clean)
            else:
                spec_data = yaml.safe_load(content_clean)
        except Exception as exc:
            return [], {}, f"Failed to parse OpenAPI JSON/YAML: {exc}"

    if not isinstance(spec_data, dict):
        return [], {}, "Parsed specification is not a valid JSON/YAML object."

    version = spec_data.get("openapi") or spec_data.get("swagger") or "unknown"
    info = spec_data.get("info") or {}
    meta = {
        "title": info.get("title", "API Specification"),
        "version": str(version),
        "api_version": info.get("version", ""),
        "description": info.get("description", ""),
    }

    # Determine base server URL
    servers = spec_data.get("servers") or []
    server_base = ""
    if servers and isinstance(servers, list) and isinstance(servers[0], dict):
        server_base = servers[0].get("url", "")
    elif spec_data.get("host"):
        schemes = spec_data.get("schemes") or ["https"]
        scheme = schemes[0] if schemes else "https"
        base_path = spec_data.get("basePath") or ""
        server_base = f"{scheme}://{spec_data['host']}{base_path}"

    if not server_base and base_url:
        server_base = base_url.rstrip("/")

    paths = spec_data.get("paths") or {}
    endpoints: List[Dict[str, Any]] = []

    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method_norm = str(method).upper()
            if method_norm not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
                continue
            if not isinstance(operation, dict):
                operation = {}

            full_url = urljoin(server_base.rstrip("/") + "/", path_str.lstrip("/")) if server_base else path_str
            params = []
            for p in operation.get("parameters") or []:
                if isinstance(p, dict):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", "query"),
                        "required": bool(p.get("required", False)),
                        "type": p.get("schema", {}).get("type", p.get("type", "string")),
                    })

            endpoints.append({
                "path": path_str,
                "method": method_norm,
                "url": full_url,
                "summary": operation.get("summary") or operation.get("operationId") or "",
                "description": operation.get("description") or "",
                "tags": operation.get("tags") or [],
                "parameters": params,
                "operation_id": operation.get("operationId") or "",
            })

    return endpoints, meta, None
