"""Bounded same-host crawler for attack-surface discovery."""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse

import requests

from .config import WEBSCAN_MAX_CRAWL_DEPTH, WEBSCAN_MAX_URLS, WEBSCAN_REQUEST_TIMEOUT
from .validators import SSRFError, validate_scan_url

HREF_RE = re.compile(r"""href=["']([^"'#]+)["']""", re.I)


DANGEROUS_PATH_PATTERNS = re.compile(
    r"/(?:log[-_]?out|sign[-_]?out|delete|destroy|terminate|cancel|remove|account[-_]?close)(?:/|\?|$)",
    re.I,
)
STATIC_BINARY_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".tgz", ".iso", ".bin", ".exe", ".dmg", ".pkg", ".apk",
    ".mp4", ".mp3", ".avi", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2"
}


def crawl(start_url: str, *, allow_private: bool = False, max_urls: int | None = None,
          max_depth: int | None = None) -> dict:
    max_urls = max_urls or WEBSCAN_MAX_URLS
    max_depth = WEBSCAN_MAX_CRAWL_DEPTH if max_depth is None else max_depth
    start = validate_scan_url(start_url, allow_private=allow_private)
    host = (start["hostname"] or "").lower()
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start["url"], 0)])
    urls: list[dict] = []

    while queue and len(seen) < max_urls:
        url, depth = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = requests.get(
                url,
                timeout=WEBSCAN_REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "ThreatHuntingPlatform-WebScanner/2.0 (+security-audit)"},
            )
            body = resp.text[:200_000] if resp.headers.get("content-type", "").startswith("text") else ""
            urls.append({
                "url": url,
                "status": resp.status_code,
                "content_type": resp.headers.get("Content-Type", ""),
                "depth": depth,
            })
        except Exception as exc:
            urls.append({"url": url, "status": 0, "error": str(exc), "depth": depth})
            continue

        if depth >= max_depth:
            continue
        for match in HREF_RE.findall(body or ""):
            absolute = urljoin(url, match)
            try:
                meta = validate_scan_url(absolute, allow_private=allow_private)
            except SSRFError:
                continue
            if (meta["hostname"] or "").lower() != host:
                continue
            
            # Real-world safety: Skip destructive endpoints (logout/delete) and bulky binary assets
            candidate_path = urlparse(meta["url"]).path.lower()
            if DANGEROUS_PATH_PATTERNS.search(candidate_path):
                continue
            if any(candidate_path.endswith(ext) for ext in STATIC_BINARY_EXTENSIONS):
                continue

            if meta["url"] not in seen and len(seen) + len(queue) < max_urls:
                queue.append((meta["url"], depth + 1))

    return {"urls": urls, "count": len(urls), "host": host}

