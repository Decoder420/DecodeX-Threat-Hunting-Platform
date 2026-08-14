"""Extract URLs from sitemap.xml, sitemap indexes, and robots.txt Sitemap directives."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

import requests

from .config import WEBSCAN_MAX_URLS, WEBSCAN_MAX_RESPONSE_BYTES, WEBSCAN_REQUEST_TIMEOUT
from .validators import SSRFError, validate_scan_url

logger = logging.getLogger("th.web_scanner.sitemap")

LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
SITEMAP_DIR_RE = re.compile(r"(?im)^\s*Sitemap:\s*(\S+)\s*$")


def _fetch(url: str, *, allow_private: bool) -> tuple[str | None, int | None]:
    try:
        validate_scan_url(url, allow_private=allow_private)
        resp = requests.get(
            url,
            timeout=WEBSCAN_REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "ThreatHuntingPlatform-WebScan/2.0"},
            stream=True,
        )
        # Bound body size
        chunks = []
        total = 0
        for chunk in resp.iter_content(8192):
            if not chunk:
                break
            total += len(chunk)
            if total > WEBSCAN_MAX_RESPONSE_BYTES:
                break
            chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        return text, resp.status_code
    except Exception as exc:
        logger.debug("sitemap fetch failed for %s: %s", url, exc)
        return None, None


def _parse_locs(xml_text: str) -> list[str]:
    urls: list[str] = []
    # Prefer regex for malformed XML tolerance
    for m in LOC_RE.finditer(xml_text or ""):
        loc = (m.group(1) or "").strip()
        if loc:
            urls.append(loc)
    if urls:
        return urls
    # Fallback XML parse
    try:
        root = ET.fromstring(xml_text)
        for el in root.iter():
            tag = el.tag.split("}")[-1].lower() if el.tag else ""
            if tag == "loc" and el.text:
                urls.append(el.text.strip())
    except Exception:
        pass
    return urls


def _is_sitemap_index(xml_text: str) -> bool:
    low = (xml_text or "").lower()
    return "sitemapindex" in low or "<sitemap>" in low


def extract_sitemap_urls(
    base_url: str,
    *,
    allow_private: bool = False,
    max_urls: int | None = None,
) -> dict:
    """
    Discover and parse sitemaps for the target.

    Returns:
      {
        "sitemap_urls": [...source sitemap documents...],
        "urls": [{"url": "...", "source": "sitemap|robots"}, ...],
        "count": N,
        "errors": [...]
      }
    """
    limit = max_urls or WEBSCAN_MAX_URLS
    result = {"sitemap_urls": [], "urls": [], "count": 0, "errors": []}
    seen: set[str] = set()
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    root = f"{parsed.scheme}://{parsed.netloc}"

    candidates: list[str] = [
        urljoin(root + "/", "sitemap.xml"),
        urljoin(root + "/", "sitemap_index.xml"),
        urljoin(root + "/", "sitemap-index.xml"),
    ]

    # robots.txt Sitemap: lines
    robots_text, robots_status = _fetch(urljoin(root + "/", "robots.txt"), allow_private=allow_private)
    if robots_text and robots_status and robots_status < 400:
        for m in SITEMAP_DIR_RE.finditer(robots_text):
            candidates.append(m.group(1).strip())

    # Deduplicate candidates while preserving order
    ordered: list[str] = []
    for c in candidates:
        if c not in ordered:
            ordered.append(c)

    queue = list(ordered)
    visited_sitemaps: set[str] = set()

    while queue and len(seen) < limit:
        sm_url = queue.pop(0)
        if sm_url in visited_sitemaps:
            continue
        visited_sitemaps.add(sm_url)
        try:
            validate_scan_url(sm_url, allow_private=allow_private)
        except SSRFError as exc:
            result["errors"].append(str(exc))
            continue

        text, status = _fetch(sm_url, allow_private=allow_private)
        if not text or not status or status >= 400:
            continue

        result["sitemap_urls"].append(sm_url)
        locs = _parse_locs(text)
        if _is_sitemap_index(text):
            for loc in locs:
                if loc not in visited_sitemaps and loc not in queue:
                    queue.append(loc)
            continue

        for loc in locs:
            if loc in seen:
                continue
            try:
                validate_scan_url(loc, allow_private=allow_private)
            except SSRFError:
                continue
            # Same-host only (authorization scope)
            host = (urlparse(loc).hostname or "").lower()
            if host and host != (parsed.hostname or "").lower():
                continue
            seen.add(loc)
            result["urls"].append({"url": loc, "source": "sitemap", "status": None})
            if len(seen) >= limit:
                break

    result["count"] = len(result["urls"])
    return result
