"""URL normalization and SSRF protections for web scanning."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse, urlunparse
import logging

try:
    import dns.resolver  # type: ignore
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger("th.web_scanner.validators")


class SSRFError(ValueError):
    """Raised when a URL/host fails SSRF checks."""


ALLOWED_SCHEMES = {"http", "https"}


def normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        raise SSRFError("URL is required.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"Scheme '{scheme}' is not allowed. Use http or https.")
    if not parsed.hostname:
        raise SSRFError("URL must include a hostname.")
    # Drop fragments; keep path/query.
    cleaned = parsed._replace(scheme=scheme, fragment="")
    return urlunparse(cleaned)


def _is_blocked_ip(ip: ipaddress._BaseAddress, *, allow_private: bool) -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.is_reserved:
        return True
    # Cloud metadata / common SSRF sinks
    if ip.version == 4 and str(ip) in {"169.254.169.254", "169.254.170.2"}:
        return True
    if not allow_private and ip.is_private:
        return True
    return False


def resolve_and_validate_host(hostname: str, *, allow_private: bool = False) -> list[str]:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        raise SSRFError("Hostname is required.")
    if host in {"localhost", "metadata", "metadata.google.internal"}:
        raise SSRFError(f"Hostname '{host}' is blocked.")

    # Literal IP in hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if _is_blocked_ip(ip, allow_private=allow_private):
            raise SSRFError(f"IP address '{host}' is not allowed.")
        return [str(ip)]

    # DNS resolution with clean timeout restoration
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(3.0)
        # socket.getaddrinfo(host, port, family, type) using positional args for cross-version compatibility
        infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for '{host}': {exc}") from exc
    except socket.error as exc:
        raise SSRFError(f"Network error resolving '{host}': {exc}") from exc
    finally:
        socket.setdefaulttimeout(old_timeout)

    if not infos:
        raise SSRFError(f"No addresses resolved for '{host}'.")

    resolved: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_blocked_ip(ip, allow_private=allow_private):
            raise SSRFError(
                f"Resolved address '{addr}' for '{host}' is not allowed (SSRF protection)."
            )
        if addr not in resolved:
            resolved.append(addr)

    if not resolved:
        raise SSRFError(f"No usable addresses resolved for '{host}'.")
    return resolved



def validate_scan_url(url: str, *, allow_private: bool = False) -> dict:
    """Normalize URL, resolve DNS, and return metadata for scanning."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    resolved = resolve_and_validate_host(parsed.hostname or "", allow_private=allow_private)
    return {
        "url": normalized,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "resolved_ips": resolved,
        "path": parsed.path or "/",
    }


def validate_redirect_url(
    base_url: str,
    location: str,
    *,
    allow_private: bool = False,
    allowed_host: str | None = None,
) -> str | None:
    """Validate redirect Location; return absolute URL or None to stop following."""
    if not location:
        return None
    absolute = urljoin(base_url, location)
    try:
        meta = validate_scan_url(absolute, allow_private=allow_private)
    except SSRFError:
        return None
    if allowed_host and (meta["hostname"] or "").lower() != allowed_host.lower():
        # Out of authorization host scope — do not follow.
        return None
    return meta["url"]
