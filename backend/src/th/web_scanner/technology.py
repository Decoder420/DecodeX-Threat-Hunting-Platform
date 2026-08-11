"""Lightweight technology fingerprinting from headers/HTML."""

from __future__ import annotations

import re


SIGNATURES = [
    ("WordPress", re.compile(r"wp-content|wordpress", re.I), "html"),
    ("React", re.compile(r"react|data-reactroot|_next/static", re.I), "html"),
    ("Next.js", re.compile(r"_next/static|__NEXT_DATA__", re.I), "html"),
    ("Django", re.compile(r"csrfmiddlewaretoken|django", re.I), "html"),
    ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I), "any"),
    ("PHP", re.compile(r"\.php\b|X-Powered-By:\s*PHP", re.I), "any"),
    ("Express", re.compile(r"X-Powered-By:\s*Express", re.I), "headers"),
    ("nginx", re.compile(r"Server:\s*nginx", re.I), "headers"),
    ("Apache", re.compile(r"Server:\s*Apache", re.I), "headers"),
    ("IIS", re.compile(r"Server:\s*Microsoft-IIS", re.I), "headers"),
    ("Flask", re.compile(r"Werkzeug|Flask", re.I), "any"),
    ("Node.js", re.compile(r"X-Powered-By:\s*Express|node", re.I), "headers"),
]


def fingerprint(headers: dict, body: str = "") -> list[dict]:
    header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    blob_any = header_blob + "\n" + (body or "")
    found: list[dict] = []
    seen = set()
    for name, pattern, where in SIGNATURES:
        hay = header_blob if where == "headers" else (body if where == "html" else blob_any)
        if pattern.search(hay or ""):
            if name in seen:
                continue
            seen.add(name)
            found.append({
                "technology": name,
                "version": "",
                "confidence": 70 if where != "html" else 65,
            })
    # Server header product
    server = ""
    for k, v in (headers or {}).items():
        if k.lower() == "server":
            server = v
            break
    if server and "nginx" in server.lower() and "nginx" not in {x["technology"].lower() for x in found}:
        found.append({"technology": "nginx", "version": "", "confidence": 80})
    return found
