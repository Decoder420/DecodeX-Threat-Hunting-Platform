"""Normalize engine-specific findings into a unified schema."""

from __future__ import annotations

import hashlib
import json
import re


def _norm_url(url: str) -> str:
    return re.sub(r"/+$", "", (url or "").strip().lower())


def fingerprint_finding(item: dict, target_url: str = "") -> str:
    basis = "|".join([
        _norm_url(item.get("affected_url") or item.get("url") or target_url),
        (item.get("category") or "").lower(),
        (item.get("title") or "").strip().lower(),
        (item.get("parameter") or "").lower(),
        (item.get("template_id") or item.get("cve") or "").lower(),
        (item.get("source_engine") or "").lower(),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:40]


def normalize_finding(raw: dict, *, target_url: str = "") -> dict:
    sev = str(raw.get("severity") or "INFO").upper()
    if sev not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        sev = "INFO"
    conf = int(raw.get("confidence") or 70)
    conf = max(0, min(100, conf))
    affected = raw.get("affected_url") or raw.get("url") or target_url or ""
    out = {
        "title": (raw.get("title") or "Untitled finding")[:300],
        "description": (raw.get("description") or "")[:4000],
        "severity": sev,
        "confidence": conf,
        "category": (raw.get("category") or "general")[:80],
        "cwe": str(raw.get("cwe") or "")[:120],
        "owasp": str(raw.get("owasp") or "")[:120],
        "cve": str(raw.get("cve") or "")[:120],
        "cvss": float(raw.get("cvss") or 0) if raw.get("cvss") not in (None, "") else 0.0,
        "affected_url": affected[:1000],
        "method": (raw.get("method") or "")[:16],
        "parameter": (raw.get("parameter") or "")[:200],
        "evidence": (raw.get("evidence") or "")[:4000],
        "recommendation": (raw.get("recommendation") or raw.get("remediation") or "")[:4000],
        "remediation": (raw.get("remediation") or raw.get("recommendation") or "")[:4000],
        "request": (raw.get("request") or "")[:4000],
        "response": (raw.get("response") or "")[:4000],
        "source_engine": (raw.get("source_engine") or "builtin")[:40],
        "template_id": (raw.get("template_id") or "")[:120],
        "url": affected[:1000],
    }
    out["fingerprint"] = raw.get("fingerprint") or fingerprint_finding(out, target_url)
    return out


def explain_risk(severity: str, confidence: int, risk_score: int) -> str:
    return (
        f"Risk {risk_score}/100 from severity={severity}, confidence={confidence}%, "
        f"plus asset/exposure adjustments applied by the platform risk engine."
    )
