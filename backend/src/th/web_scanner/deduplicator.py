"""Deduplicate findings within a scan and against prior findings."""

from __future__ import annotations

from .normalizer import fingerprint_finding, normalize_finding


def dedupe_findings(raw_findings: list[dict], *, target_url: str = "") -> list[dict]:
    seen: dict[str, dict] = {}
    for raw in raw_findings:
        item = normalize_finding(raw, target_url=target_url)
        fp = item["fingerprint"]
        if fp in seen:
            prev = seen[fp]
            prev["occurrence_count"] = int(prev.get("occurrence_count") or 1) + 1
            # Keep higher severity / confidence
            order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if order.get(item["severity"], 0) > order.get(prev["severity"], 0):
                item["occurrence_count"] = prev["occurrence_count"]
                seen[fp] = item
            continue
        item["occurrence_count"] = 1
        seen[fp] = item
    return list(seen.values())
