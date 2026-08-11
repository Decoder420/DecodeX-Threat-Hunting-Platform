"""Deterministic risk scoring (0-100) for alerts / findings."""

from __future__ import annotations

from .db import Asset

SEVERITY_BASE = {
    "info": 10,
    "informational": 10,
    "low": 30,
    "medium": 55,
    "high": 75,
    "critical": 92,
}

CRITICALITY_BONUS = {
    "low": 0,
    "medium": 5,
    "high": 12,
    "critical": 18,
}

RISK_THRESHOLDS = [
    (90, "CRITICAL"),
    (75, "HIGH"),
    (50, "MEDIUM"),
    (25, "LOW"),
    (0, "INFORMATIONAL"),
]


def risk_category(score: int) -> str:
    score = max(0, min(100, int(score)))
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFORMATIONAL"


def _asset_criticality(db, host: str) -> str:
    if not host or db is None:
        return "medium"
    asset = db.query(Asset).filter(Asset.hostname == host).first()
    if asset and asset.criticality:
        return str(asset.criticality).lower()
    # Heuristic defaults for demo hosts
    upper = host.upper()
    if upper.startswith("DC-") or "DOMAIN" in upper:
        return "critical"
    if upper.startswith(("WEB-", "DB-", "FW-")):
        return "high"
    return "medium"


def compute_risk_score(
    *,
    severity: str,
    confidence: int = 70,
    ioc_matched: bool = False,
    correlation_count: int = 0,
    host: str = "",
    db=None,
    technique_id: str = "",
) -> int:
    """Configurable, deterministic risk score in 0..100."""
    base = SEVERITY_BASE.get((severity or "").lower(), 40)
    conf = max(0, min(100, int(confidence or 0)))
    # Blend severity with confidence (never fully override severity).
    score = int(base * 0.7 + conf * 0.3)

    if ioc_matched:
        score += 12

    crit = _asset_criticality(db, host)
    score += CRITICALITY_BONUS.get(crit, 5)

    # Related alerts amplify risk modestly.
    score += min(15, max(0, int(correlation_count)) * 3)

    # High-impact ATT&CK techniques
    tid = (technique_id or "").upper()
    if tid.startswith("T1059") or tid.startswith("T1003") or tid.startswith("T1021"):
        score += 5

    return max(0, min(100, score))
