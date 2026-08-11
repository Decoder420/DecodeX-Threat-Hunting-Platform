"""Web-finding risk scoring (0-100) with transparent factors."""

from __future__ import annotations

from ..risk import compute_risk_score

SEVERITY_WEIGHT = {
    "INFO": 10,
    "LOW": 28,
    "MEDIUM": 52,
    "HIGH": 78,
    "CRITICAL": 95,
}


def score_web_finding(
    *,
    severity: str,
    confidence: int = 70,
    cvss: float = 0.0,
    host: str = "",
    db=None,
    internet_exposed: bool = True,
) -> tuple[int, dict]:
    sev = (severity or "INFO").upper()
    base = compute_risk_score(
        severity=sev,
        confidence=confidence,
        host=host,
        db=db,
    )
    factors = {
        "severity_weight": SEVERITY_WEIGHT.get(sev, 40),
        "confidence": confidence,
        "cvss": cvss,
        "internet_exposed": internet_exposed,
        "base_engine_score": base,
    }
    score = base
    if cvss and cvss > 0:
        score = int(round(score * 0.7 + min(100, cvss * 10) * 0.3))
        factors["cvss_blend"] = True
    if internet_exposed:
        score = min(100, score + 3)
    score = max(0, min(100, score))
    factors["final"] = score
    return score, factors
