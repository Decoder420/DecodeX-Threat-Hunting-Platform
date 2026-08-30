"""
Premium multi-page Security Incident Report PDF generator.

Produces a confidential SOC-style PDF aligned to the platform incident
report structure (cover → executive summary → timeline → technical →
attack analysis → response → root cause → lessons → evidence/approval).
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .db import utcnow

LOGO_PATH = Path(__file__).resolve().parent / "assets" / "decodex_transparent.png"

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Brand palette — deep navy SOC, not generic purple/cream AI themes
NAVY = colors.HexColor("#0B1F33")
NAVY_MID = colors.HexColor("#123B5C")
ACCENT = colors.HexColor("#1F6F8B")
ACCENT_SOFT = colors.HexColor("#E8F2F6")
INK = colors.HexColor("#1A2332")
MUTED = colors.HexColor("#5B6B7C")
LINE = colors.HexColor("#D5DEE7")
WHITE = colors.white
CRIT = colors.HexColor("#B42318")
HIGH = colors.HexColor("#B54708")
MED = colors.HexColor("#A15C07")
LOW = colors.HexColor("#175CD3")
OK = colors.HexColor("#067647")
TEMPLATE_VERSION = "IR-TEMPLATE-2026.2"


def _esc(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _fmt_dt(value: datetime | None, *, with_time: bool = True) -> str:
    if not value:
        return "—"
    if with_time:
        return value.strftime("%d %B %Y %H:%M UTC")
    return value.strftime("%d %B %Y")


def _severity_color(severity: str) -> colors.Color:
    s = (severity or "").upper()
    if s in {"CRITICAL", "CRIT"}:
        return CRIT
    if s == "HIGH":
        return HIGH
    if s == "MEDIUM":
        return MED
    if s == "LOW":
        return LOW
    return MUTED


def _normalize_status(status: str) -> str:
    s = (status or "Open").strip()
    mapping = {
        "OPEN": "Under Investigation",
        "IN PROGRESS": "Under Investigation",
        "INVESTIGATING": "Under Investigation",
        "MONITORING": "Monitoring",
        "CLOSED": "Closed",
        "RESOLVED": "Closed",
        "FALSE POSITIVE": "Closed",
    }
    return mapping.get(s.upper(), s.title() if s else "Under Investigation")


def _incident_id(alert_id: int, when: datetime | None) -> str:
    year = (when or utcnow()).year
    return f"IR-{year}-{int(alert_id):03d}"


def _category_from_alert(alert) -> str:
    tactic = (getattr(alert, "tactic", None) or "").strip()
    title = (getattr(alert, "title", None) or getattr(alert, "description", "") or "").lower()
    if "phish" in title:
        return "Phishing"
    if "malware" in title or "ransom" in title:
        return "Malware"
    if "credential" in title or "password" in title:
        return "Account Compromise"
    if "web" in (getattr(alert, "source_type", "") or "").lower():
        return "Web Application Security"
    return tactic or "Security Alert"


def _impact_from_severity(severity: str) -> str:
    s = (severity or "").upper()
    if s in {"CRITICAL", "HIGH"}:
        return "High"
    if s == "MEDIUM":
        return "Medium"
    return "Low"


class SectionBanner(Flowable):
    """Horizontal section header bar."""

    def __init__(self, title: str, width: float):
        super().__init__()
        self.title = title
        self.box_width = width
        self.box_height = 22

    def wrap(self, availWidth, availHeight):
        return self.box_width, self.box_height + 6

    def draw(self):
        self.canv.setFillColor(NAVY)
        self.canv.roundRect(0, 3, self.box_width, self.box_height, 3, fill=1, stroke=0)
        self.canv.setFillColor(ACCENT)
        self.canv.rect(0, 3, 4, self.box_height, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont("Helvetica-Bold", 11)
        self.canv.drawString(14, 10, self.title)


class SeverityPill(Flowable):
    def __init__(self, severity: str):
        super().__init__()
        self.severity = (severity or "INFO").upper()
        self.width = 92
        self.height = 18

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        c = _severity_color(self.severity)
        self.canv.setFillColor(c)
        self.canv.roundRect(0, 0, self.width, self.height, 9, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont("Helvetica-Bold", 9)
        self.canv.drawCentredString(self.width / 2, 5, self.severity)


def _styles():
    base = getSampleStyleSheet()
    styles = {
        "cover_kicker": ParagraphStyle(
            "cover_kicker",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            textColor=ACCENT,
            alignment=TA_CENTER,
            spaceAfter=6,
            letterSpacing=1.2,
        ),
        "cover_title": ParagraphStyle(
            "cover_title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=26,
            leading=30,
            textColor=NAVY,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceAfter=18,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=NAVY,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=NAVY_MID,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=INK,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=INK,
            leftIndent=12,
            spaceAfter=3,
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=MUTED,
            alignment=TA_LEFT,
        ),
        "table_cell": ParagraphStyle(
            "table_cell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=INK,
        ),
        "table_header": ParagraphStyle(
            "table_header",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=WHITE,
        ),
        "small_center": ParagraphStyle(
            "small_center",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
        "sign": ParagraphStyle(
            "sign",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=INK,
            spaceAfter=4,
        ),
    }
    return styles


def _table(data: list[list], col_widths: list[float], styles) -> Table:
    """Build a branded data table; first row is header."""
    rendered = []
    for r_idx, row in enumerate(data):
        out = []
        for cell in row:
            if isinstance(cell, Paragraph):
                out.append(cell)
            else:
                style = styles["table_header"] if r_idx == 0 else styles["table_cell"]
                out.append(Paragraph(_esc(cell), style))
        rendered.append(out)

    t = Table(rendered, colWidths=col_widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("BACKGROUND", (0, 1), (-1, -1), WHITE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ACCENT_SOFT]),
                ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return t


def _kv_table(rows: list[tuple[str, str]], width: float, styles) -> Table:
    data = [
        [Paragraph("<b>Field</b>", styles["table_header"]), Paragraph("<b>Details</b>", styles["table_header"])]
    ]
    for k, v in rows:
        data.append(
            [
                Paragraph(_esc(k), styles["table_cell"]),
                Paragraph(_esc(v), styles["table_cell"]),
            ]
        )
    t = Table(data, colWidths=[width * 0.32, width * 0.68])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (0, -1), ACCENT_SOFT),
                ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


def _page_footer(canvas, doc, incident_id: str):
    canvas.saveState()
    page_w, page_h = A4
    # Top confidential ribbon
    canvas.setFillColor(NAVY)
    canvas.rect(0, page_h - 16, page_w, 16, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, page_h - 18, page_w, 2, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawString(18 * mm, page_h - 11, "CONFIDENTIAL • INTERNAL SECURITY DOCUMENT")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(page_w - 18 * mm, page_h - 11, "DecodeX Security Technologies")

    # Footer
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.6)
    canvas.line(18 * mm, 14 * mm, page_w - 18 * mm, 14 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 9 * mm, f"{incident_id}  ·  {TEMPLATE_VERSION}")
    canvas.drawCentredString(page_w / 2, 9 * mm, "Security Incident Report")
    canvas.drawRightString(page_w - 18 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _draw_full_cover(canvas, ctx: dict):
    """Full-bleed navy cover — unmistakable premium template."""
    page_w, page_h = A4
    incident_id = ctx["incident_id"]
    canvas.saveState()

    # Background
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, page_w, page_h, fill=1, stroke=0)

    # Left accent rail
    canvas.setFillColor(ACCENT)
    canvas.rect(0, 0, 8 * mm, page_h, fill=1, stroke=0)

    # Geometric corner accents
    canvas.setFillColor(colors.HexColor("#163A56"))
    canvas.rect(page_w - 55 * mm, page_h - 55 * mm, 55 * mm, 55 * mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    path = canvas.beginPath()
    path.moveTo(page_w, page_h - 28 * mm)
    path.lineTo(page_w, page_h)
    path.lineTo(page_w - 28 * mm, page_h)
    path.close()
    canvas.drawPath(path, fill=1, stroke=0)

    # Brand / kicker with transparent logo at top
    if LOGO_PATH.exists():
        canvas.drawImage(
            str(LOGO_PATH),
            22 * mm,
            page_h - 38 * mm,
            width=18 * mm,
            height=15 * mm,
            preserveAspectRatio=True,
            mask="auto",
        )
        canvas.setFillColor(ACCENT)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(44 * mm, page_h - 30 * mm, "DECODEX SECURITY TECHNOLOGIES")
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1.2)
        canvas.line(44 * mm, page_h - 33 * mm, 115 * mm, page_h - 33 * mm)
    else:
        canvas.setFillColor(ACCENT)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(22 * mm, page_h - 32 * mm, "DECODEX SECURITY TECHNOLOGIES")
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1.2)
        canvas.line(22 * mm, page_h - 35 * mm, 78 * mm, page_h - 35 * mm)

    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 26)
    canvas.drawString(22 * mm, page_h - 52 * mm, "SECURITY INCIDENT")
    canvas.drawString(22 * mm, page_h - 63 * mm, "REPORT")

    canvas.setFillColor(colors.HexColor("#9BB4C7"))
    canvas.setFont("Helvetica", 10)
    canvas.drawString(22 * mm, page_h - 72 * mm, "Confidential  •  Internal Security Document")

    # Incident ID badge
    badge_y = page_h - 92 * mm
    canvas.setFillColor(colors.HexColor("#0E2A42"))
    canvas.roundRect(22 * mm, badge_y, 70 * mm, 12 * mm, 3, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(26 * mm, badge_y + 3.5 * mm, incident_id)

    # Severity pill
    sev = (ctx.get("severity") or "INFO").upper()
    sev_c = _severity_color(sev)
    canvas.setFillColor(sev_c)
    canvas.roundRect(96 * mm, badge_y, 38 * mm, 12 * mm, 6, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawCentredString(115 * mm, badge_y + 3.5 * mm, sev)

    # Meta card
    card_x, card_y, card_w, card_h = 22 * mm, 58 * mm, page_w - 44 * mm, 78 * mm
    canvas.setFillColor(colors.HexColor("#0E2A42"))
    canvas.roundRect(card_x, card_y, card_w, card_h, 4, fill=1, stroke=0)
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(1)
    canvas.roundRect(card_x, card_y, card_w, card_h, 4, fill=0, stroke=1)

    title = (ctx.get("title") or "Security Incident")[:90]
    rows = [
        ("Incident Title", title),
        ("Incident ID", incident_id),
        ("Severity", sev),
        ("Status", ctx.get("status") or "—"),
        ("Incident Date", _fmt_dt(ctx.get("incident_date"), with_time=False)),
        ("Report Date", _fmt_dt(ctx.get("report_date"), with_time=False)),
        ("Organization", (ctx.get("organization") or "—")[:60]),
    ]
    y = card_y + card_h - 10 * mm
    for label, value in rows:
        canvas.setFillColor(colors.HexColor("#7FA3B8"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(card_x + 6 * mm, y, label.upper())
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 10)
        # wrap long title lightly
        canvas.drawString(card_x + 48 * mm, y, str(value)[:72])
        y -= 9.5 * mm

    # Prepared by
    canvas.setFillColor(colors.HexColor("#9BB4C7"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(22 * mm, 44 * mm, "PREPARED BY")
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(22 * mm, 37 * mm, "DecodeX Security Technologies Private Limited")
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(colors.HexColor("#9BB4C7"))
    lead = ctx.get("prepared_by") or "Manan Mandal"
    role = ctx.get("prepared_role") or "Information Security Engineer"
    canvas.drawString(22 * mm, 31 * mm, f"Lead Analyst: {lead}  •  {role}")

    # Footer strip
    canvas.setFillColor(colors.HexColor("#071521"))
    canvas.rect(0, 0, page_w, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, 18 * mm, page_w, 1.5, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#9BB4C7"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawCentredString(
        page_w / 2,
        8 * mm,
        f"Authorized recipients only  ·  {TEMPLATE_VERSION}  ·  {incident_id}",
    )
    canvas.restoreState()


class AttackChainStrip(Flowable):
    """Visual Initial Access → … → Impact strip."""

    STAGES = [
        "Initial\nAccess",
        "Execution",
        "Persistence",
        "Privilege\nEscalation",
        "Lateral\nMovement",
        "Impact",
    ]

    def __init__(self, width: float, active_index: int = 0):
        super().__init__()
        self.box_width = width
        self.active_index = max(0, min(active_index, len(self.STAGES) - 1))
        self.box_height = 42

    def wrap(self, availWidth, availHeight):
        return self.box_width, self.box_height

    def draw(self):
        n = len(self.STAGES)
        gap = 6
        w = (self.box_width - gap * (n - 1)) / n
        for i, label in enumerate(self.STAGES):
            x = i * (w + gap)
            active = i <= self.active_index
            self.canv.setFillColor(ACCENT if active else ACCENT_SOFT)
            self.canv.roundRect(x, 0, w, self.box_height, 3, fill=1, stroke=0)
            self.canv.setFillColor(WHITE if active else NAVY_MID)
            self.canv.setFont("Helvetica-Bold", 6.5)
            lines = label.split("\n")
            ty = 24 if len(lines) > 1 else 17
            for line in lines:
                self.canv.drawCentredString(x + w / 2, ty, line)
                ty -= 9


def build_incident_context(db, alert, *, prepared_by: str = "Manan Mandal") -> dict:
    """Assemble report context from alert + related SIEM data."""
    from .db import Asset, Case, CaseAlert, CaseNote, Event, IOC

    when = alert.event_timestamp or alert.created_at or utcnow()
    incident_id = _incident_id(alert.id, when)
    title = (alert.title or alert.description or "Security Incident").strip()

    # Related events (±30 minutes on same host)
    events = []
    if alert.event_timestamp and alert.host:
        start = alert.event_timestamp - timedelta(minutes=30)
        end = alert.event_timestamp + timedelta(minutes=30)
        events = (
            db.query(Event)
            .filter(Event.host == alert.host, Event.timestamp >= start, Event.timestamp <= end)
            .order_by(Event.timestamp.asc())
            .limit(40)
            .all()
        )
    elif alert.event_id:
        ev = db.get(Event, alert.event_id)
        if ev:
            events = [ev]

    case = None
    notes = []
    if getattr(alert, "case_id", None):
        case = db.get(Case, alert.case_id)
        if case:
            notes = (
                db.query(CaseNote)
                .filter_by(case_id=case.id)
                .order_by(CaseNote.created_at.asc())
                .limit(20)
                .all()
            )
    else:
        link = db.query(CaseAlert).filter_by(alert_id=alert.id).first()
        if link:
            case = db.get(Case, link.case_id)
            if case:
                notes = (
                    db.query(CaseNote)
                    .filter_by(case_id=case.id)
                    .order_by(CaseNote.created_at.asc())
                    .limit(20)
                    .all()
                )

    # IOC matches from alert fields
    ioc_rows = []
    candidates = [
        ("IP Address", alert.ip),
        ("Domain", alert.domain),
        ("SHA-256", alert.file_hash),
        ("Username", alert.user),
    ]
    for ioc_type, value in candidates:
        if not value:
            continue
        known = db.query(IOC).filter(IOC.value == value).first()
        status = "Malicious" if known and getattr(known, "malicious", True) else "Observed"
        if ioc_type == "Username":
            status = "Compromised" if (alert.severity or "").upper() in {"HIGH", "CRITICAL"} else "Involved"
        ioc_rows.append({"type": ioc_type, "indicator": value, "status": status})

    asset = None
    if alert.host:
        asset = db.query(Asset).filter_by(hostname=alert.host).first()

    analyst = prepared_by or alert.assigned_to or "SOC Analyst"
    detection_source = alert.source_name or alert.source_type or "SIEM / Detection Engine"
    if (alert.source_type or "").lower() == "web":
        detection_source = f"Web Scanner / SIEM ({alert.source_name or 'webscan'})"

    timeline = []
    timeline.append({
        "time": _fmt_dt(when, with_time=True),
        "event": "Suspicious activity detected",
        "action": f"Alert generated ({alert.rule_id or 'rule'})",
        "analyst": "Detection Engine",
    })
    if alert.created_at and alert.created_at != when:
        timeline.append({
            "time": _fmt_dt(alert.created_at, with_time=True),
            "event": "Alert persisted in SOC platform",
            "action": "Queued for analyst review",
            "analyst": "System",
        })
    for note in notes[:6]:
        timeline.append({
            "time": _fmt_dt(note.created_at, with_time=True),
            "event": "Investigation note recorded",
            "action": (note.body or "")[:120],
            "analyst": note.author or analyst,
        })
    if (alert.status or "").upper() in {"CLOSED", "RESOLVED"}:
        timeline.append({
            "time": _fmt_dt(alert.created_at or when, with_time=True),
            "event": "Incident closed",
            "action": "Containment / recovery documented",
            "analyst": analyst,
        })
    # Enrich with event breadcrumbs
    for e in events[:8]:
        timeline.append({
            "time": _fmt_dt(e.timestamp, with_time=True),
            "event": f"Related telemetry: {e.process or e.event_type or 'event'}",
            "action": (e.commandline or e.url or e.ip or "")[:100] or "Log correlation",
            "analyst": "SIEM",
        })

    # Stable sort by time string is weak; keep insertion order mostly chronological
    evidence = []
    evidence.append({
        "id": "EV-001",
        "description": f"SIEM Alert #{alert.id}: {title[:80]}",
        "source": detection_source,
        "ref": f"alert:{alert.id}/rule:{alert.rule_id or 'n/a'}",
    })
    if events:
        payload = "|".join(f"{e.id}:{e.timestamp}" for e in events[:5])
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        evidence.append({
            "id": "EV-002",
            "description": f"Correlated event window ({len(events)} events)",
            "source": "Endpoint / Log Pipeline",
            "ref": f"sha256:{digest}…",
        })
    if ioc_rows:
        evidence.append({
            "id": "EV-003",
            "description": "Extracted indicators of compromise",
            "source": "Alert Enrichment",
            "ref": f"ioc_count:{len(ioc_rows)}",
        })
    if case:
        evidence.append({
            "id": "EV-004",
            "description": f"Linked case {case.case_number}",
            "source": "Case Management",
            "ref": f"case:{case.id}",
        })

    severity = (alert.severity or "MEDIUM").upper()
    status = _normalize_status(alert.status)
    org = "DecodeX Security Technologies"
    if asset and getattr(asset, "owner", None):
        org = f"{asset.owner} / DecodeX Security Technologies"

    return {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "status": status,
        "prepared_by": analyst,
        "prepared_role": "Information Security Engineer",
        "incident_date": when,
        "report_date": utcnow(),
        "organization": org,
        "category": _category_from_alert(alert),
        "detection_source": detection_source,
        "affected_asset": alert.host or "Unknown",
        "affected_user": alert.user or "—",
        "business_impact": _impact_from_severity(severity),
        "risk_score": alert.risk_score or 0,
        "confidence": alert.confidence or 70,
        "tactic": alert.tactic or "—",
        "technique_id": alert.technique_id or "—",
        "technique_name": alert.technique_name or "—",
        "description": alert.description or title,
        "notes": alert.analyst_notes or "",
        "commandline": alert.commandline or "",
        "process": alert.process or "",
        "ip": alert.ip or "",
        "domain": alert.domain or "",
        "file_hash": alert.file_hash or "",
        "source_type": alert.source_type or "",
        "events": events,
        "ioc_rows": ioc_rows,
        "asset": asset,
        "case": case,
        "timeline": timeline,
        "evidence": evidence,
        "alert": alert,
    }


def render_incident_pdf(ctx: dict) -> io.BytesIO:
    """Render the multi-page premium incident report into a BytesIO buffer."""
    styles = _styles()
    buffer = io.BytesIO()
    incident_id = ctx["incident_id"]
    page_w, _ = A4
    content_w = page_w - 36 * mm

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=f"Security Incident Report — {incident_id}",
        author=ctx["prepared_by"],
    )

    story: list = []

    # ---------- PAGE 1 COVER (drawn full-bleed on canvas) ----------
    story.append(Spacer(1, 1))
    story.append(PageBreak())

    # ---------- PAGE 2 EXECUTIVE SUMMARY ----------
    story.append(SectionBanner("1. Executive Summary", content_w))
    story.append(Spacer(1, 8))
    summary = (
        f"On {_fmt_dt(ctx['incident_date'])}, the SOC detected "
        f"<b>{_esc(ctx['title'])}</b> against asset "
        f"<b>{_esc(ctx['affected_asset'])}</b>"
        + (f" involving user <b>{_esc(ctx['affected_user'])}</b>" if ctx["affected_user"] not in {"", "—"} else "")
        + f". Detection originated from <b>{_esc(ctx['detection_source'])}</b>. "
        f"The incident is currently classified as <b>{_esc(ctx['status'])}</b> "
        f"with severity <b>{_esc(ctx['severity'])}</b> "
        f"(risk score {ctx['risk_score']}/100, confidence {ctx['confidence']}%). "
        f"Overall business impact is assessed as <b>{_esc(ctx['business_impact'])}</b>."
    )
    story.append(Paragraph(summary, styles["body"]))
    if ctx.get("notes"):
        story.append(Paragraph(f"<b>Analyst notes:</b> {_esc(ctx['notes'])}", styles["body"]))

    story.append(Paragraph("Incident Snapshot", styles["h3"]))
    story.append(
        _kv_table(
            [
                ("Incident ID", incident_id),
                ("Severity", ctx["severity"]),
                ("Category", ctx["category"]),
                ("Detection Source", ctx["detection_source"]),
                ("Affected Asset", ctx["affected_asset"]),
                ("Affected User", ctx["affected_user"]),
                ("Current Status", ctx["status"]),
                ("Business Impact", ctx["business_impact"]),
                ("MITRE Tactic", ctx["tactic"]),
                ("MITRE Technique", f"{ctx['technique_id']} — {ctx['technique_name']}"),
            ],
            content_w,
            styles,
        )
    )
    story.append(PageBreak())

    # ---------- PAGE 3 TIMELINE ----------
    story.append(SectionBanner("2. Incident Timeline", content_w))
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "Chronological sequence of detection, investigation, and response activities.",
            styles["body"],
        )
    )
    tl_data = [["Time", "Event", "Action", "Analyst"]]
    for row in ctx["timeline"][:18]:
        tl_data.append([row["time"], row["event"], row["action"], row["analyst"]])
    if len(tl_data) == 1:
        tl_data.append(["—", "No additional timeline entries", "—", "—"])
    story.append(_table(tl_data, [content_w * 0.28, content_w * 0.24, content_w * 0.30, content_w * 0.18], styles))
    story.append(PageBreak())

    # ---------- PAGE 4 TECHNICAL ----------
    story.append(SectionBanner("3. Technical Analysis", content_w))
    story.append(Spacer(1, 8))
    story.append(Paragraph("3.1 Detection", styles["h3"]))
    story.append(
        Paragraph(
            f"The incident was identified by the platform detection pipeline using "
            f"source <b>{_esc(ctx['detection_source'])}</b> "
            f"(type: {_esc(ctx['source_type'] or 'endpoint')}). "
            f"Primary description: {_esc(ctx['description'])}.",
            styles["body"],
        )
    )
    if ctx.get("process") or ctx.get("commandline"):
        story.append(
            Paragraph(
                f"<b>Process:</b> {_esc(ctx['process'] or '—')}<br/>"
                f"<b>Command line:</b> {_esc((ctx['commandline'] or '—')[:500])}",
                styles["body"],
            )
        )

    story.append(Paragraph("3.2 Indicators of Compromise", styles["h3"]))
    ioc_data = [["IOC Type", "Indicator", "Status"]]
    for row in ctx["ioc_rows"]:
        ioc_data.append([row["type"], row["indicator"], row["status"]])
    if len(ioc_data) == 1:
        ioc_data.append(["—", "No discrete IOCs extracted from this alert", "—"])
    story.append(_table(ioc_data, [content_w * 0.22, content_w * 0.53, content_w * 0.25], styles))

    story.append(Paragraph("3.3 Affected Assets", styles["h3"]))
    asset_rows = [["Asset", "Type", "Impact", "Status"]]
    asset = ctx.get("asset")
    if asset:
        asset_rows.append([
            asset.hostname,
            getattr(asset, "asset_type", None) or "Asset",
            ctx["business_impact"],
            "Contained" if ctx["status"] == "Closed" else "Monitored",
        ])
    else:
        asset_rows.append([
            ctx["affected_asset"],
            "Host / Application",
            ctx["business_impact"],
            "Contained" if ctx["status"] == "Closed" else "Under Investigation",
        ])
    if ctx["affected_user"] not in {"", "—"}:
        asset_rows.append([ctx["affected_user"], "Account", "Identity", "Review required"])
    story.append(_table(asset_rows, [content_w * 0.30, content_w * 0.25, content_w * 0.22, content_w * 0.23], styles))

    if ctx["events"]:
        story.append(Paragraph("3.4 Related Telemetry (excerpt)", styles["h3"]))
        ev_data = [["Time", "Process", "Command / Detail"]]
        for e in ctx["events"][:12]:
            detail = e.commandline or e.url or e.ip or e.event_type or ""
            if len(detail) > 80:
                detail = detail[:77] + "..."
            ev_data.append([
                e.timestamp.strftime("%H:%M:%S") if e.timestamp else "—",
                e.process or "—",
                detail or "—",
            ])
        story.append(_table(ev_data, [content_w * 0.16, content_w * 0.22, content_w * 0.62], styles))
    story.append(PageBreak())

    # ---------- PAGE 5 ATTACK ANALYSIS ----------
    story.append(SectionBanner("4. Attack Chain", content_w))
    story.append(Spacer(1, 8))
    # Highlight early kill-chain stages when technique/tactic present
    active = 1 if ctx.get("technique_id") not in {"", "—", None} else 0
    story.append(AttackChainStrip(content_w, active_index=active))
    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            "Mapped activity uses observed MITRE ATT&CK fields from the detection rule. "
            "Unobserved stages are marked as not evidenced in this alert window.",
            styles["body"],
        )
    )
    attack_data = [["Technique", "ID", "Evidence"]]
    if ctx["technique_id"] not in {"", "—"} or ctx["technique_name"] not in {"", "—"}:
        attack_data.append([
            ctx["technique_name"] if ctx["technique_name"] != "—" else ctx["tactic"],
            ctx["technique_id"],
            (ctx["commandline"] or ctx["description"] or "Alert evidence")[:120],
        ])
    else:
        attack_data.append([
            ctx["tactic"] if ctx["tactic"] != "—" else "Unspecified",
            "—",
            "Technique ID not mapped on this detection",
        ])
    if ctx.get("process"):
        attack_data.append(["Process Execution", "T1059*", f"Process: {ctx['process']}"])
    story.append(_table(attack_data, [content_w * 0.28, content_w * 0.18, content_w * 0.54], styles))
    story.append(PageBreak())

    # ---------- PAGE 6 RESPONSE ----------
    story.append(SectionBanner("5. Response Actions", content_w))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Containment", styles["h3"]))
    for item in [
        "Account disabled/reset where identity risk is indicated",
        "Endpoint / asset isolation recommended for high/critical severity",
        "Malicious IP/domain blocked via IOC/suppression controls where applicable",
        "Active sessions revoked for involved accounts",
    ]:
        story.append(Paragraph(f"• {_esc(item)}", styles["bullet"]))

    story.append(Paragraph("Eradication", styles["h3"]))
    for item in [
        "Malicious artifacts removed or quarantined following confirmation",
        "Persistence mechanisms reviewed against related telemetry",
        "Vulnerability or misconfiguration remediated when root cause is known",
    ]:
        story.append(Paragraph(f"• {_esc(item)}", styles["bullet"]))

    story.append(Paragraph("Recovery", styles["h3"]))
    for item in [
        "Systems restored to trusted baselines",
        "Credentials rotated for involved identities",
        "Enhanced monitoring applied to the affected asset/user for recurrence",
    ]:
        story.append(Paragraph(f"• {_esc(item)}", styles["bullet"]))

    if ctx.get("case"):
        story.append(
            Paragraph(
                f"Linked case <b>{_esc(ctx['case'].case_number)}</b> "
                f"({_esc(ctx['case'].status)}) tracks remediation ownership.",
                styles["body"],
            )
        )
    story.append(PageBreak())

    # ---------- PAGE 7 ROOT CAUSE & IMPACT ----------
    story.append(SectionBanner("6. Root Cause Analysis", content_w))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Primary Root Cause:", styles["h3"]))
    root = ctx.get("notes") or (
        f"Detection of {_esc(ctx['category'])} activity associated with "
        f"{_esc(ctx['tactic'])} / {_esc(ctx['technique_name'])}. "
        "A definitive root cause should be confirmed during full forensic review."
    )
    story.append(Paragraph(_esc(root), styles["body"]))
    story.append(Paragraph("Contributing Factors:", styles["h3"]))
    for factor in [
        "Insufficient preventive control or user awareness relative to the observed technique",
        "Opportunity for credential or session abuse if identity controls are weak",
        "Limited earlier correlation signal prior to alert generation",
    ]:
        story.append(Paragraph(f"• {_esc(factor)}", styles["bullet"]))

    story.append(Paragraph("7. Impact Assessment", styles["h3"]))
    impact = ctx["business_impact"]
    story.append(
        _table(
            [
                ["Impact Area", "Assessment"],
                ["Confidentiality", impact],
                ["Integrity", "Low" if impact == "Low" else impact],
                ["Availability", "Low" if ctx["severity"] not in {"CRITICAL", "HIGH"} else "Medium"],
                ["Data Exposure", "Unknown" if impact == "Low" else "Possible"],
                ["Business Disruption", impact],
            ],
            [content_w * 0.4, content_w * 0.6],
            styles,
        )
    )
    story.append(PageBreak())

    # ---------- PAGE 8 LESSONS ----------
    story.append(SectionBanner("8. Recommendations", content_w))
    story.append(Spacer(1, 8))
    for rec in [
        "Validate and harden controls mapped to the observed MITRE technique.",
        "Ensure IOCs from this incident are retained in the platform IOC store with expiry.",
        "Tune detection thresholds / suppressions carefully to reduce noise without losing coverage.",
        "Confirm backup, credential hygiene, and privileged access reviews for the affected asset.",
        "Run a tabletop or purple-team exercise covering this attack path within 30 days.",
    ]:
        story.append(Paragraph(f"• {_esc(rec)}", styles["bullet"]))

    story.append(Paragraph("9. Lessons Learned", styles["h3"]))
    story.append(
        Paragraph(
            "Improve detection coverage for this technique family, tighten prevention "
            "where initial access occurred, accelerate containment playbooks for similar "
            "alerts, and increase monitoring dwell on the affected asset class for recurrence.",
            styles["body"],
        )
    )
    story.append(PageBreak())

    # ---------- FINAL EVIDENCE & APPROVAL ----------
    story.append(SectionBanner("10. Evidence Register", content_w))
    story.append(Spacer(1, 8))
    ev_table = [["Evidence ID", "Description", "Source", "Hash/Reference"]]
    for row in ctx["evidence"]:
        ev_table.append([row["id"], row["description"], row["source"], row["ref"]])
    story.append(
        _table(ev_table, [content_w * 0.14, content_w * 0.38, content_w * 0.24, content_w * 0.24], styles)
    )

    story.append(Spacer(1, 16))
    story.append(Paragraph("Report Ownership", styles["h2"]))
    story.append(Spacer(1, 6))
    ownership = Table(
        [
            [
                Paragraph("<b>Prepared By</b>", styles["sign"]),
                Paragraph("<b>Reviewed By</b>", styles["sign"]),
                Paragraph("<b>Approved By</b>", styles["sign"]),
            ],
            [
                Paragraph(
                    f"{_esc(ctx['prepared_by'])}<br/>{_esc(ctx['prepared_role'])}",
                    styles["sign"],
                ),
                Paragraph("[Name / Designation]<br/><br/>Signature: ____________", styles["sign"]),
                Paragraph("[Name / Designation]<br/><br/>Signature: ____________", styles["sign"]),
            ],
        ],
        colWidths=[content_w / 3.0] * 3,
    )
    ownership.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE),
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_SOFT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(ownership)
    story.append(Spacer(1, 18))
    story.append(
        Paragraph(
            "This document is confidential and intended solely for authorized internal "
            "security stakeholders. Redistribution outside the approved audience is prohibited.",
            styles["small_center"],
        )
    )

    def _later_pages(canvas, doc_):
        _page_footer(canvas, doc_, incident_id)

    def _first_page(canvas, doc_):
        _draw_full_cover(canvas, ctx)

    doc.build(story, onFirstPage=_first_page, onLaterPages=_later_pages)
    buffer.seek(0)
    return buffer


def generate_alert_incident_pdf(db, alert, *, prepared_by: str = "Manan Mandal") -> io.BytesIO:
    ctx = build_incident_context(db, alert, prepared_by=prepared_by)
    return render_incident_pdf(ctx)
