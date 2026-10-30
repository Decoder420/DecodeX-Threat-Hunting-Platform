"""
Premium multi-page Web Application Security Assessment PDF generator.

Follows the platform's dark-navy SOC design language established in incident_report.py:
Cover page -> Executive Summary & KPI Matrix -> Attack Surface Posture ->
Detailed Vulnerability Findings Catalog -> Remediation Roadmap -> Report Sign-off.
"""

from __future__ import annotations

import io
from datetime import datetime
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

# Palette aligned to platform incident report
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
INFO = colors.HexColor("#475467")
OK = colors.HexColor("#067647")

TEMPLATE_VERSION = "WAS-TEMPLATE-2026.2"


def _esc(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _fmt_dt(value: datetime | None, tz_name: str = "UTC", *, with_time: bool = True) -> str:
    if not value:
        return "—"
    try:
        from zoneinfo import ZoneInfo
        zi = ZoneInfo(tz_name or "UTC")
    except Exception:
        from datetime import timezone as dt_tz
        zi = dt_tz.utc

    if value.tzinfo is None:
        from datetime import timezone as dt_tz
        value = value.replace(tzinfo=dt_tz.utc)

    localized = value.astimezone(zi)
    if with_time:
        tz_abbr = localized.strftime("%Z") or tz_name
        return localized.strftime(f"%d %B %Y %H:%M {tz_abbr}")
    return localized.strftime("%d %B %Y")


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
    if s == "INFO":
        return INFO
    return MUTED


class SectionBanner(Flowable):
    """Deep-navy section heading bar."""

    def __init__(self, title: str, width: float, height: float = 24):
        super().__init__()
        self.title = title
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        self.canv.setFillColor(NAVY)
        self.canv.roundRect(0, 0, self.width, self.height, 3, fill=1, stroke=0)
        self.canv.setFillColor(ACCENT)
        self.canv.rect(0, 0, 4, self.height, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont("Helvetica-Bold", 10.5)
        self.canv.drawString(10, 7, self.title.upper())


def _styles():
    base = getSampleStyleSheet()
    styles = {
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
            fontSize=10.5,
            textColor=NAVY_MID,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=INK,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        ),
        "body_mono": ParagraphStyle(
            "body_mono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10.5,
            textColor=INK,
        ),
        "table_cell": ParagraphStyle(
            "table_cell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=INK,
        ),
        "table_cell_bold": ParagraphStyle(
            "table_cell_bold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11.5,
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
            fontSize=8.5,
            leading=12.5,
            textColor=INK,
            spaceAfter=3,
        ),
        "sign_header": ParagraphStyle(
            "sign_header",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=NAVY,
        ),
        "sign_cell": ParagraphStyle(
            "sign_cell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=INK,
        ),
        "callout_warn": ParagraphStyle(
            "callout_warn",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=CRIT,
        ),
    }
    return styles


def _page_footer(canvas, doc, was_id: str, company_name: str = "DecodeX Security Technologies"):
    canvas.saveState()
    page_w, page_h = A4
    # Top confidential ribbon
    canvas.setFillColor(NAVY)
    canvas.rect(0, page_h - 16, page_w, 16, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, page_h - 18, page_w, 2, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawString(18 * mm, page_h - 11, "CONFIDENTIAL • WEB APPLICATION SECURITY ASSESSMENT")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(page_w - 18 * mm, page_h - 11, (company_name or "DecodeX Security Technologies")[:45])

    # Footer
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.6)
    canvas.line(18 * mm, 14 * mm, page_w - 18 * mm, 14 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 9 * mm, f"{was_id}  ·  {TEMPLATE_VERSION}")
    canvas.drawCentredString(page_w / 2, 9 * mm, f"{(company_name or 'Web Application')} — Vulnerability Report")
    canvas.drawRightString(page_w - 18 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _draw_full_cover(canvas, ctx: dict):
    """Full-bleed navy cover page."""
    page_w, page_h = A4
    was_id = ctx["report_id"]
    company = (ctx.get("company_name") or "DECODEX SECURITY TECHNOLOGIES").upper()
    tagline = ctx.get("tagline") or "DAST Scan & Attack Surface Security Report"
    tz = ctx.get("timezone") or "UTC"
    contact = ctx.get("contact_email") or "soc@decodex.internal"

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
        canvas.drawString(44 * mm, page_h - 30 * mm, f"{company[:32]}  •  WEB APPSEC")
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1.2)
        line_end = min(140 * mm, 44 * mm + max(12, len(company)) * 2.8 * mm)
        canvas.line(44 * mm, page_h - 33 * mm, line_end, page_h - 33 * mm)
    else:
        canvas.setFillColor(ACCENT)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(22 * mm, page_h - 32 * mm, f"{company[:32]}  •  WEB APPSEC")
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1.2)
        line_end = min(120 * mm, 22 * mm + max(12, len(company)) * 2.8 * mm)
        canvas.line(22 * mm, page_h - 35 * mm, line_end, page_h - 35 * mm)

    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 25)
    canvas.drawString(22 * mm, page_h - 52 * mm, "WEB APPLICATION")
    canvas.drawString(22 * mm, page_h - 63 * mm, "SECURITY ASSESSMENT")

    canvas.setFillColor(colors.HexColor("#9BB4C7"))
    canvas.setFont("Helvetica", 10)
    canvas.drawString(22 * mm, page_h - 72 * mm, f"DAST Scan & Attack Surface Security Report  •  {tagline[:50]}")

    # Document ID badge
    badge_y = page_h - 92 * mm
    canvas.setFillColor(colors.HexColor("#0E2A42"))
    canvas.roundRect(22 * mm, badge_y, 74 * mm, 12 * mm, 3, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(26 * mm, badge_y + 3.5 * mm, was_id)

    # Overall Risk pill
    risk_sev = ctx.get("overall_risk_severity") or "INFO"
    sev_c = _severity_color(risk_sev)
    canvas.setFillColor(sev_c)
    canvas.roundRect(100 * mm, badge_y, 44 * mm, 12 * mm, 6, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawCentredString(122 * mm, badge_y + 3.5 * mm, f"RISK: {risk_sev}")

    # Meta card
    card_x, card_y, card_w, card_h = 22 * mm, 54 * mm, page_w - 44 * mm, 86 * mm
    canvas.setFillColor(colors.HexColor("#0E2A42"))
    canvas.roundRect(card_x, card_y, card_w, card_h, 4, fill=1, stroke=0)
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(1)
    canvas.roundRect(card_x, card_y, card_w, card_h, 4, fill=0, stroke=1)

    rows = [
        ("Organization", (ctx.get("company_name") or "—")[:60]),
        ("Target Name", (ctx.get("target_name") or "Web Target")[:60]),
        ("Target URL", (ctx.get("target_url") or "—")[:60]),
        ("Scan Profile", f"{ctx.get('profile')} (ZAP + Nuclei + HTTPX)"),
        ("Scan Status", ctx.get("status") or "COMPLETED"),
        ("Overall Risk Score", f"{ctx.get('risk_score')}/100"),
        ("Total Findings", f"{ctx.get('findings_count')} issues detected"),
        ("Scan Completed", _fmt_dt(ctx.get("finished_at"), tz, with_time=True)),
        ("Discovered URLs", f"{ctx.get('discovered_urls')} endpoints"),
    ]
    y = card_y + card_h - 9 * mm
    for label, value in rows:
        canvas.setFillColor(colors.HexColor("#7FA3B8"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(card_x + 6 * mm, y, label.upper())
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(card_x + 48 * mm, y, str(value)[:65])
        y -= 8.5 * mm

    # Prepared by
    canvas.setFillColor(colors.HexColor("#9BB4C7"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(22 * mm, 42 * mm, "ASSESSMENT CONDUCTED FOR & BY")
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(22 * mm, 35 * mm, (ctx.get("company_name") or "DecodeX Security Technologies Private Limited")[:50])
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(colors.HexColor("#9BB4C7"))
    lead = ctx.get("prepared_by") or "Manan Mandal"
    canvas.drawString(22 * mm, 29 * mm, f"Lead Security Engineer: {lead}  •  {contact}")

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
        f"Authorized recipients only  ·  {TEMPLATE_VERSION}  ·  {was_id}",
    )
    canvas.restoreState()


def build_scan_context(db, scan, *, prepared_by: str = "Manan Mandal") -> dict:
    """Extract and assemble report context from scan, target, and findings."""
    from .db import WebFinding, WebTarget

    target = db.get(WebTarget, scan.target_id)
    findings = (
        db.query(WebFinding)
        .filter_by(scan_id=scan.id)
        .order_by(WebFinding.risk_score.desc(), WebFinding.id.asc())
        .all()
    )

    crit_cnt = getattr(scan, "critical_count", 0) or 0
    high_cnt = scan.high_count or 0
    med_cnt = getattr(scan, "medium_count", 0) or 0
    low_cnt = getattr(scan, "low_count", 0) or 0
    info_cnt = getattr(scan, "info_count", 0) or 0

    if crit_cnt > 0:
        overall_sev = "CRITICAL"
    elif high_cnt > 0:
        overall_sev = "HIGH"
    elif med_cnt > 0:
        overall_sev = "MEDIUM"
    elif low_cnt > 0:
        overall_sev = "LOW"
    else:
        overall_sev = "INFO"

    year = (scan.started_at or scan.created_at or utcnow()).year
    report_id = f"WAS-{year}-{int(scan.id):03d}"

    import json
    ports = []
    if getattr(scan, "ports_json", None):
        try:
            ports = json.loads(scan.ports_json)
        except Exception:
            ports = []

    tech = []
    if getattr(scan, "technologies_json", None):
        try:
            tech = json.loads(scan.technologies_json)
        except Exception:
            tech = []

    from .db import get_org_settings
    org_settings = get_org_settings(db)
    company_name = (getattr(org_settings, "company_name", None) or "DecodeX Security Technologies").strip()
    tagline = (getattr(org_settings, "tagline", None) or "Enterprise Threat Hunting & Modern Cloud SIEM").strip()
    timezone_name = (getattr(org_settings, "timezone", None) or "UTC").strip()
    contact_email = (getattr(org_settings, "contact_email", None) or "soc@decodex.internal").strip()

    return {
        "report_id": report_id,
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "target_name": target.name if target else "Web Target",
        "target_url": target.url if target else getattr(scan, "target_url", ""),
        "company_name": company_name,
        "tagline": tagline,
        "timezone": timezone_name,
        "contact_email": contact_email,
        "profile": getattr(scan, "scan_profile", "STANDARD"),
        "status": scan.status,
        "risk_score": getattr(scan, "risk_score", 0) or 0,
        "overall_risk_severity": overall_sev,
        "findings_count": scan.findings_count or len(findings),
        "critical_count": crit_cnt,
        "high_count": high_cnt,
        "medium_count": med_cnt,
        "low_count": low_cnt,
        "info_count": info_cnt,
        "discovered_urls": getattr(scan, "discovered_urls", 0) or 0,
        "discovered_ports": getattr(scan, "discovered_ports", 0) or len(ports),
        "started_at": scan.started_at or scan.created_at,
        "finished_at": scan.finished_at or utcnow(),
        "prepared_by": prepared_by,
        "ports": ports,
        "technologies": tech,
        "findings": findings,
        "target": target,
        "scan": scan,
        "error_message": getattr(scan, "error_message", "") or "",
    }


def render_web_scan_pdf(ctx: dict) -> io.BytesIO:
    """Render the multi-page premium Web AppSec PDF report into a BytesIO buffer."""
    styles = _styles()
    buffer = io.BytesIO()
    was_id = ctx["report_id"]
    page_w, _ = A4
    content_w = page_w - 36 * mm

    tz = ctx.get("timezone") or "UTC"

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=f"Web Application Security Report — {was_id}",
        author=ctx["prepared_by"],
    )

    story: list = []

    # Page 1: Cover Page
    story.append(Spacer(1, 1))
    story.append(PageBreak())

    # Page 2: Executive Summary
    story.append(SectionBanner("1. Executive Summary & Security Posture", content_w))
    story.append(Spacer(1, 8))

    summary_text = (
        f"A comprehensive Dynamic Application Security Testing (DAST) assessment was conducted against "
        f"<b>{_esc(ctx['target_name'])}</b> (<code>{_esc(ctx['target_url'])}</code>) on "
        f"{_fmt_dt(ctx['started_at'], tz)}. Testing was orchestrated using multi-engine verification, "
        f"combining OWASP ZAP spidering and passive security inspection, ProjectDiscovery Nuclei template analysis, "
        f"and built-in HTTP attack surface discovery for <b>{_esc(ctx.get('company_name', 'Enterprise'))}</b>. "
        f"The scan concluded with status <b>{_esc(ctx['status'])}</b>, identifying a total of "
        f"<b>{ctx['findings_count']} security finding(s)</b> and producing an aggregate risk score of "
        f"<b>{ctx['risk_score']}/100 ({ctx['overall_risk_severity']})</b>."
    )
    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 8))

    if ctx.get("error_message") or ctx.get("status") == "PARTIAL":
        err_msg = _esc(ctx.get("error_message") or "One or more scan engines encountered errors or were unavailable.")
        warn_data = [
            [
                Paragraph(f"<b>⚠️ Scan Engine Diagnostics / Partial Scan Notice:</b><br/>{err_msg}", styles["callout_warn"]),
            ]
        ]
        warn_table = Table(warn_data, colWidths=[content_w])
        warn_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3F2")),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#FECDCA")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(warn_table)
        story.append(Spacer(1, 8))

    # KPI Matrix
    story.append(Paragraph("<b>Vulnerability Severity Distribution</b>", styles["h3"]))
    story.append(Spacer(1, 4))

    kpi_data = [
        [
            Paragraph("<b>CRITICAL</b>", styles["table_header"]),
            Paragraph("<b>HIGH</b>", styles["table_header"]),
            Paragraph("<b>MEDIUM</b>", styles["table_header"]),
            Paragraph("<b>LOW</b>", styles["table_header"]),
            Paragraph("<b>INFO</b>", styles["table_header"]),
            Paragraph("<b>TOTAL</b>", styles["table_header"]),
        ],
        [
            Paragraph(f"<font color='#B42318'><b>{ctx['critical_count']}</b></font>", styles["table_cell_bold"]),
            Paragraph(f"<font color='#B54708'><b>{ctx['high_count']}</b></font>", styles["table_cell_bold"]),
            Paragraph(f"<font color='#A15C07'><b>{ctx['medium_count']}</b></font>", styles["table_cell_bold"]),
            Paragraph(f"<font color='#175CD3'><b>{ctx['low_count']}</b></font>", styles["table_cell_bold"]),
            Paragraph(f"<font color='#475467'><b>{ctx['info_count']}</b></font>", styles["table_cell_bold"]),
            Paragraph(f"<b>{ctx['findings_count']}</b>", styles["table_cell_bold"]),
        ],
    ]
    col_w = content_w / 6.0
    kpi_table = Table(kpi_data, colWidths=[col_w] * 6)
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (-1, 1), ACCENT_SOFT),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 14))

    # Attack Surface Snapshot
    story.append(Paragraph("<b>Target Attack Surface Snapshot</b>", styles["h3"]))
    story.append(Spacer(1, 4))

    surface_rows = [
        [Paragraph("<b>Parameter</b>", styles["table_header"]), Paragraph("<b>Details</b>", styles["table_header"])],
        [Paragraph("Organization", styles["table_cell_bold"]), Paragraph(_esc(ctx.get("company_name", "—")), styles["table_cell"])],
        [Paragraph("Target URL", styles["table_cell_bold"]), Paragraph(_esc(ctx["target_url"]), styles["table_cell"])],
        [Paragraph("Discovered Endpoints", styles["table_cell_bold"]), Paragraph(f"{ctx['discovered_urls']} crawled URLs & paths", styles["table_cell"])],
        [Paragraph("Open Service Ports", styles["table_cell_bold"]), Paragraph(f"{ctx['discovered_ports']} detected services", styles["table_cell"])],
        [
            Paragraph("Detected Technologies", styles["table_cell_bold"]),
            Paragraph(
                ", ".join(t.get("technology") or t.get("name", "") for t in ctx["technologies"][:8]) or "Standard Web Stack",
                styles["table_cell"],
            ),
        ],
        [Paragraph("Scan Profile", styles["table_cell_bold"]), Paragraph(f"{ctx['profile']} — Active DAST Suite", styles["table_cell"])],
        [Paragraph("Execution Window", styles["table_cell_bold"]), Paragraph(f"{_fmt_dt(ctx['started_at'], tz)} to {_fmt_dt(ctx['finished_at'], tz)}", styles["table_cell"])],
    ]
    surface_table = Table(surface_rows, colWidths=[content_w * 0.32, content_w * 0.68])
    surface_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ACCENT_SOFT]),
                ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(surface_table)
    story.append(Spacer(1, 14))

    # Page Break for Detailed Findings Catalog
    story.append(PageBreak())
    story.append(SectionBanner("2. Detailed Vulnerability Findings Catalog", content_w))
    story.append(Spacer(1, 8))

    if not ctx["findings"]:
        story.append(Paragraph("<b>No security vulnerabilities were detected during this scan.</b>", styles["body"]))
    else:
        for idx, f in enumerate(ctx["findings"][:30], 1):
            sev = (f.severity or "INFO").upper()
            title = _esc(f.title or "Vulnerability Finding")
            url = _esc(getattr(f, "affected_url", None) or getattr(f, "url", None) or ctx["target_url"])
            cwe = _esc(getattr(f, "cwe", "") or "—")
            owasp = _esc(getattr(f, "owasp", "") or "—")
            engine = _esc(getattr(f, "source_engine", "") or "Web Scanner")
            desc = _esc(f.description or "No description provided.")
            evidence = _esc(getattr(f, "evidence", "") or "")
            remediation = _esc(getattr(f, "recommendation", "") or "Review application configuration and apply standard security controls.")

            # Finding header bar
            header_table = Table(
                [
                    [
                        Paragraph(f"<b>#{idx}. {title}</b>", styles["table_header"]),
                        Paragraph(f"<b>{sev}</b> · Risk {f.risk_score}/100", styles["table_header"]),
                    ]
                ],
                colWidths=[content_w * 0.72, content_w * 0.28],
            )
            header_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), _severity_color(sev)),
                        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.append(header_table)

            detail_rows = [
                [Paragraph("<b>Affected Endpoint</b>", styles["table_cell_bold"]), Paragraph(f"<code>{url}</code>", styles["body_mono"])],
                [Paragraph("<b>Engine / Category</b>", styles["table_cell_bold"]), Paragraph(f"{engine} · {getattr(f, 'category', 'general')}", styles["table_cell"])],
                [Paragraph("<b>CWE / OWASP</b>", styles["table_cell_bold"]), Paragraph(f"{cwe} · {owasp}", styles["table_cell"])],
                [Paragraph("<b>Description</b>", styles["table_cell_bold"]), Paragraph(desc, styles["table_cell"])],
            ]
            if evidence:
                detail_rows.append([Paragraph("<b>Evidence / POC</b>", styles["table_cell_bold"]), Paragraph(f"<code>{evidence[:400]}</code>", styles["body_mono"])])
            detail_rows.append([Paragraph("<b>Remediation</b>", styles["table_cell_bold"]), Paragraph(remediation, styles["table_cell"])])

            dt = Table(detail_rows, colWidths=[content_w * 0.24, content_w * 0.76])
            dt.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), ACCENT_SOFT),
                        ("BACKGROUND", (1, 0), (1, -1), WHITE),
                        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.append(dt)
            story.append(Spacer(1, 8))

    # Page Break for Remediation Roadmap & Ownership
    story.append(PageBreak())
    story.append(SectionBanner("3. Remediation Roadmap & Sign-Off", content_w))
    story.append(Spacer(1, 8))

    roadmap_data = [
        [
            Paragraph("<b>Priority</b>", styles["table_header"]),
            Paragraph("<b>Vulnerability</b>", styles["table_header"]),
            Paragraph("<b>Affected Endpoint</b>", styles["table_header"]),
            Paragraph("<b>Recommended Action</b>", styles["table_header"]),
        ]
    ]

    crit_high = [f for f in ctx["findings"] if f.severity in {"CRITICAL", "HIGH", "MEDIUM"}][:10]
    if not crit_high:
        roadmap_data.append([
            Paragraph("Routine", styles["table_cell"]),
            Paragraph("No High-Risk Flaws Detected", styles["table_cell"]),
            Paragraph(_esc(ctx["target_url"]), styles["table_cell"]),
            Paragraph("Maintain regular automated scan intervals.", styles["table_cell"]),
        ])
    else:
        for f in crit_high:
            roadmap_data.append([
                Paragraph(f.severity, styles["table_cell_bold"]),
                Paragraph(_esc(f.title[:45]), styles["table_cell"]),
                Paragraph(f"<code>{_esc(getattr(f, 'affected_url', None) or ctx['target_url'])[:35]}</code>", styles["body_mono"]),
                Paragraph(_esc(getattr(f, "recommendation", "")[:70] or "Apply security patch"), styles["table_cell"]),
            ])

    roadmap_table = Table(roadmap_data, colWidths=[content_w * 0.15, content_w * 0.30, content_w * 0.27, content_w * 0.28])
    roadmap_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ACCENT_SOFT]),
                ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(roadmap_table)
    story.append(Spacer(1, 16))

    # Methodology statement
    story.append(Paragraph("<b>Scanning Methodology & Engine Attestation</b>", styles["h3"]))
    story.append(
        Paragraph(
            "This assessment was conducted using authenticated and authorized automated security testing tooling. "
            "Engines utilized include OWASP ZAP (Zed Attack Proxy) daemon for web crawling, AJAX spidering, and passive rule inspection; "
            "ProjectDiscovery Nuclei for CVE vulnerability and configuration templating; and high-concurrency HTTP probing. "
            "Findings reflect security posture observed at test execution time.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 14))

    # Ownership & Sign-off
    story.append(Paragraph("<b>Report Ownership & Sign-Off</b>", styles["h3"]))
    story.append(Spacer(1, 5))

    scan_date_str = _fmt_dt(ctx.get("finished_at") or ctx.get("started_at"), tz, with_time=False)
    company_name = ctx.get("company_name") or "DecodeX Security Technologies"
    ownership = Table(
        [
            [
                Paragraph("<b>LEAD SECURITY ASSESSOR</b>", styles["sign_header"]),
                Paragraph("<b>SOC LEAD / REVIEWER</b>", styles["sign_header"]),
                Paragraph("<b>CISO / AUTHORIZATION</b>", styles["sign_header"]),
            ],
            [
                Paragraph(f"<b>Name:</b><br/>{_esc(ctx['prepared_by'])}", styles["sign_cell"]),
                Paragraph("<b>Name:</b><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
                Paragraph("<b>Name:</b><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
            ],
            [
                Paragraph(f"<b>Designation:</b><br/>Lead Security Assessor<br/><font size='7' color='#5B6B7C'>{_esc(company_name[:35])}</font>", styles["sign_cell"]),
                Paragraph("<b>Designation:</b><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
                Paragraph("<b>Designation:</b><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
            ],
            [
                Paragraph(f"<b>Date:</b><br/>{scan_date_str}", styles["sign_cell"]),
                Paragraph("<b>Date:</b><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
                Paragraph("<b>Date:</b><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
            ],
            [
                Paragraph("<b>Signature / Approval:</b><br/><br/><font color='#0B1F33'><b>[ Verified Digital Record ]</b></font>", styles["sign_cell"]),
                Paragraph("<b>Signature / Stamp:</b><br/><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
                Paragraph("<b>Signature / Stamp:</b><br/><br/><font color='#8A99A8'>____________________________________</font>", styles["sign_cell"]),
            ],
        ],
        colWidths=[content_w / 3.0] * 3,
        rowHeights=[24, 38, 38, 34, 52],
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
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(ownership)
    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            "This document contains proprietary security evaluation data intended solely for authorized personnel. "
            "Unauthorized distribution, copying, or dissemination is strictly prohibited.",
            styles["small_center"],
        )
    )

    def _later_pages(canvas, doc_):
        _page_footer(canvas, doc_, was_id, company_name=ctx.get("company_name", "DecodeX Security Technologies"))

    def _first_page(canvas, doc_):
        _draw_full_cover(canvas, ctx)

    doc.build(story, onFirstPage=_first_page, onLaterPages=_later_pages)
    buffer.seek(0)
    return buffer


def generate_web_scan_pdf(db, scan, *, prepared_by: str = "Manan Mandal") -> io.BytesIO:
    """Generate in-memory PDF report buffer for a web scan."""
    ctx = build_scan_context(db, scan, prepared_by=prepared_by)
    return render_web_scan_pdf(ctx)
