from __future__ import annotations

import sqlite3
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = PROJECT_ROOT / "threat.db"
OUTPUT_PATH = PROJECT_ROOT / "Threat_Hunting_Platform_User_Guide.pdf"


def load_metrics() -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    data = {
        "events": cur.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"],
        "alerts": cur.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"],
        "iocs": cur.execute("SELECT COUNT(*) AS count FROM iocs").fetchone()["count"],
        "feeds": cur.execute("SELECT COUNT(*) AS count FROM feed_sources").fetchone()["count"],
        "suppression_rules": cur.execute("SELECT COUNT(*) AS count FROM suppression_rules").fetchone()["count"],
        "latest_alerts": cur.execute(
            "SELECT rule_id, severity, status, host, source_type, source_name FROM alerts ORDER BY event_timestamp DESC, id DESC LIMIT 5"
        ).fetchall(),
    }
    conn.close()
    return data


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="GuideTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0D3357"),
            spaceAfter=14,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#12456E"),
            spaceBefore=12,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SubTitle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#1D5F92"),
            spaceBefore=8,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Body",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10.5,
            leading=15,
            alignment=TA_JUSTIFY,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BulletBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10.5,
            leading=15,
            alignment=TA_LEFT,
            leftIndent=14,
            firstLineIndent=-10,
            spaceAfter=4,
        )
    )
    return styles


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#4A627A"))
    canvas.drawString(1.5 * cm, 1.1 * cm, "Threat Hunting Platform User Guide")
    canvas.drawRightString(A4[0] - 1.5 * cm, 1.1 * cm, f"Page {doc.page}")
    canvas.restoreState()


def flow_box(x, y, w, h, label, fill):
    return [
        Rect(x, y, w, h, rx=8, ry=8, fillColor=fill, strokeColor=colors.HexColor("#1C4567"), strokeWidth=1.1),
        String(x + w / 2, y + h / 2 - 5, label, textAnchor="middle", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.white),
    ]


def arrow(x1, y1, x2, y2):
    elements = [Line(x1, y1, x2, y2, strokeColor=colors.HexColor("#1C4567"), strokeWidth=1.1)]
    if x2 >= x1:
        head = Polygon([x2, y2, x2 - 8, y2 + 4, x2 - 8, y2 - 4], fillColor=colors.HexColor("#1C4567"), strokeColor=colors.HexColor("#1C4567"))
    else:
        head = Polygon([x2, y2, x2 + 8, y2 + 4, x2 + 8, y2 - 4], fillColor=colors.HexColor("#1C4567"), strokeColor=colors.HexColor("#1C4567"))
    elements.append(head)
    return elements


def login_flow():
    drawing = Drawing(500, 180)
    colorset = [colors.HexColor("#174D7A"), colors.HexColor("#2B7A78"), colors.HexColor("#A36A1C"), colors.HexColor("#9D3131")]
    labels = ["Open App", "Login", "Dashboard", "Investigate Alerts"]
    xs = [20, 145, 270, 395]
    for idx, x in enumerate(xs):
        for item in flow_box(x, 80, 85, 40, labels[idx], colorset[idx]):
            drawing.add(item)
    for start, end in [(105, 145), (230, 270), (355, 395)]:
        for item in arrow(start, 100, end, 100):
            drawing.add(item)
    drawing.add(String(250, 152, "Figure 1. Basic user journey", textAnchor="middle", fontName="Helvetica-Bold", fontSize=11, fillColor=colors.HexColor("#12456E")))
    return drawing


def dashboard_map():
    drawing = Drawing(500, 240)
    blocks = [
        (20, 165, 460, 38, "Top Summary Banner", "#174D7A"),
        (20, 118, 225, 34, "Active Alerts", "#9D3131"),
        (255, 118, 225, 34, "IOC Feeds + Suppression Rules", "#2B7A78"),
        (20, 60, 225, 34, "MITRE Heatmap Summary", "#A36A1C"),
        (255, 60, 225, 34, "Source Coverage", "#1D5F92"),
    ]
    for x, y, w, h, label, fill in blocks:
        for item in flow_box(x, y, w, h, label, colors.HexColor(fill)):
            drawing.add(item)
    drawing.add(String(250, 220, "Figure 2. Dashboard layout map", textAnchor="middle", fontName="Helvetica-Bold", fontSize=11, fillColor=colors.HexColor("#12456E")))
    return drawing


def ingestion_flow():
    drawing = Drawing(500, 220)
    labels = ["Local Logs", "Webhook /api/ingest_logs", "Events Table", "Rule Evaluator", "Alerts Table", "Dashboard"]
    xs = [10, 95, 190, 285, 380, 205]
    ys = [130, 130, 130, 130, 130, 42]
    fills = ["#174D7A", "#1D5F92", "#2B7A78", "#A36A1C", "#9D3131", "#5E4FA2"]
    widths = [70, 88, 70, 78, 70, 88]
    for idx, label in enumerate(labels):
        for item in flow_box(xs[idx], ys[idx], widths[idx], 36, label, colors.HexColor(fills[idx])):
            drawing.add(item)
    for start, end in [(80, 95), (183, 190), (260, 285), (363, 380)]:
        for item in arrow(start, 148, end, 148):
            drawing.add(item)
    for item in arrow(415, 130, 250, 78):
        drawing.add(item)
    drawing.add(String(250, 198, "Figure 3. Log ingestion and alert generation flow", textAnchor="middle", fontName="Helvetica-Bold", fontSize=11, fillColor=colors.HexColor("#12456E")))
    return drawing


def bullet(text, styles):
    return Paragraph(f"• {text}", styles["BulletBody"])


def metrics_table(metrics):
    rows = [
        ["Item", "Current Value", "What It Means"],
        ["Events", str(metrics["events"]), "All ingested log records currently stored in the system"],
        ["Alerts", str(metrics["alerts"]), "Unique detections currently available for review"],
        ["IOCs", str(metrics["iocs"]), "Indicators of compromise used for matching"],
        ["Feed Sources", str(metrics["feeds"]), "Configured external threat intelligence sources"],
        ["Suppression Rules", str(metrics["suppression_rules"]), "Rules that silence low-value repeated alerts"],
    ]
    table = Table(rows, colWidths=[4 * cm, 3 * cm, 9.2 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12456E")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CB3C8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F5F8FB"), colors.HexColor("#EAF1F7")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ]
        )
    )
    return table


def latest_alerts_table(metrics):
    rows = [["Rule", "Severity", "Status", "Host", "Source"]]
    for row in metrics["latest_alerts"]:
        rows.append([row["rule_id"], row["severity"], row["status"], row["host"], f"{row['source_type']}/{row['source_name']}"])
    table = Table(rows, colWidths=[4 * cm, 2.1 * cm, 3 * cm, 3.2 * cm, 5.2 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12456E")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CB3C8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FBFCFE"), colors.HexColor("#EDF3F8")]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    return table


def build_story(metrics):
    styles = build_styles()
    story = []

    story.append(Spacer(1, 1.1 * cm))
    story.append(Paragraph("Threat Hunting Platform", styles["GuideTitle"]))
    story.append(Paragraph("Detailed User Guide And Dashboard Explanation", styles["SubTitle"]))
    story.append(
        Paragraph(
            "This guide explains how to use the platform from the point of view of a normal user or project presenter. "
            "It covers login, dashboard navigation, alert investigation, analytics, Sigma import, suppression rules, IOC feeds, "
            "and live ingestion so that you can confidently explain each page and each major dashboard section.",
            styles["Body"],
        )
    )
    story.append(metrics_table(metrics))
    story.append(Spacer(1, 0.4 * cm))
    story.append(login_flow())

    story.append(PageBreak())
    story.append(Paragraph("1. What This Platform Does", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The Threat Hunting Platform is a small SOC-style monitoring system. It collects security logs, stores them in a database, "
            "checks them against rules and IOC watchlists, creates alerts when suspicious activity is found, and then shows those alerts in a dashboard. "
            "The dashboard is not only for viewing alerts; it also supports investigation, case management, Sigma imports, suppression tuning, and IOC feed synchronization.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("If a suspicious IP address appears in a log, the platform can generate an alert.", styles),
            bullet("If PowerShell is used in a suspicious way, the platform can flag it.", styles),
            bullet("If live logs are sent through the webhook endpoint, they can be ingested immediately.", styles),
        ]
    )

    story.append(Paragraph("2. How To Start Using The Platform", styles["SectionTitle"]))
    story.append(Paragraph("2.1 Start The App", styles["SubTitle"]))
    story.append(
        Paragraph(
            "From the project root, run the Flask application. Once it is running, open the local browser address shown by Flask, "
            "usually <b>http://127.0.0.1:5000/</b>.",
            styles["Body"],
        )
    )
    story.append(Paragraph("2.2 Login", styles["SubTitle"]))
    story.append(
        Paragraph(
            "The first screen is the login page. For the current prototype, the default credentials are <b>admin / admin123</b>. "
            "Once you log in, you are redirected to the main SOC dashboard.",
            styles["Body"],
        )
    )
    story.append(Paragraph("2.3 Main Navigation", styles["SubTitle"]))
    story.extend(
        [
            bullet("Dashboard: the main SOC console page.", styles),
            bullet("Analytics: trend and MITRE views.", styles),
            bullet("Sigma Import: upload Sigma rules and convert them into local detections.", styles),
            bullet("Logout: end the session.", styles),
        ]
    )

    story.append(PageBreak())
    story.append(Paragraph("3. Dashboard Overview", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The dashboard is the main working screen of the platform. It is designed to act like a compact SOC console. "
            "Its purpose is to show the most important security information first and then provide actions for investigation and tuning.",
            styles["Body"],
        )
    )
    story.append(dashboard_map())

    story.append(Paragraph("3.1 Top Summary Banner", styles["SubTitle"]))
    story.append(
        Paragraph(
            "At the top of the page, the dashboard shows a banner with the platform identity and quick live counters. "
            "This area tells you the current status of the system at a glance.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("Last ingest: shows the last time logs were ingested into the system.", styles),
            bullet("Events: shows the total number of stored log events.", styles),
            bullet("Alerts: shows the total number of currently stored alerts.", styles),
        ]
    )

    story.append(Paragraph("3.2 Summary Cards", styles["SubTitle"]))
    story.extend(
        [
            bullet("Total Alerts: the number of active stored detections.", styles),
            bullet("High Or Above: the number of alerts whose severity is high or critical. This helps prioritize urgent cases.", styles),
        ]
    )

    story.append(Paragraph("3.3 Active Alerts Panel", styles["SubTitle"]))
    story.append(
        Paragraph(
            "This is one of the most important parts of the dashboard. Each alert card represents a detection that deserves analyst attention.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("Rule ID: the detection name, such as `ioc_ip_match` or `suspicious_powershell`.", styles),
            bullet("Severity badge: shows how serious the alert is.", styles),
            bullet("Status badge: shows case workflow status such as Open or Resolved.", styles),
            bullet("Technique badge: shows the MITRE technique when available.", styles),
            bullet("Description: explains why the alert was triggered.", styles),
            bullet("Host and Source: show where the alert came from.", styles),
            bullet("Assigned / Suppressed: show analyst assignment and whether the alert is currently suppressed.", styles),
            bullet("Open investigation: takes you to the alert detail page.", styles),
        ]
    )

    story.append(Paragraph("3.4 IOC Feeds Panel", styles["SubTitle"]))
    story.append(
        Paragraph(
            "The IOC Feeds section is used to manage external threat intelligence connectivity. "
            "It lists configured feed sources and provides a button to synchronize them.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("Sync Live Threat Intel Feeds: manually triggers feed synchronization.", styles),
            bullet("Name: the name of the feed source.", styles),
            bullet("Type: what kind of IOC the feed provides, such as IP or domain.", styles),
            bullet("Enabled: shows whether the feed is active.", styles),
        ]
    )

    story.append(Paragraph("3.5 Suppression Rules Panel", styles["SubTitle"]))
    story.append(
        Paragraph(
            "Suppression rules are used to reduce low-value repeated alerts. "
            "They are especially useful when a rule is technically correct but too noisy in practice.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("Rule name: a human-readable label for the suppression logic.", styles),
            bullet("Alert rule id: the rule to target, for example `ioc_ip_match`.", styles),
            bullet("Field name and field value: define what should be matched and suppressed.", styles),
            bullet("Reason: explains why the alert is being suppressed.", styles),
            bullet("Create Suppression Rule: saves the suppression to the database.", styles),
        ]
    )

    story.append(Paragraph("3.6 MITRE Heatmap Summary", styles["SubTitle"]))
    story.append(
        Paragraph(
            "This section groups alerts by MITRE ATT&CK tactic and severity. "
            "It helps the user understand what kind of adversary behaviour is appearing most often.",
            styles["Body"],
        )
    )

    story.append(Paragraph("3.7 Source Coverage", styles["SubTitle"]))
    story.append(
        Paragraph(
            "This section explains where alerts are coming from, for example endpoint logs, firewall logs, authentication logs, or cloud/webhook sources. "
            "It is useful for understanding which data sources are generating the most important detections.",
            styles["Body"],
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("4. Alert Investigation Page", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "When you click <b>Open investigation</b> on an alert card, the platform opens the alert detail page. "
            "This page is where an analyst examines the alert more closely and updates case information.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("Rule ID, severity, and status appear at the top for quick context.", styles),
            bullet("MITRE Tactic and MITRE Technique explain the ATT&CK mapping.", styles),
            bullet("Host, user, process, IP, domain, file hash, and command line show the full technical context.", styles),
            bullet("Source tells you which log source created the event.", styles),
            bullet("Suppressed shows whether the alert is currently muted by a suppression rule.", styles),
        ]
    )
    story.append(Paragraph("4.1 Case Management Section", styles["SubTitle"]))
    story.extend(
        [
            bullet("Status dropdown: choose Open, In Progress, False Positive, or Resolved.", styles),
            bullet("Assigned To: record which analyst owns the case.", styles),
            bullet("Analyst Notes: store your investigation comments.", styles),
            bullet("Save Case Update: writes the case changes to the database.", styles),
        ]
    )
    story.append(Paragraph("4.2 Related Event Section", styles["SubTitle"]))
    story.append(
        Paragraph(
            "This part shows the original event that caused the alert. It includes the raw payload so that the user can see the original log content exactly as it was ingested.",
            styles["Body"],
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("5. Analytics Page", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The Analytics page is meant for trend review rather than alert-by-alert investigation. "
            "It helps users understand patterns in the stored detections and events.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("Alert Trend: shows how many alerts were created on each date.", styles),
            bullet("Top Hosts: shows which systems appear most often in the dataset.", styles),
            bullet("MITRE ATT&CK Heatmap: summarizes tactics and severity distributions in one place.", styles),
        ]
    )

    story.append(Paragraph("6. Sigma Import Page", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The Sigma Import page is for detection engineering. Sigma is an industry-standard format for security rules. "
            "This page allows the user to upload a Sigma YAML file and convert supported detections into local hunting rules.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("Choose a `.yml` or `.yaml` Sigma file.", styles),
            bullet("Click Import Sigma Rules.", styles),
            bullet("The platform converts supported field-based detections into local rules and stores them in `hunting_rules.yml`.", styles),
        ]
    )

    story.append(Paragraph("7. Live Log Ingestion", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The platform can ingest logs in two ways: from local files and from live HTTP webhook requests. "
            "The webhook mode is designed to support cloud log drains from platforms such as Vercel.",
            styles["Body"],
        )
    )
    story.append(ingestion_flow())
    story.extend(
        [
            bullet("Local file ingestion reads all `.log` files from `data/logs`.", styles),
            bullet("Webhook ingestion uses `POST /api/ingest_logs`.", styles),
            bullet("Webhook requests must include `X-API-Key`.", styles),
            bullet("Optional headers `X-Source-Name` and `X-Source-Type` help label the source.", styles),
            bullet("After webhook ingestion, the same rule engine and alert persistence logic runs immediately.", styles),
        ]
    )

    story.append(Paragraph("8. Websocket Live Updates", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The dashboard also attempts to open a websocket connection on `/ws/live`. "
            "When available, the dashboard updates its top counters automatically without requiring a full page reload.",
            styles["Body"],
        )
    )

    story.append(Paragraph("9. Recommended Usage Workflow", styles["SectionTitle"]))
    story.extend(
        [
            bullet("Log in with the analyst account.", styles),
            bullet("Review the dashboard counters and active alerts first.", styles),
            bullet("Open important alerts one by one and update case status.", styles),
            bullet("Use analyst notes to document findings.", styles),
            bullet("Create suppression rules if a low-value alert keeps repeating.", styles),
            bullet("Use Analytics to explain trends and MITRE coverage.", styles),
            bullet("Use Sigma Import to add more detections.", styles),
            bullet("Use IOC Feed Sync to refresh external threat intelligence.", styles),
            bullet("Use the ingestion API for live cloud log delivery.", styles),
        ]
    )

    story.append(Paragraph("10. Current Snapshot", styles["SectionTitle"]))
    story.append(metrics_table(metrics))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Latest Stored Alerts", styles["SubTitle"]))
    story.append(latest_alerts_table(metrics))

    story.append(PageBreak())
    story.append(Paragraph("11. Conclusion", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "This platform can now be used as both a technical security project and a demonstrable SOC workflow prototype. "
            "The dashboard is designed to guide users from visibility to investigation and then to tuning. "
            "If you understand the parts explained in this guide, you can confidently use the platform and also explain each section to teachers, interviewers, or non-technical stakeholders.",
            styles["Body"],
        )
    )

    return story


def main():
    metrics = load_metrics()
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.8 * cm,
        title="Threat Hunting Platform User Guide",
        author="OpenAI Codex",
    )
    story = build_story(metrics)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(f"Created {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
