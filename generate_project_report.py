from __future__ import annotations

import sqlite3
from collections import Counter
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = PROJECT_ROOT / "threat.db"
OUTPUT_PATH = PROJECT_ROOT / "Threat_Hunting_Platform_Report.pdf"


def read_metrics() -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    events = cur.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
    iocs = cur.execute("SELECT COUNT(*) AS count FROM iocs").fetchone()["count"]
    alerts = cur.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
    top_rules = cur.execute(
        "SELECT rule_id, COUNT(*) AS count FROM alerts GROUP BY rule_id ORDER BY count DESC"
    ).fetchall()
    top_tactics = cur.execute(
        "SELECT tactic, COUNT(*) AS count FROM alerts GROUP BY tactic ORDER BY count DESC"
    ).fetchall()
    latest_events = cur.execute(
        "SELECT timestamp, host, process, ip FROM events ORDER BY timestamp DESC LIMIT 5"
    ).fetchall()
    alert_rows = cur.execute(
        "SELECT rule_id, severity, tactic, technique_id, description, host, process, ip, event_timestamp "
        "FROM alerts ORDER BY event_timestamp DESC, id DESC"
    ).fetchall()
    conn.close()

    return {
        "events": events,
        "iocs": iocs,
        "alerts": alerts,
        "top_rules": top_rules,
        "top_tactics": top_tactics,
        "latest_events": latest_events,
        "alert_rows": alert_rows,
    }


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0B2C4D"),
            spaceAfter=18,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#123B63"),
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
            textColor=colors.HexColor("#174D7A"),
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
    styles.add(
        ParagraphStyle(
            name="SmallCenter",
            parent=styles["BodyText"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            leading=11,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#4A5E74"),
            spaceAfter=8,
        )
    )
    return styles


def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#4A5E74"))
    canvas.drawString(1.5 * cm, 1.2 * cm, "Threat Hunting Platform Report")
    canvas.drawRightString(A4[0] - 1.5 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


def flow_box(x, y, w, h, text, fill):
    items = [
        Rect(x, y, w, h, rx=8, ry=8, fillColor=fill, strokeColor=colors.HexColor("#1B3D5D"), strokeWidth=1.2),
        String(x + w / 2, y + h / 2 - 5, text, textAnchor="middle", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.white),
    ]
    return items


def arrow(x1, y1, x2, y2):
    items = [Line(x1, y1, x2, y2, strokeColor=colors.HexColor("#1B3D5D"), strokeWidth=1.2)]
    if x2 >= x1:
        head = Polygon(
            [x2, y2, x2 - 8, y2 + 4, x2 - 8, y2 - 4],
            fillColor=colors.HexColor("#1B3D5D"),
            strokeColor=colors.HexColor("#1B3D5D"),
        )
    else:
        head = Polygon(
            [x2, y2, x2 + 8, y2 + 4, x2 + 8, y2 - 4],
            fillColor=colors.HexColor("#1B3D5D"),
            strokeColor=colors.HexColor("#1B3D5D"),
        )
    items.append(head)
    return items


def build_overall_flowchart():
    d = Drawing(500, 190)
    fills = ["#174D7A", "#1E6B8D", "#2A8F7B", "#A86A1D", "#9E2F2F"]
    labels = [
        "Log File",
        "Ingestion Engine",
        "Database",
        "Rules + IOC Matching",
        "Alerts + Dashboard",
    ]
    x_positions = [10, 110, 220, 330, 430]
    for idx, x in enumerate(x_positions):
        for item in flow_box(x, 95, 70, 40, labels[idx], colors.HexColor(fills[idx])):
            d.add(item)
    for x1, x2 in [(80, 110), (190, 220), (300, 330), (410, 430)]:
        for item in arrow(x1, 115, x2, 115):
            d.add(item)
    d.add(String(250, 165, "Figure 1. End-to-end project flow", textAnchor="middle", fontName="Helvetica-Bold", fontSize=11, fillColor=colors.HexColor("#123B63")))
    d.add(String(250, 22, "The system reads activity, stores it, checks for suspicious patterns, and presents the findings.", textAnchor="middle", fontName="Helvetica", fontSize=9, fillColor=colors.HexColor("#4A5E74")))
    return d


def build_detection_flowchart():
    d = Drawing(500, 230)
    blue = colors.HexColor("#174D7A")
    teal = colors.HexColor("#2A8F7B")
    amber = colors.HexColor("#A86A1D")
    red = colors.HexColor("#9E2F2F")
    for item in flow_box(170, 170, 150, 36, "New Event Arrives", blue):
        d.add(item)
    for item in flow_box(170, 112, 150, 36, "Compare With Rules", teal):
        d.add(item)
    for item in flow_box(60, 48, 150, 36, "No Match -> Store Only", amber):
        d.add(item)
    for item in flow_box(290, 48, 150, 36, "Match -> Create Alert", red):
        d.add(item)
    for item in arrow(245, 170, 245, 148):
        d.add(item)
    for item in arrow(170, 112, 135, 84):
        d.add(item)
    for item in arrow(320, 112, 365, 84):
        d.add(item)
    d.add(String(250, 214, "Figure 2. Detection decision flow", textAnchor="middle", fontName="Helvetica-Bold", fontSize=11, fillColor=colors.HexColor("#123B63")))
    return d


def build_soc_flowchart():
    d = Drawing(500, 210)
    fills = ["#174D7A", "#2A8F7B", "#1E6B8D"]
    labels = ["Persistent Alerts", "SOC Dashboard", "Human Review / Response"]
    xs = [30, 190, 350]
    for idx, x in enumerate(xs):
        for item in flow_box(x, 90, 120, 42, labels[idx], colors.HexColor(fills[idx])):
            d.add(item)
    for item in arrow(150, 111, 190, 111):
        d.add(item)
    for item in arrow(310, 111, 350, 111):
        d.add(item)
    d.add(String(250, 170, "Figure 3. Monitoring and decision layer", textAnchor="middle", fontName="Helvetica-Bold", fontSize=11, fillColor=colors.HexColor("#123B63")))
    d.add(String(250, 30, "Stored alerts become visible to analysts through a SOC-style monitoring console.", textAnchor="middle", fontName="Helvetica", fontSize=9, fillColor=colors.HexColor("#4A5E74")))
    return d


def metric_table(metrics):
    rows = [
        ["Metric", "Current Value", "Meaning"],
        ["Events Stored", str(metrics["events"]), "Security activity records collected by the platform"],
        ["IOC Records", str(metrics["iocs"]), "Known suspicious indicators used for matching"],
        ["Alerts Stored", str(metrics["alerts"]), "Unique detections saved for analyst review"],
    ]
    table = Table(rows, colWidths=[4.2 * cm, 3.1 * cm, 8.2 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B63")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9CB3C8")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F5F8FB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("LEADING", (0, 0), (-1, -1), 12),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F5F8FB"), colors.HexColor("#EAF1F7")]),
            ]
        )
    )
    return table


def alert_table(metrics):
    rows = [["Rule", "Severity", "MITRE", "Host", "Process", "Time"]]
    for row in metrics["alert_rows"]:
        rows.append(
            [
                row["rule_id"],
                row["severity"],
                f"{row['tactic']} / {row['technique_id']}",
                row["host"],
                row["process"],
                row["event_timestamp"],
            ]
        )
    table = Table(rows, colWidths=[3.2 * cm, 2.0 * cm, 4.5 * cm, 2.3 * cm, 3.2 * cm, 3.1 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B63")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CB3C8")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FBFCFE")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FBFCFE"), colors.HexColor("#EDF3F8")]),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("LEADING", (0, 0), (-1, -1), 10.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def bullet(text, styles):
    return Paragraph(f"• {text}", styles["BulletBody"])


def build_story(metrics):
    styles = build_styles()
    story = []

    story.append(Spacer(1, 1.2 * cm))
    story.append(Paragraph("Threat Hunting Platform", styles["ReportTitle"]))
    story.append(Paragraph("Detailed Plain-English Project Report With Flowcharts", styles["SubTitle"]))
    story.append(
        Paragraph(
            "This report explains the project in language suitable for non-technical audiences. "
            "It describes the purpose of the platform, how it works, what has been built so far, "
            "what the dashboard shows, and how the project can grow in the future.",
            styles["Body"],
        )
    )
    story.append(metric_table(metrics))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Prepared for presentation and project explanation", styles["SmallCenter"]))

    story.append(PageBreak())
    story.append(Paragraph("1. Executive Summary", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "This project is a miniature threat hunting and security monitoring platform. In simple terms, "
            "it acts like a digital security assistant that reads activity logs, compares them with known warning signs, "
            "detects suspicious behaviour, stores the findings, and shows them in a monitoring console. "
            "Its main value is that it turns raw technical data into understandable security alerts.",
            styles["Body"],
        )
    )
    story.append(
        Paragraph(
            "The platform demonstrates the core ideas used in real Security Operations Centers. It does not try to replace a full enterprise SIEM, "
            "but it successfully shows the complete security workflow: collection, storage, analysis, alerting, context enrichment, and review.",
            styles["Body"],
        )
    )
    story.append(build_overall_flowchart())

    story.append(Paragraph("2. Project Goal", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The goal of the project is to help a human reviewer answer one important question: "
            "<b>Which system activities look suspicious and deserve attention first?</b> "
            "Computers generate too much activity for a person to review manually. "
            "This platform reduces that burden by scanning the data automatically and highlighting the most relevant records.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("It collects security-related activity from a log file.", styles),
            bullet("It stores that activity in a database so it can be reviewed later.", styles),
            bullet("It compares each event with known suspicious indicators such as IP addresses or malicious behaviour patterns.", styles),
            bullet("It creates alerts only when the activity matches rules that represent risk.", styles),
            bullet("It presents those alerts in a dashboard that is easier to understand than raw logs.", styles),
        ]
    )

    story.append(PageBreak())
    story.append(Paragraph("3. Main Building Blocks", styles["SectionTitle"]))
    story.append(Paragraph("3.1 Log Ingestion", styles["SubTitle"]))
    story.append(
        Paragraph(
            "The ingestion layer reads security events from a structured log file. Each event can contain details such as "
            "time, machine name, username, process name, command line, IP address, domain, and file hash. "
            "A key improvement is that the project now remembers how far it has already read into the log file. "
            "This means it can behave like a live monitor and only process new lines instead of rereading the entire file every time.",
            styles["Body"],
        )
    )
    story.append(Paragraph("3.2 IOC Matching", styles["SubTitle"]))
    story.append(
        Paragraph(
            "IOC stands for Indicator of Compromise. These are warning signs such as suspicious IP addresses, domains, or hashes. "
            "The project keeps a small local watchlist of these indicators. Whenever an event contains something from that watchlist, "
            "the system treats the activity as potentially risky.",
            styles["Body"],
        )
    )
    story.append(Paragraph("3.3 Rule Evaluation", styles["SubTitle"]))
    story.append(
        Paragraph(
            "Rules are the instructions that describe what suspicious behaviour looks like. "
            "For example, one rule looks for PowerShell running with encoded commands, because attackers often hide commands in that way. "
            "Another rule checks whether the IP address in an event matches a suspicious IP on the watchlist.",
            styles["Body"],
        )
    )
    story.append(Paragraph("3.4 Alert Persistence", styles["SubTitle"]))
    story.append(
        Paragraph(
            "When a rule matches, the platform creates an alert and saves it into the database. "
            "This is important because it creates a permanent investigation history. "
            "Without this, detections would disappear as soon as the program stopped running.",
            styles["Body"],
        )
    )
    story.append(build_detection_flowchart())

    story.append(PageBreak())
    story.append(Paragraph("4. The Database And Why It Matters", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The database is the memory of the platform. It stores the events, the suspicious indicators, the saved alerts, "
            "and the log reader position. That memory is what allows the system to behave like a real monitoring tool instead of a one-time script.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("<b>Events table:</b> keeps the activity that has been collected from logs.", styles),
            bullet("<b>IOCs table:</b> stores suspicious IP addresses, domains, and file hashes used for matching.", styles),
            bullet("<b>Alerts table:</b> stores the detections that were produced by the rules.", styles),
            bullet("<b>Ingestion state table:</b> remembers the current reading position in the log file, enabling live ingestion.", styles),
        ]
    )
    story.append(
        Paragraph(
            "The platform also includes upgrade logic for older database versions. "
            "That means if the data model changes over time, the system can add missing columns automatically instead of failing. "
            "This is a mature design choice because real software often evolves while old data must still remain usable.",
            styles["Body"],
        )
    )
    story.append(Paragraph("Current alert inventory", styles["SubTitle"]))
    story.append(alert_table(metrics))

    story.append(PageBreak())
    story.append(Paragraph("5. MITRE ATT&CK Mapping", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The project now connects each rule to MITRE ATT&CK. MITRE ATT&CK is a widely recognized framework that organizes attacker behaviour "
            "into tactics and techniques. By adding this context, the project does more than say <i>something suspicious happened</i>. "
            "It also explains the type of attacker behaviour that the alert may represent.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("The suspicious PowerShell rule is mapped to the tactic <b>Execution</b> and technique <b>T1059.001 PowerShell</b>.", styles),
            bullet("IOC communication alerts are mapped to <b>Command and Control</b>, showing that the activity may represent external attacker communication.", styles),
            bullet("This mapping makes the project easier to explain to non-technical audiences because it adds meaning and classification to alerts.", styles),
        ]
    )
    top_tactic_text = ", ".join([f"{row['tactic']} ({row['count']})" for row in metrics["top_tactics"]]) if metrics["top_tactics"] else "No tactics recorded yet"
    story.append(
        Paragraph(
            f"Based on the current database snapshot, the most visible ATT&CK tactics are: <b>{top_tactic_text}</b>.",
            styles["Body"],
        )
    )

    story.append(Paragraph("6. The SOC Dashboard", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "The web dashboard has been upgraded into a SOC-style console. "
            "Instead of showing only simple tables, it now presents a dark monitoring layout, an alert queue, summary cards, tactic rankings, "
            "severity distribution, IOC inventory, and an event timeline. The dashboard refreshes automatically every five seconds, which helps it behave like a live monitoring screen.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("It shows overall counts for events, indicators, and alerts.", styles),
            bullet("It shows the last ingestion time and the current log offset, which helps explain live monitoring.", styles),
            bullet("It keeps persistent alerts in view so a reviewer can see what matters most first.", styles),
            bullet("It shows the related MITRE ATT&CK tactic and technique for each alert.", styles),
            bullet("It surfaces top tactics and top rules to give management-style visibility into what kinds of risk are appearing.", styles),
        ]
    )
    story.append(build_soc_flowchart())

    story.append(PageBreak())
    story.append(Paragraph("7. What The Current Results Mean", styles["SectionTitle"]))
    story.append(
        Paragraph(
            f"At the time this report was generated, the platform contained <b>{metrics['events']}</b> stored events, "
            f"<b>{metrics['iocs']}</b> suspicious indicators, and <b>{metrics['alerts']}</b> stored unique alerts. "
            "This means the system is successfully completing the full security cycle from ingestion to detection and presentation.",
            styles["Body"],
        )
    )
    if metrics["top_rules"]:
        top_rules_text = ", ".join([f"{row['rule_id']} ({row['count']})" for row in metrics["top_rules"]])
        story.append(
            Paragraph(
                f"The strongest active detection patterns in the current dataset are: <b>{top_rules_text}</b>.",
                styles["Body"],
            )
        )
    story.append(Paragraph("Latest observed events", styles["SubTitle"]))
    latest_rows = [["Timestamp", "Host", "Process", "IP"]]
    for row in metrics["latest_events"]:
        latest_rows.append([row["timestamp"], row["host"], row["process"], row["ip"]])
    latest_table = Table(latest_rows, colWidths=[4.6 * cm, 3.2 * cm, 4.6 * cm, 4.2 * cm])
    latest_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B63")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CB3C8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FBFCFE"), colors.HexColor("#EDF3F8")]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(latest_table)
    story.append(
        Paragraph(
            "Some older duplicate events remain in the event history because the database existed before the newest cleanup logic was added. "
            "However, alert storage and dashboard presentation now focus on the unique security signal rather than inflated noise.",
            styles["Body"],
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("8. Why This Project Is Valuable", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "This project is valuable because it shows how raw technical activity can be converted into understandable and actionable security findings. "
            "For non-technical stakeholders, the biggest strength is that it gives a clear view of what happened, why it matters, and what pattern it fits. "
            "For technical reviewers, it demonstrates structured thinking across data ingestion, storage, rules, enrichment, alerting, and user interface design.",
            styles["Body"],
        )
    )
    story.extend(
        [
            bullet("It demonstrates automation of repetitive monitoring work.", styles),
            bullet("It provides visibility into suspicious behaviour instead of only collecting raw logs.", styles),
            bullet("It creates a review history by storing alerts in a database.", styles),
            bullet("It adds context through MITRE ATT&CK mapping, which improves explainability.", styles),
            bullet("It presents results in a format that can be shown to both technical and non-technical audiences.", styles),
        ]
    )

    story.append(Paragraph("9. Future Improvements", styles["SectionTitle"]))
    story.extend(
        [
            bullet("Add an alert details page so each detection can be investigated in depth.", styles),
            bullet("Add case management features such as open, in progress, false positive, and resolved status.", styles),
            bullet("Support Sigma rule import so the project can use industry-standard detection logic.", styles),
            bullet("Connect to live threat intelligence feeds instead of only using local sample IOC data.", styles),
            bullet("Replace timed page refresh with true real-time streaming through websockets.", styles),
            bullet("Add user authentication so access to the dashboard can be controlled.", styles),
            bullet("Add charts for trends, host rankings, and daily alert activity.", styles),
            bullet("Create MITRE ATT&CK heatmaps to show which attacker tactics are most common.", styles),
            bullet("Add alert suppression and tuning to reduce recurring low-value noise.", styles),
            bullet("Extend the platform to support multiple log sources such as authentication logs, firewall logs, or endpoint security logs.", styles),
        ]
    )
    story.append(
        Paragraph(
            "If these improvements are implemented, the project can evolve from a compact educational platform into a much stronger prototype of a real-world SOC tool.",
            styles["Body"],
        )
    )

    story.append(Paragraph("10. Closing Statement", styles["SectionTitle"]))
    story.append(
        Paragraph(
            "In plain English, this project is a security monitoring system that watches computer activity, looks for warning signs, saves the findings, "
            "and shows them in a way that helps people understand what needs attention. "
            "That is why it is a strong project for demonstrations, interviews, presentations, and non-technical discussions: it clearly shows how technology can turn large amounts of data into useful decisions.",
            styles["Body"],
        )
    )
    return story


def main():
    metrics = read_metrics()
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.8 * cm,
        title="Threat Hunting Platform Report",
        author="OpenAI Codex",
    )
    story = build_story(metrics)
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    print(f"Created {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
