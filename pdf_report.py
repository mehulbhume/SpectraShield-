# ~/firewall-agent/pdf_report.py

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.platypus import HRFlowable

DB_PATH = Path(__file__).parent / "edr.db"
OUTPUT_PATH = Path(__file__).parent / "edr_report.pdf"

# ── Colors ─────────────────────────────────────────────
RED    = colors.HexColor("#E74C3C")
MAROON = colors.HexColor("#922B21")
ORANGE = colors.HexColor("#E67E22")
YELLOW = colors.HexColor("#F1C40F")
GREEN  = colors.HexColor("#2ECC71")
DARK   = colors.HexColor("#1a1a2e")
LIGHT  = colors.HexColor("#f0f0f0")
BLACK  = colors.HexColor("#2b2b2b")
WHITE  = colors.white

def get_events():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return rows

def severity_color(severity):
    try:
        s = int(severity)
    except:
        return GREEN
    if s >= 9: return RED
    if s >= 7: return ORANGE
    if s >= 5: return YELLOW
    return GREEN

def generate_pdf():
    events = get_events()
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=A4,
        rightMargin=15*mm,
        leftMargin=15*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    elements = []

    # ── Title ────────────────────────────────────────────
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontSize=22,
        textColor=DARK,
        spaceAfter=4
    )
    sub_style = ParagraphStyle(
        "Sub",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=10
    )

    elements.append(Paragraph("EDR Security Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Host: AaruPC", sub_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=DARK))
    elements.append(Spacer(1, 8*mm))

    # ── Summary Stats ─────────────────────────────────────
    total    = len(events)
    critical = sum(1 for e in events if len(e) > 6 and e[6] is not None and int(e[6]) >= 9)
    high     = sum(1 for e in events if len(e) > 6 and e[6] is not None and 7 <= int(e[6]) < 9)
    medium   = sum(1 for e in events if len(e) > 6 and e[6] is not None and 5 <= int(e[6]) < 7)
    low      = sum(1 for e in events if len(e) > 6 and e[6] is not None and int(e[6]) < 5)

    summary_data = [
        ["Total Events", "Critical (9-10)", "High (7-8)", "Medium (5-6)", "Low (<5)"],
        [str(total), str(critical), str(high), str(medium), str(low)]
    ]

    summary_table = Table(summary_data, colWidths=[35*mm]*5)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), DARK),
        ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
        ("BACKGROUND", (0,1), (0,1), colors.HexColor("#3498db")),
        ("BACKGROUND", (1,1), (1,1), RED),
        ("BACKGROUND", (2,1), (2,1), ORANGE),
        ("BACKGROUND", (3,1), (3,1), YELLOW),
        ("BACKGROUND", (4,1), (4,1), GREEN),
        ("TEXTCOLOR",  (0,1), (-1,1), WHITE),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 11),
        ("BOX",        (0,0), (-1,-1), 1, DARK),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))

    elements.append(Paragraph("Summary", styles["Heading2"]))
    elements.append(summary_table)
    elements.append(Spacer(1, 8*mm))

    # ── Events Table ──────────────────────────────────────
    elements.append(Paragraph("Security Events (Last 50)", styles["Heading2"]))
    elements.append(Spacer(1, 3*mm))

    table_data = [["#", "Timestamp", "Event Type", "Source IP", "MITRE", "Severity"]]

    for e in events:
        try:
            id_       = e[0] if len(e) > 0 else ""
            ts        = e[1] if len(e) > 1 else ""
            event_type= e[2] if len(e) > 2 else ""
            src_ip    = e[3] if len(e) > 3 else ""
            tactic    = e[4] if len(e) > 4 else ""
            technique = e[5] if len(e) > 5 else ""
            severity  = e[6] if len(e) > 6 else ""

            ts_short = str(ts)[:19].replace("T", " ") if ts else "-"
            table_data.append([
                str(id_),
                ts_short,
                str(event_type),
                str(src_ip) if src_ip else "-",
                str(technique),
                str(severity)
            ])
        except Exception as ex:
            print(f"[PDFReport] Row error: {ex}")
            continue

    col_widths = [12*mm, 42*mm, 40*mm, 32*mm, 22*mm, 18*mm]
    events_table = Table(table_data, colWidths=col_widths, repeatRows=1)

    row_styles = [
        ("BACKGROUND",    (0,0), (-1,0), DARK),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("BOX",           (0,0), (-1,-1), 1, DARK),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.lightgrey),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [LIGHT, WHITE]),
    ]

    # Severity color per row
    for i, e in enumerate(events, start=1):
        try:
            severity = e[6]
            col = severity_color(severity)
            row_styles.append(("TEXTCOLOR", (5, i), (5, i), col))
            row_styles.append(("FONTNAME",  (5, i), (5, i), "Helvetica-Bold"))
        except:
            continue

    events_table.setStyle(TableStyle(row_styles))
    elements.append(events_table)
    elements.append(Spacer(1, 8*mm))

    # ── Footer ────────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    elements.append(Spacer(1, 3*mm))
    elements.append(Paragraph(
        "EDR Security Agent - AaruPC | Confidential",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=1)
    ))

    doc.build(elements)
    print(f"[PDFReport] Report generated: {OUTPUT_PATH}")

if __name__ == "__main__":
    generate_pdf()