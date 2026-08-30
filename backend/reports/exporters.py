"""Report exporters: JSON, CSV, HTML, PDF (reportlab)."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime

from backend.config import REPORT_DIR

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    HAS_REPORTLAB = True
except ImportError:  # pragma: no cover
    HAS_REPORTLAB = False


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S")


def export_json(context: dict) -> tuple[str, str]:
    name = f"{context['title'].lower().replace(' ', '_')}_{_stamp()}.json"
    path = REPORT_DIR / name
    path.write_text(json.dumps(context, indent=2, default=str), encoding="utf-8")
    return str(path), "json"


def export_csv(context: dict) -> tuple[str, str]:
    """Flatten alerts into a CSV (one row per alert)."""
    name = f"{context['title'].lower().replace(' ', '_')}_{_stamp()}.csv"
    path = REPORT_DIR / name
    rows = context.get("alerts") or context.get("top_threats") or []
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=list(rows[0].keys()) if rows else ["name"]
        )
        writer.writeheader()
        writer.writerows(rows)
    return str(path), "csv"


def export_html(context: dict) -> tuple[str, str]:
    name = f"{context['title'].lower().replace(' ', '_')}_{_stamp()}.html"
    path = REPORT_DIR / name
    body = _render_html(context)
    path.write_text(body, encoding="utf-8")
    return str(path), "html"


def _render_html(context: dict) -> str:
    summary = context.get("summary", {})
    score = context.get("security_score", summary.get("security_score", 0))

    alert_rows = ""
    for a in context.get("alerts", context.get("top_threats", [])):
        alert_rows += (
            "<tr>"
            f"<td>{a.get('name', '')}</td>"
            f"<td>{a.get('severity', '')}</td>"
            f"<td>{a.get('mitre_id', '')}</td>"
            f"<td>{a.get('mitre_tactic', '')}</td>"
            f"<td>{a.get('status', '')}</td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{context['title']}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2em; color: #1f2937; background: #fff; }}
  h1 {{ color: #0f172a; border-bottom: 3px solid #2563eb; padding-bottom: .4em; }}
  h2 {{ color: #1e3a8a; margin-top: 1.6em; }}
  .score {{ font-size: 2.6em; font-weight: 700; color: #2563eb; }}
  .risk {{ display: inline-block; padding: .3em .9em; border-radius: 4px; color: #fff; background: #dc2626; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: .8em; }}
  th, td {{ border: 1px solid #e5e7eb; padding: .5em .7em; text-align: left; font-size: .92em; }}
  th {{ background: #f1f5f9; }}
  .meta {{ color: #64748b; font-size: .9em; }}
  .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1em 1.4em; margin: 1em 0; }}
</style>
</head>
<body>
<h1>{context['title']}</h1>
<p class="meta">Generated: {context.get('generated_at', '')} | Period: {context.get('period', '')}</p>
<div class="card">
  <span class="score">{score:.1f}</span> / 100
  <span class="risk">{context.get('risk_level', 'N/A')} RISK</span>
  <p>{context.get('risk_description', '')}</p>
  <p>Total events: {summary.get('total_events', 0)} | Open alerts: {summary.get('active_alerts', 0)} | Critical threats: {summary.get('critical_threats', 0)} | System: {summary.get('system_status', 'N/A')}</p>
</div>
<h2>Threat Summary</h2>
<table>
<tr><th>Threat</th><th>Severity</th><th>MITRE</th><th>Tactic</th><th>Status</th></tr>
{alert_rows or '<tr><td colspan="5">No open alerts.</td></tr>'}
</table>
<h2>Severity Distribution</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{''.join(f'<tr><td>{d["severity"]}</td><td>{d["count"]}</td></tr>' for d in context.get('severity_distribution', []))}
</table>
<h2>MITRE ATT&CK Coverage</h2>
{'<ul>' + ''.join(f'<li><b>{c["tactic"]}:</b> {", ".join(c["techniques"])}</li>' for c in context.get('mitre_coverage', [])) + '</ul>'}
<p class="meta">BARAQ - Intelligent Lightweight SOC Platform</p>
</body>
</html>"""


def export_pdf(context: dict) -> tuple[str, str]:
    if not HAS_REPORTLAB:
        return export_html(context)
    name = f"{context['title'].lower().replace(' ', '_')}_{_stamp()}.pdf"
    path = REPORT_DIR / name

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "BARAQTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=4,
    )
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], textColor=colors.HexColor("#1e3a8a")
    )
    meta_style = ParagraphStyle(
        "Meta",
        parent=styles["Normal"],
        textColor=colors.HexColor("#64748b"),
        fontSize=9,
    )

    summary = context.get("summary", {})
    score = context.get("security_score", summary.get("security_score", 0))
    risk = context.get("risk_level", "N/A")

    story = [
        Paragraph("BARAQ", title_style),
        Paragraph(
            context["title"],
            ParagraphStyle(
                "Sub",
                parent=styles["Title"],
                fontSize=13,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#2563eb"),
            ),
        ),
        Spacer(1, 6),
        Paragraph(
            f"Generated: {context.get('generated_at', '')} | Period: {context.get('period', '')}",
            meta_style,
        ),
        Spacer(1, 10),
        Table(
            [
                ["Security Score", f"{score:.1f} / 100"],
                ["Risk Level", f"{risk} - {context.get('risk_description', '')}"],
                ["Total Events", str(summary.get("total_events", 0))],
                ["Open Alerts", str(summary.get("active_alerts", 0))],
                ["Critical Threats", str(summary.get("critical_threats", 0))],
                ["System Status", str(summary.get("system_status", "N/A"))],
            ],
            colWidths=[50 * mm, 110 * mm],
        ),
        Spacer(1, 10),
        Paragraph("Threat Summary", h2),
    ]

    alerts = context.get("alerts", context.get("top_threats", []))
    if alerts:
        data = [["Threat", "Severity", "MITRE", "Tactic", "Status"]]
        for a in alerts:
            data.append(
                [
                    a.get("name", ""),
                    a.get("severity", ""),
                    a.get("mitre_id", ""),
                    a.get("mitre_tactic", ""),
                    a.get("status", ""),
                ]
            )
        table = Table(data, colWidths=[58 * mm, 20 * mm, 20 * mm, 30 * mm, 20 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)
    else:
        story.append(Paragraph("No open alerts at generation time.", styles["Normal"]))

    # MITRE coverage
    story.append(Spacer(1, 8))
    story.append(Paragraph("MITRE ATT&CK Coverage", h2))
    for c in context.get("mitre_coverage", []):
        story.append(
            Paragraph(
                f"<b>{c['tactic']}:</b> " + ", ".join(c["techniques"]), styles["Normal"]
            )
        )

    # Technical detail
    if context.get("alerts"):
        story.append(PageBreak())
        story.append(Paragraph("Technical Detail - Evidence & Recommendations", h2))
        for a in context["alerts"]:
            story.append(Paragraph(f"#{a['id']} {a['name']} ({a['severity']})", h2))
            story.append(
                Paragraph(
                    f"<b>Description:</b> {a.get('description', '')}", styles["Normal"]
                )
            )
            story.append(
                Paragraph(
                    f"<b>MITRE:</b> {a.get('mitre_id', '')} - {a.get('mitre_name', '')} ({a.get('mitre_tactic', '')})",
                    styles["Normal"],
                )
            )
            story.append(
                Paragraph(f"<b>Evidence:</b> {a.get('evidence', '')}", styles["Normal"])
            )
            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> {a.get('recommendation', '')}",
                    styles["Normal"],
                )
            )
            ev = a.get("events", [])
            if ev:
                ev_data = [["Time", "Event", "User", "Category", "Risk"]]
                for e in ev[:15]:
                    ev_data.append(
                        [
                            e.get("timestamp", "")[:19],
                            e.get("event_id", ""),
                            e.get("user", ""),
                            e.get("category", ""),
                            e.get("risk", ""),
                        ]
                    )
                et = Table(
                    ev_data, colWidths=[48 * mm, 16 * mm, 30 * mm, 30 * mm, 16 * mm]
                )
                et.setStyle(
                    TableStyle(
                        [
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                            ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ]
                    )
                )
                story.append(et)
            story.append(Spacer(1, 6))

    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "BARAQ - Intelligent Lightweight SOC Platform for Real-Time Windows Threat Detection",
            meta_style,
        )
    )
    doc.build(story)
    return str(path), "pdf"


EXPORTERS = {
    "json": export_json,
    "csv": export_csv,
    "html": export_html,
    "pdf": export_pdf,
}


def export_report(context: dict, fmt: str) -> tuple[str, str]:
    if fmt not in EXPORTERS:
        raise ValueError(f"Unsupported format {fmt!r}. Choose from {list(EXPORTERS)}")
    return EXPORTERS[fmt](context)
