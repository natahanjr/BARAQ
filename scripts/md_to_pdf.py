"""Convert the documentation markdown files into a single PDF via reportlab."""

from __future__ import annotations

import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "documentation"
OUT = ROOT / "documentation" / "BARAQ_Documentation.pdf"

FILES = [
    ("user_manual.md", "User Manual"),
    ("architecture.md", "Architecture"),
    ("database_schema.md", "Database Schema"),
    ("test_results.md", "Test Results"),
    ("security_evaluation_report.md", "Security Evaluation Report"),
]

ACCENT = colors.HexColor("#0e7490")
CODE_BG = colors.HexColor("#0f172a")
CODE_FG = colors.HexColor("#e2e8f0")


def strip_inline(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", text)
    return text


def add_table(flow, lines: list[str]) -> None:
    rows = []
    for line in lines:
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if set(cells) <= {"-", "---", "--", ":", ":---", ":--:", "---:"}:
            continue
        rows.append([strip_inline(c) for c in cells])
    if not rows:
        return
    ncols = max(len(r) for r in rows)
    rows = [r + [""] * (ncols - len(r)) for r in rows]
    table = Table(rows, repeatRows=1)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#334155")),
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("LEADING", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#f1f5f9")],
        ),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]
    table.setStyle(TableStyle(style))
    flow.append(table)
    flow.append(Spacer(1, 8))


def parse_md(text: str):
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"], textColor=ACCENT, fontSize=18, spaceAfter=10
    )
    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        textColor=ACCENT,
        fontSize=14,
        spaceBefore=14,
        spaceAfter=6,
    )
    h3 = ParagraphStyle(
        "H3",
        parent=styles["Heading3"],
        textColor=colors.HexColor("#0f172a"),
        fontSize=11.5,
        spaceBefore=10,
        spaceAfter=4,
    )
    body = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontSize=9.5, leading=13.5, spaceAfter=6
    )
    bullet = ParagraphStyle("Bullet", parent=body, leftIndent=14, spaceAfter=2)
    title = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=22, textColor=ACCENT, spaceAfter=4
    )

    flow: list = []
    in_code = False
    code_lines: list[str] = []
    in_table = False
    table_lines: list[str] = []
    i = 0
    lines = text.splitlines()

    def flush_code():
        nonlocal code_lines
        if code_lines:
            code = Preformatted(
                "\n".join(code_lines),
                ParagraphStyle(
                    "Code",
                    fontName="Courier",
                    fontSize=7.5,
                    leading=9.5,
                    backColor=CODE_BG,
                    textColor=CODE_FG,
                    borderPadding=6,
                    spaceBefore=4,
                    spaceAfter=8,
                ),
            )
            flow.append(code)
            code_lines = []

    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                in_code = True
            i += 1
            continue
        if in_code:
            code_lines.append(line)
            i += 1
            continue
        if line.strip().startswith("|"):
            if not in_table:
                in_table = True
                table_lines = []
            table_lines.append(line)
            i += 1
            continue
        if in_table:
            add_table(flow, table_lines)
            in_table = False
            table_lines = []
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            content = strip_inline(stripped.lstrip("#").strip())
            if level == 1:
                flow.append(Paragraph(content, title if i == 0 else h1))
            elif level == 2:
                flow.append(Paragraph(content, h2))
            else:
                flow.append(Paragraph(content, h3))
        elif re.match(r"^[-*] ", stripped):
            items: list[str] = []
            while i < len(lines) and re.match(r"^\s*[-*] ", lines[i].strip()):
                items.append(strip_inline(lines[i].strip()[2:].strip()))
                i += 1
            flow.append(
                ListFlowable(
                    [ListItem(Paragraph(it, bullet), leftIndent=12) for it in items],
                    bulletType="bullet",
                    start="circle",
                    bulletFontSize=6,
                    leftIndent=16,
                )
            )
            flow.append(Spacer(1, 3))
            continue
        else:
            flow.append(Paragraph(strip_inline(stripped), body))
        i += 1
    if in_table:
        add_table(flow, table_lines)
    flush_code()
    return flow


def build() -> None:
    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="BARAQ Documentation",
        author="BARAQ",
    )
    cover_style = ParagraphStyle(
        "Cover", fontSize=13, leading=18, alignment=1, spaceAfter=12
    )
    flow = [
        Paragraph(
            "BARAQ", ParagraphStyle("C", fontSize=30, alignment=1, textColor=ACCENT)
        ),
        Paragraph("Documentation Package", cover_style),
        Spacer(1, 10),
    ]

    for fname, label in FILES:
        text = (DOCS / fname).read_text(encoding="utf-8")
        flow.append(PageBreak())
        flow.append(
            Paragraph(
                label,
                ParagraphStyle("Part", fontSize=16, textColor=ACCENT, spaceAfter=8),
            )
        )
        flow.append(Spacer(1, 4))
        flow += parse_md(text)

    doc.build(flow)
    print(f"PDF written to {OUT}")


if __name__ == "__main__":
    build()
