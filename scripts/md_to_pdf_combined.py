"""Render SentinelSOC_Combined_Guide.md -> a polished HTML page, then print to
A4 PDF using headless Edge (modern CSS, TOC, syntax-styled blocks, tables).
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "documentation" / "SentinelSOC_Combined_Guide.md"
HTML_OUT = ROOT / "documentation" / "SentinelSOC_Combined_Guide.html"
PDF_OUT = ROOT / "documentation" / "SentinelSOC_Combined_Guide.pdf"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

CSS = r"""
:root {
  --cyan: #0e7490;
  --teal: #0f766e;
  --ink: #1e293b;
  --muted: #64748b;
  --line: #e2e8f0;
  --code-bg: #0f172a;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body {
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  color: var(--ink);
  font-size: 10.5pt;
  line-height: 1.55;
  margin: 0;
}
@page {
  size: A4;
  margin: 20mm 16mm 18mm 16mm;
}
.page-break { page-break-before: always; }
.avoid-break { page-break-inside: avoid; }

/* ---------- cover ---------- */
.cover {
  page-break-after: always;
  height: 100vh;
  padding: 0;
  background: linear-gradient(150deg, #082f49 0%, #0e7490 55%, #0f766e 100%);
  color: #fff;
  border-radius: 0;
  position: relative;
}
.cover .inner { padding: 34mm 24mm; }
.cover .kicker {
  letter-spacing: 0.35em;
  text-transform: uppercase;
  font-size: 9pt;
  font-weight: 600;
  color: #67e8f9;
  margin-bottom: 14mm;
}
.cover h1 {
  font-size: 34pt;
  line-height: 1.1;
  font-weight: 700;
  margin: 0 0 6mm 0;
}
.cover .sub { font-size: 14pt; color: #cffafe; font-weight: 400; margin-bottom: 22mm; }
.cover .meta { border-top: 1px solid rgba(255,255,255,0.35); padding-top: 6mm; }
.cover .meta td { padding: 2mm 0; font-size: 10pt; }
.cover .meta b { color: #a5f3fc; }
.cover .meta .lbl { color: #e0f2fe; width: 32mm; font-weight: 600; }

/* ---------- toc ---------- */
.toc { page-break-after: always; }
.toc h2 { font-size: 20pt; color: #0e7490; margin: 0 0 5mm 0; }
.toc .toc { border: 0; padding: 0; }
.toc ul { list-style: none; padding: 0; margin: 0; }
.toc li { margin: 0 0 1mm 0; }
.toc li div { padding-left: 7mm; }
.toc ul ul { padding-left: 5mm; }
.toc ul ul li { margin: 0.6mm 0; }
.toc a { color: var(--ink); text-decoration: none; }
.toc div > a { font-weight: 700; font-size: 11.5pt; display: block; margin: 3mm 0 1mm 0; }
.toc li li a { font-size: 9.5pt; color: var(--muted); }
.toc a::before { content: "§ "; color: var(--teal); }
.toc li li a::before { content: "· "; color: #94a3b8; }
.toc a:hover { color: var(--teal); }

/* ---------- headings ---------- */
h1 {
  font-size: 20pt;
  color: #fff;
  background: linear-gradient(90deg, #0e7490, #0f766e);
  padding: 4mm 6mm;
  border-radius: 3mm;
  margin: 0 0 6mm 0;
  page-break-before: always;
}
h2 {
  font-size: 15pt;
  color: var(--teal);
  border-bottom: 2.5px solid var(--teal);
  padding-bottom: 1.5mm;
  margin: 0 0 5mm 0;
  page-break-after: avoid;
  page-break-before: always;
}
h2:first-of-type { page-break-before: auto; }
h3 {
  font-size: 12pt;
  color: var(--ink);
  margin: 7mm 0 3mm 0;
  page-break-after: avoid;
}
h4 { font-size: 10.5pt; color: var(--muted); margin: 5mm 0 2mm 0; }

/* ---------- body ---------- */
p { margin: 0 0 3.5mm 0; }
ul, ol { margin: 0 0 4mm 0; padding-left: 6mm; }
li { margin-bottom: 1mm; }
li > ul { margin-top: 1mm; }
code {
  font-family: "Cascadia Mono", "Consolas", monospace;
  font-size: 8.8pt;
  background: #f1f5f9;
  border: 1px solid #e2e8f0;
  border-radius: 1.2mm;
  padding: 0 1.2mm;
  color: #0f172a;
}
pre {
  background: var(--code-bg);
  color: #e2e8f0;
  border-radius: 2.5mm;
  padding: 4mm 5mm;
  font-family: "Cascadia Mono", "Consolas", monospace;
  font-size: 8.2pt;
  line-height: 1.45;
  overflow-x: hidden;
  white-space: pre-wrap;
  word-wrap: break-word;
  page-break-inside: avoid;
  margin: 0 0 5mm 0;
}
pre code { background: transparent; border: 0; color: inherit; padding: 0; }

/* ---------- tables ---------- */
table {
  border-collapse: collapse;
  width: 100%;
  margin: 0 0 6mm 0;
  page-break-inside: avoid;
  font-size: 9pt;
}
thead th {
  background: #0e7490;
  color: #fff;
  text-align: left;
  font-weight: 600;
  padding: 2.2mm 2.8mm;
}
tbody td {
  border: 1px solid var(--line);
  padding: 2mm 2.8mm;
  vertical-align: top;
}
tbody tr:nth-child(even) td { background: #f8fafc; }
tbody td code { font-size: 7.8pt; }

/* ---------- misc ---------- */
blockquote {
  margin: 0 0 4mm 0;
  padding: 2.5mm 4mm;
  border-left: 3px solid var(--teal);
  background: #f0fdfa;
  border-radius: 0 2mm 2mm 0;
  color: #134e4a;
}
blockquote p { margin: 0; }
hr { border: 0; border-top: 1px solid var(--line); margin: 6mm 0; }

/* ---------- footer ---------- */
footer {
  position: fixed;
  bottom: -14mm;
  left: 0;
  right: 0;
  font-size: 8pt;
  color: #94a3b8;
  text-align: center;
  border-top: 1px solid #e2e8f0;
  padding-top: 2mm;
}
"""


def build_html(md_text: str) -> str:
    # Strip the cover/front-matter and manual TOC (they are rebuilt below).
    lines = md_text.splitlines()
    start = 0
    for idx, line in enumerate(lines):
        if line.startswith("## 1. "):
            start = idx
            break
    body_md = "\n".join(lines[start:])

    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "sane_lists", "toc"],
        output_format="html5",
        extension_configs={"toc": {"toc_depth": "2-3", "permalink": False}},
    )
    html_body = md.convert(body_md)

    # TOC from the same conversion => anchor ids always match.
    toc_html = md.toc

    cover_rows = "<tr><td class=lbl>Version</td><td><b>1.0.0</b></td></tr>"
    for label, value in [
        ("Platform", "Windows 10/11 · local-first SOC"),
        ("Stack", "FastAPI + React 19 + SQLite/PostgreSQL"),
        ("Access", "Dashboard http(s)://127.0.0.1:8001 (or :8443)"),
    ]:
        cover_rows += f'<tr><td class="lbl">{label}</td><td><b>{value}</b></td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelSOC Combined Guide</title>
<style>{CSS}</style>
</head>
<body>
<div class="cover">
  <div class="inner">
    <div class="kicker">End Product · Platform Documentation</div>
    <h1>SentinelSOC</h1>
    <div class="sub">Intelligent Lightweight SOC Platform for Real-Time
    Windows Endpoint Threat Detection &amp; Incident Analysis</div>
    <table class="meta">{cover_rows}</table>
  </div>
</div>
<div class="toc">
  <h2>Contents</h2>
  {toc_html}
</div>
{html_body}
<footer>SentinelSOC · Combined Platform Guide v1.0.0</footer>
</body>
</html>"""
    return html


def main() -> None:
    md_text = SRC.read_text(encoding="utf-8")
    html = build_html(md_text)
    HTML_OUT.write_text(html, encoding="utf-8")

    profile = ROOT / ".edge-profile"
    profile.mkdir(exist_ok=True)
    cmd = [
        EDGE,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        f"--user-data-dir={profile}",
        f"--print-to-pdf={PDF_OUT}",
        "--no-pdf-header-footer",
        HTML_OUT.resolve().as_uri(),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print("EDGE_WARN:", proc.stderr[-2000:] if proc.stderr else "no stderr")
    for _ in range(30):
        if PDF_OUT.exists() and PDF_OUT.stat().st_size > 0:
            break
        time.sleep(0.2)
    if PDF_OUT.exists() and PDF_OUT.stat().st_size > 0:
        print(f"PDF written to {PDF_OUT} ({PDF_OUT.stat().st_size} bytes)")
    else:
        sys.exit("PDF was not produced")


if __name__ == "__main__":
    main()