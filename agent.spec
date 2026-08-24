# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller ONE-FILE spec for the BARAQ fleet agent (BARAQAgent.exe).

Build with:  venv\Scripts\pyinstaller --noconfirm --clean agent.spec
Output:      dist\BARAQAgent.exe  (single file, ~200 MB)

The agent bundles the same collectors as the server, so the one-file
executable is a complete telemetry client. Run it with:

    BARAQAgent.exe --server https://central:8443 --key <agent-key>
    BARAQAgent.exe --install --server https://central:8443 --key <agent-key>
"""
from pathlib import Path

ROOT = Path(SPECPATH)

datas = [
    (str(ROOT / "backend" / "mitre" / "techniques.json"), "backend/mitre"),
    (str(ROOT / "backend" / "vulnscan" / "cves.json"), "backend/vulnscan"),
    (str(ROOT / "backend" / "detection" / "signatures.json"), "detection"),
]

hiddenimports = [
    "backend.config",
    "backend.collectors",
    "backend.collectors.base",
    "backend.collectors.eventlog",
    "backend.collectors.powershell",
    "backend.collectors.process",
    "backend.collectors.network",
    "backend.collectors.sysmon",
    "backend.collectors.dns_http",
    "backend.collectors.email",
    "backend.collectors.usb",
    "backend.collectors.malware",
    "backend.collectors.vulnscan",
    "backend.vulnscan.engine",
    "backend.vulnscan.inventory",
    "scripts.linux_collect",
    "pywintypes",
    "win32evtlog",
    "win32evtlogutil",
    "win32timezone",
    "win32security",
    "win32file",
    "win32net",
    "win32process",
]

a = Analysis(
    [str(ROOT / "scripts" / "agent.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests", "documentation"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    exclude_binaries=False,
    name="BARAQAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)