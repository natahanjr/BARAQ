# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the SentinelSOC packaged executable.

Build with:  venv\Scripts\pyinstaller --noconfirm --clean sentinel.spec
Output:      dist\SentinelSOC\SentinelSOC.exe  (onedir layout)
"""
from pathlib import Path

ROOT = Path(SPECPATH)

datas = [
    (str(ROOT / "backend" / "mitre" / "techniques.json"), "backend/mitre"),
    (str(ROOT / "backend" / "vulnscan" / "cves.json"), "backend/vulnscan"),
    (str(ROOT / "backend" / "detection" / "signatures.json"), "detection"),
    (str(ROOT / "frontend" / "dist"), "frontend/dist"),
    (str(ROOT / "dist" / ".env"), "seed"),
]

hiddenimports = [
    "pywintypes",
    "win32evtlog",
    "win32evtlogutil",
    "win32timezone",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
]

a = Analysis(
    [str(ROOT / "scripts" / "run_server.py")],
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
    exclude_binaries=True,
    name="SentinelSOC",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="SentinelSOC",
)
