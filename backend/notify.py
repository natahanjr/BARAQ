"""Real-time alert notifications (webhook + SMTP email).

A SOC that only shows a dashboard is not a SOC. This module pushes
high/critical alerts out-of-band: an optional generic webhook (JSON POST)
and/or SMTP email. Both are opt-in via configuration; failures never
interfere with the detection pipeline (everything runs on a daemon thread).
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import subprocess
import threading
import urllib.request
from email.mime.text import MIMEText

from backend.config import (
    NOTIFY_MIN_SEVERITY,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_TO,
    SMTP_USERNAME,
    TOAST_ENABLED,
    WEBHOOK_URL,
)

logger = logging.getLogger("sentinel.notify")

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _wanted(severity: str) -> bool:
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(NOTIFY_MIN_SEVERITY, 3)


def _payload(alert: dict) -> dict:
    return {
        "event": "alert.created",
        "severity": alert.get("severity"),
        "risk_level": alert.get("risk_level"),
        "risk_score": alert.get("risk_score"),
        "name": alert.get("name"),
        "mitre_id": alert.get("mitre_id"),
        "mitre_tactic": alert.get("mitre_tactic"),
        "evidence": alert.get("evidence", "")[:2000],
        "recommendation": alert.get("recommendation", "")[:1000],
        "alert_id": alert.get("id"),
        "trigger_count": alert.get("trigger_count"),
    }


def _send_webhook(alert: dict) -> None:
    if not WEBHOOK_URL:
        return
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=json.dumps(_payload(alert)).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _send_email(alert: dict) -> None:
    if not SMTP_HOST or not SMTP_TO:
        return
    body = _payload(alert)
    text = "\n".join(f"{k}: {v}" for k, v in body.items())
    msg = MIMEText(text)
    msg["Subject"] = (
        f"[SentinelSOC] {alert.get('severity', '').upper()} alert: "
        f"{alert.get('name', '')} ({alert.get('mitre_id', '')})"
    )
    msg["From"] = SMTP_FROM or SMTP_HOST
    msg["To"] = SMTP_TO
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


def _send_toast(alert: dict) -> None:
    """Windows toast notification via a small PowerShell helper (best-effort)."""
    if not TOAST_ENABLED or os.name != "nt":
        return
    title = f"SentinelSOC: {alert.get('severity', '').upper()} alert {alert.get('mitre_id', '')}"
    message = f"{alert.get('name', '')} - {alert.get('evidence', '')[:240]}"
    script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "toast.ps1"
    )
    subprocess.run(
        [
            "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
            "-File", script, "-Title", title, "-Message", message,
        ],
        timeout=8,
        capture_output=True,
        check=False,
    )


def notify_alert(alert: dict) -> None:
    """Fire webhook + email + toast for a new alert (non-blocking)."""
    if not _wanted(alert.get("severity", "")):
        return
    if not WEBHOOK_URL and not (SMTP_HOST and SMTP_TO) and not TOAST_ENABLED:
        return

    def _run():
        for sender in (_send_webhook, _send_email, _send_toast):
            try:
                sender(alert)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Notification channel failed: %s", exc)
                if isinstance(exc, subprocess.TimeoutExpired):
                    logger.warning("Windows toast timed out (suppressed)")

    threading.Thread(target=_run, daemon=True, name="sentinel-notify").start()