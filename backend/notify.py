"""Real-time alert notifications (webhook + SMTP + Telegram + toast).

A SOC that only shows a dashboard is not a SOC. This module pushes
high/critical alerts out-of-band: a webhook (generic JSON, Slack- and
Teams-formatted when the URL matches), SMTP email, Telegram bot push and a
Windows toast. All are opt-in via configuration; failures never interfere
with the detection pipeline (everything runs on a daemon thread).
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
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
    SMTP_STARTTLS,
    SMTP_TO,
    SMTP_USERNAME,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    TOAST_ENABLED,
    WEBHOOK_URL,
)

logger = logging.getLogger("baraq.notify")

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


def _slack_payload(alert: dict) -> dict:
    body = _payload(alert)
    color = {"low": "#f0ad4e", "medium": "#f39c12", "high": "#e67e22", "critical": "#e74c3c"}.get(
        body.get("severity", ""), "#95a5a6"
    )
    lines = "\n".join(
        f"*{k}:* {v}" for k, v in body.items() if v not in (None, "")
    )
    return {
        "attachments": [
            {
                "color": color,
                "fallback": f"[BARAQ] {body.get('severity','').upper()} "
                            f"{body.get('name','')} ({body.get('mitre_id','')})",
                "title": f"BARAQ alert #{body.get('alert_id')} - {body.get('name','')}",
                "text": lines,
                "mrkdwn_in": ["text"],
            }
        ]
    }


def _teams_payload(alert: dict) -> dict:
    body = _payload(alert)
    color = {"low": "warning", "medium": "warning", "high": "attention", "critical": "attention"}.get(
        body.get("severity", ""), "accent"
    )
    facts = [
        {"name": k, "value": str(v)}
        for k, v in body.items()
        if v not in (None, "")
    ]
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"BARAQ alert {body.get('name','')}",
        "title": f"BARAQ alert #{body.get('alert_id')} - {body.get('name','')}",
        "text": body.get("evidence", ""),
        "sections": [{"facts": facts}],
    }


def _send_webhook(alert: dict) -> None:
    if not WEBHOOK_URL:
        return
    url = WEBHOOK_URL.lower()
    if "hooks.slack.com" in url:
        payload = _slack_payload(alert)
    elif "webhook.office.com" in url or "outlook.office.com" in url:
        payload = _teams_payload(alert)
    else:
        payload = _payload(alert)
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _send_telegram(alert: dict) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    body = _payload(alert)
    text = (
        f"\U0001f6a8 [BARAQ] {body.get('severity','').upper()} alert "
        f"#{body.get('alert_id')} - {body.get('name','')} "
        f"({body.get('mitre_id','')})\n"
        f"Score: {body.get('risk_score')} | {body.get('mitre_tactic','')}\n"
        f"{body.get('evidence','')[:900]}"
    )
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=json.dumps(
            {"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_notification": False}
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _send_email(alert: dict) -> None:
    if not SMTP_HOST or not SMTP_TO:
        return
    if not SMTP_STARTTLS:
        logger.warning(
            "SMTP STARTTLS is disabled: alert email will be sent in cleartext "
            "(enable BARAQ_SMTP_STARTTLS in production)"
        )
    body = _payload(alert)
    text = "\n".join(f"{k}: {v}" for k, v in body.items())
    msg = MIMEText(text)
    msg["Subject"] = (
        f"[BARAQ] {alert.get('severity', '').upper()} alert: "
        f"{alert.get('name', '')} ({alert.get('mitre_id', '')})"
    )
    msg["From"] = SMTP_FROM or SMTP_HOST
    msg["To"] = SMTP_TO
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_STARTTLS:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


def _send_toast(alert: dict) -> None:
    """Windows toast notification via a small PowerShell helper (best-effort)."""
    if not TOAST_ENABLED or os.name != "nt":
        return
    title = f"BARAQ: {alert.get('severity', '').upper()} alert {alert.get('mitre_id', '')}"
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
    """Fire webhook + email + telegram + toast for a new alert (non-blocking)."""
    if not _wanted(alert.get("severity", "")):
        return
    if not (WEBHOOK_URL or (SMTP_HOST and SMTP_TO) or (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) or TOAST_ENABLED):
        return

    def _run():
        for sender in (_send_webhook, _send_email, _send_telegram, _send_toast):
            try:
                sender(alert)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Notification channel failed: %s", exc)
                if isinstance(exc, subprocess.TimeoutExpired):
                    logger.warning("Windows toast timed out (suppressed)")

    threading.Thread(target=_run, daemon=True, name="baraq-notify").start()