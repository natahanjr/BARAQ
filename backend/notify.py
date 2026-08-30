"""Real-time alert notifications (webhook + SMTP + Telegram + toast).

A SOC that only shows a dashboard is not a SOC. This module pushes
high/critical alerts out-of-band: a webhook (generic JSON, Slack- and
Teams-formatted when the URL matches), SMTP email, Telegram bot push and a
Windows toast.

Delivery reliability (Phase 1 hardening):

* A background worker drains a queue, so the detection pipeline never blocks
  on a slow or dead notification endpoint.
* Failed channels are retried with exponential backoff (``NOTIFY_RETRIES``).
* Per-channel health counters are exposed on
  ``/api/system/notifications/health``.
* Alerts that no remote channel accepts are written to a JSON fallback
  directory (``NOTIFY_FALLBACK_DIR``) so nothing is ever silently dropped.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import smtplib
import ssl
import subprocess
import threading
import time
import urllib.request
from datetime import UTC, datetime
from email.mime.text import MIMEText
from pathlib import Path

from backend.config import (
    ASYNC_NOTIFY,
    NOTIFY_FALLBACK_DIR,
    NOTIFY_MIN_SEVERITY,
    NOTIFY_RETRIES,
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
    color = {
        "low": "#f0ad4e",
        "medium": "#f39c12",
        "high": "#e67e22",
        "critical": "#e74c3c",
    }.get(body.get("severity", ""), "#95a5a6")
    lines = "\n".join(f"*{k}:* {v}" for k, v in body.items() if v not in (None, ""))
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
    color = {
        "low": "warning",
        "medium": "warning",
        "high": "attention",
        "critical": "attention",
    }.get(body.get("severity", ""), "accent")
    facts = [
        {"name": k, "value": str(v)} for k, v in body.items() if v not in (None, "")
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
    title = (
        f"BARAQ: {alert.get('severity', '').upper()} alert {alert.get('mitre_id', '')}"
    )
    message = f"{alert.get('name', '')} - {alert.get('evidence', '')[:240]}"
    script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts",
        "toast.ps1",
    )
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script,
            "-Title",
            title,
            "-Message",
            message,
        ],
        timeout=20,
        capture_output=True,
        check=False,
    )


def _write_fallback(alert: dict) -> Path | None:
    """Persist an undeliverable alert as JSON; returns the written path."""
    try:
        directory = Path(NOTIFY_FALLBACK_DIR)
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
        target = directory / f"alert-{alert.get('id', 'unknown')}-{stamp}.json"
        target.write_text(
            json.dumps(
                {
                    "delivered": False,
                    "dropped_at": datetime.now(UTC).isoformat(),
                    "alert": alert,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return target
    except Exception as exc:
        logger.error("Notification file fallback failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Channel health
# ---------------------------------------------------------------------------
class NotificationHealth:
    """Per-channel delivery health: successes, failures, last error."""

    def __init__(self):
        self._lock = threading.Lock()
        self._channels: dict[str, dict] = {}

    @staticmethod
    def _blank(name: str) -> dict:
        return {
            "channel": name,
            "configured": False,
            "ok": True,
            "successes": 0,
            "failures": 0,
            "consecutive_failures": 0,
            "last_error": "",
            "last_success_at": None,
            "last_failure_at": None,
        }

    def record(self, name: str, ok: bool, error: str = "") -> None:
        with self._lock:
            state = self._channels.setdefault(name, self._blank(name))
            state["configured"] = True
            if ok:
                state["ok"] = True
                state["successes"] += 1
                state["consecutive_failures"] = 0
                state["last_success_at"] = datetime.now(UTC).isoformat()
            else:
                state["ok"] = False
                state["failures"] += 1
                state["consecutive_failures"] += 1
                state["last_error"] = error[:300]
                state["last_failure_at"] = datetime.now(UTC).isoformat()

    def snapshot(self) -> dict:
        with self._lock:
            return {name: dict(state) for name, state in sorted(self._channels.items())}


notification_health = NotificationHealth()


def channel_health() -> dict:
    """Public API for /api/system/notifications/health."""
    return {
        "retries": NOTIFY_RETRIES,
        "fallback_dir": NOTIFY_FALLBACK_DIR,
        "channels": notification_health.snapshot(),
    }


# ---------------------------------------------------------------------------
# Delivery queue + worker
# ---------------------------------------------------------------------------
_SENDERS: list[tuple[str, str]] = [
    ("webhook", "_send_webhook"),
    ("email", "_send_email"),
    ("telegram", "_send_telegram"),
    ("toast", "_send_toast"),
]

_queue: queue.Queue[tuple[int, dict]] = queue.Queue(maxsize=1024)
_worker_started = False
_worker_lock = threading.Lock()


def _worker_loop() -> None:
    logger.debug("Notification worker started (retries=%d)", NOTIFY_RETRIES)
    while True:
        attempts, alert = _queue.get()
        try:
            _deliver(alert, attempts)
        except Exception as exc:
            logger.error(
                "Notification worker crashed on alert %s: %s", alert.get("id"), exc
            )
        finally:
            _queue.task_done()


def _deliver(alert: dict, attempts: int) -> None:
    """One delivery pass: each configured channel, retry with backoff."""
    delay = 1.0
    for attempt in range(attempts):
        pending = [name for name, _ in _SENDERS if _configured(name)]
        if not pending:
            return
        failures: list[str] = []
        for name, attr in _SENDERS:
            sender = globals().get(attr)
            if sender is None:
                continue
            try:
                sender(alert)
                notification_health.record(name, True)
            except Exception as exc:
                notification_health.record(name, False, str(exc))
                failures.append(name)
        if not failures:
            return
        if attempt < attempts - 1:
            logger.warning(
                "Notification channels %s failed; retrying in %.1fs (attempt %d/%d)",
                ",".join(failures),
                delay,
                attempt + 2,
                attempts,
            )
            time.sleep(delay)
            delay *= 2
        else:
            logger.error(
                "Notification channels %s exhausted %d attempts for alert %s",
                ",".join(failures),
                attempts,
                alert.get("id"),
            )
            _write_fallback(alert)


def _configured(name: str) -> bool:
    if name == "webhook":
        return bool(WEBHOOK_URL)
    if name == "email":
        return bool(SMTP_HOST and SMTP_TO)
    if name == "telegram":
        return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
    if name == "toast":
        return bool(TOAST_ENABLED)
    return False


def _start_worker() -> None:
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        threading.Thread(target=_worker_loop, daemon=True, name="baraq-notify").start()
        _worker_started = True


def notify_alert(alert: dict) -> None:
    """Enqueue webhook + email + telegram + toast delivery (non-blocking).

    With ``ASYNC_NOTIFY`` (default) delivery runs on the worker queue with
    retries and file fallback. With the flag off, each alert dispatches on a
    plain daemon thread (best-effort, matches the pre-queue behaviour).
    """
    if not _wanted(alert.get("severity", "")):
        return
    if not any(_configured(name) for name, _ in _SENDERS):
        return
    if not ASYNC_NOTIFY:
        threading.Thread(
            target=_deliver, args=(alert, 1), daemon=True, name="baraq-notify"
        ).start()
        return
    try:
        _queue.put_nowait((NOTIFY_RETRIES + 1, alert))
    except queue.Full:
        logger.warning("Notification queue full; dropping alert %s", alert.get("id"))
        return
    _start_worker()
