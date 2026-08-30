"""Scheduled report generation + email delivery (roadmap 6.2).

Schedules live in the ``report_schedules`` table (managed via the API in
``backend/api/reports.py``) and are executed by the scheduler loop through
:func:`run_due_schedules` (also exposed as the Celery task
``baraq.scheduled_report``). Email delivery reuses the ``BARAQ_SMTP_*``
settings; reports are generated synchronously and shipped as attachments.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import (
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_STARTTLS,
    SMTP_TO,
    SMTP_USERNAME,
)
from backend.database.models import ReportSchedule
from backend.reports.generator import generate_report

logger = logging.getLogger("baraq.reports.schedule")

VALID_FORMATS = ("pdf", "html", "json", "csv")


def email_report(file_path: str, to: str, subject: str) -> bool:
    """Send a report file as an email attachment via SMTP.

    Returns False (silently) when SMTP is not configured so scheduled runs
    without a relay never fail; raises on genuine delivery errors.
    """
    if not SMTP_HOST or not to:
        return False
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    path = Path(file_path)
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM or SMTP_HOST
    msg["To"] = to
    msg.attach(MIMEText("BARAQ generated report attached.", "plain"))
    part = MIMEApplication(path.read_bytes(), Name=path.name)
    part.add_header("Content-Disposition", "attachment", filename=path.name)
    msg.attach(part)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        if SMTP_STARTTLS:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
    logger.info("Report emailed to %s: %s", to, path.name)
    return True


def _is_due(schedule: ReportSchedule, now: datetime) -> bool:
    if not schedule.enabled:
        return False
    if schedule.hour_of_day >= 0:
        # Daily at hour_of_day (local clock hour); must not have run yet today.
        if now.hour != schedule.hour_of_day:
            return False
        if schedule.last_run_at:
            day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            if schedule.last_run_at.astimezone(UTC) >= day_start.astimezone(UTC):
                return False
        return True
    if schedule.every_hours <= 0:
        return False
    if schedule.last_run_at is None:
        return True
    return now - schedule.last_run_at.astimezone(UTC) >= timedelta(
        hours=schedule.every_hours
    )


def run_schedule(db: Session, schedule: ReportSchedule, email: bool = True) -> dict:
    """Generate one schedule's report (and optionally email it)."""
    result = generate_report(db, schedule.report_type, schedule.fmt)
    schedule.last_run_at = datetime.now(UTC)
    schedule.runs_total += 1
    schedule.last_error = ""
    recipients = [
        r for r in (schedule.email_to or SMTP_TO or "").split(",") if r.strip()
    ]
    emailed = False
    if email and recipients:
        emailed = email_report(
            result["file_path"],
            ",".join(recipients),
            f"[BARAQ] {result['title']} - {result['format'].upper()} report",
        )
    db.commit()
    return {**result, "emailed": emailed}


def run_due_schedules(db: Session) -> dict:
    """Run every due schedule; never lets one failure stop the rest."""
    now = datetime.now(UTC)
    due = [s for s in db.scalars(select(ReportSchedule)).all() if _is_due(s, now)]
    results: list[dict] = []
    for schedule in due:
        try:
            result = run_schedule(db, schedule)
            results.append({"name": schedule.name, "status": "ok", **result})
            logger.info("Scheduled report %s generated", schedule.name)
        except Exception as exc:
            db.rollback()
            schedule.last_error = str(exc)[:400]
            db.commit()
            results.append(
                {"name": schedule.name, "status": "error", "error": str(exc)}
            )
            logger.warning("Scheduled report %s failed: %s", schedule.name, exc)
    return {"due": len(due), "results": results}
