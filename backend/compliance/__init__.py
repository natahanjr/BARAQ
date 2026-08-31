"""Compliance tooling (roadmap 3.3): GDPR / CCPA support.

* **Anonymized exports** - telemetry dumps with PII masked, for analytics /
  lawful secondary use without re-identifying data subjects.
* **DSAR packages** - a data subject access request: every record BARAQ holds
  about one person (account, audit trail, event/alert mentions).
* **Compliance report** - data inventory (what is stored, for how long) plus
  retention / anonymization posture for auditors.
* **Audit retention** - the chained audit trail ages out on its own window
  (``BARAQ_AUDIT_RETENTION_DAYS``) so GDPR "storage limitation" holds.

PII fields are masked with a stable per-value token (SHA-256 prefix), so a
masked value stays linkable across a dataset without being readable.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import Alert, AuditLog, NormalizedEvent, User

logger = logging.getLogger("baraq.compliance")

#: Fields carrying personal data; values are replaced by a token.
_PII_FIELDS = (
    "user",
    "host",
    "ip",
    "email",
    "source_ip",
    "dest_ip",
    "actor",
    "subject_user",
)


def _token(value, salt: str = "baraq-pii") -> str:
    """Deterministic, unreadable replacement for one PII value."""
    if not value:
        return ""
    digest = hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()
    return f"anonymized-{digest[:12]}"


def anonymize(record: dict) -> dict:
    """Return a copy of ``record`` with every PII field masked."""
    out = {}
    for key, value in record.items():
        if value is None:
            out[key] = value
            continue
        lowered = key.lower()
        if any(f in lowered for f in _PII_FIELDS) and isinstance(value, str):
            out[key] = _token(value)
        elif isinstance(value, dict):
            out[key] = anonymize(value)
        else:
            out[key] = value
    return out


def anonymized_export(session, hours: int = 24, org: str = "") -> dict:
    """Anonymized telemetry + alert dataset for the export window."""
    since = datetime.now(UTC).replace(tzinfo=None)
    if hours:
        from datetime import timedelta

        since = since - timedelta(hours=hours)
    events = session.scalars(
        select(NormalizedEvent)
        .where(
            NormalizedEvent.timestamp >= since,
            *((NormalizedEvent.org == org,) if org else ()),
        )
        .limit(5000)
    ).all()
    alerts = session.scalars(
        select(Alert)
        .where(
            Alert.created_at >= since,
            *((Alert.org == org,) if org else ()),
        )
        .limit(2000)
    ).all()
    return {
        "exported_at": datetime.now(UTC).isoformat(),
        "window_hours": hours,
        "org": org,
        "anonymization": "sha256-token (deterministic, not reversible)",
        "events": [anonymize(e.to_dict()) for e in events],
        "alerts": [anonymize(a.to_dict()) for a in alerts],
        "counts": {"events": len(events), "alerts": len(alerts)},
    }


def dsar_package(session, email: str) -> dict:
    """Everything BARAQ stores about one data subject (email/username)."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email is required")
    account = session.scalar(select(User).where(User.username == email))
    audit = session.scalars(
        select(AuditLog).where(AuditLog.actor == email).order_by(AuditLog.id)
    ).all()
    events = session.scalars(
        select(NormalizedEvent).where(NormalizedEvent.user == email).limit(5000)
    ).all()
    alerts = session.scalars(
        select(Alert).where(Alert.evidence.contains(email)).limit(1000)
    ).all()
    return {
        "requested_at": datetime.now(UTC).isoformat(),
        "subject": email,
        "account": account.to_dict() if account else None,
        "audit_entries": [a.to_dict() for a in audit],
        "events": [e.to_dict() for e in events],
        "alerts": [a.to_dict() for a in alerts],
        "counts": {
            "audit": len(audit),
            "events": len(events),
            "alerts": len(alerts),
        },
        "note": "DSAR packages must be delivered securely to the requester and deleted afterwards per policy.",
    }


def compliance_report(session) -> dict:
    """Data inventory + retention posture for auditors (GDPR Art. 30 / CCPA)."""
    from sqlalchemy import func

    from backend.config import AUDIT_RETENTION_DAYS, EVENT_RETENTION_DAYS

    inventory = {
        "events": session.scalar(select(func.count(NormalizedEvent.id))) or 0,
        "alerts": session.scalar(select(func.count(Alert.id))) or 0,
        "audit_entries": session.scalar(select(func.count(AuditLog.id))) or 0,
        "users": session.scalar(select(func.count(User.id))) or 0,
    }
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "inventory": inventory,
        "retention_days": {
            "telemetry": EVENT_RETENTION_DAYS,
            "audit_trail": AUDIT_RETENTION_DAYS,
        },
        "data_flow": {
            "sources": "Windows event logs, Sysmon, agents, email/files ingest",
            "storage": "PostgreSQL (primary); dashboards may read a replica",
            "exports": "reports (PDF/HTML/JSON/CSV) + anonymized compliance export",
            "deletion": "automated retention purge + DSAR / delete requests",
        },
        "anonymization": "supported (sha256 token), see /api/compliance/export",
        "dsar": "supported, see /api/compliance/dsar?email=...",
        "ccpa": "right-to-delete: purge user rows + related telemetry via admin",
        "gdpr": "controller = BARAQ operator; processing = SOC telemetry (Art. 6(1)(f))",
    }


def purge_old_audit(session, days: int | None = None) -> int:
    """Delete audit entries older than the audit retention window.

    Returns the number of rows removed. Chained integrity is unaffected:
    only the oldest entries (whose successor chain remains valid) age out.
    """
    from sqlalchemy import delete

    from backend.config import AUDIT_RETENTION_DAYS

    window = days or AUDIT_RETENTION_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=window)
    deleted = int(
        session.execute(delete(AuditLog).where(AuditLog.created_at < cutoff)).rowcount
        or 0
    )
    if deleted:
        session.commit()
        logger.info("Audit retention purge (older than %dd): %d rows", window, deleted)
    return deleted
