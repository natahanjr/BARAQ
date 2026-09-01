"""Audit trail helper - record who did what, when, tamper-evidently.

Every entry is chained to the previous one with SHA-256 (prev_hash -> hash),
so editing or deleting any historical row breaks the chain. ``verify_chain``
recomputes the whole chain and reports any breakage. Optionally each entry is
also forwarded to a remote SIEM/syslog (see ``backend.logging_config``).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy import func, select

from backend.database.models import AuditLog, canonical_timestamp

logger = logging.getLogger("baraq.audit")

_GENESIS_HASH = "0" * 64


def client_ip(request: Request | None) -> str:
    if request is None:
        return ""
    return request.client.host if request.client else ""


def _chain_hash(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: Monotonic counter of audit-log write failures. Exposed via
#: ``stats()`` / ``health()`` so operators and the /api/system/audit
#: health endpoint can detect a silently broken chain.
_write_failures: int = 0


def record_failure(reason: BaseException | str) -> None:
    """Record a chain-write failure. Imported by retry helpers and the
    callers that see a recoverable exception (DB conflict, lock timeout,
    etc.). Always increments the counter and logs at ERROR level."""
    global _write_failures
    _write_failures += 1
    logger.error("Audit chain write failure (#%d): %s", _write_failures, reason)


def audit_failure_count() -> int:
    """Return the cumulative count of audit-chain write failures since
    process start. Used by the /api/system/audit/health endpoint and
    by tests."""
    return _write_failures


def log_action(
    db,
    actor: str,
    action: str,
    entity_type: str = "",
    entity_id: str = "",
    detail: str = "",
    ip: str = "",
) -> AuditLog:
    """Persist an audit entry chained to the previous one. Never raises - the
    audit trail must not break the primary operation."""
    try:
        now = datetime.now(UTC)
        prev_hash = _GENESIS_HASH
        last = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
        if last is not None:
            prev_hash = last.hash or _GENESIS_HASH

        entry = AuditLog(
            actor=actor[:64],
            action=action[:64],
            entity_type=entity_type[:32],
            entity_id=str(entity_id)[:64],
            detail=detail[:2000],
            ip=ip[:64],
            created_at=now,
            prev_hash=prev_hash,
        )
        # Set the chained hash of this entry (canonical form without hash).
        entry.hash = _chain_hash(entry.canonical())
        db.add(entry)
        db.commit()
        # Forward a copy to the SIEM/syslog stream (best-effort, non-blocking).
        try:
            from backend.logging_config import audit_syslog

            audit_syslog(
                {
                    "event": "audit",
                    "id": entry.id,
                    "actor": entry.actor,
                    "action": entry.action,
                    "entity_type": entry.entity_type,
                    "entity_id": entry.entity_id,
                    "detail": entry.detail,
                    "ip": entry.ip,
                    "created_at": now.isoformat(),
                    "hash": entry.hash,
                    "prev_hash": prev_hash,
                }
            )
        except Exception as exc:
            # Syslog forwarder failure is non-fatal but the chain itself
            # IS already on disk above; this branch only covers the
            # external transport.
            record_failure(f"syslog forwarder: {exc}")
        return entry
    except Exception as exc:
        # Chain write failed: roll back, increment the failure counter
        # at ERROR level so the operator can see this in logs, and
        # surface it via /api/system/audit/health.
        record_failure(exc)
        try:
            db.rollback()
        except Exception:
            pass
        return None


def verify_chain(db) -> dict:
    """Recompute the whole audit chain; report the first broken link.

    Returns ``{"ok": bool, "checked": n, "broken_at": id-or-None}``.
    """
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    expected_prev = _GENESIS_HASH
    for row in rows:
        canonical = "|".join(
            [
                expected_prev,
                row.actor or "",
                row.action or "",
                row.entity_type or "",
                row.entity_id or "",
                row.detail or "",
                row.ip or "",
                canonical_timestamp(row.created_at),
            ]
        )
        if row.hash != _chain_hash(canonical):
            return {"ok": False, "checked": len(rows), "broken_at": row.id}
        expected_prev = row.hash
    return {"ok": True, "checked": len(rows), "broken_at": None}


def stats(db) -> dict:
    total = db.scalar(select(func.count(AuditLog.id))) or 0
    return {"total": total}
