"""Scoped alert suppression (roadmap P2).

An analyst declares that a detection is expected behaviour within a scope
(rule / host / user / expiry). The alerting service consults this store
before persisting a finding: a matching active rule means the finding is
annotated and dropped instead of becoming an alert.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import SuppressionRule

logger = logging.getLogger("baraq.suppression")


def _match(value: str, pattern: str) -> bool:
    return pattern in ("", "*") or value == pattern


def find_matching(
    session: Session,
    rule: str,
    host: str = "",
    user: str = "",
    org: str = "",
) -> SuppressionRule | None:
    """The first active suppression rule matching the finding's scope.

    Matching is exact on rule, host and user, with ``*`` wildcards; a rule
    applies only while ``expires_at`` is unset or in the future.
    """
    now = datetime.now(timezone.utc)
    rules = session.scalars(
        select(SuppressionRule).where(SuppressionRule.org == org)
    ).all()
    for item in rules:
        if item.expires_at is not None and item.expires_at <= now:
            continue
        if not _match(rule, item.rule):
            continue
        if not _match(host, item.host):
            continue
        if not _match(user, item.user):
            continue
        return item
    return None


def create(
    session: Session,
    rule: str,
    host: str = "*",
    user: str = "*",
    reason: str = "",
    created_by: str = "analyst",
    org: str = "",
    expires_hours: float | None = 168.0,
) -> SuppressionRule:
    """Create a suppression rule (default expiry: 7 days)."""
    item = SuppressionRule(
        rule=rule or "*",
        host=host or "*",
        user=user or "*",
        reason=(reason or "")[:512],
        created_by=created_by,
        org=org,
        expires_at=(
            datetime.now(timezone.utc) + timedelta(hours=max(0.0, expires_hours))
            if expires_hours is not None
            else None
        ),
    )
    session.add(item)
    session.commit()
    session.refresh(item)
    logger.info(
        "Suppression rule #%s: rule=%s host=%s user=%s expires=%s",
        item.id, item.rule, item.host, item.user, item.expires_at,
    )
    return item


def list_rules(session: Session, org: str = "", include_expired: bool = False) -> list[SuppressionRule]:
    stmt = select(SuppressionRule).where(SuppressionRule.org == org)
    if not include_expired:
        now = datetime.now(timezone.utc)
        stmt = stmt.where(
            (SuppressionRule.expires_at.is_(None)) | (SuppressionRule.expires_at > now)
        )
    return list(session.scalars(stmt.order_by(SuppressionRule.created_at.desc())).all())


def delete(session: Session, rule_id: int, org: str = "") -> bool:
    item = session.get(SuppressionRule, rule_id)
    if item is None or (org and item.org != org):
        return False
    session.delete(item)
    session.commit()
    logger.info("Suppression rule #%s deleted", rule_id)
    return True


def prune_expired(session: Session) -> int:
    """Delete expired suppression rules (housekeeping on scheduler cycles)."""
    now = datetime.now(timezone.utc)
    expired = session.scalars(
        select(SuppressionRule).where(SuppressionRule.expires_at.isnot(None),
                                      SuppressionRule.expires_at <= now)
    ).all()
    for item in expired:
        session.delete(item)
    if expired:
        session.commit()
    return len(expired)