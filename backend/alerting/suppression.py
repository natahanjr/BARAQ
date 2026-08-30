"""Controlled alert suppression (spec 3.25, 3.26).

A suppression policy needs a documented reason, a defined scope and an
expiration - never "too many alerts" as the reason, never permanent by
default. Every suppression is auditable via ``alert_suppression_rules``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.alerting.models import AlertSuppressionRule
from backend.config import ALERT_SUPPRESSION_MAX_DAYS
from backend.detection.contract import DETECTION

_WILDCARD = "*"


def _match(value: str, pattern: str) -> bool:
    if pattern == _WILDCARD or not pattern:
        return True
    return value == pattern


def _match_ip(value: str, pattern: str) -> bool:
    if not value or pattern == _WILDCARD or not pattern:
        return True
    try:
        return ip_address(value.split("/")[0]) in ip_network(pattern, strict=False)
    except ValueError:
        return value == pattern


def matches(rule: AlertSuppressionRule, detection: DETECTION) -> bool:
    """Does this suppression rule cover this detection?"""
    scope = rule.scope or {}
    if scope.get("detector_id") and not _match(
        detection.detector_id, str(scope["detector_id"])
    ):
        return False
    if scope.get("host") and not _match(detection.host_name, str(scope["host"])):
        return False
    if scope.get("user") and not _match(
        detection.username or detection.user_id, str(scope["user"])
    ):
        return False
    return not (
        scope.get("source_ip")
        and not _match_ip(detection.source_ip, str(scope["source_ip"]))
    )


def is_suppressed(
    db: Session, detection: DETECTION, now: datetime | None = None
) -> AlertSuppressionRule | None:
    """First non-expired rule covering the detection, or None."""
    now = now or datetime.now(UTC)
    rules = db.scalars(
        select(AlertSuppressionRule).where(AlertSuppressionRule.expires_at > now)
    ).all()
    for rule in rules:
        if matches(rule, detection):
            return rule
    return None


def create_rule(
    db: Session,
    *,
    policy_id: str,
    reason: str,
    expires_at: datetime,
    scope: dict | None = None,
    created_by: str = "system",
    now: datetime | None = None,
) -> AlertSuppressionRule:
    """Create an auditable suppression rule. Reason and expiration required."""
    now = now or datetime.now(UTC)
    if not reason.strip():
        raise ValueError("a suppression rule needs a documented reason")
    if expires_at <= now:
        raise ValueError("a suppression rule must expire in the future")
    if expires_at > now + timedelta(days=ALERT_SUPPRESSION_MAX_DAYS):
        raise ValueError(
            f"a suppression rule cannot exceed "
            f"{ALERT_SUPPRESSION_MAX_DAYS} days (no permanent suppression)"
        )
    rule = AlertSuppressionRule(
        policy_id=policy_id,
        reason=reason.strip(),
        created_by=created_by,
        expires_at=expires_at,
        scope=scope or {},
    )
    db.add(rule)
    db.flush()
    return rule
