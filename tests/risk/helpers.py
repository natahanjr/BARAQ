"""Phase 6 risk test helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from backend.risk.models import (
    EntityRiskV2,
    EntityRiskV2AuditEvent,
    EntityRiskV2Factor,
    EntityRiskV2Snapshot,
)

RISK_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def group_evidence(
    group_id: str,
    host: str,
    techniques: list[str],
    *,
    severity: str = "high",
    alert_count: int = 10,
    observed: datetime = RISK_T0,
    user: str = "u-eval",
    source: str = "203.0.113.5",
    destination: str | None = None,
    external: bool = False,
) -> dict:
    return {
        "kind": "BEHAVIOR_GROUP",
        "group_id": group_id,
        "hosts": [host],
        "users": [user],
        "source_ips": [source],
        "destination_ips": [destination] if destination else [],
        "techniques": techniques,
        "severity": severity,
        "alert_count": alert_count,
        "first_seen": observed,
        "last_seen": observed,
        "external_source": external,
    }


def alert_evidence(
    alert_id: str,
    host: str,
    *,
    detector: str = "D100",
    severity: str = "medium",
    observed: datetime = RISK_T0,
    user: str = "u-eval",
    source: str = "203.0.113.5",
    technique: str = "T1110",
    destination_ip: str = "",
    account: str = "",
    process: str = "",
) -> dict:
    return {
        "kind": "ALERT",
        "alert_id": alert_id,
        "detector_id": detector,
        "host": host,
        "user": user,
        "source_ip": source,
        "destination_ip": destination_ip,
        "account": account,
        "process": process,
        "severity": severity,
        "mitre_technique": technique,
        "first_seen": observed,
        "last_seen": observed,
    }


def finding_evidence(
    finding_id: str,
    hosts: list[str],
    *,
    observed: datetime = RISK_T0,
    user: str = "u-eval",
    source: str = "203.0.113.5",
    correlation_type: str = "MULTI_STAGE",
) -> dict:
    return {
        "kind": "CORRELATION_FINDING",
        "correlation_id": finding_id,
        "correlation_type": correlation_type,
        "hosts": hosts,
        "users": [user],
        "source_ips": [source],
        "member_group_ids": ["g-eval"],
        "confidence": 0.88,
        "first_seen": observed,
        "last_seen": observed,
    }


def stored_risks(db) -> list[EntityRiskV2]:
    return list(db.scalars(select(EntityRiskV2).order_by(EntityRiskV2.id)).all())


def stored_factors(db) -> list[EntityRiskV2Factor]:
    return list(
        db.scalars(select(EntityRiskV2Factor).order_by(EntityRiskV2Factor.id)).all()
    )


def stored_snapshots(db) -> list[EntityRiskV2Snapshot]:
    return list(
        db.scalars(select(EntityRiskV2Snapshot).order_by(EntityRiskV2Snapshot.id)).all()
    )


def stored_audit(db) -> list[EntityRiskV2AuditEvent]:
    return list(
        db.scalars(
            select(EntityRiskV2AuditEvent).order_by(EntityRiskV2AuditEvent.id)
        ).all()
    )
