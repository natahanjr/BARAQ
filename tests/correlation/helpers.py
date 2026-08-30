"""Phase 5 correlation test helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from backend.aggregation.engine import process_alerts
from backend.aggregation.models import BehaviorGroupRecord
from backend.correlation.models import (
    CorrelationAuditEvent,
    CorrelationEdge,
    CorrelationEvidence,
    CorrelationFindingRecord,
    CorrelationMember,
)
from tests.aggregation.helpers import fabricate_alerts

CORR_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def make_groups(
    db, specs: list[dict], now: datetime | None = None
) -> list[BehaviorGroupRecord]:
    """Fabricate distinct alerts, aggregate them, return the groups."""
    alerts = fabricate_alerts(db, specs)
    return process_alerts(db, alerts, now=now or CORR_T0)


def stored_correlations(db) -> list[CorrelationFindingRecord]:
    return list(
        db.scalars(
            select(CorrelationFindingRecord).order_by(CorrelationFindingRecord.id)
        ).all()
    )


def stored_corr_edges(db) -> list[CorrelationEdge]:
    return list(db.scalars(select(CorrelationEdge).order_by(CorrelationEdge.id)).all())


def stored_corr_members(db) -> list[CorrelationMember]:
    return list(
        db.scalars(select(CorrelationMember).order_by(CorrelationMember.id)).all()
    )


def stored_corr_evidence(db) -> list[CorrelationEvidence]:
    return list(
        db.scalars(select(CorrelationEvidence).order_by(CorrelationEvidence.id)).all()
    )


def stored_corr_audit(db) -> list[CorrelationAuditEvent]:
    return list(
        db.scalars(
            select(CorrelationAuditEvent).order_by(CorrelationAuditEvent.id)
        ).all()
    )


def canonical_specs() -> list[dict]:
    """The canonical RDP -> lateral example (spec 5.70): 30 alerts -> 5
    groups -> 1 finding.

    Groups (each on its own host, so no SAME_HOST inflation):
        G1 5 alerts   D002 brute force       10.0.0.4  src 198.51.100.9  -> 10.0.0.5
        G2 5 alerts   D002 brute force       10.0.0.5  src 198.51.100.9  -> 10.0.0.6
        G3 5 alerts   D002 brute force       10.0.0.6  src 198.51.100.9  -> 10.0.0.8
        G4 5 alerts   D001 external logon    10.0.0.8  src 198.51.100.9  -> 10.0.0.7
        G5 10 alerts  D003 lateral + exec    10.0.0.7  src 10.0.0.6      (internal)

    Edges: SAME_USER / SAME_SOURCE / TEMPORAL / DESTINATION_RELATION /
    LATERAL_MOVEMENT (exactly the five spec types); confidence 0.88;
    type LATERAL_MOVEMENT; highest severity never escalated above the
    member maximum; never an incident, never SOAR.
    """
    brute_force = {
        "detector_id": "D002",
        "user": "u-r1",
        "source_ip": "198.51.100.9",
        "mitre": "T1110",
        "title": "External RDP brute force",
        "severity": "high",
    }
    logon = {
        "detector_id": "D001",
        "user": "u-r1",
        "source_ip": "198.51.100.9",
        "mitre": "T1133",
        "title": "Successful logon from external source",
        "severity": "medium",
    }
    lateral = {
        "detector_id": "D003",
        "user": "u-r1",
        "source_ip": "10.0.0.6",
        "host": "10.0.0.7",
        "mitre": "T1021.001",
        "title": "RDP session to internal host",
        "severity": "high",
    }
    execution = [
        {
            "detector_id": "D003",
            "user": "u-r1",
            "source_ip": "10.0.0.6",
            "host": "10.0.0.7",
            "mitre": "T1059.001",
            "title": "Suspicious PowerShell",
            "severity": "high",
        },
        {
            "detector_id": "D004",
            "user": "u-r1",
            "source_ip": "10.0.0.6",
            "host": "10.0.0.7",
            "mitre": "T1047",
            "title": "WMI execution",
            "severity": "high",
        },
    ]

    specs: list[dict] = []
    chain = [
        (
            10.0 / 60,
            10.0 / 60,
            {"host": "10.0.0.4", "destination_ip": "10.0.0.5"},
            brute_force,
        ),
        (
            0.0 / 60,
            0.0 / 60,
            {"host": "10.0.0.5", "destination_ip": "10.0.0.6"},
            brute_force,
        ),
        (
            0.0 / 60,
            0.0 / 60,
            {"host": "10.0.0.6", "destination_ip": "10.0.0.8"},
            brute_force,
        ),
        (0.0 / 60, 0.0 / 60, {"host": "10.0.0.8", "destination_ip": "10.0.0.7"}, logon),
    ]
    base = 14.0
    for minutes_ago, _step, overrides, template in chain:
        base -= 3.0
        for i in range(5):
            spec = dict(template, minutes_ago=base - i * 0.5)
            spec.update(overrides)
            specs.append(spec)
    for i in range(8):
        spec = dict(lateral, minutes_ago=1.0 - i * 0.1)
        specs.append(spec)
    specs.append(dict(execution[0], minutes_ago=0.2))
    specs.append(dict(execution[1], minutes_ago=0.1))
    return specs
