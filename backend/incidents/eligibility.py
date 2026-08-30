"""Phase 7 incident eligibility engine (spec 7.3, 7.23, 7.24, 7.28, 7.46)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from backend.incidents.models import (
    IncidentV2,
    IncidentV2AlertLink,
    IncidentV2BehaviorGroupLink,
    IncidentV2CorrelationLink,
    IncidentV2RiskLink,
)
from backend.incidents.registry import evaluate_policy


def _load_related(db, incident_id: str) -> dict[str, Any]:
    alerts = [
        {"alert_id": row.alert_id, "membership_reason": row.membership_reason}
        for row in db.scalars(
            select(IncidentV2AlertLink).where(
                IncidentV2AlertLink.incident_id == incident_id
            )
        ).all()
    ]
    groups = [
        {
            "behavior_group_id": row.behavior_group_id,
            "membership_reason": row.membership_reason,
        }
        for row in db.scalars(
            select(IncidentV2BehaviorGroupLink).where(
                IncidentV2BehaviorGroupLink.incident_id == incident_id
            )
        ).all()
    ]
    correlations = [
        {
            "correlation_finding_id": row.correlation_finding_id,
            "membership_reason": row.membership_reason,
        }
        for row in db.scalars(
            select(IncidentV2CorrelationLink).where(
                IncidentV2CorrelationLink.incident_id == incident_id
            )
        ).all()
    ]
    return {"alerts": alerts, "groups": groups, "correlations": correlations}


def check_eligibility(db, incident_id: str, policy_id: str) -> dict:
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        return {"eligible": False, "reason": "incident not found"}

    related = _load_related(db, incident_id)
    risk = None
    risk_link = db.scalars(
        select(IncidentV2RiskLink).where(IncidentV2RiskLink.incident_id == incident_id)
    ).first()
    if risk_link:
        risk = {"risk_id": risk_link.risk_id}

    context = {
        "groups": related["groups"],
        "findings": related["correlations"],
        "risk": risk,
        "alerts": related["alerts"],
        "policy_id": policy_id,
        "incident_type": "CORRELATED" if related["correlations"] else "SUPPORTED",
        "primary_entity_type": incident.primary_entity_type,
        "primary_entity_id": incident.primary_entity_id,
    }
    result = evaluate_policy(policy_id, context)
    return {
        "policy_id": result.policy_id,
        "eligible": result.eligible,
        "reason": result.reason,
        "evidence": result.evidence,
        "source_type": result.source_type,
        "source_id": result.source_id,
    }
