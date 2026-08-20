"""Phase 7 incident engine (spec 7.1-7.8, 7.15-7.17, 7.21, 7.23-7.25, 7.26-7.29, 7.34, 7.42, 7.45-7.47)."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from backend.incidents.audit import audit
from backend.incidents.config import (
    INCIDENT_CONFIDENCE_BASE,
    INCIDENT_CONFIDENCE_CORRELATION,
    INCIDENT_CONFIDENCE_MULTI_ENTITY,
    INCIDENT_CONFIDENCE_REPEATED,
    INCIDENT_CONFIDENCE_STRONG_EVIDENCE,
    INCIDENT_MAX_CONFIDENCE,
    INCIDENT_MIN_CONFIDENCE,
    INCIDENT_MODEL_VERSION,
    INCIDENT_SUPPRESSION_MAX_DAYS,
)
from backend.incidents.evidence import add_evidence
from backend.incidents.contract import (
    AUDIT_ACTIONS,
    BANNED_INCIDENT_PHRASES,
    EVIDENCE_SOURCE_TYPES,
    GRAPH_RELATIONSHIP_TYPES,
    INCIDENT_PRIORITIES,
    INCIDENT_SEVERITIES,
    INCIDENT_STATES,
)
from backend.incidents.fingerprint import compute_fingerprint
from backend.incidents.lifecycle import can_transition, is_terminal
from backend.incidents.models import (
    IncidentV2AlertLink,
    IncidentV2BehaviorGroupLink,
    IncidentV2CorrelationLink,
    IncidentV2Evidence,
    IncidentV2GraphEdge,
    IncidentV2RiskLink,
    IncidentV2Suppression,
    IncidentV2AuditEvent,
    IncidentV2,
)
from backend.incidents.registry import evaluate_policy, list_policies


def _next_incident_id(db) -> str:
    row = db.scalars(
        select(IncidentV2).order_by(IncidentV2.id.desc()).limit(1)
    ).first()
    return f"INC-{(row.id + 1) if row else 1:06d}"


def _dedupe_title(title: str) -> str:
    return title.strip()[:255]


def _validate_title(title: str) -> None:
    lowered = title.lower()
    for phrase in BANNED_INCIDENT_PHRASES:
        if phrase in lowered:
            raise ValueError(f"banned incident phrase detected in title: {phrase!r}")


def _primary_entity(groups: list[dict], findings: list[dict], risk: dict | None) -> tuple[str, str]:
    if risk:
        return risk.get("primary_entity_type", "HOST"), risk.get("primary_entity_id", "")
    for g in groups:
        hosts = g.get("hosts", [])
        if hosts:
            return "HOST", hosts[0]
        users = g.get("users", [])
        if users:
            return "USER", users[0]
    for f in findings:
        hosts = f.get("hosts", [])
        if hosts:
            return "HOST", hosts[0]
    return "UNKNOWN", ""


def _observables(groups: list[dict], findings: list[dict]) -> dict[str, Any]:
    hosts: list[str] = []
    users: list[str] = []
    accounts: list[str] = []
    source_ips: list[str] = []
    destination_ips: list[str] = []
    processes: list[str] = []
    techniques: list[str] = []
    tactics: list[str] = []
    for g in groups:
        hosts.extend(g.get("hosts", []))
        users.extend(g.get("users", []))
        accounts.extend(g.get("accounts", []))
        source_ips.extend(g.get("source_ips", []))
        destination_ips.extend(g.get("destination_ips", []))
        techniques.extend(g.get("techniques", []))
        tactics.extend(g.get("tactics", []))
    for f in findings:
        hosts.extend(f.get("hosts", []))
        users.extend(f.get("users", []))
        source_ips.extend(f.get("source_ips", []))
    return {
        "hosts": list(dict.fromkeys(hosts)),
        "users": list(dict.fromkeys(users)),
        "accounts": list(dict.fromkeys(accounts)),
        "source_ips": list(dict.fromkeys(source_ips)),
        "destination_ips": list(dict.fromkeys(destination_ips)),
        "processes": list(dict.fromkeys(processes)),
        "techniques": list(dict.fromkeys(techniques)),
        "tactics": list(dict.fromkeys(tactics)),
    }


def _aggregate_severity(groups: list[dict], findings: list[dict], risk: dict | None) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best = "low"
    best_val = order.get(best, 0)
    for g in groups:
        sev = order.get(g.get("severity", "low"), 0)
        if sev > best_val:
            best_val = sev
            best = g.get("severity", "low")
    for f in findings:
        sev = order.get(f.get("severity", "low"), 0)
        if sev > best_val:
            best_val = sev
            best = f.get("severity", "low")
    if risk:
        risk_sev = order.get(risk.get("severity", "low"), 0)
        if risk_sev > best_val:
            best = risk.get("severity", "low")
    if best_val == 0:
        best = "medium"
    ransomware_techniques = {"T1486", "T1490"}
    for g in groups:
        if any(t in ransomware_techniques for t in g.get("techniques", [])):
            return "critical"
    return best


def _compute_confidence(
    groups: list[dict],
    findings: list[dict],
    risk: dict | None,
) -> tuple[float, dict[str, float]]:
    factors: dict[str, float] = {}
    conf = INCIDENT_CONFIDENCE_BASE
    factors["base"] = INCIDENT_CONFIDENCE_BASE
    if findings:
        conf += INCIDENT_CONFIDENCE_CORRELATION
        factors["correlation_support"] = INCIDENT_CONFIDENCE_CORRELATION
    entities = set()
    for g in groups:
        entities.update(g.get("hosts", []))
        entities.update(g.get("users", []))
    if len(entities) >= 2:
        conf += INCIDENT_CONFIDENCE_MULTI_ENTITY
        factors["multi_entity_support"] = INCIDENT_CONFIDENCE_MULTI_ENTITY
    alert_count = sum(g.get("alert_count", 0) for g in groups)
    if alert_count >= 5:
        conf += INCIDENT_CONFIDENCE_REPEATED
        factors["repeated_activity"] = INCIDENT_CONFIDENCE_REPEATED
    if risk and float(risk.get("score", 0)) >= 60:
        conf += INCIDENT_CONFIDENCE_STRONG_EVIDENCE
        factors["strong_evidence"] = INCIDENT_CONFIDENCE_STRONG_EVIDENCE
    conf = max(INCIDENT_MIN_CONFIDENCE, min(INCIDENT_MAX_CONFIDENCE, conf))
    return round(conf, 2), factors


def _priority_from_context(severity: str, risk_score: float, entity_count: int) -> str:
    if severity == "critical" or risk_score >= 80 or entity_count >= 5:
        return "P1"
    if severity == "high" or risk_score >= 60 or entity_count >= 3:
        return "P2"
    if severity == "medium" or risk_score >= 40 or entity_count >= 2:
        return "P3"
    return "P4"


def _is_suppressed(db, fingerprint: str | None) -> bool:
    if not fingerprint:
        return False
    row = db.scalars(
        select(IncidentV2Suppression).where(
            IncidentV2Suppression.fingerprint == fingerprint,
            IncidentV2Suppression.expires_at > datetime.now(timezone.utc),
        )
    ).first()
    return row is not None


def _build_graph(db, incident_id: str, incident: IncidentV2) -> None:
    edges: list[IncidentV2GraphEdge] = []
    for link in incident.alerts:
        edges.append(
            IncidentV2GraphEdge(
                incident_id=incident_id,
                relationship_type="INCIDENT_HAS_ALERT",
                source_id=incident.incident_id,
                target_id=link.alert_id,
                reason=link.membership_reason,
                evidence={"source_type": "ALERT"},
            )
        )
    for link in incident.groups:
        edges.append(
            IncidentV2GraphEdge(
                incident_id=incident_id,
                relationship_type="INCIDENT_HAS_GROUP",
                source_id=incident.incident_id,
                target_id=link.behavior_group_id,
                reason=link.membership_reason,
                evidence={"source_type": "BEHAVIOR_GROUP"},
            )
        )
    for link in incident.correlations:
        edges.append(
            IncidentV2GraphEdge(
                incident_id=incident_id,
                relationship_type="INCIDENT_HAS_CORRELATION",
                source_id=incident.incident_id,
                target_id=link.correlation_finding_id,
                reason=link.membership_reason,
                evidence={"source_type": "CORRELATION"},
            )
        )
    for link in incident.risks:
        edges.append(
            IncidentV2GraphEdge(
                incident_id=incident_id,
                relationship_type="INCIDENT_HAS_RISK",
                source_id=incident.incident_id,
                target_id=link.risk_id,
                reason=link.membership_reason,
                evidence={"source_type": "RISK"},
            )
        )
    for eid in incident.entity_ids or []:
        edges.append(
            IncidentV2GraphEdge(
                incident_id=incident_id,
                relationship_type="INCIDENT_INVOLVES_ENTITY",
                source_id=incident.incident_id,
                target_id=eid,
                reason="entity involved in incident",
                evidence={"source_type": "ENTITY"},
            )
        )
    db.add_all(edges)


def _link_sources(
    db,
    incident_id: str,
    groups: list[dict],
    findings: list[dict],
    risks: list[dict] | None,
) -> None:
    seen_groups: set[str] = set()
    for g in groups:
        gid = g.get("group_id") or g.get("behavior_group_id")
        if gid and gid not in seen_groups:
            seen_groups.add(gid)
            db.add(
                IncidentV2BehaviorGroupLink(
                    incident_id=incident_id,
                    behavior_group_id=gid,
                    membership_reason="behavior group evidence",
                )
            )
    seen_findings: set[str] = set()
    for f in findings:
        fid = f.get("correlation_id") or f.get("finding_id")
        if fid and fid not in seen_findings:
            seen_findings.add(fid)
            db.add(
                IncidentV2CorrelationLink(
                    incident_id=incident_id,
                    correlation_finding_id=fid,
                    membership_reason="correlation finding",
                )
            )
    if risks:
        for r in risks:
            rid = r.get("risk_id")
            if rid:
                db.add(
                IncidentV2RiskLink(
                    incident_id=incident_id,
                    risk_id=rid,
                    membership_reason="entity risk context",
                )
                )


def _suppress_reopen(db, incident_id: str, new_fingerprint: str, actor: str = "system") -> None:
    closed = db.scalars(
        select(IncidentV2).where(
            IncidentV2.incident_id == incident_id,
            IncidentV2.status == "CLOSED",
        )
    ).first()
    if closed is not None:
        audit(
            db,
            incident_id,
            "INCIDENT_REOPEN_REJECTED",
            actor=actor,
            reason="closed incident cannot be reopened; creating new incident",
            now=datetime.now(timezone.utc),
        )


def create_incident(
    db,
    *,
    groups: list[dict],
    findings: list[dict],
    risks: list[dict] | None = None,
    alerts: list[dict] | None = None,
    policy_id: str = "I001",
    title: str | None = None,
    description: str | None = None,
    actor: str = "system",
    now: datetime | None = None,
) -> dict:
    """Create a single deterministic, deduplicated incident (spec 7.5, 7.45-7.47)."""
    now = now or datetime.now(timezone.utc)
    start = time.perf_counter()
    try:
        primary_entity_type, primary_entity_id = _primary_entity(groups, findings, risks[0] if risks else None)
        relevant_entities = list(
            dict.fromkeys(
                [f"{primary_entity_type}:{primary_entity_id}"]
                + [f"host:{h}" for g in groups for h in g.get("hosts", [])]
                + [f"user:{u}" for g in groups for u in g.get("users", [])]
                + [f"source_ip:{s}" for f in findings for s in f.get("source_ips", [])]
            )
        )
        behavior_group_ids = [
            g.get("group_id") or g.get("behavior_group_id")
            for g in groups
            if g.get("group_id") or g.get("behavior_group_id")
        ]
        correlation_finding_ids = [
            f.get("correlation_id") or f.get("finding_id")
            for f in findings
            if f.get("correlation_id") or f.get("finding_id")
        ]
        fingerprint = compute_fingerprint(
            incident_type="CORRELATED" if correlation_finding_ids else "SUPPORTED",
            primary_entity_type=primary_entity_type,
            primary_entity_id=primary_entity_id,
            relevant_entities=relevant_entities,
            correlation_finding_ids=correlation_finding_ids,
            behavior_group_ids=behavior_group_ids,
            policy_id=policy_id,
        )

        if _is_suppressed(db, fingerprint):
            existing = db.scalars(
                select(IncidentV2).where(IncidentV2.fingerprint == fingerprint)
            ).first()
            if existing and existing.status == "SUPPRESSED":
                return {"incident_id": existing.incident_id, "status": "SUPPRESSED", "fingerprint": fingerprint}

        existing = db.scalars(
            select(IncidentV2).where(IncidentV2.fingerprint == fingerprint)
        ).first()
        if existing and not is_terminal(existing.status):
            _suppress_reopen(db, existing.incident_id, fingerprint, actor=actor)
            return {"incident_id": existing.incident_id, "status": existing.status, "fingerprint": fingerprint}

        policy_context = {
            "groups": groups,
            "findings": findings,
            "risk": risks[0] if risks else None,
            "alerts": alerts or [],
            "policy_id": policy_id,
        }
        policy_result = evaluate_policy(policy_id, policy_context)
        if not policy_result.eligible:
            return {"incident_created": False, "reason": policy_result.reason, "policy_id": policy_id}

        severity = _aggregate_severity(groups, findings, risks[0] if risks else None)
        confidence, confidence_factors = _compute_confidence(groups, findings, risks[0] if risks else None)
        risk_score = float(risks[0].get("score", 0)) if risks else 0.0
        entity_count = len(
            dict.fromkeys(
                [primary_entity_id]
                + [e for g in groups for e in (g.get("hosts", []) + g.get("users", []))]
            )
        )
        priority = _priority_from_context(severity, risk_score, entity_count)

        if title is None:
            titles = {
                "I001": "Potential Multi-Stage Lateral Movement Activity",
                "I004": "Potential Cross-Host Lateral Movement Activity",
                "I005": "Potential Credential Abuse Pattern",
                "I006": "Potential Ransomware / Impact Activity",
                "I007": "Potential Persistence Activity",
                "I002": "Potential High-Risk Entity Activity",
                "I003": "Potential Repeated High-Severity Activity",
                "I008": "Analyst Escalation",
            }
            title = titles.get(policy_id, "Potential Security Incident")

        _validate_title(title)
        title = _dedupe_title(title)

        claim_id = _next_incident_id(db)
        incident = IncidentV2(
            incident_id=claim_id,
            fingerprint=fingerprint,
            title=title,
            description=description or "Incident created from aggregated security evidence.",
            status="NEW",
            priority=priority,
            severity=severity,
            confidence=confidence,
            confidence_factors=confidence_factors,
            first_seen=min((g.get("first_seen", now) for g in groups), default=now),
            last_seen=max((g.get("last_seen", now) for g in groups), default=now),
            created_at=now,
            updated_at=now,
            closed_at=None,
            primary_entity_type=primary_entity_type,
            primary_entity_id=primary_entity_id,
            entity_ids=list(dict.fromkeys([primary_entity_id] + [e for g in groups for e in (g.get("hosts", []) + g.get("users", []))])),
            observables=_observables(groups, findings),
            investigation_state=None,
            assigned_to=None,
            assigned_team=None,
            assigned_at=None,
            source_type="CORRELATION" if findings else "BEHAVIOR_GROUP",
            source_id=correlation_finding_ids[0] if correlation_finding_ids else (behavior_group_ids[0] if behavior_group_ids else ""),
            incident_version="1.0.0",
            model_version=INCIDENT_MODEL_VERSION,
            policy_id=policy_id,
            created_by=actor,
            updated_by=actor,
        )
        db.add(incident)
        try:
            with db.begin_nested():
                db.flush()
        except IntegrityError:
            db.rollback()
            existing = db.scalars(
                select(IncidentV2).where(IncidentV2.fingerprint == fingerprint)
            ).first()
            if existing:
                return {"incident_id": existing.incident_id, "status": existing.status, "fingerprint": fingerprint}
            raise

        _link_sources(db, claim_id, groups, findings, risks)
        for alert in (alerts or []):
            db.add(
                IncidentV2AlertLink(
                    incident_id=claim_id,
                    alert_id=alert.get("alert_id", ""),
                    membership_reason="alert evidence",
                )
            )
        db.flush()
        _build_graph(db, claim_id, incident)

        audit(
            db,
            claim_id,
            "INCIDENT_CREATED",
            actor=actor,
            new_value=f"status={incident.status}, severity={incident.severity}, priority={incident.priority}",
            reason=f"policy {policy_id}",
            now=now,
        )
        duration = round((time.perf_counter() - start) * 1000.0, 3)
        db.add(
            IncidentV2AuditEvent(
                incident_id=claim_id,
                action="INCIDENT_CREATED",
                actor=actor,
                old_value=None,
                new_value=f"duration_ms={duration}",
                reason=f"policy {policy_id}",
                created_at=now,
            )
        )
        db.flush()
        for g in groups:
            add_evidence(
                db,
                claim_id,
                source_type="BEHAVIOR_GROUP",
                source_id=g.get("group_id") or g.get("behavior_group_id", ""),
                field="techniques",
                value=",".join(g.get("techniques", [])),
                reason="behavior group evidence",
                observed_at=now,
                actor=actor,
            )
        for f in findings:
            add_evidence(
                db,
                claim_id,
                source_type="CORRELATION",
                source_id=f.get("correlation_id") or f.get("finding_id", ""),
                field="correlation_type",
                value=f.get("correlation_type", ""),
                reason="correlation finding evidence",
                observed_at=now,
                actor=actor,
            )
        for a in alerts or []:
            add_evidence(
                db,
                claim_id,
                source_type="ALERT",
                source_id=a.get("alert_id", ""),
                field="alert",
                value=a.get("alert_id", ""),
                reason="alert evidence",
                observed_at=now,
                actor=actor,
            )
        for r in risks or []:
            add_evidence(
                db,
                claim_id,
                source_type="RISK",
                source_id=r.get("risk_id", ""),
                field="score",
                value=str(r.get("score", "")),
                reason="risk evidence",
                observed_at=now,
                actor=actor,
            )
        db.flush()
        return {
            "incident_id": claim_id,
            "status": incident.status,
            "fingerprint": fingerprint,
            "severity": incident.severity,
            "priority": incident.priority,
            "confidence": incident.confidence,
            "policy_id": policy_id,
            "incident_created": True,
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        try:
            audit(
                db,
                "unknown",
                "INCIDENT_CREATION_FAILED",
                actor=actor,
                reason=str(exc),
                now=now,
            )
        except Exception:  # noqa: BLE001
            pass
        raise


def transition_incident(
    db,
    incident_id: str,
    target_status: str,
    actor: str = "system",
    reason: str | None = None,
) -> dict:
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise ValueError(f"unknown incident {incident_id!r}")
    from backend.incidents.lifecycle import transition_status
    transition = transition_status(incident.status, target_status, actor, reason)
    incident.status = target_status
    incident.updated_at = datetime.now(timezone.utc)
    incident.updated_by = actor
    if target_status == "CLOSED":
        incident.closed_at = datetime.now(timezone.utc)
    db.flush()
    audit(
        db,
        incident_id,
        "INCIDENT_UPDATED",
        actor=actor,
        old_value=transition["old_status"],
        new_value=transition["new_status"],
        reason=reason,
        now=transition["transitioned_at"],
    )
    return transition


def suppress_incident(
    db,
    incident_id: str,
    reason: str,
    scope: str,
    expires_at: datetime,
    created_by: str,
) -> IncidentV2Suppression:
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise ValueError(f"unknown incident {incident_id!r}")
    if (expires_at - datetime.now(timezone.utc)).total_seconds() > INCIDENT_SUPPRESSION_MAX_DAYS * 86400:
        raise ValueError(f"suppression exceeds {INCIDENT_SUPPRESSION_MAX_DAYS} days")
    row = IncidentV2Suppression(
        incident_id=incident_id,
        fingerprint=incident.fingerprint,
        reason=reason,
        scope=scope,
        expires_at=expires_at,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    audit(
        db,
        incident_id,
        "INCIDENT_SUPPRESSED",
        actor=created_by,
        new_value=reason,
        now=datetime.now(timezone.utc),
    )
    incident.status = "SUPPRESSED"
    incident.updated_at = datetime.now(timezone.utc)
    incident.suppression_reason = reason
    incident.suppression_scope = scope
    incident.suppression_expires_at = expires_at
    incident.suppression_created_by = created_by
    db.flush()
    return row



