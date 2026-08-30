"""Phase 6 entity risk engine (spec 6.1, 6.12, 6.16, 6.30, 6.35-6.38).

The evidence -> factor -> score pipeline:

    EVIDENCE (Alert | Behavior Group | Correlation Finding)
      -> affected entities (HOST/USER/ACCOUNT/SOURCE_IP/DESTINATION_IP/PROCESS)
      -> registered factors with provenance (RF001-RF014)
      -> deterministic calculation (pure calculator, 0..100)
      -> snapshot (never overwritten) + audit + trend

Anti-double-counting (6.16): each unique evidence source contributes once.
A behavior group is one contribution per member - never one per member alert
(6.12). A correlation finding adds only its own contextual/sequence factor;
membership never re-adds group or alert factors. Repetition (6.13) applies
only to repeated *identical direct evidence*; groups absorb their member
alerts at the aggregation boundary.

Determinism (6.31): identical evidence in the same order produces identical
scores. Idempotency: re-ingesting the same source adds nothing. Concurrency
(6.35): INSERT ON CONFLICT DO NOTHING claims, never if-exists. The engine
never touches alerts, groups, findings, incidents, playbooks or SOAR (6.61),
refuses the production database by name, and every failure is contained and
audited as RISK_CALCULATION_FAILED (6.75).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from time import perf_counter

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import config
from backend.risk import audit as risk_audit
from backend.risk.calculator import (
    calculate_risk,
    thresholds_crossed,
    trend_for,
    utcnow,
)
from backend.risk.contract import ENTITY_TYPES, EVIDENCE_KINDS
from backend.risk.models import (
    EntityRiskV2,
    EntityRiskV2Event,
    EntityRiskV2Factor,
    EntityRiskV2Snapshot,
)
from backend.risk.registry import (
    FACTOR_ID_TYPES,
    get_factor,
    model_version,
    repetition_curve,
)

#: Technique -> registered factor (deterministic mapping, spec 6.9).
TECHNIQUE_FACTORS: dict[str, str] = {
    "T1021": "RF003_LATERAL_MOVEMENT",
    "T1021.001": "RF003_LATERAL_MOVEMENT",
    "T1021.002": "RF003_LATERAL_MOVEMENT",
    "T1570": "RF003_LATERAL_MOVEMENT",
    "T1059": "RF005_EXECUTION",
    "T1059.001": "RF005_EXECUTION",
    "T1047": "RF005_EXECUTION",
    "T1204": "RF005_EXECUTION",
    "T1203": "RF005_EXECUTION",
    "T1110": "RF002_CREDENTIAL_ACCESS",
    "T1133": "RF001_EXTERNAL_ACCESS",
    "T1190": "RF001_EXTERNAL_ACCESS",
    "T1078": "RF001_EXTERNAL_ACCESS",
    "T1566": "RF001_EXTERNAL_ACCESS",
    "T1547": "RF011_PERSISTENCE",
    "T1543": "RF011_PERSISTENCE",
    "T1136": "RF011_PERSISTENCE",
    "T1053": "RF011_PERSISTENCE",
    "T1562": "RF012_DEFENSE_EVASION",
    "T1070": "RF012_DEFENSE_EVASION",
    "T1218": "RF012_DEFENSE_EVASION",
    "T1036": "RF012_DEFENSE_EVASION",
    "T1068": "RF004_PRIVILEGE_ACTIVITY",
    "T1548": "RF004_PRIVILEGE_ACTIVITY",
    "T1134": "RF004_PRIVILEGE_ACTIVITY",
}

#: Factor ids whose technique contribution reaches destination hosts too
#: (external access and lateral movement target the entity being reached).
TECHNIQUE_FACTOR_DESTINATIONS = ("RF001_EXTERNAL_ACCESS", "RF003_LATERAL_MOVEMENT")

_PRIVATE_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "169.254.",
    "127.",
    "100.64.",
    "192.0.0.",
    "224.",
    "240.",
    "0.",
)


def _ensure_not_production_db() -> None:
    if (
        not config.V2_ENGINES_ALLOW_PROD
        and make_url(config.DATABASE_URL).database == config.PRODUCTION_DB_NAME
    ):
        raise RuntimeError(
            f"risk engine refuses the v1 production database "
            f"({config.PRODUCTION_DB_NAME!r}) by name"
        )


def is_external_ip(ip: str | None) -> bool:
    """Deterministic external check: any non-private literal address.

    RFC1918/loopback/link-local/metadata/CGNAT ranges are internal; empty
    values are never external.
    """
    if not ip:
        return False
    return not ip.startswith(_PRIVATE_PREFIXES)


def next_risk_id(db: Session) -> str:
    """Public id ER-<6-digit sequence>."""
    next_id = db.scalar(select(func.nextval("entity_risk_v2_id_seq")))
    return f"ER-{next_id:06d}"


def get_or_create_risk(
    db: Session,
    entity_type: str,
    entity_id: str,
    now: datetime | None = None,
    entity_name: str = "",
) -> EntityRiskV2:
    """Concurrency claim (6.35): INSERT ON CONFLICT DO NOTHING, never
    if-exists, then read the surviving row and use its id.

    The claimed public id (max sequence + 1) may collide under concurrent
    inserts of different entities; the nested savepoint turns that unique
    violation into a no-op so the surviving row is reused (6.87).
    """
    _ensure_not_production_db()
    if entity_type not in ENTITY_TYPES:
        raise ValueError(f"invalid entity type {entity_type!r}")
    if not entity_id:
        raise ValueError("entity_id must not be empty")
    now = now or utcnow()
    if entity_name == "":
        entity_name = entity_id

    # The claimed public id (max sequence + 1) may collide under concurrent
    # inserts of different entities; the nested savepoint turns that unique
    # violation into a no-op, and the retry claims the next free id. A
    # conflict on the (entity_type, entity_id) pair reuses the survivor.
    for _attempt in range(5):
        claim_id = next_risk_id(db)
        stmt = pg_insert(EntityRiskV2).values(
            risk_id=claim_id,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            score=0.0,
            severity="MINIMAL",
            state="NORMAL",
            confidence=1.0,
            trend="UNKNOWN",
            first_seen=now,
            last_seen=datetime(1970, 1, 1, tzinfo=UTC),
            created_at=now,
            updated_at=now,
        )
        stmt = stmt.on_conflict_do_nothing(index_elements=["entity_type", "entity_id"])
        try:
            with db.begin_nested():
                db.execute(stmt)
        except IntegrityError:
            pass
        db.flush()
        row = db.scalars(
            select(EntityRiskV2).where(
                EntityRiskV2.entity_type == entity_type,
                EntityRiskV2.entity_id == entity_id,
            )
        ).first()
        if row is not None:
            if row.risk_id == claim_id:
                if row.first_seen:
                    row.first_seen = min(row.first_seen, now)
                else:
                    row.first_seen = now
                db.flush()
                risk_audit.audit(
                    db,
                    row.risk_id,
                    "RISK_CREATED",
                    actor="system",
                    details={"entity_type": entity_type, "entity_id": entity_id},
                    model_version=model_version(),
                    now=now,
                )
            return row
    raise RuntimeError(
        f"risk get-or-create could not claim a row for {entity_type} {entity_id}"
    )


def risk_for_entity(
    db: Session, entity_type: str, entity_id: str
) -> EntityRiskV2 | None:
    return db.scalars(
        select(EntityRiskV2).where(
            EntityRiskV2.entity_type == entity_type,
            EntityRiskV2.entity_id == entity_id,
        )
    ).first()


def _log_event(
    db: Session,
    risk: EntityRiskV2,
    evidence_kind: str,
    source_type: str,
    source_id: str,
    source_seen_at: datetime | None,
    summary: str,
    now: datetime,
) -> None:
    stmt = pg_insert(EntityRiskV2Event).values(
        risk_id=risk.risk_id,
        evidence_kind=evidence_kind,
        source_type=source_type,
        source_id=source_id,
        source_seen_at=source_seen_at,
        summary=summary,
        captured_at=now,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["risk_id", "source_type", "source_id"]
    )
    db.execute(stmt)
    db.flush()


def _add_factor(
    db: Session,
    risk: EntityRiskV2,
    factor_id: str,
    source_type: str,
    source_id: str,
    value: float,
    *,
    reason: str,
    evidence: dict | None = None,
    origin: str = "DIRECT",
    propagation_from: str | None = None,
    relationship_type: str | None = None,
    expires_at: datetime | None = None,
    weight: float | None = None,
    now: datetime | None = None,
    observed: datetime | None = None,
) -> bool:
    """Insert a factor if absent (idempotency + concurrency, 6.35). Unknown
    factor ids are rejected (6.43). Returns True when newly created."""
    now = now or utcnow()
    definition = get_factor(factor_id)
    weight = float(weight if weight is not None else 1.0)
    contribution = min(value * weight, definition.maximum_contribution)

    stmt = pg_insert(EntityRiskV2Factor).values(
        risk_id=risk.risk_id,
        factor_id=factor_id,
        factor_type=FACTOR_ID_TYPES[factor_id],
        factor_version=definition.version,
        source_type=source_type,
        source_id=source_id,
        value=float(value),
        weight=weight,
        contribution=round(contribution, 4),
        reason=reason,
        evidence=evidence,
        origin=origin,
        propagation_from=propagation_from,
        relationship_type=relationship_type,
        created_at=observed or now,
        expires_at=expires_at,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["risk_id", "factor_id", "source_type", "source_id"]
    )
    db.execute(stmt)
    db.flush()
    row = db.scalars(
        select(EntityRiskV2Factor).where(
            EntityRiskV2Factor.risk_id == risk.risk_id,
            EntityRiskV2Factor.factor_id == factor_id,
            EntityRiskV2Factor.source_type == source_type,
            EntityRiskV2Factor.source_id == source_id,
        )
    ).first()
    if row is None:
        raise RuntimeError("risk factor get-or-create returned no row")
    if row.created_at == now:
        risk_audit.audit(
            db,
            risk.risk_id,
            "FACTOR_ADDED",
            actor="system",
            details={
                "factor_id": factor_id,
                "source_type": source_type,
                "source_id": source_id,
                "contribution": contribution,
                "origin": origin,
            },
            model_version=model_version(),
            now=now,
        )
        return True
    return False


def _factor_expiry(observed_at: datetime | None, now: datetime) -> datetime | None:
    """Factors live at most RISK_FACTOR_EXPIRES_HOURS past their evidence."""
    base = observed_at or now
    return base + timedelta(hours=float(config.RISK_FACTOR_EXPIRES_HOURS))


def _alert_entities(alert: dict) -> list[tuple[str, str]]:
    """Resolve the entities an alert directly involves (6.2)."""
    targets: list[tuple[str, str]] = []
    for key, entity_type in (
        ("host", "HOST"),
        ("user", "USER"),
        ("source_ip", "SOURCE_IP"),
        ("destination_ip", "DESTINATION_IP"),
        ("account", "ACCOUNT"),
        ("process", "PROCESS"),
    ):
        value = alert.get(key)
        if value:
            targets.append((entity_type, str(value)))
    return targets


def apply_alert(
    db: Session, alert: dict, now: datetime | None = None, actor: str = "system"
) -> list[str]:
    """Ingest one alert as direct evidence (spec 6.1).

    Per entity: one ALERT_SEVERITY tier factor (once per tier, never per
    alert - 6.12) and diminishing REPETITION factors for repeated identical
    evidence (6.13).
    """
    _ensure_not_production_db()
    now = now or utcnow()
    severity = str(alert.get("severity", "low")).lower()
    tier_value = float(config.RISK_ALERT_SEVERITY_CONTRIBUTIONS.get(severity, 1))
    observed = alert.get("first_seen") or alert.get("last_seen") or now
    detector = alert.get("detector_id") or alert.get("rule") or "unknown"
    alert_id = str(alert.get("alert_id") or alert.get("source_id") or "alert")

    affected: list[str] = []
    for entity_type, entity_id in _alert_entities(alert):
        risk = get_or_create_risk(db, entity_type, entity_id, now=now)
        affected.append(risk.risk_id)
        _log_event(
            db,
            risk,
            "ALERT",
            "alert",
            alert_id,
            observed,
            f"{severity} severity alert {alert_id} ({detector})",
            now,
        )
        risk.last_seen = max(risk.last_seen, observed) if risk.last_seen else observed
        risk.alert_count = (risk.alert_count or 0) + 1
        _add_factor(
            db,
            risk,
            "RF009_ALERT_SEVERITY",
            "alert",
            f"tier:{severity}",
            tier_value,
            reason=f"{severity} severity alert on the entity",
            evidence={
                "alert_id": alert_id,
                "detector_id": detector,
                "severity": severity,
                "technique": alert.get("mitre_technique"),
            },
            expires_at=_factor_expiry(observed, now),
            now=now,
            observed=observed,
        )
        # Occurrence of THIS alert = count of alert evidence events for the
        # detector (the current event was logged above, so the first alert
        # is occurrence 1 and never repeats; occurrences 2..k follow the
        # curve). Re-ingesting the same alert idempotently changes nothing.
        alert_occurrences = db.scalars(
            select(func.count())
            .select_from(EntityRiskV2Event)
            .where(
                EntityRiskV2Event.risk_id == risk.risk_id,
                EntityRiskV2Event.evidence_kind == "ALERT",
                EntityRiskV2Event.summary.like(f"%({detector})%"),
            )
        ).one()
        occurrence = int(alert_occurrences)
        if occurrence >= 2:
            curve = repetition_curve()
            repeat_value = curve[min(occurrence - 2, len(curve) - 1)]
            _add_factor(
                db,
                risk,
                "RF007_REPETITION",
                "alert",
                f"repeat:{detector}:{occurrence}",
                float(repeat_value),
                reason=(
                    f"repeated identical {detector} evidence on the entity "
                    f"(occurrence {occurrence})"
                ),
                evidence={
                    "alert_id": alert_id,
                    "detector_id": detector,
                    "occurrence": occurrence,
                    "curve_index": min(occurrence - 2, len(curve) - 1),
                },
                now=now,
                observed=observed,
            )
    if affected:
        for risk_id in dict.fromkeys(affected):
            recalculate_entity(db, risk_id, now=now, actor=actor)
    return list(dict.fromkeys(affected))


def _group_targets(group: dict) -> dict:
    """Targets for group evidence: members and destinations."""
    members = {
        "HOST": [str(h) for h in (group.get("hosts") or [])],
        "USER": [str(u) for u in (group.get("users") or [])],
        "SOURCE_IP": [str(s) for s in (group.get("source_ips") or [])],
        "DESTINATION_IP": [str(d) for d in (group.get("destination_ips") or [])],
    }
    external = bool(group.get("external_source", False))
    if not external:
        for source in members["SOURCE_IP"]:
            if is_external_ip(source):
                external = True
                break
    return {
        "members": members,
        "destinations": members["DESTINATION_IP"],
        "external": external,
    }


def apply_group(
    db: Session, group: dict, now: datetime | None = None, actor: str = "system"
) -> list[str]:
    """Ingest one behavior group (spec 6.1).

    A group is a single contribution per member entity - never one per member
    alert (6.12, 6.16). Technique factors come from the group's techniques;
    destinations of external access / lateral movement techniques receive
    their factor without becoming members.
    """
    _ensure_not_production_db()
    now = now or utcnow()
    group_id = str(group.get("group_id") or group.get("behavior_group_id") or "group")
    techniques = [str(t) for t in (group.get("techniques") or [])]
    targets = _group_targets(group)
    severity = str(group.get("severity", "low")).lower()
    tier_value = float(config.RISK_ALERT_SEVERITY_CONTRIBUTIONS.get(severity, 1))
    observed = group.get("last_seen") or group.get("first_seen") or now
    alert_count = int(group.get("alert_count") or 0)

    member_risks: dict[str, EntityRiskV2] = {}
    host_risks: dict[str, EntityRiskV2] = {}
    for entity_type, ids in targets["members"].items():
        for entity_id in ids:
            risk = get_or_create_risk(db, entity_type, entity_id, now=now)
            if entity_type == "HOST":
                host_risks[entity_id] = risk
            member_risks[f"{entity_type}:{entity_id}"] = risk

    all_risk = list(member_risks.values())
    target_host_risks = dict(host_risks)

    # RF010: one membership contribution per member (never per alert).
    for key, risk in member_risks.items():
        entity_type, entity_id = key.split(":", 1)
        _log_event(
            db,
            risk,
            "BEHAVIOR_GROUP",
            "behavior_group",
            group_id,
            observed,
            f"group {group_id} ({alert_count} alerts, {len(techniques)} techniques)",
            now,
        )
        risk.last_seen = max(risk.last_seen, observed) if risk.last_seen else observed
        if entity_type == "HOST":
            risk.group_count = (risk.group_count or 0) + 1
        risk.alert_count = (risk.alert_count or 0) + alert_count
        _add_factor(
            db,
            risk,
            "RF010_BEHAVIOR_GROUP",
            "behavior_group",
            group_id,
            float(config.RISK_FACTOR_WEIGHTS["RF010_BEHAVIOR_GROUP"]),
            reason=f"member of behavior group {group_id}",
            evidence={
                "group_id": group_id,
                "alert_count": alert_count,
                "techniques": techniques,
            },
            expires_at=_factor_expiry(observed, now),
            now=now,
            observed=observed,
        )

    # Technique factors: to member hosts, plus destinations for external
    # access / lateral movement techniques.
    for technique in techniques:
        factor_id = TECHNIQUE_FACTORS.get(technique)
        if factor_id is None:
            continue
        value = float(config.RISK_FACTOR_WEIGHTS.get(factor_id, 0.0))
        if value <= 0:
            continue
        hit_hosts = dict(target_host_risks)
        if factor_id in TECHNIQUE_FACTOR_DESTINATIONS:
            for destination in targets["destinations"]:
                if destination not in hit_hosts:
                    risk = get_or_create_risk(db, "HOST", destination, now=now)
                    hit_hosts[destination] = risk
                    target_host_risks[destination] = risk
        for risk in hit_hosts.values():
            _add_factor(
                db,
                risk,
                factor_id,
                "behavior_group",
                group_id,
                value,
                reason=f"{technique} activity involving the entity (group {group_id})",
                evidence={
                    "group_id": group_id,
                    "technique": technique,
                    "alert_count": alert_count,
                },
                expires_at=_factor_expiry(observed, now),
                now=now,
                observed=observed,
            )

    # RF009: one tier factor per severity, on member hosts only.
    if tier_value > 0:
        for risk in host_risks.values():
            _add_factor(
                db,
                risk,
                "RF009_ALERT_SEVERITY",
                "alert",
                f"tier:{severity}",
                tier_value,
                reason=f"{severity} severity behavior group on the entity",
                evidence={
                    "group_id": group_id,
                    "severity": severity,
                    "alert_count": alert_count,
                },
                expires_at=_factor_expiry(observed, now),
                now=now,
                observed=observed,
            )

    # RF001: external source activity
    if targets["external"]:
        for destination in targets["destinations"]:
            risk = target_host_risks.get(destination) or get_or_create_risk(
                db, "HOST", destination, now=now
            )
            target_host_risks[destination] = risk
            risk.last_seen = (
                max(risk.last_seen, observed) if risk.last_seen else observed
            )
            _add_factor(
                db,
                risk,
                "RF001_EXTERNAL_ACCESS",
                "behavior_group",
                group_id,
                float(config.RISK_FACTOR_WEIGHTS["RF001_EXTERNAL_ACCESS"]),
                reason=f"external source activity targeting the entity (group {group_id})",
                evidence={
                    "group_id": group_id,
                    "external_source": True,
                    "sources": targets["members"]["SOURCE_IP"],
                },
                expires_at=_factor_expiry(observed, now),
                now=now,
                observed=observed,
            )

    for risk in all_risk:
        recalculate_entity(db, risk.risk_id, now=now, actor=actor)
    for risk in target_host_risks.values():
        if risk not in all_risk:
            recalculate_entity(db, risk.risk_id, now=now, actor=actor)
    return list(dict.fromkeys(r.risk_id for r in all_risk))


def _apply_spread(db: Session, groups: list[dict], now: datetime) -> None:
    """RF013: entities that are members of many groups (spec 6.9).

    Spread is applied once per entity per evidence batch, from the group
    membership counts across the whole batch.
    """
    membership: dict[str, set[str]] = {}
    for group in groups:
        group_id = str(
            group.get("group_id") or group.get("behavior_group_id") or "group"
        )
        for entity_type, ids in (
            ("HOST", group.get("hosts") or []),
            ("USER", group.get("users") or []),
            ("SOURCE_IP", group.get("source_ips") or []),
        ):
            for entity_id in ids:
                membership.setdefault(f"{entity_type}:{entity_id}", set()).add(group_id)
    for key, group_ids in membership.items():
        if len(group_ids) < 3:
            continue
        entity_type, entity_id = key.split(":", 1)
        risk = get_or_create_risk(db, entity_type, entity_id, now=now)
        _add_factor(
            db,
            risk,
            "RF013_ENTITY_SPREAD",
            "behavior_group",
            f"spread:{len(group_ids)}",
            float(config.RISK_FACTOR_WEIGHTS["RF013_ENTITY_SPREAD"]),
            reason=f"entity is a member of {len(group_ids)} behavior groups",
            evidence={"group_ids": sorted(group_ids)},
            expires_at=_factor_expiry(now, now),
            now=now,
        )
        recalculate_entity(db, risk.risk_id, now=now)


def apply_groups(
    db: Session,
    groups: list[dict],
    now: datetime | None = None,
    actor: str = "system",
) -> list[str]:
    """Ingest many groups; spread is computed over the whole batch."""
    _ensure_not_production_db()
    now = now or utcnow()
    affected: list[str] = []
    for group in groups:
        affected.extend(apply_group(db, group, now=now, actor=actor))
    _apply_spread(db, groups, now)
    return list(dict.fromkeys(affected))


def apply_finding(
    db: Session,
    finding: dict,
    now: datetime | None = None,
    actor: str = "system",
) -> list[str]:
    """Ingest one correlation finding (spec 6.1).

    Only the sequence contribution (RF006) is added - membership never
    re-adds group or alert factors (6.16).
    """
    _ensure_not_production_db()
    now = now or utcnow()
    finding_id = str(
        finding.get("correlation_id") or finding.get("finding_id") or "finding"
    )
    observed = finding.get("last_seen") or finding.get("first_seen") or now
    value = float(config.RISK_FACTOR_WEIGHTS["RF006_MULTI_STAGE_CORRELATION"])
    affected: list[str] = []
    for entity_type, ids in (
        ("HOST", finding.get("hosts") or []),
        ("USER", finding.get("users") or []),
        ("SOURCE_IP", finding.get("source_ips") or []),
    ):
        for entity_id in ids:
            risk = get_or_create_risk(db, entity_type, entity_id, now=now)
            affected.append(risk.risk_id)
            _log_event(
                db,
                risk,
                "CORRELATION_FINDING",
                "correlation_finding",
                finding_id,
                observed,
                f"finding {finding_id} ({finding.get('correlation_type', '')})",
                now,
            )
            risk.last_seen = (
                max(risk.last_seen, observed) if risk.last_seen else observed
            )
            risk.correlation_count = (risk.correlation_count or 0) + 1
            _add_factor(
                db,
                risk,
                "RF006_MULTI_STAGE_CORRELATION",
                "correlation_finding",
                finding_id,
                value,
                reason=f"entity participates in correlated sequence {finding_id}",
                evidence={
                    "correlation_id": finding_id,
                    "correlation_type": finding.get("correlation_type"),
                    "confidence": finding.get("confidence"),
                    "member_group_ids": finding.get("member_group_ids"),
                },
                expires_at=_factor_expiry(observed, now),
                now=now,
                observed=observed,
            )
    if affected:
        for risk_id in dict.fromkeys(affected):
            recalculate_entity(db, risk_id, now=now, actor=actor)
    return list(dict.fromkeys(affected))


def apply_propagation(
    db: Session,
    target_entity_type: str,
    target_entity_id: str,
    *,
    from_entity: str,
    relationship_type: str,
    evidence: dict | None = None,
    reason: str = "",
    now: datetime | None = None,
    actor: str = "system",
) -> str:
    """Bounded contextual propagation (spec 6.27).

    Risk is never copied: the propagated contribution is fixed per
    relationship type (RISK_PROPAGATION_WEIGHTS), carries the relationship
    type + evidence, and expires after RISK_PROPAGATION_EXPIRES_HOURS.
    """
    _ensure_not_production_db()
    now = now or utcnow()
    weight = float(config.RISK_PROPAGATION_WEIGHTS.get(relationship_type, 0.0))
    if weight <= 0:
        raise ValueError(f"unknown propagation relationship {relationship_type!r}")
    risk = get_or_create_risk(db, target_entity_type, target_entity_id, now=now)
    risk.last_seen = max(risk.last_seen, now) if risk.last_seen else now
    _add_factor(
        db,
        risk,
        "RF006_MULTI_STAGE_CORRELATION",
        "propagation",
        f"{relationship_type}:{from_entity}",
        weight,
        reason=reason
        or f"contextual propagation from {from_entity} ({relationship_type})",
        evidence=dict(evidence or {}),
        origin="CONTEXTUAL",
        propagation_from=from_entity,
        relationship_type=relationship_type,
        expires_at=now + timedelta(hours=float(config.RISK_PROPAGATION_EXPIRES_HOURS)),
        now=now,
    )
    recalculate_entity(db, risk.risk_id, now=now, actor=actor)
    return risk.risk_id


def _refresh_recency(db: Session, risk: EntityRiskV2, now: datetime) -> None:
    """RF008: recent evidence keeps the risk current (6.11, 6.19).

    The factor is refreshed (value = configured weight) while the entity's
    last seen evidence is younger than the recency window; otherwise it is
    expired so the calculation ignores it.
    """
    window = timedelta(hours=float(config.RISK_RECENCY_BONUS_HOURS))
    recent = risk.last_seen is not None and (now - risk.last_seen) <= window
    factor = db.scalars(
        select(EntityRiskV2Factor).where(
            EntityRiskV2Factor.risk_id == risk.risk_id,
            EntityRiskV2Factor.factor_id == "RF008_RECENCY",
            EntityRiskV2Factor.source_type == "recency",
        )
    ).first()
    if recent:
        value = float(config.RISK_FACTOR_WEIGHTS["RF008_RECENCY"])
        if factor is None:
            _add_factor(
                db,
                risk,
                "RF008_RECENCY",
                "recency",
                "activity",
                value,
                reason="recent activity keeps the risk current",
                evidence={
                    "last_seen": risk.last_seen.isoformat() if risk.last_seen else None,
                    "window_hours": config.RISK_RECENCY_BONUS_HOURS,
                },
                now=now,
                observed=risk.last_seen or now,
            )
        else:
            factor.value = value
            factor.weight = 1.0
            factor.expired_at = None
            factor.created_at = min(factor.created_at, risk.last_seen or now)
    elif factor is not None and factor.expired_at is None:
        factor.expired_at = now
        factor.expires_at = now
        risk_audit.audit(
            db,
            risk.risk_id,
            "FACTOR_EXPIRED",
            actor="system",
            details={"factor_id": "RF008_RECENCY", "source_id": "activity"},
            model_version=model_version(),
            now=now,
        )


def expire_factors(
    db: Session, now: datetime | None = None, actor: str = "system"
) -> int:
    """Mark every factor past its expiry (6.21); history remains (6.72)."""
    _ensure_not_production_db()
    now = now or utcnow()
    rows = db.scalars(
        select(EntityRiskV2Factor).where(
            EntityRiskV2Factor.expires_at.is_not(None),
            EntityRiskV2Factor.expires_at <= now,
            EntityRiskV2Factor.expired_at.is_(None),
        )
    ).all()
    for row in rows:
        row.expired_at = now
        risk_audit.audit(
            db,
            row.risk_id,
            "FACTOR_EXPIRED",
            actor=actor,
            details={
                "factor_id": row.factor_id,
                "source_type": row.source_type,
                "source_id": row.source_id,
            },
            model_version=model_version(),
            now=now,
        )
    db.flush()
    return len(rows)


def recalculate_entity(
    db: Session,
    risk_id: str,
    now: datetime | None = None,
    actor: str = "system",
) -> dict:
    """Deterministic recalculation from stored factors (6.30, 6.36).

    Snapshots are append-only (6.23); stale entities are marked STALE
    (6.76); peak and trend are updated without ever rewriting history.
    """
    now = now or utcnow()
    risk = db.scalars(
        select(EntityRiskV2).where(EntityRiskV2.risk_id == risk_id)
    ).first()
    if risk is None:
        raise ValueError(f"unknown risk id {risk_id!r}")

    _calc_started = perf_counter()
    _refresh_recency(db, risk, now)
    factors = db.scalars(
        select(EntityRiskV2Factor)
        .where(EntityRiskV2Factor.risk_id == risk_id)
        .order_by(EntityRiskV2Factor.id)
    ).all()
    factor_dicts = [
        {
            "factor_id": f.factor_id,
            "factor_type": f.factor_type,
            "source_type": f.source_type,
            "source_id": f.source_id,
            "value": f.value,
            "weight": f.weight,
            "origin": f.origin,
            "created_at": f.created_at,
            "expires_at": f.expires_at,
            "reason": f.reason,
            "evidence": f.evidence,
        }
        for f in factors
    ]
    calculation = calculate_risk(factor_dicts, now)

    previous = db.scalars(
        select(EntityRiskV2Snapshot)
        .where(EntityRiskV2Snapshot.risk_id == risk_id)
        .order_by(EntityRiskV2Snapshot.id.desc())
        .limit(1)
    ).first()
    previous_score = previous.score if previous else None
    trend = trend_for(
        previous_score,
        calculation.final_score,
        delta=float(config.RISK_TREND_DELTA),
    )

    stale_window = timedelta(minutes=float(config.RISK_STALE_AFTER_MINUTES))
    is_stale = (
        risk.last_calculated_at is not None
        and (now - risk.last_calculated_at) > stale_window
        and risk.score > 0
    )

    old_score = risk.score
    old_state = risk.state

    risk.score = calculation.final_score
    risk.severity = calculation.severity
    risk.state = "STALE" if is_stale else calculation.state
    risk.confidence = calculation.confidence
    risk.trend = trend
    risk.active_factor_count = calculation.active_factor_count
    risk.risk_model_version = calculation.risk_model_version
    risk.last_calculated_at = now
    risk.updated_at = now
    if calculation.final_score >= risk.peak_score:
        risk.peak_score = calculation.final_score
        risk.peak_at = now
    db.flush()

    db.add(
        EntityRiskV2Snapshot(
            risk_id=risk_id,
            score=calculation.final_score,
            severity=calculation.severity,
            state=calculation.state,
            trend=trend,
            factor_count=calculation.factor_count,
            evidence_count=risk.evidence_count,
            risk_model_version=calculation.risk_model_version,
            captured_at=now,
        )
    )

    risk_audit.audit(
        db,
        risk_id,
        "RISK_RECALCULATED",
        actor=actor,
        details={
            "base_score": calculation.base_score,
            "factor_count": calculation.factor_count,
            "expired_factor_count": calculation.expired_factor_count,
            "duration_ms": round((perf_counter() - _calc_started) * 1000.0, 3),
        },
        old_score=old_score,
        new_score=calculation.final_score,
        old_state=old_state,
        new_state=risk.state,
        model_version=calculation.risk_model_version,
        now=now,
    )
    if risk.state != old_state:
        risk_audit.audit(
            db,
            risk_id,
            "RISK_STATE_CHANGED",
            actor=actor,
            old_state=old_state,
            new_state=risk.state,
            model_version=calculation.risk_model_version,
            now=now,
        )
    crossed = thresholds_crossed(old_score, calculation.final_score)
    if crossed:
        risk_audit.audit(
            db,
            risk_id,
            "RISK_THRESHOLD_CROSSED",
            actor=actor,
            details={"severities": crossed},
            old_score=old_score,
            new_score=calculation.final_score,
            model_version=calculation.risk_model_version,
            now=now,
        )
    db.flush()
    return {
        "risk_id": risk_id,
        "score": calculation.final_score,
        "severity": calculation.severity,
        "state": risk.state,
        "trend": trend,
        "confidence": calculation.confidence,
        "calculation": calculation,
    }


def recalculate_all(
    db: Session,
    now: datetime | None = None,
    actor: str = "system",
) -> int:
    """Recalculate every entity record (6.37)."""
    _ensure_not_production_db()
    now = now or utcnow()
    risk_ids = list(db.scalars(select(EntityRiskV2.risk_id)).all())
    for risk_id in risk_ids:
        recalculate_entity(db, risk_id, now=now, actor=actor)
    db.commit()
    return len(risk_ids)


def manual_recalculate(
    db: Session,
    risk_id: str,
    now: datetime | None = None,
    actor: str = "system",
) -> dict:
    """Operator-triggered recalculation (spec 6.65): same path as the
    engine, no side effects beyond snapshot/audit."""
    result = recalculate_entity(db, risk_id, now=now, actor=actor)
    db.commit()
    return result


def ingest_evidence(
    db: Session,
    evidence: list[dict],
    now: datetime | None = None,
    actor: str = "system",
) -> list[str]:
    """Typed evidence batch (spec 6.1). Unknown kinds are rejected."""
    _ensure_not_production_db()
    now = now or utcnow()
    affected: list[str] = []
    for item in evidence:
        kind = item.get("kind")
        if kind not in EVIDENCE_KINDS:
            raise ValueError(f"invalid evidence kind {kind!r}")
        if kind == "ALERT":
            affected.extend(apply_alert(db, item, now=now, actor=actor))
        elif kind == "BEHAVIOR_GROUP":
            affected.extend(apply_group(db, item, now=now, actor=actor))
        elif kind == "CORRELATION_FINDING":
            affected.extend(apply_finding(db, item, now=now, actor=actor))
        elif kind == "DETECTION":
            affected.extend(apply_alert(db, item, now=now, actor=actor))
    db.commit()
    return list(dict.fromkeys(affected))


def failure_boundary(
    db: Session, risk_id: str, error: Exception, now: datetime | None = None
) -> None:
    """Contain a calculation failure (6.75): previous state stays intact."""
    risk_audit.audit(
        db,
        risk_id,
        "RISK_CALCULATION_FAILED",
        actor="system",
        details={"error": str(error)[:500]},
        model_version=model_version(),
        now=now or utcnow(),
    )
    db.commit()
