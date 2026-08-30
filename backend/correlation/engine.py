"""Phase 5 correlation engine (spec 5.2, 5.5, 5.35-5.37).

The Behavior Group -> Correlation Finding pipeline:

    BEHAVIOR GROUPS
      -> summaries (family, hosts, users, sources, techniques)
      -> candidate pairs (partitioned by entity + time - never O(n^2))
      -> pair rules R001-R008 match? (>= 2 relationships required)
            no  -> uncorrelated; never a catch-all
            yes -> extend the first matching live finding, or create a
                   new finding from the first matching earlier group
      -> chain type resolution (LATERAL_MOVEMENT > HOST_CHAIN >
         MULTI_STAGE > pair rule type)
      -> fingerprint = SHA256(type + sorted member ids + normalized edges)
      -> claim fingerprint (partial unique index, ON CONFLICT)

Determinism (5.5): same groups -> same findings, always. Idempotency
(5.47): re-running attaches nothing twice. Concurrency (5.35): at most one
LIVE finding per fingerprint - partial unique index + INSERT ON CONFLICT
DO NOTHING, never if-exists. Correlation failures never break telemetry
(5.77): every store call is guarded and the run continues.

Hard boundaries (5.68, 5.79): the ONLY tables written are the five
correlation tables; behavior groups, alerts, incidents, risk, playbooks
and SOAR are never touched, and the engine refuses the production database
by name.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from backend import config
from backend.aggregation.evidence import merge_observables
from backend.aggregation.models import BehaviorGroupRecord
from backend.alerting.models import AlertRecord
from backend.correlation import audit
from backend.correlation.confidence import confidence
from backend.correlation.contract import (
    CORRELATION_TYPES,
    EDGE_TYPES,
    TYPE_TITLES,
    is_progression,
)
from backend.correlation.edges import (
    edge_strength,
    meets_minimum,
    pair_relationships,
)
from backend.correlation.evidence import evidence_rows
from backend.correlation.fingerprint import finding_fingerprint
from backend.correlation.lifecycle import IllegalTransition, apply_transition
from backend.correlation.models import (
    CorrelationEdge,
    CorrelationEvidence,
    CorrelationFindingRecord,
    CorrelationMember,
)
from backend.correlation.registry import pair_rules
from backend.correlation.rules import primary_phase

_LIVE = ("NEW", "ACTIVE", "QUIET")
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _ensure_not_production_db() -> None:
    if (
        not config.V2_ENGINES_ALLOW_PROD
        and make_url(config.DATABASE_URL).database == config.PRODUCTION_DB_NAME
    ):
        raise RuntimeError(
            f"correlation engine refuses the v1 production database "
            f"({config.PRODUCTION_DB_NAME!r}) by name"
        )


def next_correlation_id(db: Session) -> str:
    """Public id CF-<6-digit sequence> - never the fingerprint."""
    row = db.scalars(
        select(CorrelationFindingRecord)
        .order_by(CorrelationFindingRecord.id.desc())
        .limit(1)
    ).first()
    return f"CF-{(row.id if row else 0) + 1:06d}"


def family_of_group(db: Session, group: BehaviorGroupRecord) -> str:
    """Deterministic group family: lexicographically first family among the
    member alerts' detectors (fingerprint equality guarantees one family)."""
    ids = list(group.alert_ids or [])
    if not ids:
        return config.BEHAVIOR_FAMILY_DEFAULT
    alerts = db.scalars(
        select(AlertRecord)
        .where(AlertRecord.alert_id.in_(ids))
        .order_by(AlertRecord.first_seen)
    ).all()
    families = {
        config.DETECTOR_BEHAVIOR_FAMILIES.get(
            a.detector_id or "", config.BEHAVIOR_FAMILY_DEFAULT
        )
        for a in alerts
    }
    return min(families)


def group_summary(db: Session, group: BehaviorGroupRecord) -> dict:
    """Deterministic summary a rule can evaluate - never alert titles."""
    return {
        "id": group.behavior_group_id,
        "family": family_of_group(db, group),
        "hosts": list(group.host_ids or []),
        "users": list(group.user_ids or []),
        "sources": list(group.source_ips or []),
        "techniques": list(group.mitre_techniques or []),
        "tactics": list(group.mitre_tactics or []),
        "destinations": list((group.observables or {}).get("destination_ips", [])),
        "alert_ids": list(group.alert_ids or []),
        "first_seen": group.first_seen,
        "last_seen": group.last_seen,
        "severity": group.highest_severity or "low",
        "alert_count": group.alert_count,
        "occurrence_count": group.occurrence_count,
    }


def match_pair(earlier: dict, later: dict) -> list[tuple[object, dict, str]]:
    """Every pair rule that matches (earlier, later), in priority order,
    each with its relationship bundle and its "why correlated" reason. An
    empty list means the pair does not correlate - no catch-all (5.74).

    A pair only ever correlates inside the rule's sequence window (5.10):
    the temporal relationship must actually hold for the rule to count.
    """
    from backend.correlation.windows import within_window as window_check

    matches: list[tuple[object, dict, str]] = []
    for rule in pair_rules():
        temporal = window_check(
            earlier["first_seen"], later["first_seen"], rule.window_key
        )
        if not temporal:
            continue
        rel = pair_relationships(
            earlier, later, window_key=rule.window_key, within_window=temporal
        )
        if not meets_minimum(rel):
            continue
        reason = rule.matches(earlier, later)
        if reason is None:
            continue
        matches.append((rule, rel, reason))
    return matches


def edges_for_pair(
    earlier: dict,
    later: dict,
    matches: list[tuple[object, dict, str]],
    rel: dict,
) -> list[dict]:
    """One edge per relationship type, ordered by EDGE_TYPES (deterministic).

    Rule-emitted edge types (R002/R004/R007/R008) are added when the pair
    matched their rule, never duplicated.
    """
    types = list(rel["types"])
    for rule, _rule_rel, _reason in matches:
        for edge_type in rule.emits_edges:
            if edge_type not in types:
                types.append(edge_type)
    types = [t for t in EDGE_TYPES if t in types]

    shared_entities = sorted(
        set(rel["shared"]["hosts"])
        | set(rel["shared"]["users"])
        | set(rel["shared"]["sources"])
    )
    shared_techniques = sorted(
        {str(t) for t in (earlier.get("techniques") or [])}
        & {str(t) for t in (later.get("techniques") or [])}
    )
    return [
        {
            "source_group_id": earlier["id"],
            "target_group_id": later["id"],
            "relationship_type": edge_type,
            "time_delta_seconds": rel.get("time_delta_seconds"),
            "shared_entities": shared_entities,
            "shared_techniques": shared_techniques,
            "evidence": [
                {
                    "field": "relationship",
                    "value": edge_type,
                    "reason": f"shared context between {earlier['id']} and {later['id']}",
                }
            ],
            "strength": edge_strength(types),
        }
        for edge_type in types
    ]


def resolve_chain_type(
    member_summaries: list[dict],
    edge_types: set[str],
    creation_type: str,
) -> str:
    """Deterministic finding type (spec 5.4): the most specific claim the
    evidence supports. LATERAL_MOVEMENT > HOST_CHAIN > MULTI_STAGE >
    the creating pair rule's type."""
    if "LATERAL_MOVEMENT" in edge_types:
        return "LATERAL_MOVEMENT"
    hosts = set()
    for member in member_summaries:
        hosts.update(str(h).lower() for h in (member.get("hosts") or []))
    phases = {
        primary_phase(member)
        for member in member_summaries
        if primary_phase(member) != "UNKNOWN_PHASE"
    }
    if len(hosts) >= 3 and bool(
        edge_types & {"NETWORK_RELATION", "DESTINATION_RELATION"}
    ):
        return "HOST_CHAIN"
    if len(member_summaries) >= 3 and len(phases) >= 2:
        return "MULTI_STAGE"
    if creation_type not in CORRELATION_TYPES:
        return "TEMPORAL"
    return creation_type


def finding_confidence(member_summaries: list[dict], edges: list[dict]) -> float:
    """Deterministic bounded confidence (spec 5.23) - never summed from
    group confidences (spec 5.24)."""
    relationship_types = {edge["relationship_type"] for edge in edges}
    has_lateral = "LATERAL_MOVEMENT" in relationship_types
    has_progression = any(
        is_progression(primary_phase(a), primary_phase(b))
        for a, b in itertools.pairwise(member_summaries)
    )
    return confidence(
        relationship_types,
        len(member_summaries),
        has_progression,
        has_lateral,
    )


def _live_finding_for(db: Session, fp: str) -> CorrelationFindingRecord | None:
    return db.scalars(
        select(CorrelationFindingRecord).where(
            CorrelationFindingRecord.fingerprint == fp,
            CorrelationFindingRecord.status.in_(_LIVE),
        )
    ).first()


def _claim_finding(
    db: Session,
    fp: str,
    *,
    correlation_type: str,
    member_group_ids: list[str],
    first_seen,
    last_seen,
    title: str,
    description: str,
    severity: str,
    confidence_value: float,
    member_alert_ids: list[str],
    entities: list[str],
    hosts: list[str],
    users: list[str],
    source_ips: list[str],
    mitre_tactics: list[str],
    mitre_techniques: list[str],
    observables: dict,
    edges: list[dict],
    now: datetime,
) -> tuple[CorrelationFindingRecord | None, bool]:
    """Atomically claim the fingerprint (spec 5.35). Returns (finding, created).

    Mirrors the Phase 4 group claim: ON CONFLICT DO NOTHING against the
    partial unique index, then the live row is re-read - the claim is ours
    exactly when it carries our id.
    """
    candidate = CorrelationFindingRecord(
        correlation_id=next_correlation_id(db),
        fingerprint=fp,
        title=title,
        description=description,
        status="NEW",
        correlation_type=correlation_type,
        first_seen=first_seen,
        last_seen=last_seen,
        member_group_ids=member_group_ids,
        member_alert_ids=member_alert_ids,
        entities=entities,
        hosts=hosts,
        users=users,
        source_ips=source_ips,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        observables=observables,
        confidence=confidence_value,
        highest_severity=severity,
        created_at=now,
        updated_at=now,
    )
    stmt = (
        pg_insert(CorrelationFindingRecord)
        .values(
            **{
                col: getattr(candidate, col)
                for col in (
                    "correlation_id",
                    "fingerprint",
                    "title",
                    "description",
                    "status",
                    "correlation_type",
                    "first_seen",
                    "last_seen",
                    "member_group_ids",
                    "member_alert_ids",
                    "entities",
                    "hosts",
                    "users",
                    "source_ips",
                    "mitre_tactics",
                    "mitre_techniques",
                    "observables",
                    "confidence",
                    "highest_severity",
                    "created_at",
                    "updated_at",
                )
            }
        )
        .on_conflict_do_nothing(
            index_elements=["fingerprint"],
            index_where=text("status IN ('NEW', 'ACTIVE', 'QUIET')"),
        )
    )
    db.execute(stmt)
    existing = _live_finding_for(db, fp)
    if existing is None:
        return None, False
    return existing, existing.correlation_id == candidate.correlation_id


def _merge_unique(current: list | None, values: list[str]) -> list[str]:
    merged = list(dict.fromkeys([str(v) for v in (current or []) if v]))
    for value in values:
        if value and value not in merged:
            merged.append(value)
    return merged


def _write_member(
    db: Session,
    finding_id: str,
    group_id: str,
    reason: str,
    role: str,
    now: datetime,
) -> None:
    db.execute(
        pg_insert(CorrelationMember)
        .values(
            correlation_id=finding_id,
            behavior_group_id=group_id,
            membership_reason=reason,
            role=role,
            created_at=now,
        )
        .on_conflict_do_nothing(constraint="uq_corr_member_group")
    )


def _write_edges(
    db: Session,
    finding_id: str,
    edges: list[dict],
    now: datetime,
) -> None:
    for edge in edges:
        db.execute(
            pg_insert(CorrelationEdge)
            .values(
                correlation_id=finding_id,
                source_group_id=edge["source_group_id"],
                target_group_id=edge["target_group_id"],
                relationship_type=edge["relationship_type"],
                time_delta_seconds=edge.get("time_delta_seconds"),
                shared_entities=edge.get("shared_entities"),
                shared_techniques=edge.get("shared_techniques"),
                evidence=edge.get("evidence"),
                strength=edge.get("strength", 0.0),
                created_at=now,
            )
            .on_conflict_do_nothing(constraint="uq_corr_edge_pair")
        )


def _write_evidence(
    db: Session,
    finding_id: str,
    summaries: list[dict],
    reasons: dict[str, str],
    now: datetime,
) -> None:
    for summary in summaries:
        reason = reasons.get(summary["id"], "member of correlation")
        for row in evidence_rows(
            finding_id, summary, rule_id="correlation", reason=reason
        ):
            db.add(
                CorrelationEvidence(
                    correlation_id=finding_id,
                    behavior_group_id=summary["id"],
                    field=row["field"],
                    value=row["value"],
                    reason=row["reason"],
                    created_at=now,
                )
            )


def _description(member_ids: list[str], matches: list[tuple[object, dict, str]]) -> str:
    reasons = [match[0].description for match in matches]
    text = (
        f"This correlation links {len(member_ids)} behavior group(s): "
        f"{', '.join(member_ids)}. "
        + (" ".join(reasons) if reasons else "")
        + " Confidence is a deterministic correlation score, not a risk verdict."
    )
    return text


def _aggregate(members: list[dict]) -> dict:
    """Deterministic finding aggregates from member summaries."""
    hosts: list[str] = []
    users: list[str] = []
    sources: list[str] = []
    tactics: list[str] = []
    techniques: list[str] = []
    alert_ids: list[str] = []
    observables: dict = {}
    for member in members:
        hosts = _merge_unique(hosts, member.get("hosts") or [])
        users = _merge_unique(users, member.get("users") or [])
        sources = _merge_unique(sources, member.get("sources") or [])
        tactics = _merge_unique(tactics, member.get("tactics") or [])
        techniques = _merge_unique(techniques, member.get("techniques") or [])
        alert_ids = _merge_unique(alert_ids, member.get("alert_ids") or [])
        observables = merge_observables(
            observables,
            {
                "hosts": member.get("hosts") or [],
                "users": member.get("users") or [],
                "source_ips": member.get("sources") or [],
                "destination_ips": member.get("destinations") or [],
            },
        )
    return {
        "member_alert_ids": alert_ids,
        "entities": users,
        "hosts": hosts,
        "users": users,
        "source_ips": sources,
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "observables": observables,
    }


def _create_finding(
    db: Session,
    earlier: dict,
    later: dict,
    matches: list[tuple[object, dict, str]],
    now: datetime,
    actor: str,
) -> CorrelationFindingRecord | None:
    primary_rule, primary_rel, primary_reason = matches[0]
    edges = edges_for_pair(earlier, later, matches, primary_rel)
    edge_types = {edge["relationship_type"] for edge in edges}
    members = [earlier, later]
    correlation_type = resolve_chain_type(
        members, edge_types, primary_rule.correlation_type
    )
    fp = finding_fingerprint(correlation_type, [earlier["id"], later["id"]], edges)
    confidence_value = finding_confidence(members, edges)
    aggregates = _aggregate(members)

    finding, created = _claim_finding(
        db,
        fp,
        correlation_type=correlation_type,
        member_group_ids=[earlier["id"], later["id"]],
        first_seen=min(earlier["first_seen"], later["first_seen"]),
        last_seen=max(earlier["first_seen"], later["first_seen"]),
        title=TYPE_TITLES.get(correlation_type, "Related Behavioral Activity"),
        description=_description([earlier["id"], later["id"]], matches),
        severity=max(
            (earlier.get("severity") or "low", later.get("severity") or "low"),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
        ),
        confidence_value=confidence_value,
        edges=edges,
        now=now,
        **aggregates,
    )
    if not created:
        return None

    _write_member(
        db, finding.correlation_id, earlier["id"], primary_reason, "seed", now
    )
    _write_member(
        db, finding.correlation_id, later["id"], primary_reason, "member", now
    )
    _write_edges(db, finding.correlation_id, edges, now)
    _write_evidence(
        db,
        finding.correlation_id,
        members,
        {earlier["id"]: primary_reason, later["id"]: primary_reason},
        now,
    )

    audit.record(
        db,
        correlation_id=finding.correlation_id,
        action="CORRELATION_CREATED",
        actor=actor,
        details={
            "rule_id": primary_rule.rule_id,
            "correlation_type": correlation_type,
            "fingerprint": fp[:16],
            "member_group_ids": [earlier["id"], later["id"]],
            "relationships": sorted(edge_types),
            "confidence": confidence_value,
        },
        now=now,
    )
    for edge in edges:
        audit.record(
            db,
            correlation_id=finding.correlation_id,
            action="EDGE_CREATED",
            actor=actor,
            details={
                "source_group_id": edge["source_group_id"],
                "target_group_id": edge["target_group_id"],
                "relationship_type": edge["relationship_type"],
                "strength": edge["strength"],
            },
            now=now,
        )
    return finding


def _extend_finding(
    db: Session,
    finding: CorrelationFindingRecord,
    member_summaries: dict[str, dict],
    tail: dict,
    group: dict,
    matches: list[tuple[object, dict, str]],
    now: datetime,
    actor: str,
) -> bool:
    """Attach ``group`` after ``tail`` inside ``finding`` (spec 5.5, 5.47).

    Returns False when the extension would violate live-fingerprint
    uniqueness (another finding already owns the resulting fingerprint) -
    the group then stays uncorrelated rather than corrupting the store.
    """
    primary_rule, primary_rel, primary_reason = matches[0]
    new_edges = edges_for_pair(tail, group, matches, primary_rel)
    old_members = list(finding.member_group_ids or [])
    new_members = old_members + [group["id"]]

    all_edges = [
        {
            "source_group_id": e.source_group_id,
            "target_group_id": e.target_group_id,
            "relationship_type": e.relationship_type,
        }
        for e in db.scalars(
            select(CorrelationEdge).where(
                CorrelationEdge.correlation_id == finding.correlation_id
            )
        ).all()
    ] + new_edges
    edge_types = {edge["relationship_type"] for edge in all_edges}

    summaries = [member_summaries[member_id] for member_id in new_members]
    correlation_type = resolve_chain_type(
        summaries, edge_types, finding.correlation_type
    )
    fp = finding_fingerprint(correlation_type, new_members, all_edges)
    if fp != finding.fingerprint:
        conflict = db.scalars(
            select(CorrelationFindingRecord).where(
                CorrelationFindingRecord.fingerprint == fp,
                CorrelationFindingRecord.status.in_(_LIVE),
                CorrelationFindingRecord.id != finding.id,
            )
        ).first()
        if conflict is not None:
            audit.record(
                db,
                correlation_id=finding.correlation_id,
                action="CORRELATION_UPDATED",
                actor=actor,
                details={
                    "decision": "extension rejected",
                    "reason": "live fingerprint already owned",
                    "group_id": group["id"],
                    "fingerprint": fp[:16],
                },
                now=now,
            )
            return False

    was_quiet = finding.status == "QUIET"
    if finding.status in ("NEW", "QUIET"):
        apply_transition(finding, "ACTIVE", now)

    aggregates = _aggregate(summaries)
    finding.fingerprint = fp
    finding.correlation_type = correlation_type
    finding.title = TYPE_TITLES.get(correlation_type, finding.title)
    finding.description = _description(new_members, matches)
    finding.member_group_ids = new_members
    finding.member_alert_ids = aggregates["member_alert_ids"]
    finding.entities = aggregates["entities"]
    finding.hosts = aggregates["hosts"]
    finding.users = aggregates["users"]
    finding.source_ips = aggregates["source_ips"]
    finding.mitre_tactics = aggregates["mitre_tactics"]
    finding.mitre_techniques = aggregates["mitre_techniques"]
    finding.observables = aggregates["observables"]
    finding.first_seen = min(
        finding.first_seen, tail["first_seen"], group["first_seen"]
    )
    finding.last_seen = max(finding.last_seen, tail["first_seen"], group["first_seen"])
    finding.confidence = finding_confidence(summaries, all_edges)
    finding.highest_severity = max(
        (finding.highest_severity, group.get("severity") or "low"),
        key=lambda s: _SEVERITY_RANK.get(s, 0),
    )
    finding.updated_at = now

    _write_member(
        db, finding.correlation_id, group["id"], primary_reason, "member", now
    )
    _write_edges(db, finding.correlation_id, new_edges, now)
    _write_evidence(
        db,
        finding.correlation_id,
        [group],
        {group["id"]: primary_reason},
        now,
    )

    audit.record(
        db,
        correlation_id=finding.correlation_id,
        action="GROUP_ADDED",
        actor=actor,
        details={
            "group_id": group["id"],
            "rule_id": primary_rule.rule_id,
            "membership_reason": primary_reason,
            "status": "reactivated" if was_quiet else "extended",
        },
        now=now,
    )
    for edge in new_edges:
        audit.record(
            db,
            correlation_id=finding.correlation_id,
            action="EDGE_CREATED",
            actor=actor,
            details={
                "source_group_id": edge["source_group_id"],
                "target_group_id": edge["target_group_id"],
                "relationship_type": edge["relationship_type"],
                "strength": edge["strength"],
            },
            now=now,
        )
    if was_quiet:
        audit.record(
            db,
            correlation_id=finding.correlation_id,
            action="CORRELATION_UPDATED",
            actor=actor,
            details={"decision": "quiet finding reactivated", "group_id": group["id"]},
            now=now,
        )
    return True


def correlate(
    db: Session,
    now: datetime | None = None,
    actor: str = "system",
) -> list[CorrelationFindingRecord]:
    """Correlate behavior groups into findings (spec 5.2-5.10).

    Deterministic, idempotent (5.47) and concurrency-safe (5.35).
    Consumes behavior groups only - never raw events or alerts (spec 5.2).
    """
    _ensure_not_production_db()
    now = now or datetime.now(UTC)

    # Re-read everything fresh: a session reused across runs (tests,
    # scheduler retries) must never leak stale identity-map rows.
    db.expire_all()

    groups = list(
        db.scalars(
            select(BehaviorGroupRecord).order_by(
                BehaviorGroupRecord.first_seen, BehaviorGroupRecord.id
            )
        ).all()
    )
    summaries = {group.behavior_group_id: group_summary(db, group) for group in groups}
    live = list(
        db.scalars(
            select(CorrelationFindingRecord)
            .where(CorrelationFindingRecord.status.in_(_LIVE))
            .order_by(CorrelationFindingRecord.id)
        ).all()
    )
    closed = list(
        db.scalars(
            select(CorrelationFindingRecord)
            .where(CorrelationFindingRecord.status == "CLOSED")
            .order_by(CorrelationFindingRecord.id)
        ).all()
    )

    for group in groups:
        summary = summaries[group.behavior_group_id]
        if any(group.behavior_group_id in (f.member_group_ids or []) for f in live):
            continue

        # 1. Extend: the first live finding whose tail pair matches (5.5).
        handled = False
        for finding in live:
            tail_id = (
                (finding.member_group_ids or [])[-1]
                if finding.member_group_ids
                else None
            )
            tail = summaries.get(tail_id) if tail_id else None
            if tail is None:
                continue
            matches = match_pair(tail, summary)
            if not matches:
                continue
            if _extend_finding(
                db, finding, summaries, tail, summary, matches, now, actor
            ):
                handled = True
                break
        if handled:
            continue

        # 2. Create: the first earlier group whose pair matches (5.5).
        for earlier_group in groups:
            if earlier_group.behavior_group_id == group.behavior_group_id:
                continue
            if earlier_group.first_seen > group.first_seen:
                break
            earlier = summaries[earlier_group.behavior_group_id]
            if any(
                earlier["id"] in (f.member_group_ids or [])
                and group.behavior_group_id in (f.member_group_ids or [])
                for f in live
            ):
                continue
            matches = match_pair(earlier, summary)
            if not matches:
                continue
            created = _create_finding(db, earlier, summary, matches, now, actor)
            if created is not None:
                live.append(created)
                handled = True
                break
        if handled:
            continue

        # 3. Reopen rejection: a closed finding would have matched (5.32).
        for finding in closed:
            tail_id = (
                (finding.member_group_ids or [])[-1]
                if finding.member_group_ids
                else None
            )
            tail = summaries.get(tail_id) if tail_id else None
            if tail is None:
                continue
            if match_pair(tail, summary):
                audit.record(
                    db,
                    correlation_id=finding.correlation_id,
                    action="CORRELATION_REOPEN_REJECTED",
                    actor=actor,
                    details={
                        "group_id": group.behavior_group_id,
                        "decision": "closed findings never absorb new groups",
                    },
                    now=now,
                )
                break

    db.commit()
    return live


def expire_correlations(
    db: Session,
    now: datetime | None = None,
    actor: str = "system",
) -> list[CorrelationFindingRecord]:
    """Inactivity lifecycle (spec 5.31): NEW/ACTIVE -> QUIET -> CLOSED.
    CLOSED is terminal - a closed finding is never silently reopened."""
    _ensure_not_production_db()
    now = now or datetime.now(UTC)
    touched: list[CorrelationFindingRecord] = []

    from backend.correlation.windows import close_cutoff, quiet_cutoff

    for finding in db.scalars(select(CorrelationFindingRecord)).all():
        changed = False
        if finding.status in ("NEW", "ACTIVE") and quiet_cutoff(
            finding.last_seen, now, config.CORRELATION_QUIET_AFTER_MINUTES
        ):
            try:
                apply_transition(finding, "QUIET", now)
            except IllegalTransition:
                pass
            else:
                audit.record(
                    db,
                    correlation_id=finding.correlation_id,
                    action="CORRELATION_QUIET",
                    actor=actor,
                    details={
                        "inactive_minutes": config.CORRELATION_QUIET_AFTER_MINUTES
                    },
                    now=now,
                )
                changed = True
        if finding.status == "QUIET" and close_cutoff(
            finding.last_seen, now, config.CORRELATION_CLOSE_AFTER_MINUTES
        ):
            apply_transition(finding, "CLOSED", now)
            audit.record(
                db,
                correlation_id=finding.correlation_id,
                action="CORRELATION_CLOSED",
                actor=actor,
                details={"inactive_minutes": config.CORRELATION_CLOSE_AFTER_MINUTES},
                now=now,
            )
            changed = True
        if changed:
            touched.append(finding)

    db.commit()
    return touched
