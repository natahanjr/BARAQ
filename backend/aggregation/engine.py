"""Phase 4 aggregation engine (spec 4.5, 4.6, 4.46-4.48).

The Alert -> Behavior Group pipeline:

    ALERT
      -> behavior family (config detector mapping)
      -> group fingerprint (host + user + source + family)
      -> live group with same fingerprint?
            no  -> claim fingerprint (partial unique index, ON CONFLICT)
                   -> create group
            yes, alert within family window of last_seen
                   -> attach (idempotent membership, aggregates, evidence)
            yes, alert outside window
                   -> close old group, create new group
      -> closed group with same fingerprint? -> GROUP_REOPEN_REJECTED audit

Determinism (4.6): same alert set -> same grouping, always. Idempotency
(4.47): re-running over the same alerts attaches nothing twice. Concurrency
(4.48): at most one LIVE group per fingerprint - enforced by a partial
unique index + INSERT ... ON CONFLICT DO NOTHING, never by if-exists.

Hard boundaries (4.44/4.45): the ONLY tables written are the four
behavior-group tables; incidents/risk/playbooks/SOAR are never touched;
no ML anywhere.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

import backend.config as config
from backend.aggregation import audit
from backend.aggregation.contract import group_title
from backend.aggregation.evidence import aggregate_observables, evidence_rows, merge_observables
from backend.aggregation.fingerprint import group_fingerprint
from backend.aggregation.grouping import (
    behavior_family,
    membership_reason,
    membership_score,
    primary_host_of,
    primary_user_of,
    source_of,
)
from backend.aggregation.lifecycle import apply_transition
from backend.aggregation.models import (
    BehaviorGroupEvidence,
    BehaviorGroupMember,
    BehaviorGroupRecord,
)
from backend.aggregation.windows import within_window
from backend.alerting.models import AlertRecord

_LIVE = ("ACTIVE", "QUIET")
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _ensure_not_production_db() -> None:
    if make_url(config.DATABASE_URL).database == config.PRODUCTION_DB_NAME:
        raise RuntimeError(
            f"aggregation engine refuses the v1 production database "
            f"({config.PRODUCTION_DB_NAME!r}) by name"
        )


def next_group_id(db: Session) -> str:
    """Public group id BG-<6-digit sequence> - never the grouping key."""
    row = db.scalars(
        select(BehaviorGroupRecord).order_by(BehaviorGroupRecord.id.desc()).limit(1)
    ).first()
    return f"BG-{(row.id if row else 0) + 1:06d}"


def _describe(group: BehaviorGroupRecord) -> str:
    host = " ".join(group.host_ids or []) or "an unknown host"
    user = " ".join(group.user_ids or []) or "an unknown user"
    source = " ".join(group.source_ips or []) or "an unknown source"
    return (
        f"{group.alert_count} related alert(s) involving {user} on {host} "
        f"from {source} were observed within the aggregation window."
    )


def _claim_group(
    db: Session, fp: str, alert: AlertRecord, family: str, now: datetime, actor: str
) -> tuple[BehaviorGroupRecord, bool]:
    """Create a group for ``fp``, atomically claiming the fingerprint.

    Returns (group, created) where ``group`` is a live ORM row. When
    another worker already holds a live group for the fingerprint, ON
    CONFLICT DO NOTHING skips the insert and the existing group is
    returned (spec 4.48). A rare behavior_group_id collision between
    concurrent workers (both computed the same next id) is retried once
    against the now-committed state.
    """
    from sqlalchemy.exc import IntegrityError

    for _ in range(2):
        candidate = BehaviorGroupRecord(
            behavior_group_id=next_group_id(db),
            group_fingerprint=fp,
            title=group_title(family),
            description="",
            status="ACTIVE",
            first_seen=alert.first_seen,
            last_seen=alert.first_seen,
            alert_count=0,
            occurrence_count=0,
            alert_ids=[],
            host_ids=[],
            user_ids=[],
            source_ips=[],
            mitre_tactics=[],
            mitre_techniques=[],
            observables={},
            confidence=0.0,
            highest_severity="low",
            created_at=now,
            updated_at=now,
        )
        stmt = (
            pg_insert(BehaviorGroupRecord)
            .values(
                **{
                    col: getattr(candidate, col)
                    for col in (
                        "behavior_group_id", "group_fingerprint", "title", "description",
                        "status", "first_seen", "last_seen", "alert_count",
                        "occurrence_count", "alert_ids", "host_ids", "user_ids",
                        "source_ips", "mitre_tactics", "mitre_techniques",
                        "observables", "confidence", "highest_severity",
                        "created_at", "updated_at",
                    )
                }
            )
            .on_conflict_do_nothing(
                index_elements=["group_fingerprint"],
                index_where=text("status IN ('ACTIVE', 'QUIET')"),
            )
        )
        try:
            db.execute(stmt)
        except IntegrityError:
            # Id collision with a concurrent worker's claim; retry once.
            db.rollback()
            continue
        existing = _live_group_for(db, fp)
        if existing is None:
            raise RuntimeError(f"could not claim group fingerprint {fp[:12]}...")
        # The claim is ours exactly when the live group carries our id;
        # under concurrency the winner's id differs and created=False.
        return existing, existing.behavior_group_id == candidate.behavior_group_id
    raise RuntimeError(f"could not claim group fingerprint {fp[:12]}...")


def _live_group_for(db: Session, fp: str) -> BehaviorGroupRecord | None:
    return db.scalars(
        select(BehaviorGroupRecord).where(
            BehaviorGroupRecord.group_fingerprint == fp,
            BehaviorGroupRecord.status.in_(_LIVE),
        )
    ).first()


def _closed_group_for(db: Session, fp: str) -> BehaviorGroupRecord | None:
    return db.scalars(
        select(BehaviorGroupRecord)
        .where(BehaviorGroupRecord.group_fingerprint == fp)
        .order_by(BehaviorGroupRecord.id.desc())
        .limit(1)
    ).first()


def _attach(
    db: Session,
    group: BehaviorGroupRecord,
    alert: AlertRecord,
    family: str,
    now: datetime,
    actor: str,
) -> str:
    """Attach an alert to a group (idempotent) and update aggregates.

    Returns the audit action recorded (ALERT_ADDED or GROUP_REACTIVATED).
    """
    window = config.AGGREGATION_WINDOWS_MINUTES.get(
        family, config.AGGREGATION_WINDOW_DEFAULT_MINUTES
    )
    reason = membership_reason(alert, family, window)
    score = membership_score(alert, family)

    db.execute(
        pg_insert(BehaviorGroupMember)
        .values(
            behavior_group_id=group.behavior_group_id,
            alert_id=alert.alert_id,
            membership_reason=reason,
            membership_score=score,
            created_at=now,
        )
        .on_conflict_do_nothing(
            constraint="uq_group_member_alert",
        )
    )

    was_quiet = group.status == "QUIET"
    if was_quiet:
        apply_transition(group, "ACTIVE", now)
    group.alert_count += 1
    group.occurrence_count += int(alert.occurrence_count or 1)
    group.last_seen = max(group.last_seen, alert.first_seen)
    ids = list(group.alert_ids or [])
    if alert.alert_id not in ids:
        ids.append(alert.alert_id)
    group.alert_ids = ids
    group.host_ids = _merge_unique(group.host_ids, [alert.host_id or alert.host_name])
    group.user_ids = _merge_unique(group.user_ids, [alert.user_id or alert.username])
    group.source_ips = _merge_unique(group.source_ips, [alert.source_ip])
    group.mitre_tactics = _merge_unique(group.mitre_tactics, [alert.mitre_tactic])
    group.mitre_techniques = _merge_unique(group.mitre_techniques, [alert.mitre_technique])
    group.observables = merge_observables(group.observables, aggregate_observables([alert]))
    group.confidence = _recompute_confidence(group, alert)
    if _SEVERITY_RANK.get(alert.severity, 0) > _SEVERITY_RANK.get(group.highest_severity, 0):
        group.highest_severity = alert.severity
    group.description = _describe(group)
    group.updated_at = now

    for row in evidence_rows(alert):
        db.add(
            BehaviorGroupEvidence(
                behavior_group_id=group.behavior_group_id,
                alert_id=alert.alert_id,
                field=row["field"],
                value=row["value"],
                reason=row["reason"],
                created_at=now,
            )
        )

    action = "GROUP_REACTIVATED" if was_quiet else "ALERT_ADDED"
    audit.record(
        db,
        group_id=group.behavior_group_id,
        action=action,
        actor=actor,
        details={
            "alert_id": alert.alert_id,
            "membership_reason": reason,
            "membership_score": score,
            "alert_count": group.alert_count,
        },
    )
    return action


def _recompute_confidence(group: BehaviorGroupRecord, alert: AlertRecord) -> float:
    """Deterministic grouping confidence (spec 4.27), bounded 0.000-1.000.

    base = strongest member alert confidence; a multi-alert group whose
    members share host + user + source + family (guaranteed by fingerprint
    equality) earns +0.15 consistency (0.05 per shared identity factor).
    Never called risk, never summed alert confidences.
    """
    strongest = max(group.confidence, float(alert.confidence or 0.0))
    if group.alert_count > 1:
        return min(1.0, strongest + 0.15)
    return max(0.0, min(1.0, strongest))


def _merge_unique(current: list | None, values: list[str]) -> list[str]:
    merged = list(dict.fromkeys([v for v in (current or []) if v]))
    for value in values:
        if value and value not in merged:
            merged.append(value)
    return merged


def _already_member(db: Session, alert_id: str) -> bool:
    return (
        db.scalars(
            select(BehaviorGroupMember.id).where(
                BehaviorGroupMember.alert_id == alert_id
            )
        ).first()
        is not None
    )


def process_alerts(
    db: Session,
    alerts: list[AlertRecord],
    now: datetime | None = None,
    actor: str = "system",
) -> list[BehaviorGroupRecord]:
    """Aggregate v2 alerts into behavior groups (spec 4.2-4.10).

    Deterministic, idempotent (4.47) and concurrency-safe (4.48). Returns
    every group touched, in creation order. Consumes Phase 3 alerts only -
    never raw events (spec 4.4).
    """
    _ensure_not_production_db()
    now = now or datetime.now(timezone.utc)
    touched: list[BehaviorGroupRecord] = []
    ordered = sorted(alerts, key=lambda a: (a.first_seen, a.alert_id))

    for alert in ordered:
        if alert.status == "SUPPRESSED":
            continue
        if _already_member(db, alert.alert_id):
            continue

        family = behavior_family(alert)
        fp = group_fingerprint(alert, family)

        live = _live_group_for(db, fp)
        if live is not None and within_window(live.last_seen, alert.first_seen, family):
            _attach(db, live, alert, family, now, actor)
            touched.append(live)
            continue

        if live is not None:
            # Sliding-window expiry (spec 4.14): outside the window, the old
            # episode ends and the new one gets its own group. Flush the
            # status change BEFORE claiming the fingerprint - otherwise the
            # claim's ON CONFLICT sees the old group as still live.
            apply_transition(live, "CLOSED", now)
            audit.record(
                db,
                group_id=live.behavior_group_id,
                action="GROUP_CLOSED",
                actor=actor,
                details={"reason": "aggregation window expired", "alert_id": alert.alert_id},
            )
            db.flush()

        closed = _closed_group_for(db, fp)
        if closed is not None:
            audit.record(
                db,
                group_id=closed.behavior_group_id,
                action="GROUP_REOPEN_REJECTED",
                actor=actor,
                details={"alert_id": alert.alert_id, "decision": "new group created"},
            )

        group, created = _claim_group(db, fp, alert, family, now, actor)
        if created:
            audit.record(
                db,
                group_id=group.behavior_group_id,
                action="GROUP_CREATED",
                actor=actor,
                details={
                    "alert_id": alert.alert_id,
                    "behavior_family": family,
                    "primary_host": primary_host_of(alert),
                    "primary_user": primary_user_of(alert),
                    "source": source_of(alert),
                },
            )
        _attach(db, group, alert, family, now, actor)
        touched.append(group)

    db.commit()
    seen: set[str] = set()
    return [
        g for g in touched
        if not (g.behavior_group_id in seen or seen.add(g.behavior_group_id))
    ]


def expire_groups(
    db: Session,
    now: datetime | None = None,
    actor: str = "system",
) -> list[BehaviorGroupRecord]:
    """Inactivity lifecycle (spec 4.15): ACTIVE -> QUIET -> CLOSED."""
    _ensure_not_production_db()
    now = now or datetime.now(timezone.utc)
    touched: list[BehaviorGroupRecord] = []
    quiet_after = config.AGGREGATION_QUIET_AFTER_MINUTES
    close_after = config.AGGREGATION_CLOSE_AFTER_MINUTES

    from backend.aggregation.windows import close_cutoff, quiet_cutoff

    for group in db.scalars(select(BehaviorGroupRecord)).all():
        if group.status == "ACTIVE" and quiet_cutoff(group.last_seen, now, quiet_after):
            action = apply_transition(group, "QUIET", now)
            audit.record(
                db, group_id=group.behavior_group_id, action=action, actor=actor,
                details={"inactive_minutes": quiet_after},
            )
            touched.append(group)
        elif group.status == "QUIET" and close_cutoff(group.last_seen, now, close_after):
            action = apply_transition(group, "CLOSED", now)
            audit.record(
                db, group_id=group.behavior_group_id, action=action, actor=actor,
                details={"inactive_minutes": close_after},
            )
            touched.append(group)

    db.commit()
    return touched