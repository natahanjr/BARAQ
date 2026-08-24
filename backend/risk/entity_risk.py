"""Entity Risk-Based Alerting (RBA) engine - risk accumulation.

Where the hybrid risk score (``backend.risk.scoring``) describes a *single
alert*, this engine maintains a **persistent risk score per entity**
(user / host / IP):

* **Accumulate** - every detection adds a weighted delta to each entity it
  involves (``alert.risk_score`` x per-rule risk modifier).
* **Decay** - scores decay exponentially over time so stale risk ages out
  (``score *= 0.5 ** (elapsed / half_life)``). A host with 15 low-severity
  hits is now distinguishable from one with 15 clean events.
* **Escalate** - when an entity's accumulated score crosses a threshold, an
  escalated "entity notable" alert is raised that links the contributing
  findings (the RBA equivalent of a notable event).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.config import (
    ENTITY_RISK_DECAY_DAYS,
    ENTITY_RISK_ENABLED,
    ENTITY_RISK_LEVEL_CRITICAL,
    ENTITY_RISK_LEVEL_HIGH,
    ENTITY_RISK_LEVEL_MEDIUM,
    ENTITY_RISK_NOTABLE_WINDOW_HOURS,
    RULE_RISK_WEIGHTS,
)
from backend.database.models import (
    Alert,
    EntityRisk,
    EntityRiskEvent,
    NormalizedEvent,
)

logger = logging.getLogger("baraq.risk.entity_risk")

#: Entity kinds the engine tracks.
ENTITY_KINDS = ("user", "host", "ip")

#: Evidence patterns used to pull the user dimension when an alert has no
#: linked events (mirrors backend.detection.alerting).
_USER_PATTERNS = (
    re.compile(r"User '([^']+)'"),
    re.compile(r"account '([^']+)'"),
    re.compile(r"user '([^']+)'"),
)


def risk_level(score: float, thresholds: tuple[float, float, float] | None = None) -> str:
    """Map an accumulated entity score to a risk level.

    ``thresholds`` is an optional (medium, high, critical) tuple from the
    runtime tuning store; when omitted the env config defaults are used.
    """
    medium, high, critical = thresholds or (
        ENTITY_RISK_LEVEL_MEDIUM,
        ENTITY_RISK_LEVEL_HIGH,
        ENTITY_RISK_LEVEL_CRITICAL,
    )
    if score >= critical:
        return "CRITICAL"
    if score >= high:
        return "HIGH"
    if score >= medium:
        return "MEDIUM"
    return "LOW"


class EntityRiskManager:
    """Accumulate / decay / escalate entity risk within one DB session."""

    def __init__(self, session: Session, tuning: dict | None = None):
        self.session = session
        #: Runtime tuning (see backend.detection.tuning): DB overrides win
        #: over env defaults, so analysts can retune risk live from the UI.
        if tuning is None:
            from backend.detection.tuning import get_tuning

            tuning = get_tuning(session)
        self.tuning = tuning

    @property
    def enabled(self) -> bool:
        return bool(self.tuning.get("entity_risk_enabled", True))

    @property
    def thresholds(self) -> tuple[float, float, float]:
        t = self.tuning.get("risk_thresholds") or {}
        return (
            float(t.get("medium", ENTITY_RISK_LEVEL_MEDIUM)),
            float(t.get("high", ENTITY_RISK_LEVEL_HIGH)),
            float(t.get("critical", ENTITY_RISK_LEVEL_CRITICAL)),
        )

    def _risk_level(self, score: float) -> str:
        return risk_level(score, self.thresholds)

    # ------------------------------------------------------------------
    # extraction
    # ------------------------------------------------------------------
    @staticmethod
    def _evidence_user(evidence: str) -> str:
        for pattern in _USER_PATTERNS:
            m = pattern.search(evidence or "")
            if m:
                return m.group(1)[:512]
        return ""

    @staticmethod
    def _evidence_ips(evidence: str) -> list[str]:
        """Pull candidate IPv4 addresses from evidence text."""
        if not evidence:
            return []
        return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", evidence)[:4]

    def _alert_entities(self, alert: Alert) -> list[tuple[str, str]]:
        """Entities an alert contributes risk to: (kind, name) pairs."""
        entities: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(kind: str, name: str):
            name = (name or "").strip()
            if not name or name in ("-", "?", "unknown", "0.0.0.0"):
                return
            pair = (kind, name[:512])
            if pair not in seen:
                seen.add(pair)
                entities.append(pair)

        if alert.host:
            add("host", alert.host)
        user = self._evidence_user(alert.evidence)
        if user:
            add("user", user)
        for ip in self._evidence_ips(alert.evidence):
            add("ip", ip)
        return entities

    # ------------------------------------------------------------------
    # accumulation
    # ------------------------------------------------------------------
    def _already_applied(self, kind: str, name: str, org: str, alert_id: int) -> bool:
        """Idempotency guard: one alert contributes to an entity exactly once.

        Keyed on (entity, alert) so re-processing the same detection (alert
        refresh, backfill sweep, scheduler re-run) can never double-count
        risk. A single alert legitimately touches several entities; each of
        them is guarded independently.
        """
        exists = self.session.scalars(
            select(EntityRiskEvent.id).where(
                EntityRiskEvent.entity_kind == kind,
                EntityRiskEvent.entity_name == name,
                EntityRiskEvent.org == org,
                EntityRiskEvent.alert_id == alert_id,
            )
        ).first()
        return exists is not None

    def apply_alert(self, alert: Alert, org: str = "") -> list[EntityRisk]:
        """Fold one alert into the entity risk store.

        Each entity named by the alert receives ``alert.risk_score`` weighted
        by the rule's risk modifier (``RULE_RISK_WEIGHTS``). A contribution is
        applied at most once per (entity, alert): repeated calls for the same
        alert (dedup refreshes, backfills) are no-ops. Returns the touched
        ``EntityRisk`` rows so callers can inspect the new scores.
        """
        if not self.enabled:
            return []
        org = org or getattr(alert, "org", "") or ""
        delta = float(alert.risk_score if alert.risk_score is not None else alert.score or 0.0)
        weights = self.tuning.get("rule_risk_weights") or {}
        weight = float(weights.get(alert.rule, 1.0))
        contribution = round(delta * weight, 2)
        if contribution <= 0:
            return []

        #: Context is fully used for scoring: developer-workflow evidence
        #: (git/compilers/project paths, "strong developer-workflow context")
        #: dampens the contribution by 75% so benign dev activity barely
        #: moves entity scores - and therefore never pushes an entity into
        #: HIGH/CRITICAL and an auto-incident by itself.
        evidence = alert.evidence or ""
        dev_dampen = any(
            marker in evidence
            for marker in (
                "strong developer-workflow context",
                "reputation=developer",
                "dev workflow signals",
            )
        )
        if dev_dampen:
            contribution = round(contribution * 0.25, 2)
            logger.info(
                "RBA: developer-context dampening %.2f -> %.2f for alert #%s (%s)",
                delta * weight, contribution, alert.id, alert.rule,
            )
            if contribution <= 0:
                return []

        touched: list[EntityRisk] = []
        now = datetime.now(timezone.utc)
        for kind, name in self._alert_entities(alert):
            if self._already_applied(kind, name, org, alert.id):
                continue
            entity = self._get_or_create(kind, name, org)
            if getattr(alert, "demo", False):
                entity.demo = True
            # Cap at 100 so entity scores share the same 0-100 scale as the
            # hybrid alert risk (risk values > 100 leaked into alert
            # risk_score fields and broke the level mapping).
            new_score = round(min(100.0, entity.score + contribution), 2)
            entity.score = new_score
            entity.risk_level = self._risk_level(new_score)
            entity.alerts_count = (entity.alerts_count or 0) + 1
            entity.last_updated = now
            contributions = list(entity.contributions or [])
            contributions.append(
                {
                    "rule": alert.rule,
                    "mitre_id": alert.mitre_id,
                    "delta": contribution,
                    "score_after": new_score,
                    "alert_id": alert.id,
                    "created_at": now.isoformat(),
                }
            )
            entity.contributions = contributions[-20:]
            self.session.add(
                EntityRiskEvent(
                    entity_kind=kind,
                    entity_name=name,
                    org=org,
                    demo=getattr(alert, "demo", False),
                    delta=contribution,
                    score_after=new_score,
                    source_rule=alert.rule,
                    mitre_id=alert.mitre_id or "T0000",
                    alert_id=alert.id,
                )
            )
            touched.append(entity)
            logger.info(
                "RBA: %s '%s' += %s -> %s (%s)",
                kind, name, contribution, new_score, entity.risk_level,
            )
        self.session.flush()
        return touched

    def _get_or_create(self, kind: str, name: str, org: str) -> EntityRisk:
        entity = self.session.scalars(
            select(EntityRisk).where(
                EntityRisk.entity_kind == kind,
                EntityRisk.entity_name == name,
                EntityRisk.org == org,
            )
        ).first()
        if entity is not None:
            return entity
        #: Concurrent scheduler cycles (multi-instance) race on the same
        #: (kind, name, org) key. Use an atomic INSERT .. ON CONFLICT DO
        #: NOTHING so the loser reuses the winner's row without exceptions
        #: (a catch-and-reselect would hit session autoflush re-inserting the
        #: pending object and crash the whole detection cycle).
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        inserted = self.session.execute(
            pg_insert(EntityRisk)
            .values(
                entity_kind=kind,
                entity_name=name,
                org=org,
                score=0.0,
                risk_level="LOW",
                alerts_count=0,
                contributions=[],
            )
            .on_conflict_do_nothing(
                index_elements=["entity_kind", "entity_name", "org"]
            )
            .returning(EntityRisk.id)
        ).first()
        if inserted is not None:
            entity = self.session.get(EntityRisk, inserted[0])
        else:
            entity = self.session.scalars(
                select(EntityRisk).where(
                    EntityRisk.entity_kind == kind,
                    EntityRisk.entity_name == name,
                    EntityRisk.org == org,
                )
            ).first()
        if entity is None:
            raise IntegrityError(
                "entity_risk get-or-create returned no row "
                f"({kind}, {name}, {org})",
                params=None,
                orig=Exception("concurrent insert resolved to no row"),
            )
        return entity

    # ------------------------------------------------------------------
    # decay
    # ------------------------------------------------------------------
    def decay(self, now: datetime | None = None) -> int:
        """Apply exponential decay to every entity score.

        ``score = score * 0.5 ** (elapsed_days / half_life_days)``. Entities
        whose score rounds to zero are reset to zero (kept for history).
        Returns the number of entities decayed.
        """
        if not self.enabled:
            return 0
        now = now or datetime.now(timezone.utc)
        half_life_days = max(0.1, float(self.tuning.get("risk_decay_days", ENTITY_RISK_DECAY_DAYS)))
        entities = self.session.scalars(select(EntityRisk)).all()
        decayed = 0
        for entity in entities:
            last = entity.last_updated or entity.created_at or now
            elapsed_days = max(0.0, (now - last).total_seconds() / 86400.0)
            if elapsed_days <= 0 or entity.score <= 0:
                continue
            factor = 0.5 ** (elapsed_days / half_life_days)
            new_score = round(entity.score * factor, 2)
            entity.score = min(100.0, new_score)
            entity.risk_level = self._risk_level(new_score)
            entity.last_updated = now
            decayed += 1
        if decayed:
            self.session.flush()
            logger.info("RBA decay: %d entity score(s) decayed", decayed)
        return decayed

    # ------------------------------------------------------------------
    # escalation ("entity notable" alerts)
    # ------------------------------------------------------------------
    def _notable_mitre(self, entity: EntityRisk) -> tuple[str, str, str]:
        """Derive the escalation's MITRE identity from its contributions.

        The notable represents the *campaign* the entity accumulated, so its
        technique is the most frequently contributed one (ties go to the
        most recent), never a hardcoded value. Returns
        (mitre_id, mitre_name, mitre_tactic).
        """
        from backend.mitre.attack import get_tactic, get_technique_name

        counts: dict[str, int] = {}
        for c in entity.contributions or []:
            mid = c.get("mitre_id") or "T0000"
            counts[mid] = counts.get(mid, 0) + 1
        if not counts:
            return "T0000", "", ""
        top = max(
            counts,
            key=lambda mid: (
                counts[mid],
                sum(
                    1
                    for c in (entity.contributions or [])
                    if (c.get("mitre_id") or "T0000") == mid
                ),
                next(
                    (
                        i
                        for i, c in enumerate(entity.contributions or [])
                        if (c.get("mitre_id") or "T0000") == mid
                    ),
                    0,
                ),
            ),
        )
        return top, get_technique_name(top), get_tactic(top)

    @staticmethod
    def _notable_techniques(entity: EntityRisk) -> list[str]:
        """All distinct MITRE techniques behind the campaign, most frequent
        first - so the evidence shows the full technique set, not just the
        headline one."""
        counts: dict[str, int] = {}
        for c in entity.contributions or []:
            mid = c.get("mitre_id") or "T0000"
            counts[mid] = counts.get(mid, 0) + 1
        return sorted(counts, key=lambda mid: -counts[mid])

    def escalate(
        self,
        org: str = "",
        min_level: str = "HIGH",
        now: datetime | None = None,
    ) -> list[Alert]:
        """Raise escalated alerts for entities above the risk threshold.

        One "Entity Risk Escalation" alert per entity **per risk-level
        change**: a new alert is only opened when the entity's level crossed
        into a higher band (or no notable exists yet). Same-level climbs
        refresh the open notable's evidence instead of spamming the queue, so
        the dashboard shows one campaign alert per entity, not one per
        detection cycle. Returns the newly created alerts.
        """
        if not self.enabled:
            return []
        now = now or datetime.now(timezone.utc)
        notable_window = timedelta(
            hours=float(self.tuning.get("risk_notable_window_hours", ENTITY_RISK_NOTABLE_WINDOW_HOURS))
        )
        entities = self.session.scalars(
            select(EntityRisk).where(EntityRisk.org == org)
        ).all()
        created: list[Alert] = []
        for entity in entities:
            level = self._risk_level(entity.score)
            if level not in ("HIGH", "CRITICAL"):
                continue
            if level == "HIGH" and min_level == "CRITICAL":
                continue
            existing = self.session.scalars(
                select(Alert).where(
                    Alert.rule == "entity_risk",
                    Alert.name == f"Entity Risk Escalation: {entity.entity_name}",
                    Alert.org == org,
                    # kind disambiguation: the same name can exist for a host
                    # and a user (e.g. "Haaraphel" the machine + account).
                    Alert.host == (entity.entity_name if entity.entity_kind == "host" else ""),
                )
            ).all()
            active = [
                a for a in existing
                if a.status in ("open", "acknowledged", "investigating", "contained")
            ]

            # Level-gate: no new alert while the level is unchanged. The open
            # notable is refreshed with the latest evidence so analysts see
            # the accumulated campaign, not a pile of identical alerts.
            if entity.last_escalated_level == level:
                fresh = [
                    a for a in active
                    if (now - a.created_at) < notable_window
                ]
                if fresh:
                    target = max(fresh, key=lambda a: a.created_at)
                    target.evidence = self._notable_evidence(entity)
                    target.risk_score = entity.score
                    target.risk_level = entity.risk_level
                    target.event_count = entity.alerts_count
                    target.updated_at = now
                    entity.last_escalated_score = entity.score
                    entity.last_escalated_at = now
                    continue
                # no open notable (closed/aged out) but level unchanged:
                # reopen one refresh instead of stacking a duplicate
                if existing:
                    target = max(existing, key=lambda a: a.created_at)
                    target.status = "open"
                    target.evidence = self._notable_evidence(entity)
                    target.risk_score = entity.score
                    target.risk_level = entity.risk_level
                    target.event_count = entity.alerts_count
                    target.updated_at = now
                    entity.last_escalated_score = entity.score
                    entity.last_escalated_at = now
                    continue

            if active:
                for stale in active:
                    stale.status = "closed"
            contributions = entity.contributions or []
            rules = sorted({c.get("rule", "") for c in contributions if c.get("rule")})
            mitre_id, mitre_name, mitre_tactic = self._notable_mitre(entity)
            alert = Alert(
                name=f"Entity Risk Escalation: {entity.entity_name}",
                description=(
                    f"Entity '{entity.entity_name}' ({entity.entity_kind}) accumulated "
                    f"a risk score of {entity.score:.1f} ({entity.risk_level}) from "
                    f"{entity.alerts_count} detection(s) across {len(rules)} rule(s). "
                    f"Techniques observed: {', '.join(self._notable_techniques(entity)) or '-'}. "
                    "Multiple independent findings against one entity indicate an "
                    "active campaign rather than isolated noise."
                ),
                severity="critical" if entity.risk_level == "CRITICAL" else "high",
                status="open",
                confidence=0.8,
                score=10 if entity.risk_level == "CRITICAL" else 7,
                risk_score=entity.score,
                risk_level=entity.risk_level,
                correlation_id=self._new_correlation_id(),
                mitre_id=mitre_id,
                mitre_name=mitre_name,
                mitre_tactic=mitre_tactic,
                recommendation=(
                    "Treat every contributing alert as part of one campaign: "
                    "open an incident, pivot on the entity in the entity graph, "
                    "contain the affected host(s) and reset the entity's "
                    "credentials."
                ),
                evidence=self._notable_evidence(entity),
                rule="entity_risk",
                host=entity.entity_name if entity.entity_kind == "host" else "",
                org=org,
                demo=entity.demo,
                event_count=entity.alerts_count,
                detection_method="rba",
            )
            self.session.add(alert)
            self.session.flush()
            try:
                from backend.intel.detection import annotate_alert_intel

                if annotate_alert_intel(self.session, alert):
                    logger.info(
                        "RBA escalation alert #%s annotated with intel verdicts",
                        alert.id,
                    )
            except Exception:  # noqa: BLE001 - intel must never wedge RBA
                logger.exception("RBA intel annotation failed for alert #%s", alert.id)
            entity.last_escalated_level = level
            entity.last_escalated_score = entity.score
            entity.last_escalated_at = now
            created.append(alert)
            logger.info(
                "RBA escalation: %s '%s' -> %s (score %.1f)",
                entity.entity_kind, entity.entity_name, level, entity.score,
            )
        if created:
            self.session.commit()
        return created

    def _new_correlation_id(self) -> str:
        """Deterministic notable identifier: CORR-YYYYMMDD-NNNN.

        The sequence is per-day (count of existing correlation ids today + 1)
        so notables are unique and traceable without global locking.
        """
        from sqlalchemy import func

        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        prefix = f"CORR-{day}-"
        count = self.session.scalar(
            select(func.count(Alert.id)).where(Alert.correlation_id.like(f"{prefix}%"))
        ) or 0
        return f"{prefix}{count + 1:05d}"

    @staticmethod
    def _notable_evidence(entity: EntityRisk) -> str:
        techniques = EntityRiskManager._notable_techniques(entity)
        lines = [
            f"Entity: {entity.entity_name} ({entity.entity_kind})",
            f"Accumulated risk: {entity.score:.2f} ({entity.risk_level})",
            f"Contributing detections: {entity.alerts_count}",
            f"MITRE techniques: {', '.join(techniques) if techniques else 'unknown'}",
            "Contributions:",
        ]
        seen: set[tuple[str, str]] = set()
        for c in (entity.contributions or [])[-10:]:
            key = (str(c.get('alert_id')), c.get('rule', ''))
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"  - [{c.get('created_at', '')}] rule={c.get('rule', '?')} "
                f"mitre={c.get('mitre_id', '?')} delta={c.get('delta', 0)} "
                f"score_after={c.get('score_after', 0)} alert_id={c.get('alert_id')}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # queries (API support)
    # ------------------------------------------------------------------
    def leaderboard(
        self,
        org: str = "",
        kind: str | None = None,
        limit: int = 50,
        min_level: str = "LOW",
    ) -> list[EntityRisk]:
        """Top-risk entities, highest score first."""
        stmt = select(EntityRisk).where(EntityRisk.org == org)
        if kind in ENTITY_KINDS:
            stmt = stmt.where(EntityRisk.entity_kind == kind)
        if min_level and min_level != "LOW":
            threshold = {
                "MEDIUM": self.thresholds[0],
                "HIGH": self.thresholds[1],
                "CRITICAL": self.thresholds[2],
            }.get(min_level.upper(), 0)
            stmt = stmt.where(EntityRisk.score >= threshold)
        stmt = stmt.order_by(EntityRisk.score.desc()).limit(max(1, min(500, limit)))
        return list(self.session.scalars(stmt).all())

    def profile(self, kind: str, name: str, org: str = "") -> EntityRisk | None:
        """A single entity's accumulated risk record."""
        return self.session.scalars(
            select(EntityRisk).where(
                EntityRisk.entity_kind == kind,
                EntityRisk.entity_name == name,
                EntityRisk.org == org,
            )
        ).first()

    def timeline(
        self,
        kind: str,
        name: str,
        org: str = "",
        limit: int = 100,
    ) -> list[EntityRiskEvent]:
        """Chronological risk events for one entity (newest last)."""
        stmt = (
            select(EntityRiskEvent)
            .where(
                EntityRiskEvent.entity_kind == kind,
                EntityRiskEvent.entity_name == name,
                EntityRiskEvent.org == org,
            )
            .order_by(EntityRiskEvent.created_at.desc())
            .limit(max(1, min(500, limit)))
        )
        events = list(self.session.scalars(stmt).all())
        events.reverse()
        return events

    def sweep_entities_from_events(self, hours: int = 1, org: str = "") -> int:
        """Backfill: fold recent alerts into the risk store (idempotent).

        Runs on startup / manual sync so entities seen before the RBA engine
        existed still accrue risk. The per-entity idempotency guard in
        ``apply_alert`` skips alerts already reflected in the store, so a
        re-run can never double-count.
        """
        if not self.enabled:
            return 0
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        alerts = self.session.scalars(
            select(Alert).where(
                Alert.org == org,
                Alert.created_at >= since,
                Alert.rule != "entity_risk",
            )
        ).all()
        folded = 0
        for alert in alerts:
            # apply_alert is idempotent per (entity, alert): re-processing an
            # alert already folded into the store is a no-op, so the number of
            # touched entities == the number of new contributions applied.
            touched = self.apply_alert(alert, org=org)
            folded += len(touched)
        if folded:
            self.session.commit()
        return folded