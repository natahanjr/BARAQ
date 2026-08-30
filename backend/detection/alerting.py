"""Alerting service - persists detection findings as enriched alerts.

Performs rule-level deduplication: an open alert for the same rule and
same signature is not duplicated; instead its evidence is refreshed.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import (
    ALERT_ESCALATE_AFTER,
    ALERT_THROTTLE_MAX_PER_WINDOW,
    ALERT_THROTTLE_MINUTES,
    SEVERITY_LADDER,
    TEST_MODE,
)
from backend.database.models import Alert, AlertEventLink, NormalizedEvent
from backend.detection.workflow import ACTIVE_STATES
from backend.mitre.attack import get_recommendation, get_tactic, get_technique_name
from backend.ml.anomaly import event_feature_vector, get_detector
from backend.risk.scoring import hybrid_risk, risk_descriptor, risk_level

logger = logging.getLogger("baraq.detection.alerting")

SEVERITY_SCORES = {"critical": 10, "high": 7, "medium": 4, "low": 1}

#: Reopen-guard (hours): a finding whose identical alert was analyst-closed
#: within this window stays closed - the cycle refreshes counters instead of
#: raising a duplicate. Set BARAQ_FP_REOPEN_GUARD_HOURS=0 to disable.
FP_REOPEN_GUARD_HOURS = int(os.environ.get("BARAQ_FP_REOPEN_GUARD_HOURS", "24"))

#: Markers that identify commands run by the detection test harness / ad-hoc
#: rule probes. When a finding's evidence references them, the alert is a
#: byproduct of exercising the rules themselves, not real malicious activity,
#: so it is never persisted. Kept tight and explicit to avoid hiding genuine
#: attacks.
_DEV_HARNESS_MARKERS = (
    "from backend.detection.rules",
    "import _ADS",
    "hidden_artifacts import",
    "cmdline_candidates",
    "run_pipeline(",
    "pytest",
)


def _is_dev_harness(evidence: str) -> bool:
    """True when evidence looks like a byproduct of rule/test development."""
    if TEST_MODE:
        return True
    text = evidence or ""
    return any(marker in text for marker in _DEV_HARNESS_MARKERS)


def _demote_severity(severity: str) -> str:
    """Lower a severity one step (never below 'low')."""
    ladder = ("low", "medium", "high", "critical")
    try:
        idx = ladder.index(str(severity).lower())
    except ValueError:
        return ""
    if idx <= 0:
        return ""
    return ladder[idx - 1]


def _is_dev_workflow_fp(facts, rule: str) -> bool:
    """True when a finding must NOT become an alert at all.

    Strict gate, all conditions required:

    * generic noisy rules only (``sigma_rules`` / the dev-sensitive native
      list) - high-fidelity detections (brute force, malware, exfil) always
      alert regardless of context;
    * the context engine verdict is strongly developmental;
    * every observed process is known-good tooling (trusted / system /
      developer tier) - a single unknown-reputation binary keeps the finding
      in the normal pipeline.
    """
    from backend.context.engine import DEV_SENSITIVE_RULES

    # Branch 1 - learned baseline: this parent->child chain is normal for
    # the host (behavioural baseline, S2).
    if getattr(facts, "chain_known", False):
        return True

    eligible = rule in ("", "sigma_rules") or rule in DEV_SENSITIVE_RULES
    if not eligible:
        return False

    # Branch 2 - pure OS-internal chains: every observed process is a Windows
    # system binary (e.g. services.exe -> svchost.exe tripping "Suspicious
    # Parent Directory"). Machine noise, never an analyst-worthy alert. A
    # hijacked/fake system binary lands in the ``unknown`` tier instead and
    # keeps the full pipeline.
    tiers = {facts.reputation.get(p.lower(), "unknown") for p in facts.processes}
    if tiers and tiers <= {"system"} and not facts.ips:
        return True

    if not facts.strong_dev_context:
        return False
    unknown = [
        p
        for p in facts.processes
        if facts.reputation.get(p.lower(), "unknown") == "unknown"
    ]
    return not unknown


class AlertingService:
    #: Findings dropped by the deep dev-workflow FP gate this process lifetime
    #: (greppable via the "FP-suppressed" log tag; surfaced for observability).
    suppressed_fp_count = 0

    def __init__(self, session: Session):
        self.session = session

    def dedup_key(self, result, mitre_id: str) -> str:
        """Signature used to avoid duplicate alerts for the same finding."""
        try:
            first_event = self.session.get(NormalizedEvent, result.event_ids[0])
            user = first_event.user if first_event else "?"
        except (IndexError, AttributeError):
            user = "?"
        if user == "?":
            user = self._evidence_user(result.evidence)
        return f"{result.rule}:{mitre_id}:{user}"

    def _result_host(self, event_ids: list[int]) -> str:
        for event_id in event_ids[:10]:
            ev = self.session.get(NormalizedEvent, event_id)
            if ev is not None and ev.host:
                return ev.host[:128]
        return ""

    @staticmethod
    def _evidence_user(evidence: str) -> str:
        """Best-effort user dimension from evidence text (rules without links)."""
        import re

        m = re.search(r"user '([^']+)'", evidence or "", re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"account '([^']+)'", evidence or "", re.IGNORECASE)
        return m.group(1) if m else "?"

    def _evidence_events(self, event_ids: list[int]) -> list[NormalizedEvent]:
        events = []
        for event_id in event_ids[:50]:
            ev = self.session.get(NormalizedEvent, event_id)
            if ev is not None:
                events.append(ev)
        return events

    def _compute_risk(
        self, result, severity: str | None = None
    ) -> tuple[float, str, str]:
        """Hybrid risk: 0.6 * rule score + 0.4 * ML anomaly score of evidence.

        ML scores are taken from the stored ``ml_score`` when present (set by
        ``analyze_events``); otherwise they are computed live with the trained
        detector so alerts are genuinely hybrid as soon as a model exists.

        ``severity`` overrides the rule severity so severity changes
        (escalation, analyst override) keep ``risk_score`` in lockstep with
        the displayed severity - detector severity can never diverge from
        the risk the alert actually carries.
        """
        events = self._evidence_events(result.event_ids)
        anomaly_scores: list = []
        ml_present = False
        detector = get_detector()
        needs_live: list[tuple[NormalizedEvent, list[float]]] = []
        for ev in events:
            if ev.ml_score is not None:
                anomaly_scores.append(ev)
                ml_present = True
                continue
            if detector.is_ready:
                features = event_feature_vector(ev)
                if features is not None:
                    needs_live.append((ev, features))
        if needs_live and detector.is_ready:
            for ev, _ in needs_live:
                for score in detector.score_events([f for _, f in needs_live]):
                    if score > 0:
                        # Persist the live score back on the event so every
                        # later computation (risk payload, drift stats) sees
                        # the same ML signal the hybrid score used.
                        ev.ml_score = round(float(score), 4)
                        anomaly_scores.append(ev)
                        ml_present = True
        final, level = hybrid_risk(
            severity=severity or result.severity,
            confidence=result.confidence,
            event_count=len(result.event_ids),
            anomaly_scores=anomaly_scores,
        )
        method = "hybrid" if ml_present else "rule"
        return final, level, method

    def _risk_payload(
        self,
        method: str,
        final_risk: float,
        modifier: float,
        adjustments: list,
        result,
        severity: str | None = None,
    ) -> dict:
        """P1 explainable risk: structured 'how was this score built' payload.

        Composition (rule vs ML share), the context modifier and every
        dynamic adjustment with its delta and reason - the analyst sees the
        math instead of a bare number. Also rendered as the evidence text,
        but persisted structured here for the UI.

        ``severity`` pins the composition to the severity that actually
        produced ``final_risk`` (escalation path); default = result severity.
        """
        from backend.risk.scoring import hybrid_parts

        _, rule_part, ml_part, _ = hybrid_parts(
            severity=severity or result.severity,
            confidence=result.confidence,
            event_count=len(result.event_ids),
            anomaly_scores=self._evidence_events(result.event_ids),
        )
        base = round(rule_part + ml_part, 2)
        return {
            "method": method,
            "final": round(float(final_risk), 2),
            "base": base,
            "rule_share": rule_part,
            "ml_share": ml_part,
            "context_modifier": round(float(modifier), 2),
            "adjustments": adjustments,
        }

    def _throttle(self, rule: str, org: str = "") -> Alert | None:
        """Return an open alert to refresh when a rule exceeds its alert quota.

        Once a rule has opened ALERT_THROTTLE_MAX_PER_WINDOW alerts within the
        last ALERT_THROTTLE_MINUTES minutes, further findings stop creating
        new alerts; they refresh the most recent open alert of that rule
        instead (alert-fatigue management).
        """
        since = datetime.now(UTC) - timedelta(minutes=ALERT_THROTTLE_MINUTES)
        recent = self.session.scalars(
            select(Alert).where(
                Alert.rule == rule,
                Alert.org == org,
                Alert.created_at >= since,
            )
        ).all()
        if len(recent) < ALERT_THROTTLE_MAX_PER_WINDOW:
            return None
        return max(recent, key=lambda a: a.created_at)

    def handle_findings(
        self, findings: list, org: str = "", demo: bool = False
    ) -> list[Alert]:
        """Persist rule findings as alerts, scoped to ``org``.

        ``org`` is the tenant this batch belongs to; every alert opened or
        refreshed here stays inside that organization, so alerts from
        different tenants never merge even when the signature matches.

        ``demo`` tags the batch as demo/test telemetry: the alerts are
        persisted but excluded from every production view unless the console
        runs in demo mode (``include_demo=1``).
        """
        created: list[Alert] = []
        linked: set[tuple[int, int]] = set()  # (alert_id, event_id) already queued
        notified: set[int] = set()  # alert ids that already fired out-of-band

        def link_events(alert_id: int, event_ids: list[int]):
            for event_id in event_ids[:50]:
                pair = (alert_id, event_id)
                if pair in linked:
                    continue
                exists = self.session.scalars(
                    select(AlertEventLink).where(
                        AlertEventLink.alert_id == alert_id,
                        AlertEventLink.event_id == event_id,
                    )
                ).first()
                if not exists:
                    self.session.add(
                        AlertEventLink(alert_id=alert_id, event_id=event_id)
                    )
                linked.add(pair)

        for result in findings:
            mitre_id = getattr(result, "mitre_id", "T0000")
            key = self.dedup_key(result, mitre_id)

            if _is_dev_harness(result.evidence):
                logger.info(
                    "Test-harness finding suppressed (%s, %s): %s",
                    result.rule,
                    mitre_id,
                    (result.evidence or "")[:200],
                )
                continue

            # Roadmap P2 - scoped suppression: an analyst declared this
            # detection to be expected behaviour on this scope; drop the
            # finding (counted on the suppression rule for visibility).
            try:
                from backend.detection.suppression import find_matching

                suppression = find_matching(
                    self.session,
                    result.rule,
                    host=self._result_host(result.event_ids),
                    user=key.split(":", 2)[2] if ":" in key else "",
                    org=org,
                )
                if suppression is not None:
                    suppression.suppressed_count = (
                        suppression.suppressed_count or 0
                    ) + 1
                    logger.info(
                        "Suppressed %s finding (suppression #%s, scope %s/%s/%s)",
                        result.rule,
                        suppression.id,
                        suppression.rule,
                        suppression.host,
                        suppression.user,
                    )
                    continue
            except Exception:
                logger.exception("Suppression check failed for %s", result.rule)

            # Roadmap P0/P1 - context calibration: process reputation, dev
            # workflow, localhost and project-path context. Demotes the
            # severity of dev-sensitive rules under strong dev context and
            # dampens the hybrid risk, and annotates the evidence so the
            # analyst sees *why* a detection was calibrated.
            from backend.context import assess_events, assess_text

            context_events = self._evidence_events(result.event_ids)
            facts = assess_events(context_events, rule=result.rule)
            if not facts.processes and (result.evidence or "").strip():
                facts = assess_text(result.evidence, rule=result.rule)

            # Per-host behavioural baseline: a parent->child chain learned as
            # normal for THIS host silences generic rule hits on it; a novel
            # chain is annotated instead - "never seen here" is signal.
            # Network-source findings have no parent process, so the chain
            # lookup (and the "? ->" annotation) simply does not apply.
            try:
                from backend.context.baseline import lookup_chain

                _host = self._result_host(result.event_ids)
                _parent = facts.parent_names[0] if facts.parent_names else ""
                _child = next(iter(facts.processes), "")
                if _parent and _child:
                    facts.chain_known = bool(
                        lookup_chain(self.session, _host, _parent, _child)
                    )
                    if not facts.chain_known:
                        result.evidence = (
                            result.evidence or ""
                        ).rstrip() + f"\nNovel behaviour: {_parent} -> {_child} " "has no baseline history on this host."
            except Exception:
                logger.debug("baseline lookup failed", exc_info=True)

            # Deep FP defence: a strongly-developmental context over
            # known-good binaries (trusted/system/developer reputation only)
            # on generic noisy rules is NOT stored as an alert at all. This
            # is stricter than the demotion below and runs first; the
            # demotion path remains as the second layer for borderline
            # cases where an unknown-reputation process is involved.
            if _is_dev_workflow_fp(facts, result.rule):
                type(self).suppressed_fp_count += 1
                logger.info(
                    "FP-suppressed (dev workflow): rule=%s subject=%s "
                    "parents=%s signals=%s evidence=%s",
                    result.rule,
                    facts.processes,
                    facts.parent_names,
                    facts.dev_signals,
                    (result.evidence or "")[:160],
                )
                continue

            if facts.severity_adjust(result.confidence):
                demoted = _demote_severity(result.severity)
                if demoted:
                    logger.info(
                        "Context demotion: %s %s -> %s (dev workflow evidence)",
                        result.rule,
                        result.severity,
                        demoted,
                    )
                    result.severity = demoted
            context_notes = facts.notes()
            evidence_display = result.evidence
            if context_notes:
                evidence_display = (
                    (result.evidence or "").rstrip()
                    + "\nContext:\n"
                    + "\n".join(context_notes)
                )

            existing = self.session.scalars(
                select(Alert).where(
                    Alert.status.in_(ACTIVE_STATES),
                    Alert.name == result.name,
                    Alert.org == org,
                )
            ).all()

            alert = None
            for cand in existing:
                if self._signature_matches(cand, result, key):
                    alert = cand
                    break

            # Reopen-guard: if the analyst already CLOSED this exact finding
            # within the guard window, respect that decision - refresh the
            # closed record's counters instead of raising a new alert. This
            # is what stops triaged noise from resurrecting every cycle.
            try:
                guard_cutoff = datetime.now(UTC) - timedelta(
                    hours=FP_REOPEN_GUARD_HOURS
                )
                recently_closed = self.session.scalars(
                    select(Alert).where(
                        Alert.status == "closed",
                        Alert.name == result.name,
                        Alert.org == org,
                        Alert.updated_at >= guard_cutoff,
                    )
                ).all()
                guard_match = next(
                    (
                        cand
                        for cand in recently_closed
                        if self._signature_matches(cand, result, key)
                    ),
                    None,
                )
                if guard_match is not None:
                    guard_match.trigger_count = (guard_match.trigger_count or 1) + 1
                    guard_match.event_count = max(
                        guard_match.event_count or 0, len(result.event_ids)
                    )
                    type(self).suppressed_fp_count += 1
                    logger.info(
                        "Reopen-guard: %s re-triggered but alert #%s stays "
                        "closed (analyst decision, guard %sh)",
                        result.rule,
                        guard_match.id,
                        FP_REOPEN_GUARD_HOURS,
                    )
                    continue
            except Exception:
                logger.debug("reopen-guard check failed", exc_info=True)

            risk_score, risk_level_value, method = self._compute_risk(result)

            # Context risk modifier: developer/system/localhost evidence
            # dampens the hybrid score (unknown reputation keeps it at 1.0).
            modifier = facts.risk_modifier()
            if modifier < 1.0:
                risk_score = round(min(100.0, risk_score * modifier), 2)
                risk_level_value = risk_level(risk_score)
                logger.info(
                    "Context risk modifier %.2f applied to %s finding (risk %s)",
                    modifier,
                    result.rule,
                    risk_score,
                )

            # P1 explainable risk: capture the pre-dynamic composition NOW -
            # the dynamic block below mutates ``result.severity``, which
            # would otherwise skew the reported rule/ML shares.
            risk_payload = self._risk_payload(method, risk_score, modifier, [], result)

            # Roadmap P2 (feature 6) - dynamic risk scoring: additive deltas
            # from live context (developer toolchain, signed tooling, known
            # user, suspicious network, persistence, credential access) on the
            # roadmap risk scale. The final severity follows the adjusted risk
            # so the displayed severity and risk level never diverge.
            from backend.risk.dynamic import adjust_risk

            dynamic = adjust_risk(
                risk_score, facts, context_events, session=self.session
            )
            if dynamic["adjustments"]:
                risk_score = dynamic["risk"]
                risk_level_value = dynamic["level"]
                risk_payload["final"] = risk_score
                risk_payload["adjustments"] = dynamic["adjustments"]
                evidence_display = (
                    (evidence_display or "").rstrip()
                    + "\nRisk adjustments: "
                    + ", ".join(
                        f"{a['signal']} {a['delta']:+d}" for a in dynamic["adjustments"]
                    )
                )
                if dynamic["severity"] != result.severity:
                    logger.info(
                        "Dynamic risk %s: severity %s -> %s (risk %s)",
                        result.rule,
                        result.severity,
                        dynamic["severity"],
                        risk_score,
                    )
                    result.severity = dynamic["severity"]

            if alert:
                alert.evidence = evidence_display
                alert.event_count = max(alert.event_count or 0, len(result.event_ids))
                alert.trigger_count = (alert.trigger_count or 1) + 1
                escalated = self._escalate(alert, result)
                # Context re-evaluation can also DEMOTE: when fresh evidence
                # carries a strong developer-workflow verdict, the stored
                # severity must follow down instead of staying frozen high
                # forever (severity could previously only ever escalate).
                downgraded = ""
                try:
                    res_idx = SEVERITY_LADDER.index(str(result.severity))
                    cur_idx = SEVERITY_LADDER.index(str(alert.severity))
                    if not escalated and res_idx < cur_idx:
                        downgraded = str(result.severity)
                        alert.severity = downgraded
                        alert.score = SEVERITY_SCORES.get(downgraded, alert.score)
                        logger.info(
                            "Context downgrade: alert #%s %s -> %s",
                            alert.id,
                            SEVERITY_LADDER[cur_idx],
                            downgraded,
                        )
                except ValueError:
                    pass
                # Severity changed either way: recompute risk from the new
                # severity so the displayed severity and risk level never
                # diverge (roadmap P0 - severity consistency).
                if escalated or downgraded:
                    risk_score, risk_level_value, method = self._compute_risk(
                        result, severity=alert.severity
                    )
                    dynamic = adjust_risk(
                        risk_score, facts, context_events, session=self.session
                    )
                    risk_score = dynamic["risk"]
                    risk_level_value = dynamic["level"]
                    risk_payload = self._risk_payload(
                        method,
                        risk_score,
                        modifier,
                        dynamic["adjustments"],
                        result,
                        severity=alert.severity,
                    )
                alert.risk_score = risk_score
                alert.risk_level = risk_level_value
                alert.detection_method = method
                alert.risk_json = json.dumps(risk_payload, default=str)
                alert.updated_at = datetime.now(UTC)
                logger.info(
                    "Updated existing alert #%s (trigger #%s%s)",
                    alert.id,
                    alert.trigger_count,
                    " -> severity %s" % escalated if escalated else "",
                )
            elif throttle_target := self._throttle(result.rule, org):
                # Rule is above its per-window quota: refresh the newest open
                # alert instead of opening another one (anti-fatigue).
                alert = throttle_target
                alert.evidence = evidence_display
                alert.event_count = max(alert.event_count or 0, len(result.event_ids))
                alert.trigger_count = (alert.trigger_count or 1) + 1
                # Keep risk bookkeeping consistent: the payload/score must
                # never describe a different finding than the evidence does.
                alert.risk_score = risk_score
                alert.risk_level = risk_level_value
                alert.detection_method = method
                alert.risk_json = json.dumps(risk_payload, default=str)
                alert.updated_at = datetime.now(UTC)
                logger.info(
                    "Throttled duplicate for rule %s -> refreshed alert #%s",
                    result.rule,
                    alert.id,
                )
            else:
                alert = Alert(
                    name=result.name,
                    description=result.description,
                    severity=result.severity,
                    status="open",
                    confidence=result.confidence,
                    score=SEVERITY_SCORES.get(result.severity, 4),
                    detection_method=method,
                    risk_score=risk_score,
                    risk_level=risk_level_value,
                    risk_json=json.dumps(risk_payload, default=str),
                    mitre_id=mitre_id,
                    mitre_name=get_technique_name(mitre_id),
                    mitre_tactic=get_tactic(mitre_id),
                    recommendation=result.recommendation
                    or get_recommendation(mitre_id),
                    evidence=evidence_display,
                    rule=result.rule,
                    host=self._result_host(result.event_ids),
                    event_count=len(result.event_ids),
                    org=org,
                    demo=demo,
                    correlation_id=getattr(result, "correlation_id", "") or "",
                )
                self.session.add(alert)
                self.session.flush()
                created.append(alert)
                from backend.realtime import publish_alert

                try:
                    publish_alert(alert.to_dict())
                except Exception:
                    pass
                logger.info(
                    "Created alert #%s: %s (%s) risk=%s [%s] %s",
                    alert.id,
                    alert.name,
                    mitre_id,
                    risk_score,
                    risk_level_value,
                    risk_descriptor(risk_level_value),
                )

                # Entity Risk-Based Alerting: fold the alert's risk into the
                # entities it involves. Only NEW alerts contribute - a
                # refreshed/updated alert must never re-add risk for the same
                # detection (idempotency: one alert -> one contribution).
                # ``apply_alert`` is also guarded per (entity, alert_id), so
                # backfills and scheduler re-runs can never double-count.
                try:
                    from backend.risk.entity_risk import EntityRiskManager

                    EntityRiskManager(self.session).apply_alert(alert, org=org)
                except Exception:
                    logger.exception(
                        "Entity RBA accumulation failed for alert #%s", alert.id
                    )

                # Roadmap P2 - incident creation from correlated alerts:
                # correlation chains and entity-risk escalations become an
                # incident automatically (the analyst then owns it from the
                # incident center instead of one-off alert triage).
                try:
                    self._maybe_create_incident(alert, org=org)
                except Exception:
                    logger.exception(
                        "Auto-incident creation failed for alert #%s", alert.id
                    )

            if alert in created and alert.id not in notified:
                notified.add(alert.id)
                try:
                    from backend.notify import notify_alert

                    notify_alert(alert.to_dict())
                except Exception:
                    pass

            link_events(alert.id, result.event_ids)

            # P1 detection-time threat-intel annotation: reputation verdicts
            # for the alert's indicators (offline fast path - never a network
            # call in the pipeline). Runs for new AND refreshed alerts so the
            # queue always reflects the latest evidence.
            try:
                from backend.intel.detection import annotate_alert_intel

                if annotate_alert_intel(self.session, alert):
                    logger.info(
                        "Alert #%s annotated with detection-time intel verdicts",
                        alert.id,
                    )
            except Exception:
                logger.exception(
                    "Detection-time intel annotation failed for alert #%s",
                    getattr(alert, "id", "?"),
                )

            # SOAR automation: fire matching playbooks against new alerts
            # (declared triggers -> ordered actions, see backend.automation).
            try:
                from backend.automation.playbooks import fire_playbooks

                fire_playbooks(self.session, alert)
            except Exception:
                logger.exception("Automation playbooks failed for alert #%s", alert.id)
        self.session.commit()
        return created

    def _escalate(self, alert: Alert, result) -> str:
        """Escalate severity after repeated re-triggers of the same alert.

        Repeat detections indicate the adversary kept trying (or the
        containment failed); escalation surfaces that in the severity
        distribution and the security-score penalty.

        Risk bookkeeping is recomputed by the caller once the new severity
        is known, so severity and risk level stay consistent.
        """
        if (alert.trigger_count or 1) < ALERT_ESCALATE_AFTER:
            return ""
        try:
            current = SEVERITY_LADDER.index(alert.severity)
        except ValueError:
            return ""
        if current >= len(SEVERITY_LADDER) - 1:
            return ""
        new_severity = SEVERITY_LADDER[current + 1]
        alert.severity = new_severity
        alert.score = SEVERITY_SCORES.get(new_severity, alert.score)
        alert.confidence = max(alert.confidence or 0.0, result.confidence)
        return new_severity

    @staticmethod
    def _signature_matches(alert: Alert, result, key: str) -> bool:
        """Loose signature check: same rule + same user dimension.

        Rules without linked evidence (empty ``event_ids``) previously produced
        a new alert every cycle because the full evidence string changed. We
        match on rule + user so such findings refresh a single open alert.
        Findings whose user dimension is unknown (``-``/``?``/missing) also
        share one anchor per rule - an unknown user can never distinguish two
        findings from each other.
        """
        try:
            user_part = key.split(":", 2)[2] if ":" in key else ""
        except IndexError:
            user_part = ""
        if alert.rule != result.rule:
            return False
        if user_part and user_part not in _UNKNOWN_USERS:
            return _alert_user(alert.evidence) == user_part
        return True  # rule-only anchor (no user signal): refresh a single open alert

    def _maybe_create_incident(self, alert: Alert, org: str = "") -> None:
        """Roadmap P2 - incident creation from correlated alerts.

        Correlation-chain findings and *critical* entity-risk escalations
        represent a campaign, not a single event, so they automatically
        become an incident (linking the contributing alerts named in the
        evidence). One incident per chain name keeps the incident queue
        tidy; the analyst takes over from the incident center.

        SOC-usability gate: HIGH entity-risk escalations stay alerts (watch
        level), and developer-workflow-context alerts never become incidents
        - benign dev activity must not inflate the incident queue. Ordinary
        detections join/create incidents only when their dynamic risk is
        MEDIUM or above (P0: the incident queue carries signal, not noise).
        """
        if getattr(alert, "demo", False):
            return
        if alert.rule == "entity_risk":
            if (alert.risk_level or "").upper() != "CRITICAL":
                return
        elif alert.rule != "correlation_engine":
            # P0 correlation grouping: any detection whose dynamic risk is
            # MEDIUM+ is incident-worthy; the correlation group engine
            # folds related detections into one case instead of five.
            if (alert.risk_level or "").upper() not in ("MEDIUM", "HIGH", "CRITICAL"):
                return

        evidence = alert.evidence or ""
        for marker in (
            "strong developer-workflow context",
            "reputation=developer",
            "dev workflow signals",
        ):
            if marker in evidence:
                logger.info(
                    "Auto-incident skipped: %s alert #%s is developer-workflow context",
                    alert.rule,
                    alert.id,
                )
                return

        from backend.database.models import Incident, IncidentAlertLink
        from backend.investigation.dedup import (
            correlation_key,
            find_open_incident,
            merge_alert,
        )

        # Phase-1 dedup: an open incident with the same correlation key
        # (user | host | mitre | root process | 30-min window) absorbs this
        # alert instead of spawning a duplicate incident.
        key = correlation_key(self.session, alert)
        existing = find_open_incident(self.session, key, org)
        if existing:
            if merge_alert(self.session, existing, alert):
                logger.info(
                    "Auto-incident #%s absorbed alert #%s (dedup key %s)",
                    existing.id,
                    alert.id,
                    key,
                )
                _refresh_chain(self.session, existing)
            else:
                logger.info(
                    "Auto-incident #%s already contains alert #%s",
                    existing.id,
                    alert.id,
                )
            self.session.flush()
            return

        # P0 correlation group: a related-but-different detection (same
        # host/user/process ancestry, same window, different technique)
        # joins the open incident instead of spawning a duplicate case -
        # "5 python alerts -> 1 incident", not 5 incidents.
        from backend.investigation.correlation_group import (
            GROUP_WINDOW_MINUTES,
            find_group_incident,
        )

        grouped = find_group_incident(self.session, alert, org)
        if grouped:
            if merge_alert(self.session, grouped, alert):
                logger.info(
                    "Correlation group: alert #%s folded into incident #%s "
                    "(host %s, window %dm)",
                    alert.id,
                    grouped.id,
                    alert.host,
                    GROUP_WINDOW_MINUTES,
                )
                _refresh_chain(self.session, grouped)
            self.session.flush()
            return

        import re

        link_ids = set()
        for match in re.finditer(r"alert_id=(\d+)", alert.evidence or ""):
            link_ids.add(int(match.group(1)))
        link_ids.discard(alert.id)
        if alert.rule == "correlation_engine" and alert.correlation_id:
            related = self.session.scalars(
                select(Alert)
                .where(
                    Alert.correlation_id == alert.correlation_id,
                    Alert.id != alert.id,
                )
                .limit(50)
            ).all()
            link_ids.update(a.id for a in related)

        incident = Incident(
            title=f"Incident: {alert.name}",
            description=(alert.description or "")[:2000],
            severity=alert.severity,
            status="open",
            owner="",
            mitre_id=alert.mitre_id,
            mitre_name=alert.mitre_name,
            host=alert.host or "",
            org=org,
            demo=False,
            risk_score=min(100.0, alert.risk_score or 0.0),
            risk_level=alert.risk_level,
            confidence=alert.confidence,
            correlation_key=key,
            opened_at=datetime.now(UTC),
        )
        self.session.add(incident)
        self.session.flush()
        self.session.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert.id))
        for alert_id in sorted(link_ids):
            self.session.add(
                IncidentAlertLink(incident_id=incident.id, alert_id=alert_id)
            )
        self.session.flush()
        self.session.expire(incident)

        # Phase-1 confidence scoring: detection quality + correlation
        # strength + enrichment quality - suppression signals.
        from backend.investigation.confidence import incident_confidence

        incident.confidence = incident_confidence(self.session, incident)["score"]

        # P1-1 attack-chain correlation: reconstruct the multi-stage path
        # from the incident's alerts, persist it and stack the chain risk
        # boost on the incident risk. The chain re-runs on every merge.
        from backend.investigation.attack_chain import apply_chain

        try:
            chain = apply_chain(self.session, incident)
            if chain["sequence"]:
                logger.info(
                    "Attack chain on incident #%s: %s (confidence %.2f, risk +%d)",
                    incident.id,
                    " -> ".join(chain["sequence"]),
                    chain["confidence"],
                    chain["risk_boost"],
                )
        except Exception:
            logger.exception(
                "Attack-chain reconstruction failed for incident #%s", incident.id
            )
        logger.info(
            "Auto-incident #%s created for %s alert #%s (+%d contributing alerts)",
            incident.id,
            alert.rule,
            alert.id,
            len(link_ids),
        )


def _alert_user(evidence: str) -> str:
    import re

    m = re.search(r"user '([^']+)'", evidence or "", re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"account '([^']+)'", evidence or "", re.IGNORECASE)
    return m.group(1) if m else "?"


#: User values that carry no identity signal (placeholder / missing user in
#: the source event). Findings from such users merge into one open alert
#: per rule instead of opening a fresh alert on every occurrence.
_UNKNOWN_USERS = frozenset({"", "?", "-"})


def _refresh_chain(session: Session, incident) -> None:
    """Re-run P1-1 attack-chain reconstruction after an alert joins a case."""
    from backend.investigation.attack_chain import apply_chain

    try:
        apply_chain(session, incident)
    except Exception:
        logger.exception("Attack-chain refresh failed for incident #%s", incident.id)


def _maybe_create_incident_helper(
    service: AlertingService, alert: Alert, org: str = ""
) -> None:
    """Standalone entry point for auto-incident creation (tests/backfills)."""
    return service._maybe_create_incident(alert, org)


def deduplicate_stale(session: Session, hours: int = 24) -> int:
    """Close alerts older than N hours (simple triage lifecycle)."""
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    stale = session.scalars(
        select(Alert).where(Alert.status == "open", Alert.created_at < cutoff)
    ).all()
    for alert in stale:
        alert.status = "closed"
    session.commit()
    return len(stale)
