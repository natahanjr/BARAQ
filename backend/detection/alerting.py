"""Alerting service - persists detection findings as enriched alerts.

Performs rule-level deduplication: an open alert for the same rule and
same signature is not duplicated; instead its evidence is refreshed.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import Alert, AlertEventLink, NormalizedEvent
from backend.mitre.attack import get_recommendation, get_tactic, get_technique_name
from backend.ml.anomaly import event_feature_vector, get_detector
from backend.risk.scoring import hybrid_risk, risk_descriptor, risk_level

logger = logging.getLogger("sentinel.detection.alerting")

SEVERITY_SCORES = {"critical": 10, "high": 7, "medium": 4, "low": 1}


class AlertingService:
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

    @staticmethod
    def _evidence_user(evidence: str) -> str:
        """Best-effort user dimension from evidence text (rules without links)."""
        import re

        m = re.search(r"User '([^']+)'", evidence or "")
        if m:
            return m.group(1)
        m = re.search(r"account '([^']+)'", evidence or "")
        if m:
            return m.group(1)
        return "?"

    def _evidence_events(self, event_ids: list[int]) -> list[NormalizedEvent]:
        events = []
        for event_id in event_ids[:50]:
            ev = self.session.get(NormalizedEvent, event_id)
            if ev is not None:
                events.append(ev)
        return events

    def _compute_risk(self, result) -> tuple[float, str, str]:
        """Hybrid risk: 0.6 * rule score + 0.4 * ML anomaly score of evidence.

        ML scores are taken from the stored ``ml_score`` when present (set by
        ``analyze_events``); otherwise they are computed live with the trained
        detector so alerts are genuinely hybrid as soon as a model exists.
        """
        events = self._evidence_events(result.event_ids)
        anomaly_scores: list = []
        ml_present = False
        detector = get_detector()
        for ev in events:
            if ev.ml_score is not None:
                anomaly_scores.append(ev)
                ml_present = True
                continue
            if detector.is_ready:
                features = event_feature_vector(ev)
                if features is not None:
                    score = detector.score_event(features)
                    if score > 0:
                        anomaly_scores.append({"ml_score": score})
                        ml_present = True
        final, level = hybrid_risk(
            severity=result.severity,
            confidence=result.confidence,
            event_count=len(result.event_ids),
            anomaly_scores=anomaly_scores,
        )
        method = "hybrid" if ml_present else "rule"
        return final, level, method

    def handle_findings(self, findings: list) -> list[Alert]:
        created: list[Alert] = []
        linked: set[tuple[int, int]] = set()  # (alert_id, event_id) already queued

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

            existing = self.session.scalars(
                select(Alert).where(
                    Alert.status == "open",
                    Alert.name == result.name,
                )
            ).all()

            alert = None
            for cand in existing:
                if self._signature_matches(cand, result, key):
                    alert = cand
                    break

            risk_score, risk_level_value, method = self._compute_risk(result)

            if alert:
                alert.evidence = result.evidence
                alert.event_count = max(alert.event_count or 0, len(result.event_ids))
                alert.risk_score = risk_score
                alert.risk_level = risk_level_value
                alert.detection_method = method
                alert.updated_at = datetime.now(timezone.utc)
                logger.info("Updated existing alert #%s", alert.id)
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
                    mitre_id=mitre_id,
                    mitre_name=get_technique_name(mitre_id),
                    mitre_tactic=get_tactic(mitre_id),
                    recommendation=result.recommendation or get_recommendation(mitre_id),
                    evidence=result.evidence,
                    rule=result.rule,
                    event_count=len(result.event_ids),
                )
                self.session.add(alert)
                self.session.flush()
                created.append(alert)
                logger.info(
                    "Created alert #%s: %s (%s) risk=%s [%s] %s",
                    alert.id, alert.name, mitre_id, risk_score, risk_level_value,
                    risk_descriptor(risk_level_value),
                )

            link_events(alert.id, result.event_ids)
        self.session.commit()
        return created

    @staticmethod
    def _signature_matches(alert: Alert, result, key: str) -> bool:
        """Loose signature check: same rule + same user dimension.

        Rules without linked evidence (empty ``event_ids``) previously produced
        a new alert every cycle because the full evidence string changed. We
        match on rule + user so such findings refresh a single open alert.
        """
        try:
            user_part = key.split(":", 2)[2] if ":" in key else ""
        except IndexError:
            user_part = ""
        if alert.rule != result.rule:
            return False
        if user_part and user_part != "?":
            return _alert_user(alert.evidence) == user_part
        return True  # rule-only anchor (no user signal): refresh a single open alert


def _alert_user(evidence: str) -> str:
    import re

    m = re.search(r"User '([^']+)'", evidence or "")
    if m:
        return m.group(1)
    m = re.search(r"account '([^']+)'", evidence or "")
    return m.group(1) if m else "?"


def deduplicate_stale(session: Session, hours: int = 24) -> int:
    """Close alerts older than N hours (simple triage lifecycle)."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    stale = session.scalars(
        select(Alert).where(Alert.status == "open", Alert.created_at < cutoff)
    ).all()
    for alert in stale:
        alert.status = "closed"
    session.commit()
    return len(stale)
