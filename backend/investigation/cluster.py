"""Related-alert clustering for the investigation view.

Links alerts that belong to the same story: shared evidence events,
shared correlation chain, same host / same user and temporal proximity.
Each candidate gets a relevance score so the analyst sees the cluster
around the alert they opened, not a flat wall of findings.
"""

from __future__ import annotations

import logging
import re
from datetime import timedelta

from sqlalchemy import func, select

from backend.database.models import Alert, AlertEventLink, AlertVerdict

log = logging.getLogger("investigation.cluster")

CLUSTER_WINDOW_MINUTES = 120
MAX_CANDIDATES = 40
MAX_RESULTS = 10


def _evidence_scope(alert: Alert) -> str:
    text = alert.evidence or ""
    if alert.events:
        text += " " + " ".join(
            (link.event.message or "")
            + " "
            + ((link.event.user or "") + " " + (link.event.host or ""))
            for link in list(alert.events)[:12]
        )
    return text


def _evidence_user(alert: Alert) -> str:
    scope = _evidence_scope(alert)
    m = re.search(
        r"\b(?:user|user_name|user_id|account)\s*[:=]\s*([A-Za-z0-9_.\\-]+)", scope
    )
    return m.group(1) if m else ""


def _verdict_for(session, alert_id: int) -> str:
    row = session.execute(
        select(AlertVerdict.verdict).where(AlertVerdict.alert_id == alert_id)
    ).first()
    return row[0] if row else ""


def cluster_related_alerts(
    session, alert: Alert, max_results: int = MAX_RESULTS
) -> list[dict]:
    """Return alerts related to ``alert`` ranked by story relevance."""
    own_events = set(
        session.scalars(
            select(AlertEventLink.event_id).where(AlertEventLink.alert_id == alert.id)
        ).all()
    )
    own_user = _evidence_user(alert)
    own_host = alert.host or ""

    # candidates: same correlation chain OR time window (±) OR host overlap
    window_lo = alert.created_at - timedelta(minutes=CLUSTER_WINDOW_MINUTES)
    window_hi = alert.created_at + timedelta(minutes=CLUSTER_WINDOW_MINUTES)
    q = select(Alert).where(
        Alert.id != alert.id,
        Alert.created_at >= window_lo,
        Alert.created_at <= window_hi,
    )
    if alert.org:
        q = q.where(Alert.org == alert.org)
    q = q.order_by(Alert.created_at.desc()).limit(MAX_CANDIDATES)
    candidates = session.scalars(q).all()

    shared_events: dict[int, int] = {}
    if own_events:
        rows = session.execute(
            select(AlertEventLink.alert_id, func.count())
            .where(
                AlertEventLink.event_id.in_(own_events),
                AlertEventLink.alert_id != alert.id,
            )
            .group_by(AlertEventLink.alert_id)
        ).all()
        shared_events = {aid: int(cnt) for aid, cnt in rows}

    scored: list[dict] = []
    for cand in candidates:
        if cand.demo and not alert.demo:
            continue
        set(
            session.scalars(
                select(AlertEventLink.event_id).where(
                    AlertEventLink.alert_id == cand.id
                )
            ).all()
        )
        shared = shared_events.get(cand.id, 0)
        same_user = bool(own_user) and own_user == _evidence_user(cand)
        same_host = bool(own_host) and own_host == (cand.host or "")
        same_corr = (
            bool(alert.correlation_id) and alert.correlation_id == cand.correlation_id
        )

        score = 0.0
        reasons: list[str] = []
        if shared:
            score += 3.0 * min(shared, 3)
            reasons.append(f"{shared} shared event(s)")
        if same_corr:
            score += 5.0
            reasons.append("same correlation chain")
        if same_host:
            score += 2.0
            reasons.append("same host")
        if same_user:
            score += 1.5
            reasons.append("same user")
        proximity = 1.0 - min(
            1.0,
            abs((cand.created_at - alert.created_at).total_seconds())
            / (CLUSTER_WINDOW_MINUTES * 60),
        )
        score += proximity * 0.8
        if score < 1.0:
            continue
        if not shared and not same_corr and not same_host and not same_user:
            continue

        scored.append(
            {
                "id": cand.id,
                "name": cand.name,
                "rule": cand.rule,
                "severity": cand.severity,
                "status": cand.status,
                "risk_level": cand.risk_level,
                "risk_score": cand.risk_score,
                "confidence": cand.confidence,
                "mitre_id": cand.mitre_id,
                "created_at": cand.created_at.isoformat(),
                "verdict": _verdict_for(session, cand.id),
                "shared_event_count": shared,
                "relevance_score": round(score, 2),
                "reasons": reasons,
            }
        )

    scored.sort(key=lambda d: (-d["relevance_score"], d["created_at"]))
    return scored[:max_results]
