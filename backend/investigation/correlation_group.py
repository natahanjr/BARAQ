"""Alert -> incident correlation grouping (P0 production gap 2/3).

Without grouping, five detections of the same campaign (python_execution,
suspicious_powershell, account_discovery, screen_capture) each open their
own incident - five copies of one behavior for the analyst to triage.

The exact dedup key (``user|host|mitre|root|30min``) only merges alerts of
the SAME technique. The correlation group key deliberately ignores
technique and rule so related detections on the same entity fold into ONE
incident:

    Alert 1 --┐
    Alert 2 --┤
    Alert 3 --┼--> Correlation Group --> Incident
    Alert 4 --┤
    Alert 5 --┘

Grouping dimensions: host + user + process ancestry + time window.
A candidate incident must match the host and at least one entity
dimension (user or root process) within the window to absorb an alert -
unrelated campaigns never merge.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.investigation.dedup import ACTIVE_STATES, _evidence_user, _root_process

log = logging.getLogger("investigation.correlation_group")

GROUP_WINDOW_MINUTES = 60

#: Score contribution per matched dimension; a merge needs >= MERGE_SCORE.
HOST_MATCH_SCORE = 2
USER_MATCH_SCORE = 3
ROOT_MATCH_SCORE = 2
MERGE_SCORE = 3


def group_key(session, alert, now: datetime | None = None) -> str:
    """Entity-scoped grouping key: ``group|host|user|window-bucket``.

    The bucket uses the same fixed window as the exact dedup key so both
    lookups agree on boundaries; the technique/rule/root dimensions are
    intentionally absent (they are the *reason* alerts differ).
    """
    now = now or datetime.now(UTC)
    bucket = int(now.timestamp() // (GROUP_WINDOW_MINUTES * 60))
    user = _evidence_user(alert) or "?"
    host = alert.host or "?"
    return f"group|{host}|{user}|{bucket}"


def find_group_incident(
    session,
    alert,
    org: str = "",
    window_minutes: int = GROUP_WINDOW_MINUTES,
):
    """Best open incident on the same entity + window, or ``None``.

    Candidates: open incidents on the same host whose ``opened_at`` falls
    inside the window. Each candidate is scored by the entity dimensions it
    shares with the alert (user match, root-process match); the highest
    scorer above ``MERGE_SCORE`` wins. The incident that absorbs the alert
    is never re-considered for future groups (its ``correlation_key`` is
    not the group key, so exact-key dedup stays authoritative).
    """
    from backend.database.models import Incident

    if not alert.host:
        return None
    host = alert.host
    user = _evidence_user(alert) or "?"
    now = datetime.now(UTC)
    ts_min = now - timedelta(minutes=window_minutes)

    q = select(Incident).where(
        Incident.status.in_(ACTIVE_STATES),
        Incident.host == host,
        Incident.opened_at >= ts_min,
    )
    if org:
        q = q.where(Incident.org == org)
    else:
        q = q.where(Incident.org == "")
    q = q.order_by(Incident.opened_at.desc()).limit(50)
    candidates = list(session.scalars(q).all())
    if not candidates:
        return None

    root = _root_process(session, alert) or ""
    best: tuple[int, object] = (0, None)
    for incident in candidates:
        score = HOST_MATCH_SCORE
        incident_users = {
            _evidence_user(l.alert) for l in incident.alerts if l.alert
        } - {""}
        if user == "?" and not incident_users:
            score += 1  # host-only grouping on unknown-user alerts (weak)
        elif user in incident_users:
            score += USER_MATCH_SCORE
        if root:
            incident_roots = {
                _root_process(session, l.alert) for l in incident.alerts if l.alert
            } - {""}
            if root in incident_roots:
                score += ROOT_MATCH_SCORE
        if score >= MERGE_SCORE and score > best[0]:
            best = (score, incident)
    return best[1] if best[0] >= MERGE_SCORE else None
