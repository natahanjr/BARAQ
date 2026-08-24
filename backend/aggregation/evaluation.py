"""Phase 4 grouping evaluation (spec 4.41).

Runs the labeled corpus through the real aggregation engine and reports
raw counts: labeled groups, correct groupings, incorrect groupings,
over-grouping and under-grouping. No accuracy percentage is ever
fabricated - there is no claim of "99% grouping accuracy" without a
proper labeled dataset.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.aggregation.engine import process_alerts
from backend.aggregation.evaluation_data import SCENARIOS
from backend.aggregation.models import BehaviorGroupMember
from backend.alerting.models import AlertRecord


def run_evaluation(db: Session) -> dict:
    """Evaluate the labeled corpus; return raw grouping-quality counts."""
    labeled = 0
    correct = 0
    over = 0
    under = 0

    for scenario in SCENARIOS:
        from backend.aggregation.evaluation_data import _alerts

        alerts = _alerts(db, scenario)
        process_alerts(db, alerts)
        memberships = db.scalars(select(BehaviorGroupMember)).all()
        group_of: dict[str, str] = {}
        for m in memberships:
            group_of[m.alert_id] = m.behavior_group_id
        member_alert_ids = {m.alert_id for m in memberships}

        for expected_set in scenario["expected"]:
            labeled += 1
            in_scope = [i for i in expected_set if i < len(alerts)]
            if not in_scope:
                continue
            groups = {
                group_of.get(alerts[i].alert_id)
                for i in in_scope
                if alerts[i].alert_id in member_alert_ids
            }
            groups = {g for g in groups if g is not None}
            if len(groups) == 1:
                # Over-grouping: the group also contains alerts from other
                # expected sets (unrelated alerts merged together).
                extra = [
                    m.alert_id
                    for m in memberships
                    if m.behavior_group_id == next(iter(groups))
                    and m.alert_id not in {alerts[i].alert_id for i in in_scope}
                ]
                if extra:
                    over += 1
                else:
                    correct += 1
            elif len(groups) > 1:
                # Under-grouping: related alerts were separated.
                under += 1
            else:
                over += 1

    return {
        "labeled_groups": labeled,
        "correct_groupings": correct,
        "incorrect_groupings": over + under,
        "over_grouping": over,
        "under_grouping": under,
    }