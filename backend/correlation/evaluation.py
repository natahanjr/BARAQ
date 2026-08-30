"""Phase 5 correlation evaluation (spec 5.62).

Runs the labeled corpus through the real correlation engine and reports
raw counts - true/false positives, true/false negatives and over/under-
correlation. No accuracy percentage is ever fabricated. The corpus
measures the correlation layer itself, so findings are compared to the
labeled expected chains, not to group internals.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.correlation.engine import correlate
from backend.correlation.evaluation_data import SCENARIOS
from backend.correlation.models import CorrelationFindingRecord, CorrelationMember


def run_evaluation(db: Session) -> dict:
    labeled = 0
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for scenario in SCENARIOS:
        # Build the groups (scenario fabricates its own alerts), then
        # correlate and compare every labeled expected chain.
        from backend.correlation.evaluation_data import build_groups

        build_groups(db, scenario)
        correlate(db)
        finding_members = {
            f.correlation_id: list(f.member_group_ids or [])
            for f in db.scalars(select(CorrelationFindingRecord)).all()
        }
        {
            m.behavior_group_id: m.correlation_id
            for m in db.scalars(select(CorrelationMember)).all()
        }

        {member_id for members in finding_members.values() for member_id in members}
        for label in scenario.get("labels", []):
            labeled += 1
            expected_ids = {
                scenario["group_ids"][group_key] for group_key in label["groups"]
            }
            # A finding matches the label when its member set is exactly
            # the expected chain.
            matched = [
                finding_id
                for finding_id, members in finding_members.items()
                if set(members) == expected_ids
            ]
            if label["correlated"]:
                if matched:
                    tp += 1
                else:
                    fn += 1
            else:
                if matched:
                    fp += 1
                else:
                    tn += 1

    return {
        "labeled_chains": labeled,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "over_correlation": fp,
        "under_correlation": fn,
    }
