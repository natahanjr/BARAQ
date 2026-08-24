"""Phase 5 correlation evidence (spec 5.29, 5.28).

Evidence is preserved from every member group and every rule decision as
field/value/reason rows - the "why correlated" (spec 5.28) is mandatory and
stored, never reduced to "Multiple groups detected".
"""
from __future__ import annotations


def evidence_rows(
    finding_id: str,
    group: dict,
    *,
    rule_id: str,
    reason: str,
    role: str = "member",
) -> list[dict]:
    rows: list[dict] = []
    summary = [
        ("member_group", group.get("id", ""), f"member group {group.get('id', '')}"),
        ("behavior_family", group.get("family", "unknown"), rule_id),
        ("host", ", ".join(group.get("hosts") or []), rule_id),
        ("user", ", ".join(group.get("users") or []), rule_id),
        ("source_ip", ", ".join(group.get("sources") or []), rule_id),
        ("mitre_techniques", ", ".join(group.get("techniques") or []), rule_id),
    ]
    for field, value, field_reason in summary:
        if value:
            rows.append(
                {
                    "field": field,
                    "value": value,
                    "reason": field_reason or rule_id,
                }
            )
    rows.append(
        {
            "field": "rule_reason",
            "value": reason,
            "reason": rule_id,
        }
    )
    return rows
