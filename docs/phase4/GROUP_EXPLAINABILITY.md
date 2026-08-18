# Explainability (spec 4.30-4.32, 4.41)

## What makes a group explainable

Every group answers three questions without speculation:

1. **Why do these alerts belong together?**
   `behavior_group_members.membership_reason` — e.g. `same host, same user,
   same source, same family` — and `membership_score` (0.40 host + 0.25 user
   + 0.20 source + 0.15 time = 1.00) per member alert.
2. **What does the group contain?** Members, evidence, MITRE tactics and
   techniques, host/user/source identity lists, alert_count vs
   occurrence_count (dedup merges included), first/last seen.
3. **How confident is the grouping, and why?**
   `confidence = max(member alert confidence) [+0.15 consistency if
   multi-alert, capped 1.0]` (spec 4.27). The formula is stated in the docs
   and visible in code; it is never presented as risk.

## Evidence (spec 4.30)

`behavior_group_evidence` rows are derived per member alert:
`(group, alert_id, field, value, reason)`. Examples:

* `host` → `workstation-42` → `alert reported host`
* `source_ip` → `203.0.113.5` → `alert reported source`
* `username` → `ml-online-user` → `alert reported user`
* `mitre_technique` → `T1133` → `alert reported MITRE technique`

`observables` on the group row are the merged alert observables (source IPs,
hashes, hosts, users seen across the episode).

## Titles that don't overclaim (spec 4.31)

Titles come from a fixed family table (`Remote Authentication Activity`,
`Suspicious Execution Activity`, `Potential Data Encryption Activity`,
`Suspicious Activity`) and `BANNED_TITLE_PHRASES` rejects
confirmed/attack/compromised/intrusion/breach/proves/exfiltration/
"ransomware attack" at construction — hard `ValueError`, not a silent
fallback. Descriptions state facts only: `N related alert(s) involving
<user> on <host> from <source> were observed within the aggregation
window.`

## Timeline (spec 4.32)

`GET /api/behavior-groups/{id}/timeline` returns audit events + member
alerts merged and sorted chronologically, so an analyst can replay the
episode: created → alerts added → quieted → closed → reopen-rejected
decisions.

## No causality

Groups say *what was observed together*, never *what it means*. No group
field states compromise, breach, intrusion or attack intent; severity is
copied from the alerts' own severity (max), never upgraded speculatively.

## Evaluation without fake metrics (spec 4.41)

`GET /api/behavior-groups/evaluation` returns raw labeled counts only:
`correct / over_grouping / under_grouping / group_count / alert_count` per
scenario (e1-e6, defined in `evaluation_data.py`). There is no synthesized
"accuracy %" or model confidence number — reviewers can compute anything
from the raw counts, and the DoD test asserts the corpus is fully correct
(zero over/under-grouping).