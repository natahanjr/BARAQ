# Behavior Group Contract

## What a behavior group is

A behavior group is a deterministic aggregation of **already-published v2 alerts**
(table `v2_alerts`, Phase 3). Aggregation never consumes raw events (spec 4.4):
only alert records produced by the Phase 3 alerting pipeline enter the engine.

A group represents one **episode** — repeated suspicious activity that shares the
same primary host, primary user, source and behavior family — observed within a
family-specific aggregation window. Groups are the unit of review; they never
claim causality or intent.

## Group identity (fingerprint)

`backend/aggregation/fingerprint.py`:

```
fingerprint = sha256( json.dumps({
    "primary_host":   primary_host_of(alert),    # host_id or host_name, lowercased
    "primary_user":   primary_user_of(alert),    # user_id or username, lowercased
    "normalized_source": source_of(alert),       # source_ip, lowercased
    "behavior_family": behavior_family(alert),
}, sort_keys=True) ).hexdigest()
```

* Missing host/user → `"none"`; the fingerprint still groups by whatever
  identity is present (spec 4.5 — aggregation degrades gracefully).
* The fingerprint is the grouping key and is **not** the public id. Public ids
  are `BG-<6-digit>` (spec 4.7) and carry no identity information.

## Behavior families (spec 4.6, 4.49)

| Family         | Detectors  | Window  | Title                        |
|----------------|------------|---------|------------------------------|
| authentication | D001, D002 | 15 min  | Remote Authentication Activity |
| execution      | D003, D004 | 30 min  | Suspicious Execution Activity  |
| encryption     | D005       | 10 min  | Potential Data Encryption Activity |
| unknown        | (other)    | 30 min  | Suspicious Activity           |

Mapping is declarative in `DETECTOR_BEHAVIOR_FAMILIES` (config). Unknown
detectors fail closed to `unknown`, which requires the full relationship set to
group (spec 4.18, 4.49). D001+D002 share the `authentication` family so an
RDP + failed-logon + successful-logon episode aggregates into one group
(spec 4.49 example).

## Membership

* An alert belongs to **at most one group ever** (idempotent, spec 4.47):
  `unique(behavior_group_id, alert_id)` on `behavior_group_members`.
* Membership score (spec 4.17) is the sum of shared-identity weights:

  | Factor    | Weight | Source |
  |-----------|--------|--------|
  | host      | 0.40   | primary_host equality (guaranteed by fingerprint) |
  | user      | 0.25   | primary_user equality (guaranteed) |
  | source    | 0.20   | source_ip equality (guaranteed) |
  | time      | 0.15   | alert within the family window of group.last_seen |

  Fingerprint equality guarantees host+user+source+family are shared, so the
  relationship floor of `AGGREGATION_MIN_RELATIONSHIPS = 2` is always met for
  real groups (spec 4.18); the score is always 1.00 for a matched member and
  grouping is intentionally conservative (4.19).
* `membership_reason` (e.g. `same host, same user, same source, same
  family`) is stored per member for explainability (spec 4.30).

## Confidence and severity

* Group confidence = **max member-alert confidence**; a multi-alert group
  earns `+0.15` consistency (0.05 per shared identity factor), capped at
  1.000 (spec 4.27). Never summed, never called risk, never fed into risk
  scoring (spec 4.26, 4.44).
* `highest_severity` = max member severity, `low → medium → high → critical`.
  It never escalates beyond what the alerts themselves state.
* Description: `N related alert(s) involving <user> on <host> from <source>
  were observed within the aggregation window.` No causal claims.

## Title guardrails

Titles come from `FAMILY_TITLES` and are validated by `BANNED_TITLE_PHRASES`
(confirmed / attack / compromised / intrusion / breach / proves / exfiltration
/ "ransomware attack"). A `ValueError` is raised at construction if a phrase
slips through — hard failure over overclaiming (spec 4.31).

## Audit trail

Every group transition is recorded in `behavior_group_audit_events` with
`action`, `actor`, `details` and a timestamp (spec 4.33):
`GROUP_CREATED`, `ALERT_ADDED`, `GROUP_REACTIVATED`, `GROUP_QUIETED`,
`GROUP_CLOSED`, `GROUP_REOPEN_REJECTED`, `GROUP_MANUALLY_CLOSED`.

## Statuses

`ACTIVE → QUIET → CLOSED` (spec 4.15). A closed group is never reopened;
matching alerts create a new group and `GROUP_REOPEN_REJECTED` is audited
(spec 4.16, 4.52).