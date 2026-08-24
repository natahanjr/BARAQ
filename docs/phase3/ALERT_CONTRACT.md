# Phase 3 — Alert Contract (EVENT -> DETECTION -> ALERT)

**Status:** implemented, tests green (branch `development/v2`)

## Definitions

| Object | Meaning | Phase |
|---|---|---|
| EVENT | Something happened. | 1 |
| DETECTION | BARAQ determined that something suspicious happened. | 2 |
| ALERT | BARAQ decided the detection should be surfaced to an analyst. | 3 |
| INCIDENT | Multiple pieces of evidence form a meaningful security case. | 7 |

Phase 3 answers: *"Does this detection deserve to become an analyst-facing
alert?"* It does NOT answer *"Is this an incident?"* — that is Phase 7.

Phase 3 creates `DETECTION -> ALERT` only. It never creates:

```text
ALERT -> INCIDENT
ALERT -> RISK
ALERT -> SOAR
```

## Alert object

An alert carries at minimum:

```text
alert_id            public id, ALR-<6-digit sequence>, e.g. ALR-000012
detection_id        originating detection
detection_ids[]     every detection merged into this alert
alert_fingerprint   deterministic dedup key (never a UUID)

title / description
severity            inherited from the detection (low|medium|high|critical)
confidence          inherited from the detection (0.0-1.0, 3 decimals)

status              OPEN|ACKNOWLEDGED|IN_PROGRESS|RESOLVED|CLOSED|SUPPRESSED

first_seen / last_seen / occurrence_count
host_id / host_name / user_id / username
source_ip / destination_ip
mitre_tactic / mitre_technique
evidence[] / observables[]
detector_id / detector_version

created_at / updated_at
assigned_to / assigned_at
acknowledged_at / acknowledged_by
resolved_at
feedback
```

Severity is inherited from the detection and never escalated from
occurrence counts (`HIGH + 30 occurrences` stays `HIGH` — behavioral
escalation belongs to Phase 4/6). Confidence is inherited and never
multiplied by occurrence count.

## Evidence preservation

An alert preserves the full detection evidence chain — never
`"Rule matched"`. Example:

```text
1. Field: logon_type   Value: 10    Reason: Remote Interactive Logon
2. Field: source_ip    Value: 185.x Reason: Source classified as external
3. Field: username     Value: ml-online-user  Reason: Account involved
```

Every merged occurrence additionally keeps its own evidence row in
`alert_occurrences` (spec 3.33) so history is never lost.

## Storage (spec 3.32)

| Table | Purpose |
|---|---|
| `v2_alerts` | the analyst-facing alert. Named `v2_alerts` (not `alerts`) because the v1 `alerts` table is mixed with incident/risk/playbook behavior (spec 3.32: "Do NOT reuse the old v1 alert implementation") |
| `alert_occurrences` | one row per merged detection occurrence |
| `alert_feedback` | structured analyst feedback |
| `alert_audit_events` | every state-changing operation |
| `alert_suppression_rules` | auditable, expiring suppression policies |

## API (spec 3.20)

Served under `/api/alerts-v2/*`. **Documented deviation:** the spec's example
paths use `/api/alerts`, which the v1 alerts API owns (integer ids, alert/
incident/risk mixing). The v2 surface follows the established v2 convention
(`/api/v2/telemetry`, `/api/detections`) to keep the hard boundary:

```text
GET    /api/alerts-v2                        queue + filters (spec 3.21/3.22)
GET    /api/alerts-v2/{alert_id}             detail + audit trail (spec 3.43)
POST   /api/alerts-v2/{alert_id}/acknowledge
POST   /api/alerts-v2/{alert_id}/in-progress
POST   /api/alerts-v2/{alert_id}/assign
POST   /api/alerts-v2/{alert_id}/resolve
POST   /api/alerts-v2/{alert_id}/close
POST   /api/alerts-v2/{alert_id}/reopen      explicit reopen operation
POST   /api/alerts-v2/{alert_id}/suppress
POST   /api/alerts-v2/{alert_id}/feedback
GET    /api/alerts-v2/{alert_id}/occurrences
GET    /api/alerts-v2/{alert_id}/evidence
GET    /api/alerts-v2/feedback-stats
GET    /api/alerts-v2/metrics
GET    /api/alerts-v2/suppressions
POST   /api/alerts-v2/suppressions
```

Every state-changing endpoint validates legal transitions (409 on illegal),
records an audit event, and never touches incidents, risk or SOAR. All
values (`alert_id`, `assigned_to`, `feedback_type`, `status`) are validated
server-side (spec 3.41). The surface is inert when `ALERTS_V2_ENABLED` is
off and refuses the production database by name.

## Isolation

The alert engine's ONLY writes are the five tables above. `incidents`,
`entity_risk`, risk events, playbooks and SOAR are never modified; no ML
is involved in alert creation (deterministic policy only, spec 3.31).
