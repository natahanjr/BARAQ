# Incident Contract

## What an incident is (spec 7.1-7.4)

An **incident** is an analyst-facing investigation container that represents
a potentially meaningful security situation. It is:

- NOT a raw event;
- NOT a detection;
- NOT an alert;
- NOT a behavior group;
- NOT a correlation finding;
- NOT an entity risk score;
- NOT proof of compromise.

An incident reduces analyst workload by grouping validated security
evidence into a single actionable case.

## Storage

Five dedicated tables own incident data:

| Table | Purpose |
|-------|---------|
| `incidents_v2` | one row per incident |
| `incident_alerts` | alert membership |
| `incident_behavior_groups` | behavior group membership |
| `incident_correlations` | correlation finding membership |
| `incident_risk_sources` | risk source membership |
| `incident_evidence` | every evidence item with provenance |
| `incident_audit_events` | append-only attribution trail |
| `incident_notes` | analyst-owned notes |
| `incident_feedback` | analyst feedback (TP/FP/BENIGN/etc.) |
| `incident_graph_edges` | contextual graph edges |
| `incident_suppressions` | bounded suppressions |

Public ids are `INC-<6-digit sequence>`.

## Incident fields

Minimum fields:

    incident_id, fingerprint, title, description
    status, priority, severity, confidence
    first_seen, last_seen, created_at, updated_at, closed_at
    primary_entity_type, primary_entity_id
    entity_ids[], observables{}
    investigation_state, assigned_to, assigned_team
    source_type, source_id
    incident_version, model_version
    created_by, updated_by
    suppression_reason, suppression_scope, suppression_expires_at, suppression_created_by
    policy_id

## States (spec 7.15)

    NEW → TRIAGED → INVESTIGATING → CONTAINMENT_REQUIRED → CONTAINED → RESOLVED → CLOSED
    Any active state → SUPPRESSED

Invalid transitions return HTTP 422. Closed/suppressed incidents do not
silently reopen (7.6).

## Severity (spec 7.7)

Derived from the strongest legitimate supporting source (correlation,
risk, group, alert). Never inflated by arithmetic. Values:
critical / high / medium / low.

## Confidence (spec 7.8)

Deterministic formula (7.29):

    base 0.40
    + correlation_support 0.20
    + multi_entity_support 0.10
    + repeated_activity 0.08
    + strong_evidence 0.22
    = clamped 0.0..1.0

Confidence is separate from severity, priority, and risk.

## Priority (spec 7.9)

Analyst workload concept: P1 / P2 / P3 / P4. Derived from severity,
risk score, and affected entity count. Priority never modifies severity,
confidence, or risk.

## Fingerprint (spec 7.4)

SHA256 of normalized identity:

    incident_type + primary_entity + relevant_entities
    + correlation_finding_ids + behavior_group_ids + policy_id

No timestamps, no random UUIDs. Same situation → same fingerprint.

## Deduplication (spec 7.5)

Atomic `INSERT ... ON CONFLICT DO NOTHING` with savepoint retry for
public-id collisions. Concurrent workers produce exactly one incident.

## Suppression (spec 7.21)

Explicit, bounded (max 90 days), audited. No permanent suppression.

## Audit (spec 7.20)

Every state-changing operation is audited with action, actor, old/new
value, reason, and timestamp.
