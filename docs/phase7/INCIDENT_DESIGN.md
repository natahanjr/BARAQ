# Incident Design

## Package layout

    backend/incidents/
        __init__.py
        contract.py
        config.py
        models.py
        registry.py
        fingerprint.py
        eligibility.py
        engine.py
        lifecycle.py
        investigation.py
        evidence.py
        audit.py
        metrics.py
        evaluation_data.py
        evaluation.py
        README.md

    backend/api/incidents_v2.py

    tests/incidents/
    tests/evaluation/v7/
    tests/regression/v7-known-problems/

    docs/phase7/

## Ingestion boundary (spec 7.2)

Incident creation consumes:

    Detection
    Alert
    Behavior Group
    Correlation Finding
    Entity Risk

Raw telemetry never reaches the incident engine. The engine is read-only
against previous phases (7.42).

## Eligibility (spec 7.3)

Eight deterministic policies (I001-I008) evaluate grouped context and
return `eligible / reason / evidence / source_type / source_id`. No
global `if score > X: create` logic exists.

Policy trigger summary:

| Policy | Fires when |
|--------|-----------|
| I001 | MULTI_STAGE correlation with 2+ groups |
| I002 | Risk score ≥ 40 with supporting groups/activity |
| I003 | 3+ high alerts or 1+ high with 2+ groups |
| I004 | Lateral movement techniques across 2+ groups |
| I005 | Credential abuse techniques |
| I006 | Ransomware/impact techniques (T1486/T1490) |
| I007 | Persistence techniques |
| I008 | Explicit analyst escalation |

## Membership (spec 7.14)

Dedicated membership tables (`incident_alerts`, `incident_behavior_groups`,
`incident_correlations`, `incident_risk_sources`) preserve source
references without modifying upstream objects.

## Evidence (spec 7.12)

Every evidence item records `source_type, source_id, field, value, reason,
observed_at`. Allowed sources: ALERT, BEHAVIOR_GROUP, CORRELATION, RISK,
ENTITY, ANALYST.

## Isolation (spec 7.42)

Phase 7 writes only to `incidents_v2` and its child tables. Alerts,
behavior groups, correlations, risk factors, entity risk rows, and
telemetry remain byte-identical.

## Failure containment (spec 7.45)

Incident creation failures are recorded as `INCIDENT_CREATION_FAILED` and
rolled back. One failure does not stop unrelated incidents.

## Concurrency (spec 7.46)

Deterministic fingerprint + unique constraint + savepoint retry ensures
concurrent workers produce exactly one incident.
