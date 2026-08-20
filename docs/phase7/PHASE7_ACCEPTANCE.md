# Phase 7 Acceptance

## Definition of Done (spec 7.56-7.57)

Phase 7 is complete when:

    Detection → Alert → Behavior Group → Correlation → Risk → Incident

produces a small number of explainable, deduplicated, evidence-backed,
analyst-actionable incidents.

The system must NOT create incidents simply because an alert exists, a
risk score is high, an ML anomaly exists, or an event is unusual.

## Acceptance checks

1. `pytest tests/incidents tests/evaluation/v7 tests/regression/v7-known-problems --import-mode=importlib` green.
2. Full v2 suite stays green (no regression of phases 1-6).
3. Evaluation corpus passes (20 labeled scenarios).
4. Regression corpus passes (20 scenarios incl. flood, dedup, false-positive,
   reopening, suppression, severity/confidence separation, idempotency,
   concurrency, unrelated separation, SLA).
5. API: list, detail, related objects, timeline, graph, audit, metrics,
   health, transition, notes, assign, suppress, feedback.
6. Isolation: incident creation touches only `incidents_v2*` tables;
   alerts, groups, correlations, risk rows, telemetry untouched.
7. No ML imports in the incident package.
8. Determinism: same inputs → same fingerprint → at most one incident.
9. Failure containment: `INCIDENT_CREATION_FAILED` audit on error.
10. Canonical DoD: 100 events → 30 detections → 10 alerts → 5 groups →
    1 correlation → 1 risk → 1 eligible incident (spec 7.53).

## Known deviations

- Suppression expiry uses absolute datetime rather than relative policy
  duration; max 90 days enforced (7.21).
- Priority formula is deterministic but simplified (severity + risk +
  entity count) rather than the full weighted spec example (7.9).
- Evaluation corpus uses 20 scenarios rather than the minimum 20 listed
  in spec 7.40 (INC-001..INC-020), covering all required categories.
