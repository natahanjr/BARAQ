# Risk Lifecycle

## Ingestion (spec 6.1)

`engine.ingest_evidence` / `apply_alert` / `apply_group` / `apply_groups` /
`apply_finding` / `apply_propagation`. Every evidence item:

1. claims/creates the risk row (`get_or_create_risk`, ON CONFLICT);
2. logs a `entity_risk_v2_events` row (deduplicated per source);
3. adds named factors with a reason, evidence snapshot and expiry;
4. recalculates every affected entity immediately (snapshot + audit).

Re-ingesting identical evidence is a no-op (idempotency pinned by tests).

## Calculation (spec 6.30, 6.36, 6.37)

`recalculate_entity` is the single calculation path (also used by
`recalculate_all` and the API's `POST /api/risk/recalculate/{risk_id}`
operator trigger, spec 6.65):

- `_refresh_recency` (RF008) runs first, using the entity's `last_seen`;
- factors are loaded in insertion order and decayed;
- score/severity/state/trend/confidence computed deterministically;
- an append-only snapshot is written (6.23);
- peak score never decreases (6.38); trend compares against the previous
  snapshot (6.26);
- state changes and threshold crossings are audited (6.76);
- `RISK_CALCULATION_FAILED` containment keeps the previous state intact
  (6.75).

## Expiry (spec 6.21, 6.72)

`expire_factors` marks factors past `expires_at` as expired (with
`FACTOR_EXPIRED` audit); expired rows are excluded from calculations but
never deleted - history remains for explainability.

## Staleness (spec 6.76)

If no recalculation happened within `RISK_STALE_AFTER_MINUTES` (60) and the
score is above 0, the state is reported as `STALE`.

## Counters

`alert_count` / `group_count` / `correlation_count` are monotonically
growing evidence counters on the risk row (never decremented on expiry).
DoD: 30 alerts -> 5 groups -> 1 finding -> host 10.0.0.7 = 72 HIGH RISING,
alert_count 10, group_count 1, correlation_count 1.

## Failure boundary

The engine refuses the production database by name
(`PRODUCTION_DB_NAME = "sentinel"`) before any write (6.82-6.84); an
exception during calculation is recorded as
`RISK_CALCULATION_FAILED` and the previous score/state stays intact.