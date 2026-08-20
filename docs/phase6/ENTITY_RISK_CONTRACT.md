# Entity Risk Contract

## What risk is (spec 6.1-6.8)

Entity risk is a deterministic, bounded (0..100), fully explainable
*accumulator* over typed evidence (alerts, behavior groups, correlation
findings, propagation). It is:

- NOT a verdict: an entity is never "compromised" or "malicious" (`BANNED_RISK_PHRASES`
  is enforced at construction and by tests);
- NOT an incident and never auto-creates one (isolation, spec 6.61-6.64);
- NOT an ML model: every point comes from a named factor with a reason,
  an evidence reference and an expiry (spec 6.41-6.43, 6.9).

## Storage (spec 6.29-6.35) — v2 table naming note

Phase 6 stores its five tables under the established v2 convention because
Phase 1's `backend/risk` package already owns the table names
`entity_risk` / `entity_risk_events` (v1 `entity_risk.py`). The Phase 6
tables are:

| Table | Purpose |
|-------|---------|
| `entity_risk_v2` | one row per (entity_type, entity_id); unique `uq_risk_v2_entity` |
| `entity_risk_v2_events` | evidence ingest log; unique (risk_id, source_type, source_id) |
| `entity_risk_v2_factors` | every contribution with provenance; unique (risk_id, factor_id, source_type, source_id) |
| `entity_risk_v2_snapshots` | append-only calculation history (6.23) |
| `entity_risk_v2_audit` | attribution trail (6.44, 6.70) |

All children FK to `entity_risk_v2.risk_id`; public ids are `ER-<6-digit
sequence>` (`next_risk_id`); creation is a concurrency-safe
`INSERT ... ON CONFLICT DO NOTHING` on (entity_type, entity_id), never a
check-then-insert (6.35).

## Entity types (spec 6.2)

HOST, USER, SOURCE_IP, DESTINATION_IP, ACCOUNT, PROCESS.

## Model version (spec 6.5)

`RISK_MODEL_VERSION = "1.0.0"`; stored on every risk row, snapshot and
audit event so history is never reinterpreted (6.23).

## Severity, state, trend (spec 6.20, 6.76, 6.26)

| Score | Severity | State |
|-------|----------|-------|
| < 20  | MINIMAL  | NORMAL |
| 20-39 | LOW      | ELEVATED |
| 40-59 | MEDIUM   | HIGH |
| 60-79 | HIGH     | HIGH |
| 80+   | CRITICAL | CRITICAL |

The spec examples map exactly: 0 -> NORMAL, 31 -> ELEVATED, 73 -> HIGH.
`STALE` overrides state when no recalculation happened in the last
`RISK_STALE_AFTER_MINUTES` (60) while score > 0 (6.76).

Trend (RISING / STABLE / FALLING / UNKNOWN) compares against the previous
snapshot only, with `RISK_TREND_DELTA = 3` points (6.26). Decay is
`0.5^(age_hours / 24)` per factor; factor lifetime 168h; propagation 72h
(6.20, 6.22, 6.27).

## Confidence (spec 6.18)

`direct / (direct + contextual)` over contributions. Purely direct
evidence -> 1.0; purely contextual -> 0.0.

## Repetition (spec 6.13)

Repeated *identical* alerts (same detector) on an entity follow
`RISK_REPETITION_CURVE (15, 8, 4, 2)` for occurrences 2..5+, keyed on the
alert evidence events. Groups absorb alerts at the aggregation boundary:
a group is one contribution, never one per member alert (6.12, 6.16).

## Propagation (spec 6.8, 6.27, 6.28)

Bounded by relationship type (`RISK_PROPAGATION_WEIGHTS`), expires after
72h, carries `origin=CONTEXTUAL`, `propagation_from` and
`relationship_type` for full provenance. A propagated score is never the
source's score.

## Spread (spec 6.9)

RF013 fires once per entity per evidence batch when the entity is a member
of 3+ groups in that batch (`apply_groups`).

## Metrics (spec 6.55-6.56)

Aggregate counts over the store (severities, score distribution, trends,
factor distribution, latency percentiles from the audit trail). No
accuracy/precision/recall number is ever fabricated.