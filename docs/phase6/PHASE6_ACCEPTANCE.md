# Phase 6 Acceptance

## Definition of Done (spec 6.88)

30 Alerts -> 5 Behavior Groups -> 1 Correlation Finding -> Host Risk 72:

- score **72** (RF001 12 + RF003 18 + RF005 8 + RF010 10 + RF009 6 +
  RF006 10 + RF008 8), severity **HIGH**, state **HIGH**, trend **RISING**;
- the 30 alerts reach risk only through the groups
  (sum of host `alert_count` == 30);
- host 10.0.0.7: `group_count == 1` (G5 member; G4 destination),
  `correlation_count == 1`, `alert_count == 10`, confidence 1.0;
- `/api/risk/{id}/explain` decomposes 72 exactly into the 7 named factors,
  each with a reason and evidence.

Pinned in `tests/risk/test_risk_dod.py` and `test_risk_known_problems.py`.

## Acceptance checks

1. `pytest tests/risk tests/evaluation/phase6 tests/regression/v6-known-problems --import-mode=importlib` green.
2. Full v2 suite stays green (no regression of phases 1-5).
3. Evaluation: 27/27 labeled scenarios (RISK-001..RISK-027) pass through the
   real engine; counts report `scenarios`/`passed`/`failed` only - no
   fabricated accuracy. Corpus covers the spec 6.58 list: benign baseline
   (RISK-026), single low/medium/high events (RISK-026/001/027), repetition,
   decay, expiration, propagation, cap/floor, determinism, idempotency,
   types, threshold crossing, stale, trend and complete explanation.
4. API: list/filters, detail, entity lookup, factors, explain, timeline,
   graph, audit, metrics, health, ranking, factor registry, operator
   recalculation, `RISK_ENABLED` gate (404 when off).
5. Isolation: risk ingestion touches only the five `entity_risk_v2*`
   tables (v1 `entity_risk`/`risk_events`, incidents, playbooks and
   counters untouched); no ML imports in the risk package.
6. Production database refused by name (`sentinel`).
7. Determinism: same evidence + same clock -> same score (RISK-010).

## Known deviations from the spec text

- Tables are `entity_risk_v2*` instead of `entity_risk*` because Phase 1's
  v1 `backend/risk` package already owns those names; the contract doc
  documents the mapping.
- RF008 is refreshed at calculation time rather than stored per evidence
  item: it is one factor per entity, kept while evidence is recent,
  expired otherwise (prevents stacking).

## API surface (spec 6.46-6.48, 6.53, 6.65, 6.77)

GET  /api/risk, /{risk_id}, /entity/{type}/{id}, /{risk_id}/factors,
/{risk_id}/explain, /{risk_id}/timeline, /{risk_id}/graph,
/{risk_id}/audit, /metrics, /metrics/health, /ranking/top,
/evaluation, /factors/registry;
POST /api/risk/recalculate/{risk_id} (the only mutation).

The detail and entity responses include `related_entities` (incoming and
outgoing propagation neighbours with relationship type and DIRECT /
CONTEXTUAL origin, spec 6.48/6.80). Health reports calculations, failures
(RISK_CALCULATION_FAILED count), p95 latency, factor total and model
version (6.77). Metrics include concentration by entity type (6.54).