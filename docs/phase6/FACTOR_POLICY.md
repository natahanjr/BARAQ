# Risk Calculation Policy

## Factor registry (spec 6.41)

RF001-RF014 live in `backend/risk/registry.py` with a version, type and
configured base weight. The engine passes the configured value as the
factor `value` with `weight = 1.0` in the 1.0.0 model; contribution is
`min(value * weight, definition.maximum_contribution)`.

| Factor | Type | Weight | Fires on |
|--------|------|--------|----------|
| RF001_EXTERNAL_ACCESS | EXTERNAL_ACCESS | 12 | external-source technique activity (T1133/T1190/T1078/T1566) on hosts; destinations when the group source is external |
| RF002_CREDENTIAL_ACCESS | CREDENTIAL_ACCESS | 14 | T1110 |
| RF003_LATERAL_MOVEMENT | LATERAL_MOVEMENT | 18 | T1021.x / T1570; also destinations |
| RF004_PRIVILEGE_ESCALATION | PRIVILEGE_ESCALATION | 10 | T1068 / T1548 / T1134 |
| RF005_EXECUTION | EXECUTION | 8 | T1059.x / T1047 / T1204 / T1203 |
| RF006_MULTI_STAGE_CORRELATION | CORRELATION | 10 | correlation finding membership (direct) or propagation (contextual, 6.8) |
| RF007_REPETITION | REPETITION | curve 15/8/4/2 | repeated identical alerts (6.13) |
| RF008_RECENCY | RECENCY | 8 | evidence younger than `RISK_RECENCY_BONUS_HOURS` (1h), refreshed at each calculation |
| RF009_ALERT_SEVERITY | ALERT_SEVERITY | tier crit 8 / high 6 / med 3 / low 1 | once per tier, on member hosts (never per alert) |
| RF010_BEHAVIOR_GROUP | BEHAVIOR_GROUP | 10 | group membership, one per group |
| RF011_PERSISTENCE | PERSISTENCE | 10 | T1547 / T1543 / T1136 / T1053 |
| RF012_DEFENSE_EVASION | DEFENSE_EVASION | 8 | T1562 / T1070 / T1218 / T1036 |
| RF013_ENTITY_SPREAD | ENTITY_SPREAD | 8 | member of 3+ groups in one evidence batch (6.9) |
| RF014_SOURCE_REPUTATION | SOURCE_REPUTATION | 0 | reserved: never fires without a registered reputation source (6.63-6.64) |

Unknown techniques are ignored (no factor, no magic); unknown factor ids
are rejected at insertion (6.43).

## Anti-double-counting rules (spec 6.12, 6.16, 6.22)

1. A behavior group contributes once per member entity regardless of its
   alert count (RF010) and once per severity tier (RF009).
2. A correlation finding adds only the sequence factor (RF006) - it never
   re-adds group, tier or alert factors.
3. Alert evidence is the only place repetition (RF007) applies; groups
   absorb their alerts at the aggregation boundary.
4. RF008 is one factor per entity, refreshed or expired at calculation
   time - it can never stack.
5. RF013 is one factor per entity per batch (source_id `spread:N`).

## Determinism

Every step is a pure function of stored rows and the calculation time
`now`: factor decay, tier mapping, state bands, trend delta, confidence.
Same evidence + same clock -> same score (pinned by tests and the
RISK-001..025 evaluation corpus). `duration_ms` per calculation is
recorded in the audit trail for honest latency metrics.