# Risk Explainability

## "Why is this entity high risk?" (spec 6.32, 6.42, 6.88)

`GET /api/risk/{risk_id}/explain` returns the score decomposition: every
factor contribution with its value, decay factor, origin (DIRECT /
CONTEXTUAL), source type, source id, reason and evidence snapshot. The
sum of contributions equals the score exactly.

`GET /api/risk/{risk_id}/factors` returns the full provenance for every
factor, including `propagation_from` and `relationship_type` for
contextual contributions.

`GET /api/risk/{risk_id}/timeline` returns the append-only snapshot
history (score, severity, state, trend, factor count, model version per
capture).

`GET /api/risk/{risk_id}/graph` returns the entity node plus one source
node and edge per factor (factor id, contribution, origin) - the entire
evidence graph behind the score.

## DoD walk-through

30 Alerts -> 5 Behavior Groups -> 1 Correlation Finding (CF-000001) yields
host **10.0.0.7 = 72, HIGH, RISING**:

| Factor | + | Reason |
|--------|---|--------|
| RF001_EXTERNAL_ACCESS | 12 | G4 external logon (198.51.100.9, T1133) targets it |
| RF003_LATERAL_MOVEMENT | 18 | G5 lateral movement (T1021.001 x8) |
| RF005_EXECUTION | 8 | G5 PowerShell / WMI execution (T1059.001, T1047) |
| RF010_BEHAVIOR_GROUP | 10 | member of G5 |
| RF009_ALERT_SEVERITY | 6 | high-severity group on the host |
| RF006_MULTI_STAGE_CORRELATION | 10 | participant in CF-000001 |
| RF008_RECENCY | 8 | recent activity |
| **TOTAL** | **72** | HIGH RISING, confidence 1.0 |

Every number traces to a named group/finding id in the factors table -
nothing is hidden or learned.

## What never appears in risk output

- verdicts (compromised / malicious / attacker - hard-fail banned phrases);
- external reputation values (RF014 is weight 0 until a registered source);
- ML scores or "accuracy" percentages (6.56);
- incident/playbook side effects (isolation, 6.61-6.64).