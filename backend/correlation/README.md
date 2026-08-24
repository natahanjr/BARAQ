# backend/correlation - Phase 5 Behavioral Correlation

Correlates Phase 4 **behavior groups** into deterministic, explainable
correlation findings (attack hypotheses - never confirmations). See
`docs/phase5/` for the full contract, rules policy, lifecycle and
acceptance criteria.

## Layout

| Module | Purpose |
|--------|---------|
| `contract.py` | types, statuses, edge types, phases, banned phrases, titles |
| `models.py` | the five correlation tables (FKs, partial unique index) |
| `fingerprint.py` | sha256(type + sorted member ids + normalized edges) |
| `windows.py` | configurable rule windows + quiet/close cutoffs |
| `lifecycle.py` | NEW/ACTIVE/QUIET/CLOSED transition validation |
| `audit.py` | audit event records (guarded, never breaks a run) |
| `edges.py` | pair relationship detection + strength |
| `confidence.py` | bounded deterministic confidence formula |
| `evidence.py` | evidence rows per member group |
| `rules/` | R001-R009 pure deterministic rules + registry (v1.0.0) |
| `candidates.py` | entity+time partitioned candidate pairs (never O(n^2)) |
| `engine.py` | correlate / expire_correlations / claims / type resolution |
| `metrics.py` | compression and distribution metrics |
| `evaluation.py` + `evaluation_data.py` | labeled corpus, raw counts |

## Pipeline

```
behavior_groups -> summaries -> candidate pairs -> match_pair (window
gate + >= 2 relationships + rule predicate) -> extend or create ->
fingerprint claim (ON CONFLICT DO NOTHING, partial unique index) ->
chain type resolution -> edges/evidence/members -> audit
```

## Hard boundaries

- Only the five `correlation_*` tables are written; groups/alerts/
  incidents/risk/playbooks/SOAR are never touched.
- The engine refuses the v1 production database (`sentinel`) by name.
- Deterministic, idempotent, concurrency-safe; no ML, no LLM.

## Tests

`tests/correlation/` (unit + API + metrics) and
`tests/regression/v5-known-problems/` (CORR-001..025 + DoD).