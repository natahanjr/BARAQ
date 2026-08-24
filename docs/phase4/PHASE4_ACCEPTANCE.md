# Phase 4 Acceptance (spec 4.1-4.54)

## Scope

Behavioral Aggregation consumes **published v2 alerts only** (no raw events,
spec 4.4), groups them into deterministic, explainable behavior groups, and
exposes read-oriented APIs. It is a separate subsystem from Phase 3
alerting; both coexist in the same v2 database schema.

## Verification

Run from the repository root with the venv:

```
$env:PYTHONPATH="F:\My Project\SentinelSOC"
& "F:\My Project\SentinelSOC\venv\Scripts\python.exe" -m pytest tests/aggregation tests/regression/v4-known-problems -q
```

Expected: **99 passed** (aggregation unit + GROUP-001..015 + DoD regression).

Full suite (note `--import-mode=importlib`: `tests/alerting` and
`tests/detection` share the basenames `test_contract.py`/`test_engine.py`,
which default-collection rejects only when all suites run together):

```
& "F:\My Project\SentinelSOC\venv\Scripts\python.exe" -m pytest tests/aggregation tests/alerting tests/detection tests/test_telemetry_v2.py tests/regression --import-mode=importlib -q
```

Expected: **337 passed**.

## Acceptance criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 4.1 | Aggregation engine from Phase 3 alerts | `engine.process_alerts` reads `v2_alerts` |
| 4.2 | Deterministic grouping | fingerprint = sha256(host, user, source, family) |
| 4.3 | Episodes = repeated in-window alerts | occurrence_count includes dedup merges |
| 4.4 | No raw events consumed | engine input is `AlertRecord` only |
| 4.5 | Degrades on missing identity | `"none"` fallback, family still groups |
| 4.6 | Behavior families | D001/D002→auth, D003/D004→exec, D005→encryption |
| 4.7 | Public id ≠ grouping key | `BG-<6-digit>` sequence id |
| 4.8 | Same input → same groups | idempotency test, deterministic code path |
| 4.13 | Family-specific windows | auth 15 / exec 30 / encryption 10 / unknown 30 |
| 4.14 | Sliding window | old episode closed, new group claimed |
| 4.15 | ACTIVE/QUIET/CLOSED | expire_groups two-pass lifecycle |
| 4.16 | No reopening | GROUP_REOPEN_REJECTED audit, new group |
| 4.17 | Membership scores | host .40 + user .25 + source .20 + time .15 = 1.00 |
| 4.18 | ≥2 relationships to group | fingerprint guarantees 4, MIN_RELATIONSHIPS=2 |
| 4.19 | Conservative grouping | different users/hosts/sources → separate groups |
| 4.20 | Floods compressed | e5: 30 alerts → 1 group |
| 4.21 | alert_count vs occurrence_count | both stored and tested |
| 4.22 | Suppressed alerts skipped | status == SUPPRESSED → continue |
| 4.26 | Group ≠ risk | isolation tests, no risk tables touched |
| 4.27 | Confidence bounded 0-1 | max member + 0.15 consistency, cap 1.0 |
| 4.30 | Evidence per member | behavior_group_evidence (field/value/reason) |
| 4.31 | No overclaiming titles | BANNED_TITLE_PHRASES hard-fail |
| 4.32 | Timeline | GET /timeline chronological |
| 4.33 | Audit events | group_id/action/actor/details/timestamp |
| 4.41 | Evaluation raw counts | /evaluation, labeled scenarios e1-e6 |
| 4.44 | No incidents/risk/SOAR/ML | test_isolation: v1 counters byte-identical |
| 4.45 | No ML in engine | import scan, deterministic code |
| 4.47 | Idempotent | replay → identical state |
| 4.48 | Concurrency-safe | partial unique index + ON CONFLICT claim |
| 4.49 | D001+D002 one group | full-pipeline auth episode test |
| 4.52 | Closed → new group | GROUP_REOPEN_REJECTED + second group |
| 4.53 | Analyst close | POST /{id}/close, 409 on closed |
| 4.54 | API-only access | FastAPI router, no scheduler/daemon |

## Isolation guarantees (hard boundary)

* `behavior_groups` / `behavior_group_members` / `behavior_group_evidence` /
  `behavior_group_audit_events` are the **only** tables written.
* Engine refuses the v1 production database (`sentinel`) by name.
* No playbook, SOAR, risk-event, incident or entity-risk writes anywhere in
  `backend/aggregation/` or `backend/api/behavior_groups.py`; tests assert
  v1 counters stay identical through create/attach/close and a 100-alert
  flood.
* No sklearn/kmeans/embeddings/LLM imports (import scan test).

## Known deviations

* Spec 4.17's score is always 1.00 for matched members (all four factors are
  guaranteed by fingerprint equality); the weights remain the documented
  source of the sum and `membership_reason` still lists each factor.
* `created` detection uses live-id comparison instead of INSERT RETURNING
  (psycopg3 rowcount -1 / RETURNING None under ON CONFLICT DO NOTHING).