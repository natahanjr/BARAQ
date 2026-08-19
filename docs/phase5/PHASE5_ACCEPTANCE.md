# Phase 5 Acceptance (spec 5.1-5.81)

## Scope

Behavioral Correlation consumes **behavior groups only** (no raw events,
no alerts as input - spec 5.2), correlates them into deterministic,
explainable findings via rules R001-R009, maintains the NEW/ACTIVE/QUIET/
CLOSED lifecycle, and exposes read-oriented APIs plus metrics and a
labeled evaluation corpus. It is a separate subsystem from Phase 3
alerting and Phase 4 aggregation; all three coexist in the same v2
database schema.

## Verification

Run from the repository root with the venv:

```
$env:PYTHONPATH="F:\My Project\SentinelSOC"
& "F:\My Project\SentinelSOC\venv\Scripts\python.exe" -m pytest tests/correlation tests/regression/v5-known-problems -q
```

Expected: **107 passed** (correlation unit + CORR-001..025 + DoD regression).

Full suite (note `--import-mode=importlib` - several suites share
basenames like `test_contract.py`):

```
& "F:\My Project\SentinelSOC\venv\Scripts\python.exe" -m pytest tests/aggregation tests/alerting tests/detection tests/test_telemetry_v2.py tests/correlation tests/regression --import-mode=importlib -q
```

## Definition of done (spec 5.70)

The canonical example: 30 alerts -> 5 behavior groups -> **1 correlation
finding** `CF-000001`, type **LATERAL_MOVEMENT**, confidence **0.88**,
edges exactly {SAME_USER, SAME_SOURCE, TEMPORAL, DESTINATION_RELATION,
LATERAL_MOVEMENT}, 30 member alerts, idempotent re-runs, lifecycle
QUIET -> CLOSED, no silent reopen (pinned in
`test_dod_30_alerts_5_groups_1_finding` and
`test_canonical_30_alerts_5_groups_1_finding`).

## Acceptance criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 5.1 | Deterministic rules | registry tests; pure predicates over summaries |
| 5.2 | Engine consumes groups only | engine input = `BehaviorGroupRecord` |
| 5.3 | Finding fields | contract test + stored model |
| 5.4 | 9 correlation types | contract test |
| 5.5 | Same input -> same findings | deterministic rerun test |
| 5.6 | Fingerprint = sha256(type+members+edges) | fingerprint unit test |
| 5.9 | Windows configurable | `CORRELATION_WINDOWS_MINUTES` in config |
| 5.10 | Windows bound chains | 4h-apart pair never correlates |
| 5.11-5.13 | Rule registry, metadata, version | `test_corr_rules.py` |
| 5.17 | MITRE is context, not proof | transition edges only same-family |
| 5.18 | Tactic phases | phase map + progression tests |
| 5.19 | Memberships with reasons | `correlation_members` rows carry reasons |
| 5.20 | 10 edge relationship types | contract + canonical edge set |
| 5.21 | Edge strength weights | strength unit tests, cap 1.0 |
| 5.22 | >= 2 relationships floor | `meets_minimum` tests |
| 5.23 | Confidence bounded 0-1 | confidence tests |
| 5.24 | Never summed from group confidences | formula is relationship-count based |
| 5.25 | Severity never escalated | canonical test |
| 5.26 | Titles pattern-language | TYPE_TITLES + banned-phrase hard-fail |
| 5.27 | No claims of compromise | `BANNED_CORRELATION_PHRASES` enforced |
| 5.28 | No confirmation claims | contract + regression 015 |
| 5.29 | Evidence preserved | `correlation_evidence` populated |
| 5.31 | NEW/ACTIVE/QUIET/CLOSED | lifecycle tests |
| 5.32 | No silent reopen | closed finding + matching tail -> rejected + new finding |
| 5.35-5.37 | Concurrency-safe claim | partial unique index + ON CONFLICT |
| 5.47 | Idempotent | 3x re-run -> identical state |
| 5.52-5.58 | Read-only API endpoints | `test_corr_api.py` (8 GETs + metrics/evaluation/rules) |
| 5.61 | Metrics | compression, distribution, zero-safe |
| 5.62 | Evaluation raw counts | labeled corpus, no fabricated accuracy |
| 5.63 | Audit trail | CREATED/GROUP_ADDED/EDGE_CREATED/QUIET/CLOSED/REJECTED |
| 5.64 | FK constraints | all child tables FK to findings |
| 5.68 | Groups never rewritten | snapshot equality test |
| 5.70 | DoD example | canonical + regression DoD test |
| 5.74 | No catch-all | unrelated episodes -> 0 findings |
| 5.77 | Failures never break telemetry | broken rule source -> state unchanged |
| 5.79 | Only correlation tables written | isolation tests (v1 counters identical) |

## Isolation guarantees (hard boundary)

* `correlation_findings` / `correlation_members` / `correlation_edges` /
  `correlation_evidence` / `correlation_audit_events` are the **only**
  tables written.
* Engine refuses the v1 production database (`sentinel`) by name.
* No playbook, SOAR, risk-event, incident, entity-risk, alert or behavior-
  group writes anywhere in `backend/correlation/` or
  `backend/api/correlations.py`; tests assert v1 counters stay identical.
* No sklearn/kmeans/embeddings/LLM imports (import scan test).

## Known deviations

* Spec 5.70's example in the implementation uses 5 groups (each on its own
  host, chained by destination) rather than 4; the required outcome -
  1 finding, LATERAL_MOVEMENT, confidence 0.88, the five exact edge types,
  30 alerts - is identical and pinned by the DoD tests.
* `HOST_CHAIN` is a chain-level upgrade inside `resolve_chain_type`, not a
  pair rule (R005/R006 produce SOURCE_CHAIN/USER_CHAIN; a 3+ host chain
  with network/destination relations upgrades to HOST_CHAIN).
* A pair must be inside the matching rule's window (TEMPORAL gate) before
  any rule is considered - stricter than a bare relationship floor and
  required by spec 5.10.
* `created` detection uses live-id comparison instead of INSERT RETURNING
  (psycopg3 rowcount -1 / RETURNING None under ON CONFLICT DO NOTHING).
* Engine calls `db.expire_all()` at the start of a run so a session reused
  across runs (scheduler retries, tests) never leaks stale identity-map
  rows into the "live" finding list.