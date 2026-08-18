# Behavioral Aggregation (Phase 4)

Deterministic grouping of published v2 alerts into explainable behavior
groups. Consumes Phase 3 `v2_alerts` only; never raw events, never incidents,
never risk, never playbooks, never ML.

## Layout

* `contract.py` — `BehaviorGroup` dataclass, statuses, family titles, banned
  title phrases.
* `fingerprint.py` — group fingerprint (sha256 of host+user+source+family).
* `grouping.py` — family mapping, primary host/user/source, membership
  reason and score.
* `windows.py` — `within_window`, `quiet_cutoff`, `close_cutoff`.
* `lifecycle.py` — `apply_transition` with `IllegalTransition`.
* `evidence.py` — per-member evidence rows, observables merging.
* `metrics.py` — live-group summary metrics.
* `audit.py` — audit event recording.
* `engine.py` — `process_alerts`, `expire_groups`, `next_group_id`; the
  only entry points. Refuses the v1 production database by name.
* `evaluation.py` / `evaluation_data.py` — labeled grouping-quality
  scenarios (e1-e6), raw counts only.

## Schema

`behavior_groups` (partial unique index `uq_behavior_groups_live_fingerprint`
on `group_fingerprint WHERE status IN ('ACTIVE','QUIET')` — declared in
`__table_args__`), `behavior_group_members`
(`unique(behavior_group_id, alert_id)`), `behavior_group_evidence`,
`behavior_group_audit_events`. These four tables are the entire write
surface.

## Key rules

* Groups are claimed with
  `INSERT ... ON CONFLICT (group_fingerprint) WHERE status IN ('ACTIVE',
  'QUIET') DO NOTHING`; `index_where` must be literal `text()`. `created` is
  decided by comparing the live row's id to the candidate id (psycopg3
  rowcount is -1 and RETURNING is None under ON CONFLICT DO NOTHING).
* Sliding window: an out-of-window alert closes the old group first — flush
  the transition BEFORE the claim, or ON CONFLICT absorbs the new episode.
* An alert joins at most one group ever; memberships are idempotent.
* Confidence = max member alert confidence (+0.15 consistency if multi-alert,
  cap 1.0); highest_severity = max member severity; never risk.

## API

`backend/api/behavior_groups.py` — `/api/behavior-groups` (list/detail/
alerts/evidence/timeline/audit/close/metrics/evaluation). PEP 562 gate
(`BEHAVIOR_GROUPS_ENABLED`, env `BARAQ_BEHAVIOR_GROUPS`), 404 when disabled.
Order matters: `/metrics` and `/evaluation` are declared before `/{group_id}`.

## Tests

`tests/aggregation/` (contract, fingerprint, grouping, windows, lifecycle,
evidence, metrics, engine, api, isolation) and
`tests/regression/v4-known-problems/test_group_known_problems.py`
(GROUP-001..015 + DoD). `tests/aggregation/helpers.py` provides
`fabricate_alerts` (direct `AlertRecord` rows bypassing Phase 3 dedup, which
anchors to real wall-clock now) and `make_alerts` (full Phase 3 pipeline).

See `docs/phase4/` for the contract, grouping policy, lifecycle,
explainability and acceptance criteria.