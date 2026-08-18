# Group Lifecycle

## States

```
                in-window alert               inactivity timer
   (created)  ──────────────► ACTIVE ───────────────────────► QUIET ──► CLOSED
   process_alerts              ▲   │                              │
   1st alert attaches          │   │ alert within window          │
   (GROUP_CREATED,             └───┘ (GROUP_REACTIVATED)          │
    ALERT_ADDED)                      │                           │
                                      │ analyst POST /close       │
                                      └───────────────────────────┘
```

* **ACTIVE** — receiving alerts within the family window.
* **QUIET** — no in-window alert for `AGGREGATION_QUIET_AFTER_MINUTES` (30);
  an in-window alert re-activates it (sliding window, spec 4.14/4.15).
* **CLOSED** — no in-window alert for `AGGREGATION_CLOSE_AFTER_MINUTES` (60)
  after last activity, or closed by an analyst. Closed groups are immutable
  history; matching alerts create a **new** group and `GROUP_REOPEN_REJECTED`
  is audited (spec 4.16, 4.52).

## Timers

`expire_groups(db, now)` walks live groups (spec 4.15):

* `ACTIVE` and `quiet_cutoff(last_seen, now, 30)` → `QUIET`
  (`GROUP_QUIETED`, `inactive_minutes: 30`).
* `QUIET` and `close_cutoff(last_seen, now, 60)` → `CLOSED`
  (`GROUP_CLOSED`, `inactive_minutes: 60`).

Cutoffs are evaluated per group in one pass; a fresh group needs two passes to
close (ACTIVE → QUIET → CLOSED). Closing is a status transition plus audit —
no incident, no risk event, no playbook (spec 4.44).

## Sliding window (spec 4.14)

When a matching alert arrives **outside** the window of the live group, the
engine closes the old group first (audited `GROUP_CLOSED`, reason
`aggregation window expired`), then claims a fresh group. The status change is
flushed to the database **before** the fingerprint claim so the partial unique
index (see below) no longer sees the old group as live. Without this flush,
the claim's `ON CONFLICT` would absorb the new episode into the stale group.

## Concurrency (spec 4.48)

The live-fingerprint uniqueness is enforced at the database:

```sql
CREATE UNIQUE INDEX uq_behavior_groups_live_fingerprint
  ON behavior_groups (group_fingerprint)
  WHERE status IN ('ACTIVE', 'QUIET');
```

* Declared in `__table_args__` — never as an orphaned standalone `Index`,
  which SQLAlchemy silently never creates.
* Claim = `INSERT ... ON CONFLICT (group_fingerprint) WHERE status IN
  ('ACTIVE','QUIET') DO NOTHING`. The `index_where` predicate must be a
  literal `text()` — an ORM expression binds parameters and breaks ON
  CONFLICT inference.
* Two workers claiming the same fingerprint: exactly one insert wins; the
  loser reads the winner's row. `created` is true only when the live group
  carries the candidate's own `behavior_group_id` (psycopg3 reports
  `rowcount == -1` and RETURNING scalar is `None` with `on_conflict_do_nothing`,
  so the id-comparison is the reliable signal).
* Id collisions on `BG-<n>` between concurrent claims are retried once via
  `IntegrityError` → rollback → re-read max id → re-insert.
* Membership is idempotent: `unique(behavior_group_id, alert_id)` +
  `ON CONFLICT DO NOTHING`.

## Idempotency (spec 4.47)

Replaying the same alert batch changes nothing: memberships, evidence,
counts, confidence and audits are identical (guarded by
`unique(behavior_group_id, alert_id)` and the `_already_member` skip).

## Manual close (spec 4.53)

`POST /api/behavior-groups/{id}/close` (analyst actor, `GROUP_MANUALLY_CLOSED`,
409 on CLOSED). The fingerprint is released: a later matching alert creates a
new group.

## Audit events

All transitions recorded in `behavior_group_audit_events`:
`GROUP_CREATED`, `ALERT_ADDED`, `GROUP_REACTIVATED`, `GROUP_QUIETED`,
`GROUP_CLOSED`, `GROUP_REOPEN_REJECTED`, `GROUP_MANUALLY_CLOSED`.