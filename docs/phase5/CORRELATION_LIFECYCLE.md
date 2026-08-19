# Correlation Lifecycle

## Statuses (spec 5.31)

```
NEW  --(first extension / analyst activation)--> ACTIVE
NEW  --(inactivity)------------------------------> QUIET
ACTIVE --(inactivity)----------------------------> QUIET
QUIET --(new matching group)---------------------> ACTIVE
QUIET --(prolonged inactivity)-------------------> CLOSED
ACTIVE --(prolonged inactivity)------------------> CLOSED
```

- `NEW`: born by the correlation engine.
- `ACTIVE`: has matched new behavior since birth.
- `QUIET`: no new matching behavior for `CORRELATION_QUIET_AFTER_MINUTES`
  (120) since `last_seen`.
- `CLOSED`: no matching behavior for `CORRELATION_CLOSE_AFTER_MINUTES`
  (240) since `last_seen`. CLOSED is terminal.

Transitions are validated (`apply_transition` raises on illegal
transitions); `expire_correlations` walks NEW/ACTIVE -> QUIET and QUIET ->
CLOSED in one pass and records `CORRELATION_QUIET` /
`CORRELATION_CLOSED` audit events.

## No silent reopen (spec 5.32)

A closed finding never absorbs new behavior. When a new group matches a
closed finding's tail, the engine records `CORRELATION_REOPEN_REJECTED`
and the group starts a **new** finding - the closed one stays closed, its
fingerprint is released (the live-fingerprint partial index only covers
NEW/ACTIVE/QUIET), and the next matching episode claims a fresh finding.

## Inactivity cutoffs (config)

| Constant | Minutes | Meaning |
|----------|---------|---------|
| `CORRELATION_QUIET_AFTER_MINUTES` | 120 | NEW/ACTIVE -> QUIET |
| `CORRELATION_CLOSE_AFTER_MINUTES` | 240 | QUIET/ACTIVE -> CLOSED |

## Audit trail (spec 5.63)

Every state-changing operation is recorded in `correlation_audit_events`:

- `CORRELATION_CREATED` - rule, type, fingerprint, members, relationships,
  confidence;
- `GROUP_ADDED` - group id, rule, membership reason, reactivated/extended;
- `EDGE_CREATED` - source/target group, relationship type, strength;
- `CORRELATION_UPDATED` - type upgrades, extension rejections, reactivation;
- `CORRELATION_QUIET` / `CORRELATION_CLOSED` - inactivity transitions;
- `CORRELATION_REOPEN_REJECTED` - closed findings never absorb.

## Concurrency (spec 5.35-5.37)

At most one LIVE finding per fingerprint: partial unique index
`uq_correlation_live_fingerprint` (status IN NEW/ACTIVE/QUIET) plus
INSERT ... ON CONFLICT DO NOTHING. The claim is "ours" exactly when the
re-read live row carries our `correlation_id` - never if-exists, never
returning a foreign finding's data. Extensions that would collide with a
foreign live fingerprint are rejected and audited instead of corrupting
the store.