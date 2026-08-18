# Phase 3 — Alert Lifecycle

**Status:** implemented, tests green (branch `development/v2`)

## States (spec 3.11)

```text
OPEN -> ACKNOWLEDGED | IN_PROGRESS | RESOLVED | SUPPRESSED
ACKNOWLEDGED -> IN_PROGRESS | RESOLVED | SUPPRESSED
IN_PROGRESS -> RESOLVED | SUPPRESSED
RESOLVED -> CLOSED | OPEN (explicit reopen)
CLOSED -> OPEN (explicit reopen)
SUPPRESSED -> OPEN (explicit reopen)
```

No arbitrary jumps: `OPEN -> CLOSED`, `ACKNOWLEDGED -> OPEN`,
`RESOLVED -> SUPPRESSED`, `CLOSED -> IN_PROGRESS` are all rejected with 409.
Reopening a closed/resolved/suppressed alert is an explicit `REOPENED`
operation (spec 3.11: "CLOSED -> OPEN should require an explicit reopen
operation").

## Workflow fields (spec 3.12, 3.13)

| Operation | Sets | Meaning |
|---|---|---|
| acknowledge | `acknowledged_at`, `acknowledged_by` | an analyst has SEEN the alert — not that the threat is resolved |
| assign | `assigned_to`, `assigned_at` | analyst ownership (no team scheduling) |
| resolve | `resolved_at` | analyst closed out the behavior |
| close | — | final closure |
| reopen | — | explicit return to OPEN |

## Audit trail (spec 3.27, 3.35)

Every state-changing operation records an `alert_audit_events` row with
`action`, `previous_status`, `new_status`, `actor`, `details`, `created_at`:

```text
10:30  CREATED       system
10:32  ACKNOWLEDGED  analyst@example
10:35  ASSIGNED      analyst@example
10:41  FEEDBACK=TRUE_POSITIVE  analyst@example
10:50  RESOLVED      analyst@example
```

Suppressed detections are also audited (action `SUPPRESSED` with the
policy id that matched).

## Example (spec 3.44)

```text
Detection -> Eligible -> Alert created (OPEN)
  repeated detection  -> existing OPEN alert, occurrence_count += 1,
                         last_seen widened, evidence appended
  alert expires (window) -> new detection creates a NEW alert
  resolved/closed alert  -> NEVER absorbs future behavior
```
