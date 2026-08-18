# Grouping Policy

## Determinism

Grouping is fully deterministic (spec 4.8): the same alert set in the same
order produces the same groups, memberships, fingerprints and scores. There is
no randomness, no clustering model, and no time-dependent ordering beyond the
alerts' own `first_seen`.

## Fingerprint grouping (spec 4.2)

Alerts are processed in `(first_seen, alert_id)` order. For each alert:

1. `behavior_family(alert)` — detector → family mapping.
2. `group_fingerprint(alert, family)` — sha256 of the 4-factor identity.
3. Live group lookup by fingerprint:
   - live group with `within_window(group.last_seen, alert.first_seen, family)`
     → **attach** (sliding window, spec 4.14);
   - live group outside the window → **close it first** (`GROUP_CLOSED`,
     reason `aggregation window expired`), then claim a fresh group
     (spec 4.14);
   - closed group exists → audit `GROUP_REOPEN_REJECTED`, create a new group
     (spec 4.16, 4.52).

## Relationship floor (spec 4.18)

`AGGREGATION_MIN_RELATIONSHIPS = 2`. Fingerprint equality enforces at least
host+user+source+family shared identity (4 relationships) for every member;
the constant is kept for explicitness and future loosening, and the check is
performed in `membership_reason` (spec 4.30).

## Windows (spec 4.13)

| Family         | Window (min) | Config key                    |
|----------------|--------------|-------------------------------|
| authentication | 15           | `AGGREGATION_WINDOWS_MINUTES["authentication"]` |
| execution      | 30           | `AGGREGATION_WINDOWS_MINUTES["execution"]`      |
| encryption     | 10           | `AGGREGATION_WINDOWS_MINUTES["encryption"]`     |
| unknown        | 30           | `AGGREGATION_WINDOWS_MINUTES["unknown"]`        |

`within_window(last_seen, alert_time, family)`:
`last_seen <= alert_time <= last_seen + window` for live groups. Because the
window slides, an alert arriving during a quiet period re-activates the group
(`GROUP_REACTIVATED`, spec 4.15).

## Flood compression (spec 4.20, 4.21)

A 30-alert flood sharing identity compresses into a single group of 30
members (evaluation scenario e5). No cap is applied to alert_count; the
membership table carries the detail and the group row keeps `alert_count` and
`occurrence_count` (occurrences include Phase 3 dedup merges, spec 4.3).

## What never groups

* `SUPPRESSED` v2 alerts are skipped (spec 4.22).
* Alerts already members of a group are skipped (idempotency, spec 4.47).
* Alerts from different hosts, users, sources or families form separate
  groups (evaluation scenarios e2, e3, e4, e6).

## Evaluation (spec 4.41)

`backend/aggregation/evaluation_data.py` defines 6 labeled scenarios
(e1 auth episode, e2 same host / different users, e3 same user / different
hosts, e4 same source / different hosts, e5 30-alert flood, e6 unrelated
episodes). `run_evaluation` replays them and returns **raw counts only** —
`correct`, `over_grouping`, `under_grouping`, `group_count`, `alert_count`
per scenario — no synthetic accuracy numbers. Scenarios are time-shifted
(`base_minutes`) so episodes never bleed into each other's windows.

## Configuration

All grouping knobs live in `backend/config.py` under the aggregation section
and can be overridden via environment variables (`BARAQ_BEHAVIOR_GROUPS`,
`BARAQ_AGGREGATION_*`). The engine refuses to run against the v1 production
database (`sentinel`) by name (hard isolation, spec 4.44).