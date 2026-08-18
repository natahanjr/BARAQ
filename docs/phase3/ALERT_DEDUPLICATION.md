# Phase 3 — Alert Deduplication

**Status:** implemented, tests green (branch `development/v2`)

## Fingerprint (spec 3.7)

Deterministic dedup key, independent of alert id and timestamp:

```text
sha256(detector_id | host_id | user_id | source_ip | mitre_technique)
```

Stable and reproducible; never a random UUID (UUIDs are fine as alert IDs,
never as dedup keys).

## Windows (spec 3.9)

Per-detector, configuration-driven (`backend/config.py`), never hardcoded
into detectors:

```text
D001 External RDP          15 minutes
D002 Brute Force           15 minutes
D003 Suspicious PowerShell  10 minutes
D004 Python writable path   10 minutes
D005 Ransomware              5 minutes
default                      10 minutes
```

## Merge rules (spec 3.8-3.10, 3.44-3.47)

A new detection merges into an existing alert when ALL hold:

1. identical `alert_fingerprint` (same detector, host, user, source, MITRE)
2. the existing alert is still active (`OPEN`/`ACKNOWLEDGED`/`IN_PROGRESS`)
3. `last_seen` is inside the detector's dedup window

On merge: `occurrence_count += 1`, `last_seen` widened, `detection_id`
appended to `detection_ids[]`, and a full occurrence row (with its own
evidence) is stored. `first_seen` never moves.

**No silent merging of unrelated behavior:**

```text
RDP host A + RDP host B          -> 2 alerts   (different assets, spec 3.46)
RDP 185.x.x.x + RDP 41.x.x.x     -> 2 alerts   (different sources, spec 3.47)
30 RDP detections, same host/user/source, in window -> 1 alert, 30 occurrences
18 brute-force detections        -> 1 alert, 18 occurrences
```

**Reopening (spec 3.10):** a resolved/closed/suppressed alert never absorbs
future behavior — the next matching detection creates a NEW alert:

```text
10:00 RDP -> ALR-0001
10:05 RDP -> ALR-0001 (occurrences: 2)
10:10 ALR-0001 resolved
11:00 RDP -> ALR-0002 (NEW)
```

## Rationale

The goal is NOT the smallest possible alert count; it is the smallest count
that does not hide distinct security behaviors. One meaningful behavior =
one manageable analyst alert, with every underlying detection and piece of
evidence preserved.
