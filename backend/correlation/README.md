# correlation/ — from findings to detections (v2 boundary)

BOUNDARY — consumes `FINDING`s, produces `DETECTION`s. Owns the
dedup → aggregate → chain pipeline. May create the single `ALERT` that
represents a `DETECTION` (1:1), never more.

| Module | Contract |
|--------|----------|
| `deduplication/` | Fingerprint key per finding (rule + host + user + source + window). Repeat findings do not emit new alerts. |
| `aggregation/` | N related findings → 1 DETECTION with evidence set and count (e.g. brute-force burst, RDP burst). |
| `attack_chains/` | Multi-stage correlation across findings (e.g. initial access → execution → persistence) → 1 DETECTION with chain graph. |

Owns: `DETECTION` (+ the 1:1 `ALERT`). Emits: `DETECTION` only.

NOT allowed: creating >1 alert per detection, per-event alerts, incidents.
