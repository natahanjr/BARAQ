# detection/ — rule evaluation (v2 boundary)

BOUNDARY — detection consumes `EVENT`s and produces `FINDING`s. It never
creates incidents and never executes responses.

| Module | Contract |
|--------|----------|
| `rules/` | Declarative detectors (sigma + custom). Each rule: id, name, mitre mapping, severity, conditions. No side effects. |
| `engine/` | Runs rules against events; emits `FINDING`s. Pure: same input → same findings. |
| `findings/` | The `FINDING` object model: rule id, matched evidence (event ids), confidence, severity, mitre, first/last seen. |

Owns: `FINDING`. Emits: `FINDING` only.

NOT allowed: alert creation, risk mutation, incident creation, SOAR actions.

---

## Phase 2 (v2, clean-room)

New deterministic detection engine alongside the frozen v1 modules above.
`EVENT -> DETECTION` only, no alerts/incidents/risk/SOAR/ML (hard
boundary, tested). See `docs/phase2/` for the full contract, detector
development guide and acceptance record.

| Module | Contract |
|--------|----------|
| `contract.py` | Canonical `DETECTION`: severity/confidence/evidence/observables/status, deterministic `detection_id` (rule + campaign key) |
| `registry.py` | `Registry` / `default_registry`; unique ids, registration order |
| `engine.py` | `run_detection` (pure), `persist` (writes `detections` only, idempotent upsert per campaign key), `run_and_persist` |
| `context.py` | Read-only `DetectionContext` (window queries over `v2_events`) |
| `evidence.py` | `Evidence(field, value, reason)`; `is_external` IP classification (doc ranges = external, RFC1918 = private) |
| `detectors/` | D001 External RDP, D002 Brute Force, D003 Suspicious PowerShell, D004 Python Writable Path, D005 Ransomware Behavior |
| `models.py` | `detections` table (detection_id unique) |

API: `/api/detections*` (list/filter, detectors, evaluate, detail) —
same `TELEMETRY_V2_ENABLED` gate as Phase 1, always disabled against the
`sentinel` production DB. Tests: `tests/detection/` (98 tests incl. the
SC-001..SC-008 labeled benchmark) + `tests/regression/test_phase2_detection.py`.
