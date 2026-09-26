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

## Rule tuning notes (2026-09)

Three rules were corrected after running them against real host telemetry. The
common cause was **treating a missing or unmeasured signal as evidence**:

- `rules/masquerading.py` — fired when a process path was empty
  (`smss.exe is executing from ''`). An unreadable path means access was
  denied, not that the binary lives outside `C:\Windows`; it fired on
  locked-down endpoints by construction. Now skipped.
- `rules/network_recon.py` — counted a host talking to *itself*
  (`192.168.1.5 → 192.168.1.5 across 37 ports`) as a port scan. Loopback and
  keep-alive churn is not reconnaissance. The self-pair is now excluded.
- `rules/c2_beacon.py` — fired on total volume alone (≥5 MB, ≥3 connections,
  one long connection), which every browser, chat client and Windows Update
  satisfies: **104 high-severity alerts in 6h of one laptop's real traffic**,
  all false. It now classifies by *shape*:
  - **beaconing** (high) = many small transfers (≥8 connections, ≤256 KB
    average each) — repetition is the signal;
  - **bulk** (low) = few large transfers, and suppressed entirely for known
    bulk-transfer programs (browsers, WebView2, chat clients, updaters);
  - **interpreter/LOLBin bulk** (medium) = the same volume from
    `powershell.exe`, `certutil.exe` and friends, which have no normal reason
    to ship bulk data off-host. Without this carve-out the rewrite silenced a
    *real* detection (a 24 MB PowerShell exfiltration) that the hold-out suite
    caught.

The pattern to watch for in new rules: if a rule can be satisfied by a
*missing* value, it will fire on every host that lacks the telemetry.

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
