# Phase 2 Acceptance — Deterministic Detection Engine (EVENT -> DETECTION)

Status: **implemented, tests green** (branch `development/v2`).

## Scope

A deterministic, explainable v2 detection engine: `EVENT -> DETECTION`
only. Five rule-based detectors (D001–D005), a `detections` store, a
read-only API, a human-labeled evaluation benchmark, and corpus
regression wiring against the v1 known-problem baseline
(`baseline-v1-2026-08-17`).

## Detectors

| ID | Name | Rule | MITRE | Severity |
|----|------|------|-------|----------|
| D001 | External RDP Logon | logon_type 10 + external/public source | T1133 | high |
| D002 | Brute Force | 10+ auth failures / 15 min, fires at each multiple | T1110 | medium 10–29, high ≥30 (or ≥20 + success) |
| D003 | Suspicious PowerShell | encoded / download / unusual-location-or-hidden | T1059.001 | medium, high at ≥2 characteristics |
| D004 | Python from Writable Path | python from user-writable location (System32, /usr, /opt, /lib, /bin excluded) | T1059.006 | medium |
| D005 | Ransomware Behavior | 20+ file modifications / 5 min, fires at each multiple; shadow-delete & large counts escalate | T1486 | medium, high ≥50 or shadow delete |

All: deterministic, versioned (`1.0.0`), evidence-explainable,
confidence 0–1 (3 decimals), status `new`.

## Acceptance checklist

- [x] 2.1 EVENT contract is the only detection input (no raw parsing in detectors).
- [x] 2.2 Registry: 5 detectors, unique ids, deterministic order, supports() gating.
- [x] 2.3 `run_detection`/`run_detections` pure: same input -> same output, zero writes (tests assert `alerts`/`incidents`/`entity_risk`/`detections` untouched).
- [x] 2.4 `persist` writes only `detections`; idempotent per campaign key (upsert merges `event_ids`, widens span, refreshes severity/confidence).
- [x] 2.5 Hard isolation: persist refuses the production DB (`sentinel`) by name; API reports `disabled` against it (same gate as Phase 1, `TELEMETRY_V2_ENABLED`).
- [x] 2.6 Severity ∈ {low, medium, high, critical}; confidence ∈ [0,1] 3 decimals; statuses ∈ {new, expired, suppressed}.
- [x] 2.7 Evidence: per-field `field/value/reason` on every detection; `to_explain()` renders an analyst-readable block.
- [x] 2.8 Detector versioning from day one (D001–D005 all `1.0.0`).
- [x] 2.9 Deterministic identity: `detection_id` = sha256 of rule + campaign key (D001: host+user+source; D002: host+user).
- [x] 2.10 Evaluation: 8 labeled scenarios (SC-001..SC-008; 5 TP, 3 TN) replayed through the real pipeline; benchmark green (TP=5, TN=3, FP=0, FN=0, precision=recall=f1=1.0, fpr=0.0).
- [x] 2.11 Corpus regression: `tests/regression/test_phase2_detection.py` — RDP burst = 1 detection (v1: 30 alerts), 60-failure campaign = 1 detection (v1: 15 alerts + 3 families), single file modification = no detection, benign burst silent, zero v1 side effects.
- [x] 2.12 Normalizer fills canonical `event_type` from `action` when missing (additive; fingerprint/dedup unchanged).
- [x] 2.13 Tests: 98 detection tests green (contract, registry, engine, per-detector, evaluation metrics, API, regression).
- [x] 2.14 Boundary verified: no detection path creates alerts/incidents/entity_risk rows or touches v1 tables.

## Evaluation methodology (see METRICS_REGISTRY.md)

The benchmark is **n = 8 scenarios, fully human-labeled, replayable** —
it is a regression gate for detector behavior, not a statistical claim
about detection quality at scale. Metrics are computed per scenario
(one decision per scenario): TP = expected detector fired, TN = benign
scenario stayed silent, FP/FN otherwise. Each scenario replays raw
records through normalize -> enrich -> ingest -> detect -> persist.

## Verification

```powershell
$env:PYTHONPATH="F:\My Project\SentinelSOC"
& "F:\My Project\SentinelSOC\venv\Scripts\python.exe" -m pytest tests/detection tests/test_telemetry_v2.py tests/regression/test_phase2_detection.py -q
# 110+ passed
```