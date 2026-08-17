# ML_ANOMALY_OVERFLAGGING_001 — ML anomaly noise and unlabeled baseline

Captured from the v1 evaluation harness on 2026-08-17 (baseline-v1-2026-08-17).

## Input
The v1 evaluation suite (live assessment mode) with the bundled fixture
scenarios (brute force, port scan, powershell, privilege escalation,
persistence, data exfiltration) plus a synthetic baseline of normal activity.

## v1 behavior
- Overall accuracy 0.9903, precision 1.0, recall 0.9767, F1 0.9882, FPR 0.0
  (n=309, attack 129 / baseline 180, 3 rounds). These numbers are not
  independently reproducible from a documented ground-truth dataset and
  should be treated as marketing numbers until re-derived on the v2
  evaluation harness.
- Honest miss surfaced by the harness: brute_force TP 33/36 (3 FN).
- On the live system, ML anomaly detections contributed 27 anomalies on a
  day with 120 events (baseline drift caused by the model retraining every
  5 minutes on a 120-event window).

## V2 expected behavior
- Evaluation runs report metric + definition + dataset + window + threshold
  + CI (see METRICS_REGISTRY.md).
- No "100% precision / 0% FPR" claim without a documented ground-truth
  dataset and reproducible pipeline.
- ML model retrains on a stable window (not every 5 min on tiny data), and
  anomaly-rate is bounded: anomalies / events must be reported and reviewed,
  not silently accumulated.

## Regression
- Replay: run the v2 evaluation harness on the same fixture scenarios.
- Assert: every metric row has CI bounds and n; no drift flag claims
  "HEALTHY" without an explicit window + threshold.
