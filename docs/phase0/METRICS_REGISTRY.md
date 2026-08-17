# BARAQ Metrics Registry (Phase 0.11 — "No Fake Confidence" rule)

Every number the dashboard reports must be a `metric` with an explicit
definition, dataset, time window, threshold, and calculation. If any field
is missing, the number is a marketing number and must not be displayed as
an operational metric.

## Rule

BARAQ must never report `100% Precision`, `99% Accuracy`, `0% FPR`, `MODEL
HEALTHY`, or `DRIFT CLEAN` unless the evaluation pipeline can demonstrate
those numbers using a **documented ground-truth dataset**.

## Metric template

```text
metric:        <unique id, e.g. eval.accuracy>
definition:    <one-sentence meaning>
dataset:       <ground-truth dataset name/version>
time window:   <e.g. 2026-08-17T08:10Z snapshot / last 24h>
threshold:     <what counts as pass>
calculation:   <exact formula / code path>
```

## Registry (baseline v1 — captured 2026-08-17)

| metric | definition | dataset | window | threshold | calculation |
|--------|-----------|---------|--------|-----------|-------------|
| `eval.accuracy` | (TP+TN)/all, pooled over rounds | v1 harness fixture (attack 129 / baseline 180) | run time, 3 rounds | n/a | `backend/evaluation/evaluator.py` (frozen v1) |
| `eval.precision` | TP/(TP+FP) | same | same | n/a | same |
| `eval.recall` | TP/(TP+FN) | same | same | n/a | same |
| `eval.fpr` | FP/(FP+TN) | same | same | n/a | same |
| `eval.mttd_p50` | median detection latency (alert − newest linked event) | same | same | < 5s target | same |
| `eval.mttd_p95` | 95th pct detection latency | same | same | < 30s target | same |
| `sec.score` | 100 − open-alert penalties | live DB | snapshot | n/a | `dashboard.compute_security_score` (frozen v1) |
| `sec.incidents_open` | count(incidents.status=open) | live DB | snapshot | n/a | count |
| `sec.entities_high_risk` | count(entity_risk in CRITICAL/HIGH) | live DB | snapshot | n/a | count |
| `det.alerts_per_event` | alerts/events | live DB | 24h | ≤ 0.1 target | ratio |
| `det.incidents_per_alert` | open incidents/alerts | live DB | 24h | ≤ 0.05 target | ratio |
| `det.duplicate_alerts` | Σ(c−1) over (rule,host) groups with c>1 | live DB | 24h | ≤ 0 target | query |
| `ml.anomalies_per_event` | ml-anomaly alerts/events | live DB | 24h | ≤ 0.01 target | ratio |

## v1 baseline values (from `backups/2026-08-17-baseline/BARAQ_V1_BASELINE.txt`)

```text
eval.accuracy ........ 0.9903 (n=309, CI 0.9718-0.9967)
eval.precision ....... 1.0000 (CI 0.9704-1.0000)   <- must be re-derived on documented ground truth
eval.recall .......... 0.9767 (CI 0.9339-0.9921)
eval.fpr ............. 0.0                         <- same caveat
eval.mttd_p50 ........ 4147.87 ms
eval.mttd_p95 ........ 31680.33 ms
det.alerts_per_event . 0.5667
det.incidents_per_alert 0.1618
det.duplicate_alerts . 47 across 3 groups
ml.anomalies_per_event 0.0 (harness day: 27 anomalies / 120 events)
```

## Enforcement (v2)

- `EvaluationRun` rows must carry CI bounds and n (columns already exist:
  `ci_accuracy_*`, `ci_precision_*`, `ci_recall_*`, `total_samples`,
  `attack_samples`, `baseline_samples`, `rounds`).
- Any dashboard metric without a registry entry fails a v2 CI check.
