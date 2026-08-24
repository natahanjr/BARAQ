# v1 known-problem regression corpus

Each file documents a concrete behavior of the frozen v1 detection engine,
captured from the live database / evaluation harness on **2026-08-17**
(baseline tag `baseline-v1-2026-08-17`, commit 69b0259).

These are the "baseline failure states" that BARAQ v2 must demonstrably
improve. Every file follows the same structure:

```text
Input events
  ↓
v1 behavior (Detection(s) → Alert(s) → Risk → Incident(s))
  ↓
V2 expected behavior
  ↓
Regression (how to assert improvement)
```

## Index

| ID | Problem |
|----|---------|
| `RDP_DUPLICATION_001` | 1 alert per RDP event → 30 alerts for one logon burst |
| `BRUTE_FORCE_OVERALERTING_001` | 15 per-event alerts for one brute-force campaign |
| `INCIDENT_DUPLICATION_001` | playbook opened 2 incidents for 1 alert (idempotency) |
| `RISK_SATURATION_001` | critical incidents tagged MEDIUM/LOW risk |
| `ML_ANOMALY_OVERFLAGGING_001` | unreproducible 100% precision / 0% FPR claims |
| `DUPLICATE_RULES_001` | 3 alert families for one campaign |

## Baseline KPI reference (backups/2026-08-17-baseline/BARAQ_V1_BASELINE.txt)

```text
Events / 24h ........ 120
Alerts (total) ....... 68      (active 68)
Open Incidents ....... 11      (unassigned 8)
Critical Incidents ... 5       (critical+high open 10)
High-Risk Entities ... 2
ML Anomalies ......... 0 (harness: 27 on prior day)
alerts / events ...... 0.5667
incidents / alerts ... 0.1618
duplicate alerts ..... 47 across 3 group(s)
```
