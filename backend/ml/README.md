# ml/ — model scoring & evaluation (v2 boundary)

BOUNDARY — consumes `EVENT`/`DETECTION` features; produces scores and
evaluation results. All claims must be reproducible (see METRICS_REGISTRY.md).

| Module | Contract |
|--------|----------|
| `scoring/` | Model inference → anomaly/risk scores attached to events/entities. No alerting. |
| `anomaly/` | Anomaly detection models + drift monitoring with explicit window + threshold. |
| `evaluation/` | Ground-truth datasets, runs with CI/n/MTTD (metric, definition, dataset, window, threshold, calculation). |

Owns: model artifacts + evaluation records. Emits: scores, drift status,
evaluation runs.

NOT allowed: "100% precision / 0% FPR" claims without documented
ground-truth; unlabeled drift "HEALTHY".
