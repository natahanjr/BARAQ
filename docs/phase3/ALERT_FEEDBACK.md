# Phase 3 — Alert Feedback

**Status:** implemented, tests green (branch `development/v2`)

## Structured feedback (spec 3.14, 3.34)

Values:

```text
TRUE_POSITIVE
FALSE_POSITIVE
BENIGN
DUPLICATE
EXPECTED_ACTIVITY
UNKNOWN
```

Every feedback action records `alert_id`, `feedback_type`, `analyst`,
`timestamp`, optional `comment`. Everything is validated server-side
(3.41); the alert row's `feedback` field reflects the latest verdict.

## False-positive tracking (spec 3.15)

`GET /api/alerts-v2/feedback-stats` returns:

```text
total_feedback
true_positives / false_positives / benign / duplicates / expected_activity / unknown
false_positive_rate   (only when labeled_alerts >= 10)
labeled_alerts        (always shown alongside FPR)
```

**Honesty rule:** `false_positive_rate` is `None` until at least
`ALERT_MIN_LABELED_FOR_FPR` (10) labeled alerts exist. "0% FPR" is never
presented from a tiny sample.

## Metrics (spec 3.36, 3.37)

`GET /api/alerts-v2/metrics`:

```text
total_alerts, open_alerts, critical/high/medium/low_alerts
deduplicated_alerts, occurrence_count
mean/median_time_to_acknowledge_minutes  + mtta_sample_size
mean/median_time_to_resolve_minutes      + mttr_sample_size
false_positive_count, true_positive_count, feedback_count
alert_reduction_ratio, duplicate_alert_ratio
alerts_per_detection, occurrences_per_alert
age_buckets: 0-15m | 15-60m | 1-4h | 4h+
```

MTTA/MTTR are reported in minutes WITH their sample sizes (`n=37`) — no
unsupported precision, no invented "SOC efficiency" scores. Age buckets are
reported but nothing is "overdue" until an explicit SLA policy exists
(spec 3.23; severity-based SLA definitions live in config as initial
defaults per spec 3.24: critical 15m, high 30m, medium 2h, low 8h).
