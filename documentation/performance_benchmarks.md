# BARAQ — Performance Benchmarking

**Document:** Throughput, Latency and Resource Footprint on the Target Laptop
**Version:** 3.0 (PostgreSQL, 100 rules + Sigma, ML-enhanced)
**Date:** 2026-08-31

---

## 1. Target Hardware (Reference Deployment)

Single Windows 11 laptop — Intel Core i5, 12 GB RAM, any SSD. The platform
must stay idle-cpu and memory-light because it shares the machine with
normal user workloads.

---

## 2. How to Reproduce

All timings below are measured with the built-in evaluation harness and
`time.perf_counter()`; nothing external is required.

```powershell
# Full pipeline timing over the fixture attack suite (isolated temp DB)
python -m pytest tests/test_evaluation.py -v

# Hold-out evaluation reports detection_time_ms per layer:
curl.exe -X POST http://127.0.0.1:8001/api/evaluation/holdout -H "X-API-Key: baraq-dev-admin" -H "Content-Type: application/json" -d "{\"with_ml\": false, "use_real_baseline": true}"

# ML train + inference timing
curl.exe -X POST http://127.0.0.1:8001/api/system/ml/train -H "X-API-Key: baraq-dev-admin"
```

---

## 3. Benchmarks (measured 2026-08-05)

| Metric | Value | Measurement |
|---|---|---|
| Event normalization throughput | ~2,400 events/s | `Normalizer.normalize_batch` over 10k fixture records |
| Full pipeline (normalize → persist → 23 rules → alert) | ~180 ms per 100 events | `tests/test_evaluation.py` |
| Rules-engine detection latency (23 rules, 100 events) | ~90 ms | `RulesEngine.run` perf counter |
| Hold-out evaluation end-to-end (8 scenarios + real baseline) | ~2.5 s | `POST /api/evaluation/holdout` |
| ML training (Isolation Forest, 3 streams) | ~1.5 s | `POST /api/system/ml/train` |
| ML inference (per-event anomaly score) | ~0.4 ms/event | `score_event` over 1k events |
| Isolation Forest memory footprint | ~15 MB | 3 models, 60 estimators each |
| Scheduler idle CPU (15 s interval) | ~0.5 % | Task Manager, 10-minute idle window |
| REST API p95 response (list alerts) | ~45 ms | `httpx` loop, 50 requests |
| SQLite DB growth | ~60 KB per 1,000 events | `database/baraq.db` |

---

## 4. Interpretation vs. the Laptop Target

- **CPU:** the platform is idle-waiting by design — the 15-second scheduler
  wakes, collects, analyzes, sleeps. ML analysis runs every 10 cycles.
- **Memory:** SQLAlchemy + numpy + scikit-learn peaks around **90 MB RSS**
  including the API server; negligible against 12 GB.
- **Disk:** SQLite with WAL keeps growth linear and bounded; the 30-day
  retention policy (`EVENT_RETENTION_DAYS`) caps long-run growth.
- **Scalability caveat:** throughput degrades linearly once the SQLite file
  exceeds ~2 GB or the events table passes ~500k rows without pruning —
  addresses in production by PostgreSQL (see `limitations_and_future_work.md`).

---

## 5. Reproducing Against Your Deployment

---

## 6. Current Measurements (PostgreSQL Build, 2026-08-13)

The figures below were measured with the built-in harness
(`tools/perf_benchmark.py`) on a dedicated instance (HTTP 127.0.0.1:8010,
isolated scratch PostgreSQL database on the portable **PostgreSQL 16.6**
cluster at port 55432, real **2,512-rule Sigma set**, warm cache where
noted). After the native rule expansion the engine now runs **100 native
rules + 2,512 Sigma rules**. Live HTTPS figures (TLS, port 8443) are noted
where they differ.

| Metric | Value | Measurement |
|---|---|---|
| Login (PBKDF2 verification) | 168 ms p50 | 40 logins, HTTP |
| `GET /api/system/status` | 20.0 ms p50 / 43.5 ms p99 | 60 requests |
| `GET /api/alerts?limit=50` | 9.8 ms p50 | 60 requests |
| `GET /api/events?limit=50` | 12.3 ms p50 | 60 requests |
| `GET /api/dashboard/summary` | 23.9 ms p50 | 60 requests |
| `GET /api/endpoints` | 8.0 ms p50 | 60 requests |
| **Ingest, full pipeline incl. Sigma** | **2.7 events/s (377 ms/event)** | 5 batches × 20 records |
| Ingest latency (10 records) | 3.3 s p50 / 19.1 s p95 | 20 iterations |
| Sigma engine cold load (2,512 YAMLs) | 14.2 s | first load per process, then cached |
| Sigma evaluation (2,000 events, cold) | 19.8 s | scratch DB, real rule set |
| Sigma evaluation (2,000 events, warm) | 18.3 s p50 (≈ 9 ms/event) | 5 runs |
| Scheduler pipeline cycle (150 records, incl. Sigma) | 17.3 s p50 | 5 runs |
| Dashboard summary | 24 ms | in-process |
| Hold-out evaluation detection time | 30.5 s | 422 samples, 11 scenarios, real baseline |

### Hold-out evaluation metrics (2026-08-13, `run_holdout_evaluation`)

| Layer | Accuracy | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
|---|---|---|---|---|---|---|
| Rule (100 native) | 99.05% | 100% | 95.12% | 0.975 | 0.0% | 78 / 0 / 340 / 4 |
| ML (frozen detector) | 89.58% | 100% | 64.29% | 0.783 | 0.0% | 9 / 0 / 34 / 5 |
| Hybrid | 99.05% | 100% | 95.12% | 0.975 | 0.0% | 78 / 0 / 340 / 4 |

Negative class = 340 live host telemetry records; positives = hold-out attack
scenarios never seen in ML training. 25 alerts created; the 4 rule-layer
misses are all in the `ml_c2_beacon` scenario (beacon-cadence features only
partially scored by the network model — see the FN guidance in
`backend/evaluation/holdout.py`).

### Interpretation (current build)

- The **persist path is two orders of magnitude faster than the
  detection-bound ingest path**: each ingest request re-evaluates the last
  10 minutes of events against all 2,512 Sigma rules (~9 ms per event in
  the window). This is a deliberate detect-on-ingest trade-off; it is
  acceptable for the target deployment (small laboratory fleet, small
  batches every 30–60 s) and documented as future work ("incremental Sigma
  evaluation") in `limitations_and_future_work.md`.
- Rule-layer detection on the hold-out set is unchanged by the expansion
  (99.05% acc / 95.12% recall, same as the pre-expansion run) while adding
  ~52 new MITRE-mapped techniques; 100% of the documented scenarios are
  caught by at least one layer (rule or ML).
- Section 3 numbers (2026-08-05) refer to the earlier SQLite/23-rule build
  and are kept for history; use section 6 for current-state claims.

---
