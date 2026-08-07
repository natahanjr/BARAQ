# SentinelSOC — Performance Benchmarking

**Document:** Throughput, Latency and Resource Footprint on the Target Laptop
**Version:** 1.0
**Date:** 2026-08-05

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
curl.exe -X POST http://127.0.0.1:8000/api/evaluation/holdout -H "X-API-Key: sentinel-dev-admin" -H "Content-Type: application/json" -d "{\"with_ml\": false, \"use_real_baseline\": true}"

# ML train + inference timing
curl.exe -X POST http://127.0.0.1:8000/api/system/ml/train -H "X-API-Key: sentinel-dev-admin"
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
| SQLite DB growth | ~60 KB per 1,000 events | `database/sentinel.db` |

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
