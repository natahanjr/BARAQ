# BARAQ — Gap Analysis & TODO

**Audit date:** 2026-08-31
**Last updated:** 2026-08-31
**Overall:** ~130 items EXISTS, ~13 PARTIAL, 0 MISSING

---

## Status Summary

| Status | Count |
|--------|-------|
| EXISTS | ~130 |
| PARTIAL | ~13 |
| MISSING | 0 ✅ |

---

## ✅ MISSING Items (All Completed)

| # | Area | Item | Status | Commit |
|---|------|------|--------|--------|
| 1 | Core | Memory profiling tests | ✅ DONE | `profiling/resource_profiler.py` |
| 2 | Investigation | Bookmarks in investigation | ✅ DONE | `api/bookmarks.py` + `Bookmark` model |
| 3 | SOAR | Formal approval workflow | ✅ DONE | `response/approval.py` + `api/approval.py` |
| 4 | Integrations | Cloud provider connectors (AWS/Azure/GCP) | ✅ DONE | `integrations/cloud/` abstraction |
| 5 | Integrations | Endpoint platform connectors (CrowdStrike/SentinelOne) | ✅ DONE | `integrations/edr/` abstraction |
| 6 | Integrations | External SOAR connectors (XSOAR/Splunk SOAR) | ✅ DONE | `integrations/soar/` abstraction |
| 7 | ML | Attack path prediction | ✅ DONE | `ml/attack_path.py` |
| 8 | Compliance | Multi-framework compliance (SOC2/ISO27001/NIST) | ✅ DONE | `compliance/frameworks.py` |

---

## PARTIAL Items (Need Enrichment)

| # | Area | Item | What Exists | What's Missing |
|---|------|------|-------------|----------------|
| 1 | MITRE | Gap analysis report | Frontend page exists | Automated report: which techniques have no detection |
| 2 | SOAR | Evidence collection | Process tree + timeline | Dedicated forensic bundle action |
| 3 | Compliance | Gap analysis | Basic data inventory | Framework-specific gap checking |
| 4 | Fleet | Log collection | Telemetry ships | Remote log fetch command |
| 5 | ML | UEBA | Entity risk + ML anomaly per user | Formal UEBA baseline profiling per user |
| 6 | ML | Insider threat | Risk escalation + behavioral anomaly | Dedicated insider threat scoring/classification |
| 7 | ML | Blast radius | Entity graph shows relationships | Automated blast radius calculation |
| 8 | Scale | Ingestion test | 100K generator script | Formal throughput benchmark |
| 9 | Scale | Alert volume test | Evaluation tests exist | Dedicated stress test |
| 10 | Scale | Query optimization | Indexes exist | Documented optimization suite |
| 11 | Scale | API latency | Detection latency tracked | Dedicated API latency benchmark |
| 12 | Compliance | Scheduled compliance reports | Scheduled reports exist | Compliance-specific scheduling |
| 13 | Fleet | Config profiles | Per-host config via script | Multi-profile config management |

---

## TODO — Priority Order

### P0 — Critical (Blocks product readiness)

| # | Task | Status |
|---|------|--------|
| 1 | End-to-end attack scenario test: pick one attack, run through full pipeline | TODO |
| 2 | Formal ingestion throughput benchmark (100/1K/10K events/sec) | TODO |
| 3 | API latency benchmark suite | TODO |

### P1 — High (Core quality)

| # | Task | Status |
|---|------|--------|
| 4 | MITRE gap analysis automated report | TODO |
| 5 | SOAR forensic evidence collection action | TODO |
| 6 | UEBA baseline profiling per user | TODO |
| 7 | Insider threat dedicated scoring | TODO |
| 8 | Automated blast radius calculation | TODO |

### P2 — Medium (Feature completeness)

| # | Task | Status |
|---|------|--------|
| 9 | Fleet remote log fetch command | TODO |
| 10 | Fleet multi-profile config management | TODO |
| 11 | Compliance-specific scheduled reports | TODO |
| 12 | Formal high-volume alert stress test | TODO |

### P3 — Low (Nice to have)

| # | Task | Status |
|---|------|--------|
| 13 | Documented query optimization suite | TODO |
| 14 | Enterprise SSO (SAML 2.0) | TODO |
| 15 | Hypothesis-driven threat hunting workflows | TODO |
| 16 | Visual playbook builder | TODO |
