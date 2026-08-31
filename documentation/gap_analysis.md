# BARAQ — Gap Analysis & TODO

**Audit date:** 2026-08-31
**Overall:** ~130 items EXISTS, ~20 PARTIAL, ~8 MISSING

---

## Status Summary

| Status | Count |
|--------|-------|
| EXISTS | ~130 |
| PARTIAL | ~20 |
| MISSING | ~8 |

---

## MISSING Items (Must Build)

| # | Area | Item | Priority | Notes |
|---|------|------|----------|-------|
| 1 | Core | Memory profiling tests | Medium | No resource profiling scripts exist |
| 2 | Investigation | Bookmarks in investigation | Low | No favorites/bookmark feature |
| 3 | SOAR | Formal approval workflow | High | Config gate exists, no multi-step approval UI |
| 4 | Integrations | Cloud provider connectors (AWS/Azure/GCP) | Medium | No cloud integrations |
| 5 | Integrations | Endpoint platform connectors (CrowdStrike/SentinelOne) | Medium | No EDR connectors |
| 6 | Integrations | External SOAR connectors (XSOAR/Splunk SOAR) | Low | Internal playbook engine only |
| 7 | ML | Attack path prediction | Medium | Only reactive chain reconstruction, no predictive |
| 8 | Compliance | Multi-framework compliance (SOC2/ISO27001/NIST) | Low | Only GDPR/CCPA basics |

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
| 2 | SOAR approval workflow (multi-step approval UI) | TODO |
| 3 | Formal ingestion throughput benchmark (100/1K/10K events/sec) | TODO |
| 4 | API latency benchmark suite | TODO |
| 5 | Memory profiling tests | TODO |

### P1 — High (Core quality)

| # | Task | Status |
|---|------|--------|
| 6 | MITRE gap analysis automated report | TODO |
| 7 | Investigation bookmarks feature | TODO |
| 8 | SOAR forensic evidence collection action | TODO |
| 9 | UEBA baseline profiling per user | TODO |
| 10 | Insider threat dedicated scoring | TODO |
| 11 | Automated blast radius calculation | TODO |

### P2 — Medium (Feature completeness)

| # | Task | Status |
|---|------|--------|
| 12 | Attack path prediction (predictive, not reactive) | TODO |
| 13 | Cloud provider integrations (AWS/Azure/GCP) | TODO |
| 14 | Endpoint platform connectors (CrowdStrike/SentinelOne) | TODO |
| 15 | Multi-framework compliance (SOC2/ISO27001/NIST) | TODO |
| 16 | Fleet remote log fetch command | TODO |
| 17 | Fleet multi-profile config management | TODO |
| 18 | Compliance-specific scheduled reports | TODO |
| 19 | Formal high-volume alert stress test | TODO |

### P3 — Low (Nice to have)

| # | Task | Status |
|---|------|--------|
| 20 | External SOAR connectors (XSOAR/Splunk SOAR) | TODO |
| 21 | Documented query optimization suite | TODO |
| 22 | Enterprise SSO (SAML 2.0) | TODO |
| 23 | Hypothesis-driven threat hunting workflows | TODO |
| 24 | Visual playbook builder | TODO |
