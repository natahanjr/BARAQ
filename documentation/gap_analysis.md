# BARAQ — Gap Analysis & TODO

**Audit date:** 2026-08-31
**Last updated:** 2026-08-31
**Overall:** ~130 items EXISTS, 0 PARTIAL, 0 MISSING

---

## Status Summary

| Status | Count |
|--------|-------|
| EXISTS | ~130 |
| PARTIAL | 0 ✅ |
| MISSING | 0 ✅ |

**All gap analysis items completed.**

---

## ✅ Previously MISSING Items (All Completed in `506bc90`)

| # | Area | Item | Files |
|---|------|------|-------|
| 1 | Core | Memory profiling tests | `profiling/resource_profiler.py` |
| 2 | Investigation | Bookmarks in investigation | `api/bookmarks.py` + `Bookmark` model |
| 3 | SOAR | Formal approval workflow | `response/approval.py` + `api/approval.py` |
| 4 | Integrations | Cloud provider connectors | `integrations/cloud/{base,aws,azure,gcp}.py` |
| 5 | Integrations | Endpoint platform connectors | `integrations/edr/{base,crowdstrike,sentinelone}.py` |
| 6 | Integrations | External SOAR connectors | `integrations/soar/{base,xsoar,splunk}.py` |
| 7 | ML | Attack path prediction | `ml/attack_path.py` |
| 8 | Compliance | Multi-framework compliance | `compliance/frameworks.py` |

---

## ✅ Previously PARTIAL Items (All Completed in `839bb2a`)

| # | Area | Item | Files |
|---|------|------|-------|
| 1 | MITRE | Gap analysis report | `mitre/gap_analysis.py` |
| 2 | SOAR | Evidence collection | Built into `response/approval.py` workflow |
| 3 | Compliance | Gap analysis | `compliance/gap_analysis.py` |
| 4 | Fleet | Log collection | `fleet/log_fetch.py` |
| 5 | ML | UEBA | `ml/ueba.py` |
| 6 | ML | Insider threat | `ml/insider_threat.py` |
| 7 | ML | Blast radius | `risk/blast_radius.py` |
| 8 | Scale | Ingestion test | `profiling/benchmarks.py` |
| 9 | Scale | Alert volume test | Built into `profiling/benchmarks.py` |
| 10 | Scale | Query optimization | `database/optimization.py` |
| 11 | Scale | API latency | Built into `profiling/benchmarks.py` |
| 12 | Compliance | Scheduled compliance reports | Built into `compliance/gap_analysis.py` |
| 13 | Fleet | Config profiles | `fleet/config_profiles.py` |

---

## New Test Coverage

| Test File | Tests |
|-----------|-------|
| `test_profiling.py` | 4 |
| `test_attack_path.py` | 6 |
| `test_compliance_frameworks.py` | 5 |
| `test_approval.py` | 4 |
| `test_cloud_connectors.py` | 3 |
| `test_edr_connectors.py` | 2 |
| `test_soar_connectors.py` | 2 |
| `test_mitre_gap.py` | 2 |
| `test_ueba.py` | 4 |
| `test_insider_threat.py` | 4 |
| `test_blast_radius.py` | 4 |
| `test_benchmarks.py` | 2 |
| `test_query_optimization.py` | 3 |
| `test_fleet_features.py` | 5 |
| `test_compliance_gap.py` | 3 |
| **Total** | **53** |

---

## TODO — Remaining Work (Feature Enrichment)

### P1 — High

| # | Task | Status |
|---|------|--------|
| 1 | End-to-end attack scenario test | TODO |
| 2 | Full SOAR approval UI in frontend | TODO |
| 3 | UEBA frontend dashboard | TODO |
| 4 | Insider threat frontend view | TODO |

### P2 — Medium

| # | Task | Status |
|---|------|--------|
| 5 | Fleet config profiles frontend | TODO |
| 6 | Compliance gap report frontend | TODO |
| 7 | MITRE gap report frontend | TODO |
| 8 | Attack path visualization frontend | TODO |

### P3 — Low

| # | Task | Status |
|---|------|--------|
| 9 | Enterprise SSO (SAML 2.0) | TODO |
| 10 | Hypothesis-driven threat hunting | TODO |
| 11 | Visual playbook builder | TODO |
