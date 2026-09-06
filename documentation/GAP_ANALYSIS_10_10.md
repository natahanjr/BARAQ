# BARAQ — Gap Analysis: 10/10 Issues

**Audited:** 2026-09-04
**Test collection:** 1,921 tests (previously claimed 1,300+)

---

## ✅ FIXED

| # | Issue | File | Fix |
|---|-------|------|-----|
| — | `e2e_full_test.py` ran live HTTP calls at import time, breaking `pytest --collect-only` | `tests/e2e_full_test.py` | Added `pytest.skip(allow_module_level=True)` guard |

---

## 20 Remaining Gaps

| # | Category | Issue | Location |
|---|----------|-------|----------|
| 1 | Version Mismatch | README says `Python 3.13+`, pyproject.toml says `py312`, Dockerfile uses `python:3.12-slim` | `README.md`, `pyproject.toml:2`, `Dockerfile:23` |
| 2 | Version Mismatch | README says `React 18`, package.json shows `^19.2.8` | `README.md`, `frontend/package.json:13-14` |
| 3 | CI Coverage | CI only runs 3/1,921 tests (`test_ml_v7/v8/p3_enhancements`) | `.github/workflows/python-package.yml:88` |
| 4 | Missing File | No `LICENSE*` file — README and SECURITY.md reference `RAZFORGE-LICENSE` but file doesn't exist | Root directory |
| 5 | CI Config Bug | Duplicate `continue-on-error: true` (lines 45-46) | `.github/workflows/python-package.yml:45-46` |
| 6 | CI Config Bug | `test` job has `needs: lint` but lint uses `continue-on-error: true` — tests run even when lint fails | `.github/workflows/python-package.yml:44-45,65-67` |
| 7 | Documentation | `test_results.md` claims 1,300+ tests; actual collection: 1,921 | `documentation/test_results.md:13-18` |
| 8 | Documentation | `test_results.md` references `tests/test_threat_intel.py` — file doesn't exist | `documentation/test_results.md:38` |
| 9 | Documentation | `test_results.md` references `tests/test_soar.py` — file doesn't exist | `documentation/test_results.md:39` |
| 10 | Attribution | CONTRIBUTORS file has only 1 name for a project of this scope | `CONTRIBUTORS` |
| 11 | Documentation | `SECURITY.md` mentions old branch `feat/v6-phase2-supervised-enhancements` | `SECURITY.md:14` |
| 12 | Documentation | `SECURITY_AUDIT.md` uses `pip_audit` (underscore) — correct command is `pip-audit` (hyphen) | `SECURITY_AUDIT.md:20` |
| 13 | Missing File | `CONTRIBUTING.md` has a Code of Conduct section but no `CODE_OF_CONDUCT.md` file | `CONTRIBUTING.md:21`, root directory |
| 14 | Deprecation | `backend/api/export.py:157` uses deprecated `regex=` Query parameter — should be `pattern=` | `backend/api/export.py:157` |
| 15 | Deprecation Warning | All tests use `from starlette.testclient import TestClient` — Starlette deprecated this in favor of `httpx2` | All test files using `TestClient` |
| 16 | CI/CD | `docker-image` job triggers on tags but no tag/release documentation exists | `.github/workflows/python-package.yml:119-159` |
| 17 | Documentation | `compose.yml` comments reference `roadmap 5.1` and `roadmap 5.2` — roadmap max version is V2.7 | `compose.yml:13-15,406` |
| 18 | Version Mismatch | README says `Node.js 18+`, Dockerfile stage 1 uses `node:20-alpine` | `README.md:20`, `Dockerfile:15` |
| 19 | Documentation | `CHANGELOG.md` claims roadmap items completed that don't match `product_roadmap.md` | `CHANGELOG.md:7-27`, `documentation/product_roadmap.md` |
| 20 | Project State | `documentation/gap_analysis.md` claims all gaps complete with 0 MISSING/PARTIAL, yet TODO section has 11 remaining items | `documentation/gap_analysis.md:5-105` |

---

## Priority Summary

### High (break CI / test collection)
- #3 — CI runs 0.15% of test suite
- #4 — No LICENSE file
- #6 — Tests run on failed lint

### Medium (misleading docs / broken claims)
- #7, #8, #9 — test_results.md references non-existent files
- #19, #20 — CHANGELOG/gap_analysis contradict actual state
- #1, #2, #18 — Version mismatches across docs

### Low (cosmetic / deprecations)
- #5 — duplicate YAML key
- #10 — attribution incomplete
- #11 — stale branch reference
- #12 — wrong pip-audit command
- #13 — missing CODE_OF_CONDUCT
- #14, #15 — deprecated API usage
- #16 — no tag workflow docs
- #17 — stale roadmap references in compose.yml
