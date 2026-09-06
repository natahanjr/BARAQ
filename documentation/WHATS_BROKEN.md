# BARAQ — What's Broken Report

**Audited:** 2026-09-04
**Status:** 2 CRITICAL bugs · 1 BLOCKED service · Multiple non-critical issues

---

## CRITICAL — Runtime Bugs (2)

These cause immediate failures when the code runs.

### 1. Undefined name `text` in `check_database_health()`
**File:** `backend/database/connection.py:459`
```python
db.execute(text("SELECT 1"))   # "text" is not imported
```
**Impact:** `/api/system/health` endpoint crashes with `NameError`
**Fix:** Add `text` to the module-level import on line 12:
```python
from sqlalchemy import create_engine, event, inspect, text
```

---

### 2. Undefined name `MAX_REQUEST_BYTES` in exception handler
**File:** `backend/main.py:1061`
```python
@app.exception_handler(_BodyTooLargeError)
async def _body_too_large_handler(request, exc):
    return JSONResponse(
        {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},  # undefined
        status_code=413,
    )
```
`MAX_REQUEST_BYTES` is only imported inside `_body_size_guard()` function (line 1019), but the exception handler is at module level and can't see it.

**Impact:** Any 413 error will crash with `NameError`
**Fix:** Move the import to module level or import it in the handler:
```python
async def _body_too_large_handler(request, exc):
    from backend.config import MAX_REQUEST_BYTES
    return JSONResponse(
        {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},
        status_code=413,
    )
```

---

## BLOCKING — Cannot Run (1)

### 3. PostgreSQL Service Stopped
**Service:** `SentinelSOC-PostgreSQL`
**Status:** Stopped
**Impact:** All 1,921 tests fail with `connection timeout expired`. The app cannot start.
**Fix:** Start the service:
```powershell
Start-Service SentinelSOC-PostgreSQL
```

---

## NON-CRITICAL — Lint/Type Issues

### mypy — 393 errors
```bash
mypy backend --ignore-missing-imports 2>&1 | findstr "error:"
```
Mostly type annotation issues (e.g., `Pattern[str] | None` vs `Pattern[str]`).

### ruff — 5,773 issues
| Code | Meaning | Count | Critical |
|------|---------|-------|----------|
| F401 | Unused import | ~100 | No |
| F821 | **Undefined name** | **2** | **YES** |
| F841 | Unused variable | ~10 | No |
| E722 | Bare except | ~5 | Low |
| I001 | Import unsorted | ~many | No |

The 2 F821 errors are the critical ones listed above.

### FastAPIDeprecationWarning
**File:** `backend/api/export.py:157`
```python
format: str = Query("csv", regex="^(csv|json)$"),   # deprecated "regex"
# Should be:
format: str = Query("csv", pattern="^(csv|json)$"),
```

### StarletteDeprecationWarning
All test files use `from starlette.testclient import TestClient` which is deprecated in favor of `httpx2`.

---

## Summary Table

| # | Severity | Issue | File | Line |
|---|----------|-------|------|------|
| 1 | 🔴 CRITICAL | `text` undefined | `backend/database/connection.py` | 459 |
| 2 | 🔴 CRITICAL | `MAX_REQUEST_BYTES` undefined | `backend/main.py` | 1061 |
| 3 | 🟠 BLOCKED | PostgreSQL service stopped | Windows Services | — |
| 4 | 🟡 WARN | FastAPI deprecated `regex=` | `backend/api/export.py` | 157 |
| 5 | 🟡 WARN | starlette TestClient deprecated | All test files | — |
| 6 | 🟢 INFO | 393 mypy type errors | backend/ | Multiple |
| 7 | 🟢 INFO | 5,773 ruff warnings | Multiple | — |

---

## Quick Fix Commands

```powershell
# 1. Start PostgreSQL
Start-Service SentinelSOC-PostgreSQL

# 2. Fix undefined 'text' in connection.py
# Add 'text' to the import on line 12 of backend/database/connection.py

# 3. Fix undefined MAX_REQUEST_BYTES in main.py
# Either move the import to module level or add import inside the handler
```
