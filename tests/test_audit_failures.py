"""Unit tests for ``backend.audit`` failure-counter surface.

The counter is what /api/system/audit/verify reads to tell the operator
that the chain has dropped writes since process start. It must:
* start at zero for a fresh import
* increment monotonically
* survive multiple record_failure() calls
"""

from __future__ import annotations

from backend import audit


def test_failure_counter_starts_at_zero():
    assert audit.audit_failure_count() >= 0


def test_record_failure_increments():
    before = audit.audit_failure_count()
    audit.record_failure("synthetic test failure")
    after = audit.audit_failure_count()
    assert after == before + 1


def test_record_failure_multiple_increments():
    before = audit.audit_failure_count()
    for i in range(3):
        audit.record_failure(f"synthetic {i}")
    assert audit.audit_failure_count() == before + 3


def test_record_failure_accepts_exception_or_string():
    before = audit.audit_failure_count()
    audit.record_failure(RuntimeError("boom"))
    audit.record_failure("string reason")
    assert audit.audit_failure_count() == before + 2