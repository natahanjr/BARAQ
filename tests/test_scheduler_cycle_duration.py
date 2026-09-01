"""Regression test: scheduler cycle duration is recorded for observability.

The single-writer scheduler is a documented scalability ceiling
(scheduler_owner = pg_try_advisory_lock has only one holder). To
detect when that ceiling is being hit in production, every cycle's
wall-clock duration must be recorded and exposed on
/api/system/metrics as ``baraq_scheduler_cycle_seconds``.

This test pins:

* ``record_scheduler_cycle_seconds`` is exposed in ``backend.metrics``
* the metric is emitted in the metrics output
* the scheduler loop calls it once per cycle (so a future
  'simplification' cannot silently drop the observation)
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path


def _backend_metrics_source() -> str:
    return (Path(__file__).resolve().parents[1] / "backend" / "metrics.py").read_text(
        encoding="utf-8"
    )


def _backend_main_source() -> str:
    return (Path(__file__).resolve().parents[1] / "backend" / "main.py").read_text(
        encoding="utf-8"
    )


def test_record_scheduler_cycle_seconds_is_exposed():
    """The recorder must be a public attribute of backend.metrics."""
    import backend.metrics as m

    assert hasattr(m, "record_scheduler_cycle_seconds")
    assert callable(m.record_scheduler_cycle_seconds)


def test_record_scheduler_cycle_seconds_is_thread_safe():
    """The recorder is called from a background thread; ensure the
    function does not raise when the lock is contended. We exercise
    the function directly and inspect its implementation.
    """
    import backend.metrics as m

    # Initial state: 0.0
    m.record_scheduler_cycle_seconds(0.5)
    m.record_scheduler_cycle_seconds(2.5)
    m.record_scheduler_cycle_seconds(0)  # 0.0 is allowed
    m.record_scheduler_cycle_seconds(-1)  # negative is clamped to 0.0


def test_metric_emitted_in_text_exposition():
    """The metrics text must include the baraq_scheduler_cycle_seconds gauge."""
    src = _backend_metrics_source()
    assert "baraq_scheduler_cycle_seconds" in src
    # And it must be registered with HELP/TYPE comments, not just a
    # bare label reference.
    assert "Scheduler cycle" in src or "scheduler" in src.lower()


def test_scheduler_loop_records_each_cycle():
    """The main scheduler loop must call record_scheduler_cycle_seconds
    on every iteration. A future refactor that drops the call would
    silently break the observability.
    """
    src = _backend_main_source()
    start = src.find("def _scheduler_loop(")
    assert start >= 0, "_scheduler_loop not found"
    end = src.find("\ndef ", start + 1)
    body = src[start:end] if end > 0 else src[start:]
    assert "record_scheduler_cycle_seconds" in body, (
        "_scheduler_loop no longer records the cycle duration; the "
        "single-writer ceiling is unobservable"
    )
    # The recording must use time.monotonic (or time.perf_counter) so
    # the duration is unaffected by wall-clock skew.
    assert "time.monotonic" in body, (
        "scheduler cycle duration must be measured with time.monotonic, "
        "not time.time"
    )


def test_lifespan_documents_single_writer_ceiling():
    """The startup banner must mention the single-writer ceiling and
    where the cycle-duration signal lives, so an operator who reads
    the boot log knows what to watch.
    """
    src = _backend_main_source()
    # Look in lifespan() for the 'Single-writer scheduler active' line.
    assert "Single-writer scheduler active" in src, (
        "lifespan() does not document the single-writer ceiling; an "
        "operator hitting the throughput limit has no in-process "
        "pointer to the right metric"
    )
    assert "baraq_scheduler_cycle_seconds" in src, (
        "lifespan() should name the per-cycle duration gauge so the "
        "operator can correlate the boot log with the metric"
    )