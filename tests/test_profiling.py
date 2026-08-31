"""Tests for BARAQ resource profiling."""
import json
from pathlib import Path
from backend.profiling.resource_profiler import ResourceProfiler


def test_snapshot_returns_dict():
    profiler = ResourceProfiler(output_dir="/tmp/baraq_test_profiling")
    snap = profiler.snapshot("test")
    assert "timestamp" in snap
    assert snap["label"] == "test"
    assert "rss_bytes" in snap


def test_report_empty():
    profiler = ResourceProfiler(output_dir="/tmp/baraq_test_profiling")
    report = profiler.report()
    assert report["total_snapshots"] == 0


def test_report_with_snapshots():
    profiler = ResourceProfiler(output_dir="/tmp/baraq_test_profiling")
    profiler.snapshot("a")
    profiler.snapshot("b")
    report = profiler.report()
    assert report["total_snapshots"] == 2
    assert report["peak_rss_bytes"] is not None


def test_save_report():
    profiler = ResourceProfiler(output_dir="/tmp/baraq_test_profiling")
    profiler.snapshot("test_save")
    path = profiler.save_report("test_report.json")
    assert Path(path).exists()
    data = json.loads(Path(path).read_text())
    assert data["total_snapshots"] == 1
