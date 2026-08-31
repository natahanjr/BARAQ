"""Tests for benchmarks."""
from backend.profiling.benchmarks import ThroughputBenchmark, BenchmarkResult


def test_ingestion_benchmark():
    bench = ThroughputBenchmark(output_dir="/tmp/baraq_bench_test")
    counter = [0]
    def fake_ingest():
        counter[0] += 1
    results = bench.measure_ingestion(fake_ingest, event_counts=[10, 20])
    assert len(results) == 2
    assert results[0].operations == 10
    assert results[0].ops_per_sec > 0


def test_report():
    bench = ThroughputBenchmark(output_dir="/tmp/baraq_bench_test")
    def noop(): pass
    bench.measure_ingestion(noop, event_counts=[5])
    report = bench.report()
    assert report["total_benchmarks"] == 1
