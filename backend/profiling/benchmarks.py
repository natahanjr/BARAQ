"""Ingestion throughput and API latency benchmarks."""
import time
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path
from pydantic import BaseModel

logger = logging.getLogger("baraq.benchmarks")


class BenchmarkResult(BaseModel):
    name: str
    duration_s: float
    operations: int
    ops_per_sec: float
    p50_ms: float = 0
    p95_ms: float = 0
    p99_ms: float = 0
    max_ms: float = 0
    timestamp: str = ""


class ThroughputBenchmark:
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or "benchmark_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._results: list[BenchmarkResult] = []

    def measure_ingestion(self, func, event_counts: list[int] = None) -> list[BenchmarkResult]:
        counts = event_counts or [100, 500, 1000, 5000]
        results = []
        for count in counts:
            latencies = []
            start = time.perf_counter()
            for _ in range(count):
                op_start = time.perf_counter()
                func()
                op_end = time.perf_counter()
                latencies.append((op_end - op_start) * 1000)
            elapsed = time.perf_counter() - start
            latencies.sort()
            n = len(latencies)
            result = BenchmarkResult(
                name=f"ingestion_{count}_events",
                duration_s=round(elapsed, 4),
                operations=count,
                ops_per_sec=round(count / max(elapsed, 0.001), 1),
                p50_ms=round(latencies[n // 2], 3),
                p95_ms=round(latencies[int(n * 0.95)], 3),
                p99_ms=round(latencies[int(n * 0.99)], 3),
                max_ms=round(latencies[-1], 3),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            results.append(result)
            self._results.append(result)
        return results

    def measure_api_latency(self, client, endpoints: list[dict]) -> list[BenchmarkResult]:
        results = []
        for ep in endpoints:
            method = ep.get("method", "GET")
            url = ep.get("url", "/")
            iterations = ep.get("iterations", 50)
            latencies = []
            for _ in range(iterations):
                start = time.perf_counter()
                try:
                    if method == "GET":
                        client.get(url)
                    else:
                        client.post(url, json=ep.get("body", {}))
                except Exception:
                    pass
                elapsed = (time.perf_counter() - start) * 1000
                latencies.append(elapsed)
            latencies.sort()
            n = len(latencies)
            result = BenchmarkResult(
                name=f"api_{method}_{url.replace('/', '_')}",
                duration_s=round(sum(latencies) / 1000, 4),
                operations=iterations,
                ops_per_sec=round(iterations / max(sum(latencies) / 1000, 0.001), 1),
                p50_ms=round(latencies[n // 2], 3) if n else 0,
                p95_ms=round(latencies[int(n * 0.95)], 3) if n else 0,
                p99_ms=round(latencies[int(n * 0.99)], 3) if n else 0,
                max_ms=round(latencies[-1], 3) if n else 0,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            results.append(result)
            self._results.append(result)
        return results

    def report(self) -> dict:
        return {
            "total_benchmarks": len(self._results),
            "results": [r.model_dump() for r in self._results],
        }

    def save_report(self, filename: Optional[str] = None) -> str:
        report = self.report()
        fname = filename or f"benchmark_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        path = self.output_dir / fname
        path.write_text(json.dumps(report, indent=2, default=str))
        return str(path)
