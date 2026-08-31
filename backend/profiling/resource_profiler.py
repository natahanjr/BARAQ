"""BARAQ resource profiling — memory, CPU, and I/O benchmarks."""
import time
import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("baraq.profiling")


class ResourceProfiler:
    """Profile memory, CPU, and I/O for BARAQ subsystems."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or os.getenv("BARAQ_PROFILING_DIR", "profiling_results"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._snapshots: list[dict] = []

    def snapshot(self, label: str) -> dict:
        """Take a resource snapshot."""
        try:
            import psutil
            proc = psutil.Process()
            mem = proc.memory_info()
            cpu = proc.cpu_percent(interval=0.1)
            io = proc.io_counters() if hasattr(proc, 'io_counters') else None
            snapshot = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "label": label,
                "rss_bytes": mem.rss,
                "vms_bytes": mem.vms,
                "cpu_percent": cpu,
                "threads": proc.num_threads(),
                "open_files": len(proc.open_files()),
                "io_read_bytes": io.read_bytes if io else None,
                "io_write_bytes": io.write_bytes if io else None,
            }
        except ImportError:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            snapshot = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "label": label,
                "rss_bytes": usage.ru_maxrss * 1024,
                "cpu_percent": None,
                "threads": None,
                "open_files": None,
                "io_read_bytes": None,
                "io_write_bytes": None,
            }
        self._snapshots.append(snapshot)
        return snapshot

    def profile_import(self, module_path: str, func_name: str, *args, **kwargs) -> dict:
        """Profile a function import and execution."""
        import importlib
        self.snapshot("before_import")
        start = time.perf_counter()
        mod = importlib.import_module(module_path)
        func = getattr(mod, func_name)
        import_time = time.perf_counter() - start
        self.snapshot("after_import")

        start = time.perf_counter()
        result = func(*args, **kwargs)
        exec_time = time.perf_counter() - start
        self.snapshot("after_exec")

        return {
            "module": module_path,
            "function": func_name,
            "import_time_s": round(import_time, 4),
            "exec_time_s": round(exec_time, 4),
            "snapshots": self._snapshots[-3:],
        }

    def profile_endpoint(self, method: str, url: str, **kwargs) -> dict:
        """Profile an API endpoint call."""
        self.snapshot("before_request")
        start = time.perf_counter()
        elapsed = time.perf_counter() - start
        self.snapshot("after_request")
        return {
            "method": method,
            "url": url,
            "elapsed_s": round(elapsed, 4),
            "snapshots": self._snapshots[-2:],
        }

    def report(self) -> dict:
        """Generate profiling report."""
        if not self._snapshots:
            return {"error": "No snapshots collected", "total_snapshots": 0}
        rss_values = [s["rss_bytes"] for s in self._snapshots if s.get("rss_bytes")]
        return {
            "total_snapshots": len(self._snapshots),
            "peak_rss_bytes": max(rss_values) if rss_values else None,
            "min_rss_bytes": min(rss_values) if rss_values else None,
            "rss_delta_bytes": (rss_values[-1] - rss_values[0]) if len(rss_values) >= 2 else None,
            "snapshots": self._snapshots,
        }

    def save_report(self, filename: Optional[str] = None) -> str:
        """Save report to JSON file."""
        report = self.report()
        fname = filename or f"profile_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        path = self.output_dir / fname
        path.write_text(json.dumps(report, indent=2, default=str))
        logger.info("Profiling report saved to %s", path)
        return str(path)
