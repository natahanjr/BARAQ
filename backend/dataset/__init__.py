"""Research dataset collector.

Consumes the existing BARAQ telemetry pipeline (never duplicates
ingestion logic), stores compact research records with deterministic
fingerprints, and exports them to checksummed CSV part files with a
configurable 100k-events-per-file boundary up to a 1M-event target.

    telemetry -> Normalizer -> NormalizedEvent (existing pipeline)
                                         |
                                         v
                               Dataset Collector (this package)
                                         |
                                         v
                          CSV export (streamed, sha256, manifest)
"""

from .collector import active_collection, sweep
from .exporter import export_all_pending, export_pending
from .service import (
    export_detail,
    export_now,
    exports,
    manifest,
    pause,
    resume,
    start,
    stats,
    status,
    update_config,
)
from .scheduler import dataset_maybe_export, dataset_sweep

__all__ = [
    "active_collection",
    "sweep",
    "export_pending",
    "export_all_pending",
    "status",
    "start",
    "pause",
    "resume",
    "export_now",
    "stats",
    "exports",
    "export_detail",
    "manifest",
    "update_config",
    "dataset_sweep",
    "dataset_maybe_export",
]