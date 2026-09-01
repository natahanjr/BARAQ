"""ML training data retention, archival, and dashboard configuration.

Manages ML training data lifecycle:
- Retention policies (how long to keep training data)
- Data archival (compress old training sets for long-term storage)
- Dashboard configuration for ML data visibility
- Storage metrics and health monitoring
"""

from __future__ import annotations

import json
import logging
import shutil
import time
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

logger = logging.getLogger("baraq.ml.retention")


@dataclass
class RetentionPolicy:
    """Configuration for ML training data retention."""
    max_age_days: int = 90
    max_versions: int = 10
    archive_after_days: int = 30
    delete_archived_after_days: int = 365
    min_samples_per_version: int = 100
    auto_prune: bool = True


@dataclass
class ArchiveEntry:
    """Metadata for an archived training data version."""
    version: int
    archived_at: str
    original_size_bytes: int
    compressed_size_bytes: int
    n_samples: int
    streams: list[str] = field(default_factory=list)
    checksum: str = ""


class MLDataRetention:
    """Manages ML training data retention, archival, and dashboard config."""

    def __init__(
        self,
        model_dir: str | Path,
        archive_dir: str | Path | None = None,
        policy: RetentionPolicy | None = None,
    ):
        self.model_dir = Path(model_dir)
        self.archive_dir = Path(archive_dir) if archive_dir else self.model_dir / "archives"
        self.policy = policy or RetentionPolicy()
        self._archive_index: list[ArchiveEntry] = []
        self._load_archive_index()

    def _load_archive_index(self):
        """Load archive index from disk."""
        index_path = self.archive_dir / "_archive_index.json"
        if index_path.exists():
            try:
                data = json.loads(index_path.read_text(encoding="utf-8"))
                self._archive_index = [ArchiveEntry(**e) for e in data]
            except Exception:
                self._archive_index = []

    def _save_archive_index(self):
        """Persist archive index to disk."""
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        index_path = self.archive_dir / "_archive_index.json"
        data = [
            {
                "version": e.version,
                "archived_at": e.archived_at,
                "original_size_bytes": e.original_size_bytes,
                "compressed_size_bytes": e.compressed_size_bytes,
                "n_samples": e.n_samples,
                "streams": e.streams,
                "checksum": e.checksum,
            }
            for e in self._archive_index
        ]
        index_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def archive_version(
        self,
        version: int,
        model_data: bytes,
        n_samples: int,
        streams: list[str],
    ) -> ArchiveEntry:
        """Archive a model version with compression."""
        compressed = zlib.compress(model_data, level=6)
        import hashlib
        checksum = hashlib.sha256(compressed).hexdigest()[:16]

        entry = ArchiveEntry(
            version=version,
            archived_at=datetime.now(UTC).isoformat(),
            original_size_bytes=len(model_data),
            compressed_size_bytes=len(compressed),
            n_samples=n_samples,
            streams=streams,
            checksum=checksum,
        )

        # Write compressed data
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        archive_path = self.archive_dir / f"model_v{version}.bin.zst"
        archive_path.write_bytes(compressed)

        self._archive_index.append(entry)
        self._save_archive_index()

        logger.info(
            "Archived model v%d: %d bytes -> %d bytes (%.1f%% compression)",
            version, len(model_data), len(compressed),
            (1 - len(compressed) / max(len(model_data), 1)) * 100,
        )
        return entry

    def restore_version(self, version: int) -> bytes | None:
        """Restore a model version from archive."""
        archive_path = self.archive_dir / f"model_v{version}.bin.zst"
        if not archive_path.exists():
            logger.warning("Archive for v%d not found", version)
            return None

        try:
            compressed = archive_path.read_bytes()
            return zlib.decompress(compressed)
        except Exception as e:
            logger.error("Failed to restore v%d: %s", version, e)
            return None

    def prune_old_versions(self) -> dict:
        """Remove old model versions based on retention policy."""
        if not self.model_dir.exists():
            return {"pruned": 0, "kept": 0}

        model_files = sorted(self.model_dir.glob("model_v*.pkl"), key=lambda p: p.stat().st_mtime)
        archived_files = sorted(self.archive_dir.glob("model_v*.bin.zst"), key=lambda p: p.stat().st_mtime)

        pruned_count = 0
        kept_count = 0

        # Prune non-archived models older than max_versions
        if len(model_files) > self.policy.max_versions:
            to_prune = model_files[: len(model_files) - self.policy.max_versions]
            for f in to_prune:
                f.unlink(missing_ok=True)
                pruned_count += 1

        # Prune archived models older than delete_archived_after_days
        cutoff = datetime.now(UTC) - timedelta(days=self.policy.delete_archived_after_days)
        pruned_archives = []
        for entry in self._archive_index:
            try:
                archived_at = datetime.fromisoformat(entry.archived_at)
                if archived_at < cutoff:
                    archive_path = self.archive_dir / f"model_v{entry.version}.bin.zst"
                    archive_path.unlink(missing_ok=True)
                    pruned_archives.append(entry)
            except Exception:
                continue

        for entry in pruned_archives:
            self._archive_index.remove(entry)

        if pruned_archives:
            self._save_archive_index()

        return {
            "pruned_models": pruned_count,
            "pruned_archives": len(pruned_archives),
            "kept_models": max(0, len(model_files) - pruned_count),
            "kept_archives": len(self._archive_index),
        }

    def get_storage_metrics(self) -> dict:
        """Get storage metrics for ML training data."""
        model_size = 0
        model_count = 0
        if self.model_dir.exists():
            for f in self.model_dir.glob("model_v*.pkl"):
                model_size += f.stat().st_size
                model_count += 1

        archive_size = 0
        archive_count = 0
        if self.archive_dir.exists():
            for f in self.archive_dir.glob("*.bin.zst"):
                archive_size += f.stat().st_size
                archive_count += 1

        total_compressed = sum(e.compressed_size_bytes for e in self._archive_index)
        total_original = sum(e.original_size_bytes for e in self._archive_index)

        return {
            "model_dir": str(self.model_dir),
            "archive_dir": str(self.archive_dir),
            "active_models": model_count,
            "active_model_size_mb": round(model_size / (1024 * 1024), 2),
            "archived_versions": archive_count,
            "archive_size_mb": round(archive_size / (1024 * 1024), 2),
            "total_original_size_mb": round(total_original / (1024 * 1024), 2),
            "compression_ratio": round(total_compressed / max(total_original, 1), 4),
            "retention_policy": {
                "max_age_days": self.policy.max_age_days,
                "max_versions": self.policy.max_versions,
                "archive_after_days": self.policy.archive_after_days,
                "delete_archived_after_days": self.policy.delete_archived_after_days,
            },
        }

    def get_archive_history(self) -> list[dict]:
        """Get history of archived model versions."""
        return [
            {
                "version": e.version,
                "archived_at": e.archived_at,
                "original_size_kb": round(e.original_size_bytes / 1024, 1),
                "compressed_size_kb": round(e.compressed_size_bytes / 1024, 1),
                "n_samples": e.n_samples,
                "streams": e.streams,
                "checksum": e.checksum,
            }
            for e in self._archive_index
        ]


@dataclass
class MLDashboardConfig:
    """Configuration for ML dashboard visibility."""
    show_feature_importance: bool = True
    show_anomaly_scores: bool = True
    show_model_health: bool = True
    show_drift_metrics: bool = True
    show_cv_results: bool = True
    show_ensemble_weights: bool = True
    show_robustness_scores: bool = True
    show_online_learning_stats: bool = True
    score_history_retention_days: int = 30
    max_alerts_displayed: int = 100
    refresh_interval_seconds: int = 60

    def to_dict(self) -> dict:
        return {
            "show_feature_importance": self.show_feature_importance,
            "show_anomaly_scores": self.show_anomaly_scores,
            "show_model_health": self.show_model_health,
            "show_drift_metrics": self.show_drift_metrics,
            "show_cv_results": self.show_cv_results,
            "show_ensemble_weights": self.show_ensemble_weights,
            "show_robustness_scores": self.show_robustness_scores,
            "show_online_learning_stats": self.show_online_learning_stats,
            "score_history_retention_days": self.score_history_retention_days,
            "max_alerts_displayed": self.max_alerts_displayed,
            "refresh_interval_seconds": self.refresh_interval_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict) -> MLDashboardConfig:
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
