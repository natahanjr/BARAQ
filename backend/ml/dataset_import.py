"""External dataset import service for BARAQ ML training.

Downloads, parses, and loads external SOC datasets (BOTSv1, BOTES,
Security-Datasets) into the BARAQ NormalizedEvent table for ML training.

Features:
- GitHub API integration for dataset download
- Progress tracking via background task status
- Deduplication via fingerprinting
- Label propagation to Verdict table
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, Verdict, utcnow
from backend.ml.dataset_adapters import ADAPTERS, AdapterResult

log = logging.getLogger("ml.dataset_import")

# GitHub API base
_GITHUB_API = "https://api.github.com/repos"

# Dataset source definitions
DATASET_SOURCES = {
    "security_datasets": {
        "name": "OTRF Security-Datasets",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "description": "Pre-labeled attack/benign datasets with MITRE ATT&CK mappings (APT29, Turla,credential access, lateral movement, etc.)",
        "format": "OCSF JSON/Zeek",
        "adapter": "security_datasets",
        "download_mode": "api_files",  # Use GitHub API to list & download individual files
        "max_file_size_mb": 50,  # Skip files larger than 50MB
    },
    "security_datasets_atomic": {
        "name": "OTRF Security-Datasets (Atomic)",
        "repo": "OTRF/Security-Datasets",
        "branch": "master",
        "description": "Atomic attack scenarios — individual technique-level JSON datasets",
        "format": "OCSF JSON",
        "adapter": "security_datasets",
        "download_mode": "api_files",
        "path_filter": "datasets/atomic/",
        "max_file_size_mb": 50,
    },
}


class ImportStatus(str, Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    PARSING = "parsing"
    LOADING = "loading"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ImportTask:
    """Tracks the state of a dataset import operation."""

    task_id: str
    dataset: str
    status: ImportStatus = ImportStatus.PENDING
    progress: float = 0.0
    total_events: int = 0
    loaded_events: int = 0
    skipped_events: int = 0
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    completed_at: datetime | None = None
    error_message: str = ""
    max_events: int = 0
    downloaded_path: str = ""


class ImportManager:
    """Manages background dataset import tasks."""

    def __init__(self) -> None:
        self._tasks: dict[str, ImportTask] = {}
        self._lock = threading.Lock()

    def list_sources(self) -> list[dict]:
        """List available dataset sources."""
        result = []
        for key, src in DATASET_SOURCES.items():
            result.append(
                {
                    "id": key,
                    "name": src["name"],
                    "repo": src["repo"],
                    "description": src["description"],
                    "format": src["format"],
                }
            )
        return result

    def start_import(
        self, dataset: str, *, max_events: int = 0, github_token: str = ""
    ) -> ImportTask:
        """Start a background import task for a dataset."""
        if dataset not in DATASET_SOURCES:
            raise ValueError(
                f"Unknown dataset: {dataset}. Available: {list(DATASET_SOURCES.keys())}"
            )

        task_id = f"{dataset}_{int(time.time())}"
        task = ImportTask(task_id=task_id, dataset=dataset, max_events=max_events)

        with self._lock:
            self._tasks[task_id] = task

        thread = threading.Thread(
            target=self._run_import, args=(task, github_token), daemon=True
        )
        thread.start()
        return task

    def get_task(self, task_id: str) -> ImportTask | None:
        return self._tasks.get(task_id)

    def list_tasks(self) -> list[ImportTask]:
        return list(self._tasks.values())

    def cancel_task(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if task and task.status in (
            ImportStatus.PENDING,
            ImportStatus.DOWNLOADING,
            ImportStatus.PARSING,
        ):
            task.status = ImportStatus.CANCELLED
            return True
        return False

    def _run_import(self, task: ImportTask, github_token: str) -> None:
        """Execute the full import pipeline in a background thread."""
        try:
            self._do_import(task, github_token)
        except Exception as exc:
            task.status = ImportStatus.FAILED
            task.error_message = str(exc)
            task.completed_at = utcnow()
            log.exception("Import failed for %s", task.dataset)

    def _do_import(self, task: ImportTask, github_token: str) -> None:
        """Full import pipeline: download → parse → load."""
        src = DATASET_SOURCES[task.dataset]
        adapter_cls = ADAPTERS[src["adapter"]]

        # Phase 1: Download
        task.status = ImportStatus.DOWNLOADING
        task.progress = 0.0
        tmp_dir = Path(tempfile.mkdtemp(prefix="baraq_import_"))
        try:
            zip_path = self._download_github_repo(
                src["repo"], tmp_dir, github_token, task,
                branch=src.get("branch", "main"),
                download_mode=src.get("download_mode", "zip"),
                path_filter=src.get("path_filter", ""),
                max_file_size_mb=src.get("max_file_size_mb", 50),
            )
            task.downloaded_path = str(zip_path)

            # Phase 2: Parse
            task.status = ImportStatus.PARSING
            task.progress = 0.0
            adapter = adapter_cls()
            result = adapter.load(zip_path, max_events=task.max_events)
            task.total_events = result["total"]
            task.loaded_events = result["loaded"]
            task.skipped_events = result["skipped"]
            task.errors = result["errors"]

            if not result["events"]:
                task.status = ImportStatus.COMPLETED
                task.progress = 1.0
                task.completed_at = utcnow()
                return

            # Phase 3: Load into database
            task.status = ImportStatus.LOADING
            task.progress = 0.0
            self._load_events_to_db(task, result["events"])

            task.status = ImportStatus.COMPLETED
            task.progress = 1.0
            task.completed_at = utcnow()

        finally:
            # Cleanup temp files
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

    def _download_github_repo(
        self,
        repo: str,
        dest: Path,
        token: str,
        task: ImportTask,
        *,
        branch: str = "main",
        download_mode: str = "zip",
        path_filter: str = "",
        max_file_size_mb: int = 50,
    ) -> Path:
        """Download data from a GitHub repository.

        download_mode='zip' downloads the full repo archive (small repos).
        download_mode='api_files' uses the GitHub Trees API to list files
        and downloads individual data files (for large repos).
        """
        import urllib.error
        import urllib.request

        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        if download_mode == "api_files":
            return self._download_via_api(
                repo, branch, dest, token, task,
                path_filter=path_filter, max_file_size_mb=max_file_size_mb,
            )

        # ZIP mode: try main then master
        for br in [branch, "main", "master"]:
            zip_url = f"https://github.com/{repo}/archive/refs/heads/{br}.zip"
            zip_path = dest / "dataset.zip"
            try:
                req = urllib.request.Request(zip_url, headers=headers)
                with urllib.request.urlopen(req, timeout=120) as resp:
                    total = int(resp.headers.get("Content-Length", 0))
                    downloaded = 0
                    with open(zip_path, "wb") as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                task.progress = min(0.4, (downloaded / total) * 0.4)
                return zip_path
            except urllib.error.HTTPError:
                continue
            except Exception as exc:
                log.warning("Download failed from %s: %s", zip_url, exc)
                continue

        raise RuntimeError(f"Failed to download {repo} from GitHub")

    def _download_via_api(
        self,
        repo: str,
        branch: str,
        dest: Path,
        token: str,
        task: ImportTask,
        *,
        path_filter: str = "",
        max_file_size_mb: int = 50,
    ) -> Path:
        """Download individual files from a GitHub repo via the Trees API."""
        import urllib.error
        import urllib.request
        import json as _json

        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        # Get file tree
        tree_url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
        req = urllib.request.Request(tree_url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            tree_data = _json.loads(resp.read())

        tree = tree_data.get("tree", [])
        data_exts = (".json", ".jsonl", ".csv", ".log")
        candidates = []
        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")
            if not any(path.endswith(ext) for ext in data_exts):
                continue
            if path_filter and not path.startswith(path_filter):
                continue
            size_mb = item.get("size", 0) / (1024 * 1024)
            if size_mb > max_file_size_mb:
                continue
            candidates.append(item)

        # Sort by size (smallest first for fast feedback)
        candidates.sort(key=lambda x: x.get("size", 0))

        if not candidates:
            raise RuntimeError(f"No data files found in {repo} matching filter '{path_filter}'")

        downloaded_dir = dest / "files"
        downloaded_dir.mkdir(exist_ok=True)
        total_files = len(candidates)

        for idx, item in enumerate(candidates):
            path = item["path"]
            raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
            local_path = downloaded_dir / Path(path).name

            try:
                req = urllib.request.Request(raw_url, headers=headers)
                with urllib.request.urlopen(req, timeout=60) as resp:
                    with open(local_path, "wb") as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)
                task.progress = 0.4 * ((idx + 1) / total_files)
            except Exception as exc:
                log.warning("Failed to download %s: %s", path, exc)
                continue

        return downloaded_dir

    def _load_events_to_db(self, task: ImportTask, events: list) -> None:
        """Insert parsed events into NormalizedEvent table."""
        session = SessionLocal()
        try:
            loaded = 0
            total = len(events)
            batch_size = 500

            for i in range(0, total, batch_size):
                if task.status == ImportStatus.CANCELLED:
                    break

                batch = events[i : i + batch_size]
                for event_dict in batch:
                    try:
                        self._insert_event(session, event_dict)
                        loaded += 1
                    except Exception as exc:
                        task.errors.append(f"insert: {exc}")

                session.commit()
                task.loaded_events = loaded
                task.progress = 0.4 + 0.6 * (loaded / max(total, 1))

            task.loaded_events = loaded

        finally:
            session.close()

    def _insert_event(self, session, event: dict) -> None:
        """Insert a single normalized event dict into the database."""
        ts_raw = event.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                ts = utcnow()
        elif isinstance(ts_raw, datetime):
            ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=UTC)
        else:
            ts = utcnow()

        facts = event.get("raw", {})
        eid = int(event.get("event_id", 0))

        raw_json = {
            "facts": facts,
            "channel": event.get("channel", ""),
            "source": event.get("source", "external_dataset"),
            "external_dataset": True,
        }

        # Classify category
        source = event.get("source", "other")
        category_map = {
            "login": "Login",
            "process": "Process",
            "network": "Network",
            "powershell": "PowerShell",
            "other": "Other",
        }
        category = category_map.get(source, "Other")

        # Risk classification
        label = event.get("label", 0)
        risk = "High" if label == 1 else "Low"

        evt = NormalizedEvent(
            event_id=eid,
            category=category,
            source="external_dataset",
            user=event.get("user", "-"),
            host=event.get("host", "-"),
            org="",
            demo=False,
            risk=risk,
            severity="high" if label == 1 else "info",
            message=event.get("message", "")[:1024],
            timestamp=ts,
            data_integrity="complete",
            raw_json=raw_json,
            is_anomaly=bool(label),
            ml_score=None,
            risk_score=1.0 if label == 1 else 0.0,
        )
        session.add(evt)
        session.flush()

        # Create verdict if labeled
        if label is not None:
            verdict = Verdict(
                event_id=evt.id,
                verdict="true_positive" if label == 1 else "false_positive",
                created_by="external_dataset",
                created_at=utcnow(),
            )
            session.add(verdict)


# Singleton manager
import_manager = ImportManager()
