"""Collector base classes."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.collectors")


class BaseCollector(ABC):
    """Common interface for all SentinelSOC data collectors."""

    name: str = "base"

    def __init__(self):
        self.logger = logging.getLogger(f"sentinel.collectors.{self.name}")

    @abstractmethod
    def collect(self) -> list[dict]:
        """Collect a batch of raw records and return them as dicts."""

    def enabled(self) -> bool:
        return True

    def _stamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()
