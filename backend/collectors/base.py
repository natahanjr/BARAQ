"""Collector base classes."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime

logger = logging.getLogger("baraq.collectors")


class BaseCollector(ABC):
    """Common interface for all BARAQ data collectors."""

    name: str = "base"

    def __init__(self):
        self.logger = logging.getLogger(f"baraq.collectors.{self.name}")

    @abstractmethod
    def collect(self) -> list[dict]:
        """Collect a batch of raw records and return them as dicts."""

    def enabled(self) -> bool:
        return True

    def _stamp(self) -> str:
        return datetime.now(UTC).isoformat()
