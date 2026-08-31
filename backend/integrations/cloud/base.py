"""Base cloud provider connector."""
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel


class CloudEvent(BaseModel):
    provider: str
    event_type: str
    resource: str
    region: str = ""
    identity: str = ""
    timestamp: str = ""
    raw: dict = {}


class BaseCloudConnector(ABC):
    provider_name: str = "base"

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    async def fetch_events(self, since: str, limit: int = 100) -> list[CloudEvent]:
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        ...

    def normalize_event(self, raw: dict) -> CloudEvent:
        return CloudEvent(provider=self.provider_name, event_type="unknown", resource="", raw=raw)
