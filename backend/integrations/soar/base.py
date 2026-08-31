"""Base external SOAR connector."""
from abc import ABC, abstractmethod
from pydantic import BaseModel


class SOARIncident(BaseModel):
    platform: str
    incident_id: str = ""
    name: str = ""
    severity: str = ""
    status: str = ""
    alerts: list[dict] = []
    raw: dict = {}


class BaseSOARConnector(ABC):
    platform_name: str = "base"

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    async def create_incident(self, alert_data: dict) -> SOARIncident:
        ...

    @abstractmethod
    async def update_incident(self, incident_id: str, updates: dict) -> bool:
        ...

    @abstractmethod
    async def add_note(self, incident_id: str, note: str) -> bool:
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        ...
