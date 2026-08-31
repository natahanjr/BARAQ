"""Base EDR connector."""
from abc import ABC, abstractmethod
from pydantic import BaseModel


class EDRAlert(BaseModel):
    platform: str
    alert_id: str = ""
    severity: str = ""
    host: str = ""
    user: str = ""
    technique: str = ""
    description: str = ""
    raw: dict = {}


class BaseEDRConnector(ABC):
    platform_name: str = "base"

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    async def fetch_alerts(self, since: str, limit: int = 100) -> list[EDRAlert]:
        ...

    @abstractmethod
    async def get_host_info(self, host_id: str) -> dict:
        ...

    @abstractmethod
    async def isolate_host(self, host_id: str) -> bool:
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        ...
