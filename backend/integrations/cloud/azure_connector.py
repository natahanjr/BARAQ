"""Azure Monitor connector (placeholder — requires azure-identity)."""
from .base import BaseCloudConnector, CloudEvent


class AzureConnector(BaseCloudConnector):
    provider_name = "azure"

    async def fetch_events(self, since: str, limit: int = 100) -> list[CloudEvent]:
        return []

    async def test_connection(self) -> bool:
        return False
