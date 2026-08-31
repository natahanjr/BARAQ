"""GCP Audit Log connector (placeholder — requires google-cloud)."""
from .base import BaseCloudConnector, CloudEvent


class GCPConnector(BaseCloudConnector):
    provider_name = "gcp"

    async def fetch_events(self, since: str, limit: int = 100) -> list[CloudEvent]:
        return []

    async def test_connection(self) -> bool:
        return False
