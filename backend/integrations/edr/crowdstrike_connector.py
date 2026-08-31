"""CrowdStrike Falcon connector (placeholder — requires falconpy)."""
from .base import BaseEDRConnector, EDRAlert


class CrowdStrikeConnector(BaseEDRConnector):
    platform_name = "crowdstrike"

    async def fetch_alerts(self, since: str, limit: int = 100) -> list[EDRAlert]:
        return []

    async def get_host_info(self, host_id: str) -> dict:
        return {}

    async def isolate_host(self, host_id: str) -> bool:
        return False

    async def test_connection(self) -> bool:
        return False
