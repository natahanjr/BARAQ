"""AWS CloudTrail connector (placeholder — requires boto3)."""
from .base import BaseCloudConnector, CloudEvent


class AWSConnector(BaseCloudConnector):
    provider_name = "aws"

    async def fetch_events(self, since: str, limit: int = 100) -> list[CloudEvent]:
        return []

    async def test_connection(self) -> bool:
        return False
