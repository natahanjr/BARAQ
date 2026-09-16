"""AWS CloudTrail connector (requires boto3).

Configure via:
  BARAQ_AWS_ACCESS_KEY_ID=your-access-key
  BARAQ_AWS_SECRET_ACCESS_KEY=your-secret-key
  BARAQ_AWS_REGION=us-east-1
"""

from __future__ import annotations

import logging
import os

from .base import BaseCloudConnector, CloudEvent

logger = logging.getLogger("baraq.integrations.cloud.aws")

_NOT_IMPLEMENTED_MSG = (
    "AWS integration requires boto3. "
    "Install with: pip install boto3  "
    "and set BARAQ_AWS_ACCESS_KEY_ID + BARAQ_AWS_SECRET_ACCESS_KEY in .env"
)


class AWSConnector(BaseCloudConnector):
    provider_name = "aws"

    def __init__(self, config: dict):
        super().__init__(config)
        self.access_key = config.get("access_key") or os.getenv("BARAQ_AWS_ACCESS_KEY_ID", "")
        self.secret_key = config.get("secret_key") or os.getenv("BARAQ_AWS_SECRET_ACCESS_KEY", "")
        self.region = config.get("region") or os.getenv("BARAQ_AWS_REGION", "us-east-1")

    async def fetch_events(self, since: str, limit: int = 100) -> list[CloudEvent]:
        if not self.access_key or not self.secret_key:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def test_connection(self) -> bool:
        if not self.access_key or not self.secret_key:
            logger.warning("AWS not configured: set BARAQ_AWS_ACCESS_KEY_ID and BARAQ_AWS_SECRET_ACCESS_KEY")
            return False
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
