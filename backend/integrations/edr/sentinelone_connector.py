"""SentinelOne connector (requires sentinelone-api-client).

Configure via:
  BARAQ_SENTINELONE_URL=https://usea1.sentinelone.net
  BARAQ_SENTINELONE_API_TOKEN=your-api-token
"""

from __future__ import annotations

import logging
import os

from .base import BaseEDRConnector, EDRAlert

logger = logging.getLogger("baraq.integrations.edr.sentinelone")

_NOT_IMPLEMENTED_MSG = (
    "SentinelOne integration requires sentinelone-api-client. "
    "Install with: pip install sentinelone-api-client  "
    "and set BARAQ_SENTINELONE_URL + BARAQ_SENTINELONE_API_TOKEN in .env"
)


class SentinelOneConnector(BaseEDRConnector):
    platform_name = "sentinelone"

    def __init__(self, config: dict):
        super().__init__(config)
        self.url = config.get("url") or os.getenv("BARAQ_SENTINELONE_URL", "")
        self.api_token = config.get("api_token") or os.getenv("BARAQ_SENTINELONE_API_TOKEN", "")

    async def fetch_alerts(self, since: str, limit: int = 100) -> list[EDRAlert]:
        if not self.url or not self.api_token:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def get_host_info(self, host_id: str) -> dict:
        if not self.url or not self.api_token:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def isolate_host(self, host_id: str) -> bool:
        if not self.url or not self.api_token:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def test_connection(self) -> bool:
        if not self.url or not self.api_token:
            logger.warning("SentinelOne not configured: set BARAQ_SENTINELONE_URL and BARAQ_SENTINELONE_API_TOKEN")
            return False
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
