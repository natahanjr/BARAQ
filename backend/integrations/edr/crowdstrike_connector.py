"""CrowdStrike Falcon connector (requires falconpy).

Configure via:
  BARAQ_CROWDSTRIKE_CLIENT_ID=your-client-id
  BARAQ_CROWDSTRIKE_CLIENT_SECRET=your-client-secret
"""

from __future__ import annotations

import logging
import os

from .base import BaseEDRConnector, EDRAlert

logger = logging.getLogger("baraq.integrations.edr.crowdstrike")

_NOT_IMPLEMENTED_MSG = (
    "CrowdStrike integration requires falconpy. "
    "Install with: pip install falconpy  "
    "and set BARAQ_CROWDSTRIKE_CLIENT_ID + BARAQ_CROWDSTRIKE_CLIENT_SECRET in .env"
)


class CrowdStrikeConnector(BaseEDRConnector):
    platform_name = "crowdstrike"

    def __init__(self, config: dict):
        super().__init__(config)
        self.client_id = config.get("client_id") or os.getenv("BARAQ_CROWDSTRIKE_CLIENT_ID", "")
        self.client_secret = config.get("client_secret") or os.getenv("BARAQ_CROWDSTRIKE_CLIENT_SECRET", "")

    async def fetch_alerts(self, since: str, limit: int = 100) -> list[EDRAlert]:
        if not self.client_id or not self.client_secret:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def get_host_info(self, host_id: str) -> dict:
        if not self.client_id or not self.client_secret:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def isolate_host(self, host_id: str) -> bool:
        if not self.client_id or not self.client_secret:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def test_connection(self) -> bool:
        if not self.client_id or not self.client_secret:
            logger.warning("CrowdStrike not configured: set BARAQ_CROWDSTRIKE_CLIENT_ID and BARAQ_CROWDSTRIKE_CLIENT_SECRET")
            return False
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
