"""Azure Monitor connector (requires azure-identity + azure-monitor).

Configure via:
  BARAQ_AZURE_CLIENT_ID=your-client-id
  BARAQ_AZURE_CLIENT_SECRET=your-client-secret
  BARAQ_AZURE_TENANT_ID=your-tenant-id
"""

from __future__ import annotations

import logging
import os

from .base import BaseCloudConnector, CloudEvent

logger = logging.getLogger("baraq.integrations.cloud.azure")

_NOT_IMPLEMENTED_MSG = (
    "Azure integration requires azure-identity + azure-monitor-query. "
    "Install with: pip install azure-identity azure-monitor-query  "
    "and set BARAQ_AZURE_CLIENT_ID + BARAQ_AZURE_CLIENT_SECRET + BARAQ_AZURE_TENANT_ID in .env"
)


class AzureConnector(BaseCloudConnector):
    provider_name = "azure"

    def __init__(self, config: dict):
        super().__init__(config)
        self.client_id = config.get("client_id") or os.getenv("BARAQ_AZURE_CLIENT_ID", "")
        self.client_secret = config.get("client_secret") or os.getenv("BARAQ_AZURE_CLIENT_SECRET", "")
        self.tenant_id = config.get("tenant_id") or os.getenv("BARAQ_AZURE_TENANT_ID", "")

    async def fetch_events(self, since: str, limit: int = 100) -> list[CloudEvent]:
        if not self.client_id or not self.client_secret:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def test_connection(self) -> bool:
        if not self.client_id or not self.client_secret:
            logger.warning("Azure not configured: set BARAQ_AZURE_CLIENT_ID, BARAQ_AZURE_CLIENT_SECRET, BARAQ_AZURE_TENANT_ID")
            return False
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
