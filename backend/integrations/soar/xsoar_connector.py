"""Cortex XSOAR connector (requires demisto-sdk).

Configure via:
  BARAQ_XSOAR_URL=https://xsoar.example.com
  BARAQ_XSOAR_API_KEY=your-api-key
"""

from __future__ import annotations

import logging
import os

from .base import BaseSOARConnector, SOARIncident

logger = logging.getLogger("baraq.integrations.soar.xsoar")

_NOT_IMPLEMENTED_MSG = (
    "Cortex XSOAR integration requires demisto-sdk. "
    "Install with: pip install demisto-sdk  "
    "and set BARAQ_XSOAR_URL + BARAQ_XSOAR_API_KEY in .env"
)


class XSOARConnector(BaseSOARConnector):
    platform_name = "xsoar"

    def __init__(self, config: dict):
        super().__init__(config)
        self.url = config.get("url") or os.getenv("BARAQ_XSOAR_URL", "")
        self.api_key = config.get("api_key") or os.getenv("BARAQ_XSOAR_API_KEY", "")

    async def create_incident(self, alert_data: dict) -> SOARIncident:
        if not self.url or not self.api_key:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def update_incident(self, incident_id: str, updates: dict) -> bool:
        if not self.url or not self.api_key:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def add_note(self, incident_id: str, note: str) -> bool:
        if not self.url or not self.api_key:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def test_connection(self) -> bool:
        if not self.url or not self.api_key:
            logger.warning("XSOAR not configured: set BARAQ_XSOAR_URL and BARAQ_XSOAR_API_KEY")
            return False
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
