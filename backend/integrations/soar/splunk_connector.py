"""Splunk SOAR connector (requires splunk-sdk).

Configure via:
  BARAQ_SPLUNK_SOAR_URL=https://soar.splunk.example.com
  BARAQ_SPLUNK_SOAR_API_KEY=your-api-key
"""

from __future__ import annotations

import logging
import os

from .base import BaseSOARConnector, SOARIncident

logger = logging.getLogger("baraq.integrations.soar.splunk")

_NOT_IMPLEMENTED_MSG = (
    "Splunk SOAR integration requires splunk-sdk. "
    "Install with: pip install splunk-sdk  "
    "and set BARAQ_SPLUNK_SOAR_URL + BARAQ_SPLUNK_SOAR_API_KEY in .env"
)


class SplunkSOARConnector(BaseSOARConnector):
    platform_name = "splunk_soar"

    def __init__(self, config: dict):
        super().__init__(config)
        self.url = config.get("url") or os.getenv("BARAQ_SPLUNK_SOAR_URL", "")
        self.api_key = config.get("api_key") or os.getenv("BARAQ_SPLUNK_SOAR_API_KEY", "")

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
            logger.warning("Splunk SOAR not configured: set BARAQ_SPLUNK_SOAR_URL and BARAQ_SPLUNK_SOAR_API_KEY")
            return False
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
