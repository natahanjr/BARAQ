"""GCP Audit Log connector (requires google-cloud).

Configure via:
  BARAQ_GCP_PROJECT_ID=your-project-id
  BARAQ_GCP_CREDENTIALS_FILE=path/to/service-account.json
"""

from __future__ import annotations

import logging
import os

from .base import BaseCloudConnector, CloudEvent

logger = logging.getLogger("baraq.integrations.cloud.gcp")

_NOT_IMPLEMENTED_MSG = (
    "GCP integration requires google-cloud-logging. "
    "Install with: pip install google-cloud-logging  "
    "and set BARAQ_GCP_PROJECT_ID + BARAQ_GCP_CREDENTIALS_FILE in .env"
)


class GCPConnector(BaseCloudConnector):
    provider_name = "gcp"

    def __init__(self, config: dict):
        super().__init__(config)
        self.project_id = config.get("project_id") or os.getenv("BARAQ_GCP_PROJECT_ID", "")
        self.credentials_file = config.get("credentials_file") or os.getenv("BARAQ_GCP_CREDENTIALS_FILE", "")

    async def fetch_events(self, since: str, limit: int = 100) -> list[CloudEvent]:
        if not self.project_id:
            raise RuntimeError(_NOT_IMPLEMENTED_MSG)
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def test_connection(self) -> bool:
        if not self.project_id:
            logger.warning("GCP not configured: set BARAQ_GCP_PROJECT_ID")
            return False
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
