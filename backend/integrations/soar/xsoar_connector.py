"""Cortex XSOAR connector (placeholder — requires demisto-sdk)."""
from .base import BaseSOARConnector, SOARIncident


class XSOARConnector(BaseSOARConnector):
    platform_name = "xsoar"

    async def create_incident(self, alert_data: dict) -> SOARIncident:
        return SOARIncident(platform="xsoar")

    async def update_incident(self, incident_id: str, updates: dict) -> bool:
        return False

    async def add_note(self, incident_id: str, note: str) -> bool:
        return False

    async def test_connection(self) -> bool:
        return False
