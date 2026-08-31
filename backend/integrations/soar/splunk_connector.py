"""Splunk SOAR connector (placeholder — requires splunk-sdk)."""
from .base import BaseSOARConnector, SOARIncident


class SplunkSOARConnector(BaseSOARConnector):
    platform_name = "splunk_soar"

    async def create_incident(self, alert_data: dict) -> SOARIncident:
        return SOARIncident(platform="splunk_soar")

    async def update_incident(self, incident_id: str, updates: dict) -> bool:
        return False

    async def add_note(self, incident_id: str, note: str) -> bool:
        return False

    async def test_connection(self) -> bool:
        return False
