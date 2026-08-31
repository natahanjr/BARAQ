"""Tests for EDR connectors."""
import pytest
from backend.integrations.edr.crowdstrike_connector import CrowdStrikeConnector
from backend.integrations.edr.sentinelone_connector import SentinelOneConnector


@pytest.mark.asyncio
async def test_crowdstrike_stub():
    c = CrowdStrikeConnector({})
    assert c.platform_name == "crowdstrike"
    assert await c.test_connection() is False
    assert await c.fetch_alerts("2026-01-01") == []


@pytest.mark.asyncio
async def test_sentinelone_stub():
    c = SentinelOneConnector({})
    assert c.platform_name == "sentinelone"
    assert await c.test_connection() is False
