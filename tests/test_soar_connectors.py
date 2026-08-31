"""Tests for external SOAR connectors."""
import pytest
from backend.integrations.soar.xsoar_connector import XSOARConnector
from backend.integrations.soar.splunk_connector import SplunkSOARConnector


@pytest.mark.asyncio
async def test_xsoar_stub():
    c = XSOARConnector({})
    assert c.platform_name == "xsoar"
    assert await c.test_connection() is False


@pytest.mark.asyncio
async def test_splunk_soar_stub():
    c = SplunkSOARConnector({})
    assert c.platform_name == "splunk_soar"
    assert await c.test_connection() is False
