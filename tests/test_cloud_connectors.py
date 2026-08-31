"""Tests for cloud provider connectors."""
import pytest
from backend.integrations.cloud.aws_connector import AWSConnector
from backend.integrations.cloud.azure_connector import AzureConnector
from backend.integrations.cloud.gcp_connector import GCPConnector


@pytest.mark.asyncio
async def test_aws_stub():
    c = AWSConnector({})
    assert c.provider_name == "aws"
    assert await c.test_connection() is False
    events = await c.fetch_events("2026-01-01")
    assert events == []


@pytest.mark.asyncio
async def test_azure_stub():
    c = AzureConnector({})
    assert c.provider_name == "azure"
    assert await c.test_connection() is False


@pytest.mark.asyncio
async def test_gcp_stub():
    c = GCPConnector({})
    assert c.provider_name == "gcp"
    assert await c.test_connection() is False
