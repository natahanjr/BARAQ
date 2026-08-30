"""Ticketing integrations (roadmap 6.3): Jira, ServiceNow, and the BARAQ SDK.

* ``backend/integrations/client.py`` - outbound dispatch of alerts to Jira
  (REST v2) and ServiceNow (table API) with per-channel health tracking.
* ``backend/integrations/sdk.py`` - ``BARAQClient``: the official Python SDK
  for external tooling (SOAR playbooks, cron jobs, third-party consoles) to
  query alerts/incidents, take actions and dispatch tickets.
"""

from backend.integrations.client import (  # noqa: F401
    dispatch_alert,
    integration_health,
    integration_status,
)
