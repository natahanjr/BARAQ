"""Ticketing integrations (roadmap 6.3): Jira + ServiceNow.

Alerts and incidents are pushed to external ticketing systems via the
standard REST APIs. Every outbound call is best-effort and audited through
the notification-health pattern (:class:`IntegrationHealth`), so a dead
ticketing server never breaks the platform. HTTP transport is isolated in
:func:`_post_json` for testability.
"""
from __future__ import annotations

import json
import logging
import urllib.request
from datetime import datetime, timezone

from backend.config import (
    INTEGRATIONS_MIN_SEVERITY,
    JIRA_API_TOKEN,
    JIRA_EMAIL,
    JIRA_ISSUE_TYPE,
    JIRA_PROJECT_KEY,
    JIRA_URL,
    SERVICENOW_INSTANCE,
    SERVICENOW_PASSWORD,
    SERVICENOW_TABLE,
    SERVICENOW_USERNAME,
)

logger = logging.getLogger("baraq.integrations")


class IntegrationHealth:
    """Per-integration health: configured, successes, failures, last error."""

    def __init__(self):
        self._state: dict[str, dict] = {}

    def record(self, name: str, ok: bool, error: str = "") -> None:
        state = self._state.setdefault(name, {
            "configured": True, "ok": True, "successes": 0, "failures": 0,
            "last_error": "", "last_success_at": None, "last_failure_at": None,
        })
        if ok:
            state["ok"] = True
            state["successes"] += 1
            state["last_success_at"] = datetime.now(timezone.utc).isoformat()
            state["last_error"] = ""
        else:
            state["ok"] = False
            state["failures"] += 1
            state["last_error"] = error[:300]
            state["last_failure_at"] = datetime.now(timezone.utc).isoformat()

    def snapshot(self) -> dict:
        return {name: dict(state) for name, state in sorted(self._state.items())}


integration_health = IntegrationHealth()


def _configured() -> list[str]:
    configured: list[str] = []
    if JIRA_URL and JIRA_PROJECT_KEY and JIRA_API_TOKEN:
        configured.append("jira")
    if SERVICENOW_INSTANCE and SERVICENOW_USERNAME and SERVICENOW_PASSWORD:
        configured.append("servicenow")
    return configured


def _post_json(url: str, headers: dict[str, str], payload: dict) -> dict | None:
    """POST JSON; returns parsed response or None on any failure."""
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
    except Exception as exc:  # noqa: BLE001 - provider outage must not break alerts
        logger.warning("Integration POST failed for %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------
def _jira_create(alert: dict) -> dict | None:
    """Create a Jira issue from an alert; returns the issue key/URL."""
    headers = {"Authorization": f"Bearer {JIRA_API_TOKEN}"}
    if JIRA_EMAIL:
        import base64

        token = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"[BARAQ] {alert.get('severity', '').upper()} {alert.get('name', '')}",
            "description": (
                f"BARAQ alert #{alert.get('id')}\n\n"
                f"Severity: {alert.get('severity')}\n"
                f"Evidence: {alert.get('evidence', '')[:2000]}"
            ),
            "issuetype": {"name": JIRA_ISSUE_TYPE},
        }
    }
    result = _post_json(
        f"{JIRA_URL.rstrip('/')}/rest/api/2/issue", headers, payload
    )
    if result and result.get("key"):
        return {
            "system": "jira",
            "key": result["key"],
            "url": f"{JIRA_URL.rstrip('/')}/browse/{result['key']}",
        }
    return None


# ---------------------------------------------------------------------------
# ServiceNow
# ---------------------------------------------------------------------------
def _servicenow_create(alert: dict) -> dict | None:
    """Create a ServiceNow incident from an alert."""
    import base64

    headers = {
        "Authorization": "Basic "
        + base64.b64encode(f"{SERVICENOW_USERNAME}:{SERVICENOW_PASSWORD}".encode()).decode(),
        "Accept": "application/json",
    }
    payload = {
        "short_description": f"[BARAQ] {alert.get('severity', '').upper()} {alert.get('name', '')}",
        "description": f"BARAQ alert #{alert.get('id')}\n\n{alert.get('evidence', '')[:2000]}",
        "severity": _snow_severity(alert.get("severity", "low")),
        "urgency": _snow_severity(alert.get("severity", "low")),
    }
    result = _post_json(
        f"https://{SERVICENOW_INSTANCE}.service-now.com/api/now/table/{SERVICENOW_TABLE}",
        headers,
        payload,
    )
    if result and result.get("result", {}).get("sys_id"):
        return {
            "system": "servicenow",
            "key": result["result"]["sys_id"],
            "url": (
                f"https://{SERVICENOW_INSTANCE}.service-now.com/nav_to.do?uri="
                f"{SERVICENOW_TABLE}.do?sys_id={result['result']['sys_id']}"
            ),
        }
    return None


def _snow_severity(severity: str) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(
        severity.lower(), 3
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
def dispatch_alert(db, alert) -> dict:
    """Fan out one alert to every configured ticketing integration.

    Returns per-system results plus any issue links (stored on the alert as
    ``ticket_links`` JSON). Severity gate: ``INTEGRATIONS_MIN_SEVERITY``.
    """
    from backend.config import SEVERITY_ORDER

    if alert.severity not in SEVERITY_ORDER:
        alert.severity = "low"
    if SEVERITY_ORDER.index(alert.severity) < SEVERITY_ORDER.index(INTEGRATIONS_MIN_SEVERITY):
        return {"dispatched": False, "reason": "below min severity", "results": []}

    results: list[dict] = []
    if "jira" in _configured():
        link = _jira_create(alert.to_dict() if hasattr(alert, "to_dict") else {"id": alert.id})
        integration_health.record("jira", link is not None,
                                  "" if link else "Jira create failed")
        if link:
            results.append(link)
    if "servicenow" in _configured():
        link = _servicenow_create(alert.to_dict() if hasattr(alert, "to_dict") else {"id": alert.id})
        integration_health.record("servicenow", link is not None,
                                  "" if link else "ServiceNow create failed")
        if link:
            results.append(link)

    if results:
        ticket_links = list(alert.ticket_links or [])
        for link in results:
            if not any(t.get("key") == link["key"] for t in ticket_links):
                ticket_links.append(link)
        alert.ticket_links = ticket_links
        db.commit()
    return {"dispatched": bool(results), "results": results}


def integration_status() -> dict:
    """Health snapshot for /api/integrations/status."""
    return {
        "configured": _configured(),
        "min_severity": INTEGRATIONS_MIN_SEVERITY,
        "channels": integration_health.snapshot(),
    }
