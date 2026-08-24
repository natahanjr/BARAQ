"""BARAQ SDK (roadmap 6.3): typed Python client for external automation.

SOAR playbooks, cron jobs and third-party consoles talk to BARAQ through
this client instead of raw HTTP. It wraps the REST API with the same API
key / session-token auth the dashboard uses, and every method maps to one
public endpoint (list, read, mutate).

Example:
    from backend.integrations.sdk import BARAQClient

    client = BARAQClient("https://soc.corp.local:8443", api_key="baraq-prod-admin")
    open_alerts = client.alerts(status="open", limit=10)
    client.incident_create("Ransomware beacon", alert_ids=[a["id"] for a in open_alerts])
    client.alert_action(open_alerts[0]["id"], "contain")
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class BARAQError(RuntimeError):
    """Raised when the API rejects the request (HTTP >= 400)."""

    def __init__(self, message: str, status: int | None = None, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class BARAQClient:
    """Minimal, typed client for the BARAQ REST API.

    ``verify_ssl=False`` is only for the self-signed LAN setup
    (``start.bat secure``); production deployments use real certificates.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 15.0,
                 verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()  # noqa: S323

    def _request(self, method: str, path: str, body: dict | None = None,
                 params: dict | None = None) -> Any:
        url = self.base_url + path
        if params:
            clean = {k: v for k, v in params.items() if v is not None and v != ""}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = None
            try:
                detail = json.loads(exc.read().decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                pass
            raise BARAQError(f"BARAQ API {method} {path} -> {exc.code}", exc.code, detail) from exc

    # ---- Alerts ---------------------------------------------------------
    def alerts(self, status: str = "", severity: str = "", org: str = "",
               page: int = 1, limit: int = 25) -> dict:
        """List alerts with optional status / severity / org filters."""
        return self._request("GET", "/api/alerts", params={
            "page": page, "page_size": limit,
            "status": status, "severity": severity, "org": org,
        })

    def alert(self, alert_id: int) -> dict:
        return self._request("GET", f"/api/alerts/{alert_id}")

    def alert_status(self, alert_id: int, status: str) -> dict:
        return self._request("PATCH", f"/api/alerts/{alert_id}/status", {"status": status})

    def alert_action(self, alert_id: int, action: str, target: str = "") -> dict:
        """Take an action (fix / contain / isolate / block / kill / quarantine...)."""
        return self._request("POST", f"/api/alerts/{alert_id}/actions",
                             {"action": action, "target": target})

    def alert_note(self, alert_id: int, note: str) -> dict:
        return self._request("POST", f"/api/alerts/{alert_id}/notes", {"note": note})

    # ---- Incidents ------------------------------------------------------
    def incidents(self, status: str = "", limit: int = 25) -> dict:
        return self._request("GET", "/api/incidents", params={"status": status})

    def incident(self, incident_id: int) -> dict:
        return self._request("GET", f"/api/incidents/{incident_id}")

    def incident_create(self, title: str, description: str = "",
                        alert_ids: list[int] | None = None) -> dict:
        return self._request("POST", "/api/incidents", {
            "title": title, "description": description,
            "alert_ids": alert_ids or [],
        })

    def incident_comment(self, incident_id: int, body: str) -> dict:
        return self._request("POST", f"/api/incidents/{incident_id}/comments", {"body": body})

    # ---- Intel / integration dispatch -----------------------------------
    def intel_lookup(self, indicator: str) -> dict:
        return self._request("POST", "/api/intel/lookup", {"indicator": indicator})

    def intel_match(self, text: str) -> dict:
        return self._request("POST", "/api/intel/match", {"text": text})

    def dispatch_ticket(self, alert_id: int) -> dict:
        """Push an alert to the configured Jira / ServiceNow ticketing systems."""
        return self._request("POST", f"/api/integrations/dispatch/{alert_id}")

    def integration_status(self) -> dict:
        return self._request("GET", "/api/integrations/status")

    # ---- System ---------------------------------------------------------
    def status(self) -> dict:
        return self._request("GET", "/api/system/status")

    def ml_status(self) -> dict:
        return self._request("GET", "/api/system/ml/status")
