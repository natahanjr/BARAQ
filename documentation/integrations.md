# Ticketing integrations (roadmap 6.3)

BARAQ pushes high-severity alerts into external ticketing systems so the
SOC can route work through Jira / ServiceNow without losing the platform's
context. All outbound calls are best-effort: a dead ticketing server never
breaks alert processing.

## Configuration (.env)

| Variable | Purpose |
| --- | --- |
| `BARAQ_JIRA_URL` | Jira base URL, e.g. `https://jira.corp.local` |
| `BARAQ_JIRA_EMAIL` | Jira account for basic auth (optional; PAT only if empty) |
| `BARAQ_JIRA_API_TOKEN` | Jira PAT (or account password with `BARAQ_JIRA_EMAIL`) |
| `BARAQ_JIRA_PROJECT_KEY` | Project key, e.g. `SOC` |
| `BARAQ_JIRA_ISSUE_TYPE` | Issue type (default `Task`) |
| `BARAQ_SERVICENOW_INSTANCE` | ServiceNow subdomain, e.g. `acme` |
| `BARAQ_SERVICENOW_USERNAME` / `BARAQ_SERVICENOW_PASSWORD` | Basic-auth service account |
| `BARAQ_SERVICENOW_TABLE` | Target table (default `incident`) |
| `BARAQ_INTEGRATIONS_MIN_SEVERITY` | Only alerts >= this rank are dispatched (default `high`; ranks `info < low < medium < high < critical`) |

Secrets are read through the DPAPI vault first (see `backend/config.py`).

## How it works

1. `backend/integrations/client.py` exposes `dispatch_alert(db, alert)`:
   - Jira: `POST /rest/api/2/issue` (Bearer PAT or basic auth).
   - ServiceNow: `POST /api/now/table/{table}` with severity/urgency mapping
     (`critical=1 ... info=5`).
   - Successful tickets are appended to the alert's `ticket_links` column
     (visible in `GET /api/alerts/{id}` and the SDK).
   - Per-channel health (successes/failures/last error) is tracked in
     `IntegrationHealth` and surfaced at `GET /api/integrations/status`.
2. Manual dispatch: `POST /api/integrations/dispatch/{alert_id}` (admin).
3. The SDK wraps the same operations for external automation:

```python
from backend.integrations.sdk import BARAQClient

client = BARAQClient("https://soc.corp.local:8443", api_key="baraq-prod-admin")
open_alerts = client.alerts(status="open", severity="critical")
client.dispatch_ticket(open_alerts["items"][0]["id"])
```

See `backend/integrations/sdk.py` for the full client (alerts, incidents,
intel lookup, ML status). Playbooks or cron jobs can reuse `BARAQClient`
from a virtualenv that has `backend` on `PYTHONPATH`, or call the REST API
directly with an API key.
