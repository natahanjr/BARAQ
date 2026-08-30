"""Local knowledge base for the AI Security Assistant.

Each intent carries example phrases that are vectorised with TF-IDF to
match analyst questions at runtime.
"""

INTENTS: list[dict] = [
    {
        "id": "explain_alert",
        "examples": [
            "explain this alert",
            "what is alert 3",
            "explain alert 5",
            "what does this alert mean",
            "tell me about the brute force alert",
            "explain the powershell alert",
            "why was this flagged",
            "what is going on with alert 2",
        ],
    },
    {
        "id": "summarize",
        "examples": [
            "summarize the incident",
            "summary of current threats",
            "overview of open alerts",
            "summarize what happened",
            "incident summary",
            "what is the current situation",
        ],
    },
    {
        "id": "remediate",
        "examples": [
            "how do I fix this",
            "what should I do about alert 4",
            "remediation for brute force",
            "mitigate this threat",
            "how to respond",
            "recommended action",
            "what action should I take",
        ],
    },
    {
        "id": "security_score",
        "examples": [
            "what is the security score",
            "how healthy is the system",
            "security posture",
            "system status",
            "are we safe",
            "what is our risk level",
        ],
    },
    {
        "id": "analyst_note",
        "examples": [
            "generate an analyst note",
            "write a shift report",
            "create a note for the incident",
            "document this finding",
            "analyst note for alert 2",
        ],
    },
    {
        "id": "mitre",
        "examples": [
            "which mitre technique is this",
            "what tactic is mapped",
            "mitre att and ck mapping",
            "what technique was used",
            "framework mapping",
        ],
    },
    {
        "id": "greeting",
        "examples": [
            "hello",
            "hi",
            "hey there",
            "good morning",
        ],
    },
    {
        "id": "alert_search",
        "examples": [
            "show me open alerts",
            "list the high severity alerts",
            "what critical alerts are open",
            "find alerts about powershell",
            "any brute force alerts",
            "which alerts are closed today",
            "search alerts for rdp",
            "alerts from host ws01",
            "what medium alerts do we have",
        ],
    },
    {
        "id": "recent_events",
        "examples": [
            "what happened recently",
            "show recent events",
            "latest events from host ws01",
            "events from user alice",
            "what did the system log",
            "recent logins",
            "show me the last events",
        ],
    },
    {
        "id": "threat_intel",
        "examples": [
            "is this ip malicious",
            "look up this domain reputation",
            "is 8.8.8.8 suspicious",
            "check the hash against threat intel",
            "reputation of the ip",
            "is this file known bad",
            "indicator lookup",
            "lookup the domain",
        ],
    },
    {
        "id": "fleet_status",
        "examples": [
            "are my agents healthy",
            "fleet status",
            "which endpoints are online",
            "are all agents reporting",
            "list monitored hosts",
            "endpoint status",
            "are any agents stale",
        ],
    },
    {
        "id": "ml_anomalies",
        "examples": [
            "show ml anomalies",
            "what did the ml model flag",
            "any anomalous behavior",
            "top anomaly scores",
            "ml flags today",
            "show behavioral anomalies",
        ],
    },
]
