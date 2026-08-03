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
]
