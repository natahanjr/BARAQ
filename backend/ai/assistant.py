"""AI Security Assistant - local intelligent analyst helper.

Implements a lightweight, fully-local AI using:
  * intent detection (TF-IDF + cosine similarity over an analyst knowledge base)
  * structured retrieval over live alerts / MITRE ATT&CK data
  * deterministic explanation and remediation text generation

An optional OpenAI-compatible endpoint can be enabled through config for
richer prose, but the platform ships and works 100% offline by default.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.request
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.ai.knowledge import INTENTS
from backend.config import AI_API_KEY, AI_API_URL, AI_MODEL
from backend.database.models import Alert, AssistantMessage, NormalizedEvent

logger = logging.getLogger("sentinel.ai")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False


class SecurityAssistant:
    """Answers analyst questions about alerts, incidents and remediation."""

    def __init__(self, session):
        self.session = session
        self._vectorizer = None
        self._intent_matrix = None

    # ------------------------------------------------------------------
    # Knowledge retrieval
    # ------------------------------------------------------------------
    def _build_intent_index(self):
        if not HAS_SKLEARN:
            return
        docs = [i["examples"] for i in INTENTS]
        corpus = [" ".join(i["examples"]) for i in INTENTS]
        self._vectorizer = TfidfVectorizer(
            lowercase=True, stop_words="english", ngram_range=(1, 2)
        )
        self._intent_matrix = self._vectorizer.fit_transform(corpus)

    def _classify_intent(self, message: str) -> str:
        if not HAS_SKLEARN or self._vectorizer is None:
            return self._keyword_intent(message)
        query_vec = self._vectorizer.transform([message])
        scores = cosine_similarity(query_vec, self._intent_matrix)[0]
        best = int(scores.argmax())
        if scores[best] < 0.12:
            return self._keyword_intent(message)
        return INTENTS[best]["id"]

    @staticmethod
    def _keyword_intent(message: str) -> str:
        msg = message.lower()
        if any(k in msg for k in ("explain", "what is", "what's", "about this")):
            return "explain_alert"
        if any(k in msg for k in ("summar", "summary", "overview", "incident")):
            return "summarize"
        if any(k in msg for k in ("remediat", "mitigat", "fix", "how to respond", "action")):
            return "remediate"
        if any(k in msg for k in ("score", "health", "status", "security posture")):
            return "security_score"
        if any(k in msg for k in ("note", "report", "document")):
            return "analyst_note"
        if any(k in msg for k in ("mitre", "tactic", "technique", "framework")):
            return "mitre"
        if any(k in msg for k in ("hello", "hi ", "hey")):
            return "greeting"
        return "general"

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------
    def _latest_alerts(self, limit: int = 5) -> list[Alert]:
        return list(
            self.session.scalars(
                select(Alert)
                .where(Alert.status == "open")
                .order_by(Alert.created_at.desc())
                .limit(limit)
            )
        )

    def _find_alert(self, query: str) -> Alert | None:
        """Resolve an alert from an ID or a name/keyword mention."""
        m = re.search(r"#?(\d+)", query)
        if m:
            return self.session.get(Alert, int(m.group(1)))
        lowered = query.lower()
        for alert in self.session.scalars(select(Alert)).all():
            if (
                alert.name.lower() in lowered
                or lowered in alert.name.lower()
                or (alert.mitre_id and alert.mitre_id.lower() in lowered)
            ):
                return alert
        return None

    # ------------------------------------------------------------------
    # Response generation
    # ------------------------------------------------------------------
    def _alert_explanation(self, alert: Alert) -> str:
        return (
            f"Alert #{alert.id} - {alert.name} ({alert.severity} severity, "
            f"MITRE {alert.mitre_id} / {alert.mitre_tactic}).\n"
            f"What it means: {alert.description}\n"
            f"Evidence: {alert.evidence}\n"
            f"Recommended response: {alert.recommendation}"
        )

    def _respond(self, intent: str, message: str) -> str:
        alert = self._find_alert(message)
        alerts = self._latest_alerts()

        if intent == "greeting":
            return (
                "Hello, I am the SentinelSOC Security Assistant. I can explain alerts, "
                "summarize incidents, recommend remediation, and generate analyst notes. "
                f"There are currently {len(alerts)} open alerts."
            )

        if intent == "explain_alert":
            if alert:
                return self._alert_explanation(alert)
            if alerts:
                top = alerts[0]
                return (
                    f"I don't see a specific alert in your question, so here's the most recent one.\n"
                    + self._alert_explanation(top)
                )
            return "No alerts are currently open to explain. Run a collection or simulation first."

        if intent == "summarize":
            if not alerts:
                return "No open alerts. The environment is currently quiet - no active threats detected."
            lines = [
                f"Incident summary: {len(alerts)} open alerts.",
                "",
            ]
            for a in alerts:
                lines.append(
                    f"- #{a.id} {a.name} [{a.severity}] ({a.mitre_id}, {a.mitre_tactic}) "
                    f"- {a.description[:120]}"
                )
            lines.append("")
            lines.append(
                "Overall posture: "
                + ("CRITICAL - immediate response required."
                   if any(a.severity == "critical" for a in alerts)
                   else "ATTENTION - investigate all open alerts.")
            )
            return "\n".join(lines)

        if intent == "remediate":
            if alert:
                return f"Remediation plan for {alert.name} ({alert.mitre_id}):\n{alert.recommendation}"
            lines = ["Recommended remediation actions for current threats:"]
            seen = set()
            for a in alerts:
                if a.recommendation not in seen:
                    lines.append(f"- {a.name}: {a.recommendation}")
                    seen.add(a.recommendation)
            return "\n".join(lines) if alerts else "No open alerts requiring remediation."

        if intent == "security_score":
            score = self._compute_score()
            counts = dict(
                self.session.execute(
                    select(Alert.severity, func.count(Alert.id))
                    .where(Alert.status == "open")
                    .group_by(Alert.severity)
                ).all()
            )
            return (
                f"Security score: {score:.1f}/100.\n"
                f"Open alerts by severity: "
                + (", ".join(f"{k}: {v}" for k, v in counts.items()) or "none")
                + ".\n"
                + ("The environment shows elevated threat activity."
                   if score < 70
                   else "The environment is in a healthy state.")
            )

        if intent == "mitre":
            if alert:
                return (
                    f"MITRE ATT&CK mapping for #{alert.id}:\n"
                    f"Technique: {alert.mitre_id} - {alert.mitre_name}\n"
                    f"Tactic: {alert.mitre_tactic}\n"
                    f"Recommended action: {alert.recommendation}"
                )
            return (
                "The detection rules map to these MITRE ATT&CK techniques: "
                "T1110 (Brute Force), T1059.001 (PowerShell), T1068 (Privilege Escalation), "
                "T1547 (Persistence), T1046 (Network Service Discovery)."
            )

        if intent == "analyst_note":
            return self._generate_note(alerts)

        # general fallback with context
        return (
            f"Here is the current SOC picture: {len(alerts)} open alerts, "
            f"security score {self._compute_score():.1f}/100. "
            "I can explain alerts (e.g. 'explain alert 3'), summarize incidents, "
            "recommend remediation, or generate analyst notes."
        )

    def _generate_note(self, alerts: list[Alert]) -> str:
        if not alerts:
            return "Analyst note: no active threats. Environment normal; continue routine monitoring."
        lines = [
            f"ANALYST NOTE - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"During this shift {len(alerts)} alert(s) required attention.",
        ]
        for a in alerts[:5]:
            lines.append(f"  - {a.name} ({a.mitre_id}/{a.mitre_tactic}) severity={a.severity}")
        lines.append("Actions taken: initial triage; evidence preserved; MITRE mapping recorded.")
        return "\n".join(lines)

    def _compute_score(self) -> float:
        from backend.analyzers.dashboard import compute_security_score
        return compute_security_score(self.session)

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------
    def chat(self, message: str, role: str = "user", persist: bool = True) -> str:
        self._build_intent_index()
        intent = self._classify_intent(message)
        logger.info("Assistant intent=%s for: %s", intent, message[:80])

        if persist:
            self.session.add(AssistantMessage(role="user", content=message))

        if AI_API_URL:
            response = self._remote_completion(message)
        else:
            response = self._respond(intent, message)

        if persist:
            self.session.add(AssistantMessage(role="assistant", content=response))
            self.session.commit()
        return response

    def history(self, limit: int = 50) -> list[dict]:
        rows = self.session.scalars(
            select(AssistantMessage).order_by(AssistantMessage.id.desc()).limit(limit)
        ).all()
        return [r.to_dict() for r in reversed(rows)]

    # ------------------------------------------------------------------
    # Optional remote completion (OpenAI-compatible)
    # ------------------------------------------------------------------
    def _remote_completion(self, message: str) -> str:
        try:
            payload = json.dumps(
                {
                    "model": AI_MODEL,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are the SentinelSOC security analyst assistant. "
                                "Answer concisely using the context provided. "
                                "Ground all statements in MITRE ATT&CK where applicable."
                            ),
                        },
                        {"role": "user", "content": message},
                    ],
                    "max_tokens": 400,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                AI_API_URL,
                data=payload,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {AI_API_KEY}"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Remote AI failed (%s); falling back to local engine", exc)
            return self._respond(self._keyword_intent(message), message)
