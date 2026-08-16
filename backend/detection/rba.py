from __future__ import annotations
import logging
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from backend.database.models import Alert, Incident, AlertEventLink, NormalizedEvent

logger = logging.getLogger("baraq.detection.rba")

class RBAManager:
    """
    Risk-Based Alerting (RBA) Manager.
    Groups significant alerts by entity (host/user) and escalates to an
    Incident when the cumulative risk or diversity of tactics exceeds a
    threshold. Only *significant* alerts count toward a cluster: demo
    telemetry, entity-risk notables (they already have their own flow),
    developer-workflow context and low-risk noise are excluded so benign
    activity does not inflate entity scores into incidents.
    """

    #: Alerts below this risk score never count toward an RBA cluster.
    MIN_ALERT_RISK = 25.0
    #: Minimum number of significant alerts required for a cluster.
    MIN_CLUSTER_ALERTS = 2

    def __init__(self, session: Session, risk_threshold: float = 50.0):
        self.session = session
        self.risk_threshold = risk_threshold

    @staticmethod
    def _is_noise(alert: Alert) -> bool:
        """True when an alert should never feed an RBA incident.

        Developer-workflow context (git/compilers/project paths), demo
        telemetry and entity-risk notables are excluded: the first is benign
        by design, the second is synthetic, the third already escalates via
        its own entity-risk flow.
        """
        if getattr(alert, "demo", False):
            return True
        if alert.rule == "entity_risk":
            return True
        evidence = alert.evidence or ""
        for marker in (
            "strong developer-workflow context",
            "reputation=developer",
            "dev workflow signals",
        ):
            if marker in evidence:
                return True
        return False

    def evaluate_entity_risk(self, host: str, org: str = ""):
        """
        Calculates the cumulative risk for a specific host and creates
        an incident if the threshold is exceeded.
        """
        # 1. Get all open alerts for this host (only significant ones count)
        stmt = select(Alert).where(
            Alert.host == host,
            Alert.org == org,
            Alert.status == "open",
        )
        alerts = self.session.scalars(stmt).all()

        significant = [a for a in alerts if not self._is_noise(a)
                       and (a.risk_score or 0.0) >= self.MIN_ALERT_RISK]
        if len(significant) < self.MIN_CLUSTER_ALERTS:
            return None

        # 2. Calculate Risk Score
        # We use the alert's own risk_score plus a bonus for tactic diversity
        # (MITRE ATT&CK). A cluster needs either multiple tactics (campaign)
        # or at least one high/critical alert (strong signal) - a couple of
        # low-risk benign detections alone never becomes an incident.
        total_risk = 0.0
        unique_tactics = set()
        has_significant_severity = False
        for alert in significant:
            total_risk += (alert.risk_score or 0.0)
            unique_tactics.add(alert.mitre_tactic)
            has_significant_severity = has_significant_severity or alert.severity in (
                "high", "critical",
            )

        if len(unique_tactics) < 2 and not has_significant_severity:
            return None

        # Bonus: Increase risk if multiple different tactics are observed (indicates a campaign)
        tactic_bonus = len(unique_tactics) * 10.0
        final_risk = total_risk + tactic_bonus

        logger.info(
            "Entity %s risk evaluation: Score %.2f (Tactics: %d, significant alerts: %d)",
            host, final_risk, len(unique_tactics), len(significant),
        )

        # 3. Threshold Check & Incident Creation
        if final_risk >= self.risk_threshold:
            return self._create_rba_incident(host, org, significant, final_risk, unique_tactics)

        return None

    def _create_rba_incident(self, host: str, org: str, alerts: list[Alert], score: float, tactics: set[str]):
        """
        Promotes a cluster of alerts to a formal Incident.
        """
        # Check if an open RBA incident already exists for this host to avoid duplicates
        stmt = select(Incident).where(
            Incident.host == host, 
            Incident.org == org, 
            Incident.status == "open"
        )
        existing = self.session.scalar(stmt)
        
        if existing:
            existing.risk_score = score
            existing.risk_level = self._get_level(score)
            self.session.commit()
            return existing

        # Create new RBA incident
        incident = Incident(
            title=f"Entity Risk Escalation: {host}",
            description=f"Automated RBA escalation. Detected {len(alerts)} related alerts across {len(tactics)} MITRE tactics.",
            severity="high" if score > 70 else "medium",
            status="open",
            host=host,
            org=org,
            risk_score=score,
            risk_level=self._get_level(score),
            mitre_name="Multiple / Correlated",
        )
        self.session.add(incident)
        self.session.commit()
        
        # Link the alerts to this incident (using a hypothetical link model or similar)
        # In this schema, we can add notes or simply keep the association in the dashboard
        return incident

    def _get_level(self, score: float) -> str:
        if score >= 85: return "CRITICAL"
        if score >= 65: return "HIGH"
        if score >= 40: return "MEDIUM"
        return "LOW"

    def process_all_hosts(self, org: str = ""):
        """Scan all endpoints in an org for risk clusters."""
        from backend.database.models import Endpoint
        hosts = self.session.scalars(select(Endpoint.host).where(Endpoint.org == org)).all()
        
        created_count = 0
        for host in hosts:
            if self.evaluate_entity_risk(host, org):
                created_count += 1
        
        return created_count
