"""Comparison against existing SOC alternatives.

Provides a structured comparison framework for BARAQ against other
SOC/SIEM platforms across key dimensions: detection capability,
ML features, deployment model, cost, and ecosystem.

Dimensions compared:
- Detection: rule count, ML capabilities, correlation, real-time
- Deployment: on-prem, cloud, hybrid, agent-based
- Cost: licensing, infrastructure, operational
- Ecosystem: integrations, community, documentation
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("baraq.ml.comparison")


@dataclass
class PlatformCapability:
    """A single capability metric for a SOC platform."""
    name: str
    score: float  # 0-10 scale
    details: str = ""
    source: str = "estimated"


@dataclass
class SOCPlatform:
    """Profile of a SOC/SIEM platform for comparison."""
    name: str
    vendor: str
    category: str  # "siem", "edr", "xdr", "open_source"
    capabilities: list[PlatformCapability] = field(default_factory=list)
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    pricing_model: str = ""
    deployment_options: list[str] = field(default_factory=list)

    def get_capability_score(self, name: str) -> float:
        for cap in self.capabilities:
            if cap.name == name:
                return cap.score
        return 0.0

    def overall_score(self) -> float:
        if not self.capabilities:
            return 0.0
        return round(sum(c.score for c in self.capabilities) / len(self.capabilities), 2)


# Pre-built profiles for comparison
PLATFORM_PROFILES: dict[str, SOCPlatform] = {
    "baraq": SOCPlatform(
        name="BARAQ",
        vendor="BARAQ (Open Source)",
        category="open_source",
        capabilities=[
            PlatformCapability("rule_count", 8.0, "70+ native rules + 100+ Sigma rules"),
            PlatformCapability("ml_detection", 9.0, "IsolationForest, XGBoost, ensemble stacking, online learning, federated learning"),
            PlatformCapability("correlation", 8.5, "YAML + Phase 5 behavior-group correlation"),
            PlatformCapability("real_time", 8.0, "Event-driven with streaming pipeline"),
            PlatformCapability("deployment", 9.0, "Docker, on-prem, self-hosted"),
            PlatformCapability("cost", 10.0, "Free open source"),
            PlatformCapability("customization", 9.5, "Full code access, Python rules, API"),
            PlatformCapability("documentation", 7.0, "Thesis + docs + README"),
            PlatformCapability("community", 6.0, "Growing, academic-focused"),
            PlatformCapability("integrations", 7.0, "REST API, Sysmon, WFP collectors"),
        ],
        strengths=[
            "Free and open source",
            "Advanced ML pipeline (ensemble, online, federated)",
            "Full customization capability",
            "MITRE ATT&CK mapped",
            "Cross-platform (Windows agent)",
        ],
        weaknesses=[
            "Smaller community than commercial alternatives",
            "No managed cloud offering",
            "Limited pre-built dashboards",
            "Windows-only agent (Linux/macOS TBD)",
        ],
        pricing_model="Free (open source)",
        deployment_options=["docker", "on-prem", "source-build"],
    ),
    "wazuh": SOCPlatform(
        name="Wazuh",
        vendor="Wazuh Inc.",
        category="open_source",
        capabilities=[
            PlatformCapability("rule_count", 8.5, "800+ rules, Sigma support"),
            PlatformCapability("ml_detection", 5.0, "Basic anomaly detection, no deep ML"),
            PlatformCapability("correlation", 7.0, "Policy-based correlation"),
            PlatformCapability("real_time", 8.0, "Real-time alerting"),
            PlatformCapability("deployment", 8.5, "Agent-based, Docker, K8s"),
            PlatformCapability("cost", 8.0, "Free core, paid enterprise"),
            PlatformCapability("customization", 7.0, "Custom rules, API"),
            PlatformCapability("documentation", 8.0, "Extensive docs, community"),
            PlatformCapability("community", 9.0, "Large active community"),
            PlatformCapability("integrations", 8.0, "REST API, Slack, PagerDuty, etc."),
        ],
        strengths=[
            "Large rule set (800+)",
            "Active open-source community",
            "Good documentation",
            "Multi-platform agents",
            "Active response capabilities",
        ],
        weaknesses=[
            "Limited ML capabilities",
            "No ensemble learning",
            "No online learning",
            "No federated learning",
            "Complex deployment",
        ],
        pricing_model="Free core, $2-5/agent/month enterprise",
        deployment_options=["agent", "docker", "kubernetes", "on-prem"],
    ),
    "datadog_security": SOCPlatform(
        name="Datadog Security",
        vendor="Datadog Inc.",
        category="xdr",
        capabilities=[
            PlatformCapability("rule_count", 7.0, "500+ detection rules"),
            PlatformCapability("ml_detection", 7.5, "ML-based threat detection, anomaly detection"),
            PlatformCapability("correlation", 8.0, "Signal correlation, threat chains"),
            PlatformCapability("real_time", 9.0, "Real-time streaming"),
            PlatformCapability("deployment", 9.5, "Fully managed cloud SaaS"),
            PlatformCapability("cost", 4.0, "$23/host/month (security), $69/host/month (cloud SIEM)"),
            PlatformCapability("customization", 6.0, "Custom rules, limited ML customization"),
            PlatformCapability("documentation", 9.0, "Excellent docs, training"),
            PlatformCapability("community", 8.0, "Large user base"),
            PlatformCapability("integrations", 9.5, "750+ integrations"),
        ],
        strengths=[
            "Fully managed SaaS",
            "Excellent integrations (750+)",
            "Good ML capabilities",
            "Beautiful dashboards",
            "Strong ecosystem",
        ],
        weaknesses=[
            "Expensive ($23-69/host/month)",
            "Vendor lock-in",
            "Limited ML customization",
            "No on-prem option",
            "Data leaves your infrastructure",
        ],
        pricing_model="$23-69/host/month",
        deployment_options=["cloud-saas"],
    ),
    "sumo_logic": SOCPlatform(
        name="Sumo Logic",
        vendor="Sumo Logic Inc.",
        category="siem",
        capabilities=[
            PlatformCapability("rule_count", 7.5, "Cloud SIEM rules, Sigma support"),
            PlatformCapability("ml_detection", 7.0, "Cloud analytics, anomaly detection"),
            PlatformCapability("correlation", 7.5, "Unified metadata analytics"),
            PlatformCapability("real_time", 8.5, "Real-time cloud analytics"),
            PlatformCapability("deployment", 9.0, "Cloud-native SaaS"),
            PlatformCapability("cost", 4.5, "$3-5/GB/day ingested"),
            PlatformCapability("customization", 6.5, "Custom dashboards, queries"),
            PlatformCapability("documentation", 8.5, "Good docs, training"),
            PlatformCapability("community", 7.0, "Moderate community"),
            PlatformCapability("integrations", 8.0, "Good API, integrations"),
        ],
        strengths=[
            "Cloud-native architecture",
            "Good analytics capabilities",
            "Compliance reporting",
            "Multi-cloud support",
        ],
        weaknesses=[
            "Cost scales with data volume",
            "Complex pricing",
            "Limited on-prem options",
            "No federated learning",
        ],
        pricing_model="$3-5/GB/day",
        deployment_options=["cloud-saas"],
    ),
    "microsoft_sentinel": SOCPlatform(
        name="Microsoft Sentinel",
        vendor="Microsoft",
        category="siem",
        capabilities=[
            PlatformCapability("rule_count", 8.0, "300+ built-in rules, custom analytics"),
            PlatformCapability("ml_detection", 8.0, "Fusion ML, anomaly rules, UEBA"),
            PlatformCapability("correlation", 8.5, "Incident correlation, Automation rules"),
            PlatformCapability("real_time", 8.5, "Near real-time ingestion"),
            PlatformCapability("deployment", 8.0, "Azure cloud, hybrid with Arc"),
            PlatformCapability("cost", 5.0, "$2.46/GB ingested (first 5GB free)"),
            PlatformCapability("customization", 7.0, "KQL queries, Logic Apps, APIs"),
            PlatformCapability("documentation", 9.0, "Microsoft docs, Learn"),
            PlatformCapability("community", 8.5, "Large Microsoft ecosystem"),
            PlatformCapability("integrations", 9.0, "Azure, M365, third-party"),
        ],
        strengths=[
            "Deep Microsoft integration",
            "Fusion ML correlation",
            "UEBA built-in",
            "Azure ecosystem",
            "Good pricing for M365 customers",
        ],
        weaknesses=[
            "Azure-dependent",
            "Complex KQL learning curve",
            "No on-prem option",
            "Vendor lock-in to Microsoft",
        ],
        pricing_model="$2.46/GB ingested",
        deployment_options=["cloud-azure", "hybrid-arc"],
    ),
    "elastic_security": SOCPlatform(
        name="Elastic Security",
        vendor="Elastic N.V.",
        category="siem",
        capabilities=[
            PlatformCapability("rule_count", 8.0, "900+ prebuilt rules"),
            PlatformCapability("ml_detection", 8.5, "Elastic ML, anomaly detection, endpoint ML"),
            PlatformCapability("correlation", 7.5, "Event correlation, threat hunting"),
            PlatformCapability("real_time", 8.5, "Real-time Elasticsearch"),
            PlatformCapability("deployment", 8.0, "Self-managed, cloud, hybrid"),
            PlatformCapability("cost", 6.0, "Free basic, paid Standard/Platinum"),
            PlatformCapability("customization", 8.5, "Full ELK stack, custom ML"),
            PlatformCapability("documentation", 8.0, "Good docs, community"),
            PlatformCapability("community", 8.0, "Large open-source community"),
            PlatformCapability("integrations", 8.0, "Beats, Logstash, API"),
        ],
        strengths=[
            "900+ prebuilt rules",
            "Strong ML capabilities",
            "Flexible deployment",
            "Full ELK stack access",
            "Good open-source foundation",
        ],
        weaknesses=[
            "Complex to operate",
            "Resource-intensive",
            "Platinum license for advanced ML",
            "No federated learning",
        ],
        pricing_model="Free basic, $95-125/node/month enterprise",
        deployment_options=["self-managed", "cloud", "hybrid"],
    ),
}


class SOCComparison:
    """Compare BARAQ against other SOC platforms."""

    def __init__(self):
        self.platforms = dict(PLATFORM_PROFILES)

    def add_platform(self, platform: SOCPlatform):
        """Add a custom platform for comparison."""
        self.platforms[platform.name.lower().replace(" ", "_")] = platform

    def compare(self, platform_names: list[str] | None = None) -> dict:
        """Compare platforms across all dimensions."""
        if platform_names is None:
            platform_names = list(self.platforms.keys())

        platforms = {k: v for k, v in self.platforms.items() if k in platform_names}

        comparison = {}
        for key, platform in platforms.items():
            comparison[key] = {
                "name": platform.name,
                "vendor": platform.vendor,
                "category": platform.category,
                "overall_score": platform.overall_score(),
                "capabilities": {c.name: c.score for c in platform.capabilities},
                "strengths": platform.strengths,
                "weaknesses": platform.weaknesses,
                "pricing": platform.pricing_model,
                "deployment": platform.deployment_options,
            }

        # BARAQ vs others summary
        baraq = self.platforms.get("baraq")
        baraq_vs_others = {}
        if baraq:
            for key, platform in platforms.items():
                if key == "baraq":
                    continue
                baraq_score = baraq.overall_score()
                other_score = platform.overall_score()
                baraq_vs_others[platform.name] = {
                    "baraq_score": baraq_score,
                    "other_score": other_score,
                    "difference": round(baraq_score - other_score, 2),
                    "baraq_advantage": baraq_score > other_score,
                }

        return {
            "platforms": comparison,
            "baraq_comparison": baraq_vs_others,
            "dimensions": [
                "rule_count", "ml_detection", "correlation", "real_time",
                "deployment", "cost", "customization", "documentation",
                "community", "integrations",
            ],
        }

    def get_radar_chart_data(self, platform_names: list[str] | None = None) -> dict:
        """Get data formatted for radar chart visualization."""
        if platform_names is None:
            platform_names = list(self.platforms.keys())

        platforms = {k: v for k, v in self.platforms.items() if k in platform_names}

        labels = [
            "Rules", "ML", "Correlation", "Real-time",
            "Deployment", "Cost", "Customization", "Docs",
            "Community", "Integrations",
        ]
        cap_keys = [
            "rule_count", "ml_detection", "correlation", "real_time",
            "deployment", "cost", "customization", "documentation",
            "community", "integrations",
        ]

        datasets = []
        for key, platform in platforms.items():
            values = [platform.get_capability_score(k) for k in cap_keys]
            datasets.append({
                "label": platform.name,
                "data": values,
            })

        return {
            "labels": labels,
            "datasets": datasets,
        }

    def get_recommendation(self) -> dict:
        """Generate a recommendation based on comparison."""
        baraq = self.platforms.get("baraq")
        if not baraq:
            return {"recommendation": "No BARAQ profile found"}

        baraq_score = baraq.overall_score()
        best_competitor = None
        best_score = 0

        for key, platform in self.platforms.items():
            if key == "baraq":
                continue
            score = platform.overall_score()
            if score > best_score:
                best_score = score
                best_competitor = platform

        return {
            "baraq_score": baraq_score,
            "best_competitor": best_competitor.name if best_competitor else "N/A",
            "best_competitor_score": best_score,
            "recommendation": (
                "BARAQ leads in ML capabilities, customization, and cost. "
                f"Best commercial alternative: {best_competitor.name} "
                f"(score {best_score}/10 vs BARAQ's {baraq_score}/10)."
                if best_competitor else "BARAQ is the leading option."
            ),
            "key_advantages": baraq.strengths,
            "key_gaps": baraq.weaknesses,
        }
