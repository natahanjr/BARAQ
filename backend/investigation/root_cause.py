"""Root Cause Engine (Roadmap Phase 2 - Feature 7).

Automatic incident summaries for the analyst: the root process, the chain
that led to the evidence, negative observations (no persistence, no
privilege escalation, no suspicious network), and an assessment.

    summary:      "explorer.exe launched python.exe through a developer workflow."
    observations: [ "Persistence observed: ...", "No privilege escalation observed", ... ]
    assessment:   "Likely Benign Developer Activity"
"""
from __future__ import annotations

import logging

logger = logging.getLogger("baraq.root_cause")


def _chain_names(chain: list) -> list[str]:
    """Human-readable process names from the tree chain nodes."""
    names: list[str] = []
    for node in chain or []:
        name = ""
        if isinstance(node, dict):
            name = node.get("name") or node.get("pid") or ""
        else:
            name = getattr(node, "name", "") or getattr(node, "pid", "")
        if name and (not names or names[-1] != name):
            names.append(name)
    return names


def _first_named(tree: dict) -> str:
    chain = _chain_names(tree.get("chain", []))
    for name in chain:
        return name
    return tree.get("root") or ""


def _summary_text(root: str, chain: list[str], facts) -> str:
    """One-line narrative: root -> ... -> seed, with workflow flavour."""
    path = [root] + [n for n in chain if n != root]
    path = path[:6]
    if not path:
        path = [root or "unknown process"]
    narrative = " launched ".join(f"'{p}'" for p in path)
    if facts and facts.developer_workflow()["detected"]:
        narrative += (
            " through a developer workflow ("
            + ", ".join(facts.developer_workflow()["signals"][:3])
            + ")"
        )
    return narrative


def _observations(risk: dict, facts) -> list[dict]:
    """Positive/negative observations from the dynamic-risk signals."""
    adjustments = {a["signal"]: a for a in risk.get("adjustments", [])}
    out: list[dict] = []

    if "persistence_detected" in adjustments:
        out.append({"type": "warning", "text": "Persistence observed: " + adjustments["persistence_detected"]["note"]})
    else:
        out.append({"type": "ok", "text": "No persistence observed"})

    if "credential_access" in adjustments:
        out.append({"type": "warning", "text": "Privilege escalation / credential access observed: " + adjustments["credential_access"]["note"]})
    else:
        out.append({"type": "ok", "text": "No privilege escalation observed"})

    if "suspicious_network" in adjustments:
        out.append({"type": "warning", "text": "Suspicious network activity observed: " + adjustments["suspicious_network"]["note"]})
    else:
        out.append({"type": "ok", "text": "No suspicious network activity observed"})

    if risk.get("developer_workflow"):
        out.append({"type": "info", "text": "Developer workflow detected - risk reduced"})
    return out


def _assessment(risk: dict) -> tuple[str, str]:
    """(assessment, verdict_hint) from risk level + developer workflow."""
    level = risk.get("level", "MEDIUM")
    dev = risk.get("developer_workflow", False)
    if dev:
        if level in ("HIGH", "CRITICAL"):
            return "Developer Workflow with Elevated Risk", "suspicious"
        return "Likely Benign Developer Activity", "likely_benign"
    if level == "CRITICAL":
        return "Likely Malicious Activity", "likely_malicious"
    if level == "HIGH":
        return "Likely Malicious Activity", "likely_malicious"
    if level == "MEDIUM":
        return "Suspicious Activity", "suspicious"
    return "Likely Benign Activity", "likely_benign"


def root_cause(
    session,
    incident=None,
    events=None,
    facts=None,
    risk=None,
    tree=None,
) -> dict:
    """Root-cause analysis for an incident (or a bare alert/evidence set).

    ``facts`` is a ``ContextFacts``, ``risk`` the dynamic-risk dict from
    ``backend.risk.dynamic.adjust_risk`` and ``tree`` the process tree from
    ``backend.investigation.process_tree.build_process_tree``. All optional;
    the engine fills what it can from the session/incident when missing.
    """
    if tree is None and events is not None:
        from backend.investigation.process_tree import build_process_tree

        tree = build_process_tree(session, events, org=(incident.org if incident else "") or "")

    if facts is None:
        from backend.context import assess_events

        facts = assess_events(events or [], rule="")

    if risk is None:
        from backend.risk.dynamic import adjust_risk

        base = float(getattr(incident, "risk_score", 0) or 0) if incident else 0.0
        risk = adjust_risk(base, facts, events, session=session)

    root = tree.get("root") if isinstance(tree, dict) else None
    chain = _chain_names(tree.get("chain", [])) if isinstance(tree, dict) else []
    if not root:
        if incident:
            try:
                from backend.investigation.dedup import _root_process

                root = _root_process(session, incident.alerts[0].alert)
            except Exception:  # noqa: BLE001 - fallback must never crash
                root = None
        if not root and chain:
            root = chain[0]

    return {
        "root_process": root or "unknown",
        "chain": chain,
        "summary": _summary_text(root or "", chain, facts),
        "observations": _observations(risk, facts),
        "assessment": _assessment(risk)[0],
        "verdict_hint": _assessment(risk)[1],
        "risk": risk,
    }