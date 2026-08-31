"""Compliance gap analysis — framework-specific gap checking."""
from typing import Optional
from pydantic import BaseModel
from .frameworks import get_framework, ComplianceControl


class GapItem(BaseModel):
    control_id: str
    framework: str
    title: str
    status: str
    gap_description: str
    remediation: str


class ComplianceGapReport(BaseModel):
    framework: str
    total_controls: int
    compliant: int
    partial: int
    non_compliant: int
    unassessed: int
    compliance_pct: float
    gaps: list[GapItem]


def analyze_gaps(framework_name: str) -> Optional[ComplianceGapReport]:
    fw = get_framework(framework_name)
    if not fw:
        return None
    gaps = []
    compliant = partial = non_compliant = unassessed = 0
    for ctrl in fw.controls:
        if ctrl.status == "compliant":
            compliant += 1
        elif ctrl.status == "partial":
            partial += 1
            gaps.append(GapItem(
                control_id=ctrl.control_id, framework=fw.name, title=ctrl.title,
                status=ctrl.status, gap_description=f"{ctrl.title} is partially implemented",
                remediation=f"Complete implementation of {ctrl.control_id}",
            ))
        elif ctrl.status == "non-compliant":
            non_compliant += 1
            gaps.append(GapItem(
                control_id=ctrl.control_id, framework=fw.name, title=ctrl.title,
                status=ctrl.status, gap_description=f"{ctrl.title} is not implemented",
                remediation=f"Implement {ctrl.control_id}: {ctrl.description}",
            ))
        else:
            unassessed += 1
            gaps.append(GapItem(
                control_id=ctrl.control_id, framework=fw.name, title=ctrl.title,
                status=ctrl.status, gap_description=f"{ctrl.title} has not been assessed",
                remediation=f"Assess {ctrl.control_id} against current controls",
            ))
    total = len(fw.controls)
    return ComplianceGapReport(
        framework=fw.name, total_controls=total,
        compliant=compliant, partial=partial,
        non_compliant=non_compliant, unassessed=unassessed,
        compliance_pct=round(compliant / max(total, 1) * 100, 1),
        gaps=gaps,
    )
