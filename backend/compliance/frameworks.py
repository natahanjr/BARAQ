"""Multi-framework compliance — SOC2, ISO 27001, NIST CSF templates."""
from pydantic import BaseModel
from typing import Optional


class ComplianceControl(BaseModel):
    control_id: str
    framework: str
    title: str
    description: str
    category: str
    status: str = "unassessed"
    evidence: list[str] = []
    notes: str = ""


class ComplianceFramework(BaseModel):
    name: str
    version: str
    controls: list[ComplianceControl]


SOC2_CONTROLS = [
    ComplianceControl(control_id="CC6.1", framework="SOC2", title="Logical Access Controls",
                      description="The entity implements logical access security software, infrastructure, and architectures over protected information assets",
                      category="Access Control"),
    ComplianceControl(control_id="CC6.2", framework="SOC2", title="Authentication Mechanisms",
                      description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users",
                      category="Access Control"),
    ComplianceControl(control_id="CC6.3", framework="SOC2", title="Access Authorization",
                      description="The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles",
                      category="Access Control"),
    ComplianceControl(control_id="CC7.1", framework="SOC2", title="Vulnerability Management",
                      description="To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations",
                      category="System Operations"),
    ComplianceControl(control_id="CC7.2", framework="SOC2", title="Security Event Monitoring",
                      description="The entity monitors system components and the operation of those components for anomalies",
                      category="System Operations"),
    ComplianceControl(control_id="CC8.1", framework="SOC2", title="Change Management",
                      description="The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes",
                      category="Change Management"),
]

ISO27001_CONTROLS = [
    ComplianceControl(control_id="A.5.1.1", framework="ISO27001", title="Policies for Information Security",
                      description="Information security policy and topic-specific policies shall be defined, approved by management, published, and communicated",
                      category="Organizational"),
    ComplianceControl(control_id="A.6.3", framework="ISO27001", title="Information Security Awareness",
                      description="Persons subject to information security awareness and education shall be made aware of their responsibilities",
                      category="People"),
    ComplianceControl(control_id="A.8.1", framework="ISO27001", title="User Endpoint Devices",
                      description="Information stored on, processed by, or accessible via user endpoint devices shall be protected",
                      category="Technological"),
    ComplianceControl(control_id="A.8.2", framework="ISO27001", title="Privileged Access Rights",
                      description="The allocation and use of privileged access rights shall be restricted and managed",
                      category="Technological"),
    ComplianceControl(control_id="A.8.5", framework="ISO27001", title="Secure Authentication",
                      description="Secure authentication technologies and procedures shall be established and implemented",
                      category="Technological"),
    ComplianceControl(control_id="A.8.16", framework="ISO27001", title="Monitoring Activities",
                      description="Networks, systems, and applications shall be monitored for anomalous behavior and appropriate actions taken",
                      category="Technological"),
]

NIST_CSF_CONTROLS = [
    ComplianceControl(control_id="ID.AM-1", framework="NIST-CSF", title="Asset Management",
                      description="Physical devices and systems within the organization are inventoried",
                      category="Identify"),
    ComplianceControl(control_id="PR.AC-1", framework="NIST-CSF", title="Access Control Policy",
                      description="Access control policy and processes are established and managed",
                      category="Protect"),
    ComplianceControl(control_id="PR.AC-4", framework="NIST-CSF", title="Access Permissions",
                      description="Access permissions and authorizations are managed, incorporating principles of least privilege",
                      category="Protect"),
    ComplianceControl(control_id="DE.CM-1", framework="NIST-CSF", title="Network Monitoring",
                      description="The network is monitored to detect potential cybersecurity events",
                      category="Detect"),
    ComplianceControl(control_id="DE.CM-4", framework="NIST-CSF", title="Malicious Code Detection",
                      description="Malicious code is detected",
                      category="Detect"),
    ComplianceControl(control_id="RS.RP-1", framework="NIST-CSF", title="Response Plan Execution",
                      description="Response plan is executed during or after an incident",
                      category="Respond"),
]

FRAMEWORKS = {
    "SOC2": ComplianceFramework(name="SOC 2", version="Type II", controls=SOC2_CONTROLS),
    "ISO27001": ComplianceFramework(name="ISO/IEC 27001", version="2022", controls=ISO27001_CONTROLS),
    "NIST-CSF": ComplianceFramework(name="NIST Cybersecurity Framework", version="2.0", controls=NIST_CSF_CONTROLS),
}


def get_framework(name: str) -> Optional[ComplianceFramework]:
    return FRAMEWORKS.get(name)


def list_frameworks() -> list[str]:
    return list(FRAMEWORKS.keys())


def assess_control(framework_name: str, control_id: str, status: str, evidence: list[str] = None, notes: str = "") -> Optional[ComplianceControl]:
    fw = FRAMEWORKS.get(framework_name)
    if not fw:
        return None
    for ctrl in fw.controls:
        if ctrl.control_id == control_id:
            ctrl.status = status
            ctrl.evidence = evidence or []
            ctrl.notes = notes
            return ctrl
    return None


def compliance_summary(framework_name: str) -> dict:
    fw = FRAMEWORKS.get(framework_name)
    if not fw:
        return {"error": f"Framework {framework_name} not found"}
    total = len(fw.controls)
    assessed = sum(1 for c in fw.controls if c.status != "unassessed")
    compliant = sum(1 for c in fw.controls if c.status == "compliant")
    partial = sum(1 for c in fw.controls if c.status == "partial")
    non_compliant = sum(1 for c in fw.controls if c.status == "non-compliant")
    return {
        "framework": fw.name,
        "version": fw.version,
        "total_controls": total,
        "assessed": assessed,
        "compliant": compliant,
        "partial": partial,
        "non_compliant": non_compliant,
        "compliance_pct": round(compliant / max(total, 1) * 100, 1),
    }
