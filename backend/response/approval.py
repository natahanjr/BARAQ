"""SOAR approval workflow — multi-step approval for dangerous actions."""
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.soar.approval")


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalRequest(BaseModel):
    action_type: str
    action_params: dict
    requested_by: str
    justification: str = ""
    approvers_required: int = 1
    expires_in_minutes: int = 60


class ApprovalRecord(BaseModel):
    id: str
    action_type: str
    action_params: dict
    requested_by: str
    justification: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    approvers_required: int
    approvals: list[str] = []
    rejections: list[str] = []
    created_at: str = ""
    expires_at: str = ""
    resolved_at: Optional[str] = None

    def __init__(self, **data):
        super().__init__(**data)
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


class ApprovalWorkflow:
    """In-memory approval workflow manager. Persist to DB in production."""

    def __init__(self):
        self._pending: dict[str, ApprovalRecord] = {}

    def create_request(self, req: ApprovalRequest) -> ApprovalRecord:
        import uuid
        record = ApprovalRecord(
            id=str(uuid.uuid4())[:8],
            action_type=req.action_type,
            action_params=req.action_params,
            requested_by=req.requested_by,
            justification=req.justification,
            approvers_required=req.approvers_required,
        )
        self._pending[record.id] = record
        logger.info("Approval request created: %s for %s", record.id, req.action_type)
        return record

    def approve(self, request_id: str, approver: str) -> ApprovalRecord:
        record = self._pending.get(request_id)
        if not record:
            raise ValueError(f"Request {request_id} not found")
        if record.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request {request_id} is {record.status}")
        if approver not in record.approvals:
            record.approvals.append(approver)
        if len(record.approvals) >= record.approvers_required:
            record.status = ApprovalStatus.APPROVED
            record.resolved_at = datetime.now(timezone.utc).isoformat()
            logger.info("Approval request %s APPROVED by %s", request_id, approver)
        return record

    def reject(self, request_id: str, approver: str, reason: str = "") -> ApprovalRecord:
        record = self._pending.get(request_id)
        if not record:
            raise ValueError(f"Request {request_id} not found")
        record.status = ApprovalStatus.REJECTED
        record.rejections.append(f"{approver}: {reason}")
        record.resolved_at = datetime.now(timezone.utc).isoformat()
        logger.info("Approval request %s REJECTED by %s: %s", request_id, approver, reason)
        return record

    def get_status(self, request_id: str) -> Optional[ApprovalRecord]:
        return self._pending.get(request_id)

    def list_pending(self) -> list[ApprovalRecord]:
        return [r for r in self._pending.values() if r.status == ApprovalStatus.PENDING]


# Global singleton
workflow = ApprovalWorkflow()
