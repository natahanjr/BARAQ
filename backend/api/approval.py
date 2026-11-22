"""SOAR approval workflow API."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.response.approval import ApprovalRequest, workflow
from backend.security import require_admin

router = APIRouter(
    prefix="/api/approval",
    tags=["approval"],
    dependencies=[Depends(require_admin)],
)


class ApproveBody(BaseModel):
    approver: str = ""
    reason: str = ""


@router.get("/pending")
async def list_pending_approvals(admin_user: str = Depends(require_admin)):
    return workflow.list_pending()


@router.post("/request")
async def create_approval_request(
    body: ApprovalRequest, admin_user: str = Depends(require_admin)
):
    # Bind requested_by to the authenticated principal, never to a free-text
    # field. This ensures the two-person rule compares real usernames.
    body.requested_by = admin_user
    record = workflow.create_request(body)
    return record


@router.get("/{request_id}")
async def get_approval_status(request_id: str, admin_user: str = Depends(require_admin)):
    record = workflow.get_status(request_id)
    if not record:
        raise HTTPException(404, "Request not found")
    return record


@router.post("/{request_id}/approve")
async def approve_request(
    request_id: str, body: ApproveBody, admin_user: str = Depends(require_admin)
):
    # The approver is the authenticated admin, never the free-text body field.
    try:
        record = workflow.approve(request_id, admin_user)
        return record
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{request_id}/reject")
async def reject_request(
    request_id: str, body: ApproveBody, admin_user: str = Depends(require_admin)
):
    try:
        record = workflow.reject(request_id, admin_user, body.reason)
        return record
    except ValueError as e:
        raise HTTPException(400, str(e))
