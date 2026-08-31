"""SOAR approval workflow API."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from backend.response.approval import workflow, ApprovalRequest
from backend.security import require_auth

router = APIRouter(prefix="/api/approval", tags=["approval"], dependencies=[Depends(require_auth)])


class ApproveBody(BaseModel):
    approver: str = ""
    reason: str = ""


@router.post("/request")
async def create_approval_request(body: ApprovalRequest):
    record = workflow.create_request(body)
    return record


@router.post("/{request_id}/approve")
async def approve_request(request_id: str, body: ApproveBody):
    try:
        record = workflow.approve(request_id, body.approver or "admin")
        return record
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{request_id}/reject")
async def reject_request(request_id: str, body: ApproveBody):
    try:
        record = workflow.reject(request_id, body.approver or "admin", body.reason)
        return record
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/{request_id}")
async def get_approval_status(request_id: str):
    record = workflow.get_status(request_id)
    if not record:
        raise HTTPException(404, "Request not found")
    return record


@router.get("/pending")
async def list_pending_approvals():
    return workflow.list_pending()
