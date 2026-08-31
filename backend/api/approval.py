"""SOAR approval workflow API."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from response.approval import workflow, ApprovalRequest
from auth import get_current_user

router = APIRouter(prefix="/api/approval", tags=["approval"])


class ApproveBody(BaseModel):
    approver: str = ""
    reason: str = ""


@router.post("/request")
async def create_approval_request(body: ApprovalRequest, user=Depends(get_current_user)):
    record = workflow.create_request(body)
    return record


@router.post("/{request_id}/approve")
async def approve_request(request_id: str, body: ApproveBody, user=Depends(get_current_user)):
    try:
        approver = body.approver or user.username
        record = workflow.approve(request_id, approver)
        return record
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{request_id}/reject")
async def reject_request(request_id: str, body: ApproveBody, user=Depends(get_current_user)):
    try:
        approver = body.approver or user.username
        record = workflow.reject(request_id, approver, body.reason)
        return record
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/{request_id}")
async def get_approval_status(request_id: str, user=Depends(get_current_user)):
    record = workflow.get_status(request_id)
    if not record:
        raise HTTPException(404, "Request not found")
    return record


@router.get("/pending")
async def list_pending_approvals(user=Depends(get_current_user)):
    return workflow.list_pending()
