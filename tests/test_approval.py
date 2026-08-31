"""Tests for SOAR approval workflow."""
from backend.response.approval import ApprovalWorkflow, ApprovalRequest


def test_create_request():
    wf = ApprovalWorkflow()
    req = ApprovalRequest(action_type="isolate_host", action_params={"host": "PC-01"}, requested_by="analyst1")
    record = wf.create_request(req)
    assert record.status == "pending"
    assert record.approvers_required == 1


def test_approve_single():
    wf = ApprovalWorkflow()
    req = ApprovalRequest(action_type="block_ip", action_params={"ip": "1.2.3.4"}, requested_by="analyst1")
    record = wf.create_request(req)
    approved = wf.approve(record.id, "admin1")
    assert approved.status == "approved"


def test_approve_multi():
    wf = ApprovalWorkflow()
    req = ApprovalRequest(action_type="disable_account", action_params={"user": "bob"},
                          requested_by="analyst1", approvers_required=2)
    record = wf.create_request(req)
    wf.approve(record.id, "admin1")
    still_pending = wf.get_status(record.id)
    assert still_pending.status == "pending"
    wf.approve(record.id, "admin2")
    final = wf.get_status(record.id)
    assert final.status == "approved"


def test_reject():
    wf = ApprovalWorkflow()
    req = ApprovalRequest(action_type="quarantine_file", action_params={"path": "/tmp/x"}, requested_by="analyst1")
    record = wf.create_request(req)
    rejected = wf.reject(record.id, "admin1", "too risky")
    assert rejected.status == "rejected"
