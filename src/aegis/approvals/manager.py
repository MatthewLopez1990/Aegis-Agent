"""Human approval queue."""

from __future__ import annotations

import json
from typing import Any

from aegis.approvals.models import ApprovalRequest
from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore


class ApprovalManager:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def request_approval(self, request: ApprovalRequest) -> ApprovalRequest:
        self.store.insert_approval(request.to_row())
        self.audit_logger.append(
            "approval.requested",
            {"approval_id": request.id, "reason": request.reason, "risk_level": request.risk_level.value},
            task_id=request.task_id,
        )
        return request

    def approve(self, approval_id: str) -> dict[str, Any]:
        self.store.update_approval(approval_id, "approved")
        approval = self.get(approval_id)
        self.audit_logger.append("approval.approved", {"approval_id": approval_id}, task_id=approval.get("task_id"))
        return approval

    def deny(self, approval_id: str) -> dict[str, Any]:
        self.store.update_approval(approval_id, "denied")
        approval = self.get(approval_id)
        self.audit_logger.append("approval.denied", {"approval_id": approval_id}, task_id=approval.get("task_id"))
        return approval

    def get(self, approval_id: str) -> dict[str, Any]:
        row = self.store.get_approval(approval_id)
        if not row:
            raise KeyError(approval_id)
        return decode_approval(row)

    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        return [decode_approval(row) for row in self.store.list_approvals(status=status)]


def decode_approval(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["payload"] = json.loads(decoded.pop("payload_json", "{}"))
    return decoded
