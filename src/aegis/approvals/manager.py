"""Human approval queue."""

from __future__ import annotations

import json
from typing import Any

from aegis.approvals.models import ApprovalRequest
from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import now_utc


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

    def approve(self, approval_id: str, *, actor: str = "local-user", reason: str = "", admin: bool = False) -> dict[str, Any]:
        decision = _decision_metadata("approved", actor=actor, reason=reason, admin=admin)
        self.store.update_approval(approval_id, "approved", decision_metadata=decision)
        approval = self.get(approval_id)
        self.audit_logger.append("approval.approved", {"approval_id": approval_id, "decision": decision}, task_id=approval.get("task_id"))
        return approval

    def deny(self, approval_id: str, *, actor: str = "local-user", reason: str = "", admin: bool = False) -> dict[str, Any]:
        decision = _decision_metadata("denied", actor=actor, reason=reason, admin=admin)
        self.store.update_approval(approval_id, "denied", decision_metadata=decision)
        approval = self.get(approval_id)
        self.audit_logger.append("approval.denied", {"approval_id": approval_id, "decision": decision}, task_id=approval.get("task_id"))
        return approval

    def get(self, approval_id: str) -> dict[str, Any]:
        row = self.store.get_approval(approval_id)
        if not row:
            raise KeyError(approval_id)
        return decode_approval(row)

    def list(self, status: str | None = None, *, limit: int | None = None) -> list[dict[str, Any]]:
        return [decode_approval(row) for row in self.store.list_approvals(status=status, limit=limit)]


def decode_approval(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["payload"] = json.loads(decoded.pop("payload_json", "{}"))
    decision = decoded["payload"].get("_decision")
    if isinstance(decision, dict):
        decoded["decision"] = dict(decision)
    return decoded


def _decision_metadata(status: str, *, actor: str, reason: str, admin: bool) -> dict[str, Any]:
    return {
        "status": status,
        "actor": actor or "local-user",
        "reason": reason,
        "admin": bool(admin),
        "decided_at": now_utc(),
    }
