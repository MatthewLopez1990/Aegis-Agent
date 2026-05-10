"""Action receipts emitted for meaningful task activity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.security.taint import now_utc


@dataclass(frozen=True)
class ActionReceipt:
    task_id: str
    user_request: str
    agent_interpretation: str
    plan_step: str
    tool_or_connector: str
    permission_scope: tuple[str, ...]
    inputs: dict[str, Any]
    sanitized_outputs: dict[str, Any]
    files_or_records_affected: tuple[str, ...]
    risk_classification: str
    approval_status: str
    result: str
    timestamp: str = field(default_factory=now_utc)
    error_details: str | None = None
    rollback: str | None = None
    log_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "user_request": self.user_request,
            "agent_interpretation": self.agent_interpretation,
            "plan_step": self.plan_step,
            "tool_or_connector": self.tool_or_connector,
            "permission_scope": list(self.permission_scope),
            "inputs": self.inputs,
            "sanitized_outputs": self.sanitized_outputs,
            "files_or_records_affected": list(self.files_or_records_affected),
            "risk_classification": self.risk_classification,
            "approval_status": self.approval_status,
            "timestamp": self.timestamp,
            "result": self.result,
            "error_details": self.error_details,
            "rollback": self.rollback,
            "log_refs": list(self.log_refs),
        }
