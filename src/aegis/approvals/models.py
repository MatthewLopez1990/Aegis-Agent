"""Approval request model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from aegis.security.taint import RiskLevel, now_utc


@dataclass(frozen=True)
class ApprovalRequest:
    reason: str
    risk_level: RiskLevel
    payload: dict[str, Any]
    task_id: str | None = None
    id: str = field(default_factory=lambda: str(uuid4()))
    status: str = "pending"
    created_at: str = field(default_factory=now_utc)
    updated_at: str = field(default_factory=now_utc)

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "reason": self.reason,
            "risk_level": self.risk_level.value,
            "payload": self.payload,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
