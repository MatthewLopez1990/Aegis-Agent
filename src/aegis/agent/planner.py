"""Simple deterministic task planner for the MVP runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from aegis.security.taint import RiskLevel


@dataclass(frozen=True)
class PlanStep:
    description: str
    connector: str | None
    operation: str
    params: dict[str, Any] = field(default_factory=dict)
    scopes: tuple[str, ...] = ()
    risk_level: RiskLevel = RiskLevel.LOW
    id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "connector": self.connector,
            "operation": self.operation,
            "params": self.params,
            "scopes": list(self.scopes),
            "risk_level": self.risk_level.value,
        }


@dataclass(frozen=True)
class TaskPlan:
    interpretation: str
    risk_level: RiskLevel
    steps: tuple[PlanStep, ...]

    def to_rows(self) -> list[dict[str, Any]]:
        return [step.to_dict() for step in self.steps]


class TaskPlanner:
    """Plans only from trusted user directives, never from connector output."""

    def plan(self, user_request: str, *, path: str | None = None) -> TaskPlan:
        lowered = user_request.lower()

        if any(term in lowered for term in ("delete", "remove all", "drop table", "wipe")):
            return TaskPlan(
                interpretation="Potentially destructive request requiring approval.",
                risk_level=RiskLevel.HIGH,
                steps=(
                    PlanStep(
                        description="Dry-run destructive action; do not modify data until approved.",
                        connector="filesystem",
                        operation="dry_run_write",
                        params={"path": path or ".", "content": "[destructive action blocked in MVP]"},
                        scopes=("write",),
                        risk_level=RiskLevel.HIGH,
                    ),
                ),
            )

        if any(term in lowered for term in ("send email", "send message", "post message")):
            return TaskPlan(
                interpretation="Outbound communication request requiring approval.",
                risk_level=RiskLevel.HIGH,
                steps=(
                    PlanStep(
                        description="Draft outbound message; send only after approval.",
                        connector="mock_messaging",
                        operation="send_message",
                        params={"draft": user_request},
                        scopes=("write",),
                        risk_level=RiskLevel.HIGH,
                    ),
                ),
            )

        if any(term in lowered for term in ("run shell", "run command", "execute command", "shell command")):
            command = _extract_command(user_request)
            return TaskPlan(
                interpretation="Shell execution request requiring approval and allowlist checks.",
                risk_level=RiskLevel.HIGH,
                steps=(
                    PlanStep(
                        description="Dry-run shell command before any approved execution.",
                        connector="shell",
                        operation="execute",
                        params={"command": command},
                        scopes=("execute",),
                        risk_level=RiskLevel.HIGH,
                    ),
                ),
            )

        if "servicenow" in lowered:
            return TaskPlan(
                interpretation="Mock ServiceNow read-only task.",
                risk_level=RiskLevel.LOW,
                steps=(
                    PlanStep(
                        description="Read mock ServiceNow ticket data.",
                        connector="mock_servicenow",
                        operation="read_ticket",
                        params={},
                        scopes=("read",),
                        risk_level=RiskLevel.LOW,
                    ),
                ),
            )

        if any(term in lowered for term in ("summarize", "inspect", "list", "analyze files", "project")) or path:
            requested_path = path or "."
            operation = "read" if _looks_like_file(requested_path) else "list"
            return TaskPlan(
                interpretation="Read-only filesystem inspection through scoped connector.",
                risk_level=RiskLevel.LOW,
                steps=(
                    PlanStep(
                        description="Inspect scoped local filesystem content.",
                        connector="filesystem",
                        operation=operation,
                        params={"path": requested_path},
                        scopes=("read",),
                        risk_level=RiskLevel.LOW,
                    ),
                ),
            )

        return TaskPlan(
            interpretation="Low-risk planning-only task. No external action required.",
            risk_level=RiskLevel.LOW,
            steps=(PlanStep(description="Record task and produce a receipt.", connector=None, operation="record", risk_level=RiskLevel.LOW),),
        )


def _extract_command(user_request: str) -> str:
    if ":" in user_request:
        return user_request.split(":", 1)[1].strip()
    return user_request.strip()


def _looks_like_file(path: str) -> bool:
    leaf = path.rstrip("/").split("/")[-1]
    return "." in leaf and leaf not in {".", ".."}
