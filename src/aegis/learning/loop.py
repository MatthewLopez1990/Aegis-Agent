"""Governed self-improvement proposals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from aegis.security.taint import now_utc


@dataclass(frozen=True)
class ImprovementProposal:
    id: str
    kind: str
    summary: str
    evidence: tuple[str, ...]
    approval_required: bool = True
    default_state: str = "disabled_until_review"
    status: str = "proposed"
    created_at: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "approval_required": self.approval_required,
            "default_state": self.default_state,
            "status": self.status,
            "created_at": self.created_at or now_utc(),
        }


class LearningLoop:
    def propose_from_failure(self, *, task_id: str, failure_summary: str) -> ImprovementProposal:
        return ImprovementProposal(
            id=str(uuid4()),
            kind="skill_or_memory_update",
            summary=f"Review failed task {task_id}: {failure_summary}",
            evidence=(task_id,),
            created_at=now_utc(),
        )

    def repair_plan_from_failure(self, *, failure_summary: str, step: dict[str, Any] | None = None) -> dict[str, Any]:
        connector = str((step or {}).get("connector") or "runtime")
        operation = str((step or {}).get("operation") or "unknown")
        failure_class = _failure_class(failure_summary)
        return {
            "failure_class": failure_class,
            "target_subsystem": connector,
            "operation": operation,
            "proposed_action": _proposed_action(failure_class, connector, operation),
            "required_validation": [
                "capture changed files or generated candidate id",
                "run a focused regression or verification command",
                "record the verification result before marking implemented",
            ],
        }

    def periodic_nudge(self, *, stale_count: int, low_confidence_count: int) -> dict[str, Any]:
        return {
            "should_review": stale_count > 0 or low_confidence_count > 0,
            "stale_count": stale_count,
            "low_confidence_count": low_confidence_count,
            "default_action": "ask_user_before_memory_or_skill_changes",
        }


def _failure_class(summary: str) -> str:
    lowered = summary.lower()
    if "not allowlisted" in lowered or "permission" in lowered or "policy" in lowered:
        return "policy_or_permission"
    if "connector" in lowered or "tool" in lowered:
        return "tool_execution"
    if "model" in lowered:
        return "model_invocation"
    return "runtime_failure"


def _proposed_action(failure_class: str, connector: str, operation: str) -> str:
    if failure_class == "policy_or_permission":
        return f"Review whether {connector} {operation} needs a safer scoped capability, clearer denial, or documentation."
    if failure_class == "tool_execution":
        return f"Add focused coverage for {connector} {operation} and repair the failing execution path."
    if failure_class == "model_invocation":
        return "Verify provider routing, authentication, fallback behavior, and receipt capture."
    return "Investigate the runtime failure, add a regression test, and record verification evidence."
